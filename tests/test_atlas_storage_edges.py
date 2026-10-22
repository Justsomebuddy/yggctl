"""SQLite custody, transaction rollback and catalogue input/resource limits."""

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import tracemalloc
import zipfile

from core import Failure, atomic, logged
from atlas import catalogue as cat
from atlas import store as st
from observed_fixture import ObservedFixture

SHA = "1" * 40


class AtlasStorageEdges(ObservedFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_private_store_and_missing_database(self):
        with self.assertRaisesRegex(Failure, "missing_catalogue_or_crawl"), st.Store(self.ctx):
            self.fail("missing store opened")
        root = self.paths.state / "atlas"
        root.mkdir(mode=0o700)
        with self.assertRaisesRegex(Failure, "database_missing"), st.Store(self.ctx):
            self.fail("missing database opened")
        root.chmod(0o755)
        with self.assertRaisesRegex(Failure, "store_not_private"), st.Store(self.ctx, True):
            self.fail("public store opened")
        root.chmod(0o700)
        lock = root / ".writer.lock"
        atomic(lock, b"", 0o644)
        with self.assertRaisesRegex(Failure, "unsafe_lock"), st.Store(self.ctx, True):
            self.fail("unsafe lock opened")
        lock.chmod(0o600)
        self.ctx.require_root = True
        with (
            patch.object(self.ctx, "root"),
            patch.object(st.checks, "trusted"),
            self.assertRaisesRegex(Failure, "lock_not_root_owned"),
            st.Store(self.ctx, True),
        ):
            self.fail("foreign lock opened")
        self.ctx.require_root = False
        with (
            patch.object(st.sqlite3, "connect", side_effect=st.sqlite3.DatabaseError()),
            self.assertRaisesRegex(Failure, "database_open_failed"),
            st.Store(self.ctx, True),
        ):
            self.fail("database opened")

    @logged
    def test_root_trust_readonly_schema_and_sql_failures(self):
        with st.Store(self.ctx, True) as store:
            store.sql("INSERT INTO meta VALUES('bad','invalid json')")
            with self.assertRaisesRegex(Failure, "invalid_checkpoint_json"):
                store.meta("bad")
            with self.assertRaisesRegex(Failure, "database_operation_failed"):
                store.sql("SELECT * FROM nonexistent")
            with self.assertRaisesRegex(Failure, "database_operation_failed"):
                store.batch([("INSERT INTO meta VALUES('rollback','1')", ()), ("INVALID SQL", ())])
            self.assertIsNone(store.meta("rollback"))
            with (
                patch.object(st, "MAX_NODES", 1),
                self.assertRaisesRegex(Failure, "storage_frontier_guard"),
            ):
                store.seed("run", ["a", "b"], "test")
            with (
                patch.object(
                    Path, "stat", return_value=SimpleNamespace(st_size=256 * 1024 * 1024 + 1)
                ),
                self.assertRaisesRegex(Failure, "database_storage_guard"),
            ):
                store.response("run", "a", "self", "unknown")
        self.ctx.require_root = True
        with (
            patch.object(self.ctx, "root"),
            patch.object(st.checks, "trusted") as trust,
            st.Store(self.ctx) as store,
        ):
            self.assertGreaterEqual(trust.call_count, 3)
            with self.assertRaisesRegex(Failure, "readonly_store"):
                store.batch([])
        self.ctx.require_root = False
        with st.Store(self.ctx, True) as store:
            store.meta("schema", 2)
        with self.assertRaisesRegex(Failure, "unknown_database_schema"), st.Store(self.ctx):
            self.fail("invalid schema opened")

    @logged
    def zip_bytes(self, records):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in records:
                archive.writestr(name, body)
        return output.getvalue()

    @logged
    def test_zip_entry_record_and_decompression_caps(self):
        prefix = "public-peers-" + SHA + "/region/"
        for records, label in (
            ([(str(i), "") for i in range(1025)], "archive_limit"),
            ([(prefix + "a.md", "`tls://host.test:443`\n" * 10001)], "record_limit"),
            (
                [(prefix + f"{'a' * i}.md", "x" * 1024 * 1024) for i in range(1, 10)],
                "decompression_limit",
            ),
            ([(prefix + "a.md", b"\xff")], "invalid_catalogue_archive"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                cat.repository_rows(self.zip_bytes(records), SHA)
        with self.assertRaisesRegex(Failure, "empty_catalogue_archive"):
            cat.repository_rows(self.zip_bytes([(prefix + "BAD.md", "text")]), SHA)

    @logged
    def lying_zip_bytes(self, declared, expanded):
        """One deflate member whose central-directory size under-declares the stream."""
        import binascii
        import struct
        import zlib

        head = b"`tls://host.test:443?key=" + b"0" * 64 + b"`\n"
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = bytearray(compressor.compress(head))
        filler = b"\0" * (1 << 20)
        fed = len(head)
        while fed < expanded:
            packed += compressor.compress(filler)
            fed += len(filler)
        packed += compressor.flush()
        crc = binascii.crc32(head + b"\0" * (declared - len(head)))
        name = ("public-peers-" + SHA + "/region/lying.md").encode()
        local = (
            struct.pack(
                "<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0, crc, len(packed), declared, len(name), 0
            )
            + name
        )
        central = (
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                8,
                0,
                0,
                crc,
                len(packed),
                declared,
                len(name),
                0,
                0,
                0,
                0,
                0,
                0,
            )
            + name
        )
        end = struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local) + len(packed), 0
        )
        return local + bytes(packed) + central + end

    @logged
    def test_catalogue_declared_size_cannot_hide_inflated_bytes(self):
        # A member may under-declare its size; the point is that reading it must not
        # inflate the whole deflate stream into memory (ZipFile.read() did).
        payload = self.lying_zip_bytes(1024 * 1024, 8 * 1024 * 1024)
        tracemalloc.start()
        try:
            cat.repository_rows(payload, SHA)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 4 * 1024 * 1024)

    @logged
    def test_monitor_invalid_country_unknown_fields_and_cap(self):
        parser = cat.MonitorParser()
        parser.feed(
            '<tr><th id="country">bad!</th></tr><tr><td id="address">tls://host.test:443</td><td>ignored</td></tr>'
        )
        self.assertEqual(parser.invalid, 1)
        self.assertIsNone(parser.region)
        parser.region, parser.rows = "test", [{}] * 10000
        with self.assertRaisesRegex(Failure, "monitor_record_limit"):
            parser.feed('<tr><td id="address">tls://host.test:443</td></tr>')
        with self.assertRaisesRegex(Failure, "invalid_catalogue_endpoint"):
            cat.endpoint("tls://bad..host:443")

    @logged
    def test_fixed_fetch_size_and_repository_ref_errors(self):
        with (
            patch.object(self.ctx, "run", return_value=Mock(stdout=b"x" * (2 * 1024 * 1024 + 1))),
            self.assertRaisesRegex(Failure, "source_size_limit"),
        ):
            cat.fetch(self.ctx, cat.API)
        store = Mock()
        for value, label in (
            (b"bad", "invalid_repository_ref"),
            (b'{"object":{"sha":3}}', "invalid_repository_commit"),
        ):
            with (
                patch.object(cat, "fetch", return_value=value),
                self.assertRaisesRegex(Failure, label),
            ):
                cat.acquire(self.ctx, store)
        data = self.zip_bytes(
            [("public-peers-" + SHA + "/region/test.md", "`tls://host.test:443`")]
        )
        with patch.object(
            cat,
            "fetch",
            side_effect=[
                json.dumps({"object": {"sha": SHA}}).encode(),
                data,
                b"<html>empty</html>",
            ],
        ):
            result = cat.acquire(self.ctx, store)
        self.assertEqual(result["monitor_status"], "unknown")
        self.assertEqual(result["endpoints"], 1)

    @logged
    def test_catalogue_port_range_is_explicit(self):
        for port in (1, 65535):
            self.assertEqual(
                cat.endpoint(f"tls://host.test:{port}")["endpoint"], f"tls://host.test:{port}"
            )
        for port in (0, -1, 65536):
            with self.assertRaisesRegex(Failure, "invalid_catalogue_endpoint"):
                cat.endpoint(f"tls://host.test:{port}")
