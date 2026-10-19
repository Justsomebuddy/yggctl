"""Atlas checkpoint, identity and saved-response validation without mesh requests."""

import contextlib
import io
import itertools
import json
from unittest.mock import Mock, patch

from core import Failure, logged
from atlas import acquisition as ac, protocol, analysis, command
from atlas.store import Store
from observed_fixture import ObservedFixture, A, B, C


class AtlasAcquisitionEdges(ObservedFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def prepare(self, store):
        record = {
            "id": "1",
            "endpoint": "tls://example.invalid:443",
            "transport": "tls",
            "pins": [B],
            "countries": ["test"],
            "registry_online": None,
        }
        store.sql("INSERT INTO catalogue VALUES(?,?)", (record["id"], json.dumps(record)))
        store.meta("catalogue", {"endpoints": 1})
        return ac.new_run(self.ctx, store)

    @logged
    def test_local_snapshot_failures_and_seed_frontier_caps(self):
        with (
            patch.object(self.ctx, "api", side_effect=Failure("fixture")),
            self.assertRaisesRegex(Failure, "local_identity_unknown"),
        ):
            ac.local_snapshot(self.ctx)
        original = self.ctx.api
        count = 0

        @logged
        def api(method, **kw):
            nonlocal count
            if method == "getSelf":
                count += 1
                if count == 1:
                    raise Failure("fixture")
            return original(method, **kw)

        with (
            patch.object(self.ctx, "api", side_effect=api),
            self.assertRaisesRegex(Failure, "local_identity_unknown"),
        ):
            ac.local_snapshot(self.ctx)
        with Store(self.ctx, True) as store:
            with self.assertRaisesRegex(Failure, "catalogue_first"):
                ac.new_run(self.ctx, store)
            with (
                patch.object(ac, "MAX_NODES", 1),
                self.assertRaisesRegex(Failure, "frontier_guard"),
            ):
                self.prepare(store)
            self.assertEqual(store.sql("SELECT COUNT(*) FROM runs")[0][0], 0)
            self.assertIsNone(store.meta("current"))
            store.meta("current", "missing")
            with self.assertRaisesRegex(Failure, "missing_current_run"):
                ac.status(store)
            with self.assertRaisesRegex(Failure, "missing_run"):
                analysis.build(store)

    @logged
    def test_payload_revalidation_error_matrix(self):
        good = protocol.projection(B, "peers", {protocol.address(B): {"keys": [C]}})
        values = [
            "bad",
            json.dumps({}),
            json.dumps(dict(good, semantics="forged")),
            json.dumps(dict(good, returned_rows=4097)),
            json.dumps(dict(good, duplicate_rows=1)),
        ]
        for value in values:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(Failure, "invalid_saved_response"),
            ):
                ac.payload(value, B, "peers")
        with self.assertRaisesRegex(Failure, "invalid_saved_response"):
            ac.payload(json.dumps({"key": B, "routing_entries": 1, "extra": True}), B, "self")
        with self.assertRaisesRegex(Failure, "invalid_remote_method"):
            protocol.projection(B, "invalid", {})
        with patch.object(self.ctx, "run", return_value=Mock(stdout=b'{"error":"fixture"}')):
            self.assertEqual(protocol.query(self.ctx, B, "self")[0], "unknown")

    @logged
    def test_crawl_invalid_slice_exhausted_and_own_key_rejection(self):
        with Store(self.ctx, True) as store:
            run = self.prepare(store)
            for minutes in (0, True, 121):
                with self.assertRaisesRegex(Failure, "invalid_time_slice"):
                    ac.crawl(self.ctx, store, minutes)
            store.sql("UPDATE runs SET state='frontier_exhausted' WHERE id=?", (run,))
            self.assertEqual(ac.crawl(self.ctx, store)["state"], "frontier_exhausted")
            store.sql("UPDATE runs SET state='checkpoint' WHERE id=?", (run,))
            store.sql("DELETE FROM targets")
            store.seed(run, [A], "invalid_local_key")
            with self.assertRaisesRegex(Failure, "own_key_in_remote_frontier"):
                ac.crawl(self.ctx, store, 1)
            self.assertEqual(ac.status(store)["state"], "checkpoint")

    @logged
    def test_crawl_identity_change_and_mid_target_deadline(self):
        with Store(self.ctx, True) as store:
            self.prepare(store)
            with (
                patch.object(self.ctx, "api", return_value={"key": C}),
                self.assertRaisesRegex(Failure, "identity_changed"),
            ):
                ac.crawl(self.ctx, store, 1)
            with patch.object(
                ac.time, "monotonic", side_effect=itertools.chain([0, 0], itertools.repeat(61))
            ):
                result = ac.crawl(self.ctx, store, 1)
            self.assertEqual(result["state"], "checkpoint")
            self.assertGreater(result["remaining_keys"], 0)
            self.assertEqual(store.sql("SELECT COUNT(*) FROM responses")[0][0], 0)

    @logged
    def test_no_run_build_and_response_elapsed_validation(self):
        with Store(self.ctx, True) as store:
            data = analysis.build(store)
            self.assertIsNone(data["run"]["run"])
            self.assertEqual(data["nodes"], [])
            run = self.prepare(store)
            for elapsed in (-1, 86400001):
                store.response(run, B, "self", "unknown", elapsed)
                with self.assertRaisesRegex(Failure, "invalid_response_elapsed"):
                    analysis.build(store)

    @logged
    def test_identical_runs_no_topology_change_and_self_only_is_ignored(self):
        with Store(self.ctx, True) as store:
            first = self.prepare(store)
            data = {"key": B, "routing_entries": 1}
            peers = protocol.projection(B, "peers", {protocol.address(B): {"keys": [C, B]}})
            for method, value in (("self", data), ("peers", peers)):
                store.response(first, B, method, "ok", 1, value)
            second = ac.new_run(self.ctx, store)
            for method, value in (("self", data), ("peers", peers)):
                store.response(second, B, method, "ok", 1, value)
            changes = analysis.changes(store, second)
            self.assertEqual(changes["changes"], [])
            self.assertEqual(changes["comparable_reporter_methods"], 1)
            built = analysis.build(store)
            self.assertEqual(built["respondent_keys"], 1)
            self.assertFalse(any(e["source"] == e["target"] for e in built["edges"]))
        with self.assertRaises(Failure):
            command(self.ctx, ["crawl", "0"])

    @logged
    def test_empty_status_corrupt_status_and_duplicate_persisted_rows(self):
        with Store(self.ctx, True) as store:
            self.assertIsNone(ac.status(store)["run"])
            run = self.prepare(store)
            store.response(run, B, "self", "forged")
            with self.assertRaisesRegex(Failure, "invalid_response_status"):
                analysis.build(store)
            store.sql("DELETE FROM responses")
            value = protocol.projection(B, "peers", {protocol.address(B): {"keys": [C]}})
            store.response(run, B, "peers", "ok", 1, value)
            expected = analysis.build(store)["edges"]
            # Malformed persisted schema: root-private does not mean trusted data.
            # Keep duplicate rows from inventing duplicate edge reporters.
            store.sql("ALTER TABLE responses RENAME TO original_responses")
            store.sql("CREATE TABLE responses AS SELECT * FROM original_responses")
            store.sql("INSERT INTO responses SELECT * FROM original_responses")
            self.assertEqual(analysis.build(store)["edges"], expected)
