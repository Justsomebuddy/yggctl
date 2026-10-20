"""Offline regression suite. No live services, network, keys or global paths."""

from typing import BinaryIO, cast

import contextlib
import io
import json
import os
from pathlib import Path
import socket

# Security review: bounded offline subprocess regression fixtures
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import (
    Context,
    Paths,
    Failure,
    NODE,
    STACK,
    FILES,
    logged,
    bounded_process,
    digest,
    peer_uri,
    safe_config,
    atomic,
    read_regular,
)
import checks
import management
import telemetry
import recovery
import main

from test_support import ConsoleFixture, PIN, URI


class ConsoleTests(ConsoleFixture):
    @logged
    def test_fixture_does_not_depend_on_checkout_location(self):
        other = type(self)("test_peer_canonical")
        try:
            with patch.dict(globals(), {"__file__": "/outside-work/tests.py"}):
                other.setUp()
            self.assertTrue(Path(other.tmp.name).is_dir())
            self.assertNotEqual(
                Path(other.tmp.name).parent, Path("/var/lib/yggdrasil-lab/selftests")
            )
        finally:
            other.doCleanups()

    @logged
    def test_root_integrity_covers_shared_test_support(self):
        # This is a synthetic manifest. No /etc, /usr or installed files are read.
        required = {
            Path(self.paths.node),
            Path(self.paths.stack),
            *(
                self.paths.units / name
                for name in (
                    NODE,
                    STACK,
                    "ygg-metrics.timer",
                    "ygg-metrics.service",
                    "ygg-alert-forward.service",
                    "ygg-alert-forward.path",
                )
            ),
            *(
                self.paths.etc / name
                for name in (
                    *FILES,
                    "baseline.env",
                    "baseline-runtime-public.txt",
                    "baseline-nft-mullvad.txt",
                )
            ),
            *(
                self.paths.runtime / name
                for name in (
                    "main.py",
                    "core.py",
                    "checks.py",
                    "management.py",
                    "telemetry.py",
                    "recovery.py",
                    "tests.py",
                    "test_support.py",
                    "rotate.py",
                    "sandbox.py",
                    "broker.py",
                )
            ),
            *(
                self.paths.runtime / "research" / name
                for name in ("__init__.py", "model.py", "metrics.py", "tests.py")
            ),
            *(
                self.paths.runtime / "atlas" / name
                for name in (
                    "__init__.py",
                    "store.py",
                    "protocol.py",
                    "catalogue.py",
                    "acquisition.py",
                    "analysis.py",
                    "viewer.py",
                    "tests.py",
                )
            ),
            Path(self.paths.decoder),
            Path("/usr/bin/yggctl"),
            Path("/usr/local/bin/yggctl"),
            Path("/etc/sysusers.d/ygglab-worker.conf"),
        }
        body = b"synthetic-integrity-fixture"
        manifest = ""

        @logged
        def fixture_read(path, **kwargs):
            if path == self.paths.etc / "integrity.manifest":
                return manifest.encode()
            return body

        with (
            patch.object(self.ctx, "require_root", True),
            patch("checks.trusted"),
            patch("checks.read_regular", side_effect=fixture_read),
        ):
            for include_support in (False, True):
                members = (
                    required
                    if include_support
                    else required - {self.paths.runtime / "test_support.py"}
                )
                manifest = "".join(
                    digest(body) + "  " + str(path) + "\n" for path in sorted(members)
                )
                if include_support:
                    self.assertEqual(checks.integrity(self.ctx), len(required))
                else:
                    with self.assertRaisesRegex(Failure, "integrity_coverage_incomplete"):
                        checks.integrity(self.ctx)

    @logged
    def test_offline_root_gate_precedes_fixture_creation(self):
        ctx = Context(require_root=True)
        with patch("core.os.geteuid", return_value=1000), patch("tests.run_suite") as suite:
            with self.assertRaisesRegex(Failure, "root_required"):
                main.selftest(ctx, offline=True)
            suite.assert_not_called()

    @logged
    def test_peer_canonical(self):
        uri, hp = peer_uri("tls://192.0.2.1:443?key=" + PIN)
        self.assertEqual(hp, "192.0.2.1:443")
        self.assertEqual(uri, URI)

    @logged
    def test_policy_exact_hash_without_reference(self):
        _, expected, observed = self.policy_fixture()
        (self.paths.etc / "baseline-runtime-public.txt").unlink()
        with (
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            checks.policy_gate(self.ctx)
        self.assertEqual(self.calls, [])

    @logged
    def test_policy_legacy_anchored_rule_permutation(self):
        reference, _, _ = self.policy_fixture()
        prefix, rules = reference.split(b"  rich rules: \n")
        current = prefix + b"  rich rules: \n" + b"".join(reversed(rules.splitlines(keepends=True)))
        _, expected, observed = self.policy_fixture(current)
        with (
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            checks.policy_gate(self.ctx)

    @logged
    def test_policy_changed_fields_or_rules_rejected(self):
        reference, _, _ = self.policy_fixture()
        variants = (
            reference.replace(b"ports: ", b"ports: 22/tcp"),
            reference.replace(b"ipv4", b"ipv6", 1),
            reference.replace(b" accept", b" drop"),
            reference + b"\trule accept\n",
            reference.replace(b'\trule family="ipv6" drop\n', b""),
            reference + b'\trule family="ipv6" drop\n',
            reference + b"  forward: yes\n",
        )
        for current in variants:
            with self.subTest(current=current):
                _, expected, observed = self.policy_fixture(current)
                with (
                    patch("checks.baseline", return_value=expected),
                    patch("checks.policy", return_value=observed),
                    self.assertRaises(Failure),
                ):
                    checks.policy_gate(self.ctx)

    @logged
    def test_policy_untrusted_reference_and_race_rejected(self):
        reference, _, _ = self.policy_fixture()
        current = reference.replace(b"ipv4", b"ipv6", 1)
        for state in ("missing", "symlink", "wrong_hash", "race"):
            with self.subTest(state=state):
                _, expected, observed = self.policy_fixture(current)
                p = self.paths.etc / "baseline-runtime-public.txt"
                if state == "missing":
                    p.unlink()
                elif state == "symlink":
                    p.unlink()
                    p.symlink_to(self.paths.etc / "mode")
                elif state == "wrong_hash":
                    atomic(p, current)
                else:
                    self.ctx.runner = lambda argv, **kw: subprocess.CompletedProcess(
                        argv, 0, reference, b""
                    )
                with (
                    patch("checks.baseline", return_value=expected),
                    patch("checks.policy", return_value=observed),
                    self.assertRaises((Failure, OSError)),
                ):
                    checks.policy_gate(self.ctx)
                if p.is_symlink():
                    p.unlink()

    @logged
    def test_policy_other_hashes_remain_strict(self):
        _, expected, observed = self.policy_fixture()
        for key in ("FW_PERMANENT_SHA", "NFT_MULLVAD_SHA"):
            with (
                self.subTest(key=key),
                patch("checks.baseline", return_value=expected),
                patch("checks.policy", return_value=dict(observed, **{key: "3" * 64})),
                self.assertRaises(Failure),
            ):
                checks.policy_gate(self.ctx)

    @logged
    def test_policy_display_malformed_rejected(self):
        reference, _, _ = self.policy_fixture()
        bad = (
            b"",
            reference[:-1],
            reference + b"\x00\n",
            reference.replace(b"\n", b"\r\n"),
            reference.replace(b"  rich rules: \n", b""),
            reference + b"  rich rules: \n",
            reference + b"\trule \taccept\n",
            reference + b"\trule accept\n" * 257,
            b"x" * 65537 + b"\n",
        )
        for value in bad:
            with self.subTest(length=len(value)), self.assertRaises(Failure):
                checks.runtime_display(value)

    @logged
    def test_policy_legacy_anchored_quic_endpoint_only(self):
        reference, _, expected, observed = self.relay_fixture()
        with (
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            checks.policy_gate(self.ctx)
        self.assertEqual(self.relay_calls, ["status", "table", "status"])
        self.assertEqual(read_regular(self.paths.etc / "baseline-nft-mullvad.txt"), reference)
        _, _, expected, observed = self.relay_fixture()
        runtime = read_regular(self.paths.etc / "baseline-runtime-public.txt")
        prefix, rules = runtime.split(b"  rich rules: \n")
        permuted = (
            prefix + b"  rich rules: \n" + b"".join(reversed(rules.splitlines(keepends=True)))
        )
        observed["FW_RUNTIME_SHA"] = digest(permuted)
        original = self.ctx.runner

        @logged
        def both(argv, **kw):
            if argv == ["/usr/bin/firewall-cmd", "--zone=public", "--list-all"]:
                return subprocess.CompletedProcess(argv, 0, permuted, b"")
            return original(argv, **kw)

        self.ctx.runner = both
        with (
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            checks.policy_gate(self.ctx)

    @logged
    def test_policy_quic_rule_mutations_rejected(self):
        _, current, _, _ = self.relay_fixture()
        mutations = (
            current.replace(b"dport 443", b"dport 444"),
            current.replace(b"0x6d6f6c65", b"0x6d6f6c66"),
            current.replace(b" accept", b" drop"),
            current.replace(b"1.1.1.1", b"8.8.8.8", 1),
            current.replace(b"1.1.1.1", b"9.9.9.9"),
            current.replace(b"ct state established", b"ct state new,established"),
            current.replace(b"\t}\n}", b"\t\ttcp dport 22 accept\n\t}\n}"),
            b"\n".join(reversed(current.splitlines())) + b"\n",
        )
        for value in mutations:
            with self.subTest(mutation=digest(value)):
                _, _, expected, observed = self.relay_fixture(value)
                with (
                    patch("checks.baseline", return_value=expected),
                    patch("checks.policy", return_value=observed),
                    self.assertRaises(Failure),
                ):
                    checks.policy_gate(self.ctx)

    @logged
    def test_policy_quic_reference_custody_rejected(self):
        for state in ("missing", "symlink", "wrong_hash", "untrusted", "fifo"):
            with self.subTest(state=state):
                _, current, expected, observed = self.relay_fixture()
                path = self.paths.etc / "baseline-nft-mullvad.txt"
                if state == "missing":
                    path.unlink()
                elif state == "symlink":
                    path.unlink()
                    path.symlink_to(self.paths.etc / "mode")
                elif state == "wrong_hash":
                    atomic(path, current)
                elif state == "fifo":
                    path.unlink()
                    os.mkfifo(path)
                else:
                    self.ctx.require_root = True
                with (
                    patch("checks.trusted", side_effect=Failure("untrusted_deployment_path"))
                    if state == "untrusted"
                    else contextlib.nullcontext()
                ):
                    with (
                        patch("checks.baseline", return_value=expected),
                        patch("checks.policy", return_value=observed),
                        self.assertRaises(Failure),
                    ):
                        checks.policy_gate(self.ctx)
                self.ctx.require_root = False
                if path.is_symlink() or state == "fifo":
                    path.unlink()

    @logged
    def test_policy_quic_snapshot_and_daemon_races_rejected(self):
        for state in ("table", "endpoint", "disconnect"):
            with self.subTest(state=state):
                _, _, expected, observed = self.relay_fixture()
                if state == "table":
                    self.relay_table += b"\n"
                elif state == "endpoint":
                    self.relay_statuses[1] = self.relay_statuses[1].replace(b"1.1.1.1", b"9.9.9.9")
                else:
                    self.relay_statuses[1] = b'{"state":"disconnected"}'
                with (
                    patch("checks.baseline", return_value=expected),
                    patch("checks.policy", return_value=observed),
                    self.assertRaises(Failure),
                ):
                    checks.policy_gate(self.ctx)

    @logged
    def test_policy_quic_status_is_strict_and_bounded(self):
        self.relay_fixture()
        valid = self.relay_statuses[0]
        self.assertEqual(checks.quic_relay(valid), b"1.1.1.1")
        invalid = (
            b"",
            b"null",
            b"[]",
            b"{}",
            b"x" * 65537,
            b"{",
            valid.replace(b"connected", b"disconnected"),
            valid.replace(b"udp", b"tcp"),
            valid.replace(b"wg0-mullvad", b"other"),
            valid.replace(b"Quic", b"Udp2Tcp"),
            valid.replace(b"1.1.1.1:443", b"1.1.1.1:444"),
            valid.replace(b"1.1.1.1", b"127.0.0.1"),
            valid.replace(b"1.1.1.1:443", b"[2001:4860:4860::8888]:443"),
            valid.replace(b"1.1.1.1", b"relay.example"),
            valid.replace(b"1.1.1.1", b"01.1.1.1"),
            valid.replace(b'"Single": {', b'"Other": {}, "Single": {'),
        )
        for value in invalid:
            with self.subTest(length=len(value)), self.assertRaises(Failure):
                checks.quic_relay(value)

    @logged
    def test_policy_quic_reference_grammar_and_display_rejected(self):
        reference, current, _, _ = self.relay_fixture()
        bad_reference = (
            reference.replace(b"dport 443", b"dport 444"),
            reference.replace(b"8.8.8.8", b"9.9.9.9", 1),
            reference + b"#8.8.8.8\n",
            reference + reference,
            reference.replace(b"8.8.8.8", b"999.8.8.8"),
        )
        for value in bad_reference:
            with self.subTest(reference=digest(value)), self.assertRaises(Failure):
                checks.relay_display(value, current, b"1.1.1.1")
        for value in (b"", current[:-1], current + b"\x00\n", b"x" * 65537 + b"\n"):
            with self.subTest(length=len(value)), self.assertRaises(Failure):
                checks.relay_display(reference, value, b"1.1.1.1")

    @logged
    def test_policy_quic_logger_never_records_daemon_payload(self):
        _, _, expected, observed = self.relay_fixture()
        self.relay_statuses = [
            p.replace(b'"state":', b'"secret_sentinel":"SECRET_DO_NOT_LOG", "state":')
            for p in self.relay_statuses
        ]
        with (
            patch("core.event") as trace,
            patch("checks.event") as states,
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            checks.policy_gate(self.ctx)
        messages = str(trace.call_args_list) + str(states.call_args_list)
        self.assertNotIn("SECRET_DO_NOT_LOG", messages)
        self.assertNotIn("1.1.1.1", messages)
        self.assertIn("legacy_anchored_local_quic_and_tunnel_addresses", messages)

    @logged
    def test_peer_bad_inputs(self):
        for uri in (
            URI.replace("192.0.2.1", "999.0.2.1"),
            URI.replace("192.0.2.1", "host.example"),
            URI.replace(":443", ":99999"),
            URI + "&key=" + PIN,
            URI + "&bad",
            URI + "&evil=1",
            URI.replace("tls://", "tls://user@"),
            URI + "#fragment",
            URI + "\n",
            URI.replace("tls://", "ftp://"),
        ):
            with self.subTest(uri=uri), self.assertRaises(Failure):
                peer_uri(uri)

    @logged
    def test_ws_requires_force(self):
        with self.assertRaises(Failure):
            peer_uri(URI.replace("tls://", "wss://"))
        self.assertEqual(peer_uri(URI.replace("tls://", "wss://"), True)[1], "192.0.2.1:443")
        # Reading SplitResult.port is validation, not an unused computation.
        for port in ("invalid", "65536", "-1"):
            with self.subTest(origin_port_case=port):
                with self.assertRaisesRegex(Failure, "invalid_origin"):
                    peer_uri(
                        URI.replace("tls://", "wss://")
                        + "&origin=https%3A%2F%2Fexample.test%3A"
                        + port,
                        True,
                    )
        with self.assertRaises(Failure):
            peer_uri(
                URI.replace("tls://", "wss://")
                + "&origin=https%3A%2F%2Fuser%3Apassword%40example.com",
                True,
            )

    @logged
    def test_guard_structured_public_listener(self):
        c = self.ctx.config("yggdrasil-lab.conf")
        self.assertEqual(safe_config(c), [])
        for k, v in (
            ("Listen", ["tls://0.0.0.0:9001"]),
            ("MulticastInterfaces", [{}]),
            ("IfName", "auto"),
            ("InterfacePeers", {"eth0": [URI]}),
            ("PrivateKey", "synthetic"),
        ):
            with self.subTest(k=k):
                self.assertTrue(safe_config(dict(c, **{k: v})))

    @logged
    def test_atomic_reject_symlink(self):
        p = self.paths.etc / "link"
        p.symlink_to(self.paths.etc / "mode")
        with self.assertRaises(Failure):
            atomic(p, "bad")
        self.assertEqual(read_regular(self.paths.etc / "mode"), b"direct\n")

    @logged
    def test_read_reject_link_and_size(self):
        p = self.paths.etc / "link"
        p.symlink_to(self.paths.etc / "mode")
        with self.assertRaises(OSError):
            read_regular(p)
        with self.assertRaises(Failure):
            read_regular(self.paths.etc / "mode", 1)

    @logged
    def test_missing_manifest_fail(self):
        (self.paths.etc / "integrity.manifest").unlink()
        with self.assertRaises(OSError):
            checks.integrity(self.ctx)

    @logged
    def test_hash_mismatch_fail(self):
        atomic(self.paths.etc / "gate.nft", "modified")
        with self.assertRaises(Failure):
            checks.integrity(self.ctx)

    @logged
    def test_hash_missing_coverage(self):
        atomic(self.paths.etc / "integrity.manifest", "")
        with self.assertRaises(Failure):
            checks.integrity(self.ctx)

    @logged
    def test_external_failed_no_secret(self):
        self.failed_command = "getPeers"
        with patch("core.event") as log, self.assertRaises(Failure) as error:
            checks.peers(self.ctx)
        self.assertNotIn("SECRET", str(error.exception))
        self.assertNotIn("SECRET", str(log.call_args_list))

    @logged
    def test_admin_unknown_schema_fail(self):
        value: object
        for value in ({}, {"peers": {}}, {"peers": [{"up": "true"}]}, {"error": "bad"}):
            self.responses["getPeers"] = value
            with self.assertRaises(Failure):
                checks.peers(self.ctx)

    @logged
    def test_multicast_admin_failure_not_empty(self):
        self.failed_command = "getMulticastInterfaces"
        with self.assertRaises(Failure):
            checks.multicast_gate(self.ctx, False)

    @logged
    def test_underlay_own_tuples(self):
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])
        original = self.ctx.runner

        @logged
        def other(argv, **kw):
            if "conntrack" in argv[0]:
                return subprocess.CompletedProcess(
                    argv, 0, b"tcp 6 100 src=1.1.1.1 dst=9.9.9.9 sport=3 dport=4 mark=3905\n", b""
                )
            return original(argv, **kw)

        self.ctx.runner = other
        with self.assertRaises(Failure):
            checks.underlay(self.ctx)

    @logged
    def test_notify_off_honoured_unknown_saved(self):
        atomic(self.paths.state / "notify.state", "off\n")
        self.failed_command = "getPeers"
        with self.assertRaises(Failure):
            telemetry.collect(self.ctx)
        row = telemetry.rows(self.ctx)[0]
        self.assertIsNone(row["up"])
        self.assertTrue(row["errors"])
        self.assertEqual(telemetry.rows(self.ctx, "alerts.jsonl"), [])

    @logged
    def test_hourly_dedup_not_empty(self):
        atomic(self.paths.state / "notify.state", "on\n")
        self.ps = []
        for _ in range(2):
            with self.assertRaises(Failure):
                telemetry.collect(self.ctx)
        alerts = telemetry.rows(self.ctx, "alerts.jsonl")
        self.assertEqual(len(alerts), 1)
        self.assertRegex(alerts[0]["key"], r"^collect:\d{10}$")

    @logged
    def test_collect_one_query_each(self):
        telemetry.collect(self.ctx)
        self.assertEqual(sum("getPeers" in a for a in self.calls), 2)

    @logged
    def test_parallel_collect_no_loss(self):
        contexts = [Context(self.paths, runner=self.runner, require_root=False) for _ in range(4)]
        errors = []

        @logged
        def worker(c):
            try:
                telemetry.collect(c)
            except BaseException as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(c,)) for c in contexts]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(telemetry.rows(self.ctx)), 4)

    @logged
    def test_transaction_rolls_back_exact(self):
        path = self.paths.etc / "mode"
        old = read_regular(path)

        @logged
        def fail():
            raise Failure("injected_runtime_failure")

        @logged
        def ok():
            return None

        with self.assertRaises(Failure):
            management.transaction(self.ctx, {path: "tunnel\n"}, fail, ok)
        self.assertEqual(read_regular(path), old)
        self.assertFalse((self.paths.state / "transaction.json").exists())
        checks.integrity(self.ctx)

    @logged
    def test_transaction_failed_compensation_retains_journal(self):
        @logged
        def fail():
            raise Failure("injected")

        with self.assertRaises(Failure):
            management.transaction(self.ctx, {self.paths.etc / "mode": "tunnel\n"}, fail, fail)
        self.assertTrue((self.paths.state / "transaction.json").exists())

    @logged
    def test_pending_transaction_blocks_mutation(self):
        atomic(self.paths.state / "transaction.json", "{}")

        @logged
        def ok():
            return None

        with self.assertRaises(Failure):
            management.transaction(self.ctx, {self.paths.etc / "mode": "tunnel\n"}, ok, ok)

    @logged
    def test_key_free_archive_allowlist(self):
        data = recovery.archive(recovery.members(self.ctx))
        files, keys = recovery.inspect_archive(data)
        self.assertFalse(keys)
        self.assertFalse(any(k.startswith("keys/") for k in files))
        self.assertNotIn(b"synthetic test fixture, not a key", data)

    @logged
    def test_archive_traversal_link_duplicate_rejected(self):
        for name, kind in (("../../etc/passwd", tarfile.REGTYPE), ("config/mode", tarfile.SYMTYPE)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = "/etc/passwd"
                tar.addfile(info, io.BytesIO())
            with self.assertRaises(Failure):
                recovery.inspect_archive(buffer.getvalue())

    @logged
    def test_full_backup_needs_explicit_recipient(self):
        with self.assertRaises(Failure):
            recovery.backup(self.ctx, full=True)

    @logged
    def test_backup_digest_and_permissions(self):
        path = recovery.backup(self.ctx)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        recovery.restore(self.ctx, path)
        atomic(path, b"corrupt")
        with self.assertRaises(Failure):
            recovery.restore(self.ctx, path)

    @logged
    def test_peer_preview_no_changes(self):
        before = read_regular(self.paths.etc / "yggdrasil-lab.conf")
        management.change_peer(self.ctx, URI.replace("192.0.2.1", "192.0.2.9"))
        self.assertEqual(before, read_regular(self.paths.etc / "yggdrasil-lab.conf"))
        self.assertFalse(any("addpeer" in a for a in self.calls))

    @logged
    def test_remove_exact_not_regex(self):
        with self.assertRaises(Failure):
            management.change_peer(self.ctx, "192.0.2.10:443", remove=True)

    @logged
    def test_http_failure_and_status(self):
        self.failed_command = "/usr/bin/curl"
        with self.assertRaises(Failure):
            main.http_probe(self.ctx, "[200::1]:80")
        for target in ("[::1]:80", "[200::1]:65536", "example.com:80", "[200::1]:80;id"):
            with self.assertRaises((Failure, ValueError)):
                main.http_probe(self.ctx, target)

    @logged
    def test_subprocess_timeout_and_output_cap(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded_process(["/usr/bin/sleep", "1"], timeout=0.05)
        with self.assertRaises(Failure):
            bounded_process(["/usr/bin/head", "-c", "18000000", "/dev/zero"])
        result = bounded_process(["/usr/bin/cat"], input=b"fixture")
        self.assertEqual(result.stdout, b"fixture")

    @logged
    def test_http_non_2xx_rejected(self):
        original = self.ctx.runner

        @logged
        def bad(argv, **kw):
            if argv[0] == "/usr/bin/curl":
                return subprocess.CompletedProcess(argv, 0, b"503 0.1 0.15 0.2 0.3", b"")
            return original(argv, **kw)

        self.ctx.runner = bad
        with self.assertRaises(Failure):
            main.http_probe(self.ctx, "[200::1]:80")

    @logged
    def test_shared_context_threads_lock(self):
        errors = []

        @logged
        def worker():
            try:
                telemetry.collect(self.ctx)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(telemetry.rows(self.ctx)), 4)

    @logged
    def test_success_transaction_and_preview_contracts(self):
        @logged
        def ok():
            return None

        path = self.paths.etc / "mode"
        management.transaction(self.ctx, {path: "tunnel\n"}, ok, ok)
        self.assertEqual(read_regular(path), b"tunnel\n")
        self.assertFalse((self.paths.state / "transaction.json").exists())
        self.assertEqual(len(list(self.paths.state.glob("transaction-*.json"))), 1)
        with self.assertRaises(Failure):
            main.dispatch(
                self.ctx,
                main.argparse.Namespace(
                    command="collect",
                    args=["oops"],
                    apply=False,
                    force=False,
                    full=False,
                    recipient=None,
                ),
            )

    @logged
    def test_archive_duplicate_and_hash_mismatch(self):
        data = recovery.archive(recovery.members(self.ctx))
        buf = io.BytesIO()
        with (
            tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as src,
            tarfile.open(fileobj=buf, mode="w:gz") as out,
        ):
            for member in src:
                payload = cast(BinaryIO, src.extractfile(member)).read()
                if member.name == "config/mode":
                    payload = b"wrong\n"
                    member.size = len(payload)
                out.addfile(member, io.BytesIO(payload))
        with self.assertRaises(Failure):
            recovery.inspect_archive(buf.getvalue())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as out:
            for _ in range(2):
                out.addfile(tarfile.TarInfo("config/mode"), io.BytesIO())
        with self.assertRaises(Failure):
            recovery.inspect_archive(buf.getvalue())

    @logged
    def test_reject_fifo_without_blocking(self):
        fifo = self.paths.state / "untrusted.fifo"
        os.mkfifo(fifo)
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); from core import read_regular, Failure; "
            "read_regular(sys.argv[2])"
        )
        result = bounded_process(
            ["/usr/bin/python3", "-B", "-c", code, str(Path(__file__).resolve().parent), str(fifo)],
            timeout=1,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"not_regular_file", result.stderr)

    @logged
    def test_reject_archive_schema_shapes(self):
        payloads: tuple[object, ...] = (
            [],
            "bad",
            {"schema": 1, "keys": False, "sha256": []},
            {"schema": 1, "keys": False, "sha256": "bad"},
            {"schema": 1, "keys": "false", "sha256": {}},
            {"schema": 1, "keys": False, "sha256": {"config/mode": []}},
        )
        for manifest in payloads:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                raw = json.dumps(manifest).encode()
                info = tarfile.TarInfo("manifest.json")
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            with self.subTest(shape=type(manifest).__name__), self.assertRaises(Failure):
                recovery.inspect_archive(buffer.getvalue())

    @logged
    def test_graph_bins_cover_requested_window(self):
        import datetime as dt

        now = dt.datetime(2026, 10, 13, 19, 0, tzinfo=dt.timezone.utc)
        sample = {
            "ts": (now - dt.timedelta(minutes=1)).isoformat(),
            "up": 1,
            "errors": [],
            "peers": [{"r": URI, "up": True, "rtt": 1}],
        }
        atomic(self.paths.state / "metrics.jsonl", json.dumps(sample) + "\n")
        clock = unittest.mock.Mock(wraps=dt.datetime)
        clock.now.return_value = now
        capture = io.StringIO()
        with patch.object(telemetry.dt, "datetime", clock), contextlib.redirect_stdout(capture):
            telemetry.stats(self.ctx, hours=1, graph=True)
        graph = next(
            line
            for line in capture.getvalue().splitlines()
            if len(line) == 60 and set(line) <= set("?.#")
        )
        self.assertEqual(graph, "?" * 59 + "#")

    @logged
    def test_remote_tree_and_retired_dht_contract(self):
        args = main.argparse.Namespace(
            command="debug-remote",
            args=["tree", PIN],
            apply=False,
            force=False,
            full=False,
            recipient=None,
        )
        main.dispatch(self.ctx, args)
        self.assertEqual(self.calls[-1][3], "debug_remotegettree")
        args.args = ["dht", PIN]
        previous = len(self.calls)
        with self.assertRaisesRegex(Failure, "remote_dht_not_supported"):
            main.dispatch(self.ctx, args)
        self.assertEqual(len(self.calls), previous)

    @logged
    def test_recovery_journal_schema_rejected(self):
        value: object
        for value in ([], "bad", {"old": []}, {"old": {"/etc/passwd": "fixture"}}):
            atomic(self.paths.state / "transaction.json", json.dumps(value))
            with self.assertRaisesRegex(Failure, "invalid_recovery_journal"):
                management.recover_transaction(self.ctx, apply=True)
            self.assertTrue((self.paths.state / "transaction.json").exists())

    @logged
    def test_unittest_failure_method_not_shadowed(self):
        with self.assertRaises(AssertionError):
            self.assertEqual(1, 2)

    @logged
    def test_remote_own_key_rejected_without_mesh_call(self):
        self.responses["getSelf"] = {"key": PIN.upper()}
        for command, argv in (
            ("nodeinfo", [PIN]),
            ("whois", [PIN]),
            *(("debug-remote", [kind, PIN]) for kind in ("self", "peers", "tree")),
        ):
            self.calls.clear()
            args = main.argparse.Namespace(
                command=command, args=argv, apply=False, force=False, full=False, recipient=None
            )
            with self.assertRaisesRegex(Failure, "remote_target_is_local"):
                main.dispatch(self.ctx, args)
            self.assertEqual([c[3] for c in self.calls if c[0] == self.paths.ctl], ["getSelf"])
        value: object
        for value in ({}, {"key": []}, {"key": "invalid"}):
            self.responses["getSelf"] = value
            with self.assertRaisesRegex(Failure, "admin_invalid_self_key"):
                main.remote_key(self.ctx, PIN)
        self.calls.clear()
        with self.assertRaisesRegex(Failure, "expected_public_key"):
            main.remote_key(self.ctx, "invalid")
        self.assertEqual(self.calls, [])

    @logged
    def test_http_failure_metrics_do_not_fake_stage_or_log_stderr(self):
        original = self.ctx.runner

        @logged
        def timeout(argv, **kw):
            if argv[0] == "/usr/bin/curl":
                return subprocess.CompletedProcess(
                    argv,
                    28,
                    b"000 0 5.001 5.001 5.001",
                    b"Proxy connection timed out SECRET_DO_NOT_LOG",
                )
            return original(argv, **kw)

        self.ctx.runner = timeout
        capture = io.StringIO()
        with patch("core.event") as log, contextlib.redirect_stdout(capture):
            with self.assertRaisesRegex(Failure, "diagnostic=proxy_connect_timeout") as error:
                main.http_probe(self.ctx, "[200::1]:80")
        self.assertIn("curl_rc=28 HTTP=000", capture.getvalue())
        self.assertNotIn(
            "SECRET", capture.getvalue() + str(error.exception) + str(log.call_args_list)
        )

    @logged
    def test_http_metrics_unknown_timeout_and_untrusted_values(self):
        original = self.ctx.runner
        for payload, rc, expected in (
            (b"000 0 5 5 5", 28, "timeout_stage_unknown"),
            (b"200 nan 0 0 0", 0, "invalid_metrics"),
            (b"200 inf 0 0 0", 0, "invalid_metrics"),
            (b"200 -1 0 0 0", 0, "invalid_metrics"),
            (b"200 0 0 0 18", 0, "invalid_metrics"),
            (b"200 SECRET 0 0 0", 0, "invalid_metrics"),
            (b"200 0 0 0", 0, "invalid_metrics"),
        ):

            @logged
            def response(argv, **kw):
                if argv[0] == "/usr/bin/curl":
                    return subprocess.CompletedProcess(argv, rc, payload, b"SECRET")
                return original(argv, **kw)

            self.ctx.runner = response
            with (
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(Failure, expected),
            ):
                main.http_probe(self.ctx, "[200::1]:80")

    @logged
    def test_routine_trace_is_held_and_summarized(self):
        import core

        with patch("core.syslog.syslog") as sink:
            core.finish_run("reset", 0)
            sink.reset_mock()
            core.event("entry", "probe")
            core.event("external_start", "systemctl")
            core.event("state", "mutation_lock", "acquired")
            core.event("exit", "probe", "success")
            self.assertEqual(sink.call_count, 0)
            core.finish_run("collect", 0)
        self.assertEqual(
            [c.args[1] for c in sink.call_args_list], ["yggctl run collect status=0 traced=4"]
        )

    @logged
    def test_failed_run_writes_held_trace_before_summary(self):
        import core

        with patch("core.syslog.syslog") as sink:
            core.finish_run("reset", 0)
            sink.reset_mock()
            core.event("entry", "probe")
            core.event("exit", "probe", "success")
            core.finish_run("collect", 1)
        self.assertEqual(
            [c.args[1] for c in sink.call_args_list],
            [
                "yggctl entry probe ",
                "yggctl exit probe success",
                "yggctl run collect status=1 traced=2",
            ],
        )

    @logged
    def test_errors_alerts_and_state_changes_are_written_at_once(self):
        import core

        quiet = core._trace["quiet"]
        core.trace_quiet(False)
        self.addCleanup(core.trace_quiet, quiet)
        with patch("core.syslog.syslog") as sink:
            core.finish_run("reset", 0)
            sink.reset_mock()
            core.event("error", "probe", "Failure")
            core.event("external_error", "systemctl", "OSError")
            core.event("alert", "collect", "peer_down")
            core.event("state", "runtime_policy", "changed")
            self.assertEqual(sink.call_count, 4)
            core.finish_run("collect", 0)
        self.assertEqual(sink.call_args_list[-1].args[1], "yggctl run collect status=0 traced=0")

    @logged
    def test_trace_flag_writes_everything_at_once(self):
        import core

        with patch("core.syslog.syslog") as sink:
            core.finish_run("reset", 0)
            sink.reset_mock()
            core.event("entry", "probe")
            try:
                core.trace_live()
                self.assertEqual([c.args[1] for c in sink.call_args_list], ["yggctl entry probe "])
                core.event("exit", "probe", "success")
                self.assertEqual(sink.call_args_list[-1].args[1], "yggctl exit probe success")
            finally:
                core._trace["live"] = False
            core.finish_run("status", 0)
        self.assertEqual(sink.call_args_list[-1].args[1], "yggctl run status status=0 traced=1")

    @logged
    def test_quiet_mode_holds_expected_errors_until_failure(self):
        import core

        quiet = core._trace["quiet"]
        core.trace_quiet(True)
        self.addCleanup(core.trace_quiet, quiet)
        with patch("core.syslog.syslog") as sink:
            core.finish_run("reset", 0)
            sink.reset_mock()
            core.event("error", "probe", "Failure")
            core.finish_run("selftest", 0)
            self.assertEqual(
                [c.args[1] for c in sink.call_args_list], ["yggctl run selftest status=0 traced=1"]
            )
            sink.reset_mock()
            core.event("error", "probe", "Failure")
            core.finish_run("selftest", 1)
        self.assertEqual(
            [c.args[1] for c in sink.call_args_list],
            ["yggctl error probe Failure", "yggctl run selftest status=1 traced=1"],
        )

    @logged
    def test_held_trace_is_bounded(self):
        import core

        with patch("core.syslog.syslog") as sink:
            core.finish_run("reset", 0)
            sink.reset_mock()
            for _ in range(core.TRACE_KEEP + 50):
                core.event("entry", "probe")
            core.finish_run("collect", 1)
        lines = [c.args[1] for c in sink.call_args_list]
        self.assertEqual(len(lines), core.TRACE_KEEP + 1)
        self.assertEqual(
            lines[-1],
            f"yggctl run collect status=1 traced={core.TRACE_KEEP + 50} trace_kept={core.TRACE_KEEP}",
        )

    @logged
    def test_run_label_logs_only_documented_commands(self):
        self.assertEqual(main.run_label("collect"), "collect")
        self.assertEqual(main.run_label("stack-peers"), "stack-peers")
        self.assertEqual(main.run_label("pears"), "other")
        self.assertEqual(main.run_label("tls://192.0.2.1:443"), "other")
        self.assertEqual(main.run_label(""), "other")

    @logged
    def test_stats_without_sudo_reads_group_readable_metrics(self):
        import datetime as dt

        sample = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "up": 1,
            "errors": [],
            "peers": [{"r": URI, "up": True, "rtt": 1}],
        }
        atomic(self.paths.state / "metrics.jsonl", json.dumps(sample) + "\n")
        ctx = Context(self.paths, self.ctx.runner, require_root=True)
        args = main.argparse.Namespace(
            command="stats", args=["1"], apply=False, force=False, full=False, recipient=None
        )
        capture = io.StringIO()
        with patch("main.os.geteuid", return_value=1000), contextlib.redirect_stdout(capture):
            main.dispatch(ctx, args)
        self.assertIn("window=1h samples=1 ", capture.getvalue())
        with (
            patch("main.os.geteuid", return_value=1000),
            patch("main.os.access", return_value=False),
        ):
            with self.assertRaisesRegex(Failure, "root_required"):
                main.dispatch(ctx, args)

    @logged
    def test_metrics_append_does_not_rewrite_and_compacts_late(self):
        name, path = "m.jsonl", self.paths.state / "m.jsonl"
        for i in range(5):
            telemetry.append(self.ctx, name, {"i": i}, keep=5)
        inode = path.stat().st_ino
        telemetry.append(self.ctx, name, {"i": 5}, keep=5)
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual([r["i"] for r in telemetry.rows(self.ctx, name)], [0, 1, 2, 3, 4, 5])
        telemetry.append(self.ctx, name, {"i": 6}, keep=5)
        self.assertNotEqual(path.stat().st_ino, inode)
        self.assertEqual([r["i"] for r in telemetry.rows(self.ctx, name)], [2, 3, 4, 5, 6])

    @logged
    def test_metrics_torn_tail_is_skipped_and_dropped(self):
        path = self.paths.state / "m.jsonl"
        path.write_bytes(b'{"i":0}\n{"i":1')
        self.assertEqual(telemetry.rows(self.ctx, "m.jsonl"), [{"i": 0}])
        telemetry.append(self.ctx, "m.jsonl", {"i": 2}, keep=5)
        self.assertEqual(path.read_bytes(), b'{"i":0}\n{"i":2}\n')

    @logged
    def test_metrics_append_refuses_symlink(self):
        target = self.paths.state / "elsewhere"
        target.write_text("")
        (self.paths.state / "m.jsonl").symlink_to(target)
        with self.assertRaises(OSError):
            telemetry.append(self.ctx, "m.jsonl", {"i": 0})
        self.assertEqual(target.read_text(), "")

    @logged
    def test_sandbox_command_runs_as_worker_without_keys(self):
        import sandbox

        unit, argv = sandbox.command(
            "research",
            "research",
            ["report", "1"],
            "/usr/local/libexec/yggdrasil-lab/main.py",
            "1a2b3c4d",
        )
        self.assertEqual(unit, "yggctl-sandbox-research-1a2b3c4d.service")
        props = [argv[i + 1] for i, v in enumerate(argv) if v == "-p"]
        for required in (
            "User=ygglab-worker",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "InaccessiblePaths=/etc/yggdrasil-lab",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "TemporaryFileSystem=/var/lib/yggdrasil-lab:mode=0755",
            "BindPaths=/var/lib/yggdrasil-lab/research",
        ):
            self.assertIn(required, props)
        self.assertEqual(
            argv[argv.index("--") + 1 :],
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "/usr/local/libexec/yggdrasil-lab/main.py",
                "research",
                "report",
                "1",
            ],
        )
        _, remote = sandbox.command(
            "remote", "ping", ["[200::1]:80"], "/m.py", "00000000", trace=True
        )
        remote_props = [remote[i + 1] for i, v in enumerate(remote) if v == "-p"]
        self.assertIn("IPAddressDeny=any", remote_props)
        self.assertIn("IPAddressAllow=localhost", remote_props)
        self.assertNotIn("BindPaths=/var/lib/yggdrasil-lab/research", remote_props)
        self.assertEqual(remote[-3:], ["--trace", "ping", "[200::1]:80"])
        self.assertEqual(
            {
                sandbox.ROLE_OF[c]
                for c in (
                    "ping",
                    "bench",
                    "socks-test",
                    "nodeinfo",
                    "whois",
                    "debug-remote",
                    "survey",
                    "traceroute",
                )
            },
            {"remote"},
        )
        with self.assertRaises(ValueError):
            sandbox.properties("checks")

    @logged
    def test_sandbox_detects_its_own_unit(self):
        import sandbox

        with tempfile.TemporaryDirectory() as d:
            inside, outside = Path(d) / "inside", Path(d) / "outside"
            inside.write_text("0::/system.slice/yggctl-sandbox-atlas-1a2b3c4d.service\n")
            outside.write_text("0::/user.slice/user-1000.slice/session-3.scope\n")
            self.assertEqual(sandbox.own_unit(str(inside)), ("atlas", "1a2b3c4d"))
            self.assertTrue(sandbox.inside(str(inside)))
            self.assertFalse(sandbox.inside(str(outside)))
            self.assertFalse(sandbox.inside(str(Path(d) / "missing")))

    @logged
    def test_live_paths_route_sandboxed_commands(self):
        seen = []

        def fake_run(ctx, cmd, args, main_path):
            seen.append((cmd, args))
            return 3 if cmd == "atlas" else 0

        ctx = Context(Paths(), self.ctx.runner, require_root=False)

        def ns(command, *a):
            return main.argparse.Namespace(
                command=command, args=list(a), apply=False, force=False, full=False, recipient=None
            )

        with (
            patch("sandbox.inside", return_value=False),
            patch("sandbox.run", side_effect=fake_run),
        ):
            for command, *a in (
                ("research", "report", "1"),
                ("ping", "[200::1]:80"),
                ("nodeinfo", PIN),
                ("survey",),
                ("bench",),
                ("socks-test",),
            ):
                main.dispatch(ctx, ns(command, *a))
            with self.assertRaisesRegex(Failure, "sandboxed_atlas_failed:rc=3"):
                main.dispatch(ctx, ns("atlas", "status"))
        self.assertEqual(
            [c for c, _ in seen],
            ["research", "ping", "nodeinfo", "survey", "bench", "socks-test", "atlas"],
        )

    @logged
    def test_sandbox_parent_checks_before_worker(self):
        import sandbox

        steps: list[tuple] = []

        class FakeBroker:
            unit_id = "0badc0de"

            def __init__(self, ctx, role):
                steps.append(("broker", role))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                steps.append(("broker_closed",))

        def attached(argv, stop):
            steps.append(("worker", argv[-1], self.ctx.lock_depth > 0))
            return 0

        self.ctx.attached = attached
        with (
            patch("sandbox.broker.Broker", FakeBroker),
            patch("sandbox.checks.integrity", side_effect=lambda ctx: steps.append(("integrity",))),
            patch("sandbox.checks.sockets", side_effect=lambda ctx: steps.append(("sockets",))),
        ):
            self.assertEqual(sandbox.run(self.ctx, "research", ["report"], "/m.py"), 0)
            self.assertEqual(sandbox.run(self.ctx, "bench", [], "/m.py"), 0)
            self.assertEqual(sandbox.run(self.ctx, "atlas", ["status"], "/m.py"), 0)
        self.assertEqual(
            steps,
            [
                ("integrity",),
                ("broker", "research"),
                ("worker", "report", True),
                ("broker_closed",),
                ("integrity",),
                ("sockets",),
                ("broker", "remote"),
                ("worker", "bench", False),
                ("broker_closed",),
                ("integrity",),
                ("broker", "atlas"),
                ("worker", "status", False),
                ("broker_closed",),
            ],
        )

    @logged
    def test_broker_serves_only_allowlisted_reads(self):
        import broker
        import checks as checks_module

        calls = []

        def runner(argv, **kw):
            calls.append(list(argv))
            body = {"key": PIN, "method": argv[3]}
            return subprocess.CompletedProcess(argv, 0, json.dumps(body).encode(), b"")

        parent = Context(self.paths, runner, require_root=False)
        atomic(self.paths.state / "metrics.jsonl", '{"ts":"x"}\n')
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            # The actual temporary path can exceed Linux's Unix-socket path limit.
            # Keep the directory private and use a short, process-local fd alias.
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            directory = Path(f"/proc/self/fd/{fd}/broker")
            served = stack.enter_context(
                broker.Broker(parent, "research", uid=os.getuid(), directory=directory)
            )
            self.assertEqual(directory.stat().st_uid, os.geteuid())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o711)
            self.assertEqual(served.path.stat().st_uid, os.getuid())
            self.assertEqual(served.path.stat().st_mode & 0o777, 0o600)
            worker = broker.WorkerContext(served.path, paths=self.paths)
            stack.callback(worker.conn.close)
            stack.callback(worker.reader.close)
            self.assertEqual(worker.api("getSelf")["method"], "getSelf")
            remote = stack.enter_context(
                broker.Broker(parent, "remote", uid=os.getuid(), directory=directory)
            )
            remote_worker = broker.WorkerContext(remote.path, paths=self.paths)
            stack.callback(remote_worker.conn.close)
            stack.callback(remote_worker.reader.close)
            r = remote_worker.run(
                [
                    str(self.paths.ctl),
                    "-json",
                    f"-endpoint=unix://{self.paths.node_sock}",
                    "debug_remotegetpeers",
                    "key=" + PIN,
                ]
            )
            self.assertEqual(json.loads(r.stdout)["method"], "debug_remotegetpeers")
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                worker.run(
                    [
                        str(self.paths.ctl),
                        "-json",
                        f"-endpoint=unix://{self.paths.node_sock}",
                        "debug_remotegetpeers",
                        "key=" + PIN,
                    ]
                )
            self.assertEqual(worker.read_state("metrics.jsonl", 1024), b'{"ts":"x"}\n')
            for bad in (
                ["addPeer", "uri=tls://192.0.2.1:443"],
                ["debug_remotegetpeers", "key=" + "z" * 64],
                ["getself", "extra=1"],
            ):
                with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                    worker.run(
                        [
                            str(self.paths.ctl),
                            "-json",
                            f"-endpoint=unix://{self.paths.node_sock}",
                            *bad,
                        ]
                    )
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                worker.api("getPeers", stack=True)
            with self.assertRaisesRegex(Failure, "state_not_available_in_sandbox"):
                worker.read_state("alerts.jsonl", 1024)
            self.assertEqual(checks_module.integrity(worker), 0)
            worker.root()
            with worker.locked():
                pass
        self.assertEqual([c[3] for c in calls], ["getSelf", "debug_remotegetpeers"])

    @logged
    def test_broker_rejects_foreign_uid_and_metrics_for_other_roles(self):
        import broker

        parent = Context(self.paths, self.ctx.runner, require_root=False)
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            directory = Path(f"/proc/self/fd/{fd}/broker")
            with broker.Broker(parent, "remote", uid=os.getuid(), directory=directory) as served:
                served.uid = os.getuid() + 1  # the broker now expects another worker uid
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(10)  # generous under load; a rejection is immediate
                client.connect(str(served.path))
                try:
                    client.sendall(b'{"call":"metrics"}\n')
                    reply = client.recv(10)
                except (
                    BrokenPipeError,
                    ConnectionResetError,
                ):  # rejected before or after the request
                    reply = b""
                self.assertEqual(reply, b"")
                client.close()
            with (
                broker.Broker(parent, "remote", uid=os.getuid(), directory=directory) as served,
                contextlib.ExitStack() as worker_stack,
            ):
                worker = broker.WorkerContext(served.path, paths=self.paths)
                worker_stack.callback(worker.conn.close)
                worker_stack.callback(worker.reader.close)
                with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                    worker.read_state("metrics.jsonl", 1024)

    @logged
    def test_peer_alerts_after_ten_minutes_and_on_recovery(self):
        import datetime as dt

        start = dt.datetime(2026, 10, 16, 12, 0, tzinfo=dt.timezone.utc)

        def sample(minute, up):
            return {
                "ts": (start + dt.timedelta(minutes=minute)).isoformat(),
                "peers": [{"r": URI, "up": up}, {"r": "tls://192.0.2.2:443", "up": True}],
            }

        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(0, False)), [])
        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(5, False)), [])
        state = self.paths.state / "alert-state.json"
        inode = state.stat().st_ino
        down = telemetry.peer_alerts(self.ctx, sample(10, False))
        self.assertEqual(
            down, [{"kind": "ygg-peer-down", "peer": URI, "minutes": 10, "up": 1, "total": 2}]
        )
        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(11, False)), [])
        self.assertNotEqual(state.stat().st_ino, inode)
        inode = state.stat().st_ino
        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(12, False)), [])
        self.assertEqual(state.stat().st_ino, inode)
        up = telemetry.peer_alerts(self.ctx, sample(20, True))
        self.assertEqual(
            up, [{"kind": "ygg-peer-up", "peer": URI, "minutes": 20, "up": 2, "total": 2}]
        )
        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(21, False)), [])
        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(25, True)), [])

    @logged
    def test_unstable_peer_alert_from_reconnects(self):
        import datetime as dt

        start = dt.datetime(2026, 10, 16, 12, 0, tzinfo=dt.timezone.utc)

        def sample(minute):
            return {
                "ts": (start + dt.timedelta(minutes=minute)).isoformat(),
                "peers": [{"r": URI, "up": True}],
            }

        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(0), {URI: 20}), [])
        self.assertEqual(
            telemetry.peer_alerts(self.ctx, sample(1), {URI: 80}), []
        )  # same connection
        self.assertEqual(telemetry.peer_alerts(self.ctx, sample(10), {URI: 30}), [])
        alerts = telemetry.peer_alerts(self.ctx, sample(20), {URI: 5})
        self.assertEqual(
            alerts, [{"kind": "ygg-peer-unstable", "peer": URI, "count": 3, "up": 1, "total": 1}]
        )
        self.assertEqual(
            telemetry.peer_alerts(self.ctx, sample(30), {URI: 10}), []
        )  # no repeat within 6 h
        self.assertEqual(
            telemetry.peer_alerts(self.ctx, sample(95), {URI: 3500}), []
        )  # old drops aged out
        message = telemetry.alert_message(alerts[0])
        self.assertEqual(message["rule"], f"Yggdrasil: пир {URI} нестабилен")
        self.assertIn("3 разрывов за последний час", message["output"])

    @logged
    def test_peer_alert_rule_names_peer(self):
        # The sender suppresses repeats within 300 s by priority and rule[:160]: peers must not share a rule.
        other, long_peer = "tls://192.0.2.7:443", "tls://" + "a" * 200
        for kind, tail in (
            ("ygg-peer-down", "недоступен"),
            ("ygg-peer-unstable", "нестабилен"),
            ("ygg-peer-up", "снова на связи"),
        ):
            alert = {"kind": kind, "peer": URI, "minutes": 10, "count": 3, "up": 5, "total": 6}
            first, again = telemetry.alert_message(alert), telemetry.alert_message(dict(alert))
            second = telemetry.alert_message(dict(alert, peer=other))
            self.assertEqual(first["rule"], f"Yggdrasil: пир {URI} {tail}")
            self.assertEqual(first["rule"], again["rule"])
            self.assertEqual(first["priority"], second["priority"])
            self.assertNotEqual(first["rule"][:160], second["rule"][:160])
            lengthy = telemetry.alert_message(dict(alert, peer=long_peer))["rule"]
            self.assertLessEqual(len(lengthy), 160)
            self.assertIn(long_peer[:120], lengthy)
            bare = {k: v for k, v in alert.items() if k != "peer"}
            self.assertEqual(telemetry.alert_message(bare)["rule"], f"Yggdrasil: пир {tail}")
        self.assertEqual(
            telemetry.alert_message({"kind": "ygg-health", "errors": ["node_inactive"]})["rule"],
            "Yggdrasil: сбой ноды",
        )
        self.assertEqual(
            telemetry.alert_message({"kind": "labelled-local-selftest"})["rule"],
            "Yggdrasil: проверка доставки тревог",
        )

    @logged
    def test_alerts_forward_once_and_retry_failures(self):
        sent, rc = [], [0]

        def runner(argv, **kw):
            if argv[0] == telemetry.SENDER:
                sent.append(json.loads(kw["input"]))
                return subprocess.CompletedProcess(argv, rc[0], b"", b"")
            return self.ctx.runner(argv, **kw)

        ctx = Context(self.paths, runner, require_root=False)
        telemetry.append(
            ctx,
            "alerts.jsonl",
            {"ts": "t0", "kind": "ygg-health", "errors": ["node_inactive"]},
            1000,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(ctx)
            self.assertEqual(sent, [])
            telemetry.append(
                ctx,
                "alerts.jsonl",
                {
                    "ts": "t1",
                    "id": "a1",
                    "kind": "ygg-peer-down",
                    "peer": URI,
                    "minutes": 12,
                    "up": 5,
                    "total": 6,
                },
                1000,
            )
            rc[0] = 75
            with self.assertRaisesRegex(Failure, "alert_forward_failed:count=1"):
                telemetry.forward(ctx)
            rc[0] = 0
            telemetry.forward(ctx)
            telemetry.forward(ctx)
        self.assertEqual(len(sent), 2)
        message = sent[-1]
        self.assertEqual(
            (message["rule"], message["priority"], message["source"]),
            (f"Yggdrasil: пир {URI} недоступен", "Warning", "yggctl"),
        )
        self.assertIn(URI, message["output"])
        self.assertIn("12 мин", message["output"])
        self.assertLessEqual(len(message["output"]), 300)

    @logged
    def test_dispatch_table_rules(self):
        def ns(command, *a, **flags):
            values = {"apply": False, "force": False, "full": False, "recipient": None, **flags}
            return main.argparse.Namespace(command=command, args=list(a), **values)

        for args, label in (
            (ns("check", "x"), "unexpected_arguments"),
            (ns("watch", "1", "2", "3"), "unexpected_arguments"),
            (ns("check", apply=True), "apply_not_supported_here"),
            (ns("remove-peer", "x", force=True), "force_only_for_add_peer"),
            (ns("check", full=True), "backup_options_only"),
            (ns("purge"), "legacy_high_risk_operation_disabled"),
            (ns("no-such-command"), "unknown_command_use_help"),
        ):
            with self.assertRaisesRegex(Failure, label):
                main.dispatch(self.ctx, args)
        nonroot = Context(self.paths, self.ctx.runner, require_root=True)
        with patch("core.os.geteuid", return_value=1000):
            with self.assertRaisesRegex(Failure, "root_required"):
                main.dispatch(nonroot, ns("no-such-command"))
        for word in ("peers", "alerts-forward", "survey", "atlas", "notify"):
            self.assertIn(word, main.COMMANDS)

    @logged
    def test_attached_process_returns_child_status(self):
        import core

        self.assertEqual(core.attached_process(["/bin/sh", "-c", "exit 0"], stop=["/bin/true"]), 0)
        self.assertEqual(core.attached_process(["/bin/sh", "-c", "exit 3"], stop=["/bin/true"]), 3)

    # Audit regressions: journals, independently anchored Mullvad addresses and bootstrap inputs.
    @logged
    def test_journal_message_boundary_masks_secret_forms(self):
        messages = [
            '"PrivateKey": "SYNTHETIC_CANARY"',
            "password=SYNTHETIC_CANARY",
            'token: "escaped\\"SYNTHETIC_CANARY"',
            "Secret:\nSYNTHETIC_CANARY",
            r'{"\u0050rivateKey":"SYNTHETIC_CANARY"}',
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_CANARY\n-----END PRIVATE KEY-----",
        ]
        for message in messages:
            with self.subTest(form=messages.index(message)):
                data = json.dumps({"MESSAGE": message, "_SYSTEMD_UNIT": NODE}).encode()
                value = main.journal_records(data)
                self.assertNotIn("SYNTHETIC_CANARY", json.dumps(value))
                self.assertIn("REDACTED", value[0]["message"])
        safe = main.journal_records(b'{"MESSAGE":"peer connected","__REALTIME_TIMESTAMP":"123"}')[0]
        self.assertEqual(safe["message"], "peer connected")
        self.assertEqual(safe["timestamp_us"], "123")
        self.assertEqual(
            main.journal_records(b'{"MESSAGE":[1,2]}')[0]["message"],
            "[non-text journal message omitted]",
        )

    @logged
    def test_journal_invalid_input_never_printed(self):
        for raw in (b"SYNTHETIC_CANARY", b"[]", b'{"MESSAGE":'):
            with self.assertRaisesRegex(Failure, "invalid_journal_json_no_raw_output"):
                main.journal_records(raw)
        self.assertEqual(main.journal_records(b""), [])

    @logged
    def test_logs_requests_json_and_projects_metadata(self):
        response = subprocess.CompletedProcess(
            [], 0, b'{"MESSAGE":"ok","arbitrary":"SYNTHETIC_CANARY"}', b""
        )
        out = io.StringIO()
        with (
            patch.object(self.ctx, "run", return_value=response) as run,
            contextlib.redirect_stdout(out),
        ):
            main.do_logs(self.ctx, type("Args", (), {"command": "events"})(), ["2"])
        self.assertIn("json", run.call_args.args[0])
        self.assertIn("--since", run.call_args.args[0])
        self.assertNotIn("SYNTHETIC_CANARY", out.getvalue())

    @logged
    def test_policy_two_kernel_proven_tunnel_slots(self):
        ref, _, expected, observed = self.tunnel_fixture()
        with (
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            checks.policy_gate(self.ctx)
        self.assertEqual(read_regular(self.paths.etc / "baseline-nft-mullvad.txt"), ref)
        self.assertEqual(self.address_views, [])

    @logged
    def test_policy_tunnel_wrong_slot_address_verdict_rejected(self):
        ref, cur, _, _ = self.tunnel_fixture()
        for changed in (
            cur.replace(b"fc00::2", b"fc00::3"),
            cur.replace(b"10.147.0.2", b"10.147.0.3"),
            cur.replace(b"fc00::2 drop", b"fc00::2 accept"),
            cur.replace(b"\t\tip daddr 10.147.0.2 drop\n", b""),
        ):
            self.assertFalse(
                checks.relay_display(ref, changed, b"1.1.1.1", ("10.147.0.2", "fc00::2"))
            )
        extra = ref.replace(b"\t\tip6 daddr fc00::1 drop\n", b"\t\tip6 daddr fc00::1 drop\n" * 2)
        with self.assertRaises(Failure):
            checks.relay_display(extra, cur, b"1.1.1.1", ("10.147.0.2", "fc00::2"))

    @logged
    def test_policy_tunnel_kernel_race_rejected(self):
        _, _, expected, observed = self.tunnel_fixture()
        self.address_views[1] = self.address_views[1].replace(b"fc00::2", b"fc00::3")
        with (
            patch("checks.baseline", return_value=expected),
            patch("checks.policy", return_value=observed),
        ):
            with self.assertRaisesRegex(Failure, "mullvad_interface_changed_during_check"):
                checks.policy_gate(self.ctx)

    @logged
    def test_tunnel_interface_schema_rejects_ambiguous_or_wrong_family(self):
        self.tunnel_fixture()
        value = json.loads(self.address_views[0])
        invalid: object
        for invalid in (
            [],
            {},
            value * 2,
            [dict(value[0], ifname="other")],
            [dict(value[0], flags=[])],
            [dict(value[0], addr_info=value[0]["addr_info"][:1])],
            [dict(value[0], addr_info=value[0]["addr_info"] * 2)],
            [
                dict(
                    value[0],
                    addr_info=[
                        dict(value[0]["addr_info"][0], flags=["tentative"]),
                        value[0]["addr_info"][1],
                    ],
                )
            ],
        ):
            with self.assertRaises(Failure):
                checks.tunnel_addresses(json.dumps(invalid).encode())

    @logged
    def test_forward_sigterm_does_not_replay_completed_handoff(self):
        import signal

        self.prepare_forward_pending(2)
        script = """
import sys, os, signal, subprocess
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from core import Context, Paths, logged, trace_quiet
import telemetry
trace_quiet()
calls = []
@logged
def sender(argv, **kwargs):
    calls.append(1)
    if len(calls) == 2:
        os.kill(os.getpid(), signal.SIGTERM)
    return subprocess.CompletedProcess(argv, 0, b'', b'')
telemetry.forward(Context(Paths(state=Path(sys.argv[2])), sender, require_root=False))
"""
        # Security review: fixed interpreter argv exercises the offline error boundary
        result = subprocess.run(  # nosec B603
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                script,
                str(Path(__file__).resolve().parent),
                str(self.paths.state),
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"], ["a0"]
        )
        sent = []

        @logged
        def sender(argv, **kwargs):
            sent.append(json.loads(kwargs["input"])["output"])
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(self.ctx, "runner", sender), contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(self.ctx)
        self.assertEqual(len(sent), 1)
        self.assertIn("a1", sent[0])

    @logged
    def test_forward_budget_leaves_checkpoint_and_retryable_backlog(self):
        self.prepare_forward_pending(5)
        clock, timeouts = [0.0], []

        @logged
        def sender(argv, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += kwargs["timeout"]
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with (
            patch("telemetry.time.monotonic", side_effect=lambda: clock[0]),
            patch.object(self.ctx, "runner", sender),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(Failure, "alert_forward_budget_pending"):
                telemetry.forward(self.ctx)
        self.assertEqual(timeouts, [30, 30, 25])
        self.assertLess(clock[0], 120)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"],
            ["a0", "a1", "a2"],
        )

    @logged
    def test_forward_timeout_checkpoints_prior_success_and_continues(self):
        self.prepare_forward_pending(2)

        @logged
        def sender(argv, **kwargs):
            if "a1" in json.loads(kwargs["input"])["output"]:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(self.ctx, "runner", sender), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(Failure, "alert_forward_failed:count=1"):
                telemetry.forward(self.ctx)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"], ["a0"]
        )

    @logged
    def test_forward_invalid_checkpoint_fails_before_sender(self):
        self.prepare_forward_pending(1)
        for value in ("{}", "[]", '{"sent":"bad"}', '{"sent":[1]}', '{"sent":["a","a"]}'):
            atomic(self.paths.state / "alerts-forwarded.json", value)
            with patch.object(self.ctx, "run") as sender:
                with self.assertRaisesRegex(Failure, "alerts_forwarded_state_invalid"):
                    telemetry.forward(self.ctx)
                sender.assert_not_called()

    @logged
    def test_variable_metric_rows_compact_by_count_not_latest_size(self):
        for last_big in (False, True):
            name = "big-last.jsonl" if last_big else "small-last.jsonl"
            for i in range(7):
                telemetry.append(
                    self.ctx,
                    name,
                    {"i": i, "x": "X" * (5000 if (i == 6) == last_big else 1)},
                    keep=5,
                )
            self.assertEqual([r["i"] for r in telemetry.rows(self.ctx, name)], [2, 3, 4, 5, 6])

    @logged
    def test_append_parallel_calls_serialised_without_lost_rows(self):
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda i: telemetry.append(self.ctx, "parallel.jsonl", {"i": i}), range(40)
                )
            )
        self.assertEqual(
            sorted(r["i"] for r in telemetry.rows(self.ctx, "parallel.jsonl")), list(range(40))
        )

    @logged
    def test_stats_skips_invalid_timestamps_not_corrupt_json(self):
        from core import timestamp

        values = [
            {"ts": timestamp(), "up": 1, "peers": []},
            {"ts": "invalid"},
            {},
            {"ts": "2026-10-18"},
        ]
        atomic(self.paths.state / "metrics.jsonl", "".join(json.dumps(r) + "\n" for r in values))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            telemetry.stats(self.ctx, 1)
        self.assertIn("samples=1 unknown_records=0 invalid_records=3", out.getvalue())
        atomic(self.paths.state / "metrics.jsonl", "{invalid}\n")
        with self.assertRaisesRegex(Failure, "corrupt_metric_record"):
            telemetry.stats(self.ctx)
        atomic(self.paths.state / "metrics.jsonl", '{"ts":"invalid"}\n')
        with self.assertRaisesRegex(Failure, "no_samples_in_window:invalid_records=1"):
            telemetry.stats(self.ctx)

    @logged
    def test_watch_transient_failure_keeps_unknown_and_continues(self):
        out = io.StringIO()
        ps = [{"up": True}]
        with (
            patch("telemetry.peers", side_effect=[Failure("synthetic"), ps, ps, ps, ps]),
            patch("telemetry.time.sleep") as sleep,
            contextlib.redirect_stdout(out),
        ):
            with self.assertRaisesRegex(Failure, "watch_samples_failed:count=1"):
                telemetry.watch(self.ctx, 3, 1)
        self.assertEqual(sleep.call_count, 2)
        self.assertIn("[1/3] node_up=unknown stack_up=unknown errors=1", out.getvalue())
        self.assertIn("[3/3] node_up=1 stack_up=1 errors=1", out.getvalue())
        self.assertIn("processed=3 errors=1", out.getvalue())

    @logged
    def test_wait_peers_respects_desired_and_paired_health(self):
        up = [{"remote": URI.replace("192.0.2.1", f"192.0.2.{i}"), "up": True} for i in (1, 2)]
        desired = "192.0.2.1:443"
        with patch("management.peers", return_value=up):
            management.wait_peers(self.ctx, desired, seconds=0)
            with self.assertRaisesRegex(Failure, "peer_convergence_timeout"):
                management.wait_peers(self.ctx, "192.0.2.3:443", seconds=0)
            with self.assertRaisesRegex(Failure, "peer_convergence_timeout"):
                management.wait_peers(self.ctx, desired, seconds=0, absent=True)
            management.wait_peers(self.ctx, "192.0.2.3:443", seconds=0, absent=True)
        with patch("management.peers", side_effect=lambda ctx, stack: [] if stack else up):
            with self.assertRaisesRegex(Failure, "peer_convergence_timeout"):
                management.wait_peers(self.ctx, seconds=0)

    @logged
    def test_mutation_lock_timeout_releases_depth_and_fd(self):
        with (
            patch("core.fcntl.flock", side_effect=BlockingIOError),
            patch("core.time.monotonic", side_effect=[0.0, 21.0]),
            patch("core.time.sleep"),
        ):
            with self.assertRaisesRegex(Failure, "mutation_lock_timeout"):
                with self.ctx.locked():
                    self.fail("must not enter")
        self.assertEqual(self.ctx.lock_depth, 0)
        with self.ctx.locked():
            self.assertEqual(self.ctx.lock_depth, 1)
        self.assertEqual(self.ctx.lock_depth, 0)

    @logged
    def test_append_new_error_paths_fail_closed(self):
        import stat
        import types

        for keep in (0, True, 10001, "2"):
            with self.assertRaisesRegex(Failure, "invalid_metric_retention"):
                telemetry.append(self.ctx, "error.jsonl", {}, keep=keep)
        with patch("telemetry.os.write", return_value=0):
            with self.assertRaisesRegex(Failure, "metric_append_no_progress"):
                telemetry.append(self.ctx, "error.jsonl", {})
        with patch("telemetry.os.pread", return_value=b""):
            with self.assertRaisesRegex(Failure, "metric_file_changed_during_count"):
                telemetry.metric_records(-1, 1)
        # Preserve _locked's real fstat; only append's metric descriptor is changed.
        original = os.fstat

        @logged
        def oversize(fd):
            info = original(fd)
            if (self.paths.state / "error.jsonl").stat().st_ino == info.st_ino:
                return types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=32 * 1024 * 1024)
            return info

        with patch("telemetry.os.fstat", side_effect=oversize):
            with self.assertRaisesRegex(Failure, "metric_file_size_limit"):
                telemetry.append(self.ctx, "error.jsonl", {})
        self.assertEqual((self.paths.state / "error.jsonl").read_bytes(), b"")

    @logged
    def test_forward_budget_includes_lock_wait(self):
        self.prepare_forward_pending(5)
        clock, timeouts = [0.0], []
        locked = self.ctx.locked

        @contextlib.contextmanager
        @logged
        def delayed_lock():
            clock[0] += 20
            with locked():
                yield

        @logged
        def sender(argv, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += kwargs["timeout"]
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with (
            patch("telemetry.time.monotonic", side_effect=lambda: clock[0]),
            patch.object(self.ctx, "locked", delayed_lock),
            patch.object(self.ctx, "runner", sender),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(Failure, "alert_forward_budget_pending"):
                telemetry.forward(self.ctx)
        self.assertEqual(timeouts, [30, 30, 5])
        self.assertEqual(clock[0], 85)

    @logged
    def test_forward_bad_alert_ids_rejected_and_initial_duplicates_coalesced(self):
        for aid in ("", "a" * 129, 12, None):
            with self.assertRaisesRegex(Failure, "invalid_alert_id"):
                telemetry.alert_id({"id": aid})
        alert = {"kind": "synthetic"}
        atomic(self.paths.state / "alerts.jsonl", (json.dumps(alert) + "\n") * 2)
        with contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(self.ctx)
        sent = json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"]
        self.assertEqual(len(sent), 1)
        with patch.object(self.ctx, "run") as sender, contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(self.ctx)
            sender.assert_not_called()


@logged
def run_suite():
    # Negative tests raise expected errors; keep them out of syslog unless the run fails.
    import core

    core.trace_quiet()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ConsoleTests)
    print(
        f"[1/1] offline regressions total={suite.countTestCases()} remaining={suite.countTestCases()}"
    )
    start = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        f"processed={result.testsRun} errors={len(result.errors) + len(result.failures)} remaining=0 elapsed={time.monotonic() - start:.2f}s"
    )
    if not result.wasSuccessful():
        raise Failure("offline_selftest_failed")


if __name__ == "__main__":
    run_suite()
