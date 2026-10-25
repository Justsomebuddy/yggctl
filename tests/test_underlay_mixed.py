"""Configured TCP peer contradictions must not hide behind a good sibling flow."""

import contextlib
import io
import json
from pathlib import Path
from unittest.mock import patch

import checks
import management
from core import Failure, atomic, logged
from test_support import ConsoleFixture, PIN


class UnderlayMixedTests(ConsoleFixture):
    @logged
    def test_socks_client_endpoint_collision_is_not_outbound_peer(self):
        config = self.ctx.config("yggstack.conf")
        config["Peers"].append("tcp://127.0.0.1:42000?key=" + PIN)
        atomic(self.paths.etc / "yggstack.conf", json.dumps(config))
        old = self.ctx.runner

        @logged
        def runner(argv, **kw):
            result = old(argv, **kw)
            if Path(argv[0]).name == "ss":
                result.stdout += b'\ntcp ESTAB 0 0 127.0.0.1:1080 127.0.0.1:42000 users:(("stack",pid=1002,fd=9))'
            elif Path(argv[0]).name == "conntrack":
                result.stdout += b"\ntcp 6 100 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=42000 dport=1080 src=127.0.0.1 dst=127.0.0.1 sport=1080 dport=42000 mark=0 use=1"
            return result

        self.ctx.runner = runner
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])

    @logged
    def test_mixed_compensation_retains_journal_until_repaired(self):
        self.install()
        primary = Failure("synthetic_action_failure")

        @logged
        def action():
            raise primary

        with self.assertRaises(Failure) as caught:
            management.transaction(
                self.ctx, {self.paths.etc / "mode": "direct\n"}, action, lambda: None
            )
        self.assertIs(caught.exception, primary)
        self.assertEqual(str(caught.exception.__cause__), "underlay_peer_mark_mismatch")
        pending = self.paths.state / "transaction.json"
        self.assertEqual(json.loads(pending.read_text())["phase"], "rollback_runtime_failed")
        retained = pending.read_bytes()
        with patch.object(management, "restart_pair"):
            with self.assertRaisesRegex(Failure, "underlay_peer_mark_mismatch"):
                management.recover_transaction(self.ctx, apply=True)
            self.assertEqual(pending.read_bytes(), retained)
            old = self.ctx.runner

            @logged
            def repaired(argv, **kw):
                result = old(argv, **kw)
                if Path(argv[0]).name == "conntrack":
                    result.stdout = result.stdout.replace(b"mark=0 ", b"mark=3905 ")
                return result

            self.ctx.runner = repaired
            management.recover_transaction(self.ctx, apply=True)
        self.assertFalse(pending.exists())
        archives = list(self.paths.state.glob("recovered-*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), retained)

    @logged
    def install(self, mode="direct", mark=0, extra_socket=True, extra_rows=None):
        old = self.ctx.runner

        @logged
        def runner(argv, **kw):
            result = old(argv, **kw)
            name = Path(argv[0]).name
            if name == "mullvad" and mode == "tunnel":
                result.stdout = b""
            if name == "ss" and extra_socket:
                result.stdout += (
                    b'\ntcp ESTAB 0 0 10.0.0.2:41001 192.0.2.2:443 users:(("ygg",pid=1001,fd=9))'
                )
            if name == "conntrack":
                result.stdout += (
                    "\ntcp 6 100 ESTABLISHED src=10.0.0.2 dst=192.0.2.2 sport=41001 dport=443 "
                    "src=192.0.2.2 dst=10.0.0.2 sport=443 dport=41001 "
                    + (f"mark={mark}" if mark is not None else "")
                    + " use=1"
                ).encode()
                if extra_rows is not None:
                    result.stdout = extra_rows(result.stdout)
            return result

        self.ctx.runner = runner
        self.mode_patch = patch.object(self.ctx, "mode", return_value=mode)
        self.mode_patch.start()
        self.addCleanup(self.mode_patch.stop)

    @logged
    def test_direct_mixed_marks_refuse_unchanged_mode(self):
        self.install()
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(Failure, "underlay_peer_mark_mismatch"),
        ):
            management.change_mode(self.ctx, "direct")
        self.assertNotIn("runtime proof verified", output.getvalue())

    @logged
    def test_tunnel_good_sibling_cannot_hide_direct_mark(self):
        self.install(mode="tunnel", mark=0)
        with self.assertRaisesRegex(Failure, "underlay_peer_mark_mismatch"):
            checks.underlay(self.ctx)

    @logged
    def test_consistent_marks_and_nonzero_tunnel_mark(self):
        for mode, mark in (("direct", 3905), ("tunnel", 42)):
            with self.subTest(mode=mode):
                self.ctx.runner = self.runner
                self.install(
                    mode=mode,
                    mark=mark,
                    extra_rows=lambda b: b.replace(b"mark=3905", f"mark={mark}".encode()),
                )
                self.assertEqual(checks.underlay(self.ctx)["own_connections"], [2, 1])

    @logged
    def test_missing_mark_or_record_cannot_hide_behind_good_sibling(self):
        for transform in (lambda b: b, lambda b: b.rsplit(b"\n", 1)[0]):
            with self.subTest(transform=transform):
                self.ctx.runner = self.runner
                self.install(mark=None, extra_rows=transform)
                with self.assertRaisesRegex(Failure, "underlay_peer_socket_proof_missing"):
                    checks.underlay(self.ctx)

    @logged
    def test_reply_tuple_and_stale_tcp_record_are_not_outbound_proof(self):
        for replacement in (
            b"tcp 6 100 ESTABLISHED src=192.0.2.2 dst=10.0.0.2 sport=443 dport=41001 src=10.0.0.2 dst=192.0.2.2 sport=41001 dport=443 mark=3905 use=1",
            b"tcp 6 100 TIME_WAIT src=10.0.0.2 dst=192.0.2.2 sport=41001 dport=443 mark=3905 use=1",
            b"udp 17 100 src=10.0.0.2 dst=192.0.2.2 sport=41001 dport=443 mark=3905 use=1",
            b"tcp 6 100 ESTABLISHED malformed mark=3905 use=1",
        ):
            with self.subTest(replacement=replacement):
                self.ctx.runner = self.runner
                self.install(extra_rows=lambda b: b.rsplit(b"\n", 1)[0] + b"\n" + replacement)
                with self.assertRaisesRegex(Failure, "underlay_peer_socket_proof_missing"):
                    checks.underlay(self.ctx)

    @logged
    def test_unrelated_conntrack_does_not_change_result(self):
        self.install(extra_socket=False)
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])

    @logged
    def test_unrelated_socket_does_not_supply_missing_proof(self):
        old = self.ctx.runner

        @logged
        def runner(argv, **kw):
            result = old(argv, **kw)
            if Path(argv[0]).name == "ss":
                result.stdout = result.stdout.replace(b"192.0.2.1", b"192.0.2.250")
            return result

        self.ctx.runner = runner
        with self.assertRaisesRegex(Failure, "underlay_own_socket_proof_missing"):
            checks.underlay(self.ctx)

    @logged
    def test_local_socks_inbound_and_foreign_socket_do_not_trigger_peer_failure(self):
        self.install(mark=0)
        old = self.ctx.runner

        @logged
        def runner(argv, **kw):
            result = old(argv, **kw)
            if Path(argv[0]).name == "ss":
                result.stdout = result.stdout.replace(b"192.0.2.2:443", b"127.0.0.1:50000")
                result.stdout += b'\ntcp ESTAB 0 0 10.0.0.2:41001 192.0.2.2:443 users:(("other",pid=9999,fd=9))\ntcp LISTEN 0 0 10.0.0.2:41001 192.0.2.2:443 pid=1001,'
            return result

        self.ctx.runner = runner
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])

    @logged
    def test_duplicate_disagreeing_evidence_refuses(self):
        self.install(
            mark=3905,
            extra_rows=lambda b: b + b"\n" + b.rsplit(b"\n", 1)[1].replace(b"mark=3905", b"mark=0"),
        )
        with self.assertRaisesRegex(Failure, "underlay_peer_mark_mismatch"):
            checks.underlay(self.ctx)
