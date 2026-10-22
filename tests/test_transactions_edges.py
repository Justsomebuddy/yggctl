"""Synthetic transaction/service convergence and encrypted-backup boundaries."""

import contextlib
import io
import json
from pathlib import Path
from unittest.mock import Mock, patch

from core import Failure, NODE, STACK, atomic, digest, logged
import management as mg
import recovery as rc
from test_support import ConsoleFixture, URI


class TransactionEdges(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_rotation_pending_and_transaction_path_guard(self):
        path = self.paths.state / "rotation.json"
        atomic(path, "{}")
        with self.assertRaisesRegex(Failure, "identity_recovery_required"):
            mg.identity_gate(self.ctx)
        path.unlink()
        with self.assertRaisesRegex(Failure, "transaction_path_not_allowed"):
            mg.transaction(self.ctx, {self.paths.etc / "other": "no"}, Mock(), Mock())

    @logged
    def test_peer_edit_preview_apply_and_compensation_contracts(self):
        with self.assertRaisesRegex(Failure, "expected_ipv4_port"):
            mg.change_peer(self.ctx, "bad", remove=True)
        with self.assertRaisesRegex(Failure, "endpoint_missing_or_ambiguous"):
            mg.change_peer(self.ctx, "192.0.2.9:443", remove=True)
        for name in ("yggdrasil-lab.conf", "yggstack.conf"):
            config = self.ctx.config(name)
            config["Peers"] = config["Peers"][:2]
            atomic(self.paths.etc / name, json.dumps(config))
        with self.assertRaisesRegex(Failure, "retain_at_least_two"):
            mg.change_peer(self.ctx, "192.0.2.1:443", remove=True)
        for name in ("yggdrasil-lab.conf", "yggstack.conf"):
            config = self.ctx.config(name)
            config["Peers"].append(URI.replace("192.0.2.1", "192.0.2.3"))
            atomic(self.paths.etc / name, json.dumps(config))
        mg.change_peer(self.ctx, "192.0.2.1:443", remove=True)
        with (
            patch.object(mg, "transaction") as transaction,
            patch.object(mg, "runtime_peers") as runtime,
            patch.object(mg, "restart_pair") as restart,
        ):
            for remove, value, method in (
                (False, URI.replace("192.0.2.1", "192.0.2.4"), "addpeer"),
                (True, "192.0.2.1:443", "removepeer"),
            ):
                mg.change_peer(self.ctx, value, remove=remove, apply=True)
                args = transaction.call_args.args
                self.assertEqual(len(args[1]), 4)
                args[2]()
                args[3]()
                self.assertEqual(runtime.call_args.args[1], method)
            self.assertEqual(restart.call_count, 2)
        with patch.object(mg, "wait_peers") as wait:
            mg.runtime_peers(self.ctx, "removepeer", [URI, URI], "192.0.2.1:443")
            wait.assert_called_once_with(self.ctx, "192.0.2.1:443", absent=True)

    @logged
    def test_peer_wait_progress_timeout_and_absence(self):
        rows = [dict(self.ps[0]), dict(self.ps[0], remote=URI.replace("192.0.2.1", "192.0.2.2"))]
        with patch.object(mg, "peers", return_value=rows):
            mg.wait_peers(self.ctx)
            mg.wait_peers(self.ctx, "192.0.2.1:443")
            mg.wait_peers(self.ctx, "192.0.2.9:443", absent=True)
        with (
            patch.object(mg, "peers", side_effect=[[], [], rows, rows]),
            patch.object(mg.time, "sleep") as sleep,
        ):
            mg.wait_peers(self.ctx)
            sleep.assert_called_once_with(2)
        with (
            patch.object(mg, "peers", return_value=[]),
            patch.object(mg.time, "monotonic", side_effect=[0, 30]),
            self.assertRaisesRegex(Failure, "peer_convergence_timeout"),
        ):
            mg.wait_peers(self.ctx)

    @logged
    def test_mode_change_exact_and_preview_apply(self):
        with self.assertRaisesRegex(Failure, "invalid_mode"):
            mg.change_mode(self.ctx, "invalid")
        with patch.object(mg, "underlay", return_value={}) as proof:
            mg.change_mode(self.ctx, "direct")
            proof.assert_called_once_with(self.ctx)
        with (
            patch.object(mg, "transaction") as transaction,
            patch.object(mg, "restart_pair") as restart,
            patch.object(mg, "underlay") as proof,
        ):
            mg.change_mode(self.ctx, "tunnel")
            transaction.assert_not_called()
            mg.change_mode(self.ctx, "tunnel", True)
            args = transaction.call_args.args
            self.assertEqual(args[1], {self.paths.etc / "mode": "tunnel\n"})
            args[2]()
            args[3]()
            self.assertEqual(restart.call_count, 2)
            proof.assert_called_once_with(self.ctx)
        with patch.object(mg, "wait_peers") as wait:
            mg.restart_pair(self.ctx)
            wait.assert_called_once_with(self.ctx)
            self.assertEqual(self.calls[-1], ["/usr/bin/systemctl", "restart", NODE, STACK])

    @logged
    def test_service_action_whitelist_and_convergence(self):
        with self.assertRaisesRegex(Failure, "invalid_service_action"):
            mg.service(self.ctx, "destroy")
        rows = [dict(self.ps[0]), dict(self.ps[0], remote=URI.replace("192.0.2.1", "192.0.2.2"))]
        for command in ("start", "stack-restart", "stop", "enable", "stack-disable"):
            with patch.object(mg, "peers", return_value=rows):
                mg.service(self.ctx, command)
                self.assertIn(STACK if command.startswith("stack-") else NODE, self.calls[-1])
        with (
            patch.object(mg, "peers", side_effect=[[], rows]),
            patch.object(mg.time, "sleep") as sleep,
        ):
            mg.service(self.ctx, "start")
            sleep.assert_called_once_with(2)
        with (
            patch.object(mg, "peers", return_value=[]),
            patch.object(mg.time, "monotonic", side_effect=[0, 0, 0, 0, 30]),
            patch.object(mg.time, "sleep"),
            self.assertRaises(Failure),
        ):
            mg.service(self.ctx, "start")

    @logged
    def test_recovery_journal_schema_preview_and_apply(self):
        path = self.paths.state / "transaction.json"
        value: object
        for value in (
            [],
            {},
            {"old": {}},
            {"old": {"/outside": "no"}},
            {"old": {str(self.paths.etc / "mode"): 7}},
        ):
            atomic(path, json.dumps(value))
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(Failure, "invalid_recovery_journal"),
            ):
                mg.recover_transaction(self.ctx)
        atomic(path, json.dumps({"old": {str(self.paths.etc / "mode"): "direct\n"}}))
        mg.recover_transaction(self.ctx)
        self.assertTrue(path.exists())
        with (
            patch.object(mg, "restart_pair") as restart,
            patch.object(mg, "underlay") as proof,
        ):
            mg.recover_transaction(self.ctx, True)
            restart.assert_called_once_with(self.ctx)
            proof.assert_called_once_with(self.ctx)
        self.assertFalse(path.exists())
        self.assertEqual(len(list(self.paths.state.glob("recovered-*.json"))), 1)


class RecoveryEdges(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_backup_custody_permissions_and_fingerprint(self):
        with (
            patch.object(self.ctx, "config", return_value={}),
            self.assertRaisesRegex(Failure, "unsafe_config_backup"),
        ):
            rc.members(self.ctx)
        self.assertTrue(any(k.startswith("keys/") for k in rc.members(self.ctx, True)))
        with self.assertRaisesRegex(Failure, "recipient_requires_full"):
            rc.backup(self.ctx, recipient="1" * 40)
        folder = self.paths.state / "backups"
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        with self.assertRaisesRegex(Failure, "backup_directory_not_private"):
            rc.backup(self.ctx)
        folder.chmod(0o700)
        full_members = rc.members(self.ctx, True)
        with (
            patch.object(rc, "members", return_value=full_members),
            patch.object(self.ctx, "run", return_value=Mock(stdout=b"")),
            self.assertRaisesRegex(Failure, "recipient_fingerprint_not_found"),
        ):
            rc.backup(self.ctx, True, "1" * 40)
        key = ":".join(["fpr"] + [""] * 8 + ["1" * 40, ""]).encode()
        with (
            patch.object(rc, "members", return_value=full_members),
            patch.object(
                self.ctx, "run", side_effect=[Mock(stdout=key), Mock(stdout=b"encrypted-fixture")]
            ) as run,
        ):
            out = rc.backup(self.ctx, True, "1" * 40)
            self.assertTrue(out.name.endswith(".tar.gz.gpg"))
            self.assertEqual(out.read_bytes(), b"encrypted-fixture")
            self.assertEqual(run.call_args.args[0][-1], "1" * 40)
            self.assertTrue(run.call_args.kwargs["input"].startswith(b"\x1f\x8b"))

    @logged
    def save_archive(self, files, full=False, suffix=".tar.gz"):
        path = self.paths.state / ("input" + suffix)
        data = rc.archive(files, full)
        atomic(path, data)
        atomic(Path(str(path) + ".sha256"), digest(data))
        return path

    @logged
    def test_restore_review_boundaries_and_encrypted_preview(self):
        original = rc.members(self.ctx)
        for field, data, label in (
            ("config/mode", b"tunnel\n", "restore_underlay_change"),
            ("units/" + NODE, b"changed", "restore_unit_change"),
            ("config/yggdrasil-lab.conf", b"{}", "restore_unsafe_config"),
        ):
            path = self.save_archive(dict(original, **{field: data}))
            with self.subTest(field=field), self.assertRaisesRegex(Failure, label):
                rc.restore(self.ctx, path)
        path = self.save_archive(rc.members(self.ctx, True), True)
        with self.assertRaisesRegex(Failure, "encrypted_custody_verified"):
            rc.restore(self.ctx, path)
        path = self.save_archive(original)
        atomic(Path(str(path) + ".sha256"), "wrong")
        with self.assertRaisesRegex(Failure, "archive_digest_mismatch"):
            rc.restore(self.ctx, path)
        path = self.save_archive(original, suffix=".gpg")
        with patch.object(self.ctx, "run", wraps=self.ctx.run) as run:
            # Return plaintext archive only for the synthetic decrypt call.
            previous = self.ctx.runner

            @logged
            def decrypt(argv, **kw):
                result = previous(argv, **kw)
                if argv[0] == "/usr/bin/gpg":
                    result.stdout = kw["input"]
                return result

            self.ctx.runner = decrypt
            rc.restore(self.ctx, path)
            self.assertTrue(any(c.args[0][0] == "/usr/bin/gpg" for c in run.call_args_list))

    @logged
    def test_snapshot_diff_explicit_latest_and_missing(self):
        with self.assertRaisesRegex(Failure, "no_snapshot"):
            rc.diff(self.ctx)
        path = rc.snapshot(self.ctx)
        rc.diff(self.ctx)
        rc.diff(self.ctx, str(path))
        atomic(self.paths.etc / "mode", "tunnel\n")
        with self.assertRaisesRegex(Failure, "snapshot_diff_detected"):
            rc.diff(self.ctx, path)
