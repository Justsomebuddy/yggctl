"""Isolated rollback/recovery underlay proofs; no service or network execution."""

import contextlib
import io
import json
from unittest.mock import Mock, patch

from core import Failure, atomic, logged, read_regular
import management as mg
from test_support import ConsoleFixture


class CompensationProofTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.pending = self.paths.state / "transaction.json"
        self.mode = self.paths.etc / "mode"
        self.manifest = self.paths.etc / "integrity.manifest"

    @logged
    def journal(self, mode="direct"):
        record = {
            "schema": 1,
            "phase": "rollback_runtime_failed",
            "old": {
                str(self.mode): mode + "\n",
                str(self.manifest): self.manifest.read_text(),
            },
        }
        atomic(self.pending, json.dumps(record))
        return read_regular(self.pending)

    @logged
    def test_compensation_proves_restored_mode_and_manifest_before_journal_removal(self):
        for old_mode, new_mode in (("direct", "tunnel"), ("tunnel", "direct")):
            with self.subTest(old_mode=old_mode):
                atomic(self.mode, old_mode + "\n")
                original_manifest = read_regular(self.manifest)
                primary = Failure("synthetic_action_failure")
                order = []

                @logged
                def compensate():
                    order.append("compensate")
                    self.assertEqual(self.ctx.mode(), old_mode)
                    self.assertEqual(read_regular(self.manifest), original_manifest)
                    self.assertTrue(self.pending.exists())

                @logged
                def proof(ctx):
                    order.append("proof")
                    self.assertIs(ctx, self.ctx)
                    self.assertEqual(ctx.mode(), old_mode)
                    self.assertTrue(self.pending.exists())

                with (
                    patch.object(mg, "underlay", side_effect=proof) as underlay,
                    patch.object(mg, "event") as event,
                    self.assertRaises(Failure) as caught,
                ):
                    mg.transaction(
                        self.ctx,
                        {self.mode: new_mode + "\n"},
                        Mock(side_effect=primary),
                        compensate,
                    )
                self.assertIs(caught.exception, primary)
                self.assertIsNone(primary.__cause__)
                self.assertEqual(order, ["compensate", "proof"])
                underlay.assert_called_once_with(self.ctx)
                event.assert_any_call("state", "transaction", "verifying_rollback_underlay")
                event.assert_any_call("state", "transaction", "rolled_back")
                self.assertFalse(self.pending.exists())

    @logged
    def test_proof_failures_retain_journal_and_primary_exception_without_recursive_undo(self):
        for error in (
            Failure("synthetic_mismatch"),
            RuntimeError("SECRET_DO_NOT_LOG"),
            KeyboardInterrupt(),
            SystemExit(2),
        ):
            with self.subTest(error=type(error).__name__):
                primary = Failure("synthetic_action_failure")
                compensate = Mock()
                with (
                    patch.object(mg, "underlay", side_effect=error) as proof,
                    patch.object(mg, "event") as event,
                    self.assertRaises(Failure) as caught,
                ):
                    mg.transaction(
                        self.ctx, {self.mode: "tunnel\n"}, Mock(side_effect=primary), compensate
                    )
                self.assertIs(caught.exception, primary)
                self.assertIs(primary.__cause__, error)
                compensate.assert_called_once_with()
                proof.assert_called_once_with(self.ctx)
                record = json.loads(read_regular(self.pending))
                self.assertEqual(record["phase"], "rollback_runtime_failed")
                self.assertEqual(record["old"][str(self.mode)], "direct\n")
                self.assertNotIn("SECRET_DO_NOT_LOG", read_regular(self.pending).decode())
                event.assert_any_call("error", "transaction", "rollback_runtime_failed")
                self.assertNotIn("SECRET_DO_NOT_LOG", repr(event.call_args_list))
                self.assertNotIn("rolled_back", [call.args[-1] for call in event.call_args_list])
                with self.assertRaisesRegex(Failure, "unfinished_transaction"):
                    mg.transaction(self.ctx, {self.mode: "tunnel\n"}, Mock(), Mock())
                self.pending.unlink()

    @logged
    def test_compensation_failure_skips_proof_and_retains_primary(self):
        primary, secondary = Failure("synthetic_primary"), Failure("synthetic_restart_failure")
        with (
            patch.object(mg, "underlay") as proof,
            self.assertRaises(Failure) as caught,
        ):
            mg.transaction(
                self.ctx,
                {self.mode: "tunnel\n"},
                Mock(side_effect=primary),
                Mock(side_effect=secondary),
            )
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, secondary)
        proof.assert_not_called()
        self.assertEqual(json.loads(read_regular(self.pending))["phase"], "rollback_runtime_failed")

    @logged
    def test_hidden_adapter_failure_detected_and_recovery_retry_requires_new_proof(self):
        # Fixture adapter always reports direct exclusions. Restoring a tunnel file
        # and a successful restart therefore must NOT be accepted as tunnel proof.
        atomic(self.mode, "tunnel\n")
        primary = Failure("synthetic_new_mode_observation_failure")
        with (
            patch.object(mg, "mode_action", side_effect=primary),
            patch.object(mg, "restart_pair") as restart,
            self.assertRaises(Failure) as caught,
        ):
            mg.change_mode(self.ctx, "direct", apply=True)
        self.assertIs(caught.exception, primary)
        self.assertEqual(str(primary.__cause__), "underlay_pid_exclusion_mismatch")
        restart.assert_called_once_with(self.ctx)
        self.assertEqual(self.ctx.mode(), "tunnel")
        self.assertTrue(self.pending.exists())
        retained = read_regular(self.pending)
        with (
            patch.object(mg, "restart_pair"),
            self.assertRaisesRegex(Failure, "underlay_pid_exclusion_mismatch"),
        ):
            mg.recover_transaction(self.ctx, apply=True)
        self.assertEqual(read_regular(self.pending), retained)
        self.assertEqual(list(self.paths.state.glob("recovered-*.json")), [])
        original_runner = self.ctx.runner

        @logged
        def tunnel_runner(argv, **kwargs):
            result = original_runner(argv, **kwargs)
            if argv[0] == "/usr/bin/mullvad":
                result.stdout = b"Excluded PIDs:\n"
            elif argv[0] == "/usr/sbin/conntrack":
                result.stdout = result.stdout.replace(b"mark=3905", b"mark=0")
            return result

        self.ctx.runner = tunnel_runner
        with patch.object(mg, "wait_peers"):
            mg.recover_transaction(self.ctx, apply=True)
        self.assertFalse(self.pending.exists())
        archives = list(self.paths.state.glob("recovered-*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(read_regular(archives[0]), retained)
        self.assertEqual(self.ctx.mode(), "tunnel")
        self.assertTrue(any(c[0] == "/usr/sbin/conntrack" for c in self.calls))

    @logged
    def test_peer_edit_compensation_restores_exact_files_before_underlay_proof(self):
        names = (
            "yggdrasil-lab.conf",
            "yggstack.conf",
            "gate.nft",
            "gate-yggstack.nft",
            "integrity.manifest",
        )
        old = {name: read_regular(self.paths.etc / name) for name in names}
        primary = Failure("synthetic_peer_api_failure")
        actual_proof = mg.underlay

        @logged
        def proof(ctx):
            self.assertEqual({name: read_regular(self.paths.etc / name) for name in names}, old)
            self.assertTrue(self.pending.exists())
            return actual_proof(ctx)

        with (
            patch.object(mg, "runtime_peers", side_effect=primary) as runtime,
            patch.object(mg, "restart_pair") as restart,
            patch.object(mg, "underlay", side_effect=proof) as underlay,
            self.assertRaises(Failure) as caught,
        ):
            mg.change_peer(self.ctx, "192.0.2.1:443", remove=True, apply=True)
        self.assertIs(caught.exception, primary)
        runtime.assert_called_once()
        restart.assert_called_once_with(self.ctx)
        underlay.assert_called_once_with(self.ctx)
        self.assertFalse(self.pending.exists())

    @logged
    def test_recovery_preview_and_proof_order_before_archival(self):
        retained = self.journal()
        atomic(self.mode, "tunnel\n")
        with (
            patch.object(mg, "restart_pair") as restart,
            patch.object(mg, "underlay") as proof,
        ):
            mg.recover_transaction(self.ctx)
            restart.assert_not_called()
            proof.assert_not_called()
        self.assertEqual(self.ctx.mode(), "tunnel")
        self.assertEqual(read_regular(self.pending), retained)
        order = []

        @logged
        def check_stage(name):
            order.append(name)
            self.assertTrue(self.pending.exists())
            self.assertEqual(self.ctx.mode(), "direct")

        with (
            patch.object(mg, "restart_pair", side_effect=lambda ctx: check_stage("restart")),
            patch.object(mg, "integrity", side_effect=lambda ctx: check_stage("integrity")),
            patch.object(mg, "underlay", side_effect=lambda ctx: check_stage("proof")),
            patch.object(mg, "event") as event,
        ):
            mg.recover_transaction(self.ctx, True)
        self.assertEqual(order, ["restart", "integrity", "proof"])
        self.assertFalse(self.pending.exists())
        event.assert_any_call("state", "recovery", "verifying_underlay")
        event.assert_any_call("state", "recovery", "restored")

    @logged
    def test_recovery_failure_at_every_gate_retains_retryable_journal(self):
        for stage in ("restart_pair", "integrity", "underlay"):
            with self.subTest(stage=stage):
                retained = self.journal()
                failure = Failure("synthetic_recovery_failure")
                with (
                    patch.object(mg, "restart_pair") as restart,
                    patch.object(mg, "integrity") as integrity,
                    patch.object(mg, "underlay") as proof,
                    patch.object(mg, stage, side_effect=failure),
                    patch.object(mg, "event") as event,
                    self.assertRaises(Failure) as caught,
                ):
                    mg.recover_transaction(self.ctx, True)
                self.assertIs(caught.exception, failure)
                self.assertEqual(read_regular(self.pending), retained)
                self.assertEqual(list(self.paths.state.glob("recovered-*.json")), [])
                self.assertNotIn("restored", [call.args[-1] for call in event.call_args_list])
                if stage == "restart_pair":
                    integrity.assert_not_called()
                    proof.assert_not_called()
                elif stage == "integrity":
                    restart.assert_called_once_with(self.ctx)
                    proof.assert_not_called()
                else:
                    restart.assert_called_once_with(self.ctx)
                    integrity.assert_called_once_with(self.ctx)
