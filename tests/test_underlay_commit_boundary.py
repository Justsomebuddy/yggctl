"""Independent final-sample and compensation contract; no live processes/network."""

import contextlib
import io
import json
from unittest.mock import patch

import checks
import management as mg
from core import Failure, atomic, logged, read_regular
from test_support import ConsoleFixture


class UnderlayCommitBoundary(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.original_runner = self.ctx.runner
        self.split_reads = 0
        self.refuse_final = False
        self.ctx.runner = self.mode_runner

    @logged
    def mode_runner(self, argv, **kwargs):
        result = self.original_runner(argv, **kwargs)
        if argv[0] == "/usr/bin/mullvad":
            self.split_reads += 1
            direct = self.ctx.mode() == "direct"
            if self.refuse_final and self.split_reads % 2 == 0:
                direct = not direct
            # Header numbers and unrelated exclusions are not service PID evidence.
            result.stdout = b"Excluded PIDs (999):\n 9000\n"
            if direct:
                result.stdout += b" 1002 \n\t1001\n"
        elif argv[0] == "/usr/sbin/conntrack" and self.ctx.mode() == "tunnel":
            result.stdout = result.stdout.replace(b"mark=3905", b"mark=0")
        return result

    @logged
    def test_both_stable_modes_ignore_order_noise_and_unrelated_exclusions(self):
        for mode in ("direct", "tunnel"):
            with self.subTest(mode=mode):
                atomic(self.paths.etc / "mode", mode + "\n")
                self.split_reads = 0
                self.assertEqual(
                    checks.underlay(self.ctx), {"mode": mode, "own_connections": [1, 1]}
                )
                self.assertEqual(self.split_reads, 2)

    @logged
    def test_final_exclusion_drift_in_new_mode_restores_old_mode_with_new_proof(self):
        atomic(self.paths.etc / "mode", "tunnel\n")
        manifest = read_regular(self.paths.etc / "integrity.manifest")
        original = self.mode_runner

        @logged
        def runner(argv, **kwargs):
            # Reject just the action's final read; the restored old mode must be
            # checked afresh, rather than inheriting the failed action's proof.
            self.refuse_final = self.split_reads < 2
            return original(argv, **kwargs)

        self.ctx.runner = runner
        with (
            patch.object(mg, "restart_pair") as restart,
            self.assertRaisesRegex(Failure, "^underlay_pid_exclusion_mismatch$"),
        ):
            mg.change_mode(self.ctx, "direct", apply=True)
        self.assertEqual(self.split_reads, 4)
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(self.ctx.mode(), "tunnel")
        self.assertEqual(read_regular(self.paths.etc / "integrity.manifest"), manifest)
        self.assertFalse((self.paths.state / "transaction.json").exists())
        self.assertEqual(list(self.paths.state.glob("transaction-*.json")), [])

    @logged
    def test_failed_restored_final_proof_and_recovery_keep_exact_retry_journal(self):
        atomic(self.paths.etc / "mode", "tunnel\n")
        self.refuse_final = True
        pending = self.paths.state / "transaction.json"
        with (
            patch.object(mg, "restart_pair"),
            self.assertRaisesRegex(Failure, "^underlay_pid_exclusion_mismatch$") as caught,
        ):
            mg.change_mode(self.ctx, "direct", apply=True)
        self.assertEqual(str(caught.exception.__cause__), "underlay_pid_exclusion_mismatch")
        retained = read_regular(pending)
        self.assertEqual(json.loads(retained)["phase"], "rollback_runtime_failed")
        self.assertEqual(self.ctx.mode(), "tunnel")
        with (
            patch.object(mg, "restart_pair"),
            self.assertRaisesRegex(Failure, "^underlay_pid_exclusion_mismatch$"),
        ):
            mg.recover_transaction(self.ctx, apply=True)
        self.assertEqual(read_regular(pending), retained)
        self.assertEqual(list(self.paths.state.glob("recovered-*.json")), [])
        self.refuse_final = False
        with patch.object(mg, "restart_pair"):
            mg.recover_transaction(self.ctx, apply=True)
        self.assertFalse(pending.exists())
        archives = list(self.paths.state.glob("recovered-*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(read_regular(archives[0]), retained)
        self.assertEqual(self.split_reads, 8)
