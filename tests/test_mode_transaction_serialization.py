"""Mode apply decisions use committed state and honor unfinished transactions."""

import contextlib
import io
import threading
from unittest.mock import patch

from core import Context, Failure, atomic, logged
import management as mg
from test_support import ConsoleFixture


class ModeTransactionSerialization(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_apply_rejects_pending_even_if_mode_matches(self):
        atomic(self.paths.state / "transaction.json", "{}")
        with self.assertRaisesRegex(Failure, "unfinished_transaction_run_recover_transaction"):
            mg.change_mode(self.ctx, "direct", apply=True)
        self.assertTrue((self.paths.state / "transaction.json").exists())
        # A diagnostic proof without --apply remains available for recovery.
        mg.change_mode(self.ctx, "direct", apply=False)

    @logged
    def test_concurrent_apply_rechecks_after_first_rolls_back(self):
        started, release, second_done = threading.Event(), threading.Event(), threading.Event()
        first_errors, second_errors = [], []
        calls = []
        other = Context(self.paths, runner=self.runner, require_root=False)

        @logged
        def action(ctx):
            calls.append(ctx)
            if ctx is self.ctx:
                started.set()
                if not release.wait(5):
                    raise Failure("synthetic_release_timeout")
                raise Failure("synthetic_action_failure")

        @logged
        def first():
            try:
                mg.change_mode(self.ctx, "tunnel", apply=True)
            except BaseException as exc:
                first_errors.append(exc)

        @logged
        def second():
            try:
                mg.change_mode(other, "tunnel", apply=True)
            except BaseException as exc:
                second_errors.append(exc)
            finally:
                second_done.set()

        with (
            patch.object(mg, "mode_action", side_effect=action),
            patch.object(mg, "restart_pair"),
            patch.object(mg, "underlay"),
        ):
            thread1 = threading.Thread(target=first)
            thread2 = threading.Thread(target=second)
            thread1.start()
            try:
                self.assertTrue(started.wait(5))
                thread2.start()
                self.assertFalse(
                    second_done.wait(0.25), "second apply confirmed an uncommitted mode"
                )
            finally:
                release.set()
                thread1.join(10)
                if thread2.ident is not None:
                    thread2.join(10)
            self.assertFalse(thread1.is_alive())
            self.assertFalse(thread2.is_alive())
        self.assertEqual([str(exc) for exc in first_errors], ["synthetic_action_failure"])
        self.assertEqual(second_errors, [])
        self.assertEqual(calls, [self.ctx, other])
        self.assertEqual(self.ctx.mode(), "tunnel")
        self.assertFalse((self.paths.state / "transaction.json").exists())
