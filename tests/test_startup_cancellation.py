"""Signal fault injection at the Popen return boundary, using owned local children."""

import contextlib
import os
import signal
import subprocess  # nosec B404 # Only synthetic local Python children are started.
import sys
import threading
import unittest
from unittest.mock import patch

import core


class StartupInterrupted(Exception):
    """Distinctive original handler exception for the fault injection."""


class StartupCancellationTests(unittest.TestCase):
    @core.logged
    def setUp(self):
        self.children: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap_owned_children)

    @core.logged
    def reap_owned_children(self):
        # This also bounds cleanup on the unfixed revision, where the caller
        # loses the child reference before its normal cleanup scope begins.
        for proc in self.children:
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
            proc.wait(timeout=3)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()

    @core.logged
    def sleeping_argv(self):
        return [sys.executable, "-I", "-c", "import time; time.sleep(6)"]

    @core.logged
    def test_bounded_signal_after_spawn_reaps_child_and_preserves_exception(self):
        original_popen = subprocess.Popen
        prior = signal.getsignal(signal.SIGTERM)

        def interrupt(_signum, _frame):
            raise StartupInterrupted("original SIGTERM handler")

        def spawn_then_signal(*args, **kwargs):
            proc = original_popen(*args, **kwargs)
            self.children.append(proc)
            os.kill(os.getpid(), signal.SIGTERM)
            return proc

        signal.signal(signal.SIGTERM, interrupt)
        try:
            with (
                patch.object(core.subprocess, "Popen", side_effect=spawn_then_signal),
                self.assertRaisesRegex(StartupInterrupted, "original SIGTERM handler"),
            ):
                core.bounded_process(self.sleeping_argv(), timeout=2)
            self.assertIs(signal.getsignal(signal.SIGTERM), interrupt)
            self.assertEqual(len(self.children), 1)
            self.assertIsNotNone(self.children[0].poll(), "child escaped startup cleanup")
        finally:
            signal.signal(signal.SIGTERM, prior)

    @core.logged
    def test_attached_signal_after_spawn_stops_unit_and_reaps_launcher(self):
        original_popen = subprocess.Popen
        prior = signal.getsignal(signal.SIGINT)
        stopped = []

        def interrupt(_signum, _frame):
            raise StartupInterrupted("original SIGINT handler")

        def spawn_then_signal(*args, **kwargs):
            proc = original_popen(*args, **kwargs)
            self.children.append(proc)
            os.kill(os.getpid(), signal.SIGINT)
            return proc

        def stop_unit(argv, **_kwargs):
            stopped.append(argv)
            self.children[0].terminate()
            return subprocess.CompletedProcess(argv, 0)

        signal.signal(signal.SIGINT, interrupt)
        try:
            with (
                patch.object(core.subprocess, "Popen", side_effect=spawn_then_signal),
                patch.object(core.subprocess, "run", side_effect=stop_unit),
                self.assertRaisesRegex(StartupInterrupted, "original SIGINT handler"),
            ):
                core.attached_process(self.sleeping_argv(), stop=["synthetic-stop"])
            self.assertEqual(stopped, [["synthetic-stop"]])
            self.assertIs(signal.getsignal(signal.SIGINT), interrupt)
            self.assertIsNotNone(self.children[0].poll(), "launcher escaped startup cleanup")
        finally:
            signal.signal(signal.SIGINT, prior)

    @core.logged
    def test_nonraising_handlers_run_in_arrival_order_after_restoration(self):
        prior_int = signal.getsignal(signal.SIGINT)
        prior_term = signal.getsignal(signal.SIGTERM)
        observed = []
        original_popen = subprocess.Popen

        def record(signum, _frame):
            observed.append(
                (signum, signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
            )

        def spawn_then_signal(*args, **kwargs):
            proc = original_popen(*args, **kwargs)
            self.children.append(proc)
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)
            return proc

        signal.signal(signal.SIGINT, record)
        signal.signal(signal.SIGTERM, record)
        try:
            with patch.object(core.subprocess, "Popen", side_effect=spawn_then_signal):
                result = core.bounded_process([sys.executable, "-I", "-c", "pass"], timeout=2)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(
                observed,
                [(signal.SIGTERM, record, record), (signal.SIGINT, record, record)],
            )
        finally:
            signal.signal(signal.SIGINT, prior_int)
            signal.signal(signal.SIGTERM, prior_term)

    @core.logged
    def test_signal_during_handler_restoration_restores_other_handler(self):
        prior_int = signal.getsignal(signal.SIGINT)
        prior_term = signal.getsignal(signal.SIGTERM)
        original_signal = signal.signal
        original_popen = subprocess.Popen
        injected = False

        def interrupt(_signum, _frame):
            raise StartupInterrupted("restored SIGINT handler")

        def record(_signum, _frame):
            pass

        def spawn(*args, **kwargs):
            proc = original_popen(*args, **kwargs)
            self.children.append(proc)
            return proc

        def restore(signum, handler):
            nonlocal injected
            result = original_signal(signum, handler)
            if signum == signal.SIGINT and handler is interrupt and not injected:
                injected = True
                os.kill(os.getpid(), signal.SIGINT)
            return result

        original_signal(signal.SIGINT, interrupt)
        original_signal(signal.SIGTERM, record)
        try:
            with (
                patch.object(core.signal, "signal", side_effect=restore),
                patch.object(core.subprocess, "Popen", side_effect=spawn),
                self.assertRaisesRegex(StartupInterrupted, "restored SIGINT handler"),
            ):
                core.bounded_process(self.sleeping_argv(), timeout=2)
            self.assertTrue(injected)
            self.assertIs(signal.getsignal(signal.SIGINT), interrupt)
            self.assertIs(signal.getsignal(signal.SIGTERM), record)
            self.assertIsNotNone(self.children[0].poll())
        finally:
            original_signal(signal.SIGINT, prior_int)
            original_signal(signal.SIGTERM, prior_term)

    @core.logged
    def test_failed_exec_restores_handlers(self):
        prior_int = signal.getsignal(signal.SIGINT)
        prior_term = signal.getsignal(signal.SIGTERM)

        def record(_signum, _frame):
            pass

        signal.signal(signal.SIGINT, record)
        signal.signal(signal.SIGTERM, record)
        try:
            for attached in (False, True):
                with self.subTest(attached=attached):
                    with (
                        patch.object(
                            core.subprocess, "Popen", side_effect=FileNotFoundError("fixture")
                        ),
                        patch.object(core.subprocess, "run") as stop,
                        self.assertRaises(FileNotFoundError),
                    ):
                        if attached:
                            core.attached_process(["missing-fixture"], stop=["synthetic-stop"])
                        else:
                            core.bounded_process(["missing-fixture"])
                    stop.assert_not_called()
                    self.assertIs(signal.getsignal(signal.SIGINT), record)
                    self.assertIs(signal.getsignal(signal.SIGTERM), record)
        finally:
            signal.signal(signal.SIGINT, prior_int)
            signal.signal(signal.SIGTERM, prior_term)

    @core.logged
    def test_ignored_and_default_actions_are_not_replaced(self):
        prior_int = signal.getsignal(signal.SIGINT)
        prior_term = signal.getsignal(signal.SIGTERM)
        seen = []
        original_popen = subprocess.Popen

        def spawn_and_inspect(*args, **kwargs):
            seen.append((signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)))
            return original_popen(*args, **kwargs)

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        try:
            with patch.object(core.subprocess, "Popen", side_effect=spawn_and_inspect):
                result = core.bounded_process([sys.executable, "-I", "-c", "pass"], timeout=2)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(seen, [(signal.SIG_IGN, signal.SIG_DFL)])
            self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        finally:
            signal.signal(signal.SIGINT, prior_int)
            signal.signal(signal.SIGTERM, prior_term)

    @core.logged
    def test_worker_thread_uses_existing_signal_handlers(self):
        prior_int = signal.getsignal(signal.SIGINT)
        prior_term = signal.getsignal(signal.SIGTERM)
        observed = []
        outcome = {}
        original_popen = subprocess.Popen

        def record(_signum, _frame):
            pass

        def spawn_and_inspect(*args, **kwargs):
            observed.append((signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)))
            return original_popen(*args, **kwargs)

        def run_child():
            try:
                outcome["result"] = core.bounded_process(
                    [sys.executable, "-I", "-c", "pass"], timeout=2
                )
            except BaseException as exc:
                outcome["error"] = exc

        signal.signal(signal.SIGINT, record)
        signal.signal(signal.SIGTERM, record)
        try:
            with patch.object(core.subprocess, "Popen", side_effect=spawn_and_inspect):
                worker = threading.Thread(target=run_child, daemon=True)
                worker.start()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", outcome)
            self.assertEqual(outcome["result"].returncode, 0)
            self.assertEqual(observed, [(record, record)])
        finally:
            signal.signal(signal.SIGINT, prior_int)
            signal.signal(signal.SIGTERM, prior_term)

    @core.logged
    def test_child_signal_dispositions_and_mask_remain_normal(self):
        prior_int = signal.getsignal(signal.SIGINT)
        prior_term = signal.getsignal(signal.SIGTERM)

        def record(_signum, _frame):
            pass

        source = (
            "import signal,sys;"
            "blocked=signal.pthread_sigmask(signal.SIG_BLOCK, []);"
            "sys.stdout.write(str((signal.getsignal(signal.SIGTERM)==signal.SIG_DFL,"
            "signal.getsignal(signal.SIGINT)==signal.default_int_handler,"
            "signal.SIGINT not in blocked,signal.SIGTERM not in blocked)))"
        )
        signal.signal(signal.SIGINT, record)
        signal.signal(signal.SIGTERM, record)
        try:
            result = core.bounded_process([sys.executable, "-I", "-c", source], timeout=2)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"(True, True, True, True)")
            self.assertIs(signal.getsignal(signal.SIGINT), record)
            self.assertIs(signal.getsignal(signal.SIGTERM), record)
        finally:
            signal.signal(signal.SIGINT, prior_int)
            signal.signal(signal.SIGTERM, prior_term)


if __name__ == "__main__":
    unittest.main()
