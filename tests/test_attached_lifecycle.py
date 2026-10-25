"""Attached launcher cleanup when the launcher and its systemd worker diverge."""

import unittest
from unittest.mock import Mock, call, patch

import core


LAUNCH = ["/fake/systemd-run"]
STOP = ["/fake/systemctl", "stop", "fixture.service"]


class AttachedLifecycleTests(unittest.TestCase):
    @core.logged
    def test_success_does_not_stop_unit(self):
        proc = Mock()
        proc.wait.return_value = 0
        with (
            patch.object(core.subprocess, "Popen", return_value=proc),
            patch.object(core.subprocess, "run") as stop,
        ):
            self.assertEqual(core.attached_process(LAUNCH, stop=STOP), 0)
        stop.assert_not_called()
        proc.wait.assert_called_once_with()
        proc.kill.assert_not_called()

    @core.logged
    def test_nonzero_and_signalled_launcher_stop_unit_before_return(self):
        for rc in (247, -9):
            with self.subTest(rc=rc):
                proc = Mock()
                proc.wait.side_effect = [rc, rc]
                with (
                    patch.object(core.subprocess, "Popen", return_value=proc),
                    patch.object(core.subprocess, "run") as stop,
                ):
                    self.assertEqual(core.attached_process(LAUNCH, stop=STOP), rc)
                stop.assert_called_once()
                self.assertEqual(stop.call_args.args, (STOP,))
                self.assertEqual(stop.call_args.kwargs["timeout"], 30)
                self.assertFalse(stop.call_args.kwargs["check"])
                self.assertEqual(proc.wait.call_args_list, [call(), call(timeout=30)])
                proc.kill.assert_not_called()

    @core.logged
    def test_stop_command_failure_preserves_launcher_status_and_reaps(self):
        for failure in (
            Mock(returncode=5),
            OSError("fixture"),
            core.subprocess.TimeoutExpired("fixture", 30),
        ):
            with self.subTest(failure=type(failure).__name__):
                proc = Mock()
                proc.wait.side_effect = [247, 247]
                with (
                    patch.object(core.subprocess, "Popen", return_value=proc),
                    patch.object(core.subprocess, "run") as stop,
                ):
                    if isinstance(failure, BaseException):
                        stop.side_effect = failure
                    else:
                        stop.return_value = failure
                    self.assertEqual(core.attached_process(LAUNCH, stop=STOP), 247)
                stop.assert_called_once()
                self.assertEqual(proc.wait.call_args_list, [call(), call(timeout=30)])

    @core.logged
    def test_stop_failure_preserves_interruption_and_reaps(self):
        for failure in (OSError("fixture"), core.subprocess.TimeoutExpired("fixture", 30)):
            with self.subTest(failure=type(failure).__name__):
                proc = Mock()
                proc.wait.side_effect = [KeyboardInterrupt(), 0]
                with (
                    patch.object(core.subprocess, "Popen", return_value=proc),
                    patch.object(core.subprocess, "run", side_effect=failure) as stop,
                    self.assertRaises(KeyboardInterrupt),
                ):
                    core.attached_process(LAUNCH, stop=STOP)
                stop.assert_called_once()
                self.assertEqual(proc.wait.call_args_list, [call(), call(timeout=30)])
                proc.kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
