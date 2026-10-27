"""An exclusion change during proof invalidates the earlier snapshot."""

# The fixture constructs CompletedProcess values; it never starts a process.
import subprocess  # nosec B404
from unittest.mock import patch

import checks
from core import Failure, logged
from test_support import ConsoleFixture


class UnderlaySplitChange(ConsoleFixture):
    @logged
    def test_unavailable_final_split_read_does_not_confirm_proof(self):
        original = self.ctx.runner
        calls = []

        @logged
        def runner(argv, **kwargs):
            if "mullvad" in argv[0]:
                calls.append(1)
                if len(calls) == 2:
                    raise Failure("external_unavailable:mullvad")
            return original(argv, **kwargs)

        self.ctx.runner = runner
        try:
            with self.assertRaisesRegex(Failure, "^external_unavailable:mullvad$"):
                checks.underlay(self.ctx)
        finally:
            self.ctx.runner = original

    @logged
    def test_changed_exclusion_is_rejected_for_each_service(self):
        original = self.ctx.runner
        for removed in ("1001", "1002"):
            with self.subTest(removed=removed):
                calls = []

                @logged
                def runner(argv, **kwargs):
                    if "mullvad" in argv[0]:
                        calls.append(1)
                        pids = ["1001", "1002"]
                        if len(calls) == 2:
                            pids.remove(removed)
                        return subprocess.CompletedProcess(
                            argv, 0, ("\n".join(pids) + "\n").encode(), b""
                        )
                    return original(argv, **kwargs)

                self.ctx.runner = runner
                try:
                    with self.assertRaisesRegex(Failure, "^underlay_pid_exclusion_mismatch$"):
                        checks.underlay(self.ctx)
                    self.assertEqual(len(calls), 2)
                finally:
                    self.ctx.runner = original

    @logged
    def test_tunnel_rejects_exclusion_added_midproof(self):
        original = self.ctx.runner
        calls = []

        @logged
        def runner(argv, **kwargs):
            if "mullvad" in argv[0]:
                calls.append(1)
                data = b"1001\n" if len(calls) == 2 else b""
                return subprocess.CompletedProcess(argv, 0, data, b"")
            result = original(argv, **kwargs)
            if "conntrack" in argv[0]:
                result.stdout = result.stdout.replace(b"mark=3905", b"mark=0")
            return result

        self.ctx.runner = runner
        try:
            with patch.object(self.ctx, "mode", return_value="tunnel"):
                with self.assertRaisesRegex(Failure, "^underlay_pid_exclusion_mismatch$"):
                    checks.underlay(self.ctx)
            self.assertEqual(len(calls), 2)
        finally:
            self.ctx.runner = original


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
