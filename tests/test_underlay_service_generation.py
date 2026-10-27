"""A service restart during proof invalidates previously sampled sockets."""

from unittest.mock import patch

import checks
from core import Failure, NODE, STACK, logged
from test_support import ConsoleFixture


class UnderlayServiceGeneration(ConsoleFixture):
    @logged
    def test_stable_services_still_pass(self):
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])

    @logged
    def test_service_replaced_or_stopped_during_proof_is_rejected(self):
        original = self.ctx.unit
        for changed_unit in (NODE, STACK):
            for replacement in ("3000", "0"):
                with self.subTest(unit=changed_unit, replacement=replacement):
                    calls = {NODE: 0, STACK: 0}

                    @logged
                    def unit(name):
                        result = original(name)
                        calls[name] += 1
                        if name == changed_unit and calls[name] == 2:
                            result["MainPID"] = replacement
                        return result

                    with patch.object(self.ctx, "unit", side_effect=unit):
                        with self.assertRaisesRegex(Failure, "^underlay_service_pid_changed$"):
                            checks.underlay(self.ctx)
                    self.assertEqual(calls, {NODE: 2, STACK: 2})


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
