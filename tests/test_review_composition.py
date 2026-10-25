"""Owner composition edges for sampled evidence and bounded worker cleanup."""

from unittest.mock import Mock, patch

import checks
import core
from core import Failure, logged
from test_support import ConsoleFixture


class ReviewCompositionTests(ConsoleFixture):
    @logged
    def test_tcp_mark_requires_one_unambiguous_token(self):
        socket = 'tcp ESTAB 0 0 10.0.0.2:41001 192.0.2.1:443 users:(("node",pid=1001,fd=9))'
        original = "tcp 6 100 ESTABLISHED src=10.0.0.2 dst=192.0.2.1 sport=41001 dport=443 "
        for mark in ("", "mark=3905 mark=0", "mark=3905 mark=3905"):
            with self.subTest(mark=mark):
                with self.assertRaisesRegex(Failure, "underlay_peer_socket_proof_missing"):
                    checks.tcp_peer_marks(
                        self.ctx, [1001, 1002], [socket], [original + mark], "direct"
                    )
        checks.tcp_peer_marks(self.ctx, [1001, 1002], [socket], [original + "mark=3905"], "direct")

    @logged
    def test_failed_unit_stop_is_logged_without_replacing_launcher_status(self):
        proc = Mock()
        proc.wait.side_effect = [-9, -9]
        with (
            patch.object(core.subprocess, "Popen", return_value=proc),
            patch.object(core.subprocess, "run", return_value=Mock(returncode=5)),
            patch.object(core, "event") as event,
        ):
            self.assertEqual(core.attached_process(["/fake/launcher"], stop=["/fake/stop"]), -9)
        self.assertIn(
            ("external_start", "attached_unit_stop"), [c.args for c in event.call_args_list]
        )
        self.assertIn(
            ("external_exit", "attached_unit_stop", "rc=5"), [c.args for c in event.call_args_list]
        )
        self.assertEqual(proc.wait.call_count, 2)
