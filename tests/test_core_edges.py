"""Process/IO failures and strict configuration parsing without live commands."""

import stat
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import quote

import core
from core import Failure, atomic, logged
from test_support import ConsoleFixture, URI, PIN


class CoreEdges(ConsoleFixture):
    @logged
    def test_bounded_pipe_empty_and_child_closes_stdin(self):
        result = core.bounded_process(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())",
            ],
            input=b"",
        )
        self.assertEqual((result.returncode, result.stdout), (0, b""))
        result = core.bounded_process(
            [sys.executable, "-I", "-c", "import os,time;os.close(0);time.sleep(.02)"],
            input=b"x" * (2 * 1024 * 1024),
        )
        self.assertEqual(result.returncode, 0)
        with (
            patch.object(core.os, "killpg", side_effect=ProcessLookupError()),
            self.assertRaises(core.subprocess.TimeoutExpired),
        ):
            core.bounded_process(
                [sys.executable, "-I", "-c", "import time;time.sleep(.05)"], timeout=0.001
            )

    @logged
    def test_attached_interrupt_stops_then_waits_or_kills(self):
        for waits, killed in (
            ([KeyboardInterrupt(), 0], False),
            ([KeyboardInterrupt(), core.subprocess.TimeoutExpired("fixture", 30), 0], True),
        ):
            proc = Mock()
            proc.wait.side_effect = waits
            with (
                patch.object(core.subprocess, "Popen", return_value=proc),
                patch.object(core.subprocess, "run") as stop,
                self.assertRaises(KeyboardInterrupt),
            ):
                core.attached_process(["/fake/child"], stop=["/fake/stop"])
            stop.assert_called_once()
            self.assertEqual(proc.kill.called, killed)
        self.ctx.attached = Mock(side_effect=OSError())
        with self.assertRaisesRegex(Failure, "external_unavailable"):
            self.ctx.run_attached(["/fake/child"], stop=["/fake/stop"])
        self.ctx.attached = Mock(return_value=7)
        self.assertEqual(self.ctx.run_attached(["/fake/child"], stop=["/fake/stop"]), 7)

    @logged
    def test_context_read_parse_output_and_owner_failures(self):
        self.assertIsNone(self.ctx.read_state("missing", 10))
        atomic(self.paths.state / "present", "yes")
        self.assertEqual(self.ctx.read_state("present", 10), b"yes")
        for output, label in (
            (b"not-json", "config_decoder_invalid_output"),
            (b"[]", "config_not_object"),
        ):
            with (
                patch.object(self.ctx, "run", return_value=Mock(stdout=output)),
                self.assertRaisesRegex(Failure, label),
            ):
                self.ctx.config("yggdrasil-lab.conf")
        atomic(self.paths.etc / "mode", "bad")
        with self.assertRaisesRegex(Failure, "invalid_underlay_mode"):
            self.ctx.mode()
        self.ctx.require_root = True
        with (
            patch.object(core.os, "geteuid", return_value=1000),
            self.assertRaisesRegex(Failure, "root_required"),
        ):
            self.ctx.root()
        self.ctx.require_root = False
        for stdout, stderr in (
            (b"x" * (16 * 1024 * 1024 + 1), b""),
            (b"", b"x" * (1024 * 1024 + 1)),
        ):
            self.ctx.runner = Mock(return_value=Mock(stdout=stdout, stderr=stderr, returncode=0))
            with self.assertRaisesRegex(Failure, "external_output_limit"):
                self.ctx.run(["/fake/command"])

    @logged
    def test_lock_rejects_permissions_owner_and_nested_error(self):
        lock = self.paths.state / ".console.lock"
        atomic(lock, b"", 0o644)
        with self.assertRaisesRegex(Failure, "unsafe_lock_file"), self.ctx.locked():
            self.fail("unsafe lock entered")
        lock.chmod(0o600)
        self.ctx.require_root = True
        with (
            patch.object(self.ctx, "root"),
            patch.object(
                core.os,
                "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000),
            ),
            self.assertRaisesRegex(Failure, "lock_not_root_owned"),
            self.ctx.locked(),
        ):
            self.fail("wrong owner entered")
        self.ctx.require_root = False
        with self.ctx.locked():
            with self.assertRaisesRegex(Failure, "nested"), self.ctx.locked():
                raise Failure("nested")
            self.assertEqual(self.ctx.lock_depth, 1)
        self.assertEqual(self.ctx.lock_depth, 0)

    @logged
    def test_atomic_failure_removes_only_own_temporary_file(self):
        path = self.paths.state / "target"
        atomic(path, "old")
        with patch.object(core.os, "replace", side_effect=OSError()), self.assertRaises(OSError):
            atomic(path, "new")
        self.assertEqual(path.read_text(), "old")
        self.assertEqual(list(self.paths.state.glob(".yggctl-*")), [])

    @logged
    def test_uri_option_failures_and_canonical_options(self):
        bad = [
            ("tls://[200::1]:443?key=" + PIN, "ipv4_literal_required"),
            (URI + "&bad", "invalid_peer_query"),
            (URI.replace(":443?", ":443/path?"), "unexpected_peer_path"),
            (URI + "&sni=bad%2Fname", "invalid_sni"),
            (URI + "&maxbackoff=bad", "one_valid_key_pin_required"),
            (URI.replace("maxbackoff=30s", "maxbackoff=bad"), "invalid_maxbackoff"),
            (URI + "&priority=-1", "invalid_priority"),
            (URI + "&priority=256", "invalid_priority"),
        ]
        for uri, label in bad:
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                core.peer_uri(uri)
        ws = "wss://192.0.2.1:443/ws?key=" + PIN
        for origin in (
            "https://example.invalid",
            "https://example.invalid/",
            "http://example.invalid:80",
        ):
            result, endpoint = core.peer_uri(ws + "&origin=" + quote(origin, safe=""), True)
            self.assertEqual(endpoint, "192.0.2.1:443")
            self.assertIn("origin=", result)
        canonical, _ = core.peer_uri(URI + "&priority=255&sni=example.invalid")
        self.assertIn("priority=255", canonical)

    @logged
    def test_safe_config_reports_each_custody_error(self):
        config = self.ctx.config("yggdrasil-lab.conf")
        changes = {
            "IfName": "tun0",
            "Listen": ["tcp://0.0.0.0:1"],
            "MulticastInterfaces": [{}],
            "InterfacePeers": {"eth0": []},
            "PrivateKey": "SYNTHETIC_SECRET",
            "GroupPassword": "SYNTHETIC_SECRET",
            "NodeInfoPrivacy": False,
            "NodeInfo": {"test": True},
            "AdminListen": None,
            "Peers": ["bad"],
        }
        errors = core.safe_config(dict(config, **changes))
        self.assertEqual(len(errors), 10)
        self.assertIn("invalid_peer", errors)
        self.assertIn("inline_group_password", errors)
        self.assertEqual(core.safe_config(config), [])

    @logged
    def test_admin_invalid_json_and_duplicate_peer_guard(self):
        with (
            patch.object(self.ctx, "run", return_value=Mock(stdout=b"not-json")),
            self.assertRaisesRegex(Failure, "admin_invalid_json"),
        ):
            self.ctx.api("getSelf")
        import management

        with self.assertRaisesRegex(Failure, "endpoint_already_configured"):
            management.change_peer(self.ctx, URI)
