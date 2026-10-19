"""CLI contracts with synthetic state; never contacts installed services."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import runpy
import signal
import sys
from unittest.mock import Mock, patch

import core
from core import Failure, logged
import main
from test_support import ConsoleFixture, PIN


class CliEdges(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.stdout = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.stdout))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))

    @logged
    def args(self, command, values=(), **flags):
        return argparse.Namespace(
            command=command,
            args=list(values),
            apply=flags.get("apply", False),
            force=flags.get("force", False),
            full=flags.get("full", False),
            recipient=flags.get("recipient"),
        )

    @logged
    def test_information_and_readonly_handlers(self):
        for cmd in (
            "help",
            "version",
            "update-check",
            "peers",
            "stack-peers",
            "self",
            "tree",
            "paths",
            "sessions",
            "discover",
        ):
            with self.subTest(command=cmd):
                main.dispatch(self.ctx, self.args(cmd))
        self.assertTrue(any("dpkg-query" in a[0] for a in self.calls))
        self.assertIn("Python", self.stdout.getvalue())
        with (
            patch.object(main.checks, "underlay", return_value={}),
            patch.object(main.checks, "sockets", return_value="loopback") as sockets,
        ):
            main.dispatch(self.ctx, self.args("mode"))
            main.dispatch(self.ctx, self.args("mode", ["show"]))
            main.dispatch(self.ctx, self.args("socks"))
            sockets.assert_called_once_with(self.ctx)
        for cmd in ("nameserver", "timer"):
            main.dispatch(self.ctx, self.args(cmd))
            main.dispatch(self.ctx, self.args(cmd, ["show"]))
            with self.assertRaisesRegex(Failure, "requires_reviewed"):
                main.dispatch(self.ctx, self.args(cmd, ["edit"]))
        main.dispatch(self.ctx, self.args("config"))
        main.dispatch(self.ctx, self.args("config", ["show"]))
        main.dispatch(self.ctx, self.args("config", ["validate"]))
        with self.assertRaisesRegex(Failure, "config_edit_disabled"):
            main.dispatch(self.ctx, self.args("config", ["edit"]))
        with (
            patch.object(self.ctx, "config", return_value={}),
            self.assertRaisesRegex(Failure, "unsafe_config"),
        ):
            main.dispatch(self.ctx, self.args("config", ["validate"]))

    @logged
    def test_handlers_delegate_exact_arguments(self):
        cases = [
            ("check", [], main.checks, "check", (self.ctx,)),
            ("guard", [], main.checks, "guard", (self.ctx,)),
            ("verify-hashes", [], main.checks, "integrity", (self.ctx,)),
            ("socks-test", [], main, "socks_test", (self.ctx,)),
            ("bench", [], main, "socks_test", (self.ctx, 1)),
            ("bench", ["3"], main, "socks_test", (self.ctx, 3)),
            ("mode", ["tunnel"], main.management, "change_mode", (self.ctx, "tunnel", False)),
            ("start", [], main.management, "service", (self.ctx, "start")),
            (
                "add-peer",
                ["uri"],
                main.management,
                "change_peer",
                (self.ctx, "uri", False, False, False),
            ),
            (
                "remove-peer",
                ["endpoint"],
                main.management,
                "change_peer",
                (self.ctx, "endpoint", True, False, False),
            ),
            ("recover-transaction", [], main.management, "recover_transaction", (self.ctx, False)),
            ("collect", [], main.telemetry, "collect", (self.ctx,)),
            ("watch", [], main.telemetry, "watch", (self.ctx, 5, 2)),
            ("top", ["2", "3"], main.telemetry, "watch", (self.ctx, 2, 3)),
            ("notify", [], main.telemetry, "notify", (self.ctx, "show")),
            ("notify", ["off"], main.telemetry, "notify", (self.ctx, "off")),
            ("alerts-forward", [], main.telemetry, "forward", (self.ctx,)),
            ("backup", [], main.recovery, "backup", (self.ctx, False, None)),
            ("restore", ["archive"], main.recovery, "restore", (self.ctx, "archive", False)),
            ("snapshot", [], main.recovery, "snapshot", (self.ctx,)),
            ("diff", [], main.recovery, "diff", (self.ctx, None)),
            ("diff", ["saved"], main.recovery, "diff", (self.ctx, "saved")),
            ("ping", ["target"], main, "http_probe", (self.ctx, "target")),
        ]
        for cmd, args, owner, method, expected in cases:
            with (
                self.subTest(command=cmd, args=args),
                patch.object(owner, method, return_value=0) as call,
            ):
                main.dispatch(self.ctx, self.args(cmd, args))
                call.assert_called_once_with(*expected)
        for cmd, message in (
            ("restore", "one_archive"),
            ("add-peer", "one_peer"),
            ("ping", "one_overlay"),
            ("nodeinfo", "one_public"),
            ("traceroute", "one_public"),
        ):
            with self.subTest(command=cmd), self.assertRaisesRegex(Failure, message):
                main.dispatch(self.ctx, self.args(cmd))
        with (
            patch.object(main.recovery, "backup") as backup,
            patch.object(main.checks, "check") as check,
            patch.object(main.telemetry, "stats") as stats,
        ):
            main.dispatch(self.ctx, self.args("doctor"))
            main.dispatch(self.ctx, self.args("report"))
            backup.assert_called_once_with(self.ctx)
            check.assert_called_once_with(self.ctx)
            stats.assert_called_once_with(self.ctx)
        with patch.object(main.checks, "policy_gate") as policy:
            main.dispatch(self.ctx, self.args("firewall-status"))
            policy.assert_called_once_with(self.ctx)
        with (
            patch("research.command", return_value={}) as research,
            patch("atlas.command", return_value={}) as atlas,
        ):
            main.dispatch(self.ctx, self.args("research", ["report"]))
            main.dispatch(self.ctx, self.args("atlas", ["status"]))
            research.assert_called_once_with(self.ctx, ["report"])
            atlas.assert_called_once_with(self.ctx, ["status"])

    @logged
    def test_remote_commands_and_ranking(self):
        for cmd in ("nodeinfo", "whois"):
            main.dispatch(self.ctx, self.args(cmd, [PIN]))
        main.dispatch(self.ctx, self.args("debug-remote", ["tree", PIN]))
        main.dispatch(self.ctx, self.args("peers-score"))
        main.dispatch(self.ctx, self.args("survey"))
        main.dispatch(self.ctx, self.args("traceroute", [PIN]))
        with self.assertRaisesRegex(Failure, "debug_remote_self"):
            main.dispatch(self.ctx, self.args("debug-remote", ["bogus", PIN]))
        with (
            patch.object(self.ctx, "api", return_value={}),
            self.assertRaisesRegex(Failure, "admin_invalid_self"),
        ):
            main.remote_key(self.ctx, PIN)
        with (
            patch.object(self.ctx, "api", return_value={"key": PIN}),
            self.assertRaisesRegex(Failure, "remote_target_is_local"),
        ):
            main.remote_key(self.ctx, PIN)

    @logged
    def test_selftest_modes_without_recursion(self):
        with (
            patch("tests.run_suite") as console,
            patch("research.tests.run_suite") as research,
            patch("atlas.tests.run_suite") as atlas,
        ):
            main.dispatch(self.ctx, self.args("selftest", ["offline"]))
            for suite in (console, research, atlas):
                suite.assert_called_once_with()
        with (
            patch.object(main.checks, "check") as check,
            patch.object(main.telemetry, "stats") as stats,
        ):
            main.dispatch(self.ctx, self.args("selftest"))
            check.assert_called_once_with(self.ctx)
            stats.assert_called_once_with(self.ctx)
        with self.assertRaisesRegex(Failure, "selftest_only"):
            main.dispatch(self.ctx, self.args("selftest", ["other"]))

    @logged
    def test_socks_aggregates_success_and_failure(self):
        with (
            patch.object(main.checks, "sockets") as sockets,
            patch.object(main, "http_probe") as probe,
        ):
            main.socks_test(self.ctx, 2)
            self.assertEqual(probe.call_count, 2)
            sockets.assert_called_once_with(self.ctx)
            self.ctx.parent_verified = frozenset({"sockets"})
            probe.side_effect = Failure("fixture_timeout")
            with self.assertRaisesRegex(Failure, "overlay_e2e_failed"):
                main.socks_test(self.ctx, 1)
            self.assertEqual(sockets.call_count, 1)
        with patch.object(self.ctx, "run", return_value=Mock(stdout=b"200 0 0 0 0", returncode=0)):
            self.assertEqual(main.http_probe(self.ctx, "[200::1]:80"), ["200", "0", "0", "0", "0"])
        with (
            patch.object(self.ctx, "run", return_value=Mock(stdout=b"404 0 0 0 0", returncode=0)),
            self.assertRaisesRegex(Failure, "overlay_http_not_2xx"),
        ):
            main.http_probe(self.ctx, "[200::1]:80")

    @logged
    def test_main_exit_contracts_and_signal(self):
        for error, code in (
            (None, 0),
            (Failure("root_required:fixture"), 77),
            (Failure("fixture"), 1),
            (ValueError("never_render"), 1),
            (KeyboardInterrupt(), 130),
        ):
            with (
                self.subTest(code=code),
                patch.object(sys, "argv", ["yggctl", "--help", "--trace"]),
                patch.object(main.sandbox, "worker_context", return_value=self.ctx),
                patch.object(main, "dispatch", side_effect=error) as dispatch,
                patch.object(main, "trace_live") as trace,
                patch.object(main.signal, "signal"),
            ):
                self.assertEqual(main.main(), code)
                self.assertEqual(dispatch.call_args.args[1].command, "help")
                trace.assert_called_once_with()
        with (
            patch.object(sys, "argv", ["yggctl", "help"]),
            patch.object(main.sandbox, "worker_context", return_value=None),
            patch.object(main, "Context", return_value=self.ctx),
            patch.object(main, "dispatch") as dispatch,
            patch.object(main.signal, "signal"),
        ):
            self.assertEqual(main.main(), 0)
            dispatch.assert_called_once()
        with self.assertRaisesRegex(Failure, "interrupted_rollback"):
            main.interrupted(signal.SIGTERM, None)

    @logged
    def test_executable_entry_finalizes_success_and_parser_error(self):
        for argv, code in ((["yggctl", "help"], 0), (["yggctl", "--unknown-option"], 2)):
            with (
                self.subTest(code=code),
                patch.object(sys, "argv", argv),
                patch.object(main.sandbox, "worker_context", return_value=self.ctx),
                patch.object(core, "finish_run") as finish,
                patch.object(signal, "signal"),
                self.assertRaises(SystemExit) as raised,
            ):
                runpy.run_path(str(Path(main.__file__)), run_name="__main__")
            self.assertEqual(raised.exception.code, code)
            finish.assert_called_once()
            self.assertEqual(finish.call_args.args[1], code)

    @logged
    def test_journal_events_and_default_limit(self):
        payload = json.dumps(
            {"MESSAGE": "safe", "_SYSTEMD_UNIT": core.NODE, "__REALTIME_TIMESTAMP": "1"}
        ).encode()
        with patch.object(self.ctx, "run", return_value=Mock(stdout=payload)) as run:
            main.dispatch(self.ctx, self.args("logs"))
            self.assertIn("50", run.call_args.args[0])
            main.dispatch(self.ctx, self.args("events"))
            self.assertIn("6 hours ago", run.call_args.args[0])
        for cmd, hours, graph in (("stats", 24, False), ("graph", 6, True), ("stats", 2, False)):
            with (
                patch.object(main.telemetry, "stats") as stats,
                patch.object(main.os, "geteuid", return_value=0),
            ):
                main.dispatch(self.ctx, self.args(cmd, ["2"] if hours == 2 else []))
                stats.assert_called_once_with(self.ctx, hours, graph)
