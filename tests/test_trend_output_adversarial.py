"""Finite independent PR45 output/logger contract; synthetic and offline only."""

import contextlib
import datetime as dt
import io
import json
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import core
from core import Failure, atomic, logged
import main
from test_support import ConsoleFixture


class IndependentOutput(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        now = dt.datetime.now(dt.timezone.utc)
        rows = [
            {
                "schema": 2,
                "ts": (now - dt.timedelta(minutes=40 - i * 5)).isoformat(),
                "mode": "direct",
                "act": "active",
                "up": 1,
                "peers": [],
                "peers_observed": True,
                "stack_up": 1,
                "errors": [],
            }
            for i in range(8)
        ]
        self.metrics = self.paths.state / "metrics.jsonl"
        atomic(self.metrics, "".join(json.dumps(row) + "\n" for row in rows).encode())
        self.initial = self.metrics.read_bytes()

    @logged
    def invoke(self, words):
        out, err = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["yggctl", *words]),
            patch.object(main.sandbox, "worker_context", return_value=self.ctx),
            patch.object(main.signal, "signal"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = main.main()
        return code, out.getvalue(), err.getvalue()

    @logged
    def test_valid_formats_hours_and_flag_positions(self):
        cases = [
            ("trend", "json"),
            ("trend", "1", "json"),
            ("trend", "72", "json"),
            ("--trace", "trend", "json"),
            ("trend", "--trace", "1", "json"),
            ("trend", "1", "json", "--trace"),
        ]
        for words in cases:
            with self.subTest(words=words), patch.object(core.syslog, "syslog"):
                code, out, err = self.invoke(words)
                self.assertEqual(code, 0)
                report = json.loads(out, parse_constant=self.fail)
                self.assertEqual(report["verdict"], "stable")
                self.assertFalse(report["provenance"]["authenticated"])
                self.assertNotIn("[done]", out)
                self.assertRegex(err, r"^\[done\] errors=0 elapsed=\d+\.\d{2}s\n$")
        self.assertEqual(self.metrics.read_bytes(), self.initial)
        self.assertEqual(self.calls, [])

    @logged
    def test_negative_grammar_and_global_flag_contract(self):
        cases = [
            ("trend", "json", "1"),
            ("trend", "1", "json", "json"),
            ("trend", "0", "json"),
            ("trend", "73", "json"),
            ("trend", "-1", "json"),
            ("trend", "1.5", "json"),
            ("trend", "JSON"),
            ("trend", "json", "tail"),
            ("trend", "--apply", "json"),
            ("trend", "--force", "json"),
            ("trend", "--full", "json"),
            ("trend", "--recipient", "synthetic", "json"),
            ("help", "json"),
            ("version", "json"),
            ("trend", "json", "--help"),
        ]
        for words in cases:
            with self.subTest(words=words):
                code, out, err = self.invoke(words)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("FAIL "))
                self.assertNotIn("[done]", err)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.metrics.read_bytes(), self.initial)

    @logged
    def test_text_help_version_remain_stdout(self):
        for words in [("trend",), ("trend", "1"), ("help",), ("version",), ("--help",)]:
            with self.subTest(words=words):
                code, out, err = self.invoke(words)
                self.assertEqual(code, 0)
                self.assertIn("[done] errors=0", out)
                self.assertEqual(err, "")

    @logged
    def test_real_trace_uses_syslog_not_cli_streams(self):
        with patch.object(core.syslog, "syslog") as sink:
            code, out, err = self.invoke(("--trace", "trend", "json"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["samples"], 8)
        messages = [call.args[-1] for call in sink.call_args_list]
        self.assertTrue(any("entry do_trend" in line for line in messages))
        self.assertTrue(any("exit do_trend success" in line for line in messages))
        self.assertTrue(any("exit main status=0" in line for line in messages))
        self.assertNotIn("yggctl entry", out + err)
        self.assertNotIn(str(self.paths.state), "\n".join(messages))

    @logged
    def test_failures_interrupt_root_and_secret_safe_logging(self):
        cases = [
            (Failure("synthetic_safe"), 1, "FAIL synthetic_safe"),
            (Failure("root_required_synthetic"), 77, "FAIL root_required"),
            (OSError("SYNTHETIC_PRIVATE_DETAIL"), 1, "FAIL unavailable_or_invalid_data"),
            (ValueError("SYNTHETIC_PRIVATE_DETAIL"), 1, "FAIL unavailable_or_invalid_data"),
            (KeyError("SYNTHETIC_PRIVATE_DETAIL"), 1, "FAIL unavailable_or_invalid_data"),
            (TypeError("SYNTHETIC_PRIVATE_DETAIL"), 1, "FAIL unavailable_or_invalid_data"),
            (KeyboardInterrupt(), 130, "FAIL interrupted"),
        ]
        for exc, expected, label in cases:
            with (
                self.subTest(exception=type(exc).__name__),
                patch.object(core.syslog, "syslog") as sink,
            ):
                with patch.object(main.telemetry, "trend", side_effect=exc):
                    code, out, err = self.invoke(("--trace", "trend", "json"))
                self.assertEqual(code, expected)
                self.assertEqual(out, "")
                self.assertIn(label, err)
                self.assertNotIn("[done]", err)
                messages = "\n".join(call.args[-1] for call in sink.call_args_list)
                self.assertIn("error do_trend " + type(exc).__name__, messages)
                self.assertIn("exit main status=" + str(expected), messages)
                self.assertNotIn("SYNTHETIC_PRIVATE_DETAIL", messages + err)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.metrics.read_bytes(), self.initial)

    @logged
    def test_script_entrypoint_emits_one_document_and_run_logger_summary(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["yggctl", "--trace", "trend", "json"]),
            patch.object(main.sandbox, "worker_context", return_value=self.ctx),
            patch.object(main.signal, "signal"),
            patch.object(core.syslog, "syslog") as sink,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(Path(main.__file__)), run_name="__main__")
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["samples"], 8)
        self.assertRegex(stderr.getvalue(), r"^\[done\] errors=0 elapsed=\d+\.\d{2}s\n$")
        messages = [call.args[-1] for call in sink.call_args_list]
        self.assertTrue(
            any(line.startswith("yggctl run trend status=0 traced=") for line in messages)
        )
        self.assertEqual(self.calls, [])
