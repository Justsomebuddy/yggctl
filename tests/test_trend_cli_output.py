"""Complete CLI output contract for synthetic stored-history trends."""

import contextlib
import datetime as dt
import io
import json
import sys
from unittest.mock import patch

from core import atomic, logged
import main
from test_support import ConsoleFixture


class TrendCliOutput(ConsoleFixture):
    @logged
    def store(self, count):
        now = dt.datetime.now(dt.timezone.utc)
        rows = [
            {
                "schema": 2,
                "ts": (now - dt.timedelta(minutes=40 - index * 5)).isoformat(),
                "mode": "direct",
                "act": "active",
                "up": 1,
                "peers": [],
                "peers_observed": True,
                "stack_up": 1,
                "errors": [],
            }
            for index in range(count)
        ]
        atomic(
            self.paths.state / "metrics.jsonl",
            "".join(json.dumps(row) + "\n" for row in rows).encode(),
        )

    @logged
    def invoke(self, *words):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["yggctl", *words]),
            patch.object(main.sandbox, "worker_context", return_value=self.ctx),
            patch.object(main.signal, "signal"),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = main.main()
        return status, stdout.getvalue(), stderr.getvalue()

    @logged
    def test_stable_json_is_one_complete_document(self):
        self.store(8)
        status, stdout, stderr = self.invoke("trend", "2", "json")
        self.assertEqual(status, 0)
        report = json.loads(stdout, parse_constant=self.fail)
        self.assertEqual(report["verdict"], "stable")
        self.assertEqual(report["samples"], 8)
        self.assertNotIn("[done]", stdout)
        self.assertRegex(stderr, r"^\[done\] errors=0 elapsed=\d+\.\d{2}s\n$")

    @logged
    def test_insufficient_history_remains_usable_json(self):
        self.store(2)
        status, stdout, stderr = self.invoke("trend", "json")
        self.assertEqual(status, 0)
        report = json.loads(stdout, parse_constant=self.fail)
        self.assertEqual(report["verdict"], "insufficient_history")
        self.assertIn("fewer_than_8_samples", report["reasons"])
        self.assertNotIn("[done]", stdout)
        self.assertIn("[done] errors=0", stderr)

    @logged
    def test_text_trend_and_other_command_keep_stdout_summary(self):
        self.store(8)
        status, stdout, stderr = self.invoke("trend", "2")
        self.assertEqual(status, 0)
        self.assertIn("trend=stable", stdout)
        self.assertIn("[done] errors=0", stdout)
        self.assertEqual(stderr, "")

        status, stdout, stderr = self.invoke("help")
        self.assertEqual(status, 0)
        self.assertIn("[done] errors=0", stdout)
        self.assertEqual(stderr, "")

    @logged
    def test_trend_failure_has_no_stdout_or_success_summary(self):
        self.store(0)
        status, stdout, stderr = self.invoke("trend", "json")
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("FAIL no_samples_in_window", stderr)
        self.assertNotIn("[done]", stderr)

    @logged
    def test_malformed_arguments_are_not_successful_json(self):
        self.store(8)
        for words in (("trend", "json", "json"), ("trend", "2", "json", "extra")):
            with self.subTest(words=words):
                status, stdout, stderr = self.invoke(*words)
                self.assertEqual(status, 1)
                self.assertEqual(stdout, "")
                self.assertIn("FAIL ", stderr)
                self.assertNotIn("[done]", stderr)

    @logged
    def test_trace_does_not_pollute_json_stdout(self):
        self.store(8)
        with patch.object(main, "trace_live") as trace:
            status, stdout, stderr = self.invoke("--trace", "trend", "json")
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout, parse_constant=self.fail)["samples"], 8)
        self.assertIn("[done] errors=0", stderr)
        trace.assert_called_once_with()
