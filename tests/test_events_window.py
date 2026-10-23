"""Events time windows and visible bounded truncation; synthetic journal only."""

import contextlib
import datetime as dt
import io
import json

# Synthetic CompletedProcess only; this module launches no processes.
import subprocess  # nosec B404
import sys
from unittest.mock import patch

from core import Failure, logged
import main
from test_support import ConsoleFixture


class EventsWindow(ConsoleFixture):
    @logged
    def invoke(self, *words, count=13, raw=None, failure=None):
        now = dt.datetime.now(dt.timezone.utc)
        records = [
            json.dumps(
                {
                    "MESSAGE": f"event-{i}",
                    "__REALTIME_TIMESTAMP": str(int(now.timestamp() * 1e6) - count + i),
                }
            ).encode()
            for i in range(count)
        ]
        commands = []

        def journal(argv, **kwargs):
            commands.append(argv)
            if failure:
                raise failure
            limit = int(argv[argv.index("-n") + 1])
            data = raw if raw is not None else b"\n".join(records[-limit:])
            return subprocess.CompletedProcess(argv, 0, data, b"")

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["yggctl", *words]),
            patch.object(main.sandbox, "worker_context", return_value=self.ctx),
            patch.object(main.signal, "signal"),
            patch.object(self.ctx, "run", side_effect=journal),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = main.main()
        return code, stdout.getvalue(), stderr.getvalue(), commands

    @logged
    def document(self, stdout):
        # Existing human CLI completion line remains outside this JSON projection.
        result, end = json.JSONDecoder().raw_decode(stdout)
        self.assertTrue(stdout[end:].lstrip().startswith("[done]"))
        return result

    @logged
    def test_hours_do_not_limit_number_of_events(self):
        for hours in (1, 12, 72):
            with self.subTest(hours=hours):
                code, stdout, stderr, commands = self.invoke("events", str(hours))
                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                document = self.document(stdout)
                self.assertEqual(len(document["logs"]), 13)
                self.assertEqual(document["logs"][0]["message"], "event-0")
                self.assertEqual(document["window_hours"], hours)
                self.assertEqual(document["limit"], 1000)
                self.assertEqual(document["returned"], 13)
                self.assertIs(document["truncated"], False)
                self.assertIn(f"{hours} hours ago", commands[0])

    @logged
    def test_default_window_and_truncation_boundaries(self):
        for count in (0, 999, 1000, 1001, 1100):
            with self.subTest(count=count):
                code, stdout, stderr, commands = self.invoke("events", count=count)
                self.assertEqual(code, 0)
                document = self.document(stdout)
                self.assertEqual(document["window_hours"], 6)
                self.assertEqual(document["returned"], min(count, 1000))
                self.assertEqual(len(document["logs"]), min(count, 1000))
                self.assertEqual(document["truncated"], count > 1000)
                self.assertIn("6 hours ago", commands[0])
                self.assertEqual(commands[0][commands[0].index("-n") + 1], "1001")
                if count:
                    self.assertEqual(
                        document["logs"][0]["message"], f"event-{max(0, count - 1000)}"
                    )
                    self.assertEqual(document["logs"][-1]["message"], f"event-{count - 1}")
                if count > 1000:
                    self.assertIn("events_truncated", stderr)
                else:
                    self.assertEqual(stderr, "")

    @logged
    def test_logs_keep_line_count_contract(self):
        for args, limit in (((), 50), (("12",), 12), (("1000",), 1000)):
            with self.subTest(args=args):
                code, stdout, stderr, commands = self.invoke("logs", *args, count=1100)
                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                document = self.document(stdout)
                self.assertEqual(set(document), {"logs"})
                self.assertEqual(len(document["logs"]), limit)
                self.assertNotIn("--since", commands[0])

    @logged
    def test_bad_hours_rejected_before_journal_read(self):
        for value in ("0", "73", "bad"):
            with self.subTest(value=value):
                code, stdout, stderr, commands = self.invoke("events", value)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("FAIL", stderr)
                self.assertEqual(commands, [])

    @logged
    def test_journal_failures_do_not_look_like_empty_success(self):
        for kwargs in (
            {"raw": b"invalid journal"},
            {"failure": Failure("synthetic_journal_failed")},
        ):
            with self.subTest(kwargs=kwargs):
                code, stdout, stderr, _ = self.invoke("events", "1", **kwargs)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("FAIL", stderr)
                self.assertNotIn("invalid journal", stderr)

    @logged
    def test_message_redaction_remains_active(self):
        raw = json.dumps({"MESSAGE": "password=synthetic-sensitive-marker"}).encode()
        code, stdout, _, _ = self.invoke("events", "1", raw=raw)
        self.assertEqual(code, 0)
        self.assertNotIn("synthetic-sensitive-marker", stdout)
        self.assertEqual(
            self.document(stdout)["logs"][0]["message"], "[REDACTED sensitive journal message]"
        )
