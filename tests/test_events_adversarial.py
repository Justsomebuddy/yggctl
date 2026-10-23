"""Independent event-window contracts at the real Context.run boundary; no journal access."""

import contextlib
import io
import json

# Synthetic CompletedProcess/TimeoutExpired only; no subprocess execution here.
import subprocess  # nosec B404
import sys
from unittest.mock import patch

from core import NODE, STACK, logged
import main
from test_support import ConsoleFixture


class EventsAdversarial(ConsoleFixture):
    @logged
    def invoke(self, *words, raw=b"", rc=0, error=None, stderr=b""):
        commands = []

        @logged
        def journal(argv, **kwargs):
            commands.append((argv, kwargs))
            if error is not None:
                raise error
            return subprocess.CompletedProcess(argv, rc, raw, stderr)

        stdout, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["yggctl", *words]),
            patch.object(main.sandbox, "worker_context", return_value=self.ctx),
            patch.object(main.signal, "signal"),
            patch.object(self.ctx, "runner", side_effect=journal),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(errors),
        ):
            status = main.main()
        return status, stdout.getvalue(), errors.getvalue(), commands

    @logged
    def document(self, stdout):
        value, end = json.JSONDecoder().raw_decode(stdout)
        self.assertTrue(stdout[end:].lstrip().startswith("[done]"))
        return value

    @logged
    def test_journal_argv_and_existing_bounds(self):
        rc, stdout, stderr, commands = self.invoke("events", "72")
        self.assertEqual((rc, stderr), (0, ""))
        argv, kwargs = commands[0]
        self.assertEqual(
            argv,
            [
                "/usr/bin/journalctl",
                "-u",
                NODE,
                "-u",
                STACK,
                "--no-pager",
                "-o",
                "json",
                "-n",
                "1001",
                "--since",
                "72 hours ago",
            ],
        )
        self.assertEqual(kwargs["timeout"], 20)
        self.assertIs(kwargs["check"], False)
        self.assertEqual(self.document(stdout)["returned"], 0)

    @logged
    def test_nonzero_timeout_and_oserror_are_not_success(self):
        for options in (
            {"rc": 1, "raw": b'{"MESSAGE":"must-not-project"}', "stderr": b"private-marker"},
            {"error": OSError("private-marker")},
            {"error": subprocess.TimeoutExpired("private-marker", 20)},
        ):
            with self.subTest(options=tuple(options)):
                rc, stdout, stderr, _ = self.invoke("events", "1", **options)
                self.assertEqual((rc, stdout), (1, ""))
                self.assertIn("FAIL external_", stderr)
                self.assertNotIn("private-marker", stderr)
                self.assertNotIn("must-not-project", stderr)

    @logged
    def test_real_context_byte_caps_preserved(self):
        for options in (
            {"raw": b"x" * (16 * 1024 * 1024 + 1)},
            {"stderr": b"x" * (1024 * 1024 + 1)},
        ):
            with self.subTest(stream=tuple(options)):
                rc, stdout, stderr, _ = self.invoke("events", **options)
                self.assertEqual((rc, stdout), (1, ""))
                self.assertIn("external_output_limit", stderr)

    @logged
    def test_hostile_numeric_and_extra_arguments_do_not_read_journal(self):
        for args in (("0",), ("73",), ("-1",), ("1.0",), ("1;echo x",), ("9" * 5000,), ("1", "2")):
            with self.subTest(lengths=tuple(map(len, args))):
                rc, stdout, stderr, commands = self.invoke("events", *args)
                self.assertEqual((rc, stdout, commands), (1, "", []))
                self.assertIn("FAIL", stderr)

    @logged
    def test_malformed_probe_record_fails_before_truncation_or_partial_output(self):
        tail = b"\n".join([b'{"MESSAGE":"safe"}'] * 1000)
        for bad in (b"invalid", b"[]", b"null", b"\xff", b"[" * 1500):
            with self.subTest(kind=len(bad)):
                rc, stdout, stderr, _ = self.invoke("events", raw=bad + b"\n" + tail)
                self.assertEqual((rc, stdout), (1, ""))
                self.assertIn("invalid_journal_json_no_raw_output", stderr)
                self.assertNotIn("events_truncated", stderr)

    @logged
    def test_redaction_of_probe_and_returned_records_and_safe_metadata(self):
        rows = [{"MESSAGE": "password=synthetic-overflow-marker"}]
        rows.extend({"MESSAGE": f"event-{i}"} for i in range(999))
        rows.append(
            {
                "MESSAGE": "token=synthetic-visible-marker",
                "_SYSTEMD_UNIT": "unsafe-unit",
                "__REALTIME_TIMESTAMP": "unsafe-timestamp",
            }
        )
        raw = b"\n".join(json.dumps(row).encode() for row in rows)
        with patch.object(main, "event") as events:
            rc, stdout, stderr, _ = self.invoke("events", raw=raw)
        self.assertEqual(rc, 0)
        doc = self.document(stdout)
        self.assertEqual((doc["returned"], doc["truncated"]), (1000, True))
        self.assertIn("events_truncated", stderr)
        self.assertEqual(doc["logs"][0]["message"], "event-0")
        self.assertEqual(
            doc["logs"][-1],
            {
                "unit": "unknown",
                "timestamp_us": "unknown",
                "message": "[REDACTED sensitive journal message]",
            },
        )
        self.assertEqual(events.call_count, 2)
        self.assertNotIn("synthetic-overflow-marker", stdout + stderr)
        self.assertNotIn("synthetic-visible-marker", stdout + stderr)

    @logged
    def test_does_not_sort_or_deduplicate_journal_record_order(self):
        # Realtime clocks can move backwards; preserve journalctl's sequence,
        # including equal metadata, rather than sort/deduplicate on timestamp.
        rows = [
            {"MESSAGE": str(i), "__REALTIME_TIMESTAMP": str(2000 - i // 2)} for i in range(1001)
        ]
        rc, stdout, _, _ = self.invoke(
            "events", raw=b"\n".join(json.dumps(row).encode() for row in rows)
        )
        self.assertEqual(rc, 0)
        self.assertEqual(
            [row["message"] for row in self.document(stdout)["logs"]],
            [str(i) for i in range(1, 1001)],
        )

    @logged
    def test_no_mutating_journal_option_or_follow_mode(self):
        for command in ("events", "logs"):
            rc, _, _, calls = self.invoke(command)
            self.assertEqual(rc, 0)
            argv = calls[0][0]
            self.assertEqual(len(calls), 1)
            self.assertFalse(set(argv) & {"--rotate", "--vacuum-time", "--flush", "-f", "--follow"})
