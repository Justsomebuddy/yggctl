"""Forwarder control-flow mocks; real native acceptance is tested separately."""

import contextlib
import io
import json
from pathlib import Path
import subprocess  # nosec B404 # Fixed synthetic interpreter/result fixtures.
from unittest.mock import patch

import telemetry
from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture, URI, process_handoff_fixture


class ForwardFlow(ConsoleFixture):
    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_alerts_forward_once_and_retry_failures(self):
        sent, rc = [], [0]

        def runner(argv, **kw):
            if argv[0] == telemetry.SENDER:
                sent.append(json.loads(kw["input"]))
                return subprocess.CompletedProcess(argv, rc[0], b"", b"")
            return self.ctx.runner(argv, **kw)

        ctx = Context(self.paths, runner, require_root=False)
        telemetry.append(
            ctx,
            "alerts.jsonl",
            {"ts": "t0", "kind": "ygg-health", "errors": ["node_inactive"]},
            1000,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(ctx)
            self.assertEqual(sent, [])
            telemetry.append(
                ctx,
                "alerts.jsonl",
                {
                    "ts": "t1",
                    "id": "a1",
                    "kind": "ygg-peer-down",
                    "peer": URI,
                    "minutes": 12,
                    "up": 5,
                    "total": 6,
                },
                1000,
            )
            rc[0] = 75
            with self.assertRaisesRegex(Failure, "alert_forward_failed:count=1"):
                telemetry.forward(ctx)
            rc[0] = 0
            telemetry.forward(ctx)
            telemetry.forward(ctx)
        self.assertEqual(len(sent), 2)
        message = sent[-1]
        self.assertEqual(
            (message["rule"], message["priority"], message["source"]),
            (f"Yggdrasil: пир {URI} недоступен", "Warning", "yggctl"),
        )
        self.assertIn(URI, message["output"])
        self.assertIn("12 мин", message["output"])
        self.assertLessEqual(len(message["output"]), 300)

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_forward_sigterm_does_not_replay_completed_handoff(self):
        import signal

        self.prepare_forward_pending(2)
        script = """
import sys, os, signal, subprocess, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from core import Context, Paths, logged, trace_quiet, Failure
import telemetry
trace_quiet()
calls = []
@logged
def sender(argv, **kwargs):
    calls.append(1)
    if len(calls) == 2:
        os.kill(os.getpid(), signal.SIGTERM)
    return subprocess.CompletedProcess(argv, 0, b'', b'')
def fake_handoff(ctx, aid, payload, timeout=20):
    r=ctx.run([telemetry.SENDER], input=json.dumps(payload).encode(), timeout=timeout, check=False)
    if r.returncode: raise Failure("synthetic_handoff_failed")
    return 1
telemetry.simplex_sender.handoff=fake_handoff
telemetry.forward(Context(Paths(state=Path(sys.argv[2])), sender, require_root=False))
"""
        # Security review: fixed interpreter argv exercises the offline error boundary
        result = subprocess.run(  # nosec B603
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                script,
                str(Path(telemetry.__file__).resolve().parent),
                str(self.paths.state),
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"], ["a0"]
        )
        sent = []

        @logged
        def sender(argv, **kwargs):
            sent.append(json.loads(kwargs["input"])["output"])
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(self.ctx, "runner", sender), contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(self.ctx)
        self.assertEqual(len(sent), 1)
        self.assertIn("a1", sent[0])

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_forward_budget_leaves_checkpoint_and_retryable_backlog(self):
        self.prepare_forward_pending(6)
        clock, timeouts = [0.0], []

        @logged
        def sender(argv, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += kwargs["timeout"]
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with (
            patch("telemetry.time.monotonic", side_effect=lambda: clock[0]),
            patch.object(self.ctx, "runner", sender),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(Failure, "alert_forward_budget_pending"):
                telemetry.forward(self.ctx)
        self.assertEqual(timeouts, [20, 20, 20, 20, 5])
        self.assertLess(clock[0], 120)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"],
            ["a0", "a1", "a2", "a3", "a4"],
        )

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_forward_timeout_checkpoints_prior_success_and_continues(self):
        self.prepare_forward_pending(2)

        @logged
        def sender(argv, **kwargs):
            if "a1" in json.loads(kwargs["input"])["output"]:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(self.ctx, "runner", sender), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(Failure, "alert_forward_failed:count=1"):
                telemetry.forward(self.ctx)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"], ["a0"]
        )

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_forward_invalid_checkpoint_fails_before_sender(self):
        self.prepare_forward_pending(1)
        for value in ("{}", "[]", '{"sent":"bad"}', '{"sent":[1]}', '{"sent":["a","a"]}'):
            atomic(self.paths.state / "alerts-forwarded.json", value)
            with patch.object(self.ctx, "run") as sender:
                with self.assertRaisesRegex(Failure, "alerts_forwarded_state_invalid"):
                    telemetry.forward(self.ctx)
                sender.assert_not_called()

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_forward_budget_includes_lock_wait(self):
        self.prepare_forward_pending(5)
        clock, timeouts = [0.0], []
        locked = self.ctx.locked

        @contextlib.contextmanager
        @logged
        def delayed_lock():
            clock[0] += 20
            with locked():
                yield

        @logged
        def sender(argv, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += kwargs["timeout"]
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with (
            patch("telemetry.time.monotonic", side_effect=lambda: clock[0]),
            patch.object(self.ctx, "locked", delayed_lock),
            patch.object(self.ctx, "runner", sender),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(Failure, "alert_forward_budget_pending"):
                telemetry.forward(self.ctx)
        self.assertEqual(timeouts, [20, 20, 20, 5])
        self.assertEqual(clock[0], 85)

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_forward_bad_alert_ids_rejected_and_initial_duplicates_coalesced(self):
        for aid in ("", "a" * 129, 12, None):
            with self.assertRaisesRegex(Failure, "invalid_alert_id"):
                telemetry.alert_id({"id": aid})
        alert = {"kind": "synthetic"}
        atomic(self.paths.state / "alerts.jsonl", (json.dumps(alert) + "\n") * 2)
        with contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(self.ctx)
        sent = json.loads((self.paths.state / "alerts-forwarded.json").read_text())["sent"]
        self.assertEqual(len(sent), 1)
        with patch.object(self.ctx, "run") as sender, contextlib.redirect_stdout(io.StringIO()):
            telemetry.forward(self.ctx)
            sender.assert_not_called()
