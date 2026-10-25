"""Synthetic durable admission warnings; no external sender or node."""

import contextlib
import datetime as dt
import io
import json
from unittest.mock import patch

from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture, URI
import telemetry as tm


class AlertAdmissionTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.path = self.paths.state / "alert-state.json"
        self.now = dt.datetime(2026, 10, 24, 10, tzinfo=dt.timezone.utc)
        self.enterContext(patch.object(tm, "timestamp", return_value=self.now.isoformat()))
        atomic(self.paths.state / "notify.state", "on\n", 0o644)

    @logged
    def state(self):
        return tm.load_peer_state(self.ctx)

    @logged
    def peer_sample(self, up=True):
        return {"ts": self.now.isoformat(), "peers": [{"r": URI, "up": up}]}

    @logged
    def pending_peer(self):
        return {"id": "original", "ts": self.now.isoformat(), "kind": "ygg-peer-down", "peer": URI}

    @logged
    def test_peer_refusal_marks_once_and_keeps_pending_and_tracking(self):
        original = self.pending_peer()
        state = {
            "pending": [original],
            "down": {URI: {"since": self.now.isoformat(), "alerted": True}},
            "starts": {},
            "unstable": {},
        }
        tm.save_peer_state(self.ctx, state)
        with patch.object(tm, "PEER_PENDING_LIMIT", 1):
            with self.assertRaisesRegex(Failure, "alert_pending_limit"):
                tm.peer_alerts(self.ctx, self.peer_sample())
            first = self.path.read_bytes()
            with self.assertRaisesRegex(Failure, "alert_pending_limit"):
                tm.peer_alerts(self.ctx, self.peer_sample())
        self.assertEqual(self.path.read_bytes(), first)
        self.assertEqual(self.state()["pending"], [original])
        self.assertEqual(self.state()["down"], state["down"])
        self.assertIs(self.state()["admission_incomplete"], True)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])

    @logged
    def test_health_refusal_marker_is_independent_of_queue_and_retention(self):
        original = self.pending_peer()
        tm.save_peer_state(self.ctx, {"pending": [original]})
        with patch.object(tm, "PEER_PENDING_LIMIT", 1):
            with self.assertRaisesRegex(Failure, "alert_pending_limit"):
                tm.stage_health_alert(
                    self.ctx, {"ts": self.now.isoformat(), "errors": ["degraded"]}
                )
        self.assertEqual(self.state()["pending"], [original])
        self.assertIs(self.state()["admission_incomplete"], True)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])
        tm.flush_peer_alerts(self.ctx)
        self.assertEqual(self.state()["pending"], [])
        self.assertIs(self.state()["admission_incomplete"], True)
        self.assertEqual(tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))[0], None)

    @logged
    def test_legacy_false_and_invalid_marker(self):
        self.assertEqual(self.state(), {})
        tm.save_peer_state(self.ctx, {"admission_incomplete": False})
        self.assertIs(self.state()["admission_incomplete"], False)
        tm.peer_alerts(self.ctx, self.peer_sample())
        self.assertIs(self.state()["admission_incomplete"], False)
        invalid: object
        for invalid in (0, 1, "yes", None, [], {}):
            with self.subTest(invalid=invalid):
                atomic(self.path, json.dumps({"admission_incomplete": invalid}))
                with self.assertRaisesRegex(Failure, "alert_state_invalid"):
                    tm.load_peer_state(self.ctx)

    @logged
    def test_marker_survives_disabled_notify_gap_and_observed_recovery(self):
        tm.save_peer_state(self.ctx, {"admission_incomplete": True})
        tm.notify(self.ctx, "off")
        tm.peer_alerts(self.ctx, {"ts": self.now.isoformat(), "peers_observed": False})
        self.assertIs(self.state()["admission_incomplete"], True)
        tm.peer_alerts(self.ctx, self.peer_sample(up=False))
        self.assertIs(self.state()["admission_incomplete"], True)
        self.assertEqual(self.state()["pending"], [])
        tm.notify(self.ctx, "show")
        self.assertIn("WARNING alert_admission_incomplete=yes", self.output.getvalue())

    @logged
    def test_healthy_collect_and_forward_surfaces_warning_with_empty_backlog(self):
        tm.save_peer_state(self.ctx, {"admission_incomplete": True})
        restarted = Context(self.paths, runner=self.runner, require_root=False)
        tm.collect(restarted)
        self.assertIn("sample recorded; processed=2", self.output.getvalue())
        self.assertIn("notification_history_may_be_incomplete=yes", self.output.getvalue())
        tm.forward(restarted)  # First-run cursor initialisation.
        self.assertIn("forwarding initialised", self.output.getvalue())
        tm.forward(restarted)  # Empty steady-state backlog.
        self.assertIn("alerts handoff finished", self.output.getvalue())
        self.assertEqual(self.output.getvalue().count("WARNING alert_admission_incomplete=yes"), 3)
        self.assertIs(self.state()["admission_incomplete"], True)

    @logged
    def test_failed_marker_write_does_not_report_durable_marker(self):
        original = self.pending_peer()
        tm.save_peer_state(self.ctx, {"pending": [original]})
        before = self.path.read_bytes()
        with (
            patch.object(tm, "PEER_PENDING_LIMIT", 1),
            patch.object(tm, "save_peer_state", side_effect=OSError("synthetic write failure")),
        ):
            with self.assertRaises(OSError):
                tm.stage_health_alert(
                    self.ctx, {"ts": self.now.isoformat(), "errors": ["degraded"]}
                )
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(self.state().get("admission_incomplete", False))
