"""Synthetic health-alert intent and queue recovery; no native sender or network."""

import contextlib
import errno
import io
import json
import os
from unittest.mock import patch

from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture, URI
import telemetry as tm


class HealthOutboxTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        atomic(self.paths.state / "notify.state", "on\n", 0o644)
        self.queue = self.paths.state / "alerts.jsonl"

    @logged
    def degraded(self):
        with patch.object(tm, "peers", side_effect=Failure("source_unavailable")):
            return tm.collect(self.ctx)

    @logged
    def pending(self):
        return tm.load_peer_state(self.ctx).get("pending", [])

    @logged
    def restarted(self):
        return Context(self.paths, runner=self.runner, require_root=False)

    @logged
    def test_queue_write_failure_preserves_original_health_after_healthy_restart(self):
        original = os.open

        @logged
        def denied_queue(path, flags, *args, **kwargs):
            if path == self.queue and flags & (os.O_WRONLY | os.O_RDWR):
                raise OSError(errno.EACCES, "synthetic queue write denial")
            return original(path, flags, *args, **kwargs)

        with patch.object(tm.os, "open", side_effect=denied_queue):
            with self.assertRaises(OSError):
                self.degraded()
        saved = self.pending()
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["kind"], "ygg-health")
        self.assertEqual(saved[0]["errors"], ["source_unavailable"])
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])
        self.assertEqual(tm.rows(self.ctx, "metrics.jsonl")[0]["errors"], saved[0]["errors"])

        self.assertEqual(tm.collect(self.restarted())["errors"], [])
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)
        self.assertEqual(self.pending(), [])
        tm.collect(self.restarted())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)

    @logged
    def test_queue_commit_before_pending_clear_reuses_exact_health_event(self):
        sample = {"ts": "2026-10-24T10:00:00+00:00", "errors": ["source_unavailable"]}
        tm.stage_health_alert(self.ctx, sample)
        saved = self.pending()
        original = tm.save_peer_state

        @logged
        def interrupted_clear(ctx, state):
            if state.get("pending") == []:
                raise KeyboardInterrupt()
            return original(ctx, state)

        with patch.object(tm, "save_peer_state", side_effect=interrupted_clear):
            with self.assertRaises(KeyboardInterrupt):
                tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)
        self.assertEqual(self.pending(), saved)
        tm.flush_peer_alerts(self.restarted())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)
        self.assertEqual(self.pending(), [])

    @logged
    def test_health_and_peer_pending_replay_together(self):
        peer = {
            "id": "peer-event",
            "ts": "2026-10-24T10:00:00+00:00",
            "kind": "ygg-peer-down",
            "peer": URI,
            "minutes": 10,
            "up": 0,
            "total": 1,
        }
        tm.save_peer_state(self.ctx, {"pending": [peer]})
        tm.stage_health_alert(self.ctx, {"ts": peer["ts"], "errors": ["source_unavailable"]})
        saved = self.pending()
        self.assertEqual([row["kind"] for row in saved], ["ygg-peer-down", "ygg-health"])
        tm.flush_peer_alerts(self.restarted())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)
        self.assertEqual(self.pending(), [])

    @logged
    def test_failed_initial_replay_still_stages_fresh_health(self):
        peer = {
            "id": "peer-event",
            "ts": "2026-10-24T10:00:00+00:00",
            "kind": "ygg-peer-down",
            "peer": URI,
        }
        tm.save_peer_state(self.ctx, {"pending": [peer]})
        original = tm.append

        @logged
        def fail_queue(ctx, name, *args, **kwargs):
            if name == "alerts.jsonl":
                raise OSError(errno.EIO, "synthetic queue failure")
            return original(ctx, name, *args, **kwargs)

        with patch.object(tm, "append", side_effect=fail_queue):
            with self.assertRaises(OSError):
                self.degraded()
        saved = self.pending()
        self.assertEqual([row["kind"] for row in saved], ["ygg-peer-down", "ygg-health"])
        tm.flush_peer_alerts(self.restarted())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)

    @logged
    def test_corrupt_initial_queue_preserves_fresh_observation_gap_before_health_check(self):
        peer = {
            "id": "peer-event",
            "ts": "2026-10-24T10:00:00+00:00",
            "kind": "ygg-peer-down",
            "peer": URI,
        }
        tm.save_peer_state(self.ctx, {"pending": [peer]})
        atomic(self.queue, b"corrupt queue record\n")
        with patch.object(tm, "flush_peer_alerts", side_effect=Failure("first_replay_error")):
            with self.assertRaisesRegex(Failure, "first_replay_error"):
                self.degraded()
        state = tm.load_peer_state(self.ctx)
        self.assertTrue(state["observation_gap"])
        self.assertEqual(state["pending"], [peer])

    @logged
    def test_same_hour_pending_and_queue_dedup_and_notify_off(self):
        sample = {"ts": "2026-10-24T10:00:00+00:00", "errors": ["first"]}
        tm.stage_health_alert(self.ctx, sample)
        saved = self.pending()
        tm.stage_health_alert(self.ctx, {"ts": sample["ts"], "errors": ["second"]})
        self.assertEqual(self.pending(), saved)
        tm.flush_peer_alerts(self.ctx)
        tm.stage_health_alert(self.ctx, {"ts": sample["ts"], "errors": ["third"]})
        self.assertEqual(self.pending(), [])
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved)
        tm.notify(self.ctx, "off")
        with patch.object(tm, "peers", side_effect=Failure("source_unavailable")):
            with self.assertRaises(Failure):
                tm.collect(self.ctx)
        self.assertEqual(self.pending(), [])

    @logged
    def test_full_pending_and_invalid_health_do_not_mutate_state(self):
        peer = {"id": "peer", "ts": "t", "kind": "ygg-peer-down", "peer": URI}
        tm.save_peer_state(
            self.ctx, {"pending": [dict(peer, id=str(n)) for n in range(tm.PEER_PENDING_LIMIT)]}
        )
        before = (self.paths.state / "alert-state.json").read_bytes()
        with self.assertRaisesRegex(Failure, "alert_pending_limit"):
            tm.stage_health_alert(self.ctx, {"ts": "t", "errors": ["source_unavailable"]})
        self.assertEqual((self.paths.state / "alert-state.json").read_bytes(), before)
        good = {
            "id": "x",
            "ts": "t",
            "kind": "ygg-health",
            "key": "collect:2026102410",
            "errors": ["failure"],
        }
        for bad in (
            dict(good, extra=True),
            dict(good, key=1),
            dict(good, key="short"),
            dict(good, key="notlect:2026102410"),
            dict(good, key="collect:20261024００"),
            dict(good, key="collect:20261024xx"),
            dict(good, errors="failure"),
            dict(good, errors=[]),
            dict(good, errors=[1]),
        ):
            atomic(self.paths.state / "alert-state.json", json.dumps({"pending": [bad]}))
            with self.assertRaisesRegex(Failure, "alert_pending_invalid"):
                tm.load_peer_state(self.ctx)
