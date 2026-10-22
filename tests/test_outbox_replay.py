"""Synthetic checks for durable peer alerts across queue rotation and replay."""

import contextlib
import datetime as dt
import errno
import io
import json
import os
import unittest
from unittest.mock import patch

import telemetry as tm
from core import Failure, atomic, logged
from test_support import ConsoleFixture, URI


class OutboxReplayTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.now = dt.datetime(2026, 10, 21, 9, tzinfo=dt.timezone.utc)
        self.state_path = self.paths.state / "alert-state.json"
        self.queue_path = self.paths.state / "alerts.jsonl"

    @logged
    def pending_events(self, count):
        return [
            {
                "id": f"pending-{n:04d}",
                "kind": "ygg-peer-down",
                "ts": self.now.isoformat(),
                "peer": tm.peer_label(URI.replace("192.0.2.1", f"192.0.2.{n % 250 + 1}")),
                "minutes": 11,
                "up": 0,
                "total": 1,
            }
            for n in range(count)
        ]

    @logged
    def seed_queue(self, rows):
        atomic(self.queue_path, "".join(json.dumps(row) + "\n" for row in rows))

    @logged
    def test_crash_replay_rotation_retains_evicted_pending_until_retry(self):
        peers = [URI, URI.replace("192.0.2.1", "192.0.2.2")]
        state = {
            "down": {
                peer: {
                    "since": (self.now - dt.timedelta(minutes=11)).isoformat(),
                    "alerted": False,
                }
                for peer in peers
            },
            "starts": {},
            "unstable": {},
        }
        atomic(self.state_path, json.dumps(state))
        atomic(self.paths.state / "notify.state", "on\n")
        sample = {"ts": self.now.isoformat(), "peers": [{"r": peer, "up": False} for peer in peers]}
        tm.peer_alerts(self.ctx, sample)
        pending = tm.load_peer_state(self.ctx)["pending"]
        self.assertEqual(len(pending), 2)

        pid = os.fork()
        if pid == 0:
            original_append = tm.append
            calls = 0

            @logged
            def stop_after_first(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    os._exit(73)
                return original_append(*args, **kwargs)

            with patch.object(tm, "append", side_effect=stop_after_first):
                tm.flush_peer_alerts(self.ctx)
            os._exit(74)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 73)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending[:1])
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], pending)

        for _ in range(1199):
            tm.notify(self.ctx, "test")
        self.assertEqual(len(tm.rows(self.ctx, "alerts.jsonl")), 1200)

        with self.assertRaisesRegex(Failure, "alert_pending_retained_after_queue_rotation"):
            tm.flush_peer_alerts(self.ctx)
        queued = {row["id"]: row for row in tm.rows(self.ctx, "alerts.jsonl")}
        self.assertNotIn(pending[0]["id"], queued)
        self.assertEqual(queued[pending[1]["id"]], pending[1])
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], pending[:1])

        tm.flush_peer_alerts(self.ctx)
        queued = {row["id"]: row for row in tm.rows(self.ctx, "alerts.jsonl")}
        self.assertEqual([queued[item["id"]] for item in pending], pending)
        ids = [row["id"] for row in tm.rows(self.ctx, "alerts.jsonl")]
        self.assertTrue(all(ids.count(item["id"]) == 1 for item in pending))
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_full_pending_batch_only_acknowledges_final_queue_members(self):
        pending = self.pending_events(tm.PEER_PENDING_LIMIT)
        tm.save_peer_state(self.ctx, {"pending": pending})
        fillers = [
            {"id": f"filler-{n:04d}", "kind": "labelled-local-selftest", "ts": self.now.isoformat()}
            for n in range(700)
        ]
        self.seed_queue(pending[:500] + fillers)

        for _ in range(10):
            try:
                tm.flush_peer_alerts(self.ctx)
            except Failure as exc:
                self.assertEqual(str(exc), "alert_pending_retained_after_queue_rotation")
            queued = {row["id"]: row for row in tm.rows(self.ctx, "alerts.jsonl")}
            remaining = tm.load_peer_state(self.ctx)["pending"]
            missing_ids = {item["id"] for item in pending if queued.get(item["id"]) != item}
            self.assertEqual({item["id"] for item in remaining}, missing_ids)
            if not remaining:
                break
        self.assertEqual(remaining, [])
        self.assertTrue(all(queued.get(item["id"]) == item for item in pending))
        ids = [row["id"] for row in tm.rows(self.ctx, "alerts.jsonl")]
        self.assertTrue(all(ids.count(item["id"]) == 1 for item in pending))

    @logged
    def test_final_queue_read_failure_leaves_all_pending_for_retry(self):
        pending = self.pending_events(1)
        tm.save_peer_state(self.ctx, {"pending": pending})
        original_rows = tm.rows
        reads = 0

        @logged
        def fail_final_read(*args, **kwargs):
            nonlocal reads
            reads += 1
            if reads == 2:
                raise OSError(errno.EIO, "synthetic final read failure")
            return original_rows(*args, **kwargs)

        with patch.object(tm, "rows", side_effect=fail_final_read), self.assertRaises(OSError):
            tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], pending)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_final_durability_failure_does_not_acknowledge_partial_batch(self):
        pending = self.pending_events(2)
        tm.save_peer_state(self.ctx, {"pending": pending})
        with patch.object(tm, "sync_alert_queue", side_effect=OSError(errno.EIO, "synthetic")):
            with self.assertRaises(OSError):
                tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], pending)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])


if __name__ == "__main__":
    unittest.main()
