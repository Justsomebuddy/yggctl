"""Composed producer replay/retention contracts; synthetic files and no live sender."""

import contextlib
import errno
import io
import json
from unittest.mock import patch

import telemetry as tm
from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture, URI


class AlertComposition(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.queue = self.paths.state / "alerts.jsonl"

    @logged
    def pending(self, count):
        return [
            {
                "id": f"composed-{n}",
                "kind": "ygg-peer-down",
                "ts": "2026-10-22T00:00:00+00:00",
                "peer": tm.peer_label(URI),
                "minutes": 11,
                "up": 0,
                "total": 1,
            }
            for n in range(count)
        ]

    @logged
    def seed(self, alerts, total=23):
        notice = {
            "kind": tm.ALERT_RETENTION_KIND,
            "id": tm.ALERT_RETENTION_ID,
            "evicted_uncheckpointed_total": total,
        }
        atomic(self.queue, "".join(json.dumps(row) + "\n" for row in [notice, *alerts]))
        atomic(self.paths.state / "alerts-forwarded.json", '{"sent":[]}\n')

    @logged
    def test_marker_does_not_steal_full_pending_capacity_even_after_restart(self):
        for capacity in (1, 2, 4):
            with self.subTest(capacity=capacity), patch.object(tm, "PEER_PENDING_LIMIT", capacity):
                pending = self.pending(capacity)
                tm.save_peer_state(self.ctx, {"pending": pending})
                self.seed([{"id": "old", "kind": "labelled-local-selftest"}])
                tm.flush_peer_alerts(self.ctx)
                self.ctx = Context(self.paths, runner=self.runner, require_root=False)
                tm.flush_peer_alerts(self.ctx)
                notice, alerts = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
                self.assertEqual(alerts, pending)
                self.assertEqual(notice["evicted_uncheckpointed_total"], 24)
                self.assertEqual(len(tm.rows(self.ctx, "alerts.jsonl")), capacity + 1)
                self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])
                self.assertLessEqual(self.queue.stat().st_size, tm.METRICS_LIMIT)

    @logged
    def test_full_already_queued_pending_ack_keeps_exact_marker_and_payloads(self):
        pending = self.pending(3)
        tm.save_peer_state(self.ctx, {"pending": pending})
        self.seed(pending)
        before = self.queue.read_bytes()
        with patch.object(tm, "append") as append:
            tm.flush_peer_alerts(self.ctx)
        append.assert_not_called()
        self.assertEqual(self.queue.read_bytes(), before)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_crash_window_after_compaction_does_not_double_count_on_replay(self):
        pending = self.pending(2)
        tm.save_peer_state(self.ctx, {"pending": pending})
        self.seed([{"id": "old", "kind": "labelled-local-selftest"}])
        with (
            patch.object(tm, "PEER_PENDING_LIMIT", 2),
            patch.object(tm, "save_peer_state", side_effect=OSError(errno.EIO, "fixture")),
            self.assertRaises(OSError),
        ):
            tm.flush_peer_alerts(self.ctx)
        notice, alerts = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
        self.assertEqual(alerts, pending)
        self.assertEqual(notice["evicted_uncheckpointed_total"], 24)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], pending)
        self.ctx = Context(self.paths, runner=self.runner, require_root=False)
        before = self.queue.read_bytes()
        with patch.object(tm, "PEER_PENDING_LIMIT", 2):
            tm.flush_peer_alerts(self.ctx)
        self.assertEqual(self.queue.read_bytes(), before)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_byte_pressure_retains_missing_ids_without_claiming_full_batch_ack(self):
        pending = [dict(row, padding="x" * 400) for row in self.pending(2)]
        tm.save_peer_state(self.ctx, {"pending": pending})
        self.seed([])
        previous_total = 23
        for _ in range(2):
            with (
                patch.object(tm, "PEER_PENDING_LIMIT", 2),
                patch.object(tm, "METRICS_LIMIT", 1000),
                self.assertRaisesRegex(Failure, "alert_pending_retained_after_queue_rotation"),
            ):
                tm.flush_peer_alerts(self.ctx)
            notice, alerts = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
            self.assertLessEqual(self.queue.stat().st_size, 1000)
            self.assertGreater(notice["evicted_uncheckpointed_total"], previous_total)
            previous_total = notice["evicted_uncheckpointed_total"]
            remaining = tm.load_peer_state(self.ctx)["pending"]
            self.assertEqual(remaining, [row for row in pending if row not in alerts])
            self.assertEqual(len(remaining), 1)
            # Recreate a full durable batch to model a caller retry after its own
            # state checkpoint failed; no duplicate ID is invented or suppressed.
            tm.save_peer_state(self.ctx, {"pending": pending})

    @logged
    def test_checkpointed_eviction_does_not_increase_prior_loss_marker(self):
        self.seed([{"id": "old", "kind": "labelled-local-selftest"}], total=9)
        atomic(self.paths.state / "alerts-forwarded.json", '{"sent":["old"]}\n')
        tm.metric_compact(self.ctx, "alerts.jsonl", self.pending(1)[0], 1)
        notice, alerts = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
        self.assertEqual(notice["evicted_uncheckpointed_total"], 9)
        self.assertEqual(alerts, self.pending(1))

    @logged
    def test_watch_counts_identified_raw_peers_in_both_instances(self):
        valid = dict(self.ps[0])
        raw = [valid, dict(valid, key=""), dict(valid, key="invalid"), dict(valid, up=False)]
        with patch.object(tm, "peers", side_effect=[raw, raw[:1]]) as peers:
            tm.watch(self.ctx, count=1)
        self.assertEqual(peers.call_count, 2)
        self.assertIn("node_up=1 stack_up=1 errors=0", self.output.getvalue())
        self.assertIn("processed=1 errors=0", self.output.getvalue())
