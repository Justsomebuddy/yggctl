"""Real queue files/restarts; forwarding is an explicit flow-only adapter."""

import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

import core
import telemetry as tm
from core import Context, Failure, atomic
from test_support import ConsoleFixture


class QueueRetention(unittest.TestCase):
    def setUp(self):
        core.trace_quiet()
        self.fixture = ConsoleFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.ctx, self.p = self.fixture.ctx, self.fixture.paths
        self.queue = self.p.state / "alerts.jsonl"
        self.cursor = self.p.state / "alerts-forwarded.json"
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))

    def alert(self, n):
        return {"id": str(n), "kind": "labelled-local-selftest", "ts": "fixture"}

    def seed(self, values):
        atomic(self.queue, "".join(json.dumps(v, separators=(",", ":")) + "\n" for v in values))

    def checkpoint(self, ids):
        atomic(self.cursor, json.dumps({"sent": ids}))

    def split(self):
        values = tm.rows(self.ctx, "alerts.jsonl")
        notices = [v for v in values if v.get("kind") == "ygg-queue-retention"]
        alerts = [v for v in values if v.get("kind") != "ygg-queue-retention"]
        self.assertEqual(len(notices), 1)
        return notices[0]["evicted_uncheckpointed_total"], alerts

    def fresh(self):
        self.ctx = Context(self.p, runner=self.fixture.runner, require_root=False)

    def test_real_count_boundary_survives_restart_and_empty_backlog(self):
        self.checkpoint([])
        self.seed([self.alert(i) for i in range(1200)])
        tm.append(self.ctx, "alerts.jsonl", self.alert(1200), 1000)
        total, alerts = self.split()
        self.assertEqual(total, 201)
        self.assertEqual([a["id"] for a in alerts], [str(i) for i in range(201, 1201)])
        self.assertEqual(len(tm.rows(self.ctx, "alerts.jsonl")), 1001)
        self.fresh()
        with patch.object(tm.simplex_sender, "handoff", return_value=1) as handoff:
            tm.forward(self.ctx)
            tm.forward(self.ctx)
        self.assertEqual(handoff.call_count, 1000)
        self.assertTrue(all(c.args[2]["rule"].endswith("тревог") for c in handoff.call_args_list))
        self.assertIn("remaining=0", self.output.getvalue().splitlines()[-1])
        self.assertIn("evicted_uncheckpointed_total=201", self.output.getvalue().splitlines()[-1])
        self.assertEqual(self.split()[0], 201)

    def test_repeated_compaction_counts_eviction_occurrences_not_retry_success(self):
        self.checkpoint([])
        self.seed([self.alert(i) for i in range(6)])
        tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
        self.assertEqual(self.split()[0], 2)
        # A producer replay can reinsert an evicted ID; this is not a globally
        # unique-message counter. Each uncheckpointed eviction is observable.
        for i in (0, 7, 8):
            tm.append(self.ctx, "alerts.jsonl", self.alert(i), 5)
        total, alerts = self.split()
        self.assertEqual(total, 5)
        self.checkpoint([a["id"] for a in alerts])
        self.fresh()
        for i in (9, 10, 11):
            tm.append(self.ctx, "alerts.jsonl", self.alert(i), 5)
        self.assertEqual(self.split()[0], 5)

    def test_checkpointed_history_compacts_without_loss_notice(self):
        self.seed([self.alert(i) for i in range(6)])
        self.checkpoint(["0", "1"])
        tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [self.alert(i) for i in range(2, 7)])

    def test_missing_cursor_initializes_only_alerts_but_keeps_warning(self):
        self.seed([self.alert(i) for i in range(6)])
        tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
        self.fresh()
        with patch.object(tm.simplex_sender, "handoff") as handoff:
            tm.forward(self.ctx)
        handoff.assert_not_called()
        self.assertEqual(json.loads(self.cursor.read_bytes())["sent"], ["2", "3", "4", "5", "6"])
        self.assertIn("earlier alerts not sent", self.output.getvalue())
        self.assertIn("evicted_uncheckpointed_total=2", self.output.getvalue())

    def test_notice_visible_before_sender_failure(self):
        self.checkpoint([])
        self.seed([self.alert(i) for i in range(6)])
        tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
        with patch.object(tm.simplex_sender, "handoff", side_effect=Failure("fixture")):
            with self.assertRaisesRegex(Failure, "alert_forward_failed:count=5"):
                tm.forward(self.ctx)
        self.assertIn("evicted_uncheckpointed_total=2", self.output.getvalue())
        self.assertEqual(json.loads(self.cursor.read_bytes())["sent"], [])

    def test_byte_compaction_accounts_for_notice_and_retained_suffix(self):
        self.checkpoint([])
        self.seed([dict(self.alert(i), padding="x" * 150) for i in range(5)])
        before = tm.rows(self.ctx, "alerts.jsonl")
        # An actual pre-write byte-bound compaction, using a smaller injected
        # limit for the fixture; no claim of exercising a full 32 MiB workload.
        limit = self.queue.stat().st_size + 1
        with patch.object(tm, "METRICS_LIMIT", limit):
            tm.append(self.ctx, "alerts.jsonl", dict(self.alert(5), padding="y" * 200), 1000)
            total, alerts = self.split()
            self.assertLessEqual(self.queue.stat().st_size, limit)
        self.assertEqual(total + len(alerts), len(before) + 1)
        self.assertEqual(alerts[-1]["id"], "5")

    def test_failed_replace_preserves_rows_and_retry_counts_once(self):
        self.checkpoint([])
        self.seed([self.alert(i) for i in range(6)])
        with patch.object(core.os, "replace", side_effect=OSError("fixture replace")):
            with self.assertRaises(OSError):
                tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
        # The append was already fsynced; failed compaction discarded nothing.
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [self.alert(i) for i in range(7)])
        self.fresh()
        tm.append(self.ctx, "alerts.jsonl", self.alert(7), 5)
        self.assertEqual(self.split()[0], 3)

    def test_child_death_after_replace_recovers_notice_with_queue(self):
        self.checkpoint([])
        self.seed([self.alert(i) for i in range(6)])
        pid = os.fork()
        if pid == 0:
            replace = os.replace

            def die_after_replace(source, destination):
                replace(source, destination)
                os._exit(73)

            with patch.object(core.os, "replace", side_effect=die_after_replace):
                tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
            os._exit(74)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 73)
        self.fresh()
        self.assertEqual(self.split()[0], 2)
        tm.append(self.ctx, "alerts.jsonl", self.alert(7), 5)
        self.assertEqual(self.split()[0], 3)

    def test_corrupt_cursor_blocks_compaction_without_discarding_history(self):
        self.seed([self.alert(i) for i in range(6)])
        atomic(self.cursor, '{"sent":null}')
        with self.assertRaisesRegex(Failure, "alerts_forwarded_state_invalid"):
            tm.append(self.ctx, "alerts.jsonl", self.alert(6), 5)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [self.alert(i) for i in range(7)])

    def test_metrics_compaction_remains_independent_of_alert_cursor(self):
        atomic(self.cursor, "invalid")
        for i in range(7):
            tm.append(self.ctx, "metrics.jsonl", {"value": i}, 5)
        self.assertEqual(tm.rows(self.ctx), [{"value": i} for i in range(2, 7)])

    def notice(self, total=1):
        return {
            "kind": "ygg-queue-retention",
            "id": "ygg-queue-retention",
            "evicted_uncheckpointed_total": total,
        }

    def test_corrupt_or_duplicate_notice_never_discarded_or_forwarded(self):
        invalid = [
            [dict(self.notice(), extra=True)],
            [self.notice(), self.notice()],
            *[[self.notice(value)] for value in (None, True, 0, -1, 1 << 63)],
            [dict(self.notice(), id="")],
        ]
        for values in invalid:
            with self.subTest(values=values):
                self.seed(values)
                before = self.queue.read_bytes()
                with self.assertRaises(Failure):
                    tm.metric_compact(self.ctx, "alerts.jsonl", self.alert(1), 5)
                with patch.object(tm.simplex_sender, "handoff") as handoff:
                    with self.assertRaises(Failure):
                        tm.forward(self.ctx)
                handoff.assert_not_called()
                self.assertEqual(self.queue.read_bytes(), before)

    def test_reserved_kind_cannot_be_appended(self):
        self.seed([self.alert(0)])
        before = self.queue.read_bytes()
        for fn in (tm.append, tm.metric_compact):
            with self.assertRaisesRegex(Failure, "alert_retention_reserved"):
                fn(self.ctx, "alerts.jsonl", self.notice(), 5)
            self.assertEqual(self.queue.read_bytes(), before)

    def test_capacity_and_overflow_fail_before_replacement(self):
        self.checkpoint([])
        self.seed([self.alert(0)])
        before = self.queue.read_bytes()
        tm.metric_compact(self.ctx, "alerts.jsonl", self.alert(1), 1)
        self.assertEqual(self.split(), (1, [self.alert(1)]))
        self.seed([self.alert(0)])
        before = self.queue.read_bytes()
        with patch.object(tm, "METRICS_LIMIT", 100):
            with self.assertRaisesRegex(Failure, "alert_retention_capacity"):
                tm.metric_compact(self.ctx, "alerts.jsonl", self.alert(1), 5)
        self.assertEqual(self.queue.read_bytes(), before)
        self.seed([self.notice((1 << 63) - 1), self.alert(0), self.alert(1)])
        before = self.queue.read_bytes()
        with self.assertRaisesRegex(Failure, "alert_retention_overflow"):
            tm.metric_compact(self.ctx, "alerts.jsonl", self.alert(2), 2)
        self.assertEqual(self.queue.read_bytes(), before)

    def test_notice_only_and_no_eviction_compaction_preserve_total(self):
        self.seed([self.notice(9)])
        with patch.object(tm.simplex_sender, "handoff") as handoff:
            tm.forward(self.ctx)
            tm.forward(self.ctx)
        handoff.assert_not_called()
        self.assertEqual(json.loads(self.cursor.read_bytes()), {"sent": []})
        self.assertIn("evicted_uncheckpointed_total=9", self.output.getvalue())
        tm.metric_compact(self.ctx, "alerts.jsonl", self.alert(1), 5)
        self.assertEqual(self.split(), (9, [self.alert(1)]))

    def test_duplicate_rows_count_as_eviction_occurrences(self):
        self.checkpoint([])
        self.seed([self.alert(0), self.alert(0), self.alert(1)])
        tm.metric_compact(self.ctx, "alerts.jsonl", self.alert(2), 3)
        self.assertEqual(self.split(), (1, [self.alert(0), self.alert(1), self.alert(2)]))
        # Replaying and later evicting that same ID is another occurrence.
        tm.append(self.ctx, "alerts.jsonl", self.alert(0), 3)
        tm.append(self.ctx, "alerts.jsonl", self.alert(3), 3)
        tm.append(self.ctx, "alerts.jsonl", self.alert(4), 3)
        self.assertEqual(self.split(), (4, [self.alert(0), self.alert(3), self.alert(4)]))
