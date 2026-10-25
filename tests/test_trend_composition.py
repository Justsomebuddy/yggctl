"""Independent ambiguity/split/logging contracts for the composed trend pipeline."""

import datetime as dt
import json
from unittest.mock import patch

import core
from core import logged
import telemetry as tm
import test_trend as fixtures
from test_support import ConsoleFixture


class TrendComposition(ConsoleFixture):
    sample = fixtures.TrendReport.sample
    peer = fixtures.TrendReport.peer
    store = fixtures.TrendReport.store

    @logged
    def history(self, count=8):
        return [self.sample(1 + 10 * (count - i - 1), [self.peer()]) for i in range(count)]

    @logged
    def test_two_colliding_labels_count_samples_not_labels(self):
        rows = self.history()
        for row in rows:
            row["peers"] = [
                self.peer("ws://192.0.2.1:443/private-a"),
                self.peer("ws://192.0.2.1:443/private-b"),
                self.peer("tcp://192.0.2.2:1701"),
                self.peer("tcp://192.0.2.2:1701"),
            ]
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["ambiguous_labels"], ["tcp://192.0.2.2:1701", "ws://192.0.2.1:443"])
        self.assertEqual(report["ambiguous_peer_samples"], 8)
        self.assertEqual(report["reasons"], ["ambiguous_peer_labels"])
        self.assertEqual(report["verdict"], "insufficient_history")
        self.assertNotIn("private-a", json.dumps(report, allow_nan=False))
        for peer in report["peers"]:
            self.assertIsNone(peer["availability"])
            self.assertIsNone(peer["rtt_ms"])
            self.assertEqual(peer["present"], [4, 4])

    @logged
    def test_one_half_collision_with_invalid_state_preserves_counts(self):
        rows = self.history()
        rows[0]["peers"].extend([self.peer(up="true", rtt=float("inf")), None])
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["ambiguous_peer_samples"], 1)
        self.assertEqual(report["invalid_peer_rows"], 1)
        self.assertEqual(report["peers"][0]["present"], [4, 4])
        self.assertEqual(report["peers"][0]["invalid_states"], [0, 0])
        self.assertIsNone(report["peers"][0]["availability"])
        self.assertIsNone(report["peers"][0]["rtt_ms"])
        json.dumps(report, allow_nan=False)

    @logged
    def test_odd_middle_sample_is_not_folded_or_counted_as_ambiguous(self):
        rows = self.history(9)
        rows[4]["peers"].append(self.peer(rtt=1000))
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["samples"], 9)
        self.assertEqual(report["ambiguous_labels"], [])
        self.assertEqual(report["ambiguous_peer_samples"], 0)
        self.assertEqual(report["peers"][0]["present"], [4, 4])
        self.assertEqual(report["verdict"], "stable")

    @logged
    def test_unobserved_duplicates_are_not_an_answered_identity_observation(self):
        rows = self.history()
        rows[0]["peers_observed"] = False
        rows[0]["peers"].append(self.peer(rtt=1000))
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["ambiguous_labels"], [])
        self.assertEqual(report["ambiguous_peer_samples"], 0)
        self.assertEqual(report["peers"][0]["unobserved"], [1, 0])
        self.assertEqual(report["verdict"], "stable")

    @logged
    def test_trend_reads_one_snapshot_without_mutation_or_admin_calls(self):
        self.store(self.history())
        path = self.paths.state / "metrics.jsonl"
        before = path.read_bytes()
        with patch.object(tm, "window", wraps=tm.window) as window:
            report = tm.trend(self.ctx)
        self.assertEqual(window.call_count, 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(report["provenance"]["authenticated"], False)
        self.assertEqual(report["provenance"]["immutable_since_capture"], False)
        self.assertIn("undetected collisions", report["label_policy"])

    @logged
    def test_helpers_have_secret_safe_entry_exit_and_error_tracing(self):
        helpers = (
            "trend_window",
            "trend_report",
            "trend_collector_state",
            "trend_sample_labels",
            "trend_accumulate",
            "trend_sample_series",
            "trend_peer_series",
            "trend_node_block",
            "trend_peer_details",
            "trend_verdict",
        )
        self.store(self.history())
        with patch.object(core, "event") as trace:
            tm.trend(self.ctx)
            for name in helpers:
                trace.assert_any_call("entry", name)
                trace.assert_any_call("exit", name, "success")
            with self.assertRaises(IndexError):
                tm.trend_window([], [])
            trace.assert_any_call("error", "trend_window", "IndexError")

    @logged
    def test_ambiguity_logs_fixed_state_labels_without_raw_uri(self):
        rows = self.history()
        rows[0]["peers"] = [
            self.peer("ws://192.0.2.1:443/private-a"),
            self.peer("ws://192.0.2.1:443/private-b"),
        ]
        self.store(rows)
        with patch.object(tm, "event") as events:
            tm.trend(self.ctx)
        events.assert_any_call("state", "trend_ambiguity", "sample_label_collision")
        events.assert_any_call("state", "trend_ambiguity", "ambiguous_label_withheld")
        self.assertNotIn("private-a", str(events.call_args_list))
        self.assertNotIn("private-b", str(events.call_args_list))

    @logged
    def test_window_facts_and_verdict_helpers_remain_separate(self):
        now = dt.datetime.now(dt.timezone.utc)
        values = [(now - dt.timedelta(minutes=10), {"peers_observed": True}), (now, {})]
        facts = tm.trend_window(values, [now])
        self.assertEqual(facts["span"], 10)
        self.assertEqual(facts["cadence"], 10)
        self.assertEqual(facts["observed"], 1)
        self.assertEqual(facts["future"], 1)
        report = {"reasons": [], "malformed_peer_samples": 0, "node": {"error_rate": None}}
        self.assertEqual(tm.trend_verdict(report, [None], 0), "insufficient_history")
        self.assertEqual(report["reasons"], ["no_comparable_observed_metric"])
