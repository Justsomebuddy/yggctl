"""Adversarial numeric, provenance and observation contracts for stored trends."""

import json
import contextlib
import io
from typing import Any
from unittest.mock import patch

from core import Failure, logged
import main
import telemetry as tm
import test_trend as fixtures
from test_support import ConsoleFixture


class RobustTrend(ConsoleFixture):
    args = fixtures.TrendReport.args
    sample = fixtures.TrendReport.sample
    peer = fixtures.TrendReport.peer
    store = fixtures.TrendReport.store

    @logged
    def setUp(self):
        super().setUp()
        self.stdout = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.stdout))

    @logged
    def healthy(self):
        return [self.sample(age, [self.peer()]) for age in range(71, 0, -10)]

    @logged
    def test_finite_numeric_boundary_and_overflow_reason(self):
        self.assertIsNone(tm.trend_number(10**400))
        self.assertEqual(tm.trend_median([1e308, 1e308]), 1e308)
        self.assertEqual(tm.trend_median([1, 3, 5]), 3)
        detail = tm.trend_drift([1e308, 1e308], [1e308, 1e308], 5)
        json.dumps(detail, allow_nan=False)
        self.assertEqual(detail["delta"], 0)
        reasons: list[str] = []
        self.assertIsNone(tm.trend_drift([0, 1.7e308], [1], 5, reasons=reasons))
        self.assertEqual(reasons, ["arithmetic_overflow"])
        self.assertIsNone(tm.trend_drift([0, 1.7e308], [1], 5))
        self.assertIsNone(tm.trend_drift([10**400], [1], 5, reasons=reasons))
        self.assertEqual(reasons[-1], "no_valid_samples_in_one_half")
        self.assertEqual(tm.trend_drift([0, 1], [2], 5)["threshold"], 5)

    @logged
    def test_strict_projected_state_and_zero_rtt(self):
        junk_values: list[Any] = [1, "false", [], None]
        for junk in junk_values:
            row = self.peer(rtt=0)
            row["up"] = junk
            report = tm.trend_peer([row, row])
            self.assertIsNone(report["availability"])
            self.assertEqual(report["invalid_states"], [1, 1])
            self.assertEqual(report["answered"], [1, 1])
        detail = tm.trend_peer([self.peer(rtt=0)] * 2)
        self.assertEqual(detail["rtt_ms"]["first"], 0)
        with self.assertRaisesRegex(Failure, "trend_observation_length_mismatch"):
            tm.trend_peer([None], [])
        absent = tm.trend_peer([self.peer(), None, self.peer(), None])
        self.assertEqual(absent["present"], [1, 1])
        self.assertEqual(absent["answered"], [2, 2])
        self.assertEqual(absent["absent"], [1, 1])
        self.assertEqual(absent["availability"]["first"], 100)
        unknown = tm.trend_peer([self.peer()] * 2, [False, "true"])
        self.assertEqual(unknown["unobserved"], [1, 1])
        compatibility = tm.trend_peer_block([1, 1], [1, 1], [[0], [0]], [1, 1], [0, 0])
        self.assertEqual(compatibility["availability"]["first"], 100)

    @logged
    def test_future_tail_single_snapshot_and_distinct_evidence(self):
        rows = self.healthy()
        rows.append(self.sample(-10, [self.peer()]))
        self.store(rows)
        with patch.object(tm, "rows", wraps=tm.rows) as read:
            report = tm.trend(self.ctx)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(report["future_samples"], 1)
        self.assertEqual(report["collector"], "future_timestamp")
        self.assertEqual(report["verdict"], "insufficient_history")
        self.assertIn("future_samples_present", report["reasons"])
        repeated = [rows[0]] * 4 + [rows[-2]] * 4
        self.store(repeated)
        report = tm.trend(self.ctx)
        self.assertEqual(report["distinct_samples"], 2)
        self.assertIn("fewer_than_8_samples", report["reasons"])
        self.store([rows[-2]] * 8)
        self.assertIsNone(tm.trend(self.ctx)["sampling_minutes"])
        self.store([rows[-1]])
        with self.assertRaisesRegex(Failure, "no_samples_in_window"):
            tm.trend(self.ctx)

    @logged
    def test_malformed_and_missing_observation_not_false_stable(self):
        rows = self.healthy()
        for row in rows:
            row["up"], row["peers"] = None, []
        self.store(rows)
        self.assertIn("no_comparable_observed_metric", tm.trend(self.ctx)["reasons"])
        for row in rows:
            row["up"], row["peers"] = 1, 1
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["malformed_peer_samples"], 8)
        self.assertIn("malformed_peer_samples", report["reasons"])
        for row in rows:
            row["peers"] = [1, {"r": None, "up": "false"}, self.peer(rtt=10**400)]
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["invalid_peer_rows"], 8)
        self.assertTrue(any(p["availability"] is None for p in report["peers"]))
        self.assertGreater(sum(p["numeric_validation"]["invalid"] for p in report["peers"]), 0)
        json.dumps(report, allow_nan=False)

    @logged
    def test_unverified_visible_semantics_and_read_only_cli(self):
        self.store(self.healthy())
        file = self.paths.state / "metrics.jsonl"
        before = file.read_bytes()
        with patch.object(tm, "peers", side_effect=AssertionError("unexpected_admin_call")):
            report = tm.trend(self.ctx)
            main.do_trend(self.ctx, self.args("2", "json"), ["2", "json"])
        self.assertEqual(before, file.read_bytes())
        self.assertFalse(report["provenance"]["authenticated"])
        self.assertFalse(report["provenance"]["immutable_since_capture"])
        self.assertEqual(
            report["rtt_semantics"], "router_response_ewma_not_link_or_application_delay"
        )
        text = "\n".join(tm.trend_text(report))
        for phrase in (
            "unverified_role_writable_history",
            "unauthenticated",
            "NOT link/application delay",
            "NOT equal elapsed-time",
        ):
            self.assertIn(phrase, text)
        data = json.loads(self.stdout.getvalue())
        self.assertEqual(data["provenance"], report["provenance"])
        for args in (("1", "72"), ("json", "json"), ("json", "1")):
            with self.assertRaises(Failure):
                main.do_trend(self.ctx, self.args(*args), list(args))

    @logged
    def test_batch_numeric_logging_no_per_value_events(self):
        with patch.object(tm, "event") as logger:
            tm.trend_drift([1] * 100 + [10**400], [1] * 100, 5)
        validation = [
            call for call in logger.call_args_list if call.args[1] == "trend_numeric_validation"
        ]
        self.assertEqual(len(validation), 1)
        self.assertIn("checked=201 invalid=1", validation[0].args[2])
        self.assertFalse(any(call.args[1] == "trend_number" for call in logger.call_args_list))
