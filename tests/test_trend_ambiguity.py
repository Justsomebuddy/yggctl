"""Shared sanitized labels in stored trends: no fused per-link comparison.

Several links can render to one label (different WebSocket paths at one
endpoint, or an unsupported option the sanitizer drops). The 5.12.0 alert
contract already treats duplicate labels as ambiguous observations; the stored
trend must not fuse those links into one comparable numeric series either.
"""

import contextlib
import io
import json

from core import logged
import main
import telemetry as tm
import test_trend as fixtures
from test_support import ConsoleFixture

PIN = "1" * 64
SHARED_A = "ws://192.0.2.1:443/path-a?key=" + PIN
SHARED_B = "ws://192.0.2.1:443/path-b?key=" + PIN
LABEL = "ws://192.0.2.1:443"
CLEAN = "tcp://192.0.2.9:1701?key=" + PIN


class TrendAmbiguity(ConsoleFixture):
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
    def colliding(self, clean=False):
        """Two links at one endpoint, both present in every sample.

        Each link keeps a constant latency; only their order inside a sample
        changes halfway through the window.
        """
        rows = []
        for position, age in enumerate(range(71, 0, -10)):
            links = [self.peer(SHARED_A, rtt=10.0), self.peer(SHARED_B, rtt=1000.0)]
            if position >= 4:
                links.reverse()
            if clean:
                links.append(self.peer(CLEAN, rtt=25.0))
            rows.append(self.sample(age, links))
        return rows

    @logged
    def test_shared_label_links_are_not_fused_into_one_series(self):
        self.assertEqual(tm.peer_label(SHARED_A), LABEL)
        self.assertEqual(tm.peer_label(SHARED_B), LABEL)
        self.store(self.colliding())
        report = tm.trend(self.ctx)
        # Without this contract the two constant series were merged in sample
        # order and reported rtt 10.0 -> 1000.0 verdict=degrading for links whose
        # latency never changed.
        self.assertEqual(report["ambiguous_labels"], [LABEL])
        self.assertEqual(report["ambiguous_peer_samples"], 8)
        self.assertIn("ambiguous_peer_labels", report["reasons"])
        self.assertEqual(report["verdict"], "insufficient_history")
        self.assertEqual(len(report["peers"]), 1)
        row = report["peers"][0]
        self.assertEqual(row["peer"], LABEL)
        self.assertIsNone(row["availability"])
        self.assertIsNone(row["rtt_ms"])
        self.assertEqual(
            row["not_comparable"],
            {"availability": ["ambiguous_peer_label"], "rtt_ms": ["ambiguous_peer_label"]},
        )
        # Counts stay visible: both halves observed this label in every sample.
        self.assertEqual(row["present"], [4, 4])
        self.assertEqual(row["observed"], [4, 4])
        self.assertEqual(row["absent"], [0, 0])
        json.dumps(report, allow_nan=False)

    @logged
    def test_unique_label_is_still_compared_and_a_duplicate_row_is_ambiguous(self):
        rows = [self.sample(age, [self.peer(CLEAN, rtt=25.0)]) for age in range(71, 0, -10)]
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["ambiguous_labels"], [])
        self.assertEqual(report["ambiguous_peer_samples"], 0)
        self.assertNotIn("ambiguous_peer_labels", report["reasons"])
        self.assertEqual(report["verdict"], "stable")
        self.assertEqual(report["peers"][0]["rtt_ms"]["verdict"], "stable")
        self.assertEqual(report["peers"][0]["availability"]["verdict"], "stable")
        # One sample listing the same URI twice is ambiguous too, exactly as the
        # alert contract counts duplicate labels in one observation.
        rows[-1]["peers"].append(self.peer(CLEAN, rtt=25.0))
        self.store(rows)
        report = tm.trend(self.ctx)
        self.assertEqual(report["ambiguous_labels"], [CLEAN])
        self.assertEqual(report["ambiguous_peer_samples"], 1)
        self.assertIsNone(report["peers"][0]["rtt_ms"])
        self.assertEqual(report["peers"][0]["present"], [4, 4])
        self.assertEqual(report["verdict"], "insufficient_history")

    @logged
    def test_ambiguous_label_does_not_block_other_peers(self):
        self.store(self.colliding(clean=True))
        report = tm.trend(self.ctx)
        rows = {row["peer"]: row for row in report["peers"]}
        self.assertEqual(sorted(rows), sorted([CLEAN, LABEL]))
        self.assertIsNone(rows[LABEL]["rtt_ms"])
        self.assertIsNone(rows[LABEL]["availability"])
        self.assertEqual(rows[CLEAN]["rtt_ms"]["verdict"], "stable")
        self.assertEqual(rows[CLEAN]["availability"]["verdict"], "stable")
        self.assertEqual(rows[CLEAN]["not_comparable"], {"availability": [], "rtt_ms": []})
        self.assertEqual(report["ambiguous_labels"], [LABEL])
        self.assertEqual(report["verdict"], "insufficient_history")

    @logged
    def test_text_and_json_reports_disclose_ambiguity(self):
        self.store(self.colliding())
        report = tm.trend(self.ctx)
        text = "\n".join(tm.trend_text(report))
        self.assertIn(f"ambiguous_labels=['{LABEL}'] ambiguous_peer_samples=8", text)
        self.assertIn("reasons=ambiguous_peer_labels", text)
        self.assertIn("'rtt_ms': ['ambiguous_peer_label']", text)
        self.assertIn("do not identify origins and are not compared", text)
        self.assertNotIn("degrading", text)
        main.do_trend(self.ctx, self.args("24", "json"), ["24", "json"])
        data = json.loads(self.stdout.getvalue())
        self.assertEqual(data["ambiguous_labels"], [LABEL])
        self.assertEqual(data["ambiguous_peer_samples"], 8)
        self.assertIsNone(data["peers"][0]["rtt_ms"])
        self.assertEqual(data["reasons"], ["ambiguous_peer_labels"])
