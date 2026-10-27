"""Причинные проверки границ календаря на искусственной истории, без живого узла."""

import copy
import datetime as dt
import json
from pathlib import Path

from core import Failure, atomic, logged
import research as rs
from research import metrics, model
from observed_fixture import ObservedFixture, NOW

BOUNDARIES = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00")


class TimestampOverflow(ObservedFixture):
    @logged
    def test_instant_normalizes_both_overflows(self):
        for value in BOUNDARIES:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(Failure, "^research_invalid_timestamp$"),
            ):
                model.instant(value)
        self.assertEqual(model.instant(NOW), dt.datetime.fromisoformat(NOW))
        with self.assertRaisesRegex(Failure, "^research_naive_timestamp$"):
            model.instant("2026-10-19T10:00:00")

    @logged
    def test_summary_keeps_good_neighbor_and_counts_invalid(self):
        good = {"ts": NOW, "schema": 2, "act": "active", "up": 0, "errors": [], "peers": []}
        expected = metrics.summary([good], 1, NOW)
        for value in BOUNDARIES:
            with self.subTest(value=value):
                actual = metrics.summary([{"ts": value}, good], 1, NOW)
                self.assertEqual(actual["invalid_records"], 1)
                actual["invalid_records"] = 0
                self.assertEqual(actual, expected)
        for value in BOUNDARIES:
            with (
                self.subTest(now=value),
                self.assertRaisesRegex(Failure, "^research_invalid_timestamp$"),
            ):
                metrics.summary([good], 1, value)

    @logged
    def test_snapshot_load_rejects_both_boundary_fields(self):
        good = self.observation()
        path = Path(self.tmp.name) / ("snapshot-" + good["id"] + ".json")
        atomic(path, json.dumps(good))
        self.assertEqual(rs.load(path), good)
        for field in ("started", "finished"):
            for value in BOUNDARIES:
                bad = copy.deepcopy(good)
                bad[field] = value
                atomic(path, json.dumps(bad))
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaisesRegex(Failure, "^research_invalid_timestamp$"),
                ):
                    rs.load(path)

    @logged
    def test_summary_rejects_unrepresentable_window(self):
        # Допустимая UTC-дата тоже не позволяет вычесть час перед первым годом.
        with self.assertRaisesRegex(Failure, "^research_invalid_timestamp$"):
            metrics.summary([], 1, "0001-01-01T00:00:00+00:00")
        self.assertEqual(metrics.summary([], 1, "0001-01-01T01:00:00+00:00")["invalid_records"], 0)
