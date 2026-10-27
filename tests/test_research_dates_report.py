"""Independent synthetic report paths and additional calendar-edge controls."""

import contextlib
import datetime as dt
import io
import json
from pathlib import Path
from unittest.mock import patch

from core import Failure, atomic, logged
import research as rs
from research import metrics, model
from observed_fixture import ObservedFixture, NOW

BOUNDARIES = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00")


class ReportDateBoundaries(ObservedFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_actual_report_preserves_good_metrics(self):
        good = {"ts": NOW, "schema": 2, "act": "active", "up": 0, "errors": [], "peers": []}
        for boundary in BOUNDARIES:
            with (
                self.subTest(boundary=boundary),
                patch.object(rs, "timestamp", return_value=NOW),
                patch.object(rs.telemetry, "rows", return_value=[{"ts": boundary}, good]),
            ):
                result = rs.report(self.ctx, 1)
                self.assertFalse(result["unknown_history"])
                saved = json.loads(Path(result["json_file"]).read_text())
                self.assertEqual(saved["history"]["samples"], 1)
                self.assertEqual(saved["history"]["invalid_records"], 1)

    @logged
    def test_actual_report_rejects_invalid_snapshot_without_rewrite(self):
        good = self.observation()
        root = rs.folder(self.ctx, create=True)
        target = root / ("snapshot-" + good["id"] + ".json")
        for boundary in BOUNDARIES:
            for field in ("started", "finished"):
                bad = dict(good, **{field: boundary})
                data = json.dumps(bad)
                atomic(target, data)
                with (
                    self.subTest(boundary=boundary, field=field),
                    patch.object(rs, "timestamp", return_value=NOW),
                ):
                    caught = None
                    try:
                        rs.report(self.ctx, 1)
                    except Exception as exc:
                        caught = (type(exc), str(exc) if isinstance(exc, Failure) else None)
                    self.assertEqual(caught, (Failure, "research_invalid_timestamp"))
                    self.assertEqual(target.read_text(), data)

    @logged
    def test_representable_edges_and_offset_equivalence(self):
        for hours in (1, 24, 72):
            first = dt.datetime(1, 1, 1, tzinfo=dt.timezone.utc)
            end = first + dt.timedelta(hours=hours)
            result = metrics.summary([{"ts": first.isoformat()}], hours, end.isoformat())
            self.assertEqual(result["samples"], 1)
            self.assertEqual(result["window_start"], first.isoformat())
            self.assertEqual(
                model.instant("9999-12-31T23:59:59.999999Z"),
                dt.datetime.max.replace(tzinfo=dt.timezone.utc),
            )
        for hours in (-23, -1, 0, 1, 23):
            expected = dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc)
            text = expected.astimezone(dt.timezone(dt.timedelta(hours=hours))).isoformat()
            self.assertEqual(model.instant(text), expected)
