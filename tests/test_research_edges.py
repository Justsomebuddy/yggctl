"""Persisted provenance validation, retention caps and unknown historical data."""

import contextlib
import copy
import datetime as dt
import io
import json
from unittest.mock import patch

from core import Failure, atomic, logged
import research as rs
from research import model, metrics
from observed_fixture import ObservedFixture, B, NOW


class ResearchEdges(ObservedFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_model_primitive_and_projection_errors(self):
        for value, label in (
            (1, "invalid_timestamp"),
            ("bad", "invalid_timestamp"),
            ("2026-01-01", "naive_timestamp"),
        ):
            with self.assertRaisesRegex(Failure, label):
                model.instant(value)
        for name, reply, label in (
            ("self", [], "invalid_self"),
            ("paths", {"paths": [{"key": B, "path": None}]}, "invalid_path"),
            ("other", {"other": [{}]}, "unknown_source"),
        ):
            with self.assertRaisesRegex(Failure, label):
                model.project(name, reply)
        self.assertEqual(model.project("paths", {"paths": []}), [])
        with self.assertRaisesRegex(Failure, "invalid_entries"):
            model.entries({"peers": [None]}, "peers")

    @logged
    def test_persisted_snapshot_schema_failure_matrix(self):
        good = self.observation()
        cases = [
            ("schema", 2, "unknown_schema"),
            ("id", "bad", "invalid_snapshot_id"),
            ("finished", "2000-01-01T00:00:00+00:00", "reversed_time"),
            ("identity_stable", 1, "invalid_consistency"),
            ("sources", [], "invalid_sources"),
            ("observations", {}, "invalid_observations"),
        ]
        for name, value, label in cases:
            bad = copy.deepcopy(good)
            bad[name] = value
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                model.validate(bad)
        for status, data, label in (
            ("bogus", None, "invalid_source_status"),
            ("unavailable", [], "unavailable_has_data"),
            ("ok", {}, "invalid_entries"),
            ("ok", [{}], "invalid_peer_projection"),
            ("ok", [dict(good["observations"]["peers"][0], latency_ms=-1)], "invalid_latency"),
        ):
            bad = copy.deepcopy(good)
            bad["sources"]["peers"], bad["observations"]["peers"] = status, data
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                model.validate(bad)
        bad = copy.deepcopy(good)
        bad["observations"]["self"]["extra"] = True
        with self.assertRaisesRegex(Failure, "noncanonical_projection"):
            model.validate(bad)
        bad = copy.deepcopy(good)
        bad["sources"]["self"], bad["observations"]["self"] = "unavailable", None
        with self.assertRaisesRegex(Failure, "consistency_without_self"):
            model.validate(bad)
        bad["identity_stable"] = None
        graph = model.graph(bad)
        self.assertFalse(any(e["kind"] == "direct_peer" for e in graph["edges"]))

    @logged
    def test_private_store_limits_files_and_selection(self):
        self.ctx.require_root = True
        with patch.object(self.ctx, "root"), patch.object(rs.checks, "trusted") as trust:
            root = rs.folder(self.ctx, True)
            self.assertEqual(trust.call_count, 2)
        self.ctx.require_root = False
        with self.assertRaisesRegex(Failure, "no_snapshots"):
            rs.selected(self.ctx)
        with self.assertRaisesRegex(Failure, "snapshot_not_found"):
            rs.selected(self.ctx, "0" * 32)
        valid = self.observation()
        path = root / ("snapshot-" + valid["id"] + ".json")
        atomic(path, json.dumps(valid))
        self.assertEqual(rs.selected(self.ctx, valid["id"])["id"], valid["id"])
        with (
            patch.object(rs, "LIMIT", 1),
            self.assertRaisesRegex(Failure, "retention_review_required"),
        ):
            rs.capture(self.ctx)
        with self.assertRaisesRegex(Failure, "snapshot_filename_mismatch"):
            other = root / ("snapshot-" + "0" * 32 + ".json")
            atomic(other, json.dumps(valid))
            rs.load(other)
        with patch.object(rs, "LIMIT", 1), self.assertRaisesRegex(Failure, "snapshot_limit"):
            rs.snapshot_files(self.ctx)
        atomic(root / ("map-" + "0" * 32 + ".dot"), "graph{}")
        atomic(root / ("report-" + "0" * 32 + ".md"), "report")
        with patch.object(rs, "LIMIT", 1), self.assertRaisesRegex(Failure, "store_entry_limit"):
            rs.snapshot_files(self.ctx)
        for p in root.iterdir():
            p.unlink()
        (root / ("map-" + "0" * 32 + ".dot")).mkdir()
        with self.assertRaisesRegex(Failure, "unsafe_store_entry"):
            rs.snapshot_files(self.ctx)

    @logged
    def test_capture_identity_unavailable_and_size(self):
        original = self.ctx.api
        count = 0

        @logged
        def api(method, **kw):
            nonlocal count
            if method == "getSelf":
                count += 1
                if count == 2:
                    raise Failure("fixture")
            return original(method, **kw)

        with (
            patch.object(self.ctx, "api", side_effect=api),
            self.assertRaisesRegex(Failure, "partial_snapshot_saved"),
        ):
            rs.capture(self.ctx)
        self.assertIsNone(rs.snapshots(self.ctx)[0]["identity_stable"])
        with (
            patch.object(rs, "BYTE_LIMIT", 1),
            self.assertRaisesRegex(Failure, "projected_snapshot_size"),
        ):
            rs.capture(self.ctx)

    @logged
    def test_metrics_caps_bad_records_and_invalid_endpoints(self):
        for value in (None, "", "x" * 2049):
            with self.assertRaisesRegex(Failure, "invalid_metric_peer_id"):
                metrics.peer_identity(value)
        self.assertIsNone(metrics.peer_identity("tls://[bad")[1])
        for records, hours, label in (
            ([], 0, "invalid_window"),
            (None, 1, "metric_record_limit"),
            ([{}] * 12001, 1, "metric_record_limit"),
        ):
            with self.assertRaisesRegex(Failure, label):
                metrics.summary(records, hours, NOW)
        row = {
            "ts": NOW,
            "schema": 2,
            "act": "active",
            "up": 1,
            "errors": [],
            "peers": [None, {"r": 123}, {"r": "tls://example.invalid:1", "up": True}],
        }
        result = metrics.summary([None, row], 1, NOW)
        self.assertEqual(result["invalid_records"], 1)
        self.assertEqual(result["invalid_or_duplicate_peer_rows"], 2)
        self.assertEqual(result["unknown_records"], 1)
        self.assertEqual(result["peers"][0]["up_samples"], 0)
        rows = [
            dict(
                row,
                ts=(dt.datetime.fromisoformat(NOW) - dt.timedelta(seconds=i)).isoformat(),
                peers=[{"r": "tls://example.invalid:1", "up": True}] * 4096,
            )
            for i in range(25)
        ]
        with self.assertRaisesRegex(Failure, "metric_peer_row_limit"):
            metrics.summary(rows, 1, NOW)
        rows = [
            dict(row, peers=[{"r": f"tls://node{i}.invalid:1", "up": True} for i in range(4096)]),
            dict(
                row,
                ts="2026-10-19T09:59:59+00:00",
                peers=[{"r": "tls://overflow.invalid:1", "up": True}],
            ),
        ]
        with self.assertRaisesRegex(Failure, "metric_endpoint_limit"):
            metrics.summary(rows, 1, NOW)

    @logged
    def test_report_incomplete_history_and_retention(self):
        root = rs.folder(self.ctx, True)
        for i in range(128):
            atomic(root / ("report-" + f"{i:032x}" + ".md"), "fixture")
        with self.assertRaisesRegex(Failure, "report_retention_review"):
            rs.report(self.ctx)
        for p in root.iterdir():
            p.unlink()
        first = self.observation()
        second = copy.deepcopy(first)
        second["id"] = "1" * 32
        for value in (first, second):
            atomic(root / ("snapshot-" + value["id"] + ".json"), json.dumps(value))
        with (
            patch.object(rs.model, "difference", side_effect=Failure("different_identity")),
            patch.object(rs.telemetry, "rows", side_effect=Failure("corrupt")),
        ):
            result = rs.report(self.ctx)
        self.assertTrue(result["unknown_history"])
        saved = json.loads(open(result["json_file"]).read())
        self.assertEqual(saved["topology"]["skipped_comparisons"], 1)
        self.assertIn("UNKNOWN", open(result["markdown_file"]).read())

    @logged
    def test_select_missing_after_saved_and_first_identity_unavailable(self):
        root = rs.folder(self.ctx, True)
        value = self.observation()
        atomic(root / ("snapshot-" + value["id"] + ".json"), json.dumps(value))
        with self.assertRaisesRegex(Failure, "snapshot_not_found"):
            rs.selected(self.ctx, "0" * 32)
        original = self.ctx.api
        count = 0

        @logged
        def api(method, **kw):
            nonlocal count
            if method == "getSelf":
                count += 1
                if count == 1:
                    raise Failure("unavailable_first")
            return original(method, **kw)

        with (
            patch.object(self.ctx, "api", side_effect=api),
            self.assertRaisesRegex(Failure, "partial_snapshot_saved"),
        ):
            rs.capture(self.ctx)

    @logged
    def test_report_window_validation(self):
        for hours in (0, 73, True):
            with self.assertRaisesRegex(Failure, "research_invalid_window"):
                rs.report(self.ctx, hours)
