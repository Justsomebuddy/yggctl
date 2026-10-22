"""Truthful provenance, not store-owner forgery prevention or API attestation."""

import contextlib
import copy
import io
import json
from pathlib import Path
from unittest.mock import patch

from core import Failure, logged
import research
from research import metrics, model
from test_support import ConsoleFixture

A, B = "a" * 64, "b" * 64
NOW = "2026-10-19T10:00:00+00:00"


class ResearchTrust(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.responses.update(
            getSelf={"key": A, "routing_entries": 0},
            getPeers={"peers": []},
            getTree={"tree": []},
            getPaths={"paths": []},
        )

    @logged
    def capture_at(self, when):
        with patch.object(research, "timestamp", return_value=when):
            return research.capture(self.ctx)

    @logged
    def report_at_end(self):
        with patch.object(research, "timestamp", return_value=NOW):
            result = research.report(self.ctx, 1)
        saved = json.loads(Path(result["json_file"]).read_text())
        self.assert_unverified(result["provenance"])
        self.assert_unverified(saved["provenance"])
        rendered = Path(result["markdown_file"]).read_text()
        self.assertIn("UNVERIFIED role-writable snapshot history", rendered)
        self.assertIn("no authenticity/immutability guarantee", rendered)
        self.assertIn("do not verify origin, immutability or API truth", rendered)
        return result, saved

    @logged
    def assert_unverified(self, value):
        self.assertEqual(value["status"], "unverified_role_writable_history")
        self.assertIs(value["authenticated"], False)
        self.assertIs(value["immutable_since_capture"], False)
        self.assertIn("role-writable and unauthenticated", value["warning"])

    @logged
    def test_capture_map_and_dot_expose_unattested_role_writable_history(self):
        result = self.capture_at("2026-10-19T09:05:00+00:00")
        self.assert_unverified(result["provenance"])
        self.assertEqual(result["acquisition"], "local_api_sequential_unattested")
        self.assertIn("provenance=unverified_role_writable_history", self.output.getvalue())
        self.assertIn("acquisition=local_api_sequential_unattested", self.output.getvalue())
        saved = research.selected(self.ctx)
        self.assertEqual(saved["schema"], 1)
        self.assertNotIn("provenance", saved)  # Never accept a file's trust assertion.
        result = research.topology_map(self.ctx)
        self.assert_unverified(result["provenance"])
        self.assert_unverified(result["graph"]["provenance"])
        text = Path(result["dot_file"]).read_text()
        self.assertIn("UNVERIFIED role-writable history", text)
        self.assertIn("no authenticity/immutability guarantee", text)

    @logged
    def test_store_owner_mutation_remains_visible_as_unverified_in_report_and_diff(self):
        first = self.capture_at("2026-10-19T09:05:00+00:00")
        root = self.paths.state / "research"
        path = root / ("snapshot-" + first["snapshot_id"] + ".json")
        saved = json.loads(path.read_text())
        saved["observations"]["peers"] = [
            {"key": B, "up": True, "inbound": False, "port": 7, "latency_ms": 12}
        ]
        model.validate(saved)  # Valid structure is not a truthful-origin proof.
        path.write_text(json.dumps(saved))  # This test already owns the store.
        _, report = self.report_at_end()
        self.assertEqual(report["topology"]["latest_sources"]["peers"], "ok")
        self.assertIs(report["topology"]["latest_identity_stable"], True)
        self.assertEqual(report["topology"]["latest_observed_identities"], 2)
        self.assertIn(B, Path(report["dot_file"]).read_text())
        self.capture_at("2026-10-19T09:15:00+00:00")
        difference = research.compare(self.ctx)
        self.assert_unverified(difference["provenance"])
        self.assertEqual(difference["sources"]["peers"]["removed"], [B + ":7:False"])
        _, report = self.report_at_end()
        self.assertEqual(report["topology"]["latest_observed_identities"], 1)
        self.assert_unverified(report["topology"]["changes"][0]["provenance"])
        self.assertEqual(path.read_text(), json.dumps(saved))  # No silent reset/deletion.

    @logged
    def test_schema_cannot_supply_a_trust_assertion_or_hide_duplicate_tree_entries(self):
        self.capture_at("2026-10-19T09:05:00+00:00")
        good = research.selected(self.ctx)
        bad = copy.deepcopy(good)
        bad["provenance"] = {"authenticated": True, "immutable_since_capture": True}
        with self.assertRaisesRegex(Failure, "research_invalid_snapshot"):
            model.validate(bad)
        bad = copy.deepcopy(good)
        row = {"key": B, "parent": A, "sequence": 1}
        bad["observations"]["tree"] = [row, row]
        with self.assertRaisesRegex(Failure, "research_duplicate_entry"):
            model.validate(bad)
        # Generated contracts are independent objects, not mutable global acceptance.
        value = model.snapshot_provenance()
        value["authenticated"] = True
        self.assert_unverified(model.snapshot_provenance())

    @logged
    def test_allowed_api_data_is_not_independently_attested(self):
        self.responses["getPeers"]["peers"] = [
            {"key": B, "up": True, "inbound": False, "port": 7, "latency": 1e6}
        ]
        result = self.capture_at("2026-10-19T09:05:00+00:00")
        self.assert_unverified(result["provenance"])
        _, report = self.report_at_end()
        self.assertEqual(report["topology"]["latest_observed_identities"], 2)
        self.assertIs(report["topology"]["latest_identity_stable"], True)
        self.assertIn("API truth", report["provenance"]["warning"])

    @logged
    def test_unknown_snapshot_sources_and_metric_duplicate_gaps_remain_unknown(self):
        self.capture_at("2026-10-19T09:05:00+00:00")
        before = research.selected(self.ctx)
        after = copy.deepcopy(before)
        after.update(id="f" * 32, started=NOW, finished=NOW)
        after["sources"]["peers"], after["observations"]["peers"] = "unavailable", None
        result = model.difference(before, after)
        self.assert_unverified(result["provenance"])
        self.assertEqual(
            result["sources"]["peers"],
            {"known": False, "added": None, "removed": None, "changed": None},
        )
        record = {
            "ts": "2026-10-19T09:05:00+00:00",
            "schema": 2,
            "act": "active",
            "up": 1,
            "errors": [],
            "peers": [{"r": "tls://example.invalid:1", "up": True, "rtt": 12}],
        }
        history = metrics.summary([record, record, dict(record, ts=NOW)], 1, NOW)
        self.assertEqual(history["samples"], 2)
        self.assertEqual(history["duplicate_timestamps_skipped"], 1)
        self.assertEqual(history["unknown_records"], 1)
        self.assertEqual(history["minutes_without_records"], 58)
        self.assertEqual(history["peers"][0]["unknown_samples"], 1)
        self.assertEqual(history["peers"][0]["down_samples"], 0)

    @logged
    def test_empty_and_partial_capture_do_not_omit_the_trust_warning(self):
        _, report = self.report_at_end()
        self.assertEqual(report["topology"]["snapshots"], 0)
        self.responses["getPeers"] = {"peers": "malformed"}
        with self.assertRaisesRegex(Failure, "partial_snapshot_saved"):
            self.capture_at("2026-10-19T09:05:00+00:00")
        self.assertIn("provenance=unverified_role_writable_history", self.output.getvalue())
        _, report = self.report_at_end()
        self.assertEqual(report["topology"]["latest_sources"]["peers"], "invalid")
