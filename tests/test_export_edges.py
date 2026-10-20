"""Export guards and report consistency, with bounded synthetic serializer faults."""

import contextlib
import io
import json
from pathlib import Path
from unittest.mock import Mock, patch

from core import Failure, atomic, logged
import atlas
from atlas import analysis, acquisition
from atlas.store import Store
import research
from observed_fixture import ObservedFixture, B, NOW


class ExportEdges(ObservedFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_atlas_new_command_route(self):
        store = Mock()
        with (
            patch.object(atlas, "Store", return_value=contextlib.nullcontext(store)),
            patch.object(acquisition, "new_run", return_value="test-run") as new,
        ):
            self.assertEqual(
                atlas.command(self.ctx, ["new"]), {"run": "test-run", "world_coverage": None}
            )
            new.assert_called_once_with(self.ctx, store)

    @logged
    def test_atlas_export_unknown_run_and_directory_guards(self):
        with Store(self.ctx, True) as store:
            result = analysis.report(self.ctx, store)
            self.assertEqual(result["observed_identities"], 0)
            self.assertTrue(Path(result["json"]).is_file())
            original = set(store.root.iterdir())
            extra = store.root / "unrecognized"
            atomic(extra, "fixture")
            with self.assertRaisesRegex(Failure, "unsafe_export_entry"):
                analysis.report(self.ctx, store)
            extra.unlink()
            created = []
            for i in range(513):
                path = store.root / ("atlas-" + f"{i:032x}" + ".md")
                atomic(path, "fixture")
                created.append(path)
            with self.assertRaisesRegex(Failure, "export_directory_guard"):
                analysis.report(self.ctx, store)
            for path in created[253:]:
                path.unlink()
            with self.assertRaisesRegex(Failure, "export_retention_review_required"):
                analysis.report(self.ctx, store)
            for path in created[:253]:
                path.unlink()
            self.assertEqual(set(store.root.iterdir()), original)
            # Fault injection at the serializer boundary: never commit an oversized report.
            with (
                patch.object(analysis.json, "dumps", return_value="x" * (64 * 1024 * 1024 + 1)),
                self.assertRaisesRegex(Failure, "export_guard_report_not_saved"),
            ):
                analysis.report(self.ctx, store)
            self.assertEqual(set(store.root.iterdir()), original)

    @logged
    def test_research_invalid_store_and_corrupt_json(self):
        root = research.folder(self.ctx, True)
        extra = root / "unexpected"
        atomic(extra, "fixture")
        with self.assertRaisesRegex(Failure, "unrecognized_store_entry"):
            research.snapshot_files(self.ctx)
        extra.unlink()
        path = root / ("snapshot-" + "0" * 32 + ".json")
        atomic(path, "not json")
        with self.assertRaisesRegex(Failure, "invalid_snapshot_json"):
            research.load(path)

    @logged
    def test_research_report_changes_peer_history_and_size_guard(self):
        root = research.folder(self.ctx, True)
        with patch.object(
            acquisition,
            "timestamp",
            side_effect=[
                "2026-10-19T09:58:00+00:00",
                "2026-10-19T09:58:01+00:00",
                "2026-10-19T09:59:00+00:00",
                "2026-10-19T09:59:01+00:00",
            ],
        ):
            first = self.observation()
            second = self.observation()
        for value in (first, second):
            atomic(root / ("snapshot-" + value["id"] + ".json"), json.dumps(value))
        row = {
            "ts": NOW,
            "schema": 2,
            "act": "active",
            "up": 1,
            "errors": [],
            "peers": [{"r": "tls://example.invalid:443?key=" + B, "up": True, "rtt": 5}],
        }
        with (
            patch.object(research.telemetry, "rows", return_value=[row]),
            patch.object(research, "timestamp", return_value=NOW),
        ):
            result = research.report(self.ctx)
        payload = json.loads(Path(result["json_file"]).read_text())
        self.assertEqual(len(payload["topology"]["changes"]), 1)
        self.assertEqual(payload["history"]["samples"], 1)
        self.assertIn("100.0", Path(result["markdown_file"]).read_text())
        before = set(root.iterdir())
        with (
            patch.object(research.json, "dumps", return_value="x" * (16 * 1024 * 1024 + 1)),
            self.assertRaisesRegex(Failure, "research_report_size_limit"),
        ):
            research.report(self.ctx)
        self.assertEqual(set(root.iterdir()) - before, set())
