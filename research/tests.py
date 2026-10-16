"""Isolated research regressions; no live admin/network/key/config use."""
import argparse
import contextlib
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from core import Failure, atomic, logged, read_regular
from tests import ConsoleTests
from . import model, metrics, capture, report, topology_map, compare, snapshots, command, folder

A, B, C = "a"*64, "b"*64, "c"*64
NOW = "2026-10-13T20:00:00+00:00"


class ResearchTests(ConsoleTests):
    @logged
    def setUp(self):
        super().setUp()
        self.responses.update(getSelf={"key": A, "routing_entries": 12, "password": "SYNTHETIC_SECRET"},
                              getPeers={"peers": [{"key": B, "up": True, "inbound": False, "port": 1,
                                                   "latency": 12000000, "remote": "tls://user:SYNTHETIC_SECRET@example.test:443?password=SYNTHETIC_SECRET", "last_error": "SYNTHETIC_SECRET"}]},
                              getTree={"tree": [{"key": A, "parent": B, "sequence": 5}, {"key": B, "parent": B, "sequence": 1}]},
                              getPaths={"paths": [{"key": C, "path": [1, 2], "sequence": 4}]})

    @logged
    def saved(self):
        with contextlib.redirect_stdout(io.StringIO()): capture(self.ctx)
        return snapshots(self.ctx)[-1]

    @logged
    def records(self):
        uri = "tls://user:SYNTHETIC_SECRET@192.0.2.1:443?key="+B+"&password=SYNTHETIC_SECRET"
        base = {"schema": 2, "act": "active", "up": 1, "errors": [], "peers": [{"r": uri, "up": True, "rtt": 12}]}
        values = []
        for i in range(4):
            row = copy.deepcopy(base); row["ts"] = f"2026-10-13T19:0{i}:00+00:00"; values.append(row)
        values[1]["peers"][0]["up"] = False; values[1]["up"] = 0
        values[2]["errors"] = ["degraded"]; values[2]["peers"] = []
        values[3]["peers"] = []; values[3]["up"] = 0
        return values

    @logged
    def test_capture_projects_only_allowlisted_fields(self):
        saved = self.saved()
        self.assertTrue(saved["identity_stable"])
        self.assertEqual(set(saved["sources"].values()), {"ok"})
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(saved))
        self.assertNotIn("remote", json.dumps(saved))
        self.assertEqual(saved["observations"]["peers"][0]["latency_ms"], 12)
        self.assertEqual(sum(c[0] == self.paths.ctl for c in self.calls), 5)

    @logged
    def test_partial_api_failure_is_saved_nonzero_not_empty(self):
        self.failed_command = "getTree"
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(Failure, "partial_snapshot_saved"):
            capture(self.ctx)
        saved = snapshots(self.ctx)[0]
        self.assertEqual(saved["sources"]["tree"], "unavailable")
        self.assertIsNone(saved["observations"]["tree"])
        self.assertNotIn("SECRET", json.dumps(saved))

    @logged
    def test_bad_source_schema_is_unknown(self):
        self.responses["getPaths"] = {"paths": [{"key": C, "path": [True], "sequence": 1}]}
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(Failure): capture(self.ctx)
        self.assertEqual(snapshots(self.ctx)[0]["sources"]["paths"], "invalid")

    @logged
    def test_identity_rotation_during_capture_detected(self):
        old = self.ctx.runner; calls = 0
        @logged
        def runner(argv, **kw):
            nonlocal calls
            if argv[0] == self.paths.ctl and argv[3] == "getSelf":
                calls += 1
                self.responses["getSelf"]["key"] = A if calls == 1 else C
            return old(argv, **kw)
        self.ctx.runner = runner
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(Failure): capture(self.ctx)
        self.assertFalse(snapshots(self.ctx)[0]["identity_stable"])

    @logged
    def test_graph_reference_roles_edge_types_and_root_loop(self):
        saved = self.saved(); graph = model.graph(saved)
        self.assertEqual(len(graph["nodes"]), 3)
        self.assertEqual({e["kind"] for e in graph["edges"]}, {"direct_peer", "tree_parent"})
        self.assertEqual(len(graph["edges"]), 2)
        self.assertIn("path_entry", next(n for n in graph["nodes"] if n["key"] == C)["roles"])
        self.assertIn('style=dashed', model.dot(saved))
        self.assertNotIn("SYNTHETIC_SECRET", model.dot(saved))

    @logged
    def test_unknown_peer_key_is_not_invented_vertex(self):
        self.responses["getPeers"]["peers"][0]["key"] = ""
        saved = self.saved(); graph = model.graph(saved)
        self.assertEqual(graph["unknown_peer_keys"], 1)
        self.assertFalse(any(e["kind"] == "direct_peer" for e in graph["edges"]))

    @logged
    def test_duplicate_entries_and_bad_keys_fail_projection(self):
        for source, bad in (("tree", {"tree": [self.responses["getTree"]["tree"][0]]*2}),
                            ("self", {"key": "SYNTHETIC_SECRET", "routing_entries": 0}),
                            ("peers", {"peers": [{"key": B, "up": 1, "inbound": False, "port": 1}]})):
            with self.subTest(source=source), self.assertRaises(Failure): model.project(source, bad)

    @logged
    def test_numeric_latency_unknown_not_zero(self):
        for value in (None, 0, -1, True, float("nan"), float("inf"), 10**1000, "secret"):
            self.assertIsNone(model.latency(value))
        self.assertEqual(metrics.quantiles([])["n"], 0)
        self.assertEqual(metrics.quantiles([10, 20, 30])["p95"], 29)

    @logged
    def test_diff_parent_change_not_sequence_or_latency(self):
        a = self.saved(); b = copy.deepcopy(a); b["id"] = "1"*32
        b["started"] = "2099-01-01T00:00:00+00:00"; b["finished"] = b["started"]
        b["observations"]["tree"][0]["sequence"] += 100
        b["observations"]["peers"][0]["latency_ms"] = 18
        self.assertEqual(model.difference(a, b)["sources"]["tree"]["changed"], [])
        b["observations"]["tree"][0]["parent"] = C
        self.assertEqual(model.difference(a, b)["sources"]["tree"]["changed"], [A])

    @logged
    def test_partial_diff_skips_missing_source(self):
        a = self.saved(); b = copy.deepcopy(a); b["started"] = "2099-01-01T00:00:00+00:00"; b["finished"] = b["started"]
        b["sources"]["tree"] = "unavailable"; b["observations"]["tree"] = None
        d = model.difference(a, b)["sources"]["tree"]
        self.assertFalse(d["known"]); self.assertIsNone(d["removed"])

    @logged
    def test_diff_identity_and_time_boundaries(self):
        a = self.saved(); b = copy.deepcopy(a)
        with self.assertRaisesRegex(Failure, "not_sequential"): model.difference(a, b)
        b["started"] = "2099-01-01T00:00:00+00:00"; b["finished"] = b["started"]
        b["observations"]["self"]["key"] = C
        with self.assertRaisesRegex(Failure, "identity_change"): model.difference(a, b)
        b["identity_stable"] = None
        with self.assertRaisesRegex(Failure, "unstable_identity"): model.difference(a, b)

    @logged
    def test_persisted_schema_extra_fields_and_filename_rejected(self):
        a = self.saved(); name = self.paths.state/"research"/("snapshot-"+a["id"]+".json")
        for value in ([], dict(a, password="SYNTHETIC_SECRET"), dict(a, schema=True)):
            atomic(name, json.dumps(value))
            with self.assertRaises(Failure): snapshots(self.ctx)
        atomic(name, json.dumps(dict(a, id="2"*32)))
        with self.assertRaisesRegex(Failure, "filename_mismatch"): snapshots(self.ctx)

    @logged
    def test_store_symlink_and_permissions_rejected(self):
        root = self.paths.state/"research"; root.symlink_to(self.paths.etc)
        with self.assertRaises(Failure): folder(self.ctx, True)
        root.unlink(); root.mkdir(); root.chmod(0o755)
        with self.assertRaises(Failure): folder(self.ctx)

    @logged
    def test_arbitrary_id_and_no_snapshot_contract(self):
        for args in ([], ["map", "../../etc/passwd"], ["capture", "extra"], ["report", "0"], ["report", "73"], ["unknown"]):
            with self.assertRaises(Failure): command(self.ctx, args)
        with self.assertRaisesRegex(Failure, "capture_first"): topology_map(self.ctx)
        with self.assertRaisesRegex(Failure, "two_snapshots"): compare(self.ctx)

    @logged
    def test_capture_retention_limit_never_deletes(self):
        self.saved()
        from . import snapshot_files
        with patch("research.LIMIT", 1), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(Failure, "retention_review"): capture(self.ctx)
            self.assertEqual(len(snapshot_files(self.ctx)), 1)

    @logged
    def test_parallel_captures_unique_private_files(self):
        results, errors = [], []
        @logged
        def work():
            try: results.append(capture(self.ctx))
            except BaseException as exc: errors.append(type(exc).__name__)
        threads = [threading.Thread(target=work) for _ in range(3)]
        with contextlib.redirect_stdout(io.StringIO()):
            for t in threads: t.start()
            for t in threads: t.join(10)
        self.assertFalse(errors); self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(len({r["snapshot_id"] for r in results}), 3)
        for path in (self.paths.state/"research").iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    @logged
    def test_metric_unknown_absent_down_and_full_window_gaps(self):
        s = metrics.summary(self.records(), 1, NOW)
        p = s["peers"][0]
        self.assertEqual((p["up_samples"], p["down_samples"], p["unknown_samples"], p["absent_samples"]), (1, 1, 1, 1))
        self.assertEqual(p["availability_among_known_present_pct"], 50)
        self.assertEqual(s["minutes_without_records"], 56)
        self.assertEqual(p["pinned_public_key"], B)
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(s))

    @logged
    def test_metric_duplicates_degraded_and_bad_times(self):
        rows = self.records(); rows += [copy.deepcopy(rows[0]), {"ts": "bad"}, {"ts": "2026-10-13T19:00:00"}, []]
        s = metrics.summary(rows, 1, NOW)
        self.assertEqual(s["samples"], 4)
        self.assertEqual(s["unknown_records"], 2)
        self.assertEqual(s["invalid_records"], 3)
        self.assertEqual(s["duplicate_timestamps_skipped"], 1)

    @logged
    def test_bad_metric_rows_zero_latency_and_duplicate_peer(self):
        rows = self.records()[:1]
        rows[0]["peers"][0]["rtt"] = 0
        s = metrics.summary(rows, 1, NOW)
        self.assertIsNone(s["peers"][0]["latency_ms"]["p50"])
        self.assertEqual(s["peers"][0]["missing_or_invalid_latency_on_up"], 1)
        rows[0]["peers"].append(copy.deepcopy(rows[0]["peers"][0]))
        s = metrics.summary(rows, 1, NOW)
        self.assertEqual(s["peers"][0]["unknown_samples"], 1)

    @logged
    def test_unidentified_metric_peer_does_not_fabricate_absence(self):
        rows = self.records()[:2]
        rows[1]["peers"] = [{"up": True, "rtt": 10}]
        s = metrics.summary(rows, 1, NOW)
        self.assertEqual(s["unknown_records"], 1)
        p = s["peers"][0]
        self.assertEqual((p["up_samples"], p["down_samples"], p["unknown_samples"], p["absent_samples"]), (1, 0, 1, 0))

    @logged
    def test_empty_and_outside_window_not_zero_availability(self):
        s = metrics.summary([], 1, NOW)
        self.assertEqual(s["samples"], 0); self.assertEqual(s["minutes_without_records"], 60)
        self.assertEqual(s["peers"], []); self.assertIsNone(s["pooled_peer_sample_latency_ms"]["p50"])
        rows = self.records(); rows[0]["ts"] = "2099-01-01T00:00:00+00:00"
        self.assertEqual(metrics.summary(rows, 1, NOW)["outside_window_records"], 1)

    @logged
    def test_report_map_diff_and_cli_dispatch(self):
        from main import dispatch
        with contextlib.redirect_stdout(io.StringIO()):
            for args in (["capture"], ["capture"], ["map"], ["diff"], ["report", "1"]):
                dispatch(self.ctx, argparse.Namespace(command="research", args=args, apply=False, force=False, full=False, recipient=None))
        root = self.paths.state/"research"
        self.assertEqual(len(list(root.glob("snapshot-*.json"))), 2)
        files = list(root.glob("report-*.json")); self.assertEqual(len(files), 1)
        payload = json.loads(read_regular(files[0]))
        self.assertIsNone(payload["world_nodes"]); self.assertIsNone(payload["throughput_bps"])
        self.assertEqual(payload["history"]["samples"], 0)
        self.assertNotIn("SYNTHETIC_SECRET", read_regular(files[0]).decode())
        self.assertIn("UNKNOWN", read_regular(files[0].with_suffix(".md")).decode())

    @logged
    def test_corrupt_metric_stream_and_missing_topology_report(self):
        atomic(self.paths.state/"metrics.jsonl", "invalid\n")
        with contextlib.redirect_stdout(io.StringIO()): result = report(self.ctx, 1)
        self.assertTrue(result["unknown_history"])
        payload = json.loads(read_regular(Path(result["json_file"])))
        self.assertIsNone(payload["topology"]["latest_observed_identities"])
        self.assertIsNone(payload["history"])


@logged
def run_suite():
    # Explicit module-only cases; ConsoleTests fixtures reused, inherited
    # base42 are executed separately, not inflated into a second unique count.
    names = sorted(n for n in ResearchTests.__dict__ if n.startswith("test_"))
    suite = unittest.TestSuite(ResearchTests(n) for n in names)
    start = time.monotonic()
    print(f"[1/1] research regressions processed=0/{len(names)} remaining={len(names)}", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"processed={result.testsRun}/{len(names)} remaining=0 errors={len(result.errors)+len(result.failures)} elapsed={time.monotonic()-start:.2f}s")
    if not result.wasSuccessful(): raise Failure("research_offline_regressions_failed")


if __name__ == "__main__": run_suite()
