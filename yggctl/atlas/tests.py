"""Isolated atlas tests; no production data or external request."""

import argparse
import contextlib
import io
import json
import os

# Security review: synthetic CompletedProcess values only; no subprocess execution
import subprocess  # nosec B404
import time
import unittest
from unittest.mock import patch
import zipfile
from core import Failure, logged, read_regular
from test_support import ConsoleFixture
from .store import Store
from . import catalogue, protocol, acquisition, analysis, command
from .viewer import html

A, B, C, D = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
SHA = "1" * 40


class AtlasTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.responses.update(
            getSelf={"key": A, "routing_entries": 12},
            getPeers={
                "peers": [{"key": B, "up": True, "inbound": False, "port": 1, "latency": 12000000}]
            },
            getTree={
                "tree": [
                    {"key": A, "parent": B, "sequence": 1},
                    {"key": B, "parent": B, "sequence": 1},
                ]
            },
            getPaths={"paths": []},
        )
        self.remote = {
            B: {
                "self": {"key": B, "routing_entries": "3"},
                "peers": {"keys": [C, C, A]},
                "tree": {"keys": [D]},
            },
            C: {"self": {"key": C, "routing_entries": "2"}, "peers": {"keys": [B]}, "tree": {}},
        }
        self.uri = (
            "tls://user:SYNTHETIC_SECRET@192.0.2.1:443?key=" + B + "&password=SYNTHETIC_SECRET"
        )

    @logged
    def runner(self, argv, **kw):
        if argv[0] == self.paths.ctl and argv[3] in protocol.METHODS.values():
            self.calls.append(argv)
            method = next(m for m, v in protocol.METHODS.items() if v == argv[3])
            key = argv[-1].split("=", 1)[1]
            if key not in self.remote:
                return subprocess.CompletedProcess(argv, 1, b"", b"SYNTHETIC_SECRET")
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({protocol.address(key): self.remote[key][method]}).encode(), b""
            )
        if argv[0] == "/usr/bin/curl":
            self.calls.append(argv)
            if argv[-1] == catalogue.API:
                value = json.dumps({"object": {"sha": SHA}}).encode()
            elif argv[-1] == catalogue.MONITOR:
                value = (
                    "<strong>13 Oct 26 21:02 UTC</strong><table><tr><th id='country'>germany</th></tr><tr><td id='address'>"
                    + self.uri.replace("&", "&amp;")
                    + "</td><td id='status'>online 1 week+</td><td id='reliability'>98%</td></tr></table>"
                ).encode()
            else:
                value = self.archive()
            return subprocess.CompletedProcess(argv, 0, value, b"")
        return super().runner(argv, **kw)

    @logged
    def archive(self, filename=None, body=None):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(
                filename or "public-peers-" + SHA + "/europe/germany.md",
                body
                or ("`" + self.uri + "`\n`tcp://example.test:65536`\n`quic://example.test:443`"),
            )
        return output.getvalue()

    @logged
    def prepared(self, store):
        with contextlib.redirect_stdout(io.StringIO()):
            catalogue.acquire(self.ctx, store)
        return acquisition.new_run(self.ctx, store)

    @logged
    def crawled(self, store):
        run = self.prepared(store)
        with contextlib.redirect_stdout(io.StringIO()):
            acquisition.crawl(self.ctx, store, 1)
        return run

    @logged
    def test_catalogue_whole_fixed_sources_no_secrets(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            records = [json.loads(r[0]) for r in s.sql("SELECT payload FROM catalogue")]
            self.assertEqual(len(records), 2)
            self.assertEqual(s.meta("catalogue")["invalid_entries"], 1)
            self.assertNotIn("SYNTHETIC_SECRET", json.dumps(records))
            self.assertTrue(any(r["registry_online"] is True for r in records))
            self.assertEqual(s.meta("catalogue")["monitor_updated_claim"], "13 Oct 26 21:02 UTC")
            self.assertEqual(sum(c[0] == "/usr/bin/curl" for c in self.calls), 3)

    @logged
    def test_endpoint_allowlist_omits_auth_path_queries(self):
        r = catalogue.endpoint(self.uri.replace(":443?", ":443/SYNTHETIC_SECRET?"))
        self.assertEqual(r["endpoint"], "tls://192.0.2.1:443")
        self.assertEqual(r["pins"], [B])
        self.assertTrue(r["authentication_omitted"])
        self.assertTrue(r["path_omitted"])
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(r))

    @logged
    def test_bad_endpoints_country_and_fixed_urls(self):
        for v in (
            None,
            "tcp://host:0",
            "tcp://host:65536",
            "file:///etc/passwd",
            "tcp://host:1\n",
            self.uri + "&key=bad",
        ):
            with self.assertRaises(Failure):
                catalogue.endpoint(v)
        with self.assertRaises(Failure):
            catalogue.country("<script>")
        with self.assertRaises(Failure):
            catalogue.fetch(self.ctx, "http://127.0.0.1:8332")
        self.assertEqual(self.calls, [])

    @logged
    def test_zip_paths_no_extract_and_size_limits(self):
        for v in (
            b"not zip",
            self.archive("../../unsafe"),
            self.archive(body="X" * (1024 * 1024 + 1)),
        ):
            with self.assertRaises(Failure):
                catalogue.repository_rows(v, SHA)
        self.assertFalse((self.paths.state / "unsafe").exists())

    @logged
    def test_monitor_missing_country_is_invalid(self):
        p = catalogue.MonitorParser()
        p.feed('<tr><td id="address">tls://host.test:443</td></tr>')
        self.assertEqual(p.rows, [])
        self.assertEqual(p.invalid, 1)

    @logged
    def test_address_matches_upstream_go_example(self):
        self.assertEqual(
            protocol.address("000000002643ae27bad63e2a81f1d30554ce9ea634f5990062a9e079e23593cd"),
            "222:cde2:8ec2:294e:eab:f071:67d5:598b",
        )

    @logged
    def test_remote_self_decimal_identity_types(self):
        p = protocol.projection(
            B, "self", {protocol.address(B): {"key": B, "routing_entries": "293"}}
        )
        self.assertEqual(p["routing_entries"], 293)
        for n in (True, "-1", "1.5", "9" * 21, None):
            with self.assertRaises(Failure):
                protocol.projection(
                    B, "self", {protocol.address(B): {"key": B, "routing_entries": n}}
                )
        with self.assertRaises(Failure):
            protocol.projection(
                B, "self", {protocol.address(B): {"key": C, "routing_entries": "1"}}
            )

    @logged
    def test_remote_lists_dedup_empty_not_parent_up_latency(self):
        p = protocol.projection(B, "peers", {protocol.address(B): {"keys": [C, C]}})
        self.assertEqual(p["duplicate_rows"], 1)
        self.assertIsNone(p["complete"])
        self.assertNotIn("up", p)
        self.assertNotIn("latency", p)
        p = protocol.projection(B, "tree", {protocol.address(B): {}})
        self.assertEqual(p["keys"], [])
        self.assertIn("NO_parent", p["semantics"])

    @logged
    def test_wrong_envelopes_keylists_rejected(self):
        r: object
        for r in (
            {},
            {protocol.address(C): {"keys": []}},
            {protocol.address(B): {"keys": [None]}},
            {protocol.address(B): {"keys": "bad"}},
            {protocol.address(B): {"unexpected": "not an empty response"}},
        ):
            with self.assertRaises(Failure):
                protocol.projection(B, "peers", r)

    @logged
    def test_full_cyclic_frontier_dedup_unknown_not_outage(self):
        with Store(self.ctx, True) as s:
            run = self.crawled(s)
            r = acquisition.status(s)
            self.assertEqual(
                (r["discovered_remote_keys"], r["processed_keys"], r["remaining_keys"]), (3, 3, 0)
            )
            self.assertEqual(r["state"], "frontier_exhausted")
            self.assertIsNone(r["world_coverage"])
            self.assertEqual(r["methods"], {"ok": 6, "unknown": 3})
            calls = [
                c
                for c in self.calls
                if c[0] == self.paths.ctl and c[3] in protocol.METHODS.values()
            ]
            self.assertEqual(len(calls), 9)
            self.assertFalse(any(c[-1] == "key=" + A for c in calls))
            with contextlib.redirect_stdout(io.StringIO()):
                acquisition.crawl(self.ctx, s, 1)
            self.assertEqual(acquisition.status(s)["run"], run)
            self.assertEqual(
                len(
                    [
                        c
                        for c in self.calls
                        if c[0] == self.paths.ctl and c[3] in protocol.METHODS.values()
                    ]
                ),
                9,
            )

    @logged
    def test_more_than_32_keys_are_all_processed(self):
        keys = [format(i, "064x") for i in range(1, 66)]
        self.remote[B]["peers"] = {"keys": keys}
        with Store(self.ctx, True) as s:
            self.crawled(s)
            r = acquisition.status(s)
            self.assertEqual(r["processed_keys"], 67)
            self.assertEqual(r["remaining_keys"], 0)
            self.assertEqual(sum(r["methods"].values()), 201)

    @logged
    def test_default_full_sweep_continues_checkpoint_slices(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            responses = [
                {"state": "checkpoint", "remaining_keys": 65},
                {"state": "frontier_exhausted", "remaining_keys": 0},
            ]
            with patch("atlas.acquisition.crawl", side_effect=responses) as bounded:
                self.assertEqual(acquisition.sweep(self.ctx, s)["remaining_keys"], 0)
                self.assertEqual(bounded.call_count, 2)
                bounded.assert_called_with(self.ctx, s, 120)
        with patch(
            "atlas.acquisition.sweep", return_value={"state": "frontier_exhausted"}
        ) as sweep:
            self.assertEqual(command(self.ctx, ["crawl"])["state"], "frontier_exhausted")
            sweep.assert_called_once()

    @logged
    def test_replay_committed_response_reseeds_after_crash(self):
        with Store(self.ctx, True) as s:
            run = self.prepared(s)
            s.response(
                run,
                B,
                "peers",
                "ok",
                1,
                protocol.projection(B, "peers", {protocol.address(B): {"keys": [C]}}),
            )
            with contextlib.redirect_stdout(io.StringIO()):
                acquisition.crawl(self.ctx, s, 1)
            self.assertEqual(acquisition.status(s)["processed_keys"], 3)
            self.assertFalse(
                any(
                    c[0] == self.paths.ctl
                    and c[3] == "debug_remotegetpeers"
                    and c[-1] == "key=" + B
                    for c in self.calls
                )
            )

    @logged
    def test_catalogue_and_provenance_rollback_together(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            before = s.sql("SELECT * FROM catalogue")
            meta = s.meta("catalogue")
            old = s.sql

            @logged
            def fail_meta(query, args=()):
                if query.startswith("INSERT OR REPLACE INTO meta"):
                    raise Failure("synthetic_checkpoint_failure")
                return old(query, args)

            with (
                patch.object(s, "sql", side_effect=fail_meta),
                self.assertRaises(Failure),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                catalogue.acquire(self.ctx, s)
            self.assertEqual(s.sql("SELECT * FROM catalogue"), before)
            self.assertEqual(s.meta("catalogue"), meta)

    @logged
    def test_new_run_pointer_and_seeds_rollback_together(self):
        with Store(self.ctx, True) as s:
            first = self.prepared(s)
            old = s.sql

            @logged
            def fail_seed(query, args=()):
                if query.startswith("INSERT INTO targets"):
                    raise Failure("synthetic_seed_failure")
                return old(query, args)

            with patch.object(s, "sql", side_effect=fail_seed), self.assertRaises(Failure):
                acquisition.new_run(self.ctx, s)
            self.assertEqual(s.meta("current"), first)
            self.assertEqual(s.sql("SELECT COUNT(*) FROM runs")[0][0], 1)

    @logged
    def test_corrupt_database_error_is_fixed_label(self):
        root = self.paths.state / "atlas"
        root.mkdir(mode=0o700)
        p = root / "atlas.sqlite"
        p.write_bytes(b"SYNTHETIC_SECRET")
        p.chmod(0o600)
        with self.assertRaisesRegex(Failure, "^atlas_database_open_failed$"):
            Store(self.ctx, True).__enter__()

    @logged
    def test_time_slice_resumes_without_repeating_committed_method(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            clock = [0.0]
            old = protocol.query

            @logged
            def slow(ctx, key, method):
                r = old(ctx, key, method)
                clock[0] = 61.0
                return r

            with (
                patch("atlas.acquisition.time.monotonic", side_effect=lambda: clock[0]),
                patch("atlas.protocol.query", side_effect=slow),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                r = acquisition.crawl(self.ctx, s, 1)
            self.assertEqual(r["state"], "checkpoint")
            self.assertEqual(r["processed_keys"], 0)
            with contextlib.redirect_stdout(io.StringIO()):
                acquisition.crawl(self.ctx, s, 1)
            self.assertEqual(
                len(
                    [
                        c
                        for c in self.calls
                        if c[0] == self.paths.ctl
                        and c[3] == "debug_remotegetself"
                        and c[-1] == "key=" + B
                    ]
                ),
                1,
            )

    @logged
    def test_interrupted_inflight_is_unknown_no_hidden_retry(self):
        with Store(self.ctx, True) as s:
            run = self.prepared(s)
            s.response(run, B, "self", "inflight")
            with contextlib.redirect_stdout(io.StringIO()):
                acquisition.crawl(self.ctx, s, 1)
            self.assertEqual(acquisition.status(s)["methods"].get("interrupted_unknown"), 1)

    @logged
    def test_identity_change_stops_before_requests(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            self.responses["getSelf"]["key"] = C
            with (
                self.assertRaisesRegex(Failure, "identity_changed"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                acquisition.crawl(self.ctx, s, 1)
            self.assertEqual(acquisition.status(s)["state"], "checkpoint")

    @logged
    def test_independent_writer_lock_readers_release(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            with self.assertRaisesRegex(Failure, "writer_already"):
                Store(self.ctx, True).__enter__()
            with Store(self.ctx) as r:
                self.assertEqual(acquisition.status(r)["processed_keys"], 0)
        with Store(self.ctx, True):
            pass

    @logged
    def test_symlink_mode_database_fifo_rejected(self):
        root = self.paths.state / "atlas"
        root.symlink_to(self.paths.etc, target_is_directory=True)
        with self.assertRaises(Failure):
            Store(self.ctx, True).__enter__()
        root.unlink()
        root.mkdir()
        root.chmod(0o755)
        with self.assertRaises(Failure):
            Store(self.ctx, True).__enter__()
        root.chmod(0o700)
        os.mkfifo(root / "atlas.sqlite", 0o600)
        with self.assertRaises(Failure):
            Store(self.ctx, True).__enter__()

    @logged
    def test_frontier_storage_guard_no_partial_seed_or_deletion(self):
        with Store(self.ctx, True) as s:
            run = self.prepared(s)
            with (
                patch("atlas.store.MAX_NODES", 2),
                self.assertRaisesRegex(Failure, "storage_frontier_guard"),
            ):
                s.seed(run, [C, D], "test")
            self.assertEqual(acquisition.status(s)["discovered_remote_keys"], 1)

    @logged
    def test_graph_remote_tree_references_not_edges(self):
        with Store(self.ctx, True) as s:
            self.crawled(s)
            d = analysis.build(s)
            self.assertEqual(len(d["nodes"]), 4)
            self.assertEqual(d["respondent_keys"], 2)
            es = [e for e in d["edges"] if e["kind"] == "reported_peer"]
            self.assertEqual(len(es), 2)
            e = next(e for e in es if {e["source"], e["target"]} == {B, C})
            self.assertEqual(set(e["reporters"]), {B, C})
            self.assertFalse(any(e["source"] == D or e["target"] == D for e in d["edges"]))
            self.assertEqual(d["observed_peer_component_sizes"], [3, 1])
            self.assertIsNone(d["world_nodes"])
            self.assertIsNone(d["throughput_bps"])

    @logged
    def test_timing_denominators_geo_claims_asn_unknown(self):
        with Store(self.ctx, True) as s:
            self.crawled(s)
            d = analysis.build(s)
            r = d["timing"]["self"]
            self.assertEqual((r["valid_payloads"], r["unknown_or_interrupted"]), (2, 1))
            self.assertAlmostEqual(r["query_success_fraction"], 2 / 3)
            self.assertEqual(d["endpoints_without_public_pin"], 1)
            self.assertEqual(
                next(n for n in d["nodes"] if n["key"] == B)["country_claims"], ["germany"]
            )
            self.assertTrue(all(n["asn"] is None for n in d["nodes"]))

    @logged
    def test_saved_schema_and_elapsed_bounds(self):
        with self.assertRaises(Failure):
            acquisition.payload('{"keys":[]}', B, "peers")
        with Store(self.ctx, True) as s:
            run = self.crawled(s)
            s.response(run, B, "self", "ok", float("inf"), {"key": B, "routing_entries": 1})
            with self.assertRaisesRegex(Failure, "invalid_response_elapsed"):
                analysis.build(s)

    @logged
    def test_new_run_retains_history_unknown_pairs_identity(self):
        with Store(self.ctx, True) as s:
            first = self.crawled(s)
            second = acquisition.new_run(self.ctx, s)
            self.assertNotEqual(first, second)
            self.assertEqual(s.sql("SELECT COUNT(*) FROM runs")[0][0], 2)
            d = analysis.changes(s, second)
            self.assertTrue(d["comparable"])
            self.assertGreater(d["unknown_or_unpaired_reporter_methods"], 0)
            self.responses["getSelf"]["key"] = C
            third = acquisition.new_run(self.ctx, s)
            self.assertEqual(analysis.changes(s, third)["reason"], "local_identity_changed")

    @logged
    def test_changes_paired_ok_reference_semantics(self):
        with Store(self.ctx, True) as s:
            self.crawled(s)
            run = acquisition.new_run(self.ctx, s)
            p = protocol.projection(B, "peers", {protocol.address(B): {"keys": [D]}})
            s.response(run, B, "peers", "ok", 1, p)
            d = analysis.changes(s, run)
            self.assertEqual(d["comparable_reporter_methods"], 1)
            self.assertEqual(d["changes"][0]["added"], [D])
            self.assertIn("NOT confirmed outages", d["limits"])

    @logged
    def test_cli_dispatch_artifacts_private_offline_viewer(self):
        import main

        with contextlib.redirect_stdout(io.StringIO()):
            for args in (["catalogue"], ["crawl", "1"], ["status"], ["report"]):
                main.dispatch(
                    self.ctx,
                    argparse.Namespace(
                        command="atlas",
                        args=args,
                        apply=False,
                        force=False,
                        full=False,
                        recipient=None,
                    ),
                )
        root = self.paths.state / "atlas"
        fs = list(root.glob("atlas-*"))
        self.assertEqual(len(fs), 4)
        for p in fs:
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("SYNTHETIC_SECRET", read_regular(p).decode())
        page = read_regular(next(root.glob("*.html"))).decode()
        self.assertIn("connect-src 'none'", page)
        self.assertIn('id="search"', page)
        self.assertIn('id="reset"', page)
        self.assertNotIn("<script src=", page)

    @logged
    def test_empty_catalogue_arguments_root_gate(self):
        with Store(self.ctx, True) as s:
            with self.assertRaisesRegex(Failure, "catalogue_first"):
                acquisition.new_run(self.ctx, s)
        for args in (
            [],
            ["crawl", "0"],
            ["crawl", "121"],
            ["status", "extra"],
            ["new", "extra"],
            ["unknown"],
            ["report", "../../etc/passwd"],
        ):
            with self.assertRaises(Failure):
                command(self.ctx, args)
        with patch("core.os.geteuid", return_value=1000):
            from core import Context

            with self.assertRaisesRegex(Failure, "root_required"):
                command(Context(), ["catalogue"])

    @logged
    def test_partial_bundle_does_not_bypass_retention_guard(self):
        with Store(self.ctx, True) as s:
            self.prepared(s)
            for i in range(253):
                p = s.root / ("atlas-" + format(i, "032x") + ".json")
                p.write_text("{}")
                p.chmod(0o600)
            with self.assertRaisesRegex(Failure, "retention_review"):
                analysis.report(self.ctx, s)
            self.assertEqual(len(list(s.root.glob("atlas-*"))), 253)

    @logged
    def test_html_escapes_text_and_unknown_centres_preserved(self):
        with Store(self.ctx, True) as s:
            self.crawled(s)
            d = analysis.build(s)
            d["limits"].append("<img src=x onerror=alert(1)>")
            d["countries"]["unknown-country"] = {
                "endpoints": 1,
                "pin_keys": 0,
                "registry_online": 0,
                "registry_offline": 0,
                "registry_unknown": 1,
            }
            page = html(d)
            self.assertNotIn("<img src=x", page)
            self.assertIn("&lt;img", page)
            self.assertIn("unknown-country", page)

    @logged
    def test_dns_label_edges_and_idna_without_network(self):
        for host in ("bad-.test", "-bad.test", "bad..test", "a" * 64 + ".test", "bad_.test"):
            with self.assertRaisesRegex(Failure, "atlas_invalid_catalogue_endpoint"):
                catalogue.endpoint("tls://" + host + ":443")
        for host in ("a.test", "good-label.test", "a" * 63 + ".test", "example.test.", "пример.рф"):
            self.assertTrue(catalogue.endpoint("tls://" + host + ":443")["endpoint"])
        self.assertEqual(self.calls, [])

    @logged
    def test_components_adverse_chain_final_pass_compressed(self):
        # Reversed unions leave a chain in insertion order; final counting used to be O(n²).
        keys = list(range(20000))
        edges = [
            {"kind": "reported_peer", "source": i + 1, "target": i} for i in range(len(keys) - 1)
        ]
        start = time.monotonic()
        self.assertEqual(analysis.components(keys, edges), [len(keys)])
        self.assertLess(time.monotonic() - start, 2.0, "adverse chain must not take quadratic time")
        self.assertEqual(
            analysis.components(
                [1, 2, 3], [{"kind": "local_tree_parent", "source": 1, "target": 2}]
            ),
            [1, 1, 1],
        )


@logged
def run_suite():
    names = sorted(n for n in AtlasTests.__dict__ if n.startswith("test_"))
    start = time.monotonic()
    print(f"[1/1] atlas regressions processed=0/{len(names)} remaining={len(names)}", flush=True)
    r = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(AtlasTests(n) for n in names))
    print(
        f"processed={r.testsRun}/{len(names)} remaining=0 errors={len(r.errors) + len(r.failures)} elapsed={time.monotonic() - start:.2f}s"
    )
    if not r.wasSuccessful():
        raise Failure("atlas_offline_regressions_failed")
