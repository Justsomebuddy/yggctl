"""Raw identity is separate from transport state and persisted projected booleans."""

import ast
import contextlib
from collections import Counter
import inspect
import io
import os
from pathlib import Path
from unittest.mock import patch

import checks
import main
import management
import telemetry
from core import Failure, atomic, bounded_number, logged
from test_support import ConsoleFixture


class IdentityFreshnessContract(ConsoleFixture):
    @logged
    def test_raw_identity_rejects_transport_only_and_malformed_keys(self):
        value: object
        for value in (None, "", "x" * 64, "a" * 63, 42, [], {}):
            with self.subTest(key=value):
                self.assertFalse(checks.identified({"up": True, "key": value}))
        self.assertFalse(checks.identified({"up": False, "key": "a" * 64}))
        self.assertFalse(checks.identified({"up": 1, "key": "a" * 64}))
        self.assertTrue(checks.identified({"up": True, "key": "a" * 64}))

    @logged
    def test_raw_consumer_guard_is_not_a_blanket_ban_on_projected_up(self):
        # Only raw API consumer entrypoints need this predicate. Persisted metric
        # rows intentionally contain projected up booleans and do not store keys.
        for fn in (
            checks.peer_gate,
            management.wait_peers,
            management.service,
            telemetry.collect,
            telemetry.watch,
            main.do_peers_score,
        ):
            with self.subTest(consumer=fn.__name__):
                tree = ast.parse(inspect.getsource(inspect.unwrap(fn)))
                callees = [
                    node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, (ast.Name, ast.Attribute))
                ]
                self.assertIn("identified", callees)

    @logged
    def test_score_displays_identity_separately_and_ranks_it_before_transport(self):
        rows = [
            {"remote": "tls://192.0.2.1:443", "up": True, "key": "", "latency": 0},
            {"remote": "tls://192.0.2.2:443", "up": True, "key": "a" * 64, "latency": 4},
        ]
        with (
            patch("main.checks.peers", return_value=rows),
            patch("main.output") as emit,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            main.do_peers_score(self.ctx, None, [])
        result = emit.call_args.args[0]
        self.assertEqual([row["identified"] for row in result], [True, False])
        self.assertTrue(result[1]["up"])
        self.assertNotIn("identified", rows[0])
        self.assertIn("raw up is transport state", out.getvalue())

    @logged
    def test_freshness_exact_boundaries_and_near_future(self):
        path = self.paths.state / "metrics.jsonl"
        now = 2_000_000_000.0
        atomic(path, b'{"schema":2}\n')
        age: float
        for age in (0, checks.COLLECTOR_MAX_AGE_MINUTES * 60):
            os.utime(path, (now - age, now - age))
            with patch("checks.time.time", return_value=now):
                self.assertIsNone(checks.collector_freshness(self.ctx))
        for age, label in (
            (-0.5, "collector_data_future_timestamp"),
            (-60, "collector_data_future_timestamp"),
            (checks.COLLECTOR_MAX_AGE_MINUTES * 60 + 0.5, "collector_data_stale"),
        ):
            os.utime(path, (now - age, now - age))
            with (
                patch("checks.time.time", return_value=now),
                self.assertRaisesRegex(Failure, label),
            ):
                checks.collector_freshness(self.ctx)

    @logged
    def test_numeric_conversion_is_a_controlled_cli_failure(self):
        for value in ("²", "1" * 10_000):
            with self.assertRaisesRegex(Failure, "numeric_argument_out_of_range"):
                bounded_number(value, 1, 100)
        self.assertEqual(bounded_number("12", 1, 100), 12)

    @logged
    def test_unrepresentable_counter_is_controlled_and_collection_continues(self):
        atomic(self.paths.state / "notify.state", "on\n")
        base = dict(self.ps[0])
        for field in ("latency", "bytes_recvd", "bytes_sent"):
            self.ps[:] = [dict(base, **{field: 10**400})]
            with self.subTest(field=field):
                with self.assertRaisesRegex(Failure, "invalid_peer_counter"):
                    checks.peers(self.ctx)
                with self.assertRaisesRegex(
                    Failure, "sample_recorded_with_unknown_or_degraded_health"
                ):
                    telemetry.collect(self.ctx)
                sample = telemetry.rows(self.ctx)[-1]
                self.assertIn("invalid_peer_counter", sample["errors"])
                self.assertFalse(sample["peers_observed"])
                self.assertIsNone(sample["up"])
                self.assertIn(
                    "ygg-health",
                    [row["kind"] for row in telemetry.rows(self.ctx, "alerts.jsonl")],
                )

    @logged
    def test_new_direct_up_read_requires_explicit_semantic_review(self):
        # Deliberately not a taint-analysis claim: this catches direct literal
        # accesses in maintained runtime functions, including newly added ones.
        # Existing projected metrics and schema/transport projection stay valid.
        expected = {
            "checks.py:peers": 1,  # Raw schema validation, not availability.
            "checks.py:identified": 1,  # The sole raw availability predicate.
            "telemetry.py:stage_peer_alerts": 2,  # Projected schema-2 sample.
            "telemetry.py:collect": 2,  # Its own projected sample, not raw rows.
            "telemetry.py:reconnects": 1,  # Persisted projected observations.
            "telemetry.py:stats": 4,  # Persisted projected observations.
            "research/metrics.py:summary": 6,  # Persisted projected observations.
            "research/model.py:project": 2,  # Typed transport projection.
            "research/model.py:graph": 1,  # Keyless rows excluded separately.
            "research/model.py:peer_link_groups": 1,  # Keyless rows excluded.
            # `trend` reports a historical median of the projected `up` field; it makes no
            # liveness claim and does not feed a gate. Strict projected bool checks
            # are not raw availability/key identity claims. The aggregation was split
            # into named helpers, so the same three accesses are counted where they now
            # live: the per-sample read and the two per-label folds.
            "telemetry.py:trend_sample_series": 1,
            "telemetry.py:trend_accumulate": 4,
            "telemetry.py:trend_peer_details": 1,
            "telemetry.py:trend_peer": 2,
        }
        root = Path(checks.__file__).parent
        found: Counter[str] = Counter()
        for path in root.rglob("*.py"):
            if path.name in ("tests.py", "test_support.py", "alert_tests.py"):
                continue
            tree = ast.parse(path.read_text())
            parents = {
                child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                direct = (
                    isinstance(node, ast.Subscript)
                    and isinstance(node.slice, ast.Constant)
                    and node.slice.value == "up"
                )
                getter = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "up"
                )
                if not (direct or getter):
                    continue
                owner = node
                while owner in parents and not isinstance(
                    owner, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    owner = parents[owner]
                name = getattr(owner, "name", "module")
                found[f"{path.relative_to(root).as_posix()}:{name}"] += 1
        self.assertEqual(dict(found), expected)
