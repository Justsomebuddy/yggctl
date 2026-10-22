"""Degradation trend: robust drift on stored history, explicit insufficiencies."""

import argparse
import contextlib
import datetime as dt
import io
import json

from unittest.mock import patch

from core import Failure, atomic, logged
import main
import telemetry as tm
from test_support import ConsoleFixture

PEER = "tls://192.0.2.1:443"
OTHER = "tcp://192.0.2.9:1701"


class TrendReport(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.stdout = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.stdout))

    @logged
    def args(self, *values):
        return argparse.Namespace(
            command="trend",
            args=list(values),
            apply=False,
            force=False,
            full=False,
            recipient=None,
        )

    @logged
    def sample(self, minutes_ago, peers=None, up=1, observed=True, errors=None):
        at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
        return {
            "schema": 2,
            "ts": at.isoformat(),
            "mode": "direct",
            "act": "active",
            "up": up,
            "peers": peers if peers is not None else [],
            "peers_observed": observed,
            "stack_up": 1,
            "errors": list(errors or []),
        }

    @logged
    def peer(self, endpoint=PEER, up=1, rtt=10.0):
        return {"r": endpoint, "up": up, "rtt": rtt, "rx": 1, "tx": 1}

    @logged
    def store(self, rows):
        atomic(
            self.paths.state / "metrics.jsonl",
            "".join(json.dumps(row) + "\n" for row in rows).encode(),
        )

    @logged
    def test_untrusted_numbers_and_halves(self):
        for value in (True, "5", None, -1, float("nan"), float("inf"), float("-inf")):
            self.assertIsNone(tm.trend_number(value))
        self.assertEqual(tm.trend_number(0), 0.0)
        self.assertEqual(tm.trend_number(2), 2.0)
        self.assertEqual(tm.trend_number(1.5), 1.5)
        self.assertEqual(tm.trend_halves([]), ([], []))
        self.assertEqual(tm.trend_halves([1]), ([], []))
        self.assertEqual(tm.trend_halves([1, 2, 3]), ([1], [3]))
        self.assertEqual(tm.trend_halves([1, 2, 3, 4]), ([1, 2], [3, 4]))

    @logged
    def test_drift_thresholds_and_directions(self):
        self.assertIsNone(tm.trend_drift([], [1], 5.0))
        self.assertIsNone(tm.trend_drift([1], [], 5.0))
        stable = tm.trend_drift([10, 10, 10], [10, 12], 5.0)
        self.assertEqual(stable["verdict"], "stable")
        self.assertEqual(stable["threshold"], 5.0)
        worse = tm.trend_drift([10, 10.0], [40, 40.0], 5.0)
        self.assertEqual(worse["verdict"], "degrading")
        self.assertEqual(worse["delta"], 30.0)
        self.assertEqual(worse["samples"], [2, 2])
        better = tm.trend_drift([10, 10.0], [40, 40.0], 5.0, worse_higher=False)
        self.assertEqual(better["verdict"], "improving")
        spread = tm.trend_drift([1, 20, 40], [60, 60, 60], 5.0)
        self.assertEqual(spread["threshold"], 57.0)

    @logged
    def test_peer_line_absent_rows_and_invalid_latency(self):
        line = [
            None,
            self.peer(rtt=float("nan")),
            self.peer(up=0, rtt=10.0),
            self.peer(rtt=-1),
            self.peer(rtt=10.0),
            self.peer(rtt=10.0),
        ]
        detail = tm.trend_peer(line)
        self.assertEqual(detail["observed"], [2, 3])
        self.assertIsNone(detail["rtt_ms"])
        self.assertEqual(detail["availability"]["first"], 50.0)
        self.assertEqual(detail["availability"]["second"], 100.0)
        self.assertEqual(detail["availability"]["samples"], [2, 3])
        self.assertEqual(detail["availability"]["verdict"], "improving")
        self.assertNotIn("presence", detail)
        empty = tm.trend_peer([None, None])
        self.assertIsNone(empty["availability"])
        self.assertIsNone(empty["rtt_ms"])
        self.assertEqual(empty["observed"], [0, 0])
        self.assertEqual(tm.trend_peer([])["observed"], [0, 0])

    @logged
    def test_insufficient_history_reasons(self):
        self.store([self.sample(2, observed=False), self.sample(1, observed=False)])
        report = tm.trend(self.ctx, 2)
        self.assertEqual(report["verdict"], "insufficient_history")
        self.assertIn("fewer_than_8_samples", report["reasons"])
        self.assertIn("span_below_30_minutes", report["reasons"])
        self.assertIn("no_observed_samples", report["reasons"])
        self.assertEqual(report["node"]["up_peers"], None)
        self.assertEqual(report["peers"], [])
        self.store([self.sample(0, observed=False)])
        single = tm.trend(self.ctx, 2)
        self.assertIsNone(single["sampling_minutes"])
        self.assertEqual(single["span_minutes"], 0.0)
        with self.assertRaisesRegex(Failure, "no_samples_in_window"):
            self.store([])
            tm.trend(self.ctx, 2)

    @logged
    def test_degrading_window_and_json_projection(self):
        rows = []
        for index in range(12):
            first = index < 6
            rows.append(
                self.sample(
                    60 - index * 5,
                    peers=[
                        self.peer(rtt=10.0 if first else 60.0),
                        self.peer(OTHER, up=1 if first else 0, rtt=5.0),
                    ],
                )
            )
        self.store(rows)
        report = tm.trend(self.ctx, 2)
        self.assertEqual(report["verdict"], "degrading")
        self.assertEqual(report["collector"], "fresh")
        self.assertEqual(report["peer_identity"], "endpoint_not_key")
        self.assertEqual([p["peer"] for p in report["peers"]], [OTHER, PEER])
        self.assertEqual(report["peers"][1]["rtt_ms"]["verdict"], "degrading")
        # A peer that goes down keeps its row in getpeers (measured on the v0.5.14
        # corpus: five dead peers are five rows with up:false), so the loss shows up as
        # availability, and that is what must read as a degradation.
        dropped_rows = [
            self.sample(
                60 - index * 5,
                peers=[self.peer(OTHER), self.peer(up=1 if index < 6 else 0)],
            )
            for index in range(12)
        ]
        self.store(dropped_rows)
        gone = tm.trend(self.ctx, 2)
        self.assertEqual(gone["verdict"], "degrading")
        dropped = next(p for p in gone["peers"] if p["peer"] == PEER)
        self.assertEqual(dropped["availability"]["second"], 0.0)
        self.assertEqual(dropped["availability"]["verdict"], "degrading")
        # A row that is simply absent has no series in this window: no claim at all.
        self.assertNotIn("presence", dropped)
        main.dispatch(self.ctx, self.args("json"))
        payload = json.loads(self.stdout.getvalue())
        self.assertEqual(payload["verdict"], "degrading")
        self.assertEqual(payload["window_hours"], 24)

    @logged
    def test_stable_improving_junk_peers_and_staleness(self):
        rows = [self.sample(60 - index * 5, peers=[self.peer(rtt=10.0)]) for index in range(12)]
        self.store(rows)
        self.assertEqual(tm.trend(self.ctx, 2)["verdict"], "stable")
        improving = [
            self.sample(60 - index * 5, peers=[self.peer(rtt=90.0 if index < 6 else 10.0)])
            for index in range(12)
        ]
        self.store(improving)
        self.assertEqual(tm.trend(self.ctx, 2)["verdict"], "improving")
        junk = [self.sample(30 - index, peers=["junk", {"r": None}]) for index in range(9)]
        self.store(junk)
        report = tm.trend(self.ctx, 2)
        self.assertEqual([p["peer"] for p in report["peers"]], ["unknown-peer"])
        stale = [
            self.sample(300 - index, peers=[self.peer()], errors=["node_inactive"])
            for index in range(9)
        ]
        self.store(stale)
        report = tm.trend(self.ctx, 24)
        self.assertEqual(report["collector"], "stale")
        self.assertIn("collector_stale_beyond_sampling_interval", report["reasons"])
        self.assertEqual(report["verdict"], "insufficient_history")

    @logged
    def test_error_rate_drift_and_text_projection(self):
        rows = []
        for index in range(12):
            errors = ["no_up_peers"] if index >= 8 else []
            rows.append(self.sample(60 - index * 5, peers=[self.peer()], errors=errors))
        self.store(rows)
        report = tm.trend(self.ctx, 2)
        self.assertEqual(report["node"]["error_rate"]["verdict"], "degrading")
        text = "\n".join(tm.trend_text(report))
        self.assertIn("peer_identity=endpoint_not_key", text)
        self.assertIn("node error_rate%", text)
        self.assertIn(f"trend={report['verdict']}", text)
        self.assertEqual(tm.trend_line(None), "not_comparable (one half has no samples)")
        thin = tm.trend(self.ctx, 2)
        thin["reasons"] = ["fewer_than_8_samples"]
        self.assertIn("reasons=fewer_than_8_samples", "\n".join(tm.trend_text(thin)))

    @logged
    def test_hostile_history_never_emits_non_finite_json(self):
        # Same class as issue #23: NaN/Infinity are valid Python JSON literals, so a
        # stored counter can carry them. They must not reach the report or the JSON
        # output (json.dumps would emit an invalid token downstream).
        rows = []
        for index in range(12):
            peers = [self.peer(rtt=float("inf")), self.peer(), {"r": {"nested": "endpoint"}}]
            rows.append(
                {
                    "schema": 2,
                    "ts": (
                        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=60 - index * 5)
                    ).isoformat(),
                    "up": float("nan") if index % 2 else 1,
                    "peers": {"not": "a list"} if index == 3 else peers,
                    "peers_observed": True,
                    "errors": [],
                }
            )
        rows.append(dict(rows[0]))
        self.store(rows)
        report = tm.trend(self.ctx, 2)
        text = json.dumps(report, allow_nan=False)
        self.assertNotIn("NaN", text)
        self.assertNotIn("Infinity", text)
        self.assertEqual([p["peer"] for p in report["peers"]], [PEER, "unknown-peer"])
        main.dispatch(self.ctx, self.args("2", "json"))
        json.loads(self.stdout.getvalue(), parse_constant=self.fail)

    @logged
    def test_unknown_observation_is_not_a_missing_peer(self):
        # A collector outage must not read as "the peer disappeared": presence and
        # availability divide only by samples where the node actually answered.
        line = [self.peer()] * 4 + [None] * 4
        seen = [True] * 4 + [False] * 4
        detail = tm.trend_peer(line, seen)
        self.assertEqual(detail["observed"], [4, 0])
        self.assertEqual(detail["unobserved"], [0, 4])
        self.assertIsNone(detail["availability"])
        self.assertIsNone(detail["rtt_ms"])
        rows = [
            self.sample(
                60 - index * 5,
                peers=[self.peer()],
                observed=index < 6,
                errors=[] if index < 6 else ["metric_unavailable"],
            )
            for index in range(12)
        ]
        self.store(rows)
        report = tm.trend(self.ctx, 2)
        peer = next(p for p in report["peers"] if p["peer"] == PEER)
        # Half the window has no observation at all: no availability claim is made
        # from the empty half, and the unknown count is reported instead.
        self.assertEqual(peer["unobserved"], [0, 6])
        # The empty half yields no availability figure instead of a fabricated 0 %.
        self.assertIsNone(peer["availability"])
        self.assertNotIn("presence", peer)
        self.assertEqual(report["unobserved_samples"], 6)
        self.assertEqual(report["node"]["error_rate"]["verdict"], "degrading")
        # Half the window has no observation: the error signal stands, but no trend
        # claim is made from a degraded evidence base.
        self.assertEqual(report["verdict"], "insufficient_history")
        self.assertIn("unobserved_above_25_percent", report["reasons"])
        self.assertIn("unobserved=6", "\n".join(tm.trend_text(report)))

    @logged
    def test_single_pass_matches_the_per_series_path(self):
        # Differential test: the one-pass aggregation inside trend() and the
        # documented per-series API must produce the same block for the same history.
        # The pattern is arithmetic, not random: no RNG import and a fixed corpus.
        self.maxDiff = None
        names = [PEER, OTHER, "quic://192.0.2.77:9000"]
        rtts = [0.0, 8.0, 12.5, float("nan"), float("inf")]
        for count in (3, 4, 7, 12, 21, 40):
            rows = []
            for index in range(count):
                observed = (index * 7 + count) % 10 >= 3
                peers = []
                for offset, name in enumerate(names):
                    if (index * 3 + offset * 5 + count) % 7 >= 4:
                        continue
                    peers.append(
                        {
                            "r": name,
                            "up": (index + offset) % 3 != 0,
                            "rtt": rtts[(index + offset * 2) % len(rtts)],
                            "rx": 1,
                            "tx": 1,
                        }
                    )
                rows.append(
                    self.sample(
                        2 + (count - index) * 2,
                        peers=peers,
                        observed=observed,
                        errors=["no_up_peers"] if (index + count) % 4 == 0 else [],
                    )
                )
            self.store(rows)
            report = tm.trend(self.ctx, 2)
            blocks = {item["peer"]: item for item in report["peers"]}
            flags = [row["peers_observed"] is True for row in rows]
            for name in names:
                line = []
                for row in rows:
                    line.append(
                        next(
                            (
                                entry
                                for entry in row["peers"]
                                if isinstance(entry, dict) and entry["r"] == name
                            ),
                            None,
                        )
                    )
                expected = tm.trend_peer(line, flags)
                if name in blocks:
                    actual = {key: value for key, value in blocks[name].items() if key != "peer"}
                    self.assertEqual(actual, expected, msg=f"{name} count={count}")
                else:
                    self.assertIsNone(expected["availability"])
                    self.assertIsNone(expected["rtt_ms"])

    @logged
    def test_unobserved_share_boundary_and_strict_flag(self):
        rows = [self.sample(60 - index, peers=[self.peer()], observed=True) for index in range(12)]
        for index in (10, 11, 9):
            rows[index] = self.sample(60 - index, peers=[], observed=False, errors=["unavailable"])
        self.store(rows)
        quarter = tm.trend(self.ctx, 2)
        self.assertNotIn("unobserved_above_25_percent", quarter["reasons"])
        rows[8] = self.sample(52, peers=[], observed=False, errors=["unavailable"])
        self.store(rows)
        over = tm.trend(self.ctx, 2)
        self.assertIn("unobserved_above_25_percent", over["reasons"])
        # A corrupt or legacy flag is not proof of an observation.
        for raw in ("false", 1, None):
            self.store([self.sample(60 - index, peers=[self.peer()]) for index in range(8)])
            rows8 = tm.rows(self.ctx)
            for row in rows8:
                row["peers_observed"] = raw
            atomic(
                self.paths.state / "metrics.jsonl",
                "".join(json.dumps(row) + "\n" for row in rows8).encode(),
            )
            self.assertEqual(tm.trend(self.ctx, 2)["observed_samples"], 0)

    @logged
    def test_cli_arguments_and_read_only_root_boundary(self):
        self.store([self.sample(0, peers=[self.peer()])])
        with self.assertRaisesRegex(Failure, "numeric_argument_out_of_range"):
            main.dispatch(self.ctx, self.args("0"))
        with self.assertRaisesRegex(Failure, "unexpected_arguments"):
            main.dispatch(self.ctx, self.args("1", "json", "extra"))
        main.dispatch(self.ctx, self.args("2"))
        self.assertIn("trend=insufficient_history", self.stdout.getvalue())
        self.assertEqual(main.run_label("trend"), "trend")
        with (
            patch.object(main.os, "geteuid", return_value=1000),
            patch.object(main.os, "access", return_value=False),
        ):
            self.stdout.seek(0)
            self.stdout.truncate()
            main.dispatch(self.ctx, self.args("2", "json"))
        self.assertEqual(json.loads(self.stdout.getvalue())["samples"], 1)
