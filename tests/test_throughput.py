"""Stored-history throughput: counter deltas, resets, gaps and unusable rows."""

from typing import Any

import argparse
import contextlib
import datetime as dt
import io
from unittest.mock import patch

from core import Failure
import main
import telemetry as tm
from test_support import ConsoleFixture, URI

BASE = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)


def sample(minutes: float, rx: Any = 0, tx: Any = 0, label: str = URI) -> dict[str, Any]:
    return {
        "ts": (BASE + dt.timedelta(minutes=minutes)).isoformat(),
        "up": 1,
        "peers": [{"r": label, "up": True, "rx": rx, "tx": tx}],
    }


class Throughput(ConsoleFixture):
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def run_throughput(self, rows, hours=3):
        for row in rows:
            tm.append(self.ctx, "metrics.jsonl", row)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            tm.throughput(self.ctx, hours)
        return output.getvalue()

    def test_rates_are_adjacent_counter_deltas(self):
        text = self.run_throughput(
            [
                sample(0, rx=0, tx=0),
                sample(1, rx=3_750_000, tx=7_500_000),
                sample(2, rx=7_500_000, tx=15_000_000),
            ]
        )
        self.assertIn("peers=1 ambiguous_labels=0 invalid_counters=0", text)
        self.assertIn(
            "sent=1.00Mbit/s peak=1.00 recv=0.50Mbit/s peak=0.50 intervals=2 gaps=0 resets=0",
            text,
        )

    def test_counter_reset_skips_the_interval_without_clamping(self):
        text = self.run_throughput(
            [
                sample(0, rx=0, tx=0),
                sample(2, rx=2_000_000, tx=4_000_000),
                sample(4, rx=1_000_000, tx=2_000_000),
            ]
        )
        self.assertIn("intervals=1 gaps=0 resets=1", text)

    def test_duplicate_timestamp_produces_no_rate(self):
        text = self.run_throughput([sample(0), sample(0, rx=10, tx=10)])
        self.assertIn("no_usable_intervals gaps=0 resets=0", text)

    def test_long_gap_is_not_reported_as_a_rate(self):
        text = self.run_throughput([sample(0), sample(20, rx=1 << 20, tx=1 << 20)])
        self.assertIn("no_usable_intervals gaps=1 resets=0", text)

    def test_nonfinite_and_missing_counters_are_skipped(self):
        text = self.run_throughput(
            [
                sample(0, rx=None, tx=None),
                sample(1, rx="7", tx=7),
                sample(2, rx=10**400, tx=10**400),
                sample(3, rx=0, tx=0),
                sample(4, rx=0, tx=0),
            ]
        )
        self.assertIn("peers=1 ambiguous_labels=0 invalid_counters=5", text)
        self.assertIn("intervals=1 gaps=0 resets=0", text)

    def test_rows_without_usable_peer_counters_are_reported(self):
        rows = [
            {"ts": BASE.isoformat(), "up": 1},
            {"ts": (BASE + dt.timedelta(minutes=1)).isoformat(), "peers": "not-a-list"},
            {"ts": (BASE + dt.timedelta(minutes=2)).isoformat(), "peers": [1, None]},
        ]
        text = self.run_throughput(rows)
        self.assertIn("peers=0 ambiguous_labels=0 invalid_counters=0", text)
        self.assertIn("no_peer_counters: stored samples carry no usable peer counters", text)

    def test_empty_window_is_a_controlled_failure(self):
        with self.assertRaisesRegex(Failure, "no_samples_in_window"):
            tm.throughput(self.ctx, 1)

    def test_cli_defaults_to_the_24h_window(self):
        with (
            patch.object(main.os, "geteuid", return_value=0),
            patch.object(main.telemetry, "throughput") as throughput,
        ):
            main.do_throughput(self.ctx, argparse.Namespace(command="throughput"), [])
        throughput.assert_called_once_with(self.ctx, 24)

    def test_cli_asks_for_root_only_when_metrics_are_unreadable(self):
        with (
            patch.object(main.os, "geteuid", return_value=1000),
            patch.object(main.os, "access", return_value=False),
            patch.object(self.ctx, "root") as root,
            patch.object(main.telemetry, "throughput") as throughput,
        ):
            main.do_throughput(self.ctx, argparse.Namespace(command="throughput"), ["2"])
        root.assert_called_once_with()
        throughput.assert_called_once_with(self.ctx, 2)


WS = "ws://192.0.2.1:443"


def row(minutes: float, peers: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "ts": (BASE + dt.timedelta(minutes=minutes)).isoformat(),
        "up": 1,
        "peers": peers,
    }


def link(path: str, rx: Any = 0, tx: Any = 0) -> dict[str, Any]:
    return {"r": WS + path, "up": True, "rx": rx, "tx": tx}


class ThroughputSeries(Throughput):
    def test_two_ws_paths_at_one_endpoint_are_ambiguous(self):
        text = self.run_throughput(
            [
                row(0, [link("/a")]),
                row(1, [link("/b", rx=1000, tx=1000)]),
            ]
        )
        self.assertIn("peers=0 ambiguous_labels=1", text)
        self.assertIn("ws://192.0.2.1:443: ambiguous_peer_label series=2", text)
        self.assertNotIn("Mbit/s", text)

    def test_duplicate_rows_with_the_same_identity_stay_one_series(self):
        text = self.run_throughput(
            [
                row(0, [link("/a"), link("/a")]),
                row(1, [link("/a", rx=7_500_000, tx=7_500_000)]),
            ]
        )
        self.assertIn("peers=1 ambiguous_labels=0", text)
        self.assertIn("sent=1.00Mbit/s", text)

    def test_counter_above_the_exact_float_range_is_unusable(self):
        text = self.run_throughput([sample(0), sample(1, rx=(1 << 53) + 1, tx=(1 << 53) + 1)])
        self.assertIn("invalid_counters=2", text)
        self.assertIn("no_usable_intervals", text)

    def test_counter_at_the_exact_float_bound_is_accepted(self):
        text = self.run_throughput(
            [
                sample(0, rx=(1 << 53) - 1, tx=(1 << 53) - 1),
                sample(1, rx=1 << 53, tx=1 << 53),
            ]
        )
        self.assertIn("intervals=1", text)

    def test_overflowing_counters_never_print_inf(self):
        text = self.run_throughput([sample(0), sample(1, rx=1e308, tx=1e308)])
        self.assertIn("invalid_counters=2", text)
        self.assertNotRegex(text.lower(), r"\binf\b|\bnan\b")

    def test_rate_above_the_usable_domain_is_an_unusable_interval(self):
        text = self.run_throughput([sample(0), sample(1 / 60, rx=10**15, tx=10**15)])
        self.assertIn("no_usable_intervals gaps=0 resets=0 unusable=1", text)
        self.assertNotRegex(text.lower(), r"\binf\b|\bnan\b")

    def test_unparsable_peer_identity_is_counted_and_skipped(self):
        text = self.run_throughput(
            [
                row(0, [{"r": None, "rx": 0, "tx": 0}, {"r": "not-a-uri", "rx": 0, "tx": 0}]),
                row(1, [{"r": URI, "rx": 10, "tx": 10}]),
            ]
        )
        self.assertIn("invalid_identities=2", text)
        self.assertIn("peers=1", text)

    def test_rate_helper_rejects_out_of_domain_values(self):
        self.assertIsNone(tm.throughput_rate(1, 0))
        self.assertIsNone(tm.throughput_rate(-1, 1))
        self.assertIsNone(tm.throughput_rate(10**400, 1))
        self.assertIsNone(tm.throughput_rate(10**15, 1))
        self.assertEqual(tm.throughput_rate(1_000_000, 8), 1.0)

    def test_series_key_keeps_the_public_pin_and_drops_credentials(self):
        pin = "a" * 64
        self.assertEqual(
            tm.peer_series_key(f"ws://user:secret@192.0.2.1:443/a?key={pin.upper()}&password=x"),
            f"ws://192.0.2.1:443/a#{pin}",
        )
        self.assertEqual(tm.peer_series_key("tcp://192.0.2.1:443/"), "tcp://192.0.2.1:443#")
        for value in (
            None,
            7,
            "http://192.0.2.1:443",
            "tcp://192.0.2.1",
            "tcp://example.test:443",
            "tcp://fe80::1%25eth0:443",
            "tcp://[fe80::1%25eth0]:443",
            "tcp://192.0.2.1:443\n",
            "tcp://192.0.2.1:443/" + "a" * 4096,
        ):
            self.assertIsNone(tm.peer_series_key(value), value)
        self.assertEqual(
            tm.peer_series_key("tcp://192.0.2.1:443?key=" + "z" * 64),
            "tcp://192.0.2.1:443#",
        )
        self.assertEqual(tm.peer_series_key("tcp://192.0.2.1:443?bad"), "tcp://192.0.2.1:443#")
