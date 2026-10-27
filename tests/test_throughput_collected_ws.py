"""Collector redaction must not turn distinct WS links into one rate."""

import contextlib
import datetime as dt
import io
from unittest.mock import patch

import telemetry as tm
from core import logged
from test_support import ConsoleFixture


class CollectedWebSocketIdentity(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    @logged
    def peer(self, remote, counter):
        return {
            "remote": remote,
            "up": True,
            "key": "1" * 64,
            "inbound": False,
            "latency": 1000000,
            "bytes_recvd": counter,
            "bytes_sent": counter,
        }

    @logged
    def sample(self, path, counter, minutes):
        self.ps = [
            self.peer("ws://192.0.2.1:443/" + path, counter),
            self.peer("tcp://192.0.2.2:443", counter),
        ]
        stamp = (self.now - dt.timedelta(minutes=minutes)).isoformat()
        with patch.object(tm, "timestamp", return_value=stamp):
            tm.collect(self.ctx)

    @logged
    def test_collected_distinct_ws_paths_withhold_rate_without_exposing_path(self):
        self.sample("alpha", 0, 2)
        self.sample("beta", 7_500_000, 1)
        history = (self.paths.state / "metrics.jsonl").read_text()
        self.assertNotIn("alpha", history)
        self.assertNotIn("beta", history)
        self.output.seek(0)
        self.output.truncate(0)
        tm.throughput(self.ctx, 1)
        report = self.output.getvalue()
        ws = next(line for line in report.splitlines() if line.startswith("ws://192.0.2.1:443:"))
        tcp = next(line for line in report.splitlines() if line.startswith("tcp://192.0.2.2:443:"))
        self.assertIn("identity_unverifiable", ws)
        self.assertIn("ambiguous_labels=0", report)
        self.assertIn("unverifiable_labels=1", report)
        self.assertNotIn("Mbit/s", ws)
        self.assertIn("sent=1.00Mbit/s", tcp)
        self.assertNotIn("alpha", report)
        self.assertNotIn("beta", report)

    @logged
    def test_bare_legacy_wss_endpoint_is_also_unverifiable(self):
        self.ps = [self.peer("wss://192.0.2.1:443", 0)]
        for minutes, counter in ((2, 0), (1, 7_500_000)):
            self.ps[0]["bytes_recvd"] = self.ps[0]["bytes_sent"] = counter
            with patch.object(
                tm, "timestamp", return_value=(self.now - dt.timedelta(minutes=minutes)).isoformat()
            ):
                tm.collect(self.ctx)
        self.output.seek(0)
        self.output.truncate(0)
        tm.throughput(self.ctx, 1)
        report = self.output.getvalue()
        self.assertIn("wss://192.0.2.1:443: identity_unverifiable", report)
        self.assertNotIn("Mbit/s", report)

    @logged
    def test_mixed_bare_and_explicit_paths_withhold_whole_label(self):
        for minutes, remote, counter in (
            (2, "ws://192.0.2.1:443/explicit", 0),
            (1, "ws://192.0.2.1:443", 7_500_000),
        ):
            tm.append(
                self.ctx,
                "metrics.jsonl",
                {
                    "ts": (self.now - dt.timedelta(minutes=minutes)).isoformat(),
                    "peers": [{"r": remote, "up": True, "rx": counter, "tx": counter}],
                },
            )
        self.output.seek(0)
        self.output.truncate(0)
        tm.throughput(self.ctx, 1)
        report = self.output.getvalue()
        self.assertIn("ws://192.0.2.1:443: identity_unverifiable", report)
        self.assertNotIn("Mbit/s", report)

    @logged
    def test_collected_root_slash_is_also_conservatively_withheld(self):
        self.ps = [self.peer("ws://192.0.2.1:443/", 0)]
        for minutes, counter in ((2, 0), (1, 7_500_000)):
            self.ps[0]["bytes_recvd"] = self.ps[0]["bytes_sent"] = counter
            with patch.object(
                tm, "timestamp", return_value=(self.now - dt.timedelta(minutes=minutes)).isoformat()
            ):
                tm.collect(self.ctx)
        self.output.seek(0)
        self.output.truncate(0)
        tm.throughput(self.ctx, 1)
        self.assertIn("identity_unverifiable", self.output.getvalue())
        self.assertNotIn("Mbit/s", self.output.getvalue())

    @logged
    def test_legacy_explicit_path_series_is_still_calculated(self):
        for minutes, counter in ((2, 0), (1, 7_500_000)):
            tm.append(
                self.ctx,
                "metrics.jsonl",
                {
                    "ts": (self.now - dt.timedelta(minutes=minutes)).isoformat(),
                    "peers": [
                        {
                            "r": "ws://192.0.2.1:443/explicit",
                            "up": True,
                            "rx": counter,
                            "tx": counter,
                        }
                    ],
                },
            )
        self.output.seek(0)
        self.output.truncate(0)
        tm.throughput(self.ctx, 1)
        report = self.output.getvalue()
        self.assertIn("unverifiable_labels=0", report)
        self.assertIn("sent=1.00Mbit/s", report)
        self.assertNotIn("explicit", report)
