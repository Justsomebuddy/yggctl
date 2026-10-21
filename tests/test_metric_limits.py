"""Synthetic retention/wire boundaries, real local broker, no live services."""

import base64
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import broker
import core
from core import Failure, METRIC_RECORD_LIMIT, METRICS_LIMIT, logged
import research
from research import metrics
import telemetry
import test_support as fixture_support

NOW = dt.datetime(2026, 10, 20, 12, tzinfo=dt.timezone.utc)


class MetricLimits(unittest.TestCase):
    @logged
    def setUp(self):
        core.trace_quiet()
        self.fixture = fixture_support.ConsoleFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.ctx = self.fixture.ctx
        self.path = self.fixture.paths.state / "metrics.jsonl"

    @logged
    def collect(self, now=NOW):
        with (
            patch.object(telemetry, "timestamp", return_value=now.isoformat()),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            telemetry.collect(self.ctx)

    @logged
    def seed(self, sample, count):
        with self.path.open("w") as stream:
            for i in range(count):
                row = dict(sample, ts=(NOW - dt.timedelta(minutes=count - i)).isoformat())
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")

    @logged
    def worker(self):
        directory = tempfile.TemporaryDirectory(prefix="yb-")
        self.addCleanup(directory.cleanup)
        server = broker.Broker(
            self.ctx,
            "research",
            os.geteuid(),
            Path(directory.name),
            expected_cgroup=broker.process_cgroup(os.getpid()),
        )
        self.addCleanup(server.close)
        worker = broker.WorkerContext(server.path, self.fixture.paths)
        worker.conn.settimeout(10)
        self.addCleanup(worker.conn.close)
        self.addCleanup(worker.reader.close)
        return worker

    @logged
    def assert_report(self, ctx, hours, now):
        with (
            patch.object(research, "timestamp", return_value=now.isoformat()),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = research.report(ctx, hours)
        history = json.loads(Path(result["json_file"]).read_bytes())["history"]
        self.assertFalse(result["unknown_history"])
        self.assertGreater(history["samples"], 0)
        self.assertEqual(history["invalid_records"], 0)
        self.assertEqual(history["unknown_records"], 0)

    @logged
    def test_collect_report_through_full_retention_cycle(self):
        self.collect()
        sample = telemetry.rows(self.ctx)[0]
        for before, count, offset in (
            (9999, 10000, 0),
            (None, 10001, 1),
            (11999, 12000, 0),
            (None, 10000, 1),
            (None, 10001, 2),
        ):
            with self.subTest(rows=count, offset=offset):
                if before is not None:
                    self.seed(sample, before)
                now = NOW + dt.timedelta(minutes=offset)
                self.collect(now)
                self.assertEqual(len(telemetry.rows(self.ctx)), count)
                for hours in (1, 24, 72):
                    self.assert_report(self.ctx, hours, now)

    @logged
    def test_reader_still_rejects_above_retention_cap(self):
        self.assertEqual(METRIC_RECORD_LIMIT, 12000)
        with self.assertRaisesRegex(Failure, "research_metric_record_limit"):
            metrics.summary([{}] * (METRIC_RECORD_LIMIT + 1), 1, NOW.isoformat())

    @logged
    def test_metrics_wire_envelope_and_full_raw_limit(self):
        self.assertEqual(broker.REPLY_LIMIT, 24 * 1024 * 1024)
        self.assertEqual(broker.METRICS_LIMIT, METRICS_LIMIT)
        for size in (18 * 1024 * 1024, METRICS_LIMIT):
            with self.subTest(raw_bytes=size):
                raw = (bytes(range(256)) * ((size + 255) // 256))[:size]
                self.path.write_bytes(raw)
                envelope = (
                    json.dumps(
                        {"data": base64.b64encode(raw).decode()}, separators=(",", ":")
                    ).encode()
                    + b"\n"
                )
                self.assertLessEqual(len(envelope), broker.METRICS_REPLY_LIMIT)
                self.assertEqual(self.worker().read_state("metrics.jsonl", METRICS_LIMIT), raw)
                if size == METRICS_LIMIT:
                    self.assertEqual(len(envelope), broker.METRICS_REPLY_LIMIT)

    @logged
    def test_broker_rejects_raw_file_above_limit(self):
        self.path.write_bytes(b"x" * (METRICS_LIMIT + 1))
        with self.assertRaisesRegex(Failure, "file_size_limit"):
            self.worker().read_state("metrics.jsonl", METRICS_LIMIT)

    @logged
    def test_request_specific_wire_caps_remain_fail_closed(self):
        worker = broker.WorkerContext.__new__(broker.WorkerContext)
        worker.conn, worker.reader, worker.call_lock = Mock(), Mock(), threading.Lock()
        for call, expected in (("admin", 8), ("metrics", 12)):
            with (
                self.subTest(call=call),
                patch.object(broker, "REPLY_LIMIT", 8),
                patch.object(broker, "METRICS_REPLY_LIMIT", 12),
            ):
                worker.reader.readline.return_value = b"x" * (expected + 1)
                with self.assertRaisesRegex(Failure, "broker_unavailable"):
                    worker.call({"call": call})
                worker.reader.readline.assert_called_with(expected + 1)

    @logged
    def test_report_crosses_old_base64_boundary_without_losing_history(self):
        self.fixture.ps = [
            {
                "remote": f"tls://192.0.2.{i + 1}:443?key={i + 1:064x}",
                "up": True,
                "inbound": False,
                "latency": 1000000,
                "key": f"{i + 1:064x}",
            }
            for i in range(15)
        ]
        self.collect()
        sample = telemetry.rows(self.ctx)[0]
        row_bytes = len((json.dumps(sample, separators=(",", ":")) + "\n").encode())
        old_raw_cap = ((broker.REPLY_LIMIT - 12) // 4) * 3
        before = old_raw_cap // row_bytes
        self.assertLess(before + 1, 10000)
        self.seed(sample, before - 1)
        for offset in (0, 1):
            now = NOW + dt.timedelta(minutes=offset)
            self.collect(now)
            raw = self.path.read_bytes()
            self.assertLess(len(raw), METRICS_LIMIT)
            self.assertEqual(len(raw) > old_raw_cap, bool(offset))
            worker = self.worker()
            self.assertEqual(worker.read_state("metrics.jsonl", METRICS_LIMIT), raw)
            for hours in (1, 24, 72):
                self.assert_report(worker, hours, now)


@logged
def run_suite():
    start = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MetricLimits)
    total = suite.countTestCases()
    print(f"[1/1] metric contracts; processed=0/{total} remaining={total}", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    errors = len(result.errors) + len(result.failures)
    print(
        f"[done] processed={result.testsRun}/{total} remaining=0 errors={errors} "
        f"elapsed={time.monotonic() - start:.2f}s",
        flush=True,
    )
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    run_suite()
