"""Synthetic history bounds, alert independence and honest sender boundary."""

import concurrent.futures
import contextlib
import datetime as dt
import io
import json

# Fixed synthetic process results only, never a shell.
import subprocess  # nosec B404
import time
import unittest
from unittest.mock import patch

import core
import telemetry as tm
from core import Failure, atomic, logged
from test_support import ConsoleFixture as Fixture, URI


class HistorySender(unittest.TestCase):
    @logged
    def setUp(self):
        core.trace_quiet()
        f = Fixture()
        f.setUp()
        self.addCleanup(f.tmp.cleanup)
        self.f, self.ctx, self.p = f, f.ctx, f.paths
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.zero = dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc)
        atomic(self.p.state / "notify.state", "on\n")

    @logged
    def collect_at(self, minute, write_error=None, unknown=False):
        append = tm.append

        @logged
        def maybe_fail(ctx, name, *args, **kwargs):
            if name == "metrics.jsonl" and write_error:
                raise write_error
            return append(ctx, name, *args, **kwargs)

        at = (self.zero + dt.timedelta(minutes=minute)).isoformat()
        with patch.object(tm, "timestamp", return_value=at), patch.object(tm, "append", maybe_fail):
            if unknown:
                with patch.object(tm, "peers", side_effect=Failure("fixture_unknown")):
                    with self.assertRaisesRegex(Failure, "metric_write_failed_alerts_processed"):
                        tm.collect(self.ctx)
            elif write_error:
                with self.assertRaisesRegex(Failure, "metric_write_failed_alerts_processed"):
                    tm.collect(self.ctx)
            else:
                return tm.collect(self.ctx)

    @logged
    def events(self):
        return [v for v in tm.rows(self.ctx, "alerts.jsonl") if v["kind"] in tm.PEER_ALERT_KINDS]

    @logged
    def test_actual_24_and_64_peer_samples_rotate_before_byte_refusal(self):
        for count in (24, 64):
            with self.subTest(peers=count):
                self.f.ps = [
                    dict(self.f.ps[0], remote=f"tls://192.0.2.{i + 1}:443?key=" + "a" * 64)
                    for i in range(count)
                ]
                sample = self.collect_at(0)
                # Accelerated accumulated history, not a multi-day or live run.
                line = (json.dumps(sample, separators=(",", ":")) + "\n").encode()
                amount = tm.METRICS_LIMIT // len(line)
                self.assertLess(amount, 12000)
                atomic(self.p.state / "metrics.jsonl", line * amount, 0o640)
                self.collect_at(1)
                self.collect_at(2)
                data = (self.p.state / "metrics.jsonl").read_bytes()
                values = tm.rows(self.ctx)
                self.assertLessEqual(len(data), tm.METRICS_LIMIT)
                self.assertTrue(data.endswith(b"\n"))
                self.assertEqual(
                    values[-1]["ts"], (self.zero + dt.timedelta(minutes=2)).isoformat()
                )
                self.assertLessEqual(len(values), amount)
                self.assertFalse(tm.load_peer_state(self.ctx).get("observation_gap", False))

    @logged
    def test_byte_suffix_count_one_variable_rows_and_torn_tail(self):
        atomic(self.p.state / "tiny.jsonl", b'{"v":1}\n{"v":2}\n{"partial":')
        with patch.object(tm, "METRICS_LIMIT", 35):
            tm.append(self.ctx, "tiny.jsonl", {"v": "long new value"}, keep=2)
            self.assertEqual(tm.rows(self.ctx, "tiny.jsonl"), [{"v": 2}, {"v": "long new value"}])
            tm.append(self.ctx, "tiny.jsonl", {"v": "x" * 20}, keep=1)
            self.assertEqual(tm.rows(self.ctx, "tiny.jsonl"), [{"v": "x" * 20}])
        atomic(self.p.state / "tiny.jsonl", '{"v":1}\n{"v":"' + "z" * 18 + '"}\n')
        with patch.object(tm, "METRICS_LIMIT", 40):
            tm.append(self.ctx, "tiny.jsonl", {"v": "q" * 10}, keep=5)
            self.assertEqual(tm.rows(self.ctx, "tiny.jsonl"), [{"v": "q" * 10}])

    @logged
    def test_oversize_single_record_and_failed_atomic_preserve_history(self):
        path = self.p.state / "small.jsonl"
        atomic(path, b'{"x":1}\n')
        before = path.read_bytes()
        with patch.object(tm, "METRICS_LIMIT", 10):
            for fn in (tm.append, tm.metric_compact):
                with self.assertRaisesRegex(Failure, "metric_record_size_limit"):
                    fn(self.ctx, "small.jsonl", {"x": "z" * 20}, keep=2)
        with (
            patch.object(tm, "METRICS_LIMIT", 10),
            patch.object(tm, "atomic", side_effect=OSError()),
        ):
            with self.assertRaises(OSError):
                tm.append(self.ctx, "small.jsonl", {"x": 2}, keep=2)
        self.assertEqual(path.read_bytes(), before)

    @logged
    def test_corrupt_history_never_silently_replaced(self):
        path = self.p.state / "bad.jsonl"
        atomic(path, b"bad json\n")
        with patch.object(tm, "METRICS_LIMIT", 10):
            with self.assertRaisesRegex(Failure, "corrupt_metric_record"):
                tm.append(self.ctx, "bad.jsonl", {"x": 2})
        self.assertEqual(path.read_bytes(), b"bad json\n")

    @logged
    def test_existing_over_bound_history_fails_closed(self):
        path = self.p.state / "oversize.jsonl"
        with path.open("wb") as f:
            f.truncate(tm.METRICS_LIMIT + 1)
        with self.assertRaisesRegex(Failure, "file_size_limit"):
            tm.append(self.ctx, "oversize.jsonl", {})
        self.assertEqual(path.stat().st_size, tm.METRICS_LIMIT + 1)

    @logged
    def test_parallel_compaction_preserves_every_new_record(self):
        path = self.p.state / "parallel.jsonl"
        atomic(path, b'{"old":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}\n' * 2)

        @logged
        def writer(number):
            tm.append(self.ctx, "parallel.jsonl", {"new": number})

        with patch.object(tm, "METRICS_LIMIT", 120):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(writer, range(8)))
        values = tm.rows(self.ctx, "parallel.jsonl")
        self.assertEqual(sorted(v["new"] for v in values if "new" in v), list(range(8)))
        self.assertLessEqual(path.stat().st_size, 120)

    @logged
    def test_history_failure_does_not_merge_two_observed_outages(self):
        self.f.ps = [
            dict(self.f.ps[0], up=False),
            dict(self.f.ps[0], remote=URI.replace(".1:", ".2:")),
        ]
        for minute, up in ((0, False), (5, True), (18, False), (20, True)):
            self.f.ps[0]["up"] = up
            self.collect_at(minute, OSError("synthetic_history_only"))
        self.assertEqual(self.events(), [])
        self.assertEqual(tm.load_peer_state(self.ctx)["down"], {})
        self.assertIn("ygg-health", [v["kind"] for v in tm.rows(self.ctx, "alerts.jsonl")])

    @logged
    def test_history_failure_still_drains_pending_and_records_real_episode(self):
        pending = {
            "id": "old-durable-event",
            "kind": "ygg-peer-down",
            "ts": self.zero.isoformat(),
            "peer": URI,
            "minutes": 10,
            "up": 0,
            "total": 1,
        }
        state = tm.load_peer_state(self.ctx)
        state["pending"] = [pending]
        tm.save_peer_state(self.ctx, state)
        self.f.ps[0]["up"] = False
        self.collect_at(0, Failure("fixture_history_write"))
        self.assertEqual(self.events(), [pending])
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])
        self.collect_at(11, OSError())
        self.assertEqual(len(self.events()), 2)
        self.f.ps[0]["up"] = True
        self.collect_at(12, OSError())
        self.assertEqual(self.events()[-1]["kind"], "ygg-peer-up")
        self.assertEqual(self.events()[-1]["minutes"], 12)

    @logged
    def test_unknown_observation_with_history_failure_marks_gap(self):
        self.f.ps[0]["up"] = False
        self.collect_at(0, OSError())
        before = tm.load_peer_state(self.ctx)["down"]
        self.collect_at(8, OSError(), unknown=True)
        after = tm.load_peer_state(self.ctx)
        self.assertTrue(after["observation_gap"])
        self.assertEqual(after["down"], before)
        self.collect_at(11, OSError())
        self.assertEqual(self.events(), [])

    @logged
    def test_rc0_handled_command_error_is_only_process_checkpoint(self):
        atomic(
            self.p.state / "alerts.jsonl",
            json.dumps({"id": "boundary-id", "kind": "labelled-local-selftest"}) + "\n",
        )
        atomic(self.p.state / "alerts-forwarded.json", '{"sent":[]}\n')

        @logged
        def sender(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, b"synthetic command error", b"")

        with patch.object(self.ctx, "runner", sender):
            tm.forward(self.ctx)
        self.assertEqual(
            len(json.loads((self.p.state / "alerts-forwarded.json").read_bytes())["sent"]), 1
        )
        self.assertIn("NOT command acceptance/delivery/human ACK", self.output.getvalue())

    @logged
    def test_accept_then_timeout_can_retry_without_native_idempotency(self):
        atomic(
            self.p.state / "alerts.jsonl",
            json.dumps({"id": "boundary-id", "kind": "labelled-local-selftest"}) + "\n",
        )
        atomic(self.p.state / "alerts-forwarded.json", '{"sent":[]}\n')
        accepted = []

        @logged
        def sender(argv, **kwargs):
            accepted.append(kwargs["input"])
            if len(accepted) == 1:
                raise Failure("synthetic_accept_then_timeout")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(self.ctx, "runner", sender):
            with self.assertRaisesRegex(Failure, "alert_forward_failed"):
                tm.forward(self.ctx)
            self.assertEqual(
                json.loads((self.p.state / "alerts-forwarded.json").read_bytes())["sent"], []
            )
            tm.forward(self.ctx)
        self.assertEqual(len(accepted), 2)
        self.assertEqual(accepted[0], accepted[1])


@logged
def run_suite():
    core.trace_quiet()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HistorySender)
    start = time.monotonic()
    print(
        f"[1/1] history/sender contracts processed=0/{suite.countTestCases()} remaining={suite.countTestCases()}",
        flush=True,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        f"[done] processed={result.testsRun} errors={len(result.errors) + len(result.failures)} remaining=0 elapsed={time.monotonic() - start:.2f}s",
        flush=True,
    )
    if not result.wasSuccessful():
        raise Failure("history_sender_contracts_failed")


if __name__ == "__main__":
    run_suite()
