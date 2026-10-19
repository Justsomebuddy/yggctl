"""Telemetry torn writes, corrupt state, alert deduplication and unknown health."""

from typing import Any

import contextlib
import datetime as dt
import io
import json
import stat
from types import SimpleNamespace
from unittest.mock import patch

from core import Failure, atomic, logged
import telemetry as tm
from test_support import ConsoleFixture, URI


class TelemetryEdges(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_corrupt_rows_and_append_io_guards(self):
        with (
            patch.object(self.ctx, "read_state", return_value=b"[]\n"),
            self.assertRaisesRegex(Failure, "corrupt_metric_record"),
        ):
            tm.rows(self.ctx)
        for mode, size, label in (
            (stat.S_IFDIR | 0o600, 0, "metric_file_not_regular"),
            (stat.S_IFREG | 0o600, 32 * 1024 * 1024, "metric_file_size_limit"),
        ):
            with (
                patch.object(self.ctx, "locked", return_value=contextlib.nullcontext()),
                patch.object(
                    tm.os, "fstat", return_value=SimpleNamespace(st_mode=mode, st_size=size)
                ),
                self.assertRaisesRegex(Failure, label),
            ):
                tm.append(self.ctx, "metrics.jsonl", {})
        atomic(self.paths.state / "metrics.jsonl", b"x" * ((1 << 20) + 1))
        with self.assertRaisesRegex(Failure, "corrupt_metric_tail"):
            tm.append(self.ctx, "metrics.jsonl", {})
        atomic(self.paths.state / "metrics.jsonl", b"")
        with (
            patch.object(tm.os, "write", return_value=0),
            self.assertRaisesRegex(Failure, "metric_append_no_progress"),
        ):
            tm.append(self.ctx, "metrics.jsonl", {})
        with (
            patch.object(tm.os, "pread", return_value=b""),
            self.assertRaisesRegex(Failure, "metric_file_changed"),
        ):
            tm.metric_records(0, 1)

    @logged
    def test_notification_state_and_labelled_local_alert(self):
        self.assertEqual(tm.notify_state(self.ctx), "off")
        for action in ("on", "show", "test", "off"):
            tm.notify(self.ctx, action)
        self.assertEqual(tm.notify_state(self.ctx), "off")
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl")[0]["kind"], "labelled-local-selftest")
        with self.assertRaisesRegex(Failure, "notify_on_off_show_test"):
            tm.notify(self.ctx, "invalid")
        atomic(self.paths.state / "notify.state", "broken")
        with self.assertRaisesRegex(Failure, "invalid_notify_state"):
            tm.notify_state(self.ctx)

    @logged
    def test_corrupt_peer_state_and_reconnect_timestamps(self):
        sample: dict[str, Any] = {
            "ts": "2026-10-19T10:00:00+00:00",
            "peers": [{"r": URI, "up": False}],
        }
        for data in (
            b"not json",
            b"[]",
            json.dumps(
                {"down": {URI: {"since": "invalid"}}, "starts": [], "unstable": []}
            ).encode(),
        ):
            atomic(self.paths.state / "alert-state.json", data)
            self.assertEqual(tm.peer_alerts(self.ctx, sample), [])
        now = dt.datetime.fromisoformat(sample["ts"])
        starts, unstable = tm.reconnects(
            {URI: ["invalid", None, (now - dt.timedelta(hours=2)).isoformat()]},
            {URI: "invalid"},
            {},
            now,
            sample["peers"],
            0,
            1,
            [],
        )
        self.assertEqual((starts, unstable), ({}, {}))

    @logged
    def test_forward_duplicate_ids_sent_once(self):
        self.prepare_forward_pending(1)
        data = (self.paths.state / "alerts.jsonl").read_bytes()
        atomic(self.paths.state / "alerts.jsonl", data + data)
        tm.forward(self.ctx)
        self.assertEqual(sum(a[0] == tm.SENDER for a in self.calls), 1)
        self.assertEqual(
            json.loads((self.paths.state / "alerts-forwarded.json").read_text()), {"sent": ["a0"]}
        )

    @logged
    def test_collect_degraded_health_and_repeat_dedup(self):
        tm.notify(self.ctx, "on")
        self.ps[0]["up"] = False
        change = {"kind": "ygg-peer-down", "peer": URI, "minutes": 10, "up": 0, "total": 1}
        with (
            patch.object(self.ctx, "unit", return_value={"ActiveState": "inactive"}),
            patch.object(tm, "peer_alerts", return_value=[change]),
        ):
            for _ in range(2):
                with self.assertRaisesRegex(Failure, "sample_recorded"):
                    tm.collect(self.ctx)
        metrics = tm.rows(self.ctx)
        self.assertIn("node_inactive", metrics[0]["errors"])
        self.assertIn("stack_inactive", metrics[0]["errors"])
        alerts = tm.rows(self.ctx, "alerts.jsonl")
        self.assertEqual(sum(a["kind"] == "ygg-health" for a in alerts), 1)
        self.assertEqual(sum(a["kind"] == "ygg-peer-down" for a in alerts), 2)
        with (
            patch.object(tm, "peers", side_effect=OSError()),
            self.assertRaisesRegex(Failure, "sample_recorded"),
        ):
            tm.collect(self.ctx)
        self.assertEqual(tm.rows(self.ctx)[-1]["errors"], ["metric_unavailable"])

    @logged
    def test_window_ignores_out_of_window_and_watch_zero(self):
        now = dt.datetime.now(dt.timezone.utc)
        with patch.object(
            tm,
            "rows",
            return_value=[
                {"ts": (now - dt.timedelta(days=2)).isoformat()},
                {"ts": now.isoformat()},
            ],
        ):
            records, invalid = tm.window(self.ctx)
            self.assertEqual((len(records), invalid), (1, 0))
        tm.watch(self.ctx, 0)

    @logged
    def test_clean_collect_with_notifications_enabled(self):
        tm.notify(self.ctx, "on")
        result = tm.collect(self.ctx)
        self.assertEqual(result["errors"], [])
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])
