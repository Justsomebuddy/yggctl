"""Fresh observations survive old outbox failures; no services or external sender."""

import contextlib
import datetime as dt
import errno
import io
import unittest
from unittest.mock import patch

import telemetry as tm
from core import Failure, atomic, logged
from test_support import ConsoleFixture, URI


class CollectReplayTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.zero = dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc)
        self.ps = [
            dict(self.ps[0], up=False),
            dict(self.ps[0], remote=URI.replace(".1:", ".2:")),
        ]
        atomic(self.paths.state / "notify.state", "on\n")

    @logged
    def collect_at(self, minute, up=False, queue_error=None, unknown=False):
        self.ps[0]["up"] = up
        append = tm.append

        @logged
        def append_or_fail(ctx, name, *args, **kwargs):
            if name == "alerts.jsonl" and queue_error is not None:
                raise queue_error
            return append(ctx, name, *args, **kwargs)

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    tm,
                    "timestamp",
                    return_value=(self.zero + dt.timedelta(minutes=minute)).isoformat(),
                )
            )
            stack.enter_context(patch.object(tm, "append", append_or_fail))
            if unknown:
                stack.enter_context(
                    patch.object(tm, "peers", side_effect=Failure("fixture_unknown"))
                )
            return tm.collect(self.ctx)

    @logged
    def pending_down(self):
        self.collect_at(0)
        with self.assertRaises(OSError):
            self.collect_at(11, queue_error=OSError(errno.EIO, "synthetic queue failure"))
        return tm.load_peer_state(self.ctx)["pending"]

    @logged
    def test_queue_failure_preserves_two_observed_episodes(self):
        first = self.pending_down()
        for minute, up in ((15, True), (20, False), (31, False)):
            with self.assertRaises(OSError):
                self.collect_at(minute, up, OSError(errno.EIO, "synthetic queue failure"))
        pending = tm.load_peer_state(self.ctx)["pending"]
        self.assertEqual(
            [p["kind"] for p in pending],
            ["ygg-peer-down", "ygg-peer-up", "ygg-peer-down"],
        )
        self.assertEqual(pending[:1], first)
        self.assertEqual(pending[1]["minutes"], 15)
        self.collect_at(32, True)
        events = [
            row for row in tm.rows(self.ctx, "alerts.jsonl") if row["kind"] in tm.PEER_ALERT_KINDS
        ]
        self.assertEqual(
            [p["kind"] for p in events],
            ["ygg-peer-down", "ygg-peer-up", "ygg-peer-down", "ygg-peer-up"],
        )
        self.assertEqual([p["minutes"] for p in events], [11, 15, 11, 12])
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_queue_failure_records_unknown_observation_gap(self):
        pending = self.pending_down()
        with self.assertRaises(OSError):
            self.collect_at(
                15,
                queue_error=OSError(errno.EIO, "synthetic queue failure"),
                unknown=True,
            )
        state = tm.load_peer_state(self.ctx)
        self.assertTrue(state.get("observation_gap"))
        self.assertEqual(state["pending"], pending)
        self.collect_at(20, True)
        self.assertTrue(tm.rows(self.ctx, "alerts.jsonl")[-1]["observation_gap"])

    @logged
    def test_corrupt_queue_preserves_observation_without_rewriting_queue(self):
        pending = self.pending_down()
        queue = self.paths.state / "alerts.jsonl"
        atomic(queue, b"invalid json\n")
        with self.assertRaisesRegex(Failure, "corrupt_metric_record"):
            self.collect_at(15, True)
        state = tm.load_peer_state(self.ctx)
        self.assertEqual(state["down"], {})
        self.assertEqual(state["pending"][:1], pending)
        self.assertEqual(state["pending"][-1]["kind"], "ygg-peer-up")
        self.assertEqual(queue.read_bytes(), b"invalid json\n")

    @logged
    def test_original_preflush_error_is_not_silently_retried_or_hidden(self):
        self.pending_down()
        error = OSError(errno.EIO, "synthetic one-shot error")
        with patch.object(tm, "flush_peer_alerts", side_effect=[error, None]) as flush:
            with self.assertRaises(OSError) as raised:
                self.collect_at(15, True)
        self.assertIs(raised.exception, error)
        self.assertEqual(flush.call_count, 1)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"][-1]["kind"], "ygg-peer-up")

    @logged
    def test_full_recoverable_pending_drains_before_new_transition(self):
        self.pending_down()
        with patch.object(tm, "PEER_PENDING_LIMIT", 1):
            self.collect_at(15, True)
        # keep=1 also rotates the queue; this control checks that pending space
        # was freed before staging, not retention of already acknowledged rows.
        self.assertEqual([p["kind"] for p in tm.rows(self.ctx, "alerts.jsonl")], ["ygg-peer-up"])
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_still_full_pending_fails_without_discarding_existing_state(self):
        self.pending_down()
        before = (self.paths.state / "alert-state.json").read_bytes()
        error = Failure("synthetic_queue_unavailable")
        with (
            patch.object(tm, "PEER_PENDING_LIMIT", 1),
            self.assertRaisesRegex(Failure, "alert_pending_limit") as raised,
        ):
            self.collect_at(15, True, error)
        self.assertIs(raised.exception.__context__, error)
        self.assertEqual((self.paths.state / "alert-state.json").read_bytes(), before)

    @logged
    def test_id_conflict_keeps_queue_and_original_pending(self):
        pending = self.pending_down()
        tm.append(self.ctx, "alerts.jsonl", dict(pending[0], minutes=99))
        queue_before = (self.paths.state / "alerts.jsonl").read_bytes()
        with self.assertRaisesRegex(Failure, "alert_pending_id_conflict"):
            self.collect_at(15, True)
        self.assertEqual((self.paths.state / "alerts.jsonl").read_bytes(), queue_before)
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"][:1], pending)

    @logged
    def test_privacy_guard_keeps_legacy_pending_private_and_stages_safe_observation(
        self,
    ):
        self.pending_down()
        state = tm.load_peer_state(self.ctx)
        # Deliberately fake legacy private URI; no operational credential.
        state["pending"][0]["peer"] = URI + "&token=SYNTHETIC_FIXTURE"
        tm.save_peer_state(self.ctx, state)
        queue = self.paths.state / "alerts.jsonl"
        atomic(queue, b"")
        with self.assertRaisesRegex(Failure, "legacy_peer_pending_requires_privacy_review"):
            self.collect_at(15, True)
        saved = tm.load_peer_state(self.ctx)
        self.assertEqual(saved["pending"][:1], state["pending"])
        self.assertEqual(saved["pending"][-1]["kind"], "ygg-peer-up")
        self.assertEqual(saved["pending"][-1]["peer"], tm.peer_label(URI))
        self.assertEqual(queue.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
