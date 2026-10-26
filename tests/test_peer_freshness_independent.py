"""Independent peer-freshness regressions using synthetic state and local locks."""

import contextlib
import datetime as dt
import errno
import fcntl
import io
import os
import time
from unittest.mock import patch

from core import Failure, atomic, logged
from test_support import ConsoleFixture, URI
import telemetry as tm


class IndependentReview(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.zero = dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc)
        self.ps = [dict(self.ps[0], up=False), dict(self.ps[0], remote=URI.replace(".1:", ".2:"))]
        atomic(self.paths.state / "notify.state", "on\n")

    @logged
    def at(self, seconds):
        return (self.zero + dt.timedelta(seconds=seconds)).isoformat()

    @logged
    def collect(self, seconds):
        with patch.object(tm, "timestamp", return_value=self.at(seconds)):
            return tm.collect(self.ctx)

    @logged
    def state(self):
        return tm.load_peer_state(self.ctx)

    @logged
    def events(self):
        return [x for x in tm.rows(self.ctx, "alerts.jsonl") if x["kind"] in tm.PEER_ALERT_KINDS]

    @logged
    def test_real_flock_timeout_does_not_confirm_old_outage(self):
        self.collect(0)
        before = (self.paths.state / "alert-state.json").read_bytes()
        fd = os.open(self.paths.state / ".console.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            began = time.monotonic()
            with self.assertRaisesRegex(Failure, "^mutation_lock_timeout$"):
                self.collect(600)
            self.assertGreaterEqual(time.monotonic() - began, 19)
            self.assertEqual((self.paths.state / "alert-state.json").read_bytes(), before)
            self.assertEqual(len(tm.rows(self.ctx)), 1)
        finally:
            os.close(fd)
        self.collect(660)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(660))

    @logged
    def test_microsecond_boundary_and_confirm_after_reset(self):
        self.collect(0)
        self.collect(120)
        self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
        self.collect(240.000001)
        self.assertEqual(self.state()["down"][URI]["since"], self.at(240.000001))
        for minute in range(1, 11):
            self.collect(240.000001 + minute * 60)
        self.assertEqual(
            [(x["kind"], x["minutes"]) for x in self.events()], [("ygg-peer-down", 10)]
        )

    @logged
    def test_gap_recovery_preserves_pending_id_payload_despite_queue_eio(self):
        for minute in range(10):
            self.collect(minute * 60)
        original_append = tm.append

        @logged
        def queue_eio(ctx, name, *args, **kwargs):
            if name == "alerts.jsonl":
                raise OSError(errno.EIO, "synthetic")
            return original_append(ctx, name, *args, **kwargs)

        with patch.object(tm, "append", queue_eio):
            with self.assertRaises(OSError):
                self.collect(600)
        first = self.state()["pending"][0]
        self.assertEqual(first["kind"], "ygg-peer-down")
        with patch.object(tm, "flush_peer_alerts", side_effect=OSError(errno.EIO, "synthetic")):
            with self.assertRaises(OSError):
                self.collect(900)
            self.ps[0]["up"] = True
            with self.assertRaises(OSError):
                self.collect(960)
        pending = self.state()["pending"]
        self.assertEqual(pending[0], first)
        self.assertEqual([x["kind"] for x in pending], ["ygg-peer-down", "ygg-peer-up"])
        self.assertTrue(pending[1]["observation_gap"])
        self.collect(1020)
        self.collect(1080)
        self.assertEqual(self.events(), pending)
        self.assertEqual(self.state()["pending"], [])

    @logged
    def test_legacy_alerted_episode_is_migrated_once_without_duplicate(self):
        tm.save_peer_state(self.ctx, {"down": {URI: {"since": self.at(-600), "alerted": True}}})
        self.collect(0)
        self.collect(60)
        self.assertTrue(self.state()["down"][URI]["observation_gap"])
        self.ps[0]["up"] = True
        self.collect(120)
        self.assertEqual([x["kind"] for x in self.events()], ["ygg-peer-up"])
        self.assertTrue(self.events()[0]["observation_gap"])

    @logged
    def test_equivalent_offset_timestamp_does_not_reset(self):
        self.collect(0)
        state = self.state()
        state["last_observed"] = self.zero.astimezone(
            dt.timezone(dt.timedelta(hours=3))
        ).isoformat()
        tm.save_peer_state(self.ctx, state)
        self.collect(60)
        self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
        self.collect(59)
        self.assertEqual(self.state()["down"][URI]["since"], self.at(59))

    @logged
    def test_atomic_state_write_failure_keeps_old_timestamp_and_pending(self):
        self.collect(0)
        before = self.state()
        with patch.object(tm, "save_peer_state", side_effect=OSError(errno.EIO, "synthetic")):
            with self.assertRaises(OSError):
                self.collect(660)
        self.assertEqual(self.state(), before)
        self.collect(720)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(720))

    @logged
    def test_invalid_observation_types_and_extreme_offsets_are_conservative(self):
        invalid: tuple[object, ...] = (
            True,
            [],
            {},
            4.5,
            "0001-01-01T00:00:00+23:59",
            "9999-12-31T23:59:59-23:59",
        )
        for value in invalid:
            with self.subTest(value=value):
                tm.save_peer_state(
                    self.ctx,
                    {
                        "down": {URI: {"since": self.at(-660), "alerted": False}},
                        "last_observed": value,
                    },
                )
                self.collect(0)
                self.assertEqual(self.events(), [])
                self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
