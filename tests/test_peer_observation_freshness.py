"""Synthetic collector gap boundaries and durable peer observation state."""

import contextlib
import datetime as dt
import io
from unittest.mock import patch

from core import Failure, atomic, logged
from test_support import ConsoleFixture, URI
import telemetry as tm


class PeerObservationFreshnessTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.zero = dt.datetime(2026, 10, 26, tzinfo=dt.timezone.utc)
        self.down = dict(self.ps[0], up=False)
        self.ps = [self.down, dict(self.ps[0], remote=URI.replace("192.0.2.1", "192.0.2.2"))]
        atomic(self.paths.state / "notify.state", "on\n")

    @logged
    def at(self, seconds):
        return (self.zero + dt.timedelta(seconds=seconds)).isoformat()

    @logged
    def collect_at(self, seconds, unknown=False):
        with patch.object(tm, "timestamp", return_value=self.at(seconds)):
            try:
                if unknown:
                    with patch.object(self.ctx, "mode", side_effect=Failure("fixture_unavailable")):
                        tm.collect(self.ctx)
                else:
                    tm.collect(self.ctx)
            except Failure as exc:
                self.assertEqual(str(exc), "sample_recorded_with_unknown_or_degraded_health")
        return tm.rows(self.ctx)[-1]

    @logged
    def state(self):
        return tm.load_peer_state(self.ctx)

    @logged
    def events(self):
        return [
            row for row in tm.rows(self.ctx, "alerts.jsonl") if row["kind"] in tm.PEER_ALERT_KINDS
        ]

    @logged
    def test_120_seconds_is_tolerated_and_121_seconds_resets_unalerted_since(self):
        self.collect_at(0)
        self.collect_at(120)
        self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
        self.assertEqual(self.state()["last_observed"], self.at(120))
        self.collect_at(241)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(241))
        self.assertEqual(self.state()["last_observed"], self.at(241))

    @logged
    def test_omitted_collect_does_not_confirm_ten_minutes(self):
        self.collect_at(0)
        self.assertEqual(len(tm.rows(self.ctx)), 1)
        self.collect_at(660)
        self.assertEqual(len(tm.rows(self.ctx)), 2)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(660))

    @logged
    def test_regular_observations_confirm_down_and_gap_marks_recovery(self):
        for minute in range(11):
            self.collect_at(minute * 60)
        (down,) = self.events()
        self.assertEqual(
            (down["kind"], down["minutes"], down.get("observation_gap")),
            ("ygg-peer-down", 10, None),
        )
        self.down["up"] = True
        self.collect_at(721)
        down, up = self.events()
        self.assertEqual(
            (up["kind"], up["minutes"], up.get("observation_gap")), ("ygg-peer-up", 12, True)
        )
        rendered = tm.alert_message(up)["output"]
        self.assertIn("разрыв наблюдений", rendered)
        self.assertNotIn("после 12 мин", rendered)
        self.assertEqual(
            [event["kind"] for event in self.events()], ["ygg-peer-down", "ygg-peer-up"]
        )
        self.assertEqual(self.state()["down"], {})

    @logged
    def test_regular_recovery_has_duration_without_gap_marker(self):
        for minute in range(11):
            self.collect_at(minute * 60)
        self.down["up"] = True
        self.collect_at(660)
        down, up = self.events()
        self.assertEqual(
            (down["minutes"], up["minutes"], up.get("observation_gap")), (10, 11, None)
        )
        self.assertIn("после 11 мин", tm.alert_message(up)["output"])

    @logged
    def test_unknown_retains_last_observed_and_pending_episode(self):
        self.collect_at(0)
        unknown = self.collect_at(60, unknown=True)
        self.assertIs(unknown["peers_observed"], False)
        self.assertEqual(self.state()["last_observed"], self.at(0))
        self.assertTrue(self.state()["observation_gap"])
        self.collect_at(120)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(120))
        self.assertEqual(self.state()["last_observed"], self.at(120))

    @logged
    def test_legacy_down_without_timestamp_gets_one_time_gap(self):
        tm.save_peer_state(
            self.ctx,
            {
                "down": {URI: {"since": self.at(-660), "alerted": False}},
                "starts": {},
                "unstable": {},
            },
        )
        self.collect_at(0)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
        self.assertEqual(self.state()["last_observed"], self.at(0))

    @logged
    def test_invalid_legacy_last_observation_is_uncertain(self):
        invalid_previous: tuple[object, ...] = ({}, 42, "bad", "2026-10-25T23:59:00")
        for previous in invalid_previous:
            with self.subTest(previous=previous):
                tm.save_peer_state(
                    self.ctx,
                    {
                        "down": {URI: {"since": self.at(-660), "alerted": False}},
                        "starts": {},
                        "unstable": {},
                        "last_observed": previous,
                    },
                )
                atomic(self.paths.state / "alerts.jsonl", "")
                self.collect_at(0)
                self.assertEqual(self.events(), [])
                self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
                self.assertEqual(self.state()["last_observed"], self.at(0))

    @logged
    def test_equal_timestamp_is_not_a_gap(self):
        self.collect_at(0)
        self.collect_at(0)
        self.assertEqual(self.state()["down"][URI]["since"], self.at(0))
        self.assertEqual(self.state()["last_observed"], self.at(0))
        self.assertEqual(self.events(), [])

    @logged
    def test_first_observed_down_after_gap_starts_at_current_sample(self):
        self.down["up"] = True
        self.collect_at(0)
        self.down["up"] = False
        self.collect_at(660)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(660))
        self.assertEqual(self.state()["last_observed"], self.at(660))

    @logged
    def test_clock_rollback_resets_unalerted_interval(self):
        self.collect_at(60)
        self.collect_at(59)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(59))
        self.assertEqual(self.state()["last_observed"], self.at(59))

    @logged
    def test_notify_off_still_tracks_observation_gap_without_enqueue(self):
        tm.notify(self.ctx, "off")
        self.collect_at(0)
        self.collect_at(121)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state()["down"][URI]["since"], self.at(121))
        self.assertEqual(self.state()["last_observed"], self.at(121))

    @logged
    def test_pending_capacity_refusal_does_not_advance_timestamp(self):
        pending = {"id": "held", "ts": self.at(0), "kind": "ygg-peer-down", "peer": URI}
        tm.save_peer_state(
            self.ctx,
            {
                "down": {URI: {"since": self.at(0), "alerted": True}},
                "starts": {},
                "unstable": {},
                "pending": [pending],
                "last_observed": self.at(0),
            },
        )
        self.down["up"] = True
        with (
            patch.object(tm, "PEER_PENDING_LIMIT", 1),
            patch.object(tm, "timestamp", return_value=self.at(60)),
            patch.object(tm, "flush_peer_alerts", side_effect=OSError("synthetic queue failure")),
        ):
            with self.assertRaisesRegex(Failure, "alert_pending_limit"):
                tm.collect(self.ctx)
        self.assertEqual(self.state()["last_observed"], self.at(0))
        self.assertEqual(self.state()["pending"], [pending])
        self.assertEqual(self.state()["down"][URI]["alerted"], True)


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
