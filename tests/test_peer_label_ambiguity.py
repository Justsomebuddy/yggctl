"""Synthetic regression contracts for peer identities that collide after redaction."""

import contextlib
import datetime as dt
import errno
import io
import json
from typing import Any
from unittest.mock import patch

import telemetry as tm
from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture, URI
from research.metrics import summary


ENDPOINT = "ws://192.0.2.40:443"
FIRST = ENDPOINT + "/first?token=SYNTHETIC_FIRST"
SECOND = ENDPOINT + "/second?token=SYNTHETIC_SECOND"
OTHER = URI.replace("192.0.2.1", "192.0.2.41")


class PeerLabelAmbiguityTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.zero = dt.datetime(2026, 10, 23, tzinfo=dt.timezone.utc)
        atomic(self.paths.state / "notify.state", "on\n")

    @logged
    def at(self, minute):
        return (self.zero + dt.timedelta(minutes=minute)).isoformat()

    @logged
    def sample(self, minute, *rows):
        return {"ts": self.at(minute), "peers": [{"r": remote, "up": up} for remote, up in rows]}

    @logged
    def direct(self, minute, *rows, uptimes=None, ctx=None):
        return tm.peer_alerts(ctx or self.ctx, self.sample(minute, *rows), uptimes)

    @logged
    def state(self):
        return tm.load_peer_state(self.ctx)

    @logged
    def events(self):
        return [
            row for row in tm.rows(self.ctx, "alerts.jsonl") if row["kind"] in tm.PEER_ALERT_KINDS
        ]

    @logged
    def raw(self, remote, up, uptime=1):
        return {
            "remote": remote,
            "up": up,
            "uptime": uptime,
            "inbound": False,
            "latency": 1000000,
            "key": "1" * 64,
        }

    @logged
    def collect_at(self, minute, rows):
        self.ps = rows
        with patch.object(tm, "timestamp", return_value=self.at(minute)):
            with self.assertRaisesRegex(Failure, "sample_recorded_with_unknown_or_degraded_health"):
                tm.collect(self.ctx)
        return tm.rows(self.ctx)[-1]

    @logged
    def test_mixed_rows_in_both_orders_never_open_or_alert_a_down_episode(self):
        for rows in (((FIRST, False), (SECOND, True)), ((SECOND, True), (FIRST, False))):
            with self.subTest(rows=rows):
                self.assertEqual(self.direct(0, *rows), [])
                self.assertEqual(self.direct(12, *rows[::-1]), [])
                self.assertNotIn(ENDPOINT, self.state().get("down", {}))
                self.assertEqual(self.state().get("pending", []), [])

    @logged
    def test_all_down_and_all_up_collisions_do_not_start_or_recover(self):
        self.assertEqual(self.direct(0, (FIRST, False), (SECOND, False)), [])
        self.assertEqual(self.direct(15, (SECOND, False), (FIRST, False)), [])
        self.assertEqual(self.direct(16, (FIRST, True), (SECOND, True)), [])
        self.assertNotIn(ENDPOINT, self.state().get("down", {}))
        self.assertEqual(self.state().get("pending", []), [])

    @logged
    def test_exact_duplicate_rows_are_ambiguous_even_with_identical_status(self):
        self.direct(0, (FIRST, False), (FIRST, False))
        self.assertEqual(self.direct(11, (FIRST, False), (FIRST, False)), [])
        self.assertNotIn(ENDPOINT, self.state().get("down", {}))

    @logged
    def test_unknown_peer_collisions_do_not_learn_downtime(self):
        invalid = ("not-a-peer", "also-not-a-peer")
        self.assertEqual(tm.peer_label(invalid[0]), "unknown-peer")
        self.direct(0, (invalid[0], False), (invalid[1], True))
        self.assertEqual(self.direct(12, (invalid[1], True), (invalid[0], False)), [])
        self.assertNotIn("unknown-peer", self.state().get("down", {}))

    @logged
    def test_unalerted_down_restarts_threshold_after_ambiguous_interval(self):
        self.direct(0, (FIRST, False))
        self.direct(9, (FIRST, False), (SECOND, True))
        self.assertEqual(self.direct(20, (FIRST, False)), [])
        self.assertEqual(self.state()["down"][ENDPOINT]["since"], self.at(20))
        for minute in range(21, 30):
            self.assertEqual(self.direct(minute, (FIRST, False)), [])
        changes = self.direct(30, (FIRST, False))
        self.assertEqual([(x["kind"], x["minutes"]) for x in changes], [("ygg-peer-down", 10)])

    @logged
    def test_alerted_episode_survives_collision_and_restart_until_single_recovery(self):
        self.direct(0, (FIRST, False))
        for minute in range(1, 10):
            self.assertEqual(self.direct(minute, (FIRST, False)), [])
        first = self.direct(10, (FIRST, False))
        self.assertEqual([x["kind"] for x in first], ["ygg-peer-down"])
        self.assertEqual(self.direct(11, (FIRST, False)), [])
        before = self.state()
        self.assertEqual(self.direct(12, (FIRST, False), (SECOND, True)), [])
        middle = self.state()
        self.assertEqual(middle["down"][ENDPOINT]["since"], before["down"][ENDPOINT]["since"])
        self.assertTrue(middle["down"][ENDPOINT]["observation_gap"])
        self.assertEqual(middle["pending"], before["pending"])
        restarted = Context(self.paths, runner=self.runner, require_root=False)
        self.assertEqual(self.direct(22, (SECOND, False), ctx=restarted), [])
        recovered = self.direct(23, (SECOND, True), ctx=restarted)
        self.assertEqual([x["kind"] for x in recovered], ["ygg-peer-up"])
        self.assertTrue(recovered[0]["observation_gap"])

    @logged
    def test_collision_preserves_reconnect_evidence_without_learning_uptime(self):
        state: dict[str, Any] = {
            "down": {},
            "starts": {ENDPOINT: [self.at(0)]},
            "unstable": {ENDPOINT: self.at(0)},
            "pending": [],
        }
        tm.save_peer_state(self.ctx, state)
        for minute, rows in (
            (1, ((FIRST, True), (SECOND, True))),
            (2, ((SECOND, False), (FIRST, True))),
        ):
            self.assertEqual(self.direct(minute, *rows, uptimes={FIRST: 1, SECOND: 2}), [])
            saved = self.state()
            self.assertEqual(saved["starts"][ENDPOINT], state["starts"][ENDPOINT])
            self.assertEqual(saved["unstable"][ENDPOINT], state["unstable"][ENDPOINT])

    @logged
    def test_unrelated_single_peer_down_and_recovery_continue_through_collision(self):
        self.direct(0, (FIRST, True), (SECOND, False), (OTHER, False))
        for minute in range(1, 10):
            self.assertEqual(
                self.direct(minute, (FIRST, True), (SECOND, False), (OTHER, False)), []
            )
        changes = self.direct(10, (SECOND, True), (FIRST, False), (OTHER, False))
        self.assertEqual([(x["kind"], x["peer"]) for x in changes], [("ygg-peer-down", OTHER)])
        self.assertEqual(self.direct(11, (SECOND, True), (FIRST, False), (OTHER, False)), [])
        changes = self.direct(12, (FIRST, False), (SECOND, True), (OTHER, True))
        self.assertEqual([(x["kind"], x["peer"]) for x in changes], [("ygg-peer-up", OTHER)])
        self.assertNotIn(ENDPOINT, self.state().get("down", {}))

    @logged
    def test_collect_keeps_two_projected_rows_and_one_hourly_health_notice(self):
        rows = [self.raw(FIRST, False), self.raw(SECOND, True)]
        for minute in (0, 11):
            sample = self.collect_at(minute, rows)
            self.assertEqual(sample["errors"].count("ambiguous_peer_labels"), 1)
            self.assertEqual(
                [(p["r"], p["up"]) for p in sample["peers"]], [(ENDPOINT, False), (ENDPOINT, True)]
            )
            self.assertEqual((sample["up"], len(sample["peers"])), (1, 2))
        self.assertEqual(len(tm.rows(self.ctx)), 2)
        alerts = tm.rows(self.ctx, "alerts.jsonl")
        self.assertEqual([a["kind"] for a in alerts], ["ygg-health"])
        self.assertIn("ambiguous_peer_labels", alerts[0]["errors"])

    @logged
    def test_collect_ambiguous_label_does_not_block_unrelated_recovery(self):
        self.collect_at(0, [self.raw(FIRST, False), self.raw(SECOND, True), self.raw(OTHER, False)])
        for minute in range(1, 10):
            self.collect_at(
                minute, [self.raw(FIRST, False), self.raw(SECOND, True), self.raw(OTHER, False)]
            )
        self.collect_at(
            10, [self.raw(FIRST, False), self.raw(SECOND, True), self.raw(OTHER, False)]
        )
        self.collect_at(
            11, [self.raw(FIRST, False), self.raw(SECOND, True), self.raw(OTHER, False)]
        )
        self.collect_at(12, [self.raw(SECOND, False), self.raw(FIRST, True), self.raw(OTHER, True)])
        self.assertEqual(
            [(a["kind"], a["peer"]) for a in self.events()],
            [("ygg-peer-down", OTHER), ("ygg-peer-up", OTHER)],
        )

    @logged
    def test_notify_off_retains_diagnostic_but_emits_no_alerts(self):
        atomic(self.paths.state / "notify.state", "off\n")
        sample = self.collect_at(0, [self.raw(FIRST, False), self.raw(SECOND, True)])
        self.assertIn("ambiguous_peer_labels", sample["errors"])
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])
        self.assertEqual(self.state().get("pending", []), [])

    @logged
    def test_pending_preflush_replays_during_ambiguous_observation(self):
        pending = {
            "id": "synthetic-durable",
            "ts": self.at(0),
            "kind": "ygg-peer-down",
            "peer": OTHER,
            "minutes": 11,
            "up": 0,
            "total": 1,
        }
        tm.save_peer_state(
            self.ctx, {"down": {}, "starts": {}, "unstable": {}, "pending": [pending]}
        )
        self.collect_at(1, [self.raw(FIRST, False), self.raw(SECOND, True)])
        self.assertIn(pending, tm.rows(self.ctx, "alerts.jsonl"))
        self.assertEqual(self.state()["pending"], [])
        self.assertEqual(self.events(), [pending])

    @logged
    def test_preflush_eio_retains_original_pending_and_observation(self):
        pending = {
            "id": "synthetic-durable",
            "ts": self.at(0),
            "kind": "ygg-peer-down",
            "peer": OTHER,
            "minutes": 11,
            "up": 0,
            "total": 1,
        }
        tm.save_peer_state(
            self.ctx, {"down": {}, "starts": {}, "unstable": {}, "pending": [pending]}
        )
        error = OSError(errno.EIO, "synthetic queue failure")
        self.ps = [self.raw(FIRST, False), self.raw(SECOND, True)]
        with (
            patch.object(tm, "timestamp", return_value=self.at(1)),
            patch.object(tm, "flush_peer_alerts", side_effect=error),
        ):
            with self.assertRaises(OSError) as raised:
                tm.collect(self.ctx)
        self.assertIs(raised.exception, error)
        staged = self.state()["pending"]
        self.assertEqual(staged[:1], [pending])
        self.assertEqual(len(staged), 2)
        self.assertEqual(staged[1]["kind"], "ygg-health")
        self.assertEqual(staged[1]["errors"], ["ambiguous_peer_labels"])
        self.assertEqual(staged[1]["ts"], self.at(1))
        self.assertIn("ambiguous_peer_labels", tm.rows(self.ctx)[-1]["errors"])
        self.assertEqual(self.events(), [])
        self.ctx = Context(self.paths, runner=self.runner, require_root=False)
        self.collect_at(2, self.ps)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), staged)
        self.assertEqual(self.state()["pending"], [])

    @logged
    def test_corrupt_state_fails_closed_with_ambiguous_rows(self):
        path = self.paths.state / "alert-state.json"
        atomic(path, b"not json")
        with self.assertRaisesRegex(Failure, "alert_state_invalid"):
            self.direct(0, (FIRST, False), (SECOND, True))
        self.assertEqual(path.read_bytes(), b"not json")

    @logged
    def test_private_paths_and_query_never_enter_persistent_metrics_or_state(self):
        self.collect_at(0, [self.raw(FIRST, False), self.raw(SECOND, True)])
        for filename in ("metrics.jsonl", "alert-state.json", "alerts.jsonl"):
            data = (
                (self.paths.state / filename).read_text()
                if (self.paths.state / filename).exists()
                else ""
            )
            for marker in ("SYNTHETIC_FIRST", "SYNTHETIC_SECOND", "/first", "/second", "token="):
                self.assertNotIn(marker, data)
        self.assertNotIn("SYNTHETIC_FIRST", self.output.getvalue())
        self.assertNotIn("SYNTHETIC_SECOND", self.output.getvalue())

    @logged
    def test_long_collision_does_not_turn_expired_reconnects_into_an_alert(self):
        tm.save_peer_state(
            self.ctx,
            {
                "starts": {ENDPOINT: [self.at(0), self.at(1), self.at(2)]},
                "unstable": {ENDPOINT: self.at(3)},
                "pending": [],
            },
        )
        self.assertEqual(self.direct(400, (FIRST, True), (SECOND, False)), [])
        self.assertEqual(len(self.state()["starts"][ENDPOINT]), 3)
        self.assertEqual(self.direct(401, (FIRST, True), uptimes={FIRST: 1}), [])
        self.assertEqual(
            self.state()["starts"][ENDPOINT],
            [(self.zero + dt.timedelta(minutes=401, seconds=-1)).isoformat()],
        )
        self.assertEqual(self.state()["unstable"], {})

    @logged
    def test_full_pending_and_real_queue_eio_do_not_invent_a_recovery(self):
        self.direct(0, (FIRST, False))
        for minute in range(1, 11):
            self.direct(minute, (FIRST, False))
        self.direct(11, (FIRST, False))
        pending = self.state()["pending"]
        append = tm.append
        error = OSError(errno.EIO, "synthetic queue write failure")

        @logged
        def fail_queue(ctx, name, *args, **kwargs):
            if name == "alerts.jsonl":
                raise error
            return append(ctx, name, *args, **kwargs)

        self.ps = [self.raw(FIRST, False), self.raw(SECOND, True)]
        with (
            patch.object(tm, "append", fail_queue),
            patch.object(tm, "PEER_PENDING_LIMIT", 1),
            patch.object(tm, "timestamp", return_value=self.at(12)),
        ):
            with self.assertRaises(OSError) as raised:
                tm.collect(self.ctx)
        self.assertIs(raised.exception, error)
        self.assertEqual(self.state()["pending"], pending)
        self.assertTrue(self.state()["down"][ENDPOINT]["observation_gap"])
        self.assertEqual(self.events(), [])
        self.ctx = Context(self.paths, runner=self.runner, require_root=False)
        with patch.object(tm, "PEER_PENDING_LIMIT", 1):
            self.collect_at(13, self.ps)
        # With keep=1 the new health notice rotates out the acknowledged peer
        # event. Loss accounting remains visible; no false peer-up is invented.
        notice, ordinary = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
        self.assertEqual(self.events(), [])
        self.assertEqual(notice["evicted_uncheckpointed_total"], 1)
        self.assertEqual(len(ordinary), 1)
        self.assertEqual(ordinary[0]["kind"], "ygg-health")
        self.assertEqual(ordinary[0]["errors"], ["ambiguous_peer_labels"])
        self.assertEqual(ordinary[0]["ts"], self.at(13))
        self.assertNotEqual(ordinary[0]["id"], pending[0]["id"])
        self.assertEqual(self.state()["pending"], [])
        self.assertTrue(self.state()["down"][ENDPOINT]["observation_gap"])

    @logged
    def test_ack_failure_then_restart_does_not_duplicate_pending_or_clear_tracking(self):
        self.direct(0, (FIRST, False))
        for minute in range(1, 11):
            self.direct(minute, (FIRST, False))
        self.direct(11, (FIRST, False))
        pending = self.state()["pending"]
        save = tm.save_peer_state
        error = OSError(errno.EIO, "synthetic acknowledgement failure")

        @logged
        def fail_ack(ctx, state):
            if not state.get("pending"):
                raise error
            return save(ctx, state)

        self.ps = [self.raw(FIRST, False), self.raw(SECOND, True)]
        with (
            patch.object(tm, "save_peer_state", fail_ack),
            patch.object(tm, "timestamp", return_value=self.at(12)),
        ):
            with self.assertRaises(OSError) as raised:
                tm.collect(self.ctx)
        self.assertIs(raised.exception, error)
        staged = self.state()["pending"]
        self.assertEqual(staged[:1], pending)
        self.assertEqual(len(staged), 2)
        self.assertEqual(staged[1]["kind"], "ygg-health")
        self.assertEqual(staged[1]["errors"], ["ambiguous_peer_labels"])
        self.assertEqual(staged[1]["ts"], self.at(12))
        self.assertEqual(self.events(), pending)
        self.ctx = Context(self.paths, runner=self.runner, require_root=False)
        self.collect_at(13, self.ps)
        self.assertEqual(self.events(), pending)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), staged)
        self.assertEqual(self.state()["pending"], [])
        self.assertTrue(self.state()["down"][ENDPOINT]["alerted"])
        self.collect_at(14, self.ps)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), staged)

    @logged
    def test_retention_marker_and_full_batch_replay_survive_ambiguous_sample(self):
        pending = [
            {
                "id": f"synthetic-{n}",
                "kind": "ygg-peer-down",
                "ts": self.at(0),
                "peer": OTHER,
                "minutes": 11,
                "up": 0,
                "total": 1,
            }
            for n in range(2)
        ]
        tm.save_peer_state(self.ctx, {"pending": pending})
        marker = {
            "kind": tm.ALERT_RETENTION_KIND,
            "id": tm.ALERT_RETENTION_ID,
            "evicted_uncheckpointed_total": 7,
        }
        atomic(self.paths.state / "alerts.jsonl", json.dumps(marker) + "\n")
        atomic(self.paths.state / "alerts-forwarded.json", '{"sent":[]}\n')
        with patch.object(tm, "PEER_PENDING_LIMIT", 2):
            self.collect_at(1, [self.raw(FIRST, False), self.raw(SECOND, True)])
        notice, ordinary = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
        # Both peer events fit during initial replay. The subsequent health
        # append uses that same reduced keep=2 and accounts for one eviction.
        self.assertEqual(notice, dict(marker, evicted_uncheckpointed_total=8))
        self.assertEqual(self.events(), pending[1:])
        self.assertEqual(len(ordinary), 2)
        self.assertEqual(ordinary[0], pending[1])
        self.assertEqual(ordinary[1]["kind"], "ygg-health")
        self.assertEqual(ordinary[1]["errors"], ["ambiguous_peer_labels"])
        self.assertEqual(self.state()["pending"], [])

    @logged
    def test_history_write_failure_still_marks_ambiguous_existing_episode(self):
        self.direct(0, (FIRST, False))
        append = tm.append

        @logged
        def fail_metrics(ctx, name, *args, **kwargs):
            if name == "metrics.jsonl":
                raise OSError(errno.EIO, "synthetic history failure")
            return append(ctx, name, *args, **kwargs)

        self.ps = [self.raw(FIRST, False), self.raw(SECOND, True)]
        with (
            patch.object(tm, "append", fail_metrics),
            patch.object(tm, "timestamp", return_value=self.at(11)),
        ):
            with self.assertRaisesRegex(Failure, "metric_write_failed_alerts_processed"):
                tm.collect(self.ctx)
        self.assertEqual(tm.rows(self.ctx), [])
        self.assertTrue(self.state()["down"][ENDPOINT]["observation_gap"])
        self.assertEqual(self.events(), [])
        self.assertIn("ambiguous_peer_labels", tm.rows(self.ctx, "alerts.jsonl")[0]["errors"])

    @logged
    def test_research_report_consumes_degraded_history_as_unknown_not_healthy(self):
        self.collect_at(0, [self.raw(FIRST, False), self.raw(SECOND, True), self.raw(OTHER, True)])
        result = summary(tm.rows(self.ctx), 1, self.at(1))
        self.assertEqual(result["samples"], 1)
        self.assertEqual(result["unknown_records"], 1)
        self.assertEqual(len(result["peers"]), 2)
        for peer in result["peers"]:
            self.assertEqual(
                (peer["up_samples"], peer["down_samples"], peer["unknown_samples"]), (0, 0, 1)
            )
            self.assertIsNone(peer["availability_among_known_present_pct"])


if __name__ == "__main__":
    import unittest

    unittest.main()
