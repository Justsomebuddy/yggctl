"""Synthetic producer durability and replay tests; no external sender or live services."""

import contextlib
import datetime as dt
import errno
import io
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture, URI
import telemetry as tm


class AlertOutboxTests(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.now = dt.datetime(2026, 10, 20, 9, tzinfo=dt.timezone.utc)
        self.enterContext(patch.object(tm, "timestamp", return_value=self.now.isoformat()))
        self.state_path = self.paths.state / "alert-state.json"
        self.queue_path = self.paths.state / "alerts.jsonl"
        self.ps = [
            {
                "remote": URI.replace("192.0.2.1", f"192.0.2.{n}"),
                "up": n != 1,
                "inbound": False,
                "latency": 1000000,
                "key": f"{n:064x}",
            }
            for n in (1, 2, 3)
        ]
        self.initial = {
            "down": {
                URI: {"since": (self.now - dt.timedelta(minutes=11)).isoformat(), "alerted": False}
            },
            "starts": {},
            "unstable": {},
        }
        atomic(self.state_path, json.dumps(self.initial))
        atomic(self.paths.state / "notify.state", "on\n", 0o644)

    @logged
    def read_state(self):
        return json.loads(self.state_path.read_text())

    @logged
    def restarted_context(self):
        return Context(self.paths, runner=self.runner, require_root=False)

    @logged
    def sample(self, up=False):
        return {"ts": self.now.isoformat(), "peers": [{"r": URI, "up": up}]}

    @logged
    def stage(self):
        tm.peer_alerts(self.ctx, self.sample())
        return self.read_state()["pending"]

    @logged
    def test_collect_recovers_one_shot_queue_open_eio_after_restart(self):
        original = os.open

        @logged
        def failing_open(path, flags, *args, **kwargs):
            if path == self.queue_path and flags & (os.O_WRONLY | os.O_RDWR):
                raise OSError(errno.EIO, "synthetic queue-open failure")
            return original(path, flags, *args, **kwargs)

        with patch.object(tm.os, "open", side_effect=failing_open), self.assertRaises(OSError):
            tm.collect(self.ctx)
        saved = self.read_state()
        self.assertTrue(saved["down"][URI]["alerted"])
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])
        restarted = self.restarted_context()
        self.assertEqual(tm.collect(restarted)["errors"], [])
        self.assertEqual(len(tm.rows(self.ctx, "alerts.jsonl")), 1)
        self.assertEqual(len(saved["pending"]), 1)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), saved["pending"])
        self.assertEqual(self.read_state()["pending"], [])
        tm.collect(restarted)
        self.assertEqual(len(tm.rows(self.ctx, "alerts.jsonl")), 1)
        self.assertFalse(any(call[0] == tm.SENDER for call in self.calls))

    @logged
    def test_recovery_and_unstable_events_are_durable(self):
        for kind in ("ygg-peer-up", "ygg-peer-unstable"):
            with self.subTest(kind=kind):
                state: dict[str, Any] = {"down": {}, "starts": {}, "unstable": {}}
                if kind == "ygg-peer-up":
                    state["down"] = {URI: dict(self.initial["down"][URI], alerted=True)}
                else:
                    state["starts"] = {
                        URI: [(self.now - dt.timedelta(minutes=n)).isoformat() for n in (3, 2, 1)]
                    }
                atomic(self.state_path, json.dumps(state))
                atomic(self.queue_path, "")
                tm.peer_alerts(self.ctx, self.sample(up=True))
                pending = self.read_state()["pending"]
                self.assertEqual([p["kind"] for p in pending], [kind])
                with patch.object(tm, "append", side_effect=OSError(errno.EIO, "synthetic")):
                    with self.assertRaises(OSError):
                        tm.flush_peer_alerts(self.ctx)
                tm.flush_peer_alerts(self.restarted_context())
                self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
                self.assertEqual(tm.peer_alerts(self.ctx, self.sample(up=True)), [])

    @logged
    def test_partial_batch_replay_preserves_ids_and_order(self):
        sample: dict[str, Any] = {"ts": self.now.isoformat(), "peers": []}
        state: dict[str, Any] = {"down": {}, "starts": {}, "unstable": {}}
        for n in (1, 2, 3):
            uri = URI.replace("192.0.2.1", f"192.0.2.{n}")
            state["down"][uri] = self.initial["down"][URI]
            sample["peers"].append({"r": uri, "up": False})
        atomic(self.state_path, json.dumps(state))
        tm.peer_alerts(self.ctx, sample)
        pending = self.read_state()["pending"]
        original = tm.append
        calls = 0

        @logged
        def partial_append(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, "synthetic second-event failure")
            return original(*args, **kwargs)

        with patch.object(tm, "append", side_effect=partial_append), self.assertRaises(OSError):
            tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending[:1])
        self.assertEqual(self.read_state()["pending"], pending)
        tm.flush_peer_alerts(self.restarted_context())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        self.assertEqual(self.read_state()["pending"], [])

    @logged
    def test_torn_queue_write_replays_complete_event(self):
        pending = self.stage()
        original = os.write
        calls = 0

        @logged
        def torn_write(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original(fd, data[:7])
            raise OSError(errno.EIO, "synthetic partial write")

        with patch.object(tm.os, "write", side_effect=torn_write), self.assertRaises(OSError):
            tm.flush_peer_alerts(self.ctx)
        self.assertEqual(self.queue_path.stat().st_size, 7)
        tm.flush_peer_alerts(self.restarted_context())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)

    @logged
    def test_append_fsync_error_deduplicates_and_resyncs(self):
        pending = self.stage()
        with patch.object(tm.os, "fsync", side_effect=OSError(errno.EIO, "synthetic")):
            with self.assertRaises(OSError):
                tm.flush_peer_alerts(self.ctx)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        with (
            patch.object(tm, "append") as append,
            patch.object(tm.os, "fsync", wraps=os.fsync) as sync,
        ):
            tm.flush_peer_alerts(self.restarted_context())
        append.assert_not_called()
        self.assertGreaterEqual(sync.call_count, 4)  # queue, directory, state file and directory
        self.assertEqual(self.read_state()["pending"], [])

    @logged
    def test_queue_and_directory_barrier_failures_keep_pending(self):
        pending = self.stage()
        tm.append(self.ctx, "alerts.jsonl", pending[0])
        original = os.fsync
        for directory in (False, True):

            @logged
            def failing_barrier(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) == directory:
                    raise OSError(errno.EIO, "synthetic durability barrier failure")
                return original(fd)

            with patch.object(tm.os, "fsync", side_effect=failing_barrier):
                with self.assertRaises(OSError):
                    tm.flush_peer_alerts(self.ctx)
            self.assertEqual(self.read_state()["pending"], pending)
        tm.flush_peer_alerts(self.restarted_context())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)

    @logged
    def test_interrupt_after_queue_commit_does_not_duplicate(self):
        pending = self.stage()
        with patch.object(tm, "save_peer_state", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                tm.flush_peer_alerts(self.ctx)
        self.assertEqual(self.read_state()["pending"], pending)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        with patch.object(tm, "append") as append:
            tm.flush_peer_alerts(self.restarted_context())
        append.assert_not_called()
        self.assertEqual(self.read_state()["pending"], [])

    @logged
    def test_abrupt_process_exit_after_queue_commit_replays_once(self):
        pending = self.stage()

        @logged
        def abrupt_exit(*args, **kwargs):
            os._exit(73)

        pid = os.fork()
        if pid == 0:
            with patch.object(tm, "save_peer_state", side_effect=abrupt_exit):
                tm.flush_peer_alerts(self.ctx)
            os._exit(74)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 73)
        self.assertEqual(self.read_state()["pending"], pending)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)
        with patch.object(tm, "append") as append:
            tm.flush_peer_alerts(self.restarted_context())
        append.assert_not_called()
        self.assertEqual(self.read_state()["pending"], [])

    @logged
    def test_state_write_failure_before_and_after_replace(self):
        original = tm.atomic
        before = self.state_path.read_bytes()
        with patch.object(tm, "atomic", side_effect=OSError(errno.EIO, "synthetic")):
            with self.assertRaises(OSError):
                tm.peer_alerts(self.ctx, self.sample())
        self.assertEqual(self.state_path.read_bytes(), before)

        @logged
        def replaced_then_failed(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError(errno.EIO, "synthetic post-replace directory fsync failure")

        with patch.object(tm, "atomic", side_effect=replaced_then_failed):
            with self.assertRaises(OSError):
                tm.peer_alerts(self.ctx, self.sample())
        pending = self.read_state()["pending"]
        tm.collect(self.restarted_context())
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)

    @logged
    def test_invalid_outbox_is_rejected_without_modification(self):
        item = self.stage()[0]
        invalid = [
            b"",
            b"{",
            b"[]",
            {"pending": {}},
            {"pending": [item] * (tm.PEER_PENDING_LIMIT + 1)},
            {"pending": [None]},
            {"pending": [dict(item, kind=[])]},
            {"pending": [dict(item, ts=None)]},
            {"pending": [dict(item, peer=None)]},
            {"pending": [{k: v for k, v in item.items() if k != "id"}]},
            {"pending": [dict(item, id=1)]},
            {"pending": [dict(item, id="")]},
            {"pending": [dict(item, id="x" * 129)]},
            {"pending": [item, item]},
        ]
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                data = value if isinstance(value, bytes) else json.dumps(value).encode()
                atomic(self.state_path, data)
                with self.assertRaises(Failure):
                    tm.load_peer_state(self.ctx)
                self.assertEqual(self.state_path.read_bytes(), data)

    @logged
    def test_capacity_and_byte_limits_fail_before_state_commit(self):
        first = self.stage()[0]
        state = dict(self.initial, pending=[first])
        atomic(self.state_path, json.dumps(state))
        before = self.state_path.read_bytes()
        with patch.object(tm, "PEER_PENDING_LIMIT", 1):
            with self.assertRaisesRegex(Failure, "alert_pending_limit"):
                tm.peer_alerts(self.ctx, self.sample())
        self.assertEqual(self.state_path.read_bytes(), before)
        with patch.object(tm, "PEER_STATE_LIMIT", 1):
            with self.assertRaisesRegex(Failure, "alert_state_size_limit"):
                tm.save_peer_state(self.ctx, state)
        self.assertEqual(self.state_path.read_bytes(), before)

    @logged
    def test_notify_off_preserves_pending_and_does_not_stage_new_events(self):
        pending = self.stage()
        tm.notify(self.ctx, "off")
        self.ps[0]["up"] = True
        tm.collect(self.ctx)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), [])
        self.assertEqual(self.read_state()["pending"], pending)
        tm.notify(self.ctx, "on")
        tm.collect(self.ctx)
        self.assertEqual(tm.rows(self.ctx, "alerts.jsonl"), pending)

    @logged
    def test_queue_id_conflict_keeps_pending(self):
        pending = self.stage()
        tm.append(self.ctx, "alerts.jsonl", dict(pending[0], minutes=99))
        with self.assertRaisesRegex(Failure, "alert_pending_id_conflict"):
            tm.flush_peer_alerts(self.ctx)
        self.assertEqual(self.read_state()["pending"], pending)

    @logged
    def test_queue_sync_rejects_nonregular_file(self):
        atomic(self.queue_path, "")
        with patch.object(tm.os, "fstat") as fstat:
            fstat.return_value.st_mode = stat.S_IFDIR | 0o700
            with self.assertRaisesRegex(Failure, "alert_queue_not_regular"):
                tm.sync_alert_queue(self.ctx)

    @logged
    def test_concurrent_collectors_queue_transition_once(self):
        contexts = [self.restarted_context(), self.restarted_context()]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(tm.collect, contexts))
        self.assertTrue(all(result["errors"] == [] for result in results))
        self.assertEqual(len(tm.rows(self.ctx, "alerts.jsonl")), 1)
        self.assertEqual(self.read_state()["pending"], [])
