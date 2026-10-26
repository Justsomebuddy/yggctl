"""Real SQLite/Unix-lock fixtures, injected native CLI result; no live messaging."""

import concurrent.futures
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import signal
import stat
import subprocess  # nosec B404 # synthetic CompletedProcess results only.
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import core
import simplex_sender as sender
import telemetry as tm
from core import Failure, atomic, logged
from test_support import ConsoleFixture as Fixture


class NativeSender(unittest.TestCase):
    @logged
    def setUp(self):
        core.trace_quiet()
        f = Fixture()
        f.setUp()
        self.addCleanup(f.tmp.cleanup)
        self.ctx, self.p = f.ctx, f.paths
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.database = self.p.state / "fixture_chat.db"
        with sqlite3.connect(self.database) as db:
            db.executescript("""
            CREATE TABLE users(user_id INTEGER,active_user INTEGER);
            CREATE TABLE contacts(contact_id INTEGER,user_id INTEGER,local_display_name TEXT,is_user INTEGER,deleted INTEGER);
            CREATE TABLE chat_items(chat_item_id INTEGER PRIMARY KEY,user_id INTEGER,contact_id INTEGER,item_sent INTEGER,
              item_text TEXT,item_content TEXT,item_content_tag TEXT,msg_content_tag TEXT,item_deleted INTEGER,
              item_edited INTEGER,fwd_from_tag TEXT,group_id INTEGER);
            INSERT INTO users VALUES(1,1);INSERT INTO contacts VALUES(2,1,'fixture',0,0);
            """)
        self.database.chmod(0o600)
        self.binary = self.p.state / "native"
        atomic(self.binary, "fixture executable", 0o700)
        self.cfg = {
            "database": str(self.database),
            "contact": "fixture",
            "binary": str(self.binary),
            "user": "fixture",
            "lock": str(self.p.state / "profile.lock"),
        }
        atomic(self.p.etc / "simplex-sender.json", json.dumps(self.cfg))
        self.payload = {
            "rule": "fixture rule",
            "output": "fixture body",
            "priority": "Warning",
            "time": "fixture",
            "source": "yggctl",
        }
        self.calls = []
        self.mode = "accept"
        self.ctx.runner = self.native
        self.enterContext(
            patch.object(
                sender.pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid()),
            )
        )

    @logged
    def insert(self, text, **changes):
        row = dict(
            user_id=1,
            contact_id=2,
            item_sent=1,
            item_text=text,
            item_content=json.dumps(
                {"sndMsgContent": {"msgContent": {"type": "text", "text": text}}}
            ),
            item_content_tag="sndMsgContent",
            msg_content_tag="text",
            item_deleted=0,
            item_edited=0,
            fwd_from_tag=None,
            group_id=None,
        )
        row.update(changes)
        with sqlite3.connect(self.database) as db:
            columns = (
                "user_id",
                "contact_id",
                "item_sent",
                "item_text",
                "item_content",
                "item_content_tag",
                "msg_content_tag",
                "item_deleted",
                "item_edited",
                "fwd_from_tag",
                "group_id",
            )
            db.execute(
                "INSERT INTO chat_items(user_id,contact_id,item_sent,item_text,item_content,item_content_tag,msg_content_tag,item_deleted,item_edited,fwd_from_tag,group_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                [row[k] for k in columns],
            )

    @logged
    def native(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertEqual(sender.load_journal(self.ctx)[self.key()]["status"], "attempted")
        fd = kwargs["pass_fds"][0]
        with open(self.cfg["lock"], "r") as other:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
        text = json.loads(argv[-1].split(" json ", 1)[1])[0]["msgContent"]["text"]
        if self.mode in ("accept", "accepted-timeout"):
            self.insert(text)
        if self.mode in ("timeout", "accepted-timeout"):
            raise Failure("synthetic_timeout")
        return subprocess.CompletedProcess(
            argv, 0, b"handled command error" if self.mode == "reject" else b"", b""
        )

    @logged
    def key(self, event="event"):
        return hashlib.sha256(event.encode()).hexdigest()

    @logged
    def text(self, event="event"):
        return (
            "[yggctl:"
            + self.key(event)
            + "]\n"
            + self.payload["rule"]
            + "\n"
            + self.payload["output"]
        )

    @logged
    def call(self, event="event"):
        return sender.handoff(self.ctx, event, self.payload)

    @logged
    def queued(self):
        atomic(
            self.p.state / "alerts.jsonl",
            json.dumps({"id": "event", "kind": "labelled-local-selftest"}) + "\n",
        )
        atomic(self.p.state / "alerts-forwarded.json", '{"sent":[]}\n')

    @logged
    def test_handled_error_rc0_never_checkpoints_or_blindly_resends(self):
        self.queued()
        self.mode = "reject"
        for _ in range(2):
            with self.assertRaisesRegex(Failure, "alert_forward_failed"):
                tm.forward(self.ctx)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(
            json.loads((self.p.state / "alerts-forwarded.json").read_bytes()), {"sent": []}
        )
        self.assertEqual(sender.load_journal(self.ctx)[self.key()]["status"], "attempted")
        self.assertIn("native local recording is NOT delivery/human ACK", self.output.getvalue())

    @logged
    def test_forward_native_receipt_survives_cursor_crash_and_timeout(self):
        self.queued()
        self.mode = "accepted-timeout"
        with patch.object(tm, "atomic", side_effect=OSError("synthetic cursor crash")):
            with self.assertRaises(OSError):
                tm.forward(self.ctx)
        self.assertEqual(
            json.loads((self.p.state / "alerts-forwarded.json").read_bytes()), {"sent": []}
        )
        tm.forward(self.ctx)
        tm.forward(self.ctx)
        self.assertEqual(
            json.loads((self.p.state / "alerts-forwarded.json").read_bytes()), {"sent": ["event"]}
        )
        self.assertEqual(len(self.calls), 1)

    @logged
    def test_retention_notice_survives_native_handoff_and_restart_without_send(self):
        atomic(self.p.state / "alerts-forwarded.json", '{"sent":[]}\n')
        atomic(
            self.p.state / "alerts.jsonl",
            "".join(
                json.dumps({"id": f"a{i}", "kind": "labelled-local-selftest"}) + "\n"
                for i in range(6)
            ),
            0o640,
        )
        tm.append(
            self.ctx,
            "alerts.jsonl",
            {"id": "a6", "kind": "labelled-local-selftest"},
            keep=5,
        )
        notice, ordinary = tm.alert_retention(tm.rows(self.ctx, "alerts.jsonl"))
        self.assertEqual(notice["evicted_uncheckpointed_total"], 2)
        self.assertEqual([row["id"] for row in ordinary], ["a2", "a3", "a4", "a5", "a6"])

        # The shared native fixture normally expects one fixed event ID. Select
        # its sole current attempted entry so the same real SQLite adapter can
        # verify five distinct queue IDs without mocking handoff.
        def attempted_key(event="event"):
            return next(
                key
                for key, item in sender.load_journal(self.ctx).items()
                if item["status"] == "attempted"
            )

        with patch.object(self, "key", side_effect=attempted_key):
            tm.forward(self.ctx)

        expected_ids = ["a2", "a3", "a4", "a5", "a6"]
        self.assertEqual(len(self.calls), 5)
        self.assertEqual(
            json.loads((self.p.state / "alerts-forwarded.json").read_bytes()),
            {"sent": expected_ids},
        )
        journal = sender.load_journal(self.ctx)
        self.assertEqual(
            set(journal), {hashlib.sha256(a.encode()).hexdigest() for a in expected_ids}
        )
        self.assertTrue(all(item["status"] == "native-recorded" for item in journal.values()))
        with contextlib.closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM chat_items").fetchone()[0], 5)

        self.output.seek(0)
        self.output.truncate(0)
        fresh = core.Context(self.p, runner=self.native, require_root=False)
        tm.forward(fresh)
        self.assertEqual(len(self.calls), 5)
        self.assertEqual(len(sender.load_journal(fresh)), 5)
        self.assertIn("evicted_uncheckpointed_total=2", self.output.getvalue())
        self.assertIn("remaining=0", self.output.getvalue())

    @logged
    def test_native_accept_then_timeout_is_checkpointed_once_and_replay_recovers(self):
        self.mode = "accepted-timeout"
        self.assertEqual(self.call(), 1)
        self.assertEqual(self.call(), 1)
        self.assertEqual(len(self.calls), 1)
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM chat_items")
        self.assertEqual(self.call(), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual((self.p.state / "simplex-attempts.json").stat().st_mode & 0o777, 0o600)

    @logged
    def test_intent_crash_without_native_item_blocks_retry_even_before_exec(self):
        with patch.object(self.ctx, "run", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.call()
        with self.assertRaisesRegex(Failure, "ambiguous_no_auto_retry"):
            self.call()
        self.assertEqual(self.calls, [])
        self.insert(self.text())
        self.assertEqual(self.call(), 1)
        self.assertEqual(self.calls, [])

    @logged
    def test_native_record_then_journal_failure_recovers_without_resend(self):
        original = sender.save_journal
        count = 0

        @logged
        def save(ctx, journal):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("synthetic durable receipt failure")
            return original(ctx, journal)

        with patch.object(sender, "save_journal", save):
            with self.assertRaises(OSError):
                self.call()
        self.assertEqual(self.call(), 1)
        self.assertEqual(len(self.calls), 1)

    @logged
    def test_body_profile_and_contact_binding_conflicts_fail_closed(self):
        self.call()
        self.payload["output"] = "changed"
        with self.assertRaisesRegex(Failure, "(binding|existing_item)_conflict"):
            self.call()
        self.payload["output"] = "fixture body"
        with patch.object(sender, "lookup", return_value=("f" * 64, 2, None)):
            with self.assertRaisesRegex(Failure, "(binding|existing_item)_conflict"):
                self.call()
        self.assertEqual(len(self.calls), 1)

    @logged
    def test_existing_matching_native_row_reused_and_conflicting_native_rows_rejected(self):
        self.insert(self.text())
        self.assertEqual(self.call(), 1)
        self.assertEqual(self.calls, [])
        (self.p.state / "simplex-attempts.json").unlink()
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM chat_items")
        for changes in (
            {"item_content": "[]"},
            {"item_content": "{}"},
            {"item_content_tag": "rcvMsgContent"},
            {"msg_content_tag": "image"},
            {"item_deleted": 1},
            {"item_deleted": None},
            {"item_deleted": ""},
            {"item_edited": 1},
            {"fwd_from_tag": "forward"},
            {"group_id": 1},
            {
                "item_content": json.dumps(
                    {"sndMsgContent": {"msgContent": {"type": "text", "text": "different"}}}
                )
            },
        ):
            with sqlite3.connect(self.database) as db:
                db.execute("DELETE FROM chat_items")
            self.insert(self.text(), **changes)
            with self.assertRaisesRegex(Failure, "existing_item_conflict"):
                self.call()
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM chat_items")
        self.insert(self.text())
        self.insert(self.text())
        with self.assertRaisesRegex(Failure, "existing_item_conflict"):
            self.call()
        self.assertEqual(self.calls, [])

    @logged
    def test_active_contact_ambiguity_and_sqlite_deadline(self):
        for sql in (
            "UPDATE users SET active_user=0",
            "INSERT INTO contacts VALUES(3,1,'fixture',0,0)",
        ):
            with sqlite3.connect(self.database) as db:
                db.execute(sql)
            with self.assertRaisesRegex(Failure, "contact_absent_or_ambiguous"):
                self.call()
            with sqlite3.connect(self.database) as db:
                db.execute("UPDATE users SET active_user=1")
                db.execute("DELETE FROM contacts WHERE contact_id=3")
        with sqlite3.connect(self.database) as db:
            db.executemany(
                "INSERT INTO contacts VALUES(3,1,?,0,0)", (("other" + str(i),) for i in range(6000))
            )
        with self.assertRaises(sqlite3.OperationalError):
            sender.lookup(self.cfg, "marker", "text", time.monotonic() - 1)

    @logged
    def test_configuration_privacy_paths_schema_and_values(self):
        config = self.p.etc / "simplex-sender.json"
        original = config.read_bytes()
        data: object
        for data in (
            [],
            {},
            dict(self.cfg, user="bad user"),
            dict(self.cfg, contact="x" * 129),
            dict(self.cfg, database="/fixture.sqlite"),
            dict(self.cfg, lock="relative"),
            dict(self.cfg, binary=1),
        ):
            atomic(config, json.dumps(data))
            with self.assertRaisesRegex(Failure, "config_"):
                sender.configuration(self.ctx)
        atomic(config, original, 0o644)
        with self.assertRaisesRegex(Failure, "config_not_private"):
            sender.configuration(self.ctx)
        config.chmod(0o600)
        self.database.chmod(0o644)
        with self.assertRaisesRegex(Failure, "database_not_private"):
            sender.configuration(self.ctx)
        self.database.chmod(0o600)
        self.binary.chmod(0o777)
        with self.assertRaisesRegex(Failure, "binary_not_trusted"):
            sender.configuration(self.ctx)
        self.binary.unlink()
        self.binary.symlink_to(self.database)
        with self.assertRaisesRegex(Failure, "config_path"):
            sender.configuration(self.ctx)
        self.binary.unlink()
        with self.assertRaisesRegex(Failure, "config_path"):
            sender.configuration(self.ctx)

    @logged
    def test_journal_invalid_rows_capacity_and_no_implicit_reset(self):
        self.assertEqual(sender.load_journal(self.ctx), {})
        good = {"body": "a" * 64, "binding": "b" * 64, "status": "attempted", "item_id": None}
        value: object
        for value in (
            [],
            {"bad": good},
            {self.key(): []},
            {self.key(): {}},
            {self.key(): dict(good, body=1)},
            {self.key(): dict(good, binding="bad")},
            {self.key(): dict(good, status="bad")},
            {self.key(): dict(good, item_id=1)},
            {self.key(): dict(good, status="native-recorded")},
            {self.key(): dict(good, status="native-recorded", item_id=0)},
            {self.key(): dict(good, status="native-recorded", item_id=True)},
            {str(i): good for i in range(2001)},
        ):
            atomic(self.p.state / "simplex-attempts.json", json.dumps(value))
            with self.assertRaisesRegex(Failure, "journal_invalid"):
                self.call()
        atomic(
            self.p.state / "simplex-attempts.json",
            json.dumps({hashlib.sha256(str(i).encode()).hexdigest(): good for i in range(2000)}),
        )
        with self.assertRaisesRegex(Failure, "journal_capacity_operator_review"):
            self.call()
        self.assertEqual(self.calls, [])

    @logged
    def test_profile_lock_custody_contention_and_release_on_error(self):
        lock = Path(self.cfg["lock"])
        lock.write_text("")
        lock.chmod(0o666)
        with self.assertRaisesRegex(Failure, "lock_not_trusted"):
            self.call()
        lock.chmod(0o600)
        with open(lock, "r") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(Failure, "lock_timeout"):
                with sender.profile_lock(lock, time.monotonic() + 0.06):
                    self.fail("locked")
        with sender.profile_lock(lock, time.monotonic() + 1):
            pass
        lock.unlink()
        lock.symlink_to(self.database)
        with self.assertRaises(OSError):
            self.call()

    @logged
    def test_successful_kernel_lock_wait_branch_without_scheduler_race(self):
        with (
            patch.object(sender.fcntl, "flock", side_effect=BlockingIOError()),
            patch.object(
                sender.Context, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")
            ) as wait,
        ):
            with sender.profile_lock(self.cfg["lock"], time.monotonic() + 1) as fd:
                self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
                argv = wait.call_args.args[0]
                self.assertEqual(argv[:3], ["/usr/bin/flock", "--exclusive", "--timeout"])
                self.assertEqual(argv[-1], str(fd))
                self.assertEqual(wait.call_args.kwargs["pass_fds"], (fd,))
                self.assertFalse(wait.call_args.kwargs["check"])

    @logged
    def test_budget_before_intent_preserves_safe_retry_and_root_group_lock_mode(self):
        with (
            patch.object(sender, "lookup", return_value=("a" * 64, 2, None)),
            patch.object(sender.time, "monotonic", side_effect=[0, 30]),
        ):
            with self.assertRaisesRegex(Failure, "budget_before_attempt"):
                self.call()
        self.assertEqual(sender.load_journal(self.ctx), {})
        meta = SimpleNamespace(st_mode=stat.S_IFREG | 0o660, st_uid=os.geteuid(), st_gid=0)
        with patch.object(sender.os, "fstat", return_value=meta):
            with sender.profile_lock(self.cfg["lock"], time.monotonic() + 1):
                pass
        meta.st_gid = 999
        with patch.object(sender.os, "fstat", return_value=meta):
            with self.assertRaisesRegex(Failure, "lock_not_trusted"):
                with sender.profile_lock(self.cfg["lock"], time.monotonic() + 1):
                    self.fail("unsafe group")

    @logged
    def test_event_validation_size_and_changed_run_user(self):
        for event, payload in (
            (None, self.payload),
            ("", self.payload),
            ("x" * 129, self.payload),
            ("id", []),
            ("id", dict(self.payload, source="other")),
            ("id", dict(self.payload, rule=None)),
        ):
            with self.assertRaisesRegex(Failure, "event_schema"):
                sender.handoff(self.ctx, event, payload)
        self.payload["output"] = "x" * 4096
        with self.assertRaisesRegex(Failure, "message_limit"):
            self.call()
        self.payload["output"] = "fixture body"
        original = sender.pwd.getpwnam
        target = original(self.cfg["user"])
        count = 0

        @logged
        def target_user(name):
            nonlocal count
            count += 1
            return (
                target
                if count == 1
                else SimpleNamespace(pw_uid=target.pw_uid + 1, pw_gid=target.pw_gid + 1)
            )

        with patch.object(sender.pwd, "getpwnam", target_user):
            self.call()
        self.assertEqual(self.calls[0][0][0], "/usr/bin/setpriv")

    @logged
    def test_native_child_guard_rejects_wrong_parent_and_kills_on_parent_death(self):
        runtime = core.Context(require_root=False)
        prefix = ["/usr/bin/python3", "-I", "-B", "-c", sender.CHILD_GUARD]
        self.assertEqual(runtime.run([*prefix, str(os.getpid()), "/usr/bin/true"]).returncode, 0)
        self.assertEqual(runtime.run([*prefix, "0", "/usr/bin/true"], check=False).returncode, 71)
        lock = self.p.state / "guard.lock"
        marker = self.p.state / "guard-child"
        child = "import os,sys,time;open(sys.argv[1],'w').write(str(os.getpid()));time.sleep(30)"
        parent = """
import fcntl,os,subprocess,sys,time
fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
subprocess.Popen(['/usr/bin/python3','-I','-B','-c',sys.argv[3],str(os.getpid()),
                  '/usr/bin/python3','-I','-B','-c',sys.argv[4],sys.argv[2]],
                 pass_fds=(fd,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
end=time.monotonic()+3
while not os.path.exists(sys.argv[2]) and time.monotonic()<end:time.sleep(.01)
os.kill(os.getpid(),9)
"""
        result = runtime.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                parent,
                str(lock),
                str(marker),
                sender.CHILD_GUARD,
                child,
            ],
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertTrue(marker.exists())
        pid = int(marker.read_text())
        pidfd = None
        try:
            with contextlib.suppress(ProcessLookupError):
                pidfd = os.pidfd_open(pid)
            end = time.monotonic() + 2
            with open(lock, "r") as stream:
                while True:
                    try:
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= end:
                            self.fail("native orphan retained profile lock")
                        time.sleep(0.01)
        finally:
            if pidfd is not None:
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                os.close(pidfd)

    @logged
    def test_concurrent_handoffs_serialize_to_one_native_attempt(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(lambda _: self.call(), range(2))), [1, 1])
        self.assertEqual(len(self.calls), 1)

    @logged
    def test_operator_pause_defers_without_touching_queue_cursor_journal_or_cli(self):
        self.queued()
        pause = Path(self.cfg["lock"]).with_name("outbound.paused")
        atomic(pause, "")
        before = {
            name: (self.p.state / name).read_bytes()
            for name in ("alerts.jsonl", "alerts-forwarded.json")
        }
        with patch.object(sender, "lookup", side_effect=AssertionError("no native access")):
            tm.forward(self.ctx)
            with self.assertRaises(sender.OutboundPaused):
                self.call()
        self.assertFalse(self.calls)
        self.assertFalse((self.p.state / "simplex-attempts.json").exists())
        self.assertEqual(before, {name: (self.p.state / name).read_bytes() for name in before})
        self.assertIn("state=paused deferred=1", self.output.getvalue())
        self.assertIn("processed=0 errors=0 remaining=1", self.output.getvalue())
        self.assertEqual(pause.read_bytes(), b"")

    @logged
    def test_pause_preserves_ambiguous_attempt_after_release_without_retry(self):
        self.queued()
        self.mode = "reject"
        with self.assertRaisesRegex(Failure, "alert_forward_failed"):
            tm.forward(self.ctx)
        before = (self.p.state / "simplex-attempts.json").read_bytes()
        pause = Path(self.cfg["lock"]).with_name("outbound.paused")
        atomic(pause, "operator hold")
        tm.forward(self.ctx)
        self.assertEqual(before, (self.p.state / "simplex-attempts.json").read_bytes())
        pause.unlink()  # Synthetic fixture release only; no production hold removed.
        with self.assertRaisesRegex(Failure, "alert_forward_failed"):
            tm.forward(self.ctx)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(before, (self.p.state / "simplex-attempts.json").read_bytes())
        self.assertEqual(
            json.loads((self.p.state / "alerts-forwarded.json").read_bytes()), {"sent": []}
        )

    @logged
    def test_unsafe_pause_is_failure_not_successful_defer(self):
        self.queued()
        pause = Path(self.cfg["lock"]).with_name("outbound.paused")
        for shape in ("directory", "link", "dangling", "mode", "owner"):
            with self.subTest(shape=shape):
                if shape == "directory":
                    pause.mkdir()
                elif shape in ("link", "dangling"):
                    pause.symlink_to(self.database if shape == "link" else self.p.state / "absent")
                else:
                    atomic(pause, "", 0o640 if shape == "mode" else 0o600)
                info = pause.lstat()
                metadata = SimpleNamespace(
                    st_mode=info.st_mode,
                    st_uid=os.geteuid() + 1 if shape == "owner" else info.st_uid,
                )
                with patch.object(sender.Path, "lstat", return_value=metadata):
                    with self.assertRaisesRegex(Failure, "simplex_pause_not_private"):
                        sender.require_outbound_enabled(self.cfg)
                with patch.object(
                    sender,
                    "require_outbound_enabled",
                    side_effect=Failure("simplex_pause_not_private"),
                ):
                    with self.assertRaisesRegex(Failure, "alert_forward_failed"):
                        tm.forward(self.ctx)
                pause.rmdir() if shape == "directory" else pause.unlink()
        self.assertFalse(self.calls)
        self.assertNotIn("state=paused", self.output.getvalue())
        self.assertFalse((self.p.state / "simplex-attempts.json").exists())

    @logged
    def test_pause_between_events_keeps_first_receipt_and_defers_rest(self):
        self.queued()
        tm.append(self.ctx, "alerts.jsonl", {"id": "later", "kind": "labelled-local-selftest"})
        pause = Path(self.cfg["lock"]).with_name("outbound.paused")
        native = self.ctx.runner

        @logged
        def accept_then_pause(argv, **kwargs):
            result = native(argv, **kwargs)
            atomic(pause, "")
            return result

        self.ctx.runner = accept_then_pause
        tm.forward(self.ctx)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(
            json.loads((self.p.state / "alerts-forwarded.json").read_bytes()), {"sent": ["event"]}
        )
        self.assertEqual(set(sender.load_journal(self.ctx)), {self.key()})
        self.assertIn("processed=1 errors=0 remaining=1", self.output.getvalue())
        self.assertIn("state=paused deferred=1", self.output.getvalue())

    @logged
    def test_pause_never_hides_an_earlier_native_failure(self):
        self.queued()
        tm.append(self.ctx, "alerts.jsonl", {"id": "later", "kind": "labelled-local-selftest"})
        native = self.ctx.runner
        self.mode = "reject"

        @logged
        def reject_then_pause(argv, **kwargs):
            result = native(argv, **kwargs)
            atomic(Path(self.cfg["lock"]).with_name("outbound.paused"), "")
            return result

        self.ctx.runner = reject_then_pause
        with self.assertRaisesRegex(Failure, "alert_forward_failed:count=1"):
            tm.forward(self.ctx)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(sender.load_journal(self.ctx)[self.key()]["status"], "attempted")
        self.assertIn("state=paused deferred=2", self.output.getvalue())


@logged
def run_suite():
    start = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeSender)
    print(
        f"[1/1] native sender fixture contracts processed=0/{suite.countTestCases()} remaining={suite.countTestCases()}",
        flush=True,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        f"[done] processed={result.testsRun} errors={len(result.errors) + len(result.failures)} remaining=0 elapsed={time.monotonic() - start:.2f}s",
        flush=True,
    )
    if not result.wasSuccessful():
        raise Failure("native_sender_contracts_failed")


if __name__ == "__main__":
    run_suite()
