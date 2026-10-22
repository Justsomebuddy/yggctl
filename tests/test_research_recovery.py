"""Research restart contracts: real owned processes/files, synthetic admin responses."""

import contextlib
import io
import json
import os
from pathlib import Path
import select
import signal
import sys
import time
from unittest.mock import patch

import core
import broker
import main as cli
import research
from core import Context, Failure, atomic, logged
from test_support import ConsoleFixture


class ResearchRecovery(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.responses.update(
            getSelf={"key": "a" * 64, "routing_entries": 0},
            getPeers={"peers": []},
            getTree={"tree": []},
            getPaths={"paths": []},
        )
        self.commands = []
        self.children = set()
        self.addCleanup(self.clean_children)

    @logged
    def clean_children(self):
        for pid in self.children:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)

    @logged
    def fresh(self):
        return Context(self.paths, runner=self.runner, require_root=False)

    @logged
    def test_store_lock_traces_actual_context_lifetime(self):
        root = research.folder(self.ctx, create=True)
        with patch.object(research, "event") as events:
            manager = research.store_locked(root)
            events.assert_not_called()  # Constructing a generator acquires nothing.
            with manager:
                trace = [call.args for call in events.call_args_list]
                self.assertEqual(trace[0], ("entry", "store_locked"))
                self.assertIn(("state", "research_store_lock", "acquired"), trace)
                self.assertNotIn(("exit", "store_locked", "success"), trace)
            trace = [call.args for call in events.call_args_list]
            self.assertEqual(trace[-1], ("exit", "store_locked", "success"))
            self.assertIn(("state", "research_store_lock", "closed"), trace)
            for operation in ("open", "flock", "close"):
                self.assertIn(("external_start", "research_store_" + operation), trace)
                self.assertIn(("external_exit", "research_store_" + operation, "success"), trace)

    @logged
    def test_store_lock_body_failure_releases_lock_and_logs_only_type(self):
        root = research.folder(self.ctx, create=True)
        for error in (Failure("private body text"), KeyboardInterrupt("private body text")):
            with (
                patch.object(research, "event") as events,
                self.assertRaises(type(error)),
                research.store_locked(root),
            ):
                raise error
            trace = [call.args for call in events.call_args_list]
            self.assertEqual(trace[-1], ("error", "store_locked", type(error).__name__))
            self.assertIn(("state", "research_store_lock", "closed"), trace)
            self.assertNotIn(("exit", "store_locked", "success"), trace)
            self.assertNotIn("private body text", str(trace))
            self.assertNotIn(str(root), str(trace))
            with research.store_locked(root):
                pass  # The real descriptor/lock must have been released.

    @logged
    def test_store_lock_external_failures_are_visible_and_release_descriptor(self):
        root = research.folder(self.ctx, create=True)
        for operation, error in (
            ("open", OSError("private open text")),
            ("flock", OSError("private lock text")),
            ("flock", BlockingIOError("private busy text")),
            ("close", OSError("private close text")),
        ):
            target = research.fcntl if operation == "flock" else research.os
            original = getattr(target, operation)

            @logged
            def fail(*args, **kwargs):
                if operation == "close":
                    original(*args, **kwargs)  # Do not leak this fixture's real fd.
                raise error

            expected = Failure if isinstance(error, BlockingIOError) else OSError
            with (
                self.subTest(operation=operation, error=type(error).__name__),
                patch.object(research, "event") as events,
                patch.object(target, operation, side_effect=fail),
                self.assertRaises(expected),
                research.store_locked(root),
            ):
                self.fail("failed external operation must not enter context body")
            trace = [call.args for call in events.call_args_list]
            self.assertEqual(trace[-1], ("error", "store_locked", expected.__name__))
            self.assertIn(
                ("external_error", "research_store_" + operation, type(error).__name__), trace
            )
            self.assertNotIn("private", str(trace))
            if operation == "flock":
                self.assertIn(("state", "research_store_lock", "closed"), trace)
            if isinstance(error, BlockingIOError):
                self.assertIn(("state", "research_store_lock", "busy"), trace)
            with research.store_locked(root):
                pass

    @logged
    def wait(self, pid):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            found, status = os.waitpid(pid, os.WNOHANG)
            if found:
                self.children.discard(pid)
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.01)
        self.fail("owned child did not finish")

    @logged
    def invoke(self, command):
        # Call the production CLI parser/dispatcher in a separate process.
        # Only its Context and external node/OS responses come from the fixture.
        output = self.paths.state / "owned-command-output.txt"
        pid = os.fork()
        if pid == 0:
            with (
                output.open("w") as stream,
                contextlib.redirect_stdout(stream),
                contextlib.redirect_stderr(stream),
                patch.object(cli, "Context", return_value=self.fresh()),
                patch.object(cli.sandbox, "worker_context", return_value=None),
                patch.object(sys, "argv", ["yggctl", "research", command]),
            ):
                rc = cli.main()
            os._exit(rc)
        self.children.add(pid)
        rc = self.wait(pid)
        text = output.read_text()
        self.commands.append(
            {
                "command": command,
                "exit": rc,
                "orphan_error": "research_unrecognized_store_entry" in text,
            }
        )
        return rc

    @logged
    def crash(self, suffix=".json"):
        ready, notify = os.pipe()
        original = os.replace
        root = self.paths.state / "research"
        pid = os.fork()
        if pid == 0:
            os.close(ready)

            @logged
            def replacement(src, dst):
                if Path(dst).parent == root and Path(dst).suffix == suffix:
                    os.write(notify, b"x")
                    signal.pause()
                    os._exit(91)
                return original(src, dst)

            with patch.object(core.os, "replace", replacement):
                if suffix == ".md":
                    research.report(self.fresh())
                else:
                    research.capture(self.fresh())
            os._exit(92)
        self.children.add(pid)
        os.close(notify)
        try:
            self.assertTrue(select.select([ready], [], [], 5)[0])
            self.assertEqual(os.read(ready, 1), b"x")
            os.kill(pid, signal.SIGKILL)
            self.assertEqual(self.wait(pid), -signal.SIGKILL)
        finally:
            os.close(ready)
        self.assertEqual(len(list(root.glob(".yggctl-*"))), 1)

    @logged
    def evidence(self, label):
        root = self.paths.state / "research"
        print(
            "MATRIX "
            + json.dumps(
                {
                    "case": label,
                    "commands": self.commands,
                    "snapshots": len(list(root.glob("snapshot-*.json"))),
                    "report_json": len(list(root.glob("report-*.json"))),
                    "report_md": len(list(root.glob("report-*.md"))),
                    "temporary": len(list(root.glob(".yggctl-*"))),
                }
            ),
            file=sys.stderr,
        )

    @logged
    def test_manual_commands_recover_after_sigkill(self):
        self.assertEqual(self.invoke("capture"), 0)
        self.assertEqual(self.invoke("capture"), 0)
        root = self.paths.state / "research"
        saved = {p.name: p.read_bytes() for p in root.glob("snapshot-*.json")}
        self.crash()
        statuses = [self.invoke(cmd) for cmd in ("capture", "map", "diff", "report")]
        self.evidence("manual")
        self.assertEqual(statuses, [0, 0, 0, 0])
        for name, data in saved.items():
            self.assertEqual((root / name).read_bytes(), data)
        self.assertEqual(len(list(root.glob("snapshot-*.json"))), 3)
        self.assertEqual(list(root.glob(".yggctl-*")), [])

    @logged
    def scheduled(self, stop_on_capture_failure):
        self.assertEqual(self.invoke("capture"), 0)
        self.assertEqual(self.invoke("report"), 0)
        self.crash()
        ticks = []
        for _ in range(3):
            capture = self.invoke("capture")
            report = None if capture and stop_on_capture_failure else self.invoke("report")
            ticks.append([capture, report])
        self.evidence("scheduled-stop" if stop_on_capture_failure else "scheduled-continue")
        self.assertEqual(ticks, [[0, 0]] * 3)
        self.assertEqual(len(list((self.paths.state / "research").glob("snapshot-*.json"))), 4)

    @logged
    def test_repeated_schedule_independent_report(self):
        self.scheduled(False)

    @logged
    def test_repeated_schedule_report_requires_successful_capture(self):
        self.scheduled(True)

    @logged
    def test_explicit_operator_cleanup_restores_commands(self):
        research.capture(self.ctx)
        research.capture(self.ctx)
        self.crash()
        # Only remove the one file produced by this owned crash fixture.
        root = self.paths.state / "research"
        temporary = list(root.glob(".yggctl-*"))
        self.assertEqual(len(temporary), 1)
        temporary[0].unlink()
        for command in ("capture", "map", "diff", "report"):
            self.assertEqual(self.invoke(command), 0)

    @logged
    def test_repeated_crashes_do_not_accumulate_temporaries(self):
        research.capture(self.ctx)
        for _ in range(3):
            self.crash()
            self.assertEqual(self.invoke("capture"), 0)
            self.assertEqual(list((self.paths.state / "research").glob(".yggctl-*")), [])
        self.assertEqual(len(research.snapshots(self.fresh())), 4)

    @logged
    def test_report_interruption_keeps_completed_json_and_recovers(self):
        research.capture(self.ctx)
        self.crash(".md")
        root = self.paths.state / "research"
        saved = {p.name: p.read_bytes() for p in root.glob("report-*.json")}
        self.assertEqual(len(saved), 1)
        self.assertEqual(self.invoke("report"), 0)
        for name, data in saved.items():
            self.assertEqual((root / name).read_bytes(), data)
        self.assertEqual(len(list(root.glob("report-*.md"))), 1)

    @logged
    def test_valid_empty_and_partial_temporaries_are_removed_without_promotion(self):
        root = research.folder(self.ctx, create=True)
        for name, data in ((".yggctl-abcdefgh", b""), (".yggctl-1234_abz", b'{"unfinished":')):
            atomic(root / name, data)
        self.assertEqual(research.snapshot_files(self.ctx), [])
        self.assertEqual(list(root.iterdir()), [])

    @logged
    def test_unknown_entry_prevents_cleanup_of_other_temporaries(self):
        root = research.folder(self.ctx, create=True)
        temp = root / ".yggctl-abcdefgh"
        atomic(temp, "owned unfinished")
        for name in ("unrelated.txt", ".yggctl-short", ".yggctl-ABCDEFGH", ".yggctl-abcdefghi"):
            path = root / name
            atomic(path, "must remain")
            with self.assertRaisesRegex(Failure, "unrecognized_store_entry"):
                research.snapshot_files(self.ctx)
            self.assertEqual(temp.read_text(), "owned unfinished")
            self.assertEqual(path.read_text(), "must remain")
            path.unlink()

    @logged
    def test_unsafe_temporary_candidates_are_preserved(self):
        root = research.folder(self.ctx, create=True)
        temp = root / ".yggctl-abcdefgh"
        target = self.paths.state / "owned-outside-research"
        atomic(target, "must remain")
        for kind in ("symlink", "directory", "mode", "hardlink", "owner"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    temp.symlink_to(target)
                elif kind == "directory":
                    temp.mkdir()
                elif kind == "hardlink":
                    os.link(target, temp)
                else:
                    atomic(temp, "candidate", 0o644 if kind == "mode" else 0o600)
                with contextlib.ExitStack() as stack:
                    if kind == "owner":
                        stack.enter_context(
                            patch.object(os, "geteuid", return_value=os.geteuid() + 1)
                        )
                    with self.assertRaisesRegex(
                        Failure, "unsafe_temporary|unrecognized_store_entry"
                    ):
                        research.snapshot_files(self.ctx)
                self.assertTrue(temp.exists())
                self.assertEqual(target.read_text(), "must remain")
                if kind == "directory":
                    temp.rmdir()
                else:
                    temp.unlink()

    @logged
    def test_cleanup_failure_is_explicit_and_next_attempt_recovers(self):
        root = research.folder(self.ctx, create=True)
        temp = root / ".yggctl-abcdefgh"
        atomic(temp, "candidate")
        with (
            patch.object(Path, "unlink", side_effect=PermissionError("owned fixture")),
            self.assertRaises(PermissionError),
        ):
            research.snapshot_files(self.ctx)
        self.assertTrue(temp.exists())
        self.assertEqual(research.snapshot_files(self.ctx), [])
        self.assertFalse(temp.exists())

    @logged
    def test_scanner_waits_for_active_writer_instead_of_removing_its_temp(self):
        research.capture(self.ctx)
        ready, notify = os.pipe()
        release, go = os.pipe()
        original = os.replace
        pid = os.fork()
        if pid == 0:

            @logged
            def replacement(src, dst):
                if Path(dst).parent == self.paths.state / "research":
                    os.write(notify, b"x")
                    if os.read(release, 1) != b"x":
                        os._exit(93)
                return original(src, dst)

            with patch.object(core.os, "replace", replacement):
                research.capture(self.fresh())
            os._exit(0)
        self.children.add(pid)
        self.assertTrue(select.select([ready], [], [], 5)[0])
        self.assertEqual(os.read(ready, 1), b"x")
        started, start = os.pipe()
        finished, finish = os.pipe()
        reader = os.fork()
        if reader == 0:
            os.write(start, b"x")
            try:
                research.snapshot_files(self.fresh())
            except Failure:
                os.write(finish, b"e")
                os._exit(1)
            os.write(finish, b"x")
            os._exit(0)
        self.children.add(reader)
        try:
            self.assertTrue(select.select([started], [], [], 5)[0])
            self.assertEqual(os.read(started, 1), b"x")
            blocked = not select.select([finished], [], [], 0.15)[0]
        finally:
            os.write(go, b"x")
            writer_rc, reader_rc = self.wait(pid), self.wait(reader)
            for fd in (ready, notify, release, go, started, start, finished, finish):
                os.close(fd)
        self.assertTrue(blocked)
        self.assertEqual((writer_rc, reader_rc), (0, 0))
        self.assertEqual(len(research.snapshots(self.fresh())), 2)

    @logged
    def test_surviving_worker_temp_is_not_removed_without_parent_console_lock(self):
        research.capture(self.ctx)
        ready, notify = os.pipe()
        release, go = os.pipe()
        original = os.replace
        root = self.paths.state / "research"
        pid = os.fork()
        if pid == 0:
            # The real worker's lock is a no-op. Model the state after its
            # parent died; external admin calls still use synthetic responses.
            ctx = self.fresh()
            ctx.locked = broker.WorkerContext.locked.__get__(ctx)

            @logged
            def replacement(src, dst):
                if Path(dst).parent == root:
                    os.write(notify, b"x")
                    if os.read(release, 1) != b"x":
                        os._exit(93)
                return original(src, dst)

            try:
                with patch.object(core.os, "replace", replacement):
                    research.capture(ctx)
            except OSError:
                os._exit(1)
            os._exit(0)
        self.children.add(pid)
        try:
            self.assertTrue(select.select([ready], [], [], 5)[0])
            self.assertEqual(os.read(ready, 1), b"x")
            with self.assertRaisesRegex(Failure, "research_store_busy"):
                research.snapshot_files(self.fresh())
            self.assertEqual(len(list(root.glob(".yggctl-*"))), 1)
        finally:
            os.write(go, b"x")
            writer_rc = self.wait(pid)
            for fd in (ready, notify, release, go):
                os.close(fd)
        self.assertEqual(writer_rc, 0)
        self.assertEqual(len(research.snapshots(self.fresh())), 2)
