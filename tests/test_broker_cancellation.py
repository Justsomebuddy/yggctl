"""Real local child and broker cancellation; no node or external service."""

import contextlib
from dataclasses import replace
import os
from pathlib import Path
import signal
import subprocess  # nosec B404 # Synthetic local child only.
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest.mock import Mock, patch

import broker
import core
from core import Context, Failure, Paths, logged


@logged
def wait_for_marker(path, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return int(path.read_text())
        except (FileNotFoundError, ValueError):
            # The child may have created the marker but not written its PID yet.
            pass
        time.sleep(0.01)
    raise AssertionError("synthetic child did not start")


@logged
def kill_owned_child(pidfd):
    with contextlib.suppress(ProcessLookupError):
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)


class ProcessCancellation(unittest.TestCase):
    @logged
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yc-")
        self.addCleanup(self.tmp.cleanup)
        self.marker = Path(self.tmp.name) / "started"

    @logged
    def child_argv(self, close_pipes):
        source = (
            "import os,pathlib,time;"
            + ("os.close(1);os.close(2);" if close_pipes else "")
            + f"pathlib.Path({str(self.marker)!r}).write_text(str(os.getpid()));"
            + "time.sleep(8)"
        )
        return [sys.executable, "-I", "-c", source]

    @logged
    def test_precancel_does_not_spawn_and_context_forwarding_is_opt_in(self):
        cancel = threading.Event()
        cancel.set()
        with (
            patch.object(core.subprocess, "Popen") as popen,
            self.assertRaisesRegex(Failure, "external_cancelled"),
        ):
            core.bounded_process(self.child_argv(False), cancel=cancel)
        popen.assert_not_called()

        runner = Mock(return_value=subprocess.CompletedProcess(["fixture"], 0, b"ok", b""))
        ctx = Context(runner=runner, require_root=False)
        self.assertEqual(ctx.run(["/fake/fixture"]).stdout, b"ok")
        self.assertNotIn("cancel", runner.call_args.kwargs)
        self.assertEqual(ctx.run(["/fake/fixture"], cancel=cancel).stdout, b"ok")
        self.assertIs(runner.call_args.kwargs["cancel"], cancel)

    @logged
    def test_cancel_kills_and_reaps_child_with_open_or_closed_pipes(self):
        for close_pipes in (False, True):
            with self.subTest(close_pipes=close_pipes):
                self.marker.unlink(missing_ok=True)
                cancel = threading.Event()
                result = {}

                @logged
                def run_child():
                    try:
                        core.bounded_process(self.child_argv(close_pipes), timeout=6, cancel=cancel)
                    except BaseException as exc:
                        result["error"] = exc

                thread = threading.Thread(target=run_child, daemon=True)
                thread.start()
                pid = wait_for_marker(self.marker)
                pidfd = os.pidfd_open(pid)
                try:
                    cancel.set()
                    thread.join(timeout=3)
                    self.assertFalse(thread.is_alive(), "cancelled child remained in wait")
                    self.assertIsInstance(result.get("error"), Failure)
                    self.assertEqual(str(result["error"]), "external_cancelled")
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                finally:
                    kill_owned_child(pidfd)
                    os.close(pidfd)
                    thread.join(timeout=3)

    @logged
    def test_closed_pipes_still_obey_timeout(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            core.bounded_process(self.child_argv(True), timeout=0.25)
        self.assertLess(time.monotonic() - started, 3)
        pid = wait_for_marker(self.marker)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


class BrokerCancellation(unittest.TestCase):
    @logged
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yc-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.marker = self.root / "admin-started"
        script = self.root / "synthetic-ctl"
        script.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, sys, time\n"
            "method = sys.argv[3]\n"
            "if method == 'getSelf':\n"
            "    os.close(1); os.close(2)\n"
            f"    pathlib.Path({str(self.marker)!r}).write_text(str(os.getpid()))\n"
            "    time.sleep(8)\n"
            "elif method == 'getPeers':\n"
            "    print('peer-ok')\n"
            "elif method == 'getPaths':\n"
            "    print('synthetic-error', file=sys.stderr)\n"
            "    sys.exit(7)\n"
            "elif method == 'getTree':\n"
            "    time.sleep(8)\n"
            "elif method == 'getSessions':\n"
            f"    marker = pathlib.Path({str(self.root / 'second-started')!r})\n"
            "    marker.write_text(str(os.getpid()))\n"
            f"    release = pathlib.Path({str(self.root / 'release-second')!r})\n"
            "    while not release.exists(): time.sleep(.01)\n"
            "    print('sessions-ok')\n"
        )
        script.chmod(0o700)
        self.paths = replace(
            Paths(), ctl=str(script), node_sock=self.root / "admin.sock", state=self.root
        )
        self.ctx = Context(self.paths, require_root=False)
        self.directory = self.root / "broker"
        self.cgroup = broker.process_cgroup(os.getpid())

    @logged
    def serve(self):
        server = broker.Broker(
            self.ctx,
            "research",
            uid=os.getuid(),
            directory=self.directory,
            expected_cgroup=self.cgroup,
        )
        self.addCleanup(server.close)
        worker = broker.WorkerContext(server.path, paths=self.paths)
        worker.conn.settimeout(5)
        self.addCleanup(worker.conn.close)
        self.addCleanup(worker.reader.close)
        return server, worker

    @logged
    def argv(self, method):
        return [
            self.paths.ctl,
            "-json",
            f"-endpoint=unix://{self.paths.node_sock}",
            method,
        ]

    @logged
    def test_close_reaps_active_admin_and_keeps_peer_broker_operational(self):
        first, first_worker = self.serve()
        second, second_worker = self.serve()
        self.assertEqual(second_worker.run(self.argv("getPeers")).stdout, b"peer-ok\n")
        result = {}

        @logged
        def active_request():
            try:
                result["reply"] = first_worker.run(self.argv("getSelf"), timeout=6)
            except (Failure, OSError) as exc:
                result["error"] = exc

        request = threading.Thread(target=active_request, daemon=True)
        request.start()
        pid = wait_for_marker(self.marker)
        pidfd = os.pidfd_open(pid)
        try:
            started = time.monotonic()
            first.close()
            self.assertLess(time.monotonic() - started, 3)
            self.assertFalse(first.thread.is_alive())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            request.join(timeout=3)
            self.assertFalse(request.is_alive())
            self.assertNotIn("reply", result)
            self.assertIsInstance(result.get("error"), (Failure, OSError))
            self.assertEqual(second_worker.run(self.argv("getPeers")).stdout, b"peer-ok\n")
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                second_worker.run(self.argv("addPeer"))
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                second_worker.run(self.argv("debug_remotegetself"))
            first.close()
            self.assertFalse(first.path.exists())
            self.assertTrue(second.thread.is_alive())
        finally:
            kill_owned_child(pidfd)
            os.close(pidfd)
            request.join(timeout=3)

    @logged
    def test_stop_before_child_spawn_refuses_the_pending_request(self):
        entered, release = threading.Event(), threading.Event()

        @logged
        def gated_runner(argv, **kwargs):
            entered.set()
            if not release.wait(4):
                raise AssertionError("synthetic runner gate timed out")
            return core.bounded_process(argv, **kwargs)

        self.ctx.runner = gated_runner
        server, worker = self.serve()
        result = {}

        @logged
        def pending_request():
            try:
                worker.run(self.argv("getSelf"), timeout=6)
            except (Failure, OSError) as exc:
                result["error"] = exc

        request = threading.Thread(target=pending_request, daemon=True)
        request.start()
        self.assertTrue(entered.wait(3), "broker never reached runner")
        closing = threading.Thread(target=server.close, daemon=True)
        closing.start()
        try:
            self.assertTrue(server.stop.wait(3), "close did not signal cancellation")
            with patch.object(core.subprocess, "Popen") as popen:
                release.set()
                closing.join(timeout=3)
                self.assertFalse(closing.is_alive())
                popen.assert_not_called()
            request.join(timeout=3)
            self.assertFalse(request.is_alive())
            self.assertIsInstance(result.get("error"), (Failure, OSError))
            self.assertFalse(server.thread.is_alive())
        finally:
            release.set()
            closing.join(timeout=5)
            request.join(timeout=3)

    @logged
    def test_two_active_reads_cancel_only_the_closing_broker(self):
        first, first_worker = self.serve()
        second, second_worker = self.serve()
        cancelled: dict[str, Any] = {}
        completed: dict[str, Any] = {}

        @logged
        def request(worker, method, result):
            try:
                result["reply"] = worker.run(self.argv(method), timeout=6)
            except (Failure, OSError) as exc:
                result["error"] = exc

        threads = [
            threading.Thread(
                target=request, args=(first_worker, "getSelf", cancelled), daemon=True
            ),
            threading.Thread(
                target=request, args=(second_worker, "getSessions", completed), daemon=True
            ),
        ]
        pids, handles = [], []
        try:
            for thread, marker in zip(threads, (self.marker, self.root / "second-started")):
                thread.start()
                pid = wait_for_marker(marker)
                pids.append(pid)
                handles.append(os.pidfd_open(pid))
            first.close()
            threads[0].join(timeout=3)
            self.assertFalse(threads[0].is_alive())
            self.assertIsInstance(cancelled.get("error"), (Failure, OSError))
            with self.assertRaises(ProcessLookupError):
                os.kill(pids[0], 0)
            self.assertTrue(threads[1].is_alive())
            os.kill(pids[1], 0)
            self.assertFalse(second.stop.is_set())
            (self.root / "release-second").touch()
            threads[1].join(timeout=3)
            self.assertFalse(threads[1].is_alive())
            self.assertNotIn("error", completed)
            self.assertEqual(completed["reply"].stdout, b"sessions-ok\n")
            with self.assertRaises(ProcessLookupError):
                os.kill(pids[1], 0)
        finally:
            for handle in handles:
                kill_owned_child(handle)
                os.close(handle)
            for thread in threads:
                if thread.ident is not None:
                    thread.join(timeout=3)

    @logged
    def test_close_immediately_after_start_is_idempotent(self):
        for _ in range(3):
            server, _worker = self.serve()
            server.close()
            server.close()
            self.assertFalse(server.thread.is_alive())
            self.assertFalse(server.path.exists())

    @logged
    def test_normal_nonzero_and_timeout_paths(self):
        server, worker = self.serve()
        self.assertEqual(worker.run(self.argv("getPeers")).stdout, b"peer-ok\n")
        failed = worker.run(self.argv("getPaths"), check=False)
        self.assertEqual((failed.returncode, failed.stderr), (7, b"synthetic-error\n"))
        with self.assertRaisesRegex(Failure, "external_failed"):
            worker.run(self.argv("getPaths"))
        with self.assertRaisesRegex(Failure, "external_unavailable"):
            worker.run(self.argv("getTree"), timeout=1)
        self.assertTrue(server.thread.is_alive())
        self.assertEqual(worker.run(self.argv("getPeers")).stdout, b"peer-ok\n")
