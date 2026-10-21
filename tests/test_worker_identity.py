"""Kernel-credential/unit binding and separate role principals; no host changes."""

import contextlib
import concurrent.futures
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import broker
import core
import sandbox
from core import Failure, logged
from test_support import ConsoleFixture as Fixture


class WorkerIdentity(unittest.TestCase):
    @logged
    def setUp(self):
        core.trace_quiet()
        f = Fixture()
        f.setUp()
        self.addCleanup(f.tmp.cleanup)
        self.ctx, self.paths = f.ctx, f.paths
        self.group = broker.process_cgroup(os.getpid())

    @logged
    def test_role_users_and_missing_root_accounts_fail_closed(self):
        for role, name in broker.USERS.items():
            with patch.object(
                broker.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=123)
            ) as get:
                self.assertEqual(broker.worker_uid(role), 123)
                get.assert_called_once_with(name)
        for role in ("unknown", "research"):
            with patch.object(broker.pwd, "getpwnam", side_effect=KeyError()):
                with self.assertRaisesRegex(Failure, "sandbox_worker_user_missing"):
                    broker.worker_uid(role)
        for uid in (0, -1):
            with patch.object(broker.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=uid)):
                with self.assertRaisesRegex(Failure, "sandbox_worker_must_be_unprivileged"):
                    broker.worker_uid("atlas")

    @logged
    def test_bounded_kernel_cgroup_v2_parser(self):
        root = self.paths.state / "proc"
        (root / "123").mkdir(parents=True)
        file = root / "123/cgroup"
        file.write_text("1:net_cls:/\n0::/system.slice/unit.service\n")
        self.assertEqual(broker.process_cgroup(123, root), "/system.slice/unit.service")
        for text in ("", "1:cpu:/other\n", "0::/a\n0::/b\n", "0::relative\n"):
            file.write_text(text)
            with self.assertRaisesRegex(Failure, "broker_peer_cgroup_invalid"):
                broker.process_cgroup(123, root)
        for pid in (0, -1, True, "123"):
            with self.assertRaisesRegex(Failure, "broker_peer_pid_invalid"):
                broker.process_cgroup(pid, root)
        file.write_bytes(b"\xff")
        with self.assertRaises(UnicodeError):
            broker.process_cgroup(123, root)
        file.write_bytes(b"0::/" + b"a" * 8192)
        with self.assertRaisesRegex(Failure, "file_size_limit"):
            broker.process_cgroup(123, root)
        with self.assertRaises(OSError):
            broker.process_cgroup(999, root)

    @logged
    def test_peer_binding_uid_group_unavailable_and_malformed_credentials(self):
        obj = broker.Broker.__new__(broker.Broker)
        obj.uid, obj.cgroup = os.getuid(), self.group
        conn = Mock()
        conn.getsockopt.return_value = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
        self.assertTrue(obj.peer_allowed(conn))
        obj.cgroup += "/wrong-instance"
        self.assertFalse(obj.peer_allowed(conn))
        obj.cgroup = self.group
        with patch.object(broker, "process_cgroup", side_effect=OSError()):
            self.assertFalse(obj.peer_allowed(conn))
        with patch.object(broker, "process_cgroup", side_effect=Failure("unavailable")):
            self.assertFalse(obj.peer_allowed(conn))
        conn.getsockopt.return_value = b"bad"
        self.assertFalse(obj.peer_allowed(conn))
        conn.getsockopt.side_effect = OSError()
        self.assertFalse(obj.peer_allowed(conn))
        conn.getsockopt.side_effect = None
        conn.getsockopt.return_value = struct.pack("3i", os.getpid(), os.getuid() + 1, os.getgid())
        with patch.object(broker, "process_cgroup") as group:
            self.assertFalse(obj.peer_allowed(conn))
            group.assert_not_called()

    @logged
    def test_real_same_uid_wrong_unit_rejected_before_serving_then_correct_client(self):
        rejected = threading.Event()
        original = broker.event

        @logged
        def observe(kind, operation, detail=""):
            original(kind, operation, detail)
            if detail == "foreign_peer_rejected":
                rejected.set()

        with (
            tempfile.TemporaryDirectory(prefix="identity-") as directory,
            patch.object(broker, "event", observe),
        ):
            with broker.Broker(
                self.ctx,
                "research",
                os.getuid(),
                Path(directory),
                expected_cgroup=self.group + "/wrong",
            ) as served:
                with socket.socket(socket.AF_UNIX) as wrong:
                    wrong.settimeout(3)
                    wrong.connect(str(served.path))
                    wrong.sendall(b'{"call":"metrics","role":"research"}\n')
                    with contextlib.suppress(ConnectionResetError):
                        self.assertEqual(wrong.recv(4096), b"")
                self.assertTrue(rejected.wait(3))
                served.cgroup = self.group
                worker = broker.WorkerContext(served.path, self.paths)
                self.addCleanup(worker.conn.close)
                self.addCleanup(worker.reader.close)
                self.assertIsNone(worker.read_state("metrics.jsonl", 1024))

    @logged
    def test_default_expected_unit_and_role_properties(self):
        with tempfile.TemporaryDirectory(prefix="identity-") as directory:
            with patch.object(broker, "worker_uid", return_value=os.getuid()) as uid:
                with broker.Broker(self.ctx, "atlas", directory=Path(directory)) as served:
                    self.assertEqual(
                        served.cgroup,
                        f"/system.slice/yggctl-sandbox-atlas-{served.unit_id}.service",
                    )
                uid.assert_called_once_with("atlas")
            with self.assertRaisesRegex(Failure, "sandbox_unknown_role"):
                broker.Broker(self.ctx, "other", uid=os.getuid(), directory=Path(directory))
        self.assertEqual(len(set(broker.USERS.values())), 3)
        for role, name in broker.USERS.items():
            props = sandbox.properties(role)
            for value in ("User=" + name, "Group=" + name, "Delegate=no", "Slice=system.slice"):
                self.assertIn(value, props)

    @logged
    def test_idle_authenticated_connection_is_closed_without_thread_leak(self):
        with tempfile.TemporaryDirectory(prefix="identity-") as directory:
            served = broker.Broker(
                self.ctx, "research", os.getuid(), Path(directory), expected_cgroup=self.group
            )
            worker = broker.WorkerContext(served.path, self.paths)
            self.assertIsNone(worker.read_state("metrics.jsonl", 1024))
            started = time.monotonic()
            served.close()
            self.assertFalse(served.thread.is_alive())
            self.assertLess(time.monotonic() - started, 1)
            worker.reader.close()
            worker.conn.close()
            self.assertFalse(served.path.exists())

    @logged
    def test_migration_barrier_shared_concurrency_exclusive_timeout_and_custody(self):
        with sandbox.launch_guard(self.ctx), sandbox.launch_guard(self.ctx):
            with self.assertRaisesRegex(Failure, "worker_launch_lock_timeout"):
                with sandbox.launch_guard(self.ctx, exclusive=True, timeout=0.03):
                    self.fail("busy")
        with sandbox.launch_guard(self.ctx, exclusive=True):
            with self.assertRaisesRegex(Failure, "worker_launch_lock_timeout"):
                with sandbox.launch_guard(self.ctx, timeout=0.03):
                    self.fail("migration active")
        lock = self.paths.state / ".worker.lock"
        lock.chmod(0o644)
        with self.assertRaisesRegex(Failure, "worker_launch_lock_untrusted"):
            with sandbox.launch_guard(self.ctx):
                self.fail("unsafe")
        lock.unlink()
        lock.symlink_to(self.paths.state / "absent")
        with self.assertRaises(OSError):
            with sandbox.launch_guard(self.ctx):
                self.fail("symlink")

    @logged
    def test_migration_waiter_proceeds_after_last_shared_worker_exits(self):
        waiting = threading.Event()
        original = sandbox.event

        @logged
        def observed(kind, operation, detail=""):
            original(kind, operation, detail)
            if kind == "external_start" and operation == "worker_launch_lock_wait":
                waiting.set()

        @logged
        def migration():
            with sandbox.launch_guard(self.ctx, exclusive=True, timeout=2):
                return "acquired"

        with (
            patch.object(sandbox, "event", observed),
            concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool,
        ):
            with sandbox.launch_guard(self.ctx):
                future = pool.submit(migration)
                self.assertTrue(waiting.wait(2))
                self.assertFalse(future.done())
            self.assertEqual(future.result(timeout=3), "acquired")

    @logged
    def test_read_error_is_logged_and_does_not_escape_broker_thread(self):
        obj = broker.Broker.__new__(broker.Broker)
        obj.stop = threading.Event()
        conn = Mock()
        conn.__enter__ = Mock(return_value=conn)
        conn.__exit__ = Mock(return_value=False)
        conn.makefile.side_effect = OSError()
        with patch.object(obj, "accept", return_value=conn):
            obj.serve()
        self.assertIs(obj.conn, conn)


@logged
def run_suite():
    core.trace_quiet()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(WorkerIdentity)
    start = time.monotonic()
    print(
        f"[1/1] worker identity contracts processed=0/{suite.countTestCases()} remaining={suite.countTestCases()}",
        flush=True,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        f"[done] processed={result.testsRun} errors={len(result.errors) + len(result.failures)} remaining=0 elapsed={time.monotonic() - start:.2f}s",
        flush=True,
    )
    if not result.wasSuccessful():
        raise Failure("worker_identity_contracts_failed")


if __name__ == "__main__":
    run_suite()
