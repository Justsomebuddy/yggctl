"""Privilege boundary rejection and worker decoding tests; no real broker service."""

import base64
import io
import os
from pathlib import Path
import socket
import struct
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import broker
import sandbox
from core import Context, Failure, logged
from test_support import ConsoleFixture


class BrokerEdges(ConsoleFixture):
    @logged
    def server(self):
        obj = broker.Broker.__new__(broker.Broker)
        obj.ctx, obj.role, obj.uid = self.ctx, "research", 1000
        obj.stop, obj.server = threading.Event(), Mock()
        return obj

    @logged
    def worker(self):
        obj = broker.WorkerContext.__new__(broker.WorkerContext)
        Context.__init__(obj, self.paths, require_root=False)
        obj.conn, obj.reader, obj.call_lock = Mock(), Mock(), threading.Lock()
        return obj

    @logged
    def test_missing_worker_and_directory_custody(self):
        with patch.object(broker.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1000)):
            self.assertEqual(broker.worker_uid(), 1000)
        with (
            patch.object(broker.pwd, "getpwnam", side_effect=KeyError()),
            self.assertRaisesRegex(Failure, "sandbox_worker_user_missing"),
        ):
            broker.worker_uid()
        directory = self.paths.state / "broker"
        directory.mkdir()
        with (
            patch.object(
                Path, "lstat", return_value=SimpleNamespace(st_mode=0, st_uid=os.geteuid())
            ),
            self.assertRaisesRegex(Failure, "broker_directory_untrusted"),
        ):
            broker.Broker(self.ctx, "research", uid=1000, directory=directory)

    @logged
    def test_accept_timeout_foreign_uid_error_and_stop(self):
        obj = self.server()
        wrong, right = Mock(), Mock()
        wrong.getsockopt.return_value = struct.pack("3i", 1, 999, 999)
        right.getsockopt.return_value = struct.pack("3i", 1, 1000, 1000)
        obj.server.accept.side_effect = [socket.timeout(), (wrong, None), (right, None)]
        self.assertIs(obj.accept(), right)
        wrong.close.assert_called_once_with()
        obj.server.accept.side_effect = OSError()
        self.assertIsNone(obj.accept())
        obj.stop.set()
        self.assertIsNone(obj.accept())
        with patch.object(obj, "accept", return_value=None):
            obj.serve()

    @logged
    def test_serve_stops_after_current_reply(self):
        obj = self.server()
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.makefile.return_value = io.BytesIO(b'{"call":"metrics"}\n')
        connection.sendall.side_effect = lambda data: obj.stop.set()
        with patch.object(obj, "accept", return_value=connection):
            obj.serve()
        connection.sendall.assert_called_once_with(b'{"data":null}\n')
        for data in (b"", b"x" * (broker.LINE_LIMIT + 1)):
            obj.stop.clear()
            connection.makefile.return_value = io.BytesIO(data)
            with patch.object(obj, "accept", return_value=connection):
                obj.serve()

    @logged
    def test_handle_bad_json_timeouts_and_metrics(self):
        obj = self.server()
        for payload, error in (
            (b"[]", "broker_bad_request"),
            (b"not json", "broker_bad_request"),
            (b'{"call":"admin","timeout":0}', "broker_bad_timeout"),
            (b'{"call":"admin","timeout":"20"}', "broker_bad_timeout"),
            (b'{"call":"other"}', "broker_call_not_allowed"),
        ):
            self.assertEqual(obj.handle(payload), {"error": error})
        with patch.object(self.ctx, "run", side_effect=OSError()):
            self.assertEqual(
                obj.handle(b'{"call":"admin","method":"getSelf"}'), {"error": "broker_bad_request"}
            )
        obj.role = "remote"
        self.assertEqual(obj.handle(b'{"call":"metrics"}'), {"error": "broker_call_not_allowed"})

    @logged
    def test_worker_request_reply_failure_contracts(self):
        worker = self.worker()
        worker.root()
        with worker.locked():
            self.assertFalse(worker.require_root)
        with (
            patch.object(broker, "LINE_LIMIT", 4),
            self.assertRaisesRegex(Failure, "broker_request_too_large"),
        ):
            worker.call({"long": "request"})
        for reply, label in (
            (b"", "broker_unavailable"),
            (b"x" * (broker.METRICS_REPLY_LIMIT + 1), "broker_unavailable"),
            (b"not json", "broker_invalid_reply"),
            (b"[]", "broker_invalid_reply"),
            (b'{"error":"fixed_failure"}', "fixed_failure"),
        ):
            worker.reader.readline.return_value = reply
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                worker.call({"call": "metrics"})
        worker.reader.readline.return_value = b'{"data":null}'
        self.assertEqual(worker.call({"call": "metrics"}), {"data": None})
        self.assertTrue(worker.conn.sendall.call_args.args[0].endswith(b"\n"))

    @logged
    def test_worker_command_and_payload_validation(self):
        worker = self.worker()
        with patch.object(Context, "run", return_value="fallback") as fallback:
            self.assertEqual(worker.run(["/fake/other"], check=False), "fallback")
            fallback.assert_called_once()
        for argv in (
            [self.paths.ctl],
            [self.paths.ctl, "-json", "-endpoint=unix:///wrong", "getSelf"],
        ):
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                worker.run(argv)
        argv = [self.paths.ctl, "-json", "-endpoint=unix://" + str(self.paths.node_sock), "getSelf"]
        for value, label in (
            ({}, "broker_invalid_reply"),
            ({"rc": "bad", "stdout": "", "stderr": ""}, "broker_invalid_reply"),
            ({"rc": 1, "stdout": "", "stderr": ""}, "external_failed"),
        ):
            with (
                patch.object(worker, "call", return_value=value),
                self.assertRaisesRegex(Failure, label),
            ):
                worker.run(argv)
        with patch.object(worker, "call", return_value={"rc": 7, "stdout": "", "stderr": ""}):
            self.assertEqual(worker.run(argv, check=False).returncode, 7)
        with self.assertRaisesRegex(Failure, "state_not_available"):
            worker.read_state("other", 1)
        for encoded, limit, label in (
            ("non-ascii-é", 8, "broker_invalid_reply"),
            (base64.b64encode(b"xx").decode(), 1, "file_size_limit"),
        ):
            with (
                patch.object(worker, "call", return_value={"data": encoded}),
                self.assertRaisesRegex(Failure, label),
            ):
                worker.read_state("metrics.jsonl", limit)
        with patch.object(worker, "call", return_value={"data": None}):
            self.assertIsNone(worker.read_state("metrics.jsonl", 1))
        with patch.object(worker, "call", return_value={"data": "eA=="}):
            self.assertEqual(worker.read_state("metrics.jsonl", 1), b"x")

    @logged
    def test_worker_context_only_in_unprivileged_unit(self):
        for unit, uid in ((None, 1000), (("research", "01234567"), 0)):
            with (
                patch.object(sandbox, "own_unit", return_value=unit),
                patch.object(sandbox.os, "geteuid", return_value=uid),
            ):
                self.assertIsNone(sandbox.worker_context())
        with (
            patch.object(sandbox, "own_unit", return_value=("research", "01234567")),
            patch.object(sandbox.os, "geteuid", return_value=1000),
            patch.object(broker, "WorkerContext", return_value=self.ctx) as worker,
        ):
            self.assertIs(sandbox.worker_context(), self.ctx)
            worker.assert_called_once_with(broker.BROKER_DIR / "research-01234567.sock")
