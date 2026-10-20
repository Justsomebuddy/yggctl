"""Role isolation and actual Atlas-to-worker-to-broker composition; fully offline."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

import broker
import core
import sandbox
import main
from atlas import acquisition, protocol
from atlas.store import Store
from core import Context, Failure, logged
from test_support import ConsoleFixture

KEY = "ab" * 32
OWN = "cd" * 32


class SandboxRoles(unittest.TestCase):
    @logged
    def setUp(self):
        core.trace_quiet()
        fixture = ConsoleFixture()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        self.ctx, self.paths = fixture.ctx, fixture.paths

    @logged
    def worker(self, role, runner):
        # Short fixture path keeps the real AF_UNIX name below Linux's 108-byte cap.
        directory = tempfile.TemporaryDirectory(prefix="yr-")
        self.addCleanup(directory.cleanup)
        parent = Context(self.paths, runner, require_root=False)
        server = broker.Broker(parent, role, uid=os.getuid(), directory=Path(directory.name))
        self.addCleanup(server.close)
        worker = broker.WorkerContext(server.path, paths=self.paths)
        worker.conn.settimeout(5)
        self.addCleanup(worker.conn.close)
        self.addCleanup(worker.reader.close)
        return worker

    @logged
    def test_consumer_method_lists_match_parent_role_policy(self):
        self.assertLessEqual(
            {m.lower() for m in main.API_VIEWS.values()}, broker.ADMIN_METHODS["research"]
        )
        self.assertLessEqual(
            set(main.REMOTE_DEBUG.values()) | {"getnodeinfo"}, broker.ADMIN_METHODS["remote"]
        )
        self.assertEqual(
            broker.ADMIN_METHODS["atlas"] - broker.LOCAL, frozenset(protocol.METHODS.values())
        )

    @logged
    def test_exact_role_matrix_and_argument_validation(self):
        expected = {
            "research": broker.LOCAL,
            "atlas": broker.LOCAL | frozenset(protocol.METHODS.values()),
            "remote": broker.LOCAL | broker.REMOTE,
        }
        for role in (*expected, "unknown"):
            for name in broker.LOCAL | broker.REMOTE:
                args = [] if name in broker.LOCAL else ["key=" + KEY]
                if name in expected.get(role, ()):
                    self.assertEqual(
                        broker.admin_argv(self.ctx, name.upper(), args, role)[3], name.upper()
                    )
                else:
                    with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                        broker.admin_argv(self.ctx, name, args, role)
        for method, bad_args in (
            (None, []),
            ("getSelf", ["key=" + KEY]),
            ("getnodeinfo", []),
            ("getnodeinfo", ["key=bad"]),
            ("getnodeinfo", ["key=" + KEY, "extra=1"]),
            ("getnodeinfo", [1]),
        ):
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                broker.admin_argv(self.ctx, method, bad_args, "remote")

    @logged
    def test_research_denies_remote_and_worker_cannot_select_role(self):
        runner = Mock(return_value=Mock(returncode=0, stdout=b"{}", stderr=b""))
        worker = self.worker("research", runner)
        for method in broker.REMOTE:
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                worker.call(
                    {"call": "admin", "method": method, "args": ["key=" + KEY], "role": "remote"}
                )
        runner.assert_not_called()
        self.assertEqual(worker.api("getSelf"), {})
        self.assertEqual(runner.call_count, 1)

    @logged
    def test_atlas_crawl_preserves_three_real_broker_remote_reads(self):
        calls = []

        @logged
        def runner(argv, **kwargs):
            method = argv[3]
            calls.append(method)
            if method == "getSelf":
                body: dict[str, object] = {"key": OWN}
            else:
                value = (
                    {"key": KEY, "routing_entries": 1}
                    if method == "debug_remotegetself"
                    else {"keys": []}
                )
                body = {protocol.address(KEY): value}
            return Mock(returncode=0, stdout=json.dumps(body).encode(), stderr=b"")

        worker = self.worker("atlas", runner)
        with Store(worker, True) as store, contextlib.redirect_stdout(io.StringIO()):
            store.sql(
                "INSERT INTO runs VALUES(?,?,?,NULL,?,?)",
                ("fixture", OWN, "2026-10-20T00:00:00+00:00", "checkpoint", "{}"),
            )
            store.meta("current", "fixture")
            store.seed("fixture", [KEY], "fixture")
            result = acquisition.crawl(worker, store, 1)
            self.assertEqual(result["state"], "frontier_exhausted")
            self.assertEqual(result["processed_keys"], 1)
            self.assertEqual(result["methods"], {"ok": 3})
        self.assertEqual(calls, ["getSelf", *protocol.METHODS.values()])
        with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
            worker.call({"call": "admin", "method": "getnodeinfo", "args": ["key=" + KEY]})
        self.assertEqual(len(calls), 4)

    @logged
    def test_every_command_checks_integrity_before_broker_and_worker(self):
        for cmd in sandbox.ROLE_OF:
            steps = []

            @logged
            def integrity(ctx):
                self.assertGreater(ctx.lock_depth, 0)
                steps.append("integrity")

            @logged
            def attached(argv, stop):
                steps.append("worker")
                self.assertEqual(self.ctx.lock_depth > 0, cmd == "research")
                return 0

            @logged
            def open_broker(*args):
                steps.append("broker")
                return contextlib.nullcontext(SimpleNamespace(unit_id="deadbeef"))

            self.ctx.attached = attached
            with (
                patch.object(sandbox.checks, "integrity", side_effect=integrity),
                patch.object(
                    sandbox.checks, "sockets", side_effect=lambda ctx: steps.append("sockets")
                ),
                patch.object(sandbox.broker, "Broker") as server,
            ):
                server.side_effect = open_broker
                self.assertEqual(sandbox.run(self.ctx, cmd, [], self.paths.runtime / "main.py"), 0)
            expected = (
                ["integrity"]
                + (["sockets"] if cmd in ("bench", "socks-test") else [])
                + ["broker", "worker"]
            )
            self.assertEqual(steps, expected, cmd)
            self.assertEqual(self.ctx.lock_depth, 0)

    @logged
    def test_integrity_failure_never_opens_broker_or_starts_worker(self):
        for cmd in sandbox.ROLE_OF:
            with (
                patch.object(sandbox.checks, "integrity", side_effect=Failure("fixture_integrity")),
                patch.object(sandbox.broker, "Broker") as server,
                patch.object(self.ctx, "run_attached") as worker,
                self.assertRaisesRegex(Failure, "fixture_integrity"),
            ):
                sandbox.run(self.ctx, cmd, [], self.paths.runtime / "main.py")
            server.assert_not_called()
            worker.assert_not_called()
            self.assertEqual(self.ctx.lock_depth, 0)
