"""Role scoping for the broker allowlist and the per-role integrity check; no live service."""

import contextlib
from types import SimpleNamespace
from unittest.mock import patch

import broker
import sandbox
from core import Context, Failure, logged
from test_support import ConsoleFixture

PIN = "ab" * 32
LOCAL_ONLY = ("research",)


def result(returncode=0, stdout=b"{}", stderr=b""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class SandboxRoles(ConsoleFixture):
    @logged
    def test_admin_methods_are_allowlisted_per_role(self):
        ctx = Context(self.paths, self.ctx.runner, require_root=False)
        for role in ("research", "atlas", "remote"):
            for method in sorted(broker.LOCAL):
                self.assertEqual(broker.admin_argv(ctx, method, [], role)[3], method)
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                broker.admin_argv(ctx, method, ["key=" + PIN], role)
        for method in sorted(broker.REMOTE):
            with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
                broker.admin_argv(ctx, method, ["key=" + PIN], "research")
            for role in ("atlas", "remote"):
                self.assertEqual(
                    broker.admin_argv(ctx, method, ["key=" + PIN], role)[3],
                    method,
                )
        with self.assertRaisesRegex(Failure, "broker_call_not_allowed"):
            broker.admin_argv(ctx, "getSelf", [], "unknown-role")

    @logged
    def test_handle_denies_remote_methods_for_research_only(self):
        calls = []

        def runner(argv, **kw):
            calls.append(list(argv))
            return result()

        def handle(role, method):
            ctx = Context(self.paths, runner, require_root=False)
            obj = broker.Broker.__new__(broker.Broker)
            obj.ctx, obj.role, obj.uid = ctx, role, 1000
            return broker.Broker.handle(
                obj, '{"call":"admin","method":"' + method + '","args":["key=' + PIN + '"]}'
            )

        self.assertIn("error", handle("research", "debug_remotegetself"))
        self.assertEqual(handle("atlas", "debug_remotegetpeers")["rc"], 0)
        self.assertEqual(handle("remote", "debug_remotegetself")["rc"], 0)
        self.assertEqual([c[3] for c in calls], ["debug_remotegetpeers", "debug_remotegetself"])

    @logged
    def test_integrity_runs_for_every_sandboxed_role(self):
        seen = {"integrity": 0, "sockets": 0}

        class FakeBroker:
            def __init__(self, ctx, role, *a, **k):
                self.unit_id = "deadbeef"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def count(name):
            def inner(ctx):
                seen[name] += 1
                return 0

            return inner

        ctx = SimpleNamespace(
            p=self.paths,
            root=lambda: None,
            locked=lambda: contextlib.nullcontext(),
            run_attached=lambda argv, stop: 0,
        )
        main_path = self.paths.state / "main.py"
        with (
            patch.object(sandbox.checks, "integrity", count("integrity")),
            patch.object(sandbox.checks, "sockets", count("sockets")),
            patch.object(sandbox.broker, "Broker", FakeBroker),
        ):
            for cmd in ("ping", "atlas", "research", "bench"):
                before = dict(seen)
                sandbox.run(ctx, cmd, [], main_path)
                self.assertEqual(seen["integrity"], before["integrity"] + 1, cmd)
                expected_sockets = 1 if cmd == "bench" else 0
                self.assertEqual(seen["sockets"], before["sockets"] + expected_sockets, cmd)
