"""Offline collector, shared-principal and bounded archive contracts."""

import contextlib
import datetime as dt
import gzip
import io
import os
from pathlib import Path
import socket

# Fixed Python child inside the network-isolated test runner, never a shell.
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import broker
import core
import recovery as rc
import sandbox
import telemetry as tm
from core import Failure, atomic, logged
from test_support import ConsoleFixture as Fixture, URI


class ObservationBudget(unittest.TestCase):
    @logged
    def setUp(self):
        core.trace_quiet()
        fixture = Fixture()
        fixture.setUp()
        self.addCleanup(fixture.tmp.cleanup)
        self.fixture = fixture
        self.ctx, self.paths = fixture.ctx, fixture.paths
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.zero = dt.datetime(2026, 10, 20, 10, tzinfo=dt.timezone.utc)
        self.ps = [
            dict(fixture.ps[0], up=False),
            dict(fixture.ps[0], remote=URI.replace(".1:", ".2:")),
        ]
        fixture.ps = self.ps
        atomic(self.paths.state / "notify.state", "on\n")

    @logged
    def collect_at(self, minute, error=None, stack_only=False):
        original = self.fixture.runner

        @logged
        def faulty(argv, **kwargs):
            is_stack = "-endpoint=unix://" + str(self.paths.stack_sock) in argv
            if (
                error
                and argv[0] == self.paths.ctl
                and argv[3] == "getPeers"
                and is_stack == stack_only
            ):
                if error == "json":
                    return subprocess.CompletedProcess(argv, 0, b"{", b"")
                raise error
            return original(argv, **kwargs)

        at = (self.zero + dt.timedelta(minutes=minute)).isoformat()
        with (
            patch.object(tm, "timestamp", return_value=at),
            patch.object(self.ctx, "runner", faulty),
        ):
            try:
                return tm.collect(self.ctx)
            except Failure as exc:
                self.assertEqual(str(exc), "sample_recorded_with_unknown_or_degraded_health")
                return tm.rows(self.ctx)[-1]

    @logged
    def peer_events(self):
        return [a for a in tm.rows(self.ctx, "alerts.jsonl") if a["kind"] in tm.PEER_ALERT_KINDS]

    @logged
    def test_unknown_preserves_episode_then_restarts_unconfirmed_duration(self):
        self.collect_at(0)
        before = tm.load_peer_state(self.ctx)
        sample = self.collect_at(9, subprocess.TimeoutExpired("fixture", 1))
        state = tm.load_peer_state(self.ctx)
        self.assertFalse(sample["peers_observed"])
        self.assertTrue(sample["errors"])
        self.assertEqual(state["down"], before["down"])
        self.assertTrue(state["observation_gap"])
        self.collect_at(11)
        self.assertEqual(self.peer_events(), [])
        self.assertEqual(
            tm.load_peer_state(self.ctx)["down"][URI]["since"],
            (self.zero + dt.timedelta(minutes=11)).isoformat(),
        )
        self.collect_at(21)
        self.assertEqual([a["kind"] for a in self.peer_events()], ["ygg-peer-down"])
        self.assertEqual(self.peer_events()[0]["minutes"], 10)

    @logged
    def test_alerted_episode_survives_gap_without_duplicate_and_recovery_is_uncertain(self):
        self.collect_at(0)
        self.collect_at(11)
        first = self.peer_events()[0]
        self.collect_at(12, ConnectionResetError())
        self.collect_at(13, "json")
        self.collect_at(24)
        self.collect_at(36)
        self.assertEqual(self.peer_events(), [first])
        self.ps[0]["up"] = True
        self.collect_at(37)
        events = self.peer_events()
        self.assertEqual([a["kind"] for a in events], ["ygg-peer-down", "ygg-peer-up"])
        self.assertTrue(events[1]["observation_gap"])
        rendered = tm.alert_message(events[1])["output"]
        self.assertIn("разрыв наблюдений", rendered)
        self.assertNotIn("после 37 мин", rendered)
        self.collect_at(38)
        self.assertEqual(self.peer_events(), events)

    @logged
    def test_unknown_preserves_reconnect_evidence_and_pending_replay(self):
        self.collect_at(0)
        state = tm.load_peer_state(self.ctx)
        state["starts"] = {URI: [self.zero.isoformat()]}
        state["unstable"] = {URI: self.zero.isoformat()}
        tm.save_peer_state(self.ctx, state)
        for minute, error in ((1, OSError()), (2, "json"), (3, ConnectionResetError())):
            self.collect_at(minute, error)
            after = tm.load_peer_state(self.ctx)
            for name in ("down", "starts", "unstable"):
                self.assertEqual(after[name], state[name])
            self.assertEqual(self.peer_events(), [])
        # A valid durable event still drains while observation is unknown.
        state = tm.load_peer_state(self.ctx)
        pending = {
            "id": "synthetic-durable-id",
            "kind": "ygg-peer-down",
            "ts": self.zero.isoformat(),
            "peer": URI,
            "minutes": 11,
            "up": 1,
            "total": 2,
        }
        state["pending"] = [pending]
        tm.save_peer_state(self.ctx, state)
        self.collect_at(4, OSError())
        self.assertEqual(self.peer_events(), [pending])
        self.assertEqual(tm.load_peer_state(self.ctx)["pending"], [])

    @logged
    def test_confirmed_empty_and_stack_only_failure_are_not_unknown_node(self):
        self.collect_at(0)
        sample = self.collect_at(11, OSError(), stack_only=True)
        self.assertTrue(sample["peers_observed"])
        self.assertEqual([a["kind"] for a in self.peer_events()], ["ygg-peer-down"])
        self.fixture.ps = []
        sample = self.collect_at(12)
        self.assertTrue(sample["peers_observed"])
        state = tm.load_peer_state(self.ctx)
        self.assertEqual((state["down"], state["starts"], state["unstable"]), ({}, {}, {}))
        self.assertEqual(len(self.peer_events()), 1)  # removal is not observed recovery

    @logged
    def test_mode_failure_also_marks_unknown_without_erasing_episode(self):
        self.collect_at(0)
        before = tm.load_peer_state(self.ctx)["down"]
        with patch.object(self.ctx, "mode", side_effect=Failure("fixture_unavailable")):
            sample = self.collect_at(12)
        self.assertFalse(sample["peers_observed"])
        self.assertEqual(tm.load_peer_state(self.ctx)["down"], before)

    @logged
    def pax_archive(self, size):
        # Retain every legitimate member/hash; the only extra data is metadata.
        normal = rc.archive(rc.members(self.ctx))
        out = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(normal), mode="r:gz") as src:
            with tarfile.open(
                fileobj=out,
                mode="w:gz",
                format=tarfile.PAX_FORMAT,
                pax_headers={"comment": "x" * size},
            ) as dst:
                for info in src:
                    dst.addfile(info, src.extractfile(info))
        return out.getvalue()

    @logged
    def test_pax_expansion_rejected_before_tar_parser_and_preview(self):
        data = self.pax_archive(8 * 1024 * 1024)
        self.assertLess(len(data), 16384)
        with patch.object(rc.tarfile, "open", side_effect=AssertionError("parser reached")):
            with self.assertRaisesRegex(Failure, "backup_expansion_limit"):
                rc.inspect_archive(data)
        archive = self.paths.state / "metadata.tar.gz"
        atomic(archive, data)
        atomic(Path(str(archive) + ".sha256"), core.digest(data))
        before = {p: p.read_bytes() for p in self.paths.etc.iterdir()}
        with self.assertRaisesRegex(Failure, "backup_expansion_limit"):
            rc.restore(self.ctx, archive)
        self.assertEqual(before, {p: p.read_bytes() for p in self.paths.etc.iterdir()})

    @logged
    def test_total_budget_covers_concatenated_gzip_and_ignored_tar_tail(self):
        normal = rc.archive(rc.members(self.ctx))
        limit = rc.ARCHIVE_RAW_LIMIT
        for data in (
            normal + gzip.compress(b"x" * limit),
            gzip.compress(gzip.decompress(normal) + b"\0" * limit),
        ):
            with (
                self.subTest(size=len(data)),
                self.assertRaisesRegex(Failure, "backup_expansion_limit"),
            ):
                rc.inspect_archive(data)

    @logged
    def test_gnu_long_header_expansion_is_bounded_before_parser(self):
        # GNU metadata need not be a legal final member to exhaust a pre-parser.
        info = tarfile.TarInfo("././@LongLink")
        info.type, info.size = tarfile.GNUTYPE_LONGNAME, 8 * 1024 * 1024
        data = gzip.compress(info.tobuf(format=tarfile.GNU_FORMAT) + b"x" * info.size)
        with self.assertRaisesRegex(Failure, "backup_expansion_limit"):
            rc.inspect_archive(data)

    @logged
    def test_exact_total_byte_boundary_including_padding(self):
        normal = rc.archive(rc.members(self.ctx))
        raw = gzip.decompress(normal)
        at_limit = raw + b"\0" * (rc.ARCHIVE_RAW_LIMIT - len(raw))
        self.assertEqual(rc.inspect_archive(gzip.compress(at_limit)), (rc.members(self.ctx), False))
        with self.assertRaisesRegex(Failure, "backup_expansion_limit"):
            rc.inspect_archive(gzip.compress(at_limit + b"\0"))

    @logged
    def test_normal_small_pax_full_key_and_gzip_corruption_controls(self):
        self.assertEqual(rc.inspect_archive(self.pax_archive(1024)), (rc.members(self.ctx), False))
        self.assertEqual(
            rc.inspect_archive(rc.archive(rc.members(self.ctx, True), True)),
            (rc.members(self.ctx, True), True),
        )
        normal = rc.archive(rc.members(self.ctx))
        for data in (b"not gzip", normal[:-3], normal[:-8] + b"\0" * 8):
            with (
                self.subTest(size=len(data)),
                self.assertRaisesRegex(Failure, "invalid_backup_archive"),
            ):
                rc.inspect_archive(data)

    @logged
    def test_same_unit_process_is_allowed_but_role_principals_are_distinct(self):
        # A genuinely separate Python process, same unprivileged UID. This is
        # deliberately NOT a proof about systemd confinement or an exploit.
        with tempfile.TemporaryDirectory(prefix="yu-") as directory:
            with broker.Broker(
                self.ctx,
                "research",
                os.getuid(),
                Path(directory),
                expected_cgroup=broker.process_cgroup(os.getpid()),
            ) as served:
                code = (
                    "import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(3);"
                    's.connect(sys.argv[1]);s.sendall(b\'{"call":"metrics"}\\n\');'
                    "assert s.recv(1024)==b'{\"data\":null}\\n';s.close()"
                )
                result = subprocess.run(  # nosec B603
                    [sys.executable, "-I", "-B", "-c", code, str(served.path)],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)
        self.assertEqual(len(set(broker.USERS.values())), 3)
        self.assertIn("User=" + broker.USERS["research"], sandbox.properties("research"))
        self.assertIn("ProtectProc=invisible", sandbox.COMMON)

    @logged
    def test_second_connection_cannot_replace_already_accepted_worker(self):
        with tempfile.TemporaryDirectory(prefix="yu-") as directory:
            with broker.Broker(
                self.ctx,
                "research",
                os.getuid(),
                Path(directory),
                expected_cgroup=broker.process_cgroup(os.getpid()),
            ) as served:
                with (
                    socket.socket(socket.AF_UNIX) as first,
                    socket.socket(socket.AF_UNIX) as second,
                ):
                    first.settimeout(3)
                    first.connect(str(served.path))
                    first.sendall(b'{"call":"metrics"}\n')
                    self.assertEqual(first.recv(1024), b'{"data":null}\n')
                    second.settimeout(0.1)
                    second.connect(str(served.path))
                    second.sendall(b'{"call":"metrics"}\n')
                    with self.assertRaises(socket.timeout):
                        second.recv(1024)


@logged
def run_suite():
    core.trace_quiet()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ObservationBudget)
    start = time.monotonic()
    print(
        f"[1/1] observation/archive/shared-principal contracts processed=0/{suite.countTestCases()} remaining={suite.countTestCases()}",
        flush=True,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        f"[done] processed={result.testsRun} errors={len(result.errors) + len(result.failures)} remaining=0 elapsed={time.monotonic() - start:.2f}s",
        flush=True,
    )
    if not result.wasSuccessful():
        raise Failure("observation_budget_contracts_failed")


if __name__ == "__main__":
    run_suite()
