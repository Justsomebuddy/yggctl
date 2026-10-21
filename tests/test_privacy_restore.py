"""Synthetic persistence/sender privacy and untrusted archive apply boundaries."""

from test_support import process_handoff_fixture

import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import unittest
import time
from unittest.mock import patch

from core import Failure, atomic, digest, logged
from test_support import ConsoleFixture, URI
import recovery as rc
import telemetry as tm

MARKER = "synthetic-uri-private-marker"
ENDPOINT = "tls://192.0.2.1:443"


class PrivacyRestore(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    @logged
    def test_console_output_redacts_peer_credentials(self):
        from core import public_config

        hostile = "tls://user:" + MARKER + "@192.0.2.1:443?password=" + MARKER
        for data, expected in (
            ({"peers": [{"remote": hostile}]}, {"peers": [{"remote": ENDPOINT}]}),
            ("dial " + hostile + ": timeout", "dial " + ENDPOINT + ": timeout"),
            (
                "see tls://peer.example:443?password=" + MARKER + " now",
                "see tls://peer.example:443 now",
            ),
            ("tls://@ now", "[REDACTED-URI] now"),
        ):
            clean = public_config(data)
            self.assertNotIn(MARKER, json.dumps(clean))
            self.assertEqual(clean, expected)

    @logged
    def test_peer_label_allowlisted_public_parameters_and_hostile_uri_shapes(self):
        # Preserve the established public-pin/timing identity only for a fully
        # allowlisted shape. Everything else loses ALL userinfo/path/query/fragment.
        self.assertEqual(tm.peer_label(URI), URI)
        self.assertEqual(tm.peer_label(ENDPOINT + "?priority=3"), ENDPOINT + "?priority=3")
        self.assertEqual(tm.peer_label(ENDPOINT), ENDPOINT)
        self.assertEqual(
            tm.peer_label("tls://[2001:db8::1]:443?password=" + MARKER), "tls://[2001:db8::1]:443"
        )
        for tail in (
            "?password=",
            "?PASSWORD=",
            "?pass%77ord=",
            "?token=",
            "?secret=",
            "?key=invalid",
            "?sni=",
            "?origin=",
            "?key=" + "1" * 64 + "&password=",
            "/path/",
            "#",
            "?maxbackoff=",
            "?priority=999",
            "?key=x&key=",
            "?broken",
        ):
            with self.subTest(tail=tail):
                self.assertEqual(tm.peer_label(ENDPOINT + tail + MARKER), ENDPOINT)
        self.assertEqual(tm.peer_label("tls://user:" + MARKER + "@192.0.2.1:443"), ENDPOINT)
        values: tuple[object, ...] = (
            None,
            1,
            {},
            "",
            MARKER,
            "https://192.0.2.1:443?password=" + MARKER,
            "tls://[broken",
            "tls://[fe80::1%private-zone]:443",
            "tls://192.0.2.1:99999",
            "tls://192.0.2.1",
            "tls://host.example:443",
            ENDPOINT + "\n" + MARKER,
            "x" * 4097,
        )
        for value in values:
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(tm.peer_label(value), "unknown-peer")

    @logged
    @patch("simplex_sender.handoff", new=process_handoff_fixture)
    def test_actual_collect_persistence_alert_transitions_and_sender_no_uri_secrets(self):
        now = dt.datetime(2026, 10, 20, 10, tzinfo=dt.timezone.utc)
        raw = ENDPOINT + "?password=" + MARKER + "&key=" + "1" * 64
        self.ps = [
            dict(self.ps[0], remote=raw, up=False),
            dict(self.ps[0], remote=URI.replace("192.0.2.1", "192.0.2.2")),
        ]
        atomic(self.paths.state / "notify.state", "on\n")
        for minute, up in ((0, False), (11, False), (12, True)):
            self.ps[0]["up"] = up
            at = (now + dt.timedelta(minutes=minute)).isoformat()
            with patch.object(tm, "timestamp", return_value=at):
                sample = tm.collect(self.ctx)
            self.assertEqual(sample["peers"][0]["r"], ENDPOINT)
        for name in ("metrics.jsonl", "alert-state.json", "alerts.jsonl"):
            text = (self.paths.state / name).read_text()
            self.assertNotIn(MARKER, text)
            self.assertNotIn("password", text.lower())
        self.assertEqual(
            [row["kind"] for row in tm.rows(self.ctx, "alerts.jsonl")],
            ["ygg-peer-down", "ygg-peer-up"],
        )
        # Old queue rows are not rewritten (stable IDs/cursors remain valid), but
        # even their untrusted raw peer is cleaned before the external sender.
        legacy = dict(tm.rows(self.ctx, "alerts.jsonl")[0], id="legacy-row", peer=raw)
        tm.append(self.ctx, "alerts.jsonl", legacy, 1000)
        atomic(self.paths.state / "alerts-forwarded.json", '{"sent": []}')
        with patch.object(self.ctx, "run", wraps=self.ctx.run) as run:
            tm.forward(self.ctx)
        sent = [
            json.loads(c.kwargs["input"]) for c in run.call_args_list if c.args[0][0] == tm.SENDER
        ]
        self.assertEqual(len(sent), 3)
        self.assertNotIn(MARKER, json.dumps(sent))
        self.assertTrue(all(ENDPOINT in row["rule"] for row in sent))
        self.assertIn(MARKER, (self.paths.state / "alerts.jsonl").read_text())

    @logged
    def test_stage_and_legacy_stats_also_protect_the_output_boundary(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw = ENDPOINT + "?password=" + MARKER
        sample = {"ts": now.isoformat(), "up": 1, "peers": [{"r": raw, "up": True, "rtt": 1}]}
        tm.peer_alerts(self.ctx, sample, {raw: 1})
        self.assertNotIn(MARKER, (self.paths.state / "alert-state.json").read_text())
        tm.append(self.ctx, "metrics.jsonl", sample)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            tm.stats(self.ctx, 1, graph=True)
        self.assertNotIn(MARKER, output.getvalue())
        self.assertIn(ENDPOINT, output.getvalue())

    @logged
    def test_legacy_private_pending_is_retained_without_leaking_into_queue(self):
        raw = ENDPOINT + "?password=" + MARKER
        state = {
            "pending": [
                {
                    "id": "legacy-id",
                    "ts": "2026-10-20T10:00:00+00:00",
                    "kind": "ygg-peer-down",
                    "peer": raw,
                    "minutes": 11,
                }
            ]
        }
        tm.save_peer_state(self.ctx, state)
        before = (self.paths.state / "alert-state.json").read_bytes()
        with self.assertRaisesRegex(Failure, "legacy_peer_pending_requires_privacy_review"):
            tm.flush_peer_alerts(self.ctx)
        self.assertEqual(before, (self.paths.state / "alert-state.json").read_bytes())
        self.assertFalse((self.paths.state / "alerts.jsonl").exists())

    @logged
    def test_forged_self_consistent_archive_is_not_authenticated_and_never_applied(self):
        files = rc.members(self.ctx)
        cfg = json.loads(files["config/yggdrasil-lab.conf"])
        cfg["Peers"][0] = URI.replace("192.0.2.1", "192.0.2.9")
        files["config/yggdrasil-lab.conf"] = json.dumps(cfg).encode()
        path = self.paths.state / "untrusted.tar.gz"
        archive = rc.archive(files)
        atomic(path, archive)
        atomic(Path(str(path) + ".sha256"), digest(archive))
        before = {
            p: p.read_bytes() for d in (self.paths.etc, self.paths.units) for p in d.iterdir()
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc.restore(self.ctx, path)
        self.assertIn("NOT AUTHENTICATED", output.getvalue())
        self.assertNotIn("VERIFIED", output.getvalue())
        with (
            patch.object(self.ctx, "run") as run,
            patch.object(self.ctx, "locked") as lock,
            self.assertRaisesRegex(
                Failure, "restore_apply_requires_independent_authentication_review"
            ),
        ):
            rc.restore(self.ctx, path, True)
        run.assert_not_called()
        lock.assert_not_called()
        self.assertEqual(
            before,
            {p: p.read_bytes() for d in (self.paths.etc, self.paths.units) for p in d.iterdir()},
        )


if __name__ == "__main__":
    started = time.monotonic()
    print("[1/1] privacy/restore fixture suite; processed=0 remaining=1", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(PrivacyRestore)
    )
    print(
        f"[1/1] processed={result.testsRun} errors={len(result.errors) + len(result.failures)} remaining=0 "
        f"elapsed={time.monotonic() - started:.2f}s",
        flush=True,
    )
    raise SystemExit(not result.wasSuccessful())
