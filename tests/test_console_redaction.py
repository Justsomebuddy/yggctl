"""Console privacy regressions using synthetic URI markers and temporary config."""

import argparse
import contextlib
import io
import json
from unittest.mock import patch

import main
from core import logged, public_config
from test_support import ConsoleFixture

MARKER = "synthetic-console-private-marker"
IPV6 = "tls://[2001:db8::1]:443"
IPV4 = "tls://192.0.2.1:443"


class ConsoleRedaction(ConsoleFixture):
    @logged
    def test_punctuation_only_private_values_are_not_restored_as_prose(self):
        for value in (")))", ";;;", "'''", ".,:;)]}\"'`>"):
            for field in ("?password=", "#", "/"):
                with self.subTest(value=value, field=field):
                    self.assertEqual(public_config(IPV4 + field + value), IPV4)

    @logged
    def test_peer_uri_shapes_reach_actual_console_output(self):
        # Exercise dispatch -> API/config -> output -> JSON, not just the helper.
        for raw in (
            IPV6 + "?password=" + MARKER,
            "TLS://[2001:db8::1]:443?token=" + MARKER,
            IPV4 + "?password=prefix," + MARKER,
            IPV4 + "?password=prefix;" + MARKER,
            IPV4 + "?password=prefix'" + MARKER,
            IPV4 + "?password=prefix(" + MARKER + ")",
            "tls://user:" + MARKER + "@[2001:db8::1]:443",
            "tls://peer.example:443/private/" + MARKER,
        ):
            for command in ("peers", "stack-peers", "config"):
                with self.subTest(raw=raw, command=command):
                    data = {"peers": [{"remote": raw, "last_error": "dial " + raw + ": timeout"}]}
                    original = json.dumps(data)
                    args = argparse.Namespace(
                        command=command,
                        args=[],
                        apply=False,
                        force=False,
                        full=False,
                        recipient=None,
                    )
                    stdout = io.StringIO()
                    with (
                        patch.object(self.ctx, "api", return_value=data),
                        patch.object(self.ctx, "config", return_value=data),
                        contextlib.redirect_stdout(stdout),
                    ):
                        main.dispatch(self.ctx, args)
                    self.assertNotIn(MARKER, stdout.getvalue())
                    self.assertIn("timeout", stdout.getvalue())
                    self.assertEqual(json.dumps(data), original)

    @logged
    def test_public_options_and_surrounding_text_remain_useful(self):
        for endpoint in (IPV4, IPV6):
            for option in ("", "?key=" + "a" * 64, "?maxbackoff=10s", "?priority=3"):
                uri = endpoint + option
                for template in ("{}", "dial {}: timeout", "see [{}], next", 'see "{}" now'):
                    value = template.format(uri)
                    self.assertEqual(public_config(value), value)
                    self.assertEqual(public_config(public_config(value)), value)
        # Unrelated URI schemes retain their prior display contract.
        self.assertEqual(
            public_config("unix:///run/node/admin.sock"), "unix:///run/node/admin.sock"
        )
        self.assertEqual(
            public_config("https://user:" + MARKER + "@example.test/path"),
            "https://[REDACTED]@example.test/path",
        )

    @logged
    def test_malformed_and_dns_uri_metadata_is_not_a_fallback_escape(self):
        for raw in (
            "tls://[broken?password=" + MARKER,
            "tls://peer.example:99999?token=" + MARKER,
            "tls://peer.example/private/" + MARKER,
            "tls://peer.example:443/path/" + MARKER,
            "tls://[fe80::1%" + MARKER + "]:443",
            "tls://@?secret=" + MARKER,
            IPV6 + "?pass%77ord=" + MARKER,
            IPV6 + "#" + MARKER,
        ):
            with self.subTest(raw=raw):
                data = {"nested": [raw, "error: " + raw + ": timeout"], "count": 2}
                clean = public_config(data)
                self.assertNotIn(MARKER, json.dumps(clean))
                self.assertEqual(clean["count"], 2)
        self.assertEqual(
            public_config("tls://peer.example:443/path?token=" + MARKER),
            "tls://peer.example:443",
        )

    @logged
    def test_journal_records_apply_the_uri_boundary(self):
        # Keywords are not the only way a credential reaches a journal line.
        for message, expected in (
            ("peer dial failed " + IPV4 + "?password=" + MARKER, None),
            ("peer dial failed tls://peer.example:443/private/" + MARKER, "tls://peer.example:443"),
            (
                "peer dial failed https://user:" + MARKER + "@example.test/p",
                "https://[REDACTED]@example.test/p",
            ),
            ("peer dial failed tls://user%40host:" + MARKER + "@192.0.2.1:443", IPV4),
        ):
            with self.subTest(message=message):
                raw = json.dumps(
                    {
                        "_SYSTEMD_UNIT": "yggdrasil-lab.service",
                        "__REALTIME_TIMESTAMP": "1",
                        "MESSAGE": message,
                    }
                )
                record = main.journal_records(raw)[0]
                self.assertNotIn(MARKER, record["message"])
                if expected:
                    self.assertIn(expected, record["message"])
        keyword = json.dumps({"MESSAGE": "password=" + MARKER})
        self.assertEqual(
            main.journal_records(keyword)[0]["message"], "[REDACTED sensitive journal message]"
        )

    @logged
    def test_mixed_safe_and_hostile_query_parameters(self):
        for raw in (
            IPV4 + "?key=" + "a" * 64 + "&password=" + MARKER,
            IPV6 + "?PASSWORD=" + MARKER,
            IPV4 + "?password=" + MARKER + "?token=" + MARKER,
            IPV4 + "?password=" + MARKER + "\x00",
            "tls://user%40host:" + MARKER + "@192.0.2.1:443",
        ):
            with self.subTest(raw=raw):
                clean = json.dumps(public_config({"remote": raw, "last_error": "dial " + raw}))
                self.assertNotIn(MARKER, clean)
