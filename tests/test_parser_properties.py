"""Deterministic offline property tests; examples/database never persisted."""

import ipaddress
import json
import unittest
from hypothesis import given, settings, strategies as st

from core import Failure, logged, peer_uri, public_config
from atlas import protocol
import main

PROFILE = settings(max_examples=200, derandomize=True, database=None, deadline=1000)
REDACTED = "[REDACTED]"


class ParserProperties(unittest.TestCase):
    @PROFILE
    @given(st.ip_addresses(v=4), st.integers(1, 65535), st.binary(min_size=32, max_size=32))
    @logged
    def test_peer_canonicalization_is_idempotent(self, ip, port, pin):
        raw = f"tls://{ip}:{port}?key={pin.hex().upper()}"
        uri, endpoint = peer_uri(raw)
        self.assertEqual(endpoint, f"{ip}:{port}")
        self.assertEqual(peer_uri(uri), (uri, endpoint))
        self.assertIn("key=" + pin.hex(), uri)

    @PROFILE
    @given(st.binary(min_size=32, max_size=32))
    @logged
    def test_overlay_address_and_remote_self_envelope(self, pin):
        key = pin.hex()
        address = protocol.address(key)
        self.assertIn(ipaddress.IPv6Address(address), ipaddress.IPv6Network("200::/7"))
        self.assertEqual(
            protocol.projection(key, "self", {address: {"key": key, "routing_entries": "0"}}),
            {"key": key, "routing_entries": 0},
        )

    @PROFILE
    @given(st.binary(max_size=512))
    @logged
    def test_journal_arbitrary_bytes_fail_with_safe_label_or_project(self, raw):
        try:
            rows = main.journal_records(raw)
        except Failure as error:
            self.assertEqual(str(error), "invalid_journal_json_no_raw_output")
        else:
            for row in rows:
                self.assertEqual(set(row), {"unit", "timestamp_us", "message"})
                self.assertIn(row["unit"], (main.NODE, main.STACK, "unknown"))
                self.assertIsInstance(row["message"], str)

    @PROFILE
    @given(
        st.sampled_from(
            ["private_key", "GROUP-PASSWORD", "Token", "password", "Authorization", "secret"]
        ),
        st.text(max_size=100),
    )
    @logged
    def test_journal_sensitive_message_is_omitted(self, label, value):
        raw = json.dumps({"MESSAGE": label + "=" + value, "untrusted": value})
        self.assertEqual(
            main.journal_records(raw)[0]["message"], "[REDACTED sensitive journal message]"
        )

    @PROFILE
    @given(st.text(min_size=1, max_size=128))
    @logged
    def test_nested_secret_projection_is_idempotent(self, value):
        data = {"password": value, "rows": [{"TOKEN": value}], "empty": None}
        clean = public_config(data)
        self.assertEqual(
            clean, {"password": REDACTED, "rows": [{"TOKEN": REDACTED}], "empty": None}
        )
        self.assertEqual(public_config(clean), clean)
