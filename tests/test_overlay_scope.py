"""Independent no-network adversarial packet-scope and malformed-input controls."""

import json
from typing import Any
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from core import Failure
import checks


class ScopedPolicy(unittest.TestCase):
    def document(self, exprs=(), policy="drop", **metadata):
        chain = {
            "family": "inet",
            "table": "mullvad",
            "name": "output",
            "type": "filter",
            "hook": "output",
            "prio": 0,
            "policy": policy,
            **metadata,
        }
        return {
            "nftables": [
                {"chain": chain},
                *[
                    {
                        "rule": {
                            "family": "inet",
                            "table": "mullvad",
                            "chain": "output",
                            "handle": i + 1,
                            "expr": expr,
                        }
                    }
                    for i, expr in enumerate(exprs)
                ],
            ]
        }

    def diagnose(self, document, outputs=None, interface=None):
        commands = []
        values = {
            "ip": "3: ygg0: <UP> mtu 1420\n    tun type tun pi off\n",
            "firewall-cmd": "trusted\n  interfaces: ygg0\n",
            "nft": json.dumps(document),
            **(outputs or {}),
        }

        def run(argv):
            commands.append(argv)
            value = values[argv[0].rsplit("/", 1)[1]]
            if isinstance(value, Exception):
                raise value
            return SimpleNamespace(stdout=value if isinstance(value, bytes) else value.encode())

        result = checks.overlay_policy(SimpleNamespace(run=run), interface)
        self.assertEqual(
            commands,
            [
                ["/usr/sbin/ip", "-d", "link", "show"],
                ["/usr/bin/firewall-cmd", "--get-active-zones"],
                ["/usr/sbin/nft", "-j", "list", "ruleset"],
            ],
        )
        self.assertEqual(result["host_permission"], "unknown")
        self.assertEqual(result["reachability"], "not_tested")
        self.assertNotIn("overlay_verdict", result)
        return result

    def test_limit_and_quota_are_predicates_not_annotations(self):
        for kind in ("limit", "quota", "notrack", "ct", "mangle"):
            with self.subTest(kind=kind):
                r = self.diagnose(self.document([[{kind: {}}, {"accept": None}]]))
                self.assertEqual(r["sample_verdict"], "conditional")

    def test_one_destination_never_becomes_an_overlay_or_host_permission(self):
        expr = {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": "ip6", "field": "daddr"}},
                "right": "200::1/128",
            }
        }
        r = self.diagnose(self.document([[expr, {"accept": None}]]))
        self.assertEqual(r["sample_verdict"], "allowed")
        self.assertEqual(r["sample_scope"]["destination"], "200::1")
        self.assertIn("sample_not_overlay_wide", r["limitations"])
        self.assertIn("other_chains_hooks_and_routing_not_evaluated", r["limitations"])

    def test_unknown_rule_before_return_cannot_erase_uncertainty(self):
        conditional = {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                "right": 22,
            }
        }
        r = self.diagnose(
            self.document([[conditional, {"drop": None}], [{"return": None}]], policy="accept")
        )
        self.assertEqual(r["sample_verdict"], "conditional")

    def test_name_alone_and_wrong_metadata_do_not_establish_a_base_chain(self):
        for field, bad in (
            ("hook", None),
            ("hook", "input"),
            ("type", None),
            ("type", "nat"),
            ("prio", None),
            ("prio", True),
            ("prio", "filter"),
            ("prio", 1 << 31),
        ):
            with self.subTest(field=field, bad=bad):
                r = self.diagnose(self.document([[{"accept": None}]], **{field: bad}))
                self.assertEqual(r["sample_verdict"], "unknown")

    def test_control_flow_is_explicitly_unsupported_not_invented(self):
        for kind in ("jump", "goto"):
            r = self.diagnose(self.document([[{kind: {"target": "sub"}}]], policy="accept"))
            self.assertEqual(r["sample_verdict"], "conditional")
        for policy, verdict in (("accept", "allowed"), ("drop", "denied")):
            r = self.diagnose(self.document([[{"return": None}]], policy=policy))
            self.assertEqual(r["sample_verdict"], verdict)

    def test_malformed_left_and_expression_types_are_controlled(self):
        for left in ("x", [1], None, 0, {}, {"meta": None}):
            r = self.diagnose(
                self.document(
                    [[{"match": {"left": left, "op": "==", "right": "ygg0"}}, {"accept": None}]]
                )
            )
            self.assertEqual(r["sample_verdict"], "conditional")
        expr: Any
        for expr in (
            None,
            {},
            [{"counter": 1}],
            [{"accept": {}}],
            [{"reject": "x"}],
            [{"return": {}}],
            [{}] * 65,
        ):
            self.assertEqual(checks.overlay_rule(expr, "ygg0")[0], "unknown")

    def test_prefix_operands_use_native_nft_json_schema_and_validate_every_member(self):
        prefix = {"prefix": {"addr": "200::", "len": 7}}
        self.assertEqual(checks.overlay_prefix_match(prefix, "=="), "match")
        self.assertEqual(checks.overlay_prefix_match({"set": [prefix, "fc00::/7"]}, "=="), "match")
        rhs: Any
        for rhs in (
            {"set": []},
            {"set": ["200::/7", "broken"]},
            ["200::/7"] * 65,
            {"prefix": {"addr": "200::", "len": True}},
            {"prefix": {"addr": "200::", "len": 129}},
            {"prefix": "x"},
            {"range": ["200::1", "200::2"]},
        ):
            self.assertEqual(checks.overlay_prefix_match(rhs, "=="), "unknown")
        self.assertEqual(checks.overlay_prefix_match(prefix, "in"), "unknown")

    def test_malformed_or_duplicate_index_members_are_not_silently_dropped(self):
        documents: list[Any] = [
            {"nftables": [{"rule": 3}]},
            {"nftables": [{"chain": 3}]},
            {"nftables": [{"rule": {"family": "inet", "table": "mullvad", "chain": "output"}}]},
            {"nftables": [{"metainfo": {}}] * (checks.OVERLAY_ITEM_LIMIT + 1)},
        ]
        duplicate = self.document()
        duplicate["nftables"] *= 2
        documents.append(duplicate)
        for document in documents:
            with (
                self.subTest(document_type=type(document).__name__),
                self.assertRaisesRegex(Failure, "invalid_nft_json"),
            ):
                checks.nft_chains(document)
        r = self.diagnose({"nftables": [{"rule": 3}]})
        self.assertEqual(r["inspection"]["nft"], "invalid_json")
        self.assertEqual(r["sample_verdict"], "unknown")

    def test_only_recognized_side_effect_free_annotations_fall_through(self):
        annotation: Any
        for annotation in (
            {"counter": None},
            {"counter": {}},
            {"log": {}},
            {"comment": "synthetic"},
        ):
            self.assertEqual(
                self.diagnose(self.document([[annotation]], policy="accept"))["sample_verdict"],
                "allowed",
            )
        self.assertEqual(
            self.diagnose(self.document([[{"reject": {}}]]))["sample_verdict"], "denied"
        )
        self.assertEqual(
            checks.overlay_match(
                {"left": {"meta": {"key": "oifname"}}, "op": "!=", "right": "ygg0"}, "ygg0"
            ),
            "miss",
        )
        self.assertEqual(
            checks.overlay_match({"left": {"payload": None}, "op": "=="}, "ygg0"), "unknown"
        )

    def test_inspection_failure_is_not_absence_or_permission(self):
        for name, state, value in (
            ("ip", "failed", Failure("external_failed:ip")),
            ("ip", "invalid_text", b"\xff"),
            ("nft", "invalid_text", b"\xff"),
            ("firewall-cmd", "failed", Failure("external_failed:firewall")),
        ):
            r = self.diagnose(self.document(policy="accept"), outputs={name: value})
            self.assertEqual(
                r["inspection"]["firewalld" if name == "firewall-cmd" else name], state
            )
        r = self.diagnose(self.document(), outputs={"ip": "2: eth0: <UP> mtu 1500\n"})
        self.assertIn("tun_interface_not_found", r["findings"])
        self.assertIsNone(r["sample_scope"]["output_interface"])

    def test_invalid_explicit_interface_refuses_before_external_calls(self):
        interface: Any
        for interface in ([], 1, "", "x" * 16, "ygg0\n"):
            run = Mock()
            with self.assertRaisesRegex(Failure, "invalid_overlay_interface"):
                checks.overlay_policy(SimpleNamespace(run=run), interface)
            run.assert_not_called()
