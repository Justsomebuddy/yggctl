"""Read-only overlay policy diagnosis: static nft interpretation and zones."""

import argparse
import contextlib
import io
import json
from types import SimpleNamespace
from unittest.mock import patch

from core import Failure
import checks
import main
from test_support import ConsoleFixture

LINKS = """3: ygp1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq_codel state UNKNOWN
    link/none  promiscuity 0
    tun type tun pi off vnet_hdr off persist off
4: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
"""

ZONES_BLOCKED = """docker
  interfaces: docker0
public (default)
  interfaces: wlo1
trusted
  interfaces: wg0
"""

ZONES_OK = """trusted
  interfaces: wg0 ygp1
"""

ACCEPT = {"accept": None}
DROP = {"drop": None}
REJECT = {"reject": None}
COUNTER = {"counter": {"packets": 0, "bytes": 0}}


def meta(key):
    return {"meta": {"key": key}}


def payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}


def match(op, left, right):
    return {"match": {"op": op, "left": left, "right": right}}


def ruleset(rules, policy="drop", chain="output", table="mullvad", family="inet", extra=()):
    objects = [
        {"metainfo": {"version": "1.0.9", "release_name": "test", "json_schema_version": 1}},
        {"table": {"family": family, "name": table}},
        {"chain": {"family": family, "table": table, "name": chain, "policy": policy}},
        *extra,
    ]
    for handle, expr in enumerate(rules, start=100):
        expr = expr if isinstance(expr, list) else [expr]
        objects.append(
            {
                "rule": {
                    "family": family,
                    "table": table,
                    "chain": chain,
                    "handle": handle,
                    "expr": expr,
                }
            }
        )
    return {"nftables": objects}


class OverlayPolicy(ConsoleFixture):
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def fake_run(self, outputs):
        def run(argv, **kwargs):
            name = argv[1]
            if name in outputs:
                value = outputs[name]
                if isinstance(value, Exception):
                    raise value
                if isinstance(value, dict):
                    value = json.dumps(value)
                return SimpleNamespace(stdout=value.encode(), returncode=0)
            raise Failure(f"unexpected_command:{argv[0]}")

        return run

    def policy(self, links=LINKS, zones=ZONES_BLOCKED, nft=None, interface=None):
        outputs = {
            "-d": links,
            "--get-active-zones": zones,
            "-j": ruleset([], policy="drop") if nft is None else nft,
        }
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            return checks.overlay_policy(self.ctx, interface)

    def test_source_only_accept_is_conditional_not_permission(self):
        result = self.policy(
            nft=ruleset([[match("==", payload("ip6", "saddr"), "200::/7"), ACCEPT]])
        )
        self.assertEqual(result["overlay_verdict"], "conditional")
        self.assertNotIn("mullvad_killswitch_rejects_overlay", result["findings"])
        self.assertIn("conditional_rules_require_packet_trace", result["limitations"])

    def test_negated_destination_does_not_establish_permission(self):
        result = self.policy(
            zones=ZONES_OK,
            nft=ruleset([[match("!=", payload("ip6", "daddr"), "200::/7"), ACCEPT]]),
        )
        self.assertEqual(result["overlay_verdict"], "denied")
        self.assertEqual(result["findings"], ["mullvad_killswitch_rejects_overlay"])

    def test_port_constrained_allow_is_not_an_overlay_allowance(self):
        result = self.policy(
            nft=ruleset(
                [
                    [
                        match("==", meta("oifname"), "ygp1"),
                        match("==", payload("tcp", "dport"), 22),
                        ACCEPT,
                    ]
                ]
            )
        )
        self.assertEqual(result["overlay_verdict"], "conditional")
        self.assertEqual(result["inspection"]["nft"], "ok")

    def test_accept_after_unconditional_reject_is_unreachable(self):
        result = self.policy(
            nft=ruleset([[REJECT], [match("==", payload("ip6", "daddr"), "200::/7"), ACCEPT]])
        )
        self.assertEqual(result["overlay_verdict"], "denied")
        self.assertEqual(result["matched_rule"], 100)

    def test_destination_accept_allows_the_overlay_sample(self):
        result = self.policy(
            zones=ZONES_OK,
            nft=ruleset([[match("==", payload("ip6", "daddr"), "200::/7"), ACCEPT]]),
        )
        self.assertEqual(result["overlay_verdict"], "allowed")
        self.assertEqual(result["findings"], [])

    def test_policy_accept_allows_when_no_rule_matches(self):
        result = self.policy(nft=ruleset([], policy="accept"))
        self.assertEqual(result["overlay_verdict"], "allowed")

    def test_chain_without_a_policy_is_unknown(self):
        result = self.policy(nft=ruleset([], policy=""))
        self.assertEqual(result["overlay_verdict"], "unknown")
        self.assertIn("overlay_verdict_unknown", result["limitations"])

    def test_missing_chain_is_unknown_and_not_a_blocker(self):
        result = self.policy(nft={"nftables": [{"metainfo": {"version": "1.0.9"}}]})
        self.assertEqual(result["overlay_verdict"], "unknown")
        self.assertIn("mullvad_chain_missing", result["limitations"])
        self.assertEqual(result["findings"], [])

    def test_missing_nft_is_reported_as_unavailable(self):
        outputs = {
            "-d": LINKS,
            "--get-active-zones": ZONES_OK,
            "-j": Failure("external_unavailable:nft"),
        }
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            result = checks.overlay_policy(self.ctx)
        self.assertEqual(result["inspection"]["nft"], "unavailable")
        self.assertIn("nft_inspection_unavailable", result["limitations"])
        self.assertEqual(result["findings"], [])

    def test_failed_nft_is_distinguished_from_absence(self):
        outputs = {
            "-d": LINKS,
            "--get-active-zones": ZONES_OK,
            "-j": Failure("external_failed:nft:rc=1"),
        }
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            result = checks.overlay_policy(self.ctx)
        self.assertIn("nft_inspection_failed", result["limitations"])

    def test_invalid_nft_json_is_reported(self):
        result = self.policy(nft="not-json")
        self.assertEqual(result["inspection"]["nft"], "invalid_json")
        self.assertIn("nft_inspection_invalid_json", result["limitations"])

    def test_missing_ip_reporting_is_not_a_tun_finding_only(self):
        outputs = {
            "-d": Failure("external_unavailable:ip"),
            "--get-active-zones": ZONES_OK,
            "-j": ruleset([]),
        }
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            result = checks.overlay_policy(self.ctx)
        self.assertEqual(result["inspection"]["ip"], "unavailable")
        self.assertIn("ip_inspection_unavailable", result["limitations"])
        self.assertIn("tun_interface_not_found", result["findings"])

    def test_firewalld_zone_is_evidence_not_permission(self):
        result = self.policy(
            zones=ZONES_OK,
            nft=ruleset([[match("==", payload("ip6", "daddr"), "200::/7"), ACCEPT]]),
        )
        self.assertEqual(result["firewalld_zone"], "trusted")
        self.assertEqual(result["firewalld_evidence"], "zone_membership_is_not_permission")

    def test_firewalld_unavailable_does_not_block_the_verdict(self):
        outputs = {
            "-d": LINKS,
            "--get-active-zones": Failure("external_unavailable:firewall-cmd"),
            "-j": ruleset([[match("==", payload("ip6", "daddr"), "200::/7"), ACCEPT]]),
        }
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            result = checks.overlay_policy(self.ctx)
        self.assertEqual(result["inspection"]["firewalld"], "unavailable")
        self.assertEqual(result["overlay_verdict"], "allowed")

    def test_jump_into_a_resolved_chain_uses_its_verdict(self):
        extra = [
            {
                "chain": {
                    "family": "inet",
                    "table": "mullvad",
                    "name": "sub",
                    "policy": "accept",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "mullvad",
                    "chain": "sub",
                    "handle": 900,
                    "expr": [ACCEPT],
                }
            },
        ]
        result = self.policy(
            nft=ruleset(
                [{"jump": {"target": "sub"}}],
                policy="drop",
                extra=extra,
            )
        )
        self.assertEqual(result["overlay_verdict"], "allowed")

    def test_jump_to_unknown_target_is_conditional(self):
        result = self.policy(nft=ruleset([[{"jump": {"target": "missing"}}]], policy="drop"))
        self.assertEqual(result["overlay_verdict"], "conditional")

    def test_jump_without_target_or_too_deep_is_conditional(self):
        self.assertEqual(
            self.policy(nft=ruleset([[{"goto": None}]], policy="drop"))["overlay_verdict"],
            "conditional",
        )
        deep = ruleset([[{"jump": {"target": "output"}}]], policy="drop")
        self.assertEqual(self.policy(nft=deep)["overlay_verdict"], "conditional")

    def test_unknown_rule_before_return_is_conditional(self):
        result = self.policy(
            nft=ruleset([[{"ct": {"key": "state"}}, {"return": None}]], policy="drop")
        )
        self.assertEqual(result["overlay_verdict"], "conditional")

    def test_return_falls_back_to_the_chain_policy(self):
        result = self.policy(nft=ruleset([[{"return": None}]], policy="drop"))
        self.assertEqual(result["overlay_verdict"], "denied")

    def test_unknown_expression_with_accept_is_conditional(self):
        result = self.policy(nft=ruleset([[{"ct": {"key": "state", "value": "new"}}, ACCEPT]]))
        self.assertEqual(result["overlay_verdict"], "conditional")

    def test_non_matching_statements_do_not_change_the_verdict(self):
        result = self.policy(
            nft=ruleset(
                [
                    [
                        COUNTER,
                        {"log": {"prefix": "x"}},
                        match("==", payload("ip6", "daddr"), "200::/7"),
                        ACCEPT,
                    ]
                ]
            )
        )
        self.assertEqual(result["overlay_verdict"], "allowed")
        self.assertIn("matched_rule", result)

    def test_path_is_bounded_for_long_chains(self):
        rules = [match("==", payload("ip6", "saddr"), "200::/7") for _ in range(80)]
        rules.append(ACCEPT)
        result = self.policy(nft=ruleset(rules, policy="accept"))
        self.assertEqual(len(result["evaluated_rules"]), checks.OVERLAY_PATH_LIMIT)

    def test_zone_parser_ignores_empty_and_header_lines(self):
        self.assertEqual(
            checks.zone_interfaces(
                "  interfaces: before-any-zone\n\npublic (default)\n  interfaces: a b\n"
                "\ntrusted\n  interfaces:\n  interfaces: c\n"
            ),
            {"a": "public", "b": "public", "c": "trusted"},
        )

    def test_overlay_named_tun_is_preferred_over_the_vpn_tunnel(self):
        links = (
            "5: wg0-mullvad: <POINTOPOINT,NOARP,UP> mtu 1420\n"
            "    link/none\n    tun type tun pi off\n"
            "6: ygg0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 65535\n"
            "    link/none\n    tun type tun pi on\n"
        )
        self.assertEqual(checks.preferred_interface(checks.tun_interfaces(links)), "ygg0")
        self.assertEqual(checks.preferred_interface([]), "")

    def test_explicit_interface_overrides_detection(self):
        self.assertEqual(self.policy(interface="other0")["interface"], "other0")

    def test_cli_prints_the_verdict(self):
        outputs = {
            "-d": LINKS,
            "--get-active-zones": ZONES_OK,
            "-j": ruleset([[match("==", payload("ip6", "daddr"), "200::/7"), ACCEPT]]),
        }
        out = io.StringIO()
        with (
            patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)),
            contextlib.redirect_stdout(out),
        ):
            main.do_overlay_policy(self.ctx, argparse.Namespace(command="overlay-policy"), [])
        self.assertIn('"overlay_verdict": "allowed"', out.getvalue())
        self.assertIn('"interface": "ygp1"', out.getvalue())

    def test_prefix_helper_handles_sets_and_invalid_values(self):
        self.assertEqual(checks.overlay_prefix_match("200::/7", "=="), "match")
        self.assertEqual(checks.overlay_prefix_match(["200::/7", "::/0"], "=="), "match")
        self.assertEqual(checks.overlay_prefix_match("200::/7", "!="), "miss")
        self.assertEqual(checks.overlay_prefix_match([], "=="), "unknown")
        self.assertEqual(checks.overlay_prefix_match([1], "=="), "unknown")
        self.assertEqual(checks.overlay_prefix_match("not-a-network", "=="), "unknown")

    def test_match_and_rule_helpers_reject_malformed_input(self):
        self.assertEqual(checks.overlay_match(None, "ygp1"), "unknown")
        self.assertEqual(checks.overlay_match({"left": {}, "op": "=="}, "ygp1"), "unknown")
        self.assertEqual(
            checks.overlay_match({"left": meta("mark"), "op": "==", "right": 1}, "ygp1"),
            "unknown",
        )
        self.assertEqual(
            checks.overlay_match({"left": meta("oifname"), "op": "==", "right": "other"}, "ygp1"),
            "miss",
        )
        self.assertEqual(
            checks.overlay_rule(
                [{"match": {"op": "in", "left": meta("oifname"), "right": []}}], "ygp1"
            )[0],
            "unknown",
        )
        self.assertEqual(
            checks.overlay_match(
                {"left": {"ct": {"key": "state"}}, "op": "==", "right": "new"}, "ygp1"
            ),
            "unknown",
        )
        self.assertEqual(checks.overlay_rule(["bad"], "ygp1")[0], "unknown")
        self.assertEqual(
            checks.overlay_rule([{"accept": None, "drop": None}], "ygp1")[0], "unknown"
        )

    def test_chain_index_rejects_malformed_documents(self):
        with self.assertRaisesRegex(Failure, "invalid_nft_json"):
            checks.nft_chains([])
        self.assertEqual(checks.nft_chains({"nftables": [1, {"chain": 2}, {"rule": 3}]}), {})
        self.assertEqual(
            checks.nft_chains({"nftables": [{"chain": {"family": "inet", "name": "x"}}]}), {}
        )
