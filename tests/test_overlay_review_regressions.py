"""Original-head-transplant controls; stable helper contracts, no host commands."""

import unittest

import checks
from core import Failure


KEY = ("inet", "mullvad", "output")


def chain(*rules):
    return {
        KEY: {
            "type": "filter",
            "hook": "output",
            "prio": 0,
            "policy": "accept",
            "rules": [{"handle": i, "expr": expr} for i, expr in enumerate(rules)],
        }
    }


class OriginalHeadRegressions(unittest.TestCase):
    def test_limit_and_quota_cannot_make_unconditional_accept(self):
        for kind in ("limit", "quota"):
            with self.subTest(kind=kind):
                state, _, _ = checks.overlay_rule([{kind: {}}, {"accept": None}], "ygg0")
                self.assertEqual(state, "unknown")

    def test_return_does_not_erase_unknown_port_predicate(self):
        port = {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                "right": 22,
            }
        }
        rules = chain([port, {"drop": None}], [{"return": None}])
        self.assertEqual(checks.overlay_chain(rules, KEY, "ygg0")["verdict"], "conditional")

    def test_unhooked_name_is_not_a_host_output_path(self):
        rules = chain([{"accept": None}])
        del rules[KEY]["hook"]
        self.assertEqual(checks.overlay_chain(rules, KEY, "ygg0")["verdict"], "unknown")

    def test_malformed_left_is_unknown_instead_of_attribute_error(self):
        try:
            actual = checks.overlay_match({"left": "x", "op": "==", "right": "ygg0"}, "ygg0")
        except AttributeError:
            actual = "attribute_error"
        self.assertEqual(actual, "unknown")

    def test_real_nft_json_prefix_schema_is_interpreted(self):
        self.assertEqual(
            checks.overlay_prefix_match({"prefix": {"addr": "200::", "len": 7}}, "=="), "match"
        )

    def test_malformed_rule_cannot_be_omitted_before_accept(self):
        with self.assertRaisesRegex(Failure, "invalid_nft_json"):
            checks.nft_chains({"nftables": [{"rule": 7}]})
