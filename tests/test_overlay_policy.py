"""Read-only overlay policy diagnosis: firewalld zones and mullvad kill-switch."""

import argparse
import contextlib
import io
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

NFT_BLOCKED = """chain output {
\ttype filter hook output priority filter; policy drop;
\t\toif "lo" accept
\t\tip6 daddr fc00::/7 accept
\t\treject
}
"""

NFT_OK = """chain output {
\ttype filter hook output priority filter; policy drop;
\t\toif "lo" accept
\t\toifname "ygp1" accept
\t\treject
}
"""


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
                return SimpleNamespace(stdout=value.encode(), returncode=0)
            raise Failure(f"unexpected_command:{argv[0]}")

        return run

    def policy(self, links=LINKS, zones=ZONES_BLOCKED, nft=NFT_BLOCKED, interface=None):
        outputs = {"-d": links, "--get-active-zones": zones, "list": nft}
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            return checks.overlay_policy(self.ctx, interface)

    def test_unclassified_tun_and_mullvad_drop_are_both_reported(self):
        result = self.policy()
        self.assertEqual(result["interface"], "ygp1")
        self.assertIsNone(result["firewalld_zone"])
        self.assertEqual(result["mullvad_output_policy"], "drop")
        self.assertEqual(
            result["findings"],
            [
                "tun_interface_not_in_any_firewalld_zone",
                "mullvad_killswitch_rejects_overlay",
            ],
        )

    def test_trusted_zone_and_explicit_accept_clear_the_findings(self):
        result = self.policy(zones=ZONES_OK, nft=NFT_OK)
        self.assertEqual(result["firewalld_zone"], "trusted")
        self.assertEqual(result["findings"], [])

    def test_overlay_prefix_accept_also_clears_the_finding(self):
        result = self.policy(
            zones=ZONES_OK,
            nft="chain output {\n\ttype filter hook output priority filter; policy drop;\n"
            "\tip6 daddr 200::/7 accept\n}\n",
        )
        self.assertEqual(result["findings"], [])

    def test_missing_firewall_tools_are_not_reported_as_blockers(self):
        outputs = {
            "-d": LINKS,
            "--get-active-zones": Failure("external_unavailable:firewall-cmd"),
            "list": Failure("external_unavailable:nft"),
        }
        with patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)):
            result = checks.overlay_policy(self.ctx)
        self.assertEqual(result["findings"], [])
        self.assertIsNone(result["mullvad_output_policy"])

    def test_no_tun_device_is_reported(self):
        result = self.policy(links="1: lo: <LOOPBACK,UP> mtu 65536\n    link/loopback\n")
        self.assertIsNone(result["interface"])
        self.assertEqual(result["findings"], ["tun_interface_not_found"])

    def test_overlay_named_tun_is_preferred_over_the_vpn_tunnel(self):
        links = (
            "5: wg0-mullvad: <POINTOPOINT,NOARP,UP> mtu 1420\n"
            "    link/none\n    tun type tun pi off\n"
            "6: ygg0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 65535\n"
            "    link/none\n    tun type tun pi on\n"
        )
        self.assertEqual(checks.preferred_interface(checks.tun_interfaces(links)), "ygg0")
        self.assertEqual(checks.preferred_interface([]), "")

    def test_device_accepted_by_the_killswitch_needs_no_zone(self):
        result = self.policy(zones=ZONES_BLOCKED, nft=NFT_OK)
        self.assertIsNone(result["firewalld_zone"])
        self.assertEqual(result["findings"], [])

    def test_explicit_interface_overrides_detection(self):
        result = self.policy(interface="other0")
        self.assertEqual(result["interface"], "other0")

    def test_cli_prints_the_findings(self):
        outputs = {"-d": LINKS, "--get-active-zones": ZONES_OK, "list": NFT_OK}
        out = io.StringIO()
        with (
            patch.object(self.ctx, "run", side_effect=self.fake_run(outputs)),
            contextlib.redirect_stdout(out),
        ):
            main.do_overlay_policy(self.ctx, argparse.Namespace(command="overlay-policy"), [])
        self.assertIn('"findings": []', out.getvalue())
        self.assertIn('"interface": "ygp1"', out.getvalue())

    def test_zone_parser_ignores_empty_and_header_lines(self):
        self.assertEqual(
            checks.zone_interfaces(
                "  interfaces: before-any-zone\n\npublic (default)\n  interfaces: a b\n"
                "\ntrusted\n  interfaces:\n  interfaces: c\n"
            ),
            {"a": "public", "b": "public", "c": "trusted"},
        )

    def test_mullvad_verdict_without_policy_line_is_not_a_blocker_signal(self):
        verdict = checks.mullvad_overlay_verdict("chain output {\n}\n", "ygp1")
        self.assertEqual(verdict, {"policy": "", "allows_overlay": False})
