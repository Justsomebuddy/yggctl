"""Synthetic QUIC underlay observations; no sockets or network are opened."""

import json

# The fixture constructs CompletedProcess values; it never starts a process.
import subprocess  # nosec B404

import checks
from core import Failure, atomic, logged
from test_support import ConsoleFixture, PIN, URI


QUIC = "quic://192.0.2.77:19003?key=" + PIN
LISTENER = 'tcp LISTEN 0 0 127.0.0.1:1080 0.0.0.0:* users:(("stack",pid=1002,fd=1))'
SOCKETS = (
    'udp UNCONN 0 0 *:41001 *:* users:(("node",pid=1001,fd=7))',
    'udp UNCONN 0 0 *:41002 *:* users:(("stack",pid=1002,fd=8))',
)


def flow(port, destination="192.0.2.77", protocol="udp", mark="3905"):
    return (
        f"{protocol} 17 29 src=10.0.0.2 dst={destination} sport={port} dport=19003 "
        f"src={destination} dst=10.0.0.2 sport=19003 dport={port} mark={mark} use=1"
    )


class QuicUnderlay(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        config = self.ctx.config("yggdrasil-lab.conf")
        config["Peers"] = [QUIC]
        for name in ("yggdrasil-lab.conf", "yggstack.conf"):
            atomic(self.paths.etc / name, json.dumps(config))
        # Yggdrasil's urlForLinkInfo removes the configured query from getPeers.
        self.ps = [{"remote": QUIC.split("?", 1)[0], "up": True, "inbound": False, "key": PIN}]
        self.ss = [LISTENER, *SOCKETS]
        self.ct = [flow(41001), flow(41002)]
        original = self.ctx.runner

        @logged
        def runner(argv, **kwargs):
            if argv[0] == "/usr/bin/ss":
                return subprocess.CompletedProcess(argv, 0, "\n".join(self.ss).encode(), b"")
            if argv[0] == "/usr/sbin/conntrack":
                return subprocess.CompletedProcess(argv, 0, "\n".join(self.ct).encode(), b"")
            return original(argv, **kwargs)

        self.ctx.runner = runner

    @logged
    def test_quic_wildcard_socket_original_tuple_and_listener(self):
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])
        self.assertEqual(checks.sockets(self.ctx), "SOCKS loopback only")

    @logged
    def test_quic_rejects_wrong_destination_protocol_mark_and_absence(self):
        for records in (
            [flow(41001, destination="192.0.2.78"), flow(41002)],
            [flow(41001, protocol="tcp"), flow(41002)],
            [flow(41001, mark="0"), flow(41002)],
            [flow(41002)],
            [flow(41001), flow(41001), flow(41002)],
        ):
            with self.subTest(records=records):
                self.ct = records
                with self.assertRaises(Failure):
                    checks.underlay(self.ctx)
                with self.assertRaises(Failure):
                    checks.sockets(self.ctx)

    @logged
    def test_quic_rejects_unidentified_inbound_and_pin_mismatch(self):
        for peer in (
            dict(self.ps[0], key=""),
            dict(self.ps[0], inbound=True),
            dict(self.ps[0], key="2" * 64),
            dict(self.ps[0], remote="quic://192.0.2.78:19003"),
            dict(self.ps[0], remote="tcp://192.0.2.77:19003"),
        ):
            with self.subTest(peer=peer):
                self.ps = [peer]
                with self.assertRaises(Failure):
                    checks.underlay(self.ctx)

    @logged
    def test_quic_rejects_extra_unknown_or_shared_own_udp(self):
        for extra in (
            'udp UNCONN 0 0 *:41999 *:* users:(("node",pid=1001,fd=9))',
            'udp UNCONN 0 0 *:41001 *:* users:(("other",pid=9000,fd=9))',
            'udp UNCONN 0 0 *:41001 *:* users:(("node",pid=1001,fd=7),("other",pid=9000,fd=9))',
        ):
            with self.subTest(extra=extra):
                self.ss = [LISTENER, *SOCKETS, extra]
                with self.assertRaises(Failure):
                    checks.underlay(self.ctx)
                with self.assertRaises(Failure):
                    checks.sockets(self.ctx)

    @logged
    def test_foreign_conntrack_and_reply_tuple_do_not_prove_quic(self):
        self.ct = [
            flow(49999),
            "udp 17 29 src=192.0.2.77 dst=10.0.0.2 sport=19003 dport=41001 "
            "src=10.0.0.2 dst=192.0.2.77 sport=41001 dport=19003 mark=3905 use=1",
            flow(41002),
        ]
        with self.assertRaises(Failure):
            checks.underlay(self.ctx)

    @logged
    def test_unproven_udp_cannot_be_hidden_by_good_tcp(self):
        self.ss.append('tcp ESTAB 0 0 10.0.0.2:42001 192.0.2.1:443 users:(("node",pid=1001,fd=10))')
        self.ct = [
            flow(41002),
            "tcp 6 100 ESTABLISHED src=10.0.0.2 dst=192.0.2.1 sport=42001 dport=443 "
            "src=192.0.2.1 dst=10.0.0.2 sport=443 dport=42001 mark=3905 use=1",
        ]
        with self.assertRaises(Failure):
            checks.underlay(self.ctx)

    @logged
    def test_bound_ipv4_and_zero_wildcard(self):
        self.ss[1] = self.ss[1].replace("*:41001", "10.0.0.2:41001")
        self.ss[2] = self.ss[2].replace("*:41002", "0.0.0.0:41002")
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])
        self.ct[0] = self.ct[0].replace("src=10.0.0.2", "src=10.0.0.3", 1)
        with self.assertRaises(Failure):
            checks.underlay(self.ctx)

    @logged
    def test_rejects_malformed_socket_and_duplicate_ports(self):
        original = self.ss[1]
        for row in (
            original.replace("UNCONN", "ESTAB"),
            original.replace("*:*", "192.0.2.77:19003"),
            original.replace("*:41001", "*:bad"),
            original.replace("*:41001", "*:0"),
            original.replace("*:41001", "*:65536"),
            original.replace("*:41001", "bad:41001"),
            original.replace("*:41001", "*:41002"),
            original.replace("pid=1001", 'pid=1001,fd=7),("other",pid=9000'),
            "udp UNCONN pid=1001,",
        ):
            with self.subTest(row=row):
                self.ss[1] = row
                with self.assertRaises(Failure):
                    checks.underlay(self.ctx)

    @logged
    def test_rejects_missing_or_duplicate_mark_and_non_ipv4_original(self):
        original = self.ct[0]
        for record in (
            original.replace(" mark=3905", ""),
            original.replace(" mark=3905", " mark=3905 mark=3905"),
            original.replace("src=10.0.0.2", "src=bad", 1),
        ):
            with self.subTest(record=record):
                self.ct[0] = record
                with self.assertRaises(Failure):
                    checks.underlay(self.ctx)

    @logged
    def test_extra_tcp_listener_still_rejected(self):
        self.ss.append('tcp LISTEN 0 0 0.0.0.0:5555 0.0.0.0:* users:(("node",pid=1001,fd=2))')
        with self.assertRaisesRegex(Failure, "unexpected_node_stack_listener"):
            checks.sockets(self.ctx)

    @logged
    def test_mixed_configured_tcp_and_quic_still_proves_quic(self):
        for name in ("yggdrasil-lab.conf", "yggstack.conf"):
            config = self.ctx.config(name)
            config["Peers"].append(URI)
            atomic(self.paths.etc / name, json.dumps(config))
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])

    @logged
    def test_duplicate_quic_endpoint_with_different_pin_is_ambiguous(self):
        config = self.ctx.config("yggdrasil-lab.conf")
        config["Peers"].append(QUIC.replace(PIN, "2" * 64))
        atomic(self.paths.etc / "yggdrasil-lab.conf", json.dumps(config))
        with self.assertRaisesRegex(Failure, "underlay_quic_peer_ambiguous"):
            checks.underlay(self.ctx)

    @logged
    def test_tunnel_quic_accepts_unmarked_and_rejects_direct_mark(self):
        atomic(self.paths.etc / "mode", "tunnel\n")
        original = self.ctx.runner

        @logged
        def tunnel_runner(argv, **kwargs):
            if argv[0] == "/usr/bin/mullvad":
                return subprocess.CompletedProcess(argv, 0, b"Excluded PIDs:\n", b"")
            return original(argv, **kwargs)

        self.ctx.runner = tunnel_runner
        self.ct = [flow(41001, mark="42"), flow(41002, mark="42")]
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1, 1])
        self.ct[0] = flow(41001, mark="3905")
        with self.assertRaisesRegex(Failure, "underlay_quic_peer_or_mark_mismatch"):
            checks.underlay(self.ctx)
