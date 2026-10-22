"""Shared synthetic console fixtures; no inherited regression test cases."""

from typing import Any

import json
from pathlib import Path

# Security review: synthetic CompletedProcess values only; no subprocess execution
import subprocess  # nosec B404
import tempfile
import unittest

from core import (
    Context,
    Failure,
    Paths,
    NODE,
    STACK,
    TIMER,
    FILES,
    KEYS,
    logged,
    digest,
    atomic,
    read_regular,
)

PIN = "1" * 64
URI = "tls://192.0.2.1:443?key=" + PIN + "&maxbackoff=30s"


@logged
def process_handoff_fixture(ctx, event_id, payload, timeout=20):
    """Flow-only fake acceptance boundary, NOT a native SimpleX qualification."""
    result = ctx.run(
        ["/usr/local/bin/simplex-alert.sh"],
        input=json.dumps(payload, ensure_ascii=False).encode(),
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise Failure("synthetic_handoff_failed")
    return 1


class ConsoleFixture(unittest.TestCase):
    """Reusable temporary state and mocked commands, never a live deployment."""

    @logged
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yggctl-test-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.paths = Paths(
            etc=root / "etc",
            units=root / "units",
            state=root / "state",
            runtime=root / "runtime",
            node_sock=root / "run/node/admin.sock",
            stack_sock=root / "run/stack/admin.sock",
            node=str(root / "node"),
            stack=str(root / "stack"),
            decoder=str(root / "decoder"),
            ctl=str(root / "ctl"),
        )
        for p in (self.paths.etc, self.paths.units, self.paths.state, self.paths.runtime):
            p.mkdir()
        self.ctx = Context(self.paths, runner=self.runner, require_root=False)
        self.responses: dict[str, Any] = {}
        self.calls = []
        self.failed_command = None
        self.ps = [{"remote": URI, "up": True, "inbound": False, "latency": 1000000, "key": PIN}]
        config = {
            "Peers": [
                URI,
                URI.replace("192.0.2.1", "192.0.2.2"),
                URI.replace("192.0.2.1", "192.0.2.3"),
            ],
            "IfName": "none",
            "Listen": [],
            "MulticastInterfaces": [],
            "InterfacePeers": {},
            "NodeInfoPrivacy": True,
            "AdminListen": "unix:///run/fake/admin.sock",
            "PrivateKeyPath": "/run/credentials/fake/key",
        }
        for n in FILES:
            atomic(
                self.paths.etc / n,
                json.dumps(config)
                if n.endswith("conf")
                else "direct\n"
                if n == "mode"
                else "fixture gate\n",
            )
        for n in (NODE, STACK, "ygg-metrics.timer", "ygg-metrics.service"):
            atomic(self.paths.units / n, "fixture unit")
        for p in (Path(self.paths.node), Path(self.paths.stack)):
            atomic(p, "fixture binary")
        for n in KEYS:
            atomic(self.paths.etc / n, "synthetic test fixture, not a key")
        required = [
            Path(self.paths.node),
            Path(self.paths.stack),
            self.paths.units / NODE,
            self.paths.units / STACK,
            *(self.paths.etc / n for n in FILES if n != "mode"),
        ]
        atomic(
            self.paths.etc / "integrity.manifest",
            "".join(digest(read_regular(p)) + "  " + str(p) + "\n" for p in required),
        )

    @logged
    def tearDown(self):
        self.tmp.cleanup()

    @logged
    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == self.paths.decoder:
            return subprocess.CompletedProcess(argv, 0, kwargs["input"], b"")
        if self.failed_command and self.failed_command in argv:
            return subprocess.CompletedProcess(argv, 1, b"", b"SECRET_DO_NOT_LOG")
        if argv[0] == self.paths.ctl:
            method = argv[3]
            default: dict[str, Any] = (
                {"peers": self.ps}
                if method == "getPeers"
                else {"key": "2" * 64}
                if method == "getSelf"
                else {}
            )
            value = self.responses.get(method, default)
            return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
        if "systemctl" in argv[0]:
            # systemd 262 renders a fired timer with a trigger timestamp; a unit that
            # never fired keeps the property empty.
            data = (
                "ActiveState=active\nSubState=running\nMainPID="
                + ("1002" if STACK in argv else "1001")
                + "\nNRestarts=0\nExecMainStatus=0\nLastTriggerUSec="
                + ("Thu 2026-10-19 10:00:00 UTC" if TIMER in argv else "")
                + "\n"
            )
        elif "mullvad" in argv[0]:
            data = "Excluded PIDs:\n1001\n1002\n"
        elif "ss" == Path(argv[0]).name:
            data = "\n".join(
                f'tcp ESTAB 0 0 10.0.0.2:{p} 192.0.2.1:443 users:(("ygg",pid={p},fd=1))'
                for p in (1001, 1002)
            )
        elif "conntrack" in argv[0]:
            data = "\n".join(
                f"tcp 6 100 ESTABLISHED src=10.0.0.2 dst=192.0.2.1 sport={p} dport=443 src=192.0.2.1 dst=10.0.0.2 sport=443 dport={p} mark=3905 use=1"
                for p in (1001, 1002)
            )
        elif "curl" in argv[0]:
            data = "200 0.001 0.05 0.1 0.2"
        else:
            data = ""
        return subprocess.CompletedProcess(argv, 0, data.encode(), b"")

    @logged
    def policy_fixture(self, current=None):
        reference = b'public (active)\n  ports: \n  rich rules: \n\trule family="ipv4" accept\n\trule family="ipv6" drop\n'
        current = current if current is not None else reference
        atomic(self.paths.etc / "baseline-runtime-public.txt", reference)
        expected = {
            "FW_RUNTIME_SHA": digest(reference),
            "FW_PERMANENT_SHA": "1" * 64,
            "NFT_MULLVAD_SHA": "2" * 64,
        }
        observed = dict(expected, FW_RUNTIME_SHA=digest(current))
        self.ctx.runner = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, current, b"")
        return reference, expected, observed

    @logged
    def relay_fixture(self, current=None):
        reference = (
            b"table inet mullvad {\n\tchain prerouting {\n"
            b"\t\tip saddr 8.8.8.8 udp sport 443 meta mark set 0x6d6f6c65\n\t}\n"
            b"\tchain output {\n"
            b"\t\tip daddr 8.8.8.8 udp dport 443 meta mark 0x6d6f6c65 accept\n\t}\n"
            b"\tchain input {\n"
            b"\t\tip saddr 8.8.8.8 udp sport 443 ct state established accept\n\t}\n}\n"
        )
        current = current if current is not None else reference.replace(b"8.8.8.8", b"1.1.1.1")
        _, expected, observed = self.policy_fixture()
        expected["NFT_MULLVAD_SHA"] = digest(reference)
        observed["NFT_MULLVAD_SHA"] = digest(current)
        atomic(self.paths.etc / "baseline-nft-mullvad.txt", reference)
        status = {
            "state": "connected",
            "details": {
                "endpoint": {
                    "protocol": "udp",
                    "tunnel_interface": "wg0-mullvad",
                    "obfuscation": {
                        "Single": {
                            "obfuscation_type": "Quic",
                            "endpoint": {"address": "1.1.1.1:443", "protocol": "udp"},
                        }
                    },
                }
            },
        }
        self.relay_table = current
        self.relay_statuses = [json.dumps(status).encode()] * 2
        self.relay_calls: list[str] = []
        original = self.ctx.runner

        @logged
        def response(argv, **kw):
            if argv == ["/usr/bin/mullvad", "status", "--json"]:
                self.relay_calls.append("status")
                return subprocess.CompletedProcess(argv, 0, self.relay_statuses.pop(0), b"")
            if argv == ["/usr/sbin/nft", "list", "table", "inet", "mullvad"]:
                self.relay_calls.append("table")
                return subprocess.CompletedProcess(argv, 0, self.relay_table, b"")
            return original(argv, **kw)

        self.ctx.runner = response
        return reference, current, expected, observed

    @logged
    def tunnel_fixture(self):
        ref, _, expected, _ = self.relay_fixture()
        ref = ref.replace(
            b"\tchain input {\n",
            b"\tchain input {\n\t\tip daddr 10.147.0.1 drop\n\t\tip6 daddr fc00::1 drop\n",
        )
        cur = ref.replace(b"8.8.8.8", b"1.1.1.1").replace(b"10.147.0.1", b"10.147.0.2")
        cur = cur.replace(b"fc00::1", b"fc00::2")
        expected["NFT_MULLVAD_SHA"] = digest(ref)
        observed = dict(expected, NFT_MULLVAD_SHA=digest(cur))
        atomic(self.paths.etc / "baseline-nft-mullvad.txt", ref)
        self.relay_table = cur
        addresses = [
            {
                "ifname": "wg0-mullvad",
                "flags": ["UP"],
                "addr_info": [
                    {"family": "inet", "scope": "global", "local": "10.147.0.2"},
                    {"family": "inet6", "scope": "global", "local": "fc00::2"},
                ],
            }
        ]
        self.address_views = [json.dumps(addresses).encode()] * 2
        previous = self.ctx.runner

        @logged
        def response(argv, **kwargs):
            if argv[0] == "/usr/sbin/ip":
                return subprocess.CompletedProcess(argv, 0, self.address_views.pop(0), b"")
            return previous(argv, **kwargs)

        self.ctx.runner = response
        return ref, cur, expected, observed

    @logged
    def prepare_forward_pending(self, count=5):
        atomic(self.paths.state / "alerts-forwarded.json", '{"sent":[]}\n', 0o600)
        atomic(
            self.paths.state / "alerts.jsonl",
            "".join(json.dumps({"id": f"a{i}", "kind": f"a{i}"}) + "\n" for i in range(count)),
            0o640,
        )
