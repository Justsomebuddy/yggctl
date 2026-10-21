"""Fail-closed health gates with synthetic kernel/daemon observations."""

from typing import Any

import dataclasses
import contextlib
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import Mock, patch

import checks
from core import Failure, NODE, KEYS, atomic, digest, logged
from test_support import ConsoleFixture, URI


class CheckEdges(ConsoleFixture):
    @logged
    def test_baseline_hash_schema(self):
        values = {k: str(i) * 64 for i, k in enumerate(checks.policy_keys(), 1)}
        path = self.paths.etc / "baseline.env"
        valid = "# comment\n\n" + "\n".join(f"{k}={v}" for k, v in values.items())
        atomic(path, valid + "\nBASELINE_AT=fixture\n")
        self.assertEqual(checks.baseline(self.ctx), dict(values, BASELINE_AT="fixture"))
        for text, label in (
            (valid + "\nBOGUS=1", "invalid_baseline"),
            (valid + "\nFW_RUNTIME_SHA=1", "invalid_baseline"),
            ("BASELINE_AT=fixture", "missing_baseline_hash"),
        ):
            atomic(path, text)
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                checks.baseline(self.ctx)
        self.assertEqual(set(checks.policy(self.ctx)), set(values))

    @logged
    def test_trusted_rejects_ancestor_ownership_write_and_links(self):
        good = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644)
        for info in (
            good,
            SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o600),
            SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777),
            SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o600),
        ):
            with patch.object(Path, "lstat", return_value=info):
                if info is good:
                    self.assertTrue(checks.trusted("/synthetic/leaf"))
                else:
                    with self.assertRaisesRegex(Failure, "untrusted_deployment_path"):
                        checks.trusted("/synthetic/leaf")

    @logged
    def test_integrity_relative_duplicate_malformed_and_mismatch(self):
        path = self.paths.etc / "integrity.manifest"
        manifest = path.read_text()
        for text, label in (
            ("bad", "invalid_integrity_manifest"),
            (manifest + manifest.splitlines()[0] + "\n", "duplicate_integrity_member"),
            (manifest.replace(manifest[:64], "0" * 64, 1), "integrity_mismatch"),
        ):
            atomic(path, text)
            with self.subTest(label=label), self.assertRaisesRegex(Failure, label):
                checks.integrity(self.ctx)
        atomic(self.paths.etc / "extra", "fixture")
        atomic(path, manifest + digest(b"fixture") + "  extra\n")
        self.assertGreater(checks.integrity(self.ctx), 8)
        self.ctx.parent_verified = frozenset({"integrity"})
        self.assertEqual(checks.integrity(self.ctx), 0)

    @logged
    def test_peer_schema_negative_values(self):
        for peer, label in (
            ({"up": True}, "invalid_peer_remote"),
            ({"up": True, "remote": URI, "latency": -1}, "invalid_peer_counter"),
            ({"up": True, "remote": URI, "bytes_sent": True}, "invalid_peer_counter"),
        ):
            self.responses["getPeers"] = {"peers": [peer]}
            with self.subTest(peer=peer), self.assertRaisesRegex(Failure, label):
                checks.peers(self.ctx)

    @logged
    def guard_config(self, name):
        config = json.loads((self.paths.etc / name).read_text())
        sock = self.paths.node_sock if name.startswith("yggdrasil") else self.paths.stack_sock
        config["AdminListen"] = "unix://" + str(sock)
        return config

    @logged
    def custody_stat(self, path, *args, **kwargs):
        mode = stat.S_IFREG | 0o600
        if path in (self.paths.node_sock, self.paths.stack_sock):
            mode = stat.S_IFSOCK | 0o600
        elif path in (self.paths.node_sock.parent, self.paths.stack_sock.parent):
            mode = stat.S_IFDIR | 0o700
        return SimpleNamespace(st_uid=0, st_mode=mode)

    @logged
    def test_guard_custody_and_socket_boundaries(self):
        self.paths = dataclasses.replace(
            self.paths,
            node_sock=Path("/run/fake/node.sock"),
            stack_sock=Path("/run/fake/stack.sock"),
        )
        self.ctx.p = self.paths
        with (
            patch.object(self.ctx, "config", side_effect=self.guard_config),
            patch.object(Path, "lstat", autospec=True, side_effect=self.custody_stat),
        ):
            self.assertIn("key custody", checks.guard(self.ctx))
        for config, label in (
            ({}, "unsafe_config"),
            (self.ctx.config("yggstack.conf"), "admin_config_mismatch"),
        ):
            with (
                patch.object(self.ctx, "config", return_value=config),
                self.assertRaisesRegex(Failure, label),
            ):
                checks.guard(self.ctx)
        for mode, label in (
            (stat.S_IFREG | 0o644, "key_permissions"),
            (stat.S_IFREG | 0o600, "admin_socket_permissions"),
        ):
            with (
                patch.object(self.ctx, "config", side_effect=self.guard_config),
                patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=0, st_mode=mode)),
                self.assertRaisesRegex(Failure, label),
            ):
                checks.guard(self.ctx)
        self.assertEqual(len(KEYS), 2)

    @logged
    def test_listener_is_stack_only_and_unique(self):
        valid = b'tcp LISTEN 0 0 127.0.0.1:1080 0.0.0.0:* users:(("stack",pid=1002,fd=1))\n'
        for data in (
            valid,
            b"",
            valid + valid,
            valid.replace(b"127.0.0.1", b"0.0.0.0"),
            valid.replace(b"1002", b"1001"),
        ):
            with (
                patch.object(self.ctx, "run", return_value=Mock(stdout=data)),
                patch.object(
                    self.ctx, "unit", side_effect=[{"MainPID": "1001"}, {"MainPID": "1002"}]
                ),
            ):
                if data == valid:
                    self.assertEqual(checks.sockets(self.ctx), "SOCKS loopback only")
                else:
                    with self.assertRaisesRegex(Failure, "unexpected_node_stack_listener"):
                        checks.sockets(self.ctx)

    @logged
    def test_underlay_bad_pids_selectors_and_unparseable_rows(self):
        with (
            patch.object(self.ctx, "unit", return_value={"MainPID": "0"}),
            self.assertRaisesRegex(Failure, "missing_runtime_pid"),
        ):
            checks.underlay(self.ctx)
        with (
            patch.object(self.ctx, "run", return_value=Mock(stdout=b"")),
            patch.object(self.ctx, "unit", return_value={"MainPID": "1001"}),
            self.assertRaisesRegex(Failure, "underlay_pid_exclusion_mismatch"),
        ):
            checks.underlay(self.ctx)
        old = self.ctx.runner

        @logged
        def malformed(argv, **kw):
            result = old(argv, **kw)
            if Path(argv[0]).name == "ss":
                result.stdout = b"short\ntcp A B C invalid invalid pid=1001,\n" + result.stdout
            return result

        self.ctx.runner = malformed
        self.assertEqual(checks.underlay(self.ctx)["mode"], "direct")

    @logged
    def test_small_gates_positive_and_negative(self):
        checks.service_gate(self.ctx, NODE)
        with (
            patch.object(self.ctx, "unit", return_value={}),
            self.assertRaisesRegex(Failure, "unit_not_stably_running"),
        ):
            checks.service_gate(self.ctx, NODE)
        with self.assertRaisesRegex(Failure, "less_than_two"):
            checks.peer_gate(self.ctx, False)
        self.ps.append(dict(self.ps[0], remote=URI.replace("192.0.2.1", "192.0.2.2")))
        checks.peer_gate(self.ctx, True)
        for method, field, good, bad, fn in (
            ("getMulticastInterfaces", "multicast_interfaces", [], [{}], checks.multicast_gate),
            ("getTun", "enabled", False, True, checks.tun_gate),
        ):
            value: object
            for value in (good, bad):
                self.responses[method] = {field: value}
                args = (self.ctx, False) if fn is checks.multicast_gate else (self.ctx,)
                if value == good:
                    fn(*args)
                else:
                    with self.assertRaises(Failure):
                        fn(*args)
        for rows in ([], [{"table": {"name": "other"}}], [{"table": {"name": "ygglab"}}]):
            with patch.object(
                self.ctx, "run", return_value=Mock(stdout=json.dumps({"nftables": rows}).encode())
            ):
                if rows and rows[0]["table"]["name"] == "ygglab":
                    with self.assertRaisesRegex(Failure, "transient_gate"):
                        checks.nft_gate(self.ctx)
                else:
                    checks.nft_gate(self.ctx)
        for data in ({"UnitFileState": "masked", "ActiveState": "inactive"}, {}):
            with patch.object(self.ctx, "unit", return_value=data):
                if data:
                    checks.masked_gate(self.ctx)
                else:
                    with self.assertRaisesRegex(Failure, "packaged_unit"):
                        checks.masked_gate(self.ctx)
        for timer, service, label in (
            ({"ActiveState": "active"}, {"ActiveState": "inactive", "ExecMainStatus": "0"}, None),
            ({}, {}, "collector_timer_inactive"),
            (
                {"ActiveState": "active"},
                {"ActiveState": "failed", "ExecMainStatus": "0"},
                "collector_failed",
            ),
            ({"ActiveState": "active"}, {"ExecMainStatus": "1"}, "collector_failed"),
        ):
            with patch.object(self.ctx, "unit", side_effect=[timer, service]):
                if label:
                    with self.assertRaisesRegex(Failure, label):
                        checks.timer_gate(self.ctx)
                else:
                    checks.timer_gate(self.ctx)

    @logged
    def test_identified_requires_up_and_a_public_key(self):
        peer = {"remote": URI, "up": True, "key": "a" * 64}
        self.assertTrue(checks.identified(peer))
        for broken in (
            dict(peer, up=False),
            dict(peer, key=""),
            dict(peer, key="A" * 64),
            dict(peer, key="a" * 63),
            dict(peer, up=1),
            {"remote": URI},
        ):
            with self.subTest(row=broken):
                self.assertFalse(checks.identified(broken))

    @logged
    def test_composite_check_runs_every_gate_even_on_failure(self):
        gates = (
            "guard",
            "integrity",
            "sockets",
            "underlay",
            "service_gate",
            "peer_gate",
            "multicast_gate",
            "tun_gate",
            "policy_gate",
            "nft_gate",
            "masked_gate",
            "timer_gate",
        )
        for emit, error in (
            (False, None),
            (True, None),
            (True, Failure("fixture")),
            (False, OSError("not_rendered")),
        ):
            with contextlib.ExitStack() as stack:
                mocks = {name: stack.enter_context(patch.object(checks, name)) for name in gates}
                mocks["guard"].side_effect = error
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if error:
                    with self.assertRaisesRegex(Failure, "health_gates_failed"):
                        checks.check(self.ctx, emit)
                else:
                    self.assertEqual(checks.check(self.ctx, emit), 15)
                self.assertEqual(sum(m.call_count for m in mocks.values()), 15)

    @logged
    def test_policy_root_trust_and_reference_failures(self):
        ref, expected, observed = self.policy_fixture()
        self.ctx.require_root = True
        current = ref.replace(b'rule family="ipv4" accept', b'rule family="ipv4" drop')
        observed["FW_RUNTIME_SHA"] = digest(current)
        with (
            patch.object(checks, "baseline", return_value=expected),
            patch.object(checks, "policy", return_value=observed),
            patch.object(checks, "trusted") as trust,
            patch.object(self.ctx, "run", return_value=Mock(stdout=current)),
            self.assertRaisesRegex(Failure, "policy_baseline_drift"),
        ):
            checks.policy_gate(self.ctx)
        trust.assert_called_once_with(self.paths.etc / "baseline-runtime-public.txt")
        self.ctx.require_root = False
        with (
            patch.object(checks, "read_regular", side_effect=OSError()),
            self.assertRaisesRegex(Failure, "mullvad_reference_unavailable"),
        ):
            checks.nft_relay_gate(self.ctx, "x", "y")

    @logged
    def test_relay_tunnel_shape_address_and_races(self):
        ref, cur, expected, observed = self.tunnel_fixture()
        for tunnel, label in (
            ([], "unsupported_mullvad_tunnel_address"),
            (("10.0.0.1",), "unsupported_mullvad_tunnel_address"),
            (("8.8.8.8", "fc00::1"), "unsupported_mullvad_tunnel_address"),
            (("10.0.0.1", "200::1"), "unsupported_mullvad_tunnel_address"),
        ):
            with self.assertRaisesRegex(Failure, label):
                checks.relay_display(ref, cur, b"1.1.1.1", tunnel)
        with self.assertRaisesRegex(Failure, "unsupported_mullvad_tunnel_slots"):
            checks.relay_display(
                ref.replace(b"chain input", b"chain other"),
                cur,
                b"1.1.1.1",
                ("10.0.0.1", "fc00::1"),
            )
        with self.assertRaisesRegex(Failure, "unsupported_mullvad_interface_addresses"):
            checks.tunnel_addresses("not bytes")
        bad: list[dict[str, Any]] = [
            {
                "ifname": "wg0-mullvad",
                "flags": ["UP"],
                "addr_info": [{"family": "inet", "scope": "global", "local": "192.0.2.1"}],
            }
        ]
        with self.assertRaisesRegex(Failure, "unsupported_mullvad_interface_addresses"):
            checks.tunnel_addresses(json.dumps(bad).encode())
        bad[0]["addr_info"][0]["local"] = "10.0.0.1"
        bad[0]["addr_info"].insert(0, {"scope": "link"})
        with self.assertRaisesRegex(Failure, "unsupported_mullvad_interface_addresses"):
            checks.tunnel_addresses(json.dumps(bad).encode())
        # A second nft/kernel observation must match the first: no enrolling races.
        with (
            patch.object(checks, "relay_display", side_effect=[False, False]),
            self.assertRaisesRegex(Failure, "policy_baseline_drift"),
        ):
            checks.nft_relay_gate(
                self.ctx, expected["NFT_MULLVAD_SHA"], observed["NFT_MULLVAD_SHA"]
            )
        self.tunnel_fixture()
        with (
            patch.object(checks, "relay_display", side_effect=[False, True]),
            patch.object(
                checks,
                "tunnel_addresses",
                side_effect=[("10.0.0.1", "fc00::1"), ("10.0.0.2", "fc00::2")],
            ),
            self.assertRaisesRegex(Failure, "mullvad_interface_changed"),
        ):
            checks.nft_relay_gate(
                self.ctx, expected["NFT_MULLVAD_SHA"], observed["NFT_MULLVAD_SHA"]
            )

    @logged
    def test_nft_second_observation_race_rejected(self):
        _, cur, expected, observed = self.tunnel_fixture()
        outputs = [self.relay_statuses[0], cur, self.address_views[0], cur + b"changed\n"]
        with (
            patch.object(self.ctx, "run", side_effect=[Mock(stdout=data) for data in outputs]),
            self.assertRaisesRegex(Failure, "mullvad_display_changed"),
        ):
            checks.nft_relay_gate(
                self.ctx, expected["NFT_MULLVAD_SHA"], observed["NFT_MULLVAD_SHA"]
            )

    @logged
    def test_relay_strict_ipv4_canonical_inputs(self):
        reference, current, _, _ = self.relay_fixture()
        for address in (b"001.1.1.1", b"1.1.1", b"1.1.1.256", b"1.1.1.1 ", b"200::1", b"\xff"):
            with (
                self.subTest(address=address),
                self.assertRaisesRegex(Failure, "invalid_mullvad_relay_address"),
            ):
                checks.relay_display(reference, current, address)
        invalid_reference = reference.replace(b"8.8.8.8", b"008.8.8.8")
        with self.assertRaisesRegex(Failure, "invalid_mullvad_relay_address"):
            checks.relay_display(invalid_reference, current, b"1.1.1.1")
