"""Fail-closed structured health checks, including PID-bound underlay proof."""

from pathlib import Path
from typing import Any
import ipaddress
import math
import json
import re
import stat
import errno
import os
import time
import urllib.parse

from core import (
    Failure,
    NODE,
    STACK,
    TIMER,
    KEYS,
    read_regular,
    logged,
    event,
    digest,
    safe_config,
    endpoint,
    peer_uri,
)

# The collector runs once a minute and retains 10,000 samples (about a week), so a
# frozen file keeps serving history long after collection stopped. 72 h is the longest
# report window, PEER_DOWN_MINUTES is 10; 15 minutes tolerates a short collector outage
# while still failing a file that a stopped or never-triggered collector left behind.
# There is no runtime override: this project fixes paths, units and thresholds in code
# and deliberately reads no environment variables.
COLLECTOR_MAX_AGE_MINUTES = 15

# ss renders wildcard UDP addresses in either form. These values only compare
# observed socket rows; they never bind or create a network listener.
UDP_WILDCARD_BINDS = ("*", "0.0.0.0")  # nosec B104
UDP_WILDCARD_REMOTES = tuple(f"{address}:*" for address in UDP_WILDCARD_BINDS)


@logged
def peers(ctx, stack=False):
    rows = ctx.api("getPeers", stack=stack).get("peers")
    if not isinstance(rows, list) or any(
        not isinstance(p, dict) or type(p.get("up")) is not bool for p in rows
    ):
        raise Failure("invalid_peer_schema")
    for p in rows:
        if not isinstance(p.get("remote"), str):
            raise Failure("invalid_peer_remote")
        for field in ("latency", "bytes_recvd", "bytes_sent"):
            value = p.get(field, 0)
            # NaN passes `value < 0`, is written back by json.dumps as a bare NaN token
            # and breaks every non-Python reader of metrics.jsonl (research already
            # rejects non-finite latency).
            try:
                valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
            except OverflowError:
                # JSON integers may exceed float range; latency conversion and
                # downstream numerical consumers cannot represent those values.
                valid = False
            if not valid:
                raise Failure("invalid_peer_counter")
    return rows


@logged
def identified(peer):
    """A row is a peer only after the handshake gave it a public key.

    getPeers reports up:true as soon as the transport connects, with an empty key,
    so transport-only rows must not feed availability, alerts or convergence waits.
    """
    public_key = peer.get("key")
    return (
        peer.get("up") is True
        and isinstance(public_key, str)
        and re.fullmatch(r"[0-9a-f]{64}", public_key) is not None
    )


@logged
def policy(ctx):
    return {
        "FW_RUNTIME_SHA": digest(
            ctx.run(["/usr/bin/firewall-cmd", "--zone=public", "--list-all"]).stdout
        ),
        "FW_PERMANENT_SHA": digest(
            ctx.run(["/usr/bin/firewall-cmd", "--permanent", "--zone=public", "--list-all"]).stdout
        ),
        "NFT_MULLVAD_SHA": digest(
            ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout
        ),
    }


@logged
def baseline(ctx):
    values = {}
    for line in read_regular(ctx.p.etc / "baseline.env").decode().splitlines():
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            if k in values or k not in {
                "FW_RUNTIME_SHA",
                "FW_PERMANENT_SHA",
                "NFT_MULLVAD_SHA",
                "BASELINE_AT",
            }:
                raise Failure("invalid_baseline")
            values[k] = v
    for k in policy_keys():
        if not re.fullmatch("[0-9a-f]{64}", values.get(k, "")):
            raise Failure("missing_baseline_hash")
    return values


@logged
def policy_keys():
    return ("FW_RUNTIME_SHA", "FW_PERMANENT_SHA", "NFT_MULLVAD_SHA")


@logged
def trusted(path):
    """Reject a writable or symlink ancestor, not just the leaf owner."""
    path = Path(path)
    for p in (path, *path.parents):
        s = p.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise Failure("untrusted_deployment_path")
    return True


@logged
def state_member(path, *, directory=False, mode=None, optional=False):
    """Admit existing privileged state without silently repairing its permissions."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return
        raise
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or (not directory and info.st_nlink != 1)
        or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
    ):
        raise Failure("untrusted_state_custody")
    for name in (
        ("system.posix_acl_access", "system.posix_acl_default")
        if directory
        else ("system.posix_acl_access",)
    ):
        event("external_start", "state_acl_read")
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                event("external_error", "state_acl_read", type(exc).__name__)
                raise Failure("state_acl_unavailable") from None
            event("external_exit", "state_acl_read", "absent")
        else:
            event("external_exit", "state_acl_read", "present")
            raise Failure("state_extended_acl_requires_review")


@logged
def state_custody(ctx):
    """Root-only state is pre-provisioned; role-owned research/atlas are separate."""
    root = ctx.p.state
    for path in (root, *root.parents):
        state_member(path, directory=True)
    for name, mode in (
        (".console.lock", 0o600),
        (".worker.lock", 0o600),
        ("alert-state.json", 0o600),
        ("alerts-forwarded.json", 0o600),
        ("simplex-attempts.json", 0o600),
        ("alerts.jsonl", 0o640),
        ("metrics.jsonl", 0o640),
        ("notify.state", 0o644),
    ):
        state_member(root / name, mode=mode, optional=True)
    event("state", "state_custody", "existing_permissions_accepted_no_repair")


@logged
def integrity(ctx):
    if "integrity" in ctx.parent_verified:
        return 0
    manifest = read_regular(ctx.p.etc / "integrity.manifest").decode()
    checked = set()
    for line in manifest.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not m:
            raise Failure("invalid_integrity_manifest")
        path = Path(m[2])
        if not path.is_absolute():
            path = ctx.p.etc / path
        if path in checked:
            raise Failure("duplicate_integrity_member")
        if ctx.require_root:
            trusted(path)
        if digest(read_regular(path, limit=256 * 1024 * 1024)) != m[1]:
            raise Failure("integrity_mismatch")
        checked.add(path)
    required = {
        Path(ctx.p.node),
        Path(ctx.p.stack),
        ctx.p.units / NODE,
        ctx.p.units / STACK,
        ctx.p.etc / "yggdrasil-lab.conf",
        ctx.p.etc / "yggstack.conf",
        ctx.p.etc / "gate.nft",
        ctx.p.etc / "gate-yggstack.nft",
    }
    if ctx.require_root:
        required |= {
            ctx.p.units / TIMER,
            ctx.p.units / "ygg-metrics.service",
            Path("/usr/bin/yggctl"),
            ctx.p.runtime / "main.py",
            ctx.p.runtime / "core.py",
            ctx.p.runtime / "checks.py",
            ctx.p.runtime / "management.py",
            ctx.p.runtime / "telemetry.py",
            ctx.p.runtime / "recovery.py",
            ctx.p.runtime / "tests.py",
            ctx.p.runtime / "test_support.py",
            ctx.p.runtime / "rotate.py",
            ctx.p.runtime / "sandbox.py",
            ctx.p.runtime / "broker.py",
            ctx.p.runtime / "simplex_sender.py",
            ctx.p.units / "ygg-alert-forward.service",
            ctx.p.units / "ygg-alert-forward.path",
            Path("/etc/sysusers.d/ygglab-worker.conf"),
            Path("/usr/local/bin/yggctl"),
            Path(ctx.p.decoder),
            ctx.p.etc / "mode",
            ctx.p.etc / "baseline.env",
        }
        required.add(ctx.p.etc / "baseline-runtime-public.txt")
        required.add(ctx.p.etc / "baseline-nft-mullvad.txt")
        required |= {
            ctx.p.runtime / "research" / n
            for n in ("__init__.py", "model.py", "metrics.py", "tests.py")
        }
        required |= {
            ctx.p.runtime / "atlas" / n
            for n in (
                "__init__.py",
                "store.py",
                "protocol.py",
                "catalogue.py",
                "acquisition.py",
                "analysis.py",
                "viewer.py",
                "tests.py",
            )
        }
    if not required <= checked:
        raise Failure("integrity_coverage_incomplete")
    return len(checked)


@logged
def quic_socket_proof(ctx, pids, socket_lines, conn_lines, mode):
    """Correlate observed outbound QUIC, own UDP port and ORIGINAL IPv4 tuple.

    This is a sampled state check. It cannot attest prior/future packets or kernel
    file-descriptor history. Any port-sharing or unmatched own UDP fails closed.
    """
    udp_rows = []
    for line in socket_lines:
        fields = line.split()
        if fields and fields[0] == "udp":
            udp_rows.append((line, fields))
    own = [
        (line, fields)
        for line, fields in udp_rows
        if any(re.search(rf"\bpid={pid},", line) for pid in pids)
    ]
    proof = dict.fromkeys(pids, 0)
    if not own:
        return proof
    targets = {}
    for stack, pid in ((False, pids[0]), (True, pids[1])):
        configured = {}
        for uri in ctx.config("yggstack.conf" if stack else "yggdrasil-lab.conf")["Peers"]:
            if not uri.startswith("quic://"):
                continue
            _, remote = peer_uri(uri)
            parsed = urllib.parse.urlsplit(uri)
            selector = (remote, parsed.path)
            pin = urllib.parse.parse_qs(parsed.query)["key"][0].lower()
            if selector in configured:
                raise Failure("underlay_quic_peer_ambiguous")
            configured[selector] = pin
        live = set()
        for peer in peers(ctx, stack=stack):
            uri = peer["remote"]
            parsed = urllib.parse.urlsplit(uri)
            if (
                parsed.scheme != "quic"
                or parsed.query
                or parsed.fragment
                or not identified(peer)
                or peer.get("inbound")
            ):
                continue
            selector = (endpoint(uri), parsed.path)
            if peer["key"].lower() == configured.get(selector):
                remote = selector[0]
                live.add(remote)
        targets[pid] = live
    used_ports = set()
    for line, fields in own:
        owners = {int(p) for p in re.findall(r"\bpid=(\d+),", line)}
        if (
            len(fields) < 6
            or len(owners) != 1
            or fields[1] != "UNCONN"
            or fields[5] not in UDP_WILDCARD_REMOTES
        ):
            raise Failure("underlay_quic_socket_ambiguous")
        pid = next(iter(owners))
        try:
            local_ip, port = fields[4].rsplit(":", 1)
            if not port.isdecimal() or not 0 < int(port) <= 65535:
                raise ValueError
            if local_ip not in UDP_WILDCARD_BINDS:
                ipaddress.IPv4Address(local_ip)
        except ValueError:
            raise Failure("underlay_quic_socket_ambiguous") from None
        if port in used_ports or any(
            other_line != line and re.search(rf":{re.escape(port)}(?:\s|$)", other_fields[4])
            for other_line, other_fields in udp_rows
            if len(other_fields) >= 5
        ):
            raise Failure("underlay_quic_socket_ambiguous")
        used_ports.add(port)
        matches = []
        for record in conn_lines:
            parts = record.split()
            if not parts or parts[0] != "udp":
                continue
            original = re.search(
                r"\bsrc=([^ ]+) dst=([^ ]+) sport=(\d+) dport=(\d+)(?:\s|$)", record
            )
            if not original or original[3] != port:
                continue
            src, dst, sport, dport = original.groups()
            if local_ip not in UDP_WILDCARD_BINDS and src != local_ip:
                continue
            try:
                ipaddress.IPv4Address(src)
                ipaddress.IPv4Address(dst)
            except ValueError:
                raise Failure("underlay_quic_socket_ambiguous") from None
            marks = re.findall(r"\bmark=(\d+)\b", record)
            if (
                f"{dst}:{dport}" not in targets[pid]
                or len(marks) != 1
                or (marks[0] == "3905") != (mode == "direct")
            ):
                raise Failure("underlay_quic_peer_or_mark_mismatch")
            matches.append(record)
        if len(matches) != 1:
            raise Failure("underlay_quic_socket_proof_missing_or_ambiguous")
        proof[pid] += 1
    return proof


@logged
def underlay(ctx):
    mode = ctx.mode()
    pids = [int(ctx.unit(u).get("MainPID", "0")) for u in (NODE, STACK)]
    if not all(p > 0 for p in pids):
        raise Failure("missing_runtime_pid")
    split_list = ctx.run(["/usr/bin/mullvad", "split-tunnel", "list"]).stdout.decode()
    exclusions = set(re.findall(r"(?m)^\s*(\d+)\s*$", split_list))
    if any((str(p) in exclusions) != (mode == "direct") for p in pids):
        raise Failure("underlay_pid_exclusion_mismatch")
    # Bind conntrack evidence to the local/remote four-tuple of each own socket.
    sockets = ctx.run(["/usr/bin/ss", "-H", "-antup"]).stdout.decode().splitlines()
    conn = ctx.run(["/usr/sbin/conntrack", "-L"]).stdout.decode().splitlines()
    proof = quic_socket_proof(ctx, pids, sockets, conn, mode)
    for line in sockets:
        fields = line.split()
        if len(fields) < 6:
            continue
        if fields[0] == "udp" or fields[1] == "LISTEN":
            continue
        for pid in pids:
            if not re.search(rf"\bpid={pid},", line):
                continue
            local, remote = fields[4:6]
            try:
                src, sport = local.rsplit(":", 1)
                dst, dport = remote.rsplit(":", 1)
            except ValueError:
                continue
            prefix = f"src={src} dst={dst} sport={sport} dport={dport}"
            matches = [r for r in conn if prefix + " " in r and r.split()[0] == fields[0]]
            if any(bool(re.search(r"\bmark=3905\b", r)) == (mode == "direct") for r in matches):
                proof[pid] += 1
    tcp_peer_marks(ctx, pids, sockets, conn, mode)
    if not all(proof.values()):
        raise Failure("underlay_own_socket_proof_missing")
    return {"mode": mode, "own_connections": list(proof.values())}


@logged
def guard(ctx):
    if ctx.require_root:
        state_custody(ctx)
    for name in ("yggdrasil-lab.conf", "yggstack.conf"):
        config = ctx.config(name)
        if safe_config(config):
            raise Failure("unsafe_config")
        expected = ctx.p.node_sock if name.startswith("yggdrasil") else ctx.p.stack_sock
        if config.get("AdminListen") != f"unix://{expected}":
            raise Failure("admin_config_mismatch")
    for name in KEYS:
        s = (ctx.p.etc / name).lstat()
        if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o600 or s.st_uid != 0:
            raise Failure("key_permissions")
    for sock in (ctx.p.node_sock, ctx.p.stack_sock):
        s, d = sock.lstat(), sock.parent.lstat()
        # DynamicUser owns its runtime directory; root can access it, others cannot.
        if not stat.S_ISSOCK(s.st_mode) or stat.S_IMODE(d.st_mode) != 0o700:
            raise Failure("admin_socket_permissions")
    return "hardened config and key custody"


@logged
def sockets(ctx):
    lines = ctx.run(["/usr/bin/ss", "-H", "-antup"]).stdout.decode().splitlines()
    pids = [int(ctx.unit(u).get("MainPID", "0")) for u in (NODE, STACK)]
    own = [
        line
        for line in lines
        if line.startswith("tcp ")
        and " LISTEN " in line
        and any(re.search(rf"\bpid={p},", line) for p in pids if p)
    ]
    if len(own) != 1 or own[0].split()[4] != "127.0.0.1:1080" or f"pid={pids[1]}," not in own[0]:
        raise Failure("unexpected_node_stack_listener")
    if any(
        line.startswith("udp ") and any(re.search(rf"\bpid={p},", line) for p in pids if p)
        for line in lines
    ):
        conn = ctx.run(["/usr/sbin/conntrack", "-L"]).stdout.decode().splitlines()
        quic_socket_proof(ctx, pids, lines, conn, ctx.mode())
    return "SOCKS loopback only"


@logged
def check(ctx, emit=True):
    ctx.root()
    gates = [
        ("config/keys/admin", guard),
        ("integrity/root trust", integrity),
        ("listeners", sockets),
        ("underlay own sockets", underlay),
    ]
    for u in (NODE, STACK):
        gates.append((u, lambda c, u=u: service_gate(c, u)))
    for stack in (False, True):
        gates.append(("stack peers" if stack else "node peers", lambda c, s=stack: peer_gate(c, s)))
        gates.append(
            (
                "stack no multicast" if stack else "node no multicast",
                lambda c, s=stack: multicast_gate(c, s),
            )
        )
    gates += [
        ("no TUN", tun_gate),
        ("firewall baseline", policy_gate),
        ("no transient gates", nft_gate),
        ("packaged masked", masked_gate),
        ("collector timer", timer_gate),
    ]
    failures = []
    start = time.monotonic()
    for i, (label, fn) in enumerate(gates, 1):
        try:
            fn(ctx)
            result = "PASS"
        except (Failure, OSError, ValueError, KeyError) as exc:
            failures.append(label)
            result = f"FAIL {exc}" if isinstance(exc, Failure) else "FAIL unavailable/invalid"
        if emit:
            print(f"[{i}/{len(gates)}] {label}: {result}; remaining={len(gates) - i}", flush=True)
    if emit:
        print(
            f"CHECK {'FAIL' if failures else 'PASS'} processed={len(gates)} errors={len(failures)} "
            f"elapsed={time.monotonic() - start:.2f}s"
        )
    if failures:
        raise Failure("health_gates_failed")
    return len(gates)


@logged
def service_gate(ctx, unit):
    u = ctx.unit(unit)
    if (
        u.get("ActiveState") != "active"
        or u.get("SubState") != "running"
        or int(u.get("NRestarts", "1"))
    ):
        raise Failure("unit_not_stably_running")


@logged
def peer_gate(ctx, stack):
    rows = peers(ctx, stack)
    expected = set(ctx.config("yggstack.conf" if stack else "yggdrasil-lab.conf")["Peers"])
    # A transport-only link reports up:true before the handshake and carries no public key;
    # it is not a peer (research/atlas already skip such rows for the same reason).
    up = {endpoint(p.get("remote", "")) for p in rows if identified(p) and not p.get("inbound")}
    if len(up & {endpoint(p) for p in expected}) < 2:
        raise Failure("less_than_two_configured_peers_up")


@logged
def multicast_gate(ctx, stack):
    if ctx.api("getMulticastInterfaces", stack=stack).get("multicast_interfaces") != []:
        raise Failure("multicast_unknown_or_nonempty")


@logged
def tun_gate(ctx):
    if ctx.api("getTun").get("enabled") is not False:
        raise Failure("tun_unknown_or_enabled")


@logged
def runtime_display(data):
    """Normalize ONLY the unordered trailing rich-rule display, never nft order.

    All zone fields and every rule byte stay significant. This is not a policy
    parser: unsupported formatting, duplicates or control bytes fail closed.
    """
    marker = b"  rich rules: \n"
    if (
        not isinstance(data, bytes)
        or len(data) > 65536
        or not data.endswith(b"\n")
        or data.count(marker) != 1
        or any(c < 32 and c not in (9, 10) for c in data)
        or b"\x7f" in data
    ):
        raise Failure("invalid_runtime_display")
    prefix, tail = data.split(marker)
    rules = tail.splitlines(keepends=True)
    if (
        len(rules) > 256
        or len(rules) != len(set(rules))
        or any(
            not r.startswith(b"\trule ") or not r.endswith(b"\n") or b"\t" in r[1:] for r in rules
        )
    ):
        raise Failure("invalid_runtime_rich_rules")
    return prefix + marker + b"".join(sorted(rules))


@logged
def quic_relay(data):
    """Only the connected local daemon's supported IPv4/UDP443 QUIC endpoint."""
    if not isinstance(data, bytes) or len(data) > 65536:
        raise Failure("invalid_mullvad_status")
    try:
        status = json.loads(data)
        tunnel = status["details"]["endpoint"]
        obfuscation = tunnel["obfuscation"]
        single = obfuscation["Single"]
        relay = single["endpoint"]
        address = relay["address"]
        if (
            status["state"] != "connected"
            or tunnel["protocol"] != "udp"
            or tunnel["tunnel_interface"] != "wg0-mullvad"
            or set(obfuscation) != {"Single"}
            or single["obfuscation_type"] != "Quic"
            or relay["protocol"] != "udp"
            or not isinstance(address, str)
            or not address.endswith(":443")
        ):
            raise ValueError
        ip = ipaddress.IPv4Address(address[:-4])
        if not ip.is_global or address != f"{ip}:443":
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Failure("unsupported_mullvad_relay_status") from None
    return str(ip).encode("ascii")


@logged
def relay_display(reference, current, relay, tunnel=None):
    """Replace three relay slots and optional two INPUT slots; all other bytes exact.

    No nft parsing/canonicalization: order, ports, marks, interfaces and verdicts
    remain significant. The caller must first anchor reference to the old SHA.
    """
    for data in (reference, current):
        if (
            not isinstance(data, bytes)
            or len(data) > 65536
            or not data.endswith(b"\n")
            or any(c < 32 and c not in (9, 10) for c in data)
            or b"\x7f" in data
        ):
            raise Failure("invalid_mullvad_display")
    slots = (
        (b"ip saddr ", b" udp sport 443 meta mark set 0x6d6f6c65"),
        (b"ip daddr ", b" udp dport 443 meta mark 0x6d6f6c65 accept"),
        (b"ip saddr ", b" udp sport 443 ct state established accept"),
    )
    addresses = []
    for prefix, suffix in slots:
        pattern = b"^\\t\\t" + re.escape(prefix) + rb"([0-9.]+)" + re.escape(suffix) + b"\\n"
        matches = re.findall(pattern, reference, re.MULTILINE)
        if len(matches) != 1:
            raise Failure("unsupported_mullvad_reference_slots")
        addresses.extend(matches)
    old = addresses[0]
    if len(set(addresses)) != 1 or reference.count(old) != 3:
        raise Failure("unsupported_mullvad_reference_slots")
    try:
        # IPv4Address(str) already rejects non-canonical dotted decimal (including
        # leading zeroes). Rechecking str(parsed) introduced unreachable branches;
        # retain both strict parses and their shared fail-closed error boundary.
        ipaddress.IPv4Address(old.decode("ascii"))
        ipaddress.IPv4Address(relay.decode("ascii"))
    except (ValueError, UnicodeError, AttributeError):
        raise Failure("invalid_mullvad_relay_address") from None
    candidate = reference.replace(old, relay)
    if tunnel is not None:
        if (
            not isinstance(tunnel, tuple)
            or len(tunnel) != 2
            or any(not isinstance(a, str) for a in tunnel)
        ):
            raise Failure("unsupported_mullvad_tunnel_address")
        # Anchor slots to the INPUT chain of the accepted reference, not arbitrary drop rules.
        marker = b"\tchain input {\n"
        if reference.count(marker) != 1:
            raise Failure("unsupported_mullvad_tunnel_slots")
        body = reference.split(marker, 1)[1].split(b"\t}\n", 1)[0]
        for family, address in zip((b"ip", b"ip6"), tunnel, strict=True):
            pattern = rb"(?m)^\t\t" + family + rb" daddr ([0-9a-f:.]+) drop\n"
            matches = list(re.finditer(pattern, reference))
            if len(matches) != 1 or matches[0][0] not in body:
                raise Failure("unsupported_mullvad_tunnel_slots")
            previous = matches[0][1]
            try:
                version = 4 if family == b"ip" else 6
                for value in (previous.decode("ascii"), address):
                    parsed = ipaddress.ip_address(value)
                    network = "10.0.0.0/8" if version == 4 else "fc00::/7"
                    if (
                        parsed.version != version
                        or str(parsed) != value
                        or parsed not in ipaddress.ip_network(network)
                    ):
                        raise ValueError
            except (ValueError, UnicodeError, TypeError):
                raise Failure("unsupported_mullvad_tunnel_address") from None
            candidate = candidate.replace(
                matches[0][0],
                b"\t\t" + family + b" daddr " + address.encode("ascii") + b" drop\n",
                1,
            )
    return candidate == current


@logged
def tunnel_addresses(data):
    """Independent kernel observation, not addresses learned from the nft table."""
    if not isinstance(data, bytes) or len(data) > 65536:
        raise Failure("unsupported_mullvad_interface_addresses")
    try:
        rows = json.loads(data)
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError
        row = rows[0]
        if (
            row["ifname"] != "wg0-mullvad"
            or not isinstance(row["flags"], list)
            or "UP" not in row["flags"]
        ):
            raise ValueError
        found: dict[str, list[str]] = {"inet": [], "inet6": []}
        for addr in row["addr_info"]:
            if addr.get("scope") != "global":
                continue
            family = addr["family"]
            if (
                family not in found
                or any(addr.get(f) for f in ("tentative", "dadfailed", "deprecated"))
                or not isinstance(addr.get("flags", []), list)
                or any(f in addr.get("flags", []) for f in ("tentative", "dadfailed", "deprecated"))
            ):
                raise ValueError
            ip = ipaddress.ip_address(addr["local"])
            version = 4 if family == "inet" else 6
            network = "10.0.0.0/8" if version == 4 else "fc00::/7"
            if (
                ip.version != version
                or str(ip) != addr["local"]
                or ip not in ipaddress.ip_network(network)
                or addr.get("valid_life_time", 1) == 0
            ):
                raise ValueError
            found[family].append(str(ip))
        if any(len(values) != 1 for values in found.values()):
            raise ValueError
        return found["inet"][0], found["inet6"][0]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Failure("unsupported_mullvad_interface_addresses") from None


@logged
def nft_relay_gate(ctx, expected, observed):
    path = ctx.p.etc / "baseline-nft-mullvad.txt"
    if ctx.require_root:
        trusted(path)
    try:
        reference = read_regular(path, limit=65536)
    except OSError:
        raise Failure("mullvad_reference_unavailable") from None
    if digest(reference) != expected:
        raise Failure("mullvad_reference_not_accepted_baseline")
    relay = quic_relay(ctx.run(["/usr/bin/mullvad", "status", "--json"]).stdout)
    current = ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout
    if digest(current) != observed:
        raise Failure("mullvad_display_changed_during_check")
    if not relay_display(reference, current, relay):
        command = ["/usr/sbin/ip", "-j", "addr", "show", "dev", "wg0-mullvad"]
        before = tunnel_addresses(ctx.run(command).stdout)
        current = ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout
        if digest(current) != observed:
            raise Failure("mullvad_display_changed_during_check")
        if not relay_display(reference, current, relay, before):
            raise Failure("policy_baseline_drift_do_not_auto_accept")
        if tunnel_addresses(ctx.run(command).stdout) != before:
            raise Failure("mullvad_interface_changed_during_check")
    if quic_relay(ctx.run(["/usr/bin/mullvad", "status", "--json"]).stdout) != relay:
        raise Failure("mullvad_relay_changed_during_check")
    event("state", "mullvad_policy", "legacy_anchored_local_quic_and_tunnel_addresses")


@logged
def policy_gate(ctx):
    expected = baseline(ctx)
    observed = policy(ctx)
    if observed["FW_PERMANENT_SHA"] != expected["FW_PERMANENT_SHA"]:
        raise Failure("policy_baseline_drift_do_not_auto_accept")
    if observed["NFT_MULLVAD_SHA"] != expected["NFT_MULLVAD_SHA"]:
        nft_relay_gate(ctx, expected["NFT_MULLVAD_SHA"], observed["NFT_MULLVAD_SHA"])
    if observed["FW_RUNTIME_SHA"] == expected["FW_RUNTIME_SHA"]:
        event("state", "runtime_policy", "exact_legacy_hash")
        return
    # Legacy SHA is authoritative; never enroll a current observation as accepted.
    path = ctx.p.etc / "baseline-runtime-public.txt"
    if ctx.require_root:
        trusted(path)
    reference = read_regular(path, limit=65536)
    if digest(reference) != expected["FW_RUNTIME_SHA"]:
        raise Failure("runtime_reference_not_accepted_baseline")
    current = ctx.run(["/usr/bin/firewall-cmd", "--zone=public", "--list-all"]).stdout
    if digest(current) != observed["FW_RUNTIME_SHA"]:
        raise Failure("runtime_display_changed_during_check")
    if runtime_display(reference) != runtime_display(current):
        raise Failure("policy_baseline_drift_do_not_auto_accept")
    event("state", "runtime_policy", "legacy_anchored_rule_permutation")


@logged
def nft_gate(ctx):
    data = json.loads(ctx.run(["/usr/sbin/nft", "-j", "list", "tables"]).stdout)
    if any(e.get("table", {}).get("name") in ("ygglab", "yggstack-gate") for e in data["nftables"]):
        raise Failure("transient_gate_left_active")


@logged
def masked_gate(ctx):
    for u in ("yggdrasil.service", "yggdrasil-default-config.service"):
        v = ctx.unit(u)
        if v.get("UnitFileState") != "masked" or v.get("ActiveState") != "inactive":
            raise Failure("packaged_unit_unmasked_or_running")


@logged
def collector_freshness(ctx):
    """Require recent, non-future file metadata as a bounded freshness heuristic.

    systemd reports a oneshot that never ran as ActiveState=inactive, Result=success and
    ExecMainStatus=0, so service state alone cannot prove that samples are still written.
    A missing, empty, non-regular or future-stamped file is not such evidence either.
    """
    path = ctx.p.state / "metrics.jsonl"
    try:
        info = path.lstat()
    except OSError:
        raise Failure("collector_data_missing") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise Failure("collector_data_missing")
    # Do not turn a future timestamp into freshness by taking its absolute age.
    # This checks file-write metadata, not sample correctness or authenticity.
    age = time.time() - info.st_mtime
    if age < 0:
        raise Failure("collector_data_future_timestamp")
    if age > COLLECTOR_MAX_AGE_MINUTES * 60:
        raise Failure("collector_data_stale")


@logged
def timer_gate(ctx):
    t = ctx.unit(TIMER)
    if t.get("ActiveState") != "active":
        raise Failure("collector_timer_inactive")
    # An active timer that never fired renders LastTriggerUSec as an empty value, not as
    # "0"; "n/a" is systemd's other rendering of "no value" and a missing or non-string
    # property is not proof of a trigger.
    triggered = t.get("LastTriggerUSec")
    if not isinstance(triggered, str) or triggered.strip().lower() in ("", "0", "n/a"):
        raise Failure("collector_never_fired")
    u = ctx.unit("ygg-metrics.service")
    if u.get("ActiveState") == "failed" or u.get("ExecMainStatus") != "0":
        raise Failure("collector_failed")
    collector_freshness(ctx)


@logged
def tcp_peer_marks(ctx, pids, sockets, conn, mode):
    """Reject contradictory/missing evidence for configured outbound TCP peers.

    Only the original conntrack direction can prove an outbound connection.
    Local SOCKS clients, listeners and unrelated records are outside this check.
    This is a point-in-time observation, not a route or lifetime guarantee.
    """
    for pid, name in zip(pids, ("yggdrasil-lab.conf", "yggstack.conf")):
        destinations = {
            endpoint(uri)
            for uri in ctx.config(name)["Peers"]
            if uri.startswith(("tcp://", "tls://", "ws://", "wss://"))
        }
        for line in sockets:
            fields = line.split()
            if (
                len(fields) < 6
                or fields[:2] != ["tcp", "ESTAB"]
                or not re.search(rf"\bpid={pid},", line)
                or fields[5] not in destinations
                or (name == "yggstack.conf" and fields[4] == "127.0.0.1:1080")
            ):
                continue
            src, sport = fields[4].rsplit(":", 1)
            dst, dport = fields[5].rsplit(":", 1)
            expected = (src, dst, sport, dport)
            marks = []
            for row in conn:
                original = re.search(r"\bsrc=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)", row)
                if (
                    not row.startswith("tcp ")
                    or " ESTABLISHED " not in row
                    or original is None
                    or original.groups() != expected
                ):
                    continue
                mark = re.findall(r"\bmark=(\d+)\b", row)
                if len(mark) != 1:
                    raise Failure("underlay_peer_socket_proof_missing")
                marks.append(mark[0] == "3905")
            if not marks:
                raise Failure("underlay_peer_socket_proof_missing")
            if any(mark != (mode == "direct") for mark in marks):
                raise Failure("underlay_peer_mark_mismatch")


# Overlay policy diagnosis: a read-only, static interpretation of the effective
# nftables ruleset. It does not inject packets and never edits rules. Text output
# is parsed for firewalld zones only; nft rules come from the JSON schema, so a
# rule that only matches source addresses, a negated prefix, a port or an
# unreachable accept cannot be mistaken for a general overlay allowance.
OVERLAY_PREFIX = ipaddress.ip_network("200::/7")
OVERLAY_SAMPLE = ipaddress.ip_address("200::1")
OVERLAY_MAX_DEPTH = 4
OVERLAY_PATH_LIMIT = 64
OVERLAY_TERMINAL = ("accept", "drop", "reject")
OVERLAY_NON_MATCH = ("counter", "log", "comment", "limit", "quota", "notrack")


@logged
def zone_interfaces(text):
    """Interface -> zone from `firewall-cmd --get-active-zones` output."""
    zones: dict[str, str] = {}
    zone = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            zone = line.split()[0]
            continue
        name, _, value = line.strip().partition(":")
        if name == "interfaces" and zone:
            for interface in value.split():
                zones[interface] = zone
    return zones


@logged
def tun_interfaces(text):
    """TUN device names from `ip -d link show` output, in kernel order."""
    names = []
    current = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            current = line.split(":", 2)[1].strip() if ":" in line else ""
        elif current and "tun type tun" in line:
            names.append(current)
    return names


@logged
def preferred_interface(devices):
    """Prefer an overlay-looking TUN name over tunnel devices such as wg0-mullvad."""
    for name in devices:
        if name.startswith(("ygg", "yg", "tun")):
            return name
    return devices[0] if devices else ""


@logged
def nft_chains(data):
    """Index (family, table, chain) -> policy and ordered rules from `nft -j`."""
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise Failure("invalid_nft_json")
    chains: dict[tuple[str, str, str], dict] = {}
    rules: dict[tuple[str, str, str], list] = {}
    for item in data["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            continue
        kind, body = next(iter(item.items()))
        if not isinstance(body, dict):
            continue
        family, table = body.get("family"), body.get("table")
        member = body.get("name") if kind == "chain" else body.get("chain")
        if kind not in ("chain", "rule"):
            continue
        if not isinstance(family, str) or not isinstance(table, str) or not isinstance(member, str):
            continue
        key = (family, table, member)
        if kind == "chain":
            chains[key] = {"policy": body.get("policy") or "", "rules": []}
        else:
            rules.setdefault(key, []).append(body)
    for key, rows in rules.items():
        chains.setdefault(key, {"policy": "", "rules": []})["rules"] = rows
    return chains


@logged
def overlay_prefix_match(right, op):
    """`match`/`miss`/`unknown` for the overlay sample address, never a guess."""
    if isinstance(right, str):
        values = [right]
    elif isinstance(right, list) and right and all(isinstance(v, str) for v in right):
        values = right
    else:
        return "unknown"
    try:
        hit = any(OVERLAY_SAMPLE in ipaddress.ip_network(value, strict=False) for value in values)
    except ValueError:
        return "unknown"
    return "match" if hit == (op == "==") else "miss"


@logged
def overlay_match(match, interface):
    """`match`/`miss`/`unknown` for one nft match expression."""
    if not isinstance(match, dict) or len(match.get("left") or {}) != 1:
        return "unknown"
    op = match.get("op")
    if op not in ("==", "!="):
        return "unknown"
    kind, spec = next(iter(match["left"].items()))
    if kind == "meta" and isinstance(spec, dict):
        if spec.get("key") in ("oif", "oifname") and isinstance(match.get("right"), str):
            hit = match["right"] == interface
            return "match" if hit == (op == "==") else "miss"
        return "unknown"
    if kind == "payload" and isinstance(spec, dict):
        if spec.get("protocol") == "ip6" and spec.get("field") == "daddr":
            return overlay_prefix_match(match.get("right"), op)
        return "unknown"
    return "unknown"


@logged
def overlay_rule(exprs, interface):
    """`match`/`miss`/`unknown`, the terminal action and its target for one rule."""
    state, action, target = "match", None, None
    for expr in exprs or []:
        if not isinstance(expr, dict) or len(expr) != 1:
            state = "unknown"
            continue
        kind, body = next(iter(expr.items()))
        if kind in OVERLAY_NON_MATCH:
            continue
        if kind in OVERLAY_TERMINAL:
            return state, kind, None
        if kind == "return":
            return state, "return", None
        if kind in ("jump", "goto"):
            return state, kind, body.get("target") if isinstance(body, dict) else None
        if kind != "match":
            state = "unknown"
            continue
        outcome = overlay_match(body, interface)
        if outcome == "miss":
            return "miss", None, None
        if outcome == "unknown":
            state = "unknown"
    return state, action, target


@logged
def overlay_chain(chains, key, interface, depth=0):
    """Static verdict for one chain: allowed/denied/conditional/unknown."""
    chain = chains.get(key)
    if chain is None:
        return {"verdict": "unknown", "reason": "chain_missing", "matched": None, "path": []}
    unresolved = False
    path: list[dict[str, Any]] = []
    for rule in chain["rules"]:
        state, action, target = overlay_rule(rule.get("expr"), interface)
        if len(path) < OVERLAY_PATH_LIMIT:
            path.append({"handle": rule.get("handle"), "state": state, "action": action})
        if state == "miss":
            continue
        if action is None:
            continue
        if action == "return":
            unresolved = state == "unknown"
            break
        if action in ("jump", "goto"):
            if depth >= OVERLAY_MAX_DEPTH or not isinstance(target, str):
                unresolved = True
                continue
            nested = overlay_chain(chains, (key[0], key[1], target), interface, depth + 1)
            if nested["verdict"] == "unknown":
                unresolved = True
                continue
            verdict = nested["verdict"] if state == "match" and not unresolved else "conditional"
            return {
                "verdict": verdict,
                "reason": "nested_chain",
                "matched": rule.get("handle"),
                "path": path,
            }
        if state == "unknown" or unresolved:
            unresolved = True
            continue
        return {
            "verdict": "allowed" if action == "accept" else "denied",
            "reason": None,
            "matched": rule.get("handle"),
            "path": path,
        }
    policy = chain["policy"]
    if policy not in ("accept", "drop"):
        return {"verdict": "unknown", "reason": "chain_no_verdict", "matched": None, "path": path}
    verdict = "allowed" if policy == "accept" else "denied"
    return {
        "verdict": "conditional" if unresolved else verdict,
        "reason": "unresolved_rule" if unresolved else None,
        "matched": None,
        "path": path,
    }


@logged
def overlay_policy(ctx, interface=None):
    """Read-only findings for host policy that silently rejects overlay traffic."""
    limitations: list[str] = []
    findings: list[str] = []
    inspection = {"ip": "ok", "nft": "ok", "firewalld": "ok"}
    devices: list[str] = []
    try:
        devices = tun_interfaces(ctx.run(["/usr/sbin/ip", "-d", "link", "show"]).stdout.decode())
    except Failure:
        inspection["ip"] = "unavailable"
        limitations.append("ip_inspection_unavailable")
    target = interface or preferred_interface(devices)
    if not target:
        findings.append("tun_interface_not_found")
    zones: dict[str, str] = {}
    try:
        zones = zone_interfaces(
            ctx.run(["/usr/bin/firewall-cmd", "--get-active-zones"]).stdout.decode()
        )
    except Failure:
        inspection["firewalld"] = "unavailable"
    chains: dict[tuple[str, str, str], dict] = {}
    try:
        chains = nft_chains(json.loads(ctx.run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout))
    except Failure as exc:
        inspection["nft"] = "unavailable"
        limitations.append(
            "nft_inspection_unavailable"
            if str(exc).startswith("external_unavailable")
            else "nft_inspection_failed"
        )
    except ValueError:
        inspection["nft"] = "invalid_json"
        limitations.append("nft_inspection_invalid_json")
    key = ("inet", "mullvad", "output")
    result = (
        overlay_chain(chains, key, target)
        if inspection["nft"] == "ok"
        else {
            "verdict": "unknown",
            "reason": "nft_inspection_unavailable",
            "matched": None,
            "path": [],
        }
    )
    if result["reason"] == "chain_missing":
        limitations.append("mullvad_chain_missing")
    if result["verdict"] == "denied":
        findings.append("mullvad_killswitch_rejects_overlay")
    if result["verdict"] == "conditional":
        limitations.append("conditional_rules_require_packet_trace")
    if result["verdict"] == "unknown" and result["reason"] not in (
        "chain_missing",
        "nft_inspection_unavailable",
    ):
        limitations.append("overlay_verdict_unknown")
    return {
        "interface": target or None,
        "tun_devices": devices,
        "firewalld_zone": zones.get(target) if target else None,
        "firewalld_evidence": "zone_membership_is_not_permission" if target in zones else None,
        "mullvad_output_policy": chains.get(key, {}).get("policy") or None,
        "overlay_verdict": result["verdict"],
        "matched_rule": result["matched"],
        "evaluated_rules": result["path"],
        "inspection": inspection,
        "limitations": limitations,
        "findings": findings,
        "side_effects": "none; read-only commands only, no firewall changes",
    }
