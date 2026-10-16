"""Fail-closed structured health checks, including PID-bound underlay proof."""
from pathlib import Path
import ipaddress
import json
import re
import stat
import time

from core import (Failure, NODE, STACK, TIMER, KEYS, read_regular, logged, event,
                  digest, safe_config, endpoint)


@logged
def peers(ctx, stack=False):
    rows = ctx.api("getPeers", stack=stack).get("peers")
    if not isinstance(rows, list) or any(not isinstance(p, dict) or type(p.get("up")) is not bool for p in rows):
        raise Failure("invalid_peer_schema")
    for p in rows:
        if not isinstance(p.get("remote"), str): raise Failure("invalid_peer_remote")
        for field in ("latency", "bytes_recvd", "bytes_sent"):
            value = p.get(field, 0)
            if type(value) not in (int, float) or value < 0: raise Failure("invalid_peer_counter")
    return rows


@logged
def policy(ctx):
    return {
        "FW_RUNTIME_SHA": digest(ctx.run(["/usr/bin/firewall-cmd", "--zone=public", "--list-all"]).stdout),
        "FW_PERMANENT_SHA": digest(ctx.run(["/usr/bin/firewall-cmd", "--permanent", "--zone=public", "--list-all"]).stdout),
        "NFT_MULLVAD_SHA": digest(ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout),
    }


@logged
def baseline(ctx):
    values = {}
    for line in read_regular(ctx.p.etc / "baseline.env").decode().splitlines():
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            if k in values or k not in {"FW_RUNTIME_SHA", "FW_PERMANENT_SHA", "NFT_MULLVAD_SHA", "BASELINE_AT"}:
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
def integrity(ctx):
    manifest = read_regular(ctx.p.etc / "integrity.manifest").decode()
    checked = set()
    for line in manifest.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not m: raise Failure("invalid_integrity_manifest")
        path = Path(m[2])
        if not path.is_absolute(): path = ctx.p.etc / path
        if path in checked: raise Failure("duplicate_integrity_member")
        if ctx.require_root: trusted(path)
        if digest(read_regular(path, limit=256 * 1024 * 1024)) != m[1]:
            raise Failure("integrity_mismatch")
        checked.add(path)
    required = {Path(ctx.p.node), Path(ctx.p.stack), ctx.p.units / NODE, ctx.p.units / STACK,
                ctx.p.etc / "yggdrasil-lab.conf", ctx.p.etc / "yggstack.conf",
                ctx.p.etc / "gate.nft", ctx.p.etc / "gate-yggstack.nft"}
    if ctx.require_root:
        required |= {ctx.p.units / TIMER, ctx.p.units / "ygg-metrics.service", Path("/usr/bin/yggctl"),
                     ctx.p.runtime / "main.py", ctx.p.runtime / "core.py", ctx.p.runtime / "checks.py",
                     ctx.p.runtime / "management.py", ctx.p.runtime / "telemetry.py", ctx.p.runtime / "recovery.py",
                     ctx.p.runtime / "tests.py", ctx.p.runtime / "rotate.py", Path("/usr/local/bin/yggctl"), Path(ctx.p.decoder),
                     ctx.p.etc / "mode", ctx.p.etc / "baseline.env"}
        required.add(ctx.p.etc / "baseline-runtime-public.txt")
        required.add(ctx.p.etc / "baseline-nft-mullvad.txt")
        required |= {ctx.p.runtime / "research" / n for n in ("__init__.py", "model.py", "metrics.py", "tests.py")}
        required |= {ctx.p.runtime / "atlas" / n for n in ("__init__.py", "store.py", "protocol.py", "catalogue.py",
                                                            "acquisition.py", "analysis.py", "viewer.py", "tests.py")}
    if not required <= checked: raise Failure("integrity_coverage_incomplete")
    return len(checked)


@logged
def underlay(ctx):
    mode = ctx.mode()
    pids = [int(ctx.unit(u).get("MainPID", "0")) for u in (NODE, STACK)]
    if not all(p > 0 for p in pids): raise Failure("missing_runtime_pid")
    exclusions = set(re.findall(r"(?m)^\s*(\d+)\s*$", ctx.run(["/usr/bin/mullvad", "split-tunnel", "list"]).stdout.decode()))
    if any((str(p) in exclusions) != (mode == "direct") for p in pids):
        raise Failure("underlay_pid_exclusion_mismatch")
    # Bind conntrack evidence to the local/remote four-tuple of each own socket.
    sockets = ctx.run(["/usr/bin/ss", "-H", "-ntup"]).stdout.decode().splitlines()
    conn = ctx.run(["/usr/sbin/conntrack", "-L"]).stdout.decode().splitlines()
    proof = dict.fromkeys(pids, 0)
    for line in sockets:
        fields = line.split()
        if len(fields) < 6: continue
        for pid in pids:
            if not re.search(rf"\bpid={pid},", line): continue
            local, remote = fields[4:6]
            try:
                src, sport = local.rsplit(":", 1)
                dst, dport = remote.rsplit(":", 1)
            except ValueError: continue
            prefix = f"src={src} dst={dst} sport={sport} dport={dport}"
            matches = [r for r in conn if prefix + " " in r and r.split()[0] == fields[0]]
            if any(bool(re.search(r"\bmark=3905\b", r)) == (mode == "direct") for r in matches):
                proof[pid] += 1
    if not all(proof.values()): raise Failure("underlay_own_socket_proof_missing")
    return {"mode": mode, "own_connections": list(proof.values())}


@logged
def guard(ctx):
    for name in ("yggdrasil-lab.conf", "yggstack.conf"):
        config = ctx.config(name)
        if safe_config(config): raise Failure("unsafe_config")
        expected = ctx.p.node_sock if name.startswith("yggdrasil") else ctx.p.stack_sock
        if config.get("AdminListen") != f"unix://{expected}": raise Failure("admin_config_mismatch")
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
    lines = ctx.run(["/usr/bin/ss", "-H", "-lntup"]).stdout.decode().splitlines()
    pids = [int(ctx.unit(u).get("MainPID", "0")) for u in (NODE, STACK)]
    own = [line for line in lines if any(re.search(rf"\bpid={p},", line) for p in pids if p)]
    if len(own) != 1 or own[0].split()[4] != "127.0.0.1:1080" or f"pid={pids[1]}," not in own[0]:
        raise Failure("unexpected_node_stack_listener")
    return "SOCKS loopback only"


@logged
def check(ctx, emit=True):
    ctx.root()
    gates = [("config/keys/admin", guard), ("integrity/root trust", integrity),
             ("listeners", sockets), ("underlay own sockets", underlay)]
    for u in (NODE, STACK): gates.append((u, lambda c, u=u: service_gate(c, u)))
    for stack in (False, True):
        gates.append(("stack peers" if stack else "node peers", lambda c, s=stack: peer_gate(c, s)))
        gates.append(("stack no multicast" if stack else "node no multicast", lambda c, s=stack: multicast_gate(c, s)))
    gates += [("no TUN", tun_gate), ("firewall baseline", policy_gate),
              ("no transient gates", nft_gate), ("packaged masked", masked_gate), ("collector timer", timer_gate)]
    failures = []
    start = time.monotonic()
    for i, (label, fn) in enumerate(gates, 1):
        try:
            fn(ctx)
            result = "PASS"
        except (Failure, OSError, ValueError, KeyError) as exc:
            failures.append(label)
            result = f"FAIL {exc}" if isinstance(exc, Failure) else "FAIL unavailable/invalid"
        if emit: print(f"[{i}/{len(gates)}] {label}: {result}; remaining={len(gates)-i}", flush=True)
    if emit: print(f"CHECK {'FAIL' if failures else 'PASS'} processed={len(gates)} errors={len(failures)} elapsed={time.monotonic()-start:.2f}s")
    if failures: raise Failure("health_gates_failed")
    return len(gates)


@logged
def service_gate(ctx, unit):
    u = ctx.unit(unit)
    if u.get("ActiveState") != "active" or u.get("SubState") != "running" or int(u.get("NRestarts", "1")):
        raise Failure("unit_not_stably_running")


@logged
def peer_gate(ctx, stack):
    rows = peers(ctx, stack)
    expected = set(ctx.config("yggstack.conf" if stack else "yggdrasil-lab.conf")["Peers"])
    up = {endpoint(p.get("remote", "")) for p in rows if p["up"] and not p.get("inbound")}
    if len(up & {endpoint(p) for p in expected}) < 2: raise Failure("less_than_two_configured_peers_up")


@logged
def multicast_gate(ctx, stack):
    if ctx.api("getMulticastInterfaces", stack=stack).get("multicast_interfaces") != []:
        raise Failure("multicast_unknown_or_nonempty")


@logged
def tun_gate(ctx):
    if ctx.api("getTun").get("enabled") is not False: raise Failure("tun_unknown_or_enabled")


@logged
def runtime_display(data):
    """Normalize ONLY the unordered trailing rich-rule display, never nft order.

    All zone fields and every rule byte stay significant. This is not a policy
    parser: unsupported formatting, duplicates or control bytes fail closed.
    """
    marker = b"  rich rules: \n"
    if (not isinstance(data, bytes) or len(data) > 65536 or not data.endswith(b"\n")
            or data.count(marker) != 1 or any(c < 32 and c not in (9, 10) for c in data)
            or b"\x7f" in data):
        raise Failure("invalid_runtime_display")
    prefix, tail = data.split(marker)
    rules = tail.splitlines(keepends=True)
    if (len(rules) > 256 or len(rules) != len(set(rules))
            or any(not r.startswith(b"\trule ") or not r.endswith(b"\n")
                   or b"\t" in r[1:] for r in rules)):
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
        if (status["state"] != "connected" or tunnel["protocol"] != "udp"
                or tunnel["tunnel_interface"] != "wg0-mullvad"
                or set(obfuscation) != {"Single"}
                or single["obfuscation_type"] != "Quic" or relay["protocol"] != "udp"
                or not isinstance(address, str) or not address.endswith(":443")):
            raise ValueError
        ip = ipaddress.IPv4Address(address[:-4])
        if not ip.is_global or address != f"{ip}:443": raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Failure("unsupported_mullvad_relay_status") from None
    return str(ip).encode("ascii")


@logged
def relay_display(reference, current, relay):
    """Replace ONLY three reviewed endpoint slots; every other byte stays exact.

    No nft parsing/canonicalization: order, ports, marks, interfaces and verdicts
    remain significant. The caller must first anchor reference to the old SHA.
    """
    for data in (reference, current):
        if (not isinstance(data, bytes) or len(data) > 65536 or not data.endswith(b"\n")
                or any(c < 32 and c not in (9, 10) for c in data) or b"\x7f" in data):
            raise Failure("invalid_mullvad_display")
    slots = ((b"ip saddr ", b" udp sport 443 meta mark set 0x6d6f6c65"),
             (b"ip daddr ", b" udp dport 443 meta mark 0x6d6f6c65 accept"),
             (b"ip saddr ", b" udp sport 443 ct state established accept"))
    addresses = []
    for prefix, suffix in slots:
        pattern = b"^\\t\\t" + re.escape(prefix) + rb"([0-9.]+)" + re.escape(suffix) + b"\\n"
        matches = re.findall(pattern, reference, re.MULTILINE)
        if len(matches) != 1: raise Failure("unsupported_mullvad_reference_slots")
        addresses.extend(matches)
    old = addresses[0]
    if len(set(addresses)) != 1 or reference.count(old) != 3:
        raise Failure("unsupported_mullvad_reference_slots")
    try:
        if str(ipaddress.IPv4Address(old.decode("ascii"))).encode("ascii") != old:
            raise ValueError
        if str(ipaddress.IPv4Address(relay.decode("ascii"))).encode("ascii") != relay:
            raise ValueError
    except (ValueError, UnicodeError, AttributeError):
        raise Failure("invalid_mullvad_relay_address") from None
    return reference.replace(old, relay) == current


@logged
def nft_relay_gate(ctx, expected, observed):
    path = ctx.p.etc / "baseline-nft-mullvad.txt"
    if ctx.require_root: trusted(path)
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
        raise Failure("policy_baseline_drift_do_not_auto_accept")
    if quic_relay(ctx.run(["/usr/bin/mullvad", "status", "--json"]).stdout) != relay:
        raise Failure("mullvad_relay_changed_during_check")
    event("state", "mullvad_policy", "legacy_anchored_local_quic_relay_only")


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
    if ctx.require_root: trusted(path)
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
        if v.get("UnitFileState") != "masked" or v.get("ActiveState") != "inactive": raise Failure("packaged_unit_unmasked_or_running")


@logged
def timer_gate(ctx):
    if ctx.unit(TIMER).get("ActiveState") != "active": raise Failure("collector_timer_inactive")
    u = ctx.unit("ygg-metrics.service")
    if u.get("ActiveState") == "failed" or u.get("ExecMainStatus") != "0": raise Failure("collector_failed")
