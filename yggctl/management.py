"""Serialized config transactions with durable preimages and compensation."""

import json
import re
import time
import uuid
from pathlib import Path

from core import (
    Failure,
    NODE,
    STACK,
    logged,
    atomic,
    read_regular,
    peer_uri,
    endpoint,
    digest,
    timestamp,
    event,
)
from checks import identified, integrity, peers, underlay


@logged
def identity_gate(ctx):
    if (ctx.p.state / "rotation.json").exists():
        raise Failure("identity_recovery_required_use_encrypted_custody_tool")


@logged
def manifest_update(ctx, changed):
    rows = {}
    for line in read_regular(ctx.p.etc / "integrity.manifest").decode().splitlines():
        h, path = line.split("  ", 1)
        actual = Path(path) if path.startswith("/") else ctx.p.etc / path
        rows[path] = digest(read_regular(actual, 256 * 1024 * 1024)) if actual in changed else h
    atomic(ctx.p.etc / "integrity.manifest", "".join(f"{v}  {k}\n" for k, v in rows.items()), 0o644)


@logged
def gate_bytes(configs, table):
    ips = sorted({endpoint(uri).split(":")[0] for c in configs for uri in c["Peers"]})
    return (
        f"table inet {table} {{\n  chain output {{\n    type filter hook output priority 0; policy accept;\n"
        f"    ip daddr {{ {','.join(ips)} }} drop\n  }}\n}}\n"
    ).encode()


@logged
def transaction(ctx, updates, action, compensate):
    with ctx.locked():
        identity_gate(ctx)
        pending = ctx.p.state / "transaction.json"
        if pending.exists():
            raise Failure("unfinished_transaction_run_recover_transaction")
        integrity(ctx)
        # Only secret-free console-owned configs/gates/mode and manifest are admitted.
        allowed = {
            ctx.p.etc / n
            for n in (
                "yggdrasil-lab.conf",
                "yggstack.conf",
                "gate.nft",
                "gate-yggstack.nft",
                "mode",
            )
        }
        if not set(updates) <= allowed:
            raise Failure("transaction_path_not_allowed")
        old = {
            str(p): read_regular(p).decode() for p in (*updates, ctx.p.etc / "integrity.manifest")
        }
        record = {"schema": 1, "at": timestamp(), "old": old, "phase": "prepared"}
        atomic(pending, json.dumps(record))
        event("state", "transaction", "prepared")
        try:
            for path, data in updates.items():
                atomic(path, data, 0o644)
            record["phase"] = "published"
            atomic(pending, json.dumps(record))
            event("state", "transaction", "published")
            action()
            manifest_update(ctx, set(updates))
            integrity(ctx)
        except BaseException as primary_error:
            event("state", "transaction", "rolling_back")
            for name, data in old.items():
                atomic(Path(name), data, 0o644)
            try:
                compensate()
                # Restored files and peers do not prove the selected old underlay.
                event("state", "transaction", "verifying_rollback_underlay")
                underlay(ctx)
            except BaseException as rollback_error:
                event("error", "transaction", "rollback_runtime_failed")
                record["phase"] = "rollback_runtime_failed"
                atomic(pending, json.dumps(record))
                # Keep the initiating failure primary, with rollback failure as cause.
                raise primary_error from rollback_error
            pending.unlink()
            event("state", "transaction", "rolled_back")
            raise
        record["phase"] = "committed"
        atomic(pending, json.dumps(record))
        saved = ctx.p.state / ("transaction-" + uuid.uuid4().hex + ".json")
        pending.rename(saved)
        event("state", "transaction", "committed")


@logged
def wait_peers(ctx, desired=None, seconds=25, absent=False):
    deadline = time.monotonic() + seconds
    while True:
        valid = True
        for stack in (False, True):
            rows = peers(ctx, stack)
            up = {endpoint(p.get("remote", "")) for p in rows if identified(p)}
            configured = {endpoint(p.get("remote", "")) for p in rows}
            valid &= len(up) >= 2 and (
                desired is None or (desired not in configured if absent else desired in up)
            )
        if valid:
            return
        if time.monotonic() >= deadline:
            raise Failure("peer_convergence_timeout")
        print(
            f"[2/3] convergence pending; elapsed={seconds - (deadline - time.monotonic()):.1f}s "
            f"ETA<={deadline - time.monotonic():.1f}s speed=1 probe/2s remaining=1",
            flush=True,
        )
        time.sleep(2)


@logged
def restart_pair(ctx):
    ctx.run(["/usr/bin/systemctl", "restart", NODE, STACK], timeout=45)
    wait_peers(ctx)


@logged
def change_peer(ctx, value, remove=False, force=False, apply=False):
    ctx.root()
    with ctx.locked():
        configs = [ctx.config(n) for n in ("yggdrasil-lab.conf", "yggstack.conf")]
        if remove:
            # Exact endpoint comparison, never a shell/regex match against dotted IPs.
            if not re.fullmatch(r"[0-9.]+:[0-9]+", value):
                raise Failure("expected_ipv4_port")
            peer_uri(f"tls://{value}?key={'0' * 64}")
            matching = [[u for u in c["Peers"] if endpoint(u) == value] for c in configs]
            if any(len(m) != 1 for m in matching):
                raise Failure("endpoint_missing_or_ambiguous")
            if any(len(c["Peers"]) <= 2 for c in configs):
                raise Failure("retain_at_least_two_peers")
            uris = [m[0] for m in matching]
            for c, uri in zip(configs, uris):
                c["Peers"].remove(uri)
            desired = value
        else:
            uri, desired = peer_uri(value, force)
            if any(any(endpoint(u) == desired for u in c["Peers"]) for c in configs):
                raise Failure("endpoint_already_configured")
            uris = [uri, uri]
            for c in configs:
                c["Peers"].append(uri)
        if not apply:
            print("PREVIEW: both configs/runtime peers/gates; use --apply after firewall review")
            return
        names = ("yggdrasil-lab.conf", "yggstack.conf")
        updates = {
            ctx.p.etc / name: json.dumps(c, indent=2) + "\n" for name, c in zip(names, configs)
        }
        updates[ctx.p.etc / "gate.nft"] = gate_bytes(configs, "ygglab")
        updates[ctx.p.etc / "gate-yggstack.nft"] = gate_bytes(configs, "yggstack-gate")
        action = "removepeer" if remove else "addpeer"
        transaction(
            ctx,
            updates,
            lambda: runtime_peers(ctx, action, uris, desired),
            lambda: restart_pair(ctx),
        )
        print("[3/3] peer transaction committed; processed=2 errors=0 remaining=0")


@logged
def runtime_peers(ctx, action, uris, desired):
    for stack, uri in zip((False, True), uris):
        ctx.api(action, stack=stack, uri=uri)
    wait_peers(ctx, desired, absent=action == "removepeer")


@logged
def change_mode(ctx, mode, apply=False):
    ctx.root()
    if mode not in ("direct", "tunnel"):
        raise Failure("invalid_mode")
    if ctx.mode() == mode:
        underlay(ctx)
        print("mode unchanged; runtime proof verified")
        return
    if not apply:
        print("PREVIEW: restart both services; use --apply after firewall review")
        return
    transaction(
        ctx, {ctx.p.etc / "mode": mode + "\n"}, lambda: mode_action(ctx), lambda: restart_pair(ctx)
    )


@logged
def mode_action(ctx):
    restart_pair(ctx)
    underlay(ctx)


@logged
def recover_transaction(ctx, apply=False):
    ctx.root()
    with ctx.locked():
        path = ctx.p.state / "transaction.json"
        identity_gate(ctx)
        record = json.loads(read_regular(path).decode())
        if not isinstance(record, dict) or not isinstance(record.get("old"), dict):
            raise Failure("invalid_recovery_journal")
        allowed = {
            str(ctx.p.etc / n)
            for n in (
                "mode",
                "gate.nft",
                "gate-yggstack.nft",
                "yggdrasil-lab.conf",
                "yggstack.conf",
                "integrity.manifest",
            )
        }
        old = record.get("old", {})
        if not old or not set(old) <= allowed or any(not isinstance(v, str) for v in old.values()):
            raise Failure("invalid_recovery_journal")
        if not apply:
            print("PREVIEW: restore exact transaction preimages, restart both; use --apply")
            return
        for name, data in old.items():
            atomic(Path(name), data, 0o644)
        restart_pair(ctx)
        integrity(ctx)
        event("state", "recovery", "verifying_underlay")
        underlay(ctx)
        path.rename(ctx.p.state / ("recovered-" + uuid.uuid4().hex + ".json"))
        event("state", "recovery", "restored")


@logged
def service(ctx, command):
    ctx.root()
    stack = command.startswith("stack-")
    action = command.removeprefix("stack-")
    if action not in ("start", "stop", "restart", "enable", "disable"):
        raise Failure("invalid_service_action")
    with ctx.locked():
        identity_gate(ctx)
        integrity(ctx)
        ctx.run(["/usr/bin/systemctl", action, STACK if stack else NODE], timeout=45)
        if action in ("start", "restart"):
            # Node commands may start stack via dependency; require the requested unit.
            deadline = time.monotonic() + 25
            while sum(identified(p) for p in peers(ctx, stack)) < 2:
                if time.monotonic() >= deadline:
                    raise Failure("service_peer_timeout")
                time.sleep(2)
        event("state", "service", action)
