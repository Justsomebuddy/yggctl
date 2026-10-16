#!/usr/bin/python3
"""Operator CLI; no environment-selected paths or legacy unsafe fallback."""
import argparse
import ipaddress
import json
import math
import os
import re
import signal
import sys
import time
from pathlib import Path

# -I removes PYTHONPATH and the repository cwd. Installed directory is root-owned.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Context, Paths, Failure, VERSION, NODE, STACK, TIMER, logged, public_config, bounded_number, event, trace_live, finish_run
import checks
import management
import telemetry
import recovery
import sandbox

HELP = """yggctl 5 — trusted root-owned CLI (sudo for full data)
Health: check, selftest [offline], status, guard, verify-hashes, socks, socks-test
View: peers, stack-peers, self, tree, paths, sessions, config [show|validate],
      mode [show], version, update-check, logs [N], events [hours], firewall-status
Metrics: collect, stats [hours], graph [hours], watch/top [N] [seconds],
         notify on|off|show|test, report, peers-score
Management: start|stop|restart|enable|disable (or stack-*),
            add-peer URI [--force] [--apply], remove-peer IPv4:port [--apply],
            mode direct|tunnel [--apply], recover-transaction [--apply]
Recovery: snapshot, diff [file], backup [--full --recipient FINGERPRINT],
          restore FILE [--apply], doctor
Research: research capture|map [ID]|diff [earlier ID]|report [1..72 hours]
          Local observations + history only; global size/capacity UNKNOWN.
Atlas: atlas catalogue|new|crawl [1..120 minutes]|status|report
  crawl without a duration completes the discovered frontier; duration saves one slice.
       Whole public catalogue + resumable discovered-key frontier, no32-key cutoff.
       Remote lists may truncate; geography is a claim, NOT world completeness.
Overlay: ping [IPv6]:port (HTTP timing, NOT ICMP RTT), bench [N],
         nodeinfo KEY, whois KEY, debug-remote self|peers|tree KEY,
         survey, traceroute KEY (tree inspection, NOT packet route), discover
         Remote commands require another node's key; own key: use self/peers/tree.
Guarded/deferred: nameserver show (mutations require firewall review), timer
 show; install/remove via trusted deployer. purge, rotate-key, chaos, upgrade,
 baseline-update fail closed pending separate custody/review. No SimpleX wiring.
Without sudo: help, version, update-check, stats, graph (metrics group-readable).
Research and atlas run in a transient systemd sandbox: no capabilities, read-only
 system, no node keys; research without network.
Logging: one syslog summary line per run; the call trace is written only when
 the run fails, or always with --trace.
Exit 0 verified success/explicit preview; 1 failure; 2 parser; 77 root required.
"""


@logged
def output(value):
    print(json.dumps(public_config(value), indent=2, ensure_ascii=True))


@logged
def key(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value): raise Failure("expected_public_key_hex64")
    return value.lower()


@logged
def http_probe(ctx, target):
    if not re.fullmatch(r"\[[0-9A-Fa-f:]+\]:[0-9]{1,5}", target): raise Failure("expected_overlay_ipv6_port")
    host, port = target[1:].split("]:")
    if ipaddress.ip_address(host) not in ipaddress.ip_network("200::/7") or not 1 <= int(port) <= 65535:
        raise Failure("overlay_target_required")
    r = ctx.run(["/usr/bin/curl", "-q", "--silent", "--show-error", "--noproxy", "", "--proxy", "socks5h://127.0.0.1:1080",
                 "--connect-timeout", "5", "--max-time", "15", "--max-filesize", "131072", "--proto", "=http",
                 "--output", "/dev/null", "--write-out", "%{http_code} %{time_connect} %{time_pretransfer} %{time_starttransfer} %{time_total}",
                 "http://" + target + "/"], timeout=17, check=False)
    parts = r.stdout.decode().split()
    if len(parts) != 5 or not re.fullmatch(r"[0-9]{3}", parts[0]):
        raise Failure("overlay_invalid_metrics")
    try:
        timings = [float(p) for p in parts[1:]]
    except ValueError:
        raise Failure("overlay_invalid_metrics") from None
    if any(not math.isfinite(t) or not 0 <= t <= 17 for t in timings):
        raise Failure("overlay_invalid_metrics")
    # Only validated numeric metrics, never curl's raw stderr/URLs. In failed
    # proxy negotiation curl can finalize pretransfer/first-byte counters at
    # the timeout, so these counters do NOT prove that HTTP was reached.
    connect, ready, first, total = timings
    print(f"curl_rc={r.returncode} HTTP={parts[0]} curl_connect_counter={connect:.6f}s pretransfer_counter={ready:.6f}s first_byte_counter={first:.6f}s total={total:.6f}s; counters do NOT prove failure stage/remote RTT")
    if r.returncode:
        # Translate only known fixed curl messages; never echo arbitrary
        # server-controlled stderr. Unknown messages must stay unknown.
        label = "proxy_connect_timeout" if r.returncode == 28 and b"Proxy connection timed out" in r.stderr else "timeout_stage_unknown" if r.returncode == 28 else "transfer_failed"
        event("state", "http_probe", label)
        raise Failure(f"overlay_curl_failed:rc={r.returncode}:diagnostic={label}")
    if not 200 <= int(parts[0]) < 300:
        raise Failure("overlay_http_not_2xx")
    return parts


@logged
def remote_key(ctx, value):
    target = key(value)
    own = ctx.api("getSelf").get("key")
    if not isinstance(own, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", own):
        raise Failure("admin_invalid_self_key")
    if target == own.lower():
        raise Failure("remote_target_is_local_use_self_peers_tree_config")
    return target


@logged
def socks_test(ctx, count=2):
    start = time.monotonic()
    checks.sockets(ctx)
    targets = ("[21e:a51c:885b:7db0:166e:927:98cd:d186]:80", "[222:a8e4:50cd:55c:788e:b0a5:4e2f:a92c]:80")
    errors = 0
    for i in range(count):
        print(f"[{i+1}/{count}] overlay HTTP; processed={i}/{count} remaining={count-i-1} elapsed={time.monotonic()-start:.2f}s ETA<={(count-i)*17}s speed<=128KiB/request", flush=True)
        try: http_probe(ctx, targets[i % 2])
        except Failure as exc:
            errors += 1
            print(f"FAIL overlay request: {exc} (bounded timeout/status/size)")
    print(f"processed={count} errors={errors} elapsed={time.monotonic()-start:.2f}s")
    if errors: raise Failure("overlay_e2e_failed")


@logged
def selftest(ctx, offline=False):
    if offline:
        # Installed fixtures live in root-only state; fail once, before tests.
        ctx.root()
        # No runtime files, backups, snapshots or collector mutation.
        from tests import run_suite
        run_suite()
        from research.tests import run_suite as research_suite
        research_suite()
        from atlas.tests import run_suite as atlas_suite
        atlas_suite()
        return
    checks.check(ctx)
    for method in ("getSelf", "getTree", "getPaths", "getSessions"):
        ctx.api(method)
        print(f"PASS {method}")
    telemetry.stats(ctx)
    print("SELFTEST PASS read-only; overlay e2e separate socks-test; mutations isolated offline")


@logged
def dispatch(ctx, args):
    cmd, a = args.command, args.args
    no_args = {"help", "version", "update-check", "check", "status", "guard", "verify-hashes", "socks", "socks-test", "collect", "snapshot", "backup", "doctor", "report", "firewall-status", "peers", "stack-peers", "self", "tree", "paths", "sessions", "peers-score", "survey", "discover", "recover-transaction"}
    no_args |= {"start", "stop", "restart", "enable", "disable", "stack-start", "stack-stop", "stack-restart", "stack-enable", "stack-disable"}
    one_arg = {"mode", "config", "stats", "graph", "notify", "restore", "diff", "logs", "events", "ping", "bench", "nodeinfo", "whois", "nameserver", "timer", "selftest", "traceroute"}
    if (cmd in no_args and a) or (cmd in one_arg and len(a)>1) or (cmd in {"watch","top"} and len(a)>2):
        raise Failure("unexpected_arguments")
    if args.apply and cmd not in {"add-peer","remove-peer","mode","restore","recover-transaction"}: raise Failure("apply_not_supported_here")
    if args.force and cmd != "add-peer": raise Failure("force_only_for_add_peer")
    if (args.full or args.recipient) and cmd != "backup": raise Failure("backup_options_only")
    if cmd in ("help", "--help"):
        print(HELP)
        return
    if cmd == "version":
        print(f"yggctl {VERSION}; Python {sys.version.split()[0]}")
        print(ctx.run(["/usr/bin/dpkg-query", "-W", "-f=${Version}\n", "yggdrasil"]).stdout.decode().strip())
        return
    if cmd == "update-check":
        print(ctx.run(["/usr/bin/apt-cache", "policy", "yggdrasil"]).stdout.decode())
        print("Upstream comparison requires an explicit small GitHub fetch; no automatic install")
        return
    if cmd == "selftest" and a == ["offline"]:
        selftest(ctx, True)
        return
    if cmd in ("stats", "graph"):
        # Read-only and lock-free: the metrics file is group-readable, so sudo is
        # needed only when this user cannot read it.
        if os.geteuid() != 0 and not os.access(ctx.p.state / "metrics.jsonl", os.R_OK):
            ctx.root()
        telemetry.stats(ctx, bounded_number(a[0], 1, 72) if a else (6 if cmd == "graph" else 24), cmd == "graph")
        return
    ctx.root()
    api = {"peers": "getPeers", "stack-peers": "getPeers", "self": "getSelf", "tree": "getTree", "paths": "getPaths", "sessions": "getSessions"}
    if cmd in api:
        output(ctx.api(api[cmd], stack=cmd == "stack-peers"))
    elif cmd in ("check", "status"):
        checks.check(ctx)
    elif cmd == "selftest":
        if a: raise Failure("selftest_only_optional_offline")
        selftest(ctx)
    elif cmd == "guard": print(checks.guard(ctx)); print("GUARD PASS (not a numerical security score)")
    elif cmd == "verify-hashes": print(f"integrity PASS members={checks.integrity(ctx)}")
    elif cmd == "socks": print(checks.sockets(ctx)); output(checks.underlay(ctx))
    elif cmd == "socks-test": socks_test(ctx)
    elif cmd == "mode":
        if not a or a == ["show"]: output({"mode": ctx.mode(), "proof": checks.underlay(ctx)})
        else: management.change_mode(ctx, a[0], args.apply)
    elif cmd == "config":
        for name in ("yggdrasil-lab.conf", "yggstack.conf"):
            config = ctx.config(name)
            if not a or a == ["show"]: output({name: config})
            elif a == ["validate"]:
                if checks.safe_config(config): raise Failure("unsafe_config")
                print(name + " syntax/security PASS")
            else: raise Failure("config_edit_disabled_use_reviewed_transaction")
    elif cmd in {"start", "stop", "restart", "enable", "disable", "stack-start", "stack-stop", "stack-restart", "stack-enable", "stack-disable"}:
        management.service(ctx, cmd)
    elif cmd in ("add-peer", "remove-peer"):
        if len(a) != 1: raise Failure("one_peer_argument_required")
        management.change_peer(ctx, a[0], cmd == "remove-peer", args.force, args.apply)
    elif cmd == "recover-transaction": management.recover_transaction(ctx, args.apply)
    elif cmd == "collect": telemetry.collect(ctx)
    elif cmd in ("watch", "top"):
        telemetry.watch(ctx, bounded_number(a[0], 1, 60) if a else 5, bounded_number(a[1], 1, 30) if len(a)>1 else 2)
    elif cmd == "notify": telemetry.notify(ctx, a[0] if len(a) == 1 else "show")
    elif cmd == "backup": recovery.backup(ctx, args.full, args.recipient)
    elif cmd == "restore":
        if len(a) != 1: raise Failure("one_archive_path_required")
        recovery.restore(ctx, a[0], args.apply)
    elif cmd == "snapshot": recovery.snapshot(ctx)
    elif cmd == "diff": recovery.diff(ctx, a[0] if a else None)
    elif cmd == "doctor":
        # Secret-free allowlisted backup and structured data; no broad log/config tar.
        recovery.backup(ctx)
        output({"node": ctx.unit(NODE), "stack": ctx.unit(STACK), "timer": ctx.unit(TIMER), "pending_transaction": (ctx.p.state/"transaction.json").exists()})
    elif cmd == "report":
        checks.check(ctx)
        telemetry.stats(ctx)
    elif cmd in ("research", "atlas") and not sandbox.inside() and ctx.p == Paths():
        # The live system runs these in a transient systemd sandbox (see sandbox.py).
        rc = sandbox.run(ctx, cmd, a, Path(__file__).resolve())
        if rc: raise Failure(f"sandboxed_{cmd}_failed:rc={rc}")
    elif cmd == "research":
        import research
        output(research.command(ctx, a))
    elif cmd == "atlas":
        import atlas
        output(atlas.command(ctx, a))
    elif cmd in ("logs", "events"):
        n = bounded_number(a[0], 1, 1000) if a else 50
        command = ["/usr/bin/journalctl", "-u", NODE, "-u", STACK, "--no-pager", "-n", str(n)]
        if cmd == "events": command += ["--since", f"{bounded_number(a[0],1,72) if a else 6} hours ago"]
        value = ctx.run(command).stdout.decode(errors="replace")
        # JSON presentation escapes terminal controls; known secret-shaped assignments masked.
        value = re.sub(r"(?i)(privatekey|password|token|secret)\s*[:=]\s*\S+", r"\1=[REDACTED]", value)
        output({"logs": value})
    elif cmd == "firewall-status":
        checks.policy_gate(ctx)
        output({"accepted_surface": "unchanged", "watchdog": "independent; no baseline/allowlist rewrite"})
    elif cmd in ("ping", "bench"):
        if cmd == "ping":
            if len(a) != 1: raise Failure("one_overlay_ipv6_port_required")
            http_probe(ctx, a[0])
        else: socks_test(ctx, bounded_number(a[0],1,3) if a else 1)
    elif cmd in ("nodeinfo", "whois", "debug-remote"):
        if cmd == "debug-remote":
            methods = {"self": "debug_remotegetself", "peers": "debug_remotegetpeers", "tree": "debug_remotegettree"}
            if len(a) == 2 and a[0] == "dht":
                raise Failure("remote_dht_not_supported_by_upstream_use_tree")
            if len(a) != 2 or a[0] not in methods: raise Failure("debug_remote_self_peers_tree_key")
            output(ctx.api(methods[a[0]], key=remote_key(ctx, a[1])))
        else:
            if len(a) != 1: raise Failure("one_public_key_required")
            target = remote_key(ctx, a[0])
            output(ctx.api("getNodeInfo", key=target))
            if cmd == "whois": output(ctx.api("debug_remotegetself", key=target))
    elif cmd == "peers-score":
        data = checks.peers(ctx)
        output(sorted(data, key=lambda p: (not p["up"], p.get("latency", 0))))
        print("Ranking by current up/latency only; not a trust/reliability score")
    elif cmd in ("survey", "traceroute"):
        if cmd == "traceroute":
            if len(a) != 1: raise Failure("one_public_key_required")
            key(a[0])
        output(ctx.api("getTree"))
        print("Tree introspection only; not forwarding path/traceroute; no automatic remote survey")
    elif cmd == "discover":
        print("Offline public-peers catalogue: Iggdrasil_full_repo/public-peers; no root git pull or TCP probe masquerading as QUIC test")
    elif cmd in ("nameserver", "timer"):
        if a and a != ["show"]: raise Failure("requires_reviewed_deployment_or_firewall_review")
        output(ctx.unit(STACK if cmd == "nameserver" else TIMER))
        print("nameserver not added; SOCKS remains 127.0.0.1:1080" if cmd == "nameserver" else "trusted deployer owns timer")
    elif cmd in ("purge", "rotate-key", "chaos", "upgrade", "baseline-update"):
        raise Failure("legacy_high_risk_operation_disabled_requires_separate_custody_review_and_tests")
    else: raise Failure("unknown_command_use_help")


# Only command words documented in HELP reach the run summary; anything else is "other".
RUN = {"command": "other"}


@logged
def run_label(command):
    if re.fullmatch(r"[a-z][a-z-]{0,23}", command or "") and re.search(rf"(?<![\w-]){re.escape(command)}(?![\w-])", HELP):
        return command
    return "other"


@logged
def interrupted(signum, frame):
    raise Failure("interrupted_rollback_requested")


@logged
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("command", nargs="?", default="help")
    parser.add_argument("args", nargs="*")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--recipient")
    parser.add_argument("--help", action="store_true")
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_intermixed_args()
    if args.help: args.command = "help"
    if args.trace: trace_live()
    RUN["command"] = run_label(args.command)
    signal.signal(signal.SIGTERM, interrupted)
    start = time.monotonic()
    try:
        dispatch(Context(), args)
    except (Failure, OSError, ValueError, KeyError, TypeError) as exc:
        label = str(exc) if isinstance(exc, Failure) else "unavailable_or_invalid_data"
        print(f"FAIL {label}; processed=0 errors=1 elapsed={time.monotonic()-start:.2f}s", file=sys.stderr)
        return 77 if label.startswith("root_required") else 1
    except KeyboardInterrupt:
        print("FAIL interrupted; rollback attempted if transaction active", file=sys.stderr)
        return 130
    print(f"[done] errors=0 elapsed={time.monotonic()-start:.2f}s")
    return 0


if __name__ == "__main__":
    status = 1
    try:
        status = main()
    except SystemExit as exc:
        status = exc.code if isinstance(exc.code, int) else 2
        raise
    finally:
        finish_run(RUN["command"], status)
    sys.exit(status)
