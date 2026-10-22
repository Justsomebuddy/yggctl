#!/usr/bin/python3
"""Operator CLI; no environment-selected paths or legacy unsafe fallback."""

from typing import Callable

import argparse
import dataclasses
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
from core import (
    Context,
    Paths,
    Failure,
    VERSION,
    NODE,
    STACK,
    TIMER,
    logged,
    public_config,
    bounded_number,
    event,
    trace_live,
    finish_run,
)
import checks
import management
import telemetry
import recovery
import sandbox

HELP = """yggctl 5 — управление нодой Yggdrasil лаборатории (принадлежит root; полные данные — через sudo)

Здоровье:     check (15 проверок), status, selftest [offline], guard, verify-hashes, socks, socks-test
Просмотр:     peers, stack-peers, self, tree, paths, sessions, config [show|validate], mode [show],
              version, update-check, logs [N], events [часы], firewall-status
Метрики:      collect, stats [часы], graph [часы], trend [часы] [json], watch/top [N] [секунды],
              report, peers-score,
              notify on|off|show|test, alerts-forward
Управление:   start, stop, restart, enable, disable (с приставкой stack- — для стека),
              stack-start, stack-stop, stack-restart, stack-enable, stack-disable;
              add-peer URI [--force] [--apply], remove-peer IPv4:порт [--apply],
              add-peer принимает только IPv4-литерал и обязательный ?key=HEX64; меняет оба инстанса.
              mode direct|tunnel [--apply], recover-transaction [--apply].
              Без --apply изменение только показывается.
Восстановление: snapshot, diff [файл], backup [--full --recipient ОТПЕЧАТОК], restore ФАЙЛ (только просмотр; --apply отключён), doctor
Исследования: research capture|map [ID]|diff [ранний ID]|report [1..72 часа] — снимки своей ноды
              и их история; размер всей сети неизвестен.
Атлас:        atlas catalogue|new|crawl [1..120 минут]|status|report — весь публичный каталог пиров и
              обход найденных ключей; crawl без срока идёт до конца очереди, со сроком — один отрезок.
              Страна узла — его заявление, а не геолокация.
Сеть Yggdrasil: ping [IPv6]:порт (время HTTP, не ICMP), bench [N], nodeinfo КЛЮЧ, whois КЛЮЧ,
              debug-remote self|peers|tree КЛЮЧ, survey, traceroute КЛЮЧ (дерево, а не путь пакетов),
              discover. Для своей ноды — self, peers, tree.
Закрыто:      nameserver и timer — только show; purge, rotate-key, chaos, upgrade, baseline-update
              отключены до отдельного ревью. Установка — scripts/deployment/deploy.sh.
Без sudo:     help, version, update-check, stats, graph, trend.
Самотест:     selftest и selftest offline требуют sudo; stats/graph/trend — читаемый файл метрик.
Песочница:    research, atlas и команды сети Yggdrasil работают от отдельных пользователей ролей без
              root и без ключей; у research нет сети, у сетевых команд — только localhost.
Тревоги:      пир недоступен 10+ минут, нестабилен (3+ разрыва за час) или вернулся, сбой ноды —
              в SimpleX, пока notify включён.
Журнал:       одна строка на запуск; след вызовов — при сбое или с --trace.
Коды выхода:  0 — успех или показ изменения; 1 — сбой; 2 — ошибка аргументов; 77 — нужен root.
"""


@logged
def output(value):
    print(json.dumps(public_config(value), indent=2, ensure_ascii=True))


@logged
def key(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise Failure("expected_public_key_hex64")
    return value.lower()


@logged
def http_probe(ctx, target):
    if not re.fullmatch(r"\[[0-9A-Fa-f:]+\]:[0-9]{1,5}", target):
        raise Failure("expected_overlay_ipv6_port")
    host, port = target[1:].split("]:")
    if (
        ipaddress.ip_address(host) not in ipaddress.ip_network("200::/7")
        or not 1 <= int(port) <= 65535
    ):
        raise Failure("overlay_target_required")
    r = ctx.run(
        [
            "/usr/bin/curl",
            "-q",
            "--silent",
            "--show-error",
            "--noproxy",
            "",
            "--proxy",
            "socks5h://127.0.0.1:1080",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "--max-filesize",
            "131072",
            "--proto",
            "=http",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code} %{time_connect} %{time_pretransfer} %{time_starttransfer} %{time_total}",
            "http://" + target + "/",
        ],
        timeout=17,
        check=False,
    )
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
    print(
        f"curl_rc={r.returncode} HTTP={parts[0]} curl_connect_counter={connect:.6f}s "
        f"pretransfer_counter={ready:.6f}s first_byte_counter={first:.6f}s total={total:.6f}s; "
        "counters do NOT prove failure stage/remote RTT"
    )
    if r.returncode:
        # Translate only known fixed curl messages; never echo arbitrary
        # server-controlled stderr. Unknown messages must stay unknown.
        if r.returncode == 28 and b"Proxy connection timed out" in r.stderr:
            label = "proxy_connect_timeout"
        else:
            label = "timeout_stage_unknown" if r.returncode == 28 else "transfer_failed"
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
    if "sockets" not in ctx.parent_verified:
        checks.sockets(ctx)
    targets = (
        "[21e:a51c:885b:7db0:166e:927:98cd:d186]:80",
        "[222:a8e4:50cd:55c:788e:b0a5:4e2f:a92c]:80",
    )
    errors = 0
    for i in range(count):
        print(
            f"[{i + 1}/{count}] overlay HTTP; processed={i}/{count} remaining={count - i - 1} "
            f"elapsed={time.monotonic() - start:.2f}s ETA<={(count - i) * 17}s speed<=128KiB/request",
            flush=True,
        )
        try:
            http_probe(ctx, targets[i % 2])
        except Failure as exc:
            errors += 1
            print(f"FAIL overlay request: {exc} (bounded timeout/status/size)")
    print(f"processed={count} errors={errors} elapsed={time.monotonic() - start:.2f}s")
    if errors:
        raise Failure("overlay_e2e_failed")


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


@dataclasses.dataclass(frozen=True)
class Command:
    """A CLI command and the rules dispatch enforces before calling its handler."""

    handler: Callable[[Context, argparse.Namespace, list[str]], None]
    most: int = 0  # most positional arguments; -1 lets the handler check
    root: bool = True  # dispatch requires sudo before calling the handler
    flags: frozenset = frozenset()  # allowed among: apply, force, full, recipient


@logged
def do_help(ctx, args, a):
    print(HELP)


@logged
def do_version(ctx, args, a):
    print(f"yggctl {VERSION}; Python {sys.version.split()[0]}")
    print(
        ctx.run(["/usr/bin/dpkg-query", "-W", "-f=${Version}\n", "yggdrasil"])
        .stdout.decode()
        .strip()
    )


@logged
def do_update_check(ctx, args, a):
    print(ctx.run(["/usr/bin/apt-cache", "policy", "yggdrasil"]).stdout.decode())
    print("Upstream comparison requires an explicit small GitHub fetch; no automatic install")


@logged
def do_selftest(ctx, args, a):
    if a == ["offline"]:
        selftest(ctx, True)
        return
    ctx.root()
    if a:
        raise Failure("selftest_only_optional_offline")
    selftest(ctx)


@logged
def do_stats(ctx, args, a):
    # Read-only and lock-free: the metrics file is group-readable, so sudo is
    # needed only when this user cannot read it.
    if os.geteuid() != 0 and not os.access(ctx.p.state / "metrics.jsonl", os.R_OK):
        ctx.root()
    graph = args.command == "graph"
    telemetry.stats(ctx, bounded_number(a[0], 1, 72) if a else (6 if graph else 24), graph)


@logged
def do_trend(ctx, args, a):
    # Read-only and lock-free like stats: sudo only when this user cannot read the file.
    if os.geteuid() != 0 and not os.access(ctx.p.state / "metrics.jsonl", os.R_OK):
        ctx.root()
    hours, machine = 24, False
    for item in a:
        if item == "json":
            machine = True
        else:
            hours = bounded_number(item, 1, 72)
    report = telemetry.trend(ctx, hours)
    if machine:
        output(report)
        return
    for line in telemetry.trend_text(report):
        print(line)


API_VIEWS = {
    "peers": "getPeers",
    "stack-peers": "getPeers",
    "self": "getSelf",
    "tree": "getTree",
    "paths": "getPaths",
    "sessions": "getSessions",
}


@logged
def do_view(ctx, args, a):
    output(ctx.api(API_VIEWS[args.command], stack=args.command == "stack-peers"))


@logged
def do_check(ctx, args, a):
    checks.check(ctx)


@logged
def do_guard(ctx, args, a):
    print(checks.guard(ctx))
    print("GUARD PASS (not a numerical security score)")


@logged
def do_verify_hashes(ctx, args, a):
    print(f"integrity PASS members={checks.integrity(ctx)}")


@logged
def do_socks(ctx, args, a):
    print(checks.sockets(ctx))
    output(checks.underlay(ctx))


@logged
def do_socks_test(ctx, args, a):
    socks_test(ctx)


@logged
def do_mode(ctx, args, a):
    if not a or a == ["show"]:
        output({"mode": ctx.mode(), "proof": checks.underlay(ctx)})
    else:
        management.change_mode(ctx, a[0], args.apply)


@logged
def do_config(ctx, args, a):
    for name in ("yggdrasil-lab.conf", "yggstack.conf"):
        config = ctx.config(name)
        if not a or a == ["show"]:
            output({name: config})
        elif a == ["validate"]:
            if checks.safe_config(config):
                raise Failure("unsafe_config")
            print(name + " syntax/security PASS")
        else:
            raise Failure("config_edit_disabled_use_reviewed_transaction")


@logged
def do_service(ctx, args, a):
    management.service(ctx, args.command)


@logged
def do_peer(ctx, args, a):
    if len(a) != 1:
        raise Failure("one_peer_argument_required")
    management.change_peer(ctx, a[0], args.command == "remove-peer", args.force, args.apply)


@logged
def do_recover(ctx, args, a):
    management.recover_transaction(ctx, args.apply)


@logged
def do_collect(ctx, args, a):
    telemetry.collect(ctx)


@logged
def do_watch(ctx, args, a):
    count = bounded_number(a[0], 1, 60) if a else 5
    telemetry.watch(ctx, count, bounded_number(a[1], 1, 30) if len(a) > 1 else 2)


@logged
def do_notify(ctx, args, a):
    telemetry.notify(ctx, a[0] if len(a) == 1 else "show")


@logged
def do_alerts_forward(ctx, args, a):
    telemetry.forward(ctx)


@logged
def do_backup(ctx, args, a):
    recovery.backup(ctx, args.full, args.recipient)


@logged
def do_restore(ctx, args, a):
    if len(a) != 1:
        raise Failure("one_archive_path_required")
    recovery.restore(ctx, a[0], args.apply)


@logged
def do_snapshot(ctx, args, a):
    recovery.snapshot(ctx)


@logged
def do_diff(ctx, args, a):
    recovery.diff(ctx, a[0] if a else None)


@logged
def do_doctor(ctx, args, a):
    # Secret-free allowlisted backup and structured data; no broad log/config tar.
    recovery.backup(ctx)
    output(
        {
            "node": ctx.unit(NODE),
            "stack": ctx.unit(STACK),
            "timer": ctx.unit(TIMER),
            "pending_transaction": (ctx.p.state / "transaction.json").exists(),
        }
    )


@logged
def do_report(ctx, args, a):
    checks.check(ctx)
    telemetry.stats(ctx)


@logged
def do_research(ctx, args, a):
    import research

    output(research.command(ctx, a))


@logged
def do_atlas(ctx, args, a):
    import atlas

    output(atlas.command(ctx, a))


@logged
def journal_records(data):
    """Project JSON journal records; never expose raw records or partial secret values.

    A MESSAGE is the redaction boundary, including multiline/PEM contents. Dropping
    the whole sensitive message avoids guessing where a quoted value ends. Only a
    fixed unit label and a numeric timestamp are projected from journal metadata.
    """
    records = []
    for line in data.splitlines():
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError
            message = row.get("MESSAGE")
            if not isinstance(message, str):
                message = "[non-text journal message omitted]"
            probe = message
            # Decode nested JSON-style unicode escaping for detection only, never output it.
            for _ in range(4):
                probe = re.sub(r"\\u([0-9a-fA-F]{4})", unicode_escape, probe)
            if re.search(
                r"(?i)private[\s_-]*key|group[\s_-]*password|password|token|secret|authorization",
                probe,
            ) or re.search(r"\\u[0-9a-fA-F]{4}", probe):
                message = "[REDACTED sensitive journal message]"
                event("state", "journal_redaction", "message_omitted")
            else:
                # A journal line can carry a peer URI with userinfo or a private path
                # without any keyword. Apply the same output boundary as console/config.
                message = public_config(message)
            unit = row.get("_SYSTEMD_UNIT")
            at = row.get("__REALTIME_TIMESTAMP", "")
            records.append(
                {
                    "unit": unit if unit in (NODE, STACK) else "unknown",
                    "timestamp_us": at
                    if isinstance(at, str) and re.fullmatch(r"[0-9]{1,20}", at)
                    else "unknown",
                    "message": message,
                }
            )
        except (ValueError, TypeError, RecursionError):
            raise Failure("invalid_journal_json_no_raw_output") from None
    return records


@logged
def unicode_escape(match):
    return chr(int(match[1], 16))


@logged
def do_logs(ctx, args, a):
    n = bounded_number(a[0], 1, 1000) if a else 50
    command = [
        "/usr/bin/journalctl",
        "-u",
        NODE,
        "-u",
        STACK,
        "--no-pager",
        "-o",
        "json",
        "-n",
        str(n),
    ]
    if args.command == "events":
        command += ["--since", f"{bounded_number(a[0], 1, 72) if a else 6} hours ago"]
    output({"logs": journal_records(ctx.run(command).stdout)})


@logged
def do_firewall_status(ctx, args, a):
    checks.policy_gate(ctx)
    output(
        {"accepted_surface": "unchanged", "watchdog": "independent; no baseline/allowlist rewrite"}
    )


@logged
def do_ping(ctx, args, a):
    if len(a) != 1:
        raise Failure("one_overlay_ipv6_port_required")
    http_probe(ctx, a[0])


@logged
def do_bench(ctx, args, a):
    socks_test(ctx, bounded_number(a[0], 1, 3) if a else 1)


REMOTE_DEBUG = {
    "self": "debug_remotegetself",
    "peers": "debug_remotegetpeers",
    "tree": "debug_remotegettree",
}


@logged
def do_debug_remote(ctx, args, a):
    if len(a) == 2 and a[0] == "dht":
        raise Failure("remote_dht_not_supported_by_upstream_use_tree")
    if len(a) != 2 or a[0] not in REMOTE_DEBUG:
        raise Failure("debug_remote_self_peers_tree_key")
    output(ctx.api(REMOTE_DEBUG[a[0]], key=remote_key(ctx, a[1])))


@logged
def do_nodeinfo(ctx, args, a):
    if len(a) != 1:
        raise Failure("one_public_key_required")
    target = remote_key(ctx, a[0])
    output(ctx.api("getNodeInfo", key=target))
    if args.command == "whois":
        output(ctx.api("debug_remotegetself", key=target))


@logged
def do_peers_score(ctx, args, a):
    data = [dict(p, identified=checks.identified(p)) for p in checks.peers(ctx)]
    output(sorted(data, key=lambda p: (not p["identified"], p.get("latency", 0))))
    print(
        "Ranking by identified peer/latency only; raw up is transport state, "
        "not a trust/reliability or application-liveness score"
    )


@logged
def do_survey(ctx, args, a):
    if args.command == "traceroute":
        if len(a) != 1:
            raise Failure("one_public_key_required")
        key(a[0])
    output(ctx.api("getTree"))
    print("Tree introspection only; not forwarding path/traceroute; no automatic remote survey")


@logged
def do_discover(ctx, args, a):
    print(
        "Offline public-peers catalogue: Iggdrasil_full_repo/public-peers; "
        "no root git pull or TCP probe masquerading as QUIC test"
    )


@logged
def do_unit_show(ctx, args, a):
    if a and a != ["show"]:
        raise Failure("requires_reviewed_deployment_or_firewall_review")
    nameserver = args.command == "nameserver"
    output(ctx.unit(STACK if nameserver else TIMER))
    print(
        "nameserver not added; SOCKS remains 127.0.0.1:1080"
        if nameserver
        else "trusted deployer owns timer"
    )


APPLY = frozenset({"apply"})
SERVICES = (
    "start",
    "stop",
    "restart",
    "enable",
    "disable",
    "stack-start",
    "stack-stop",
    "stack-restart",
    "stack-enable",
    "stack-disable",
)
COMMANDS = {
    "help": Command(do_help, root=False),
    "--help": Command(do_help, root=False),
    "version": Command(do_version, root=False),
    "update-check": Command(do_update_check, root=False),
    "selftest": Command(do_selftest, most=1, root=False),
    "stats": Command(do_stats, most=1, root=False),
    "graph": Command(do_stats, most=1, root=False),
    "trend": Command(do_trend, most=2, root=False),
    **{name: Command(do_view) for name in API_VIEWS},
    "check": Command(do_check),
    "status": Command(do_check),
    "guard": Command(do_guard),
    "verify-hashes": Command(do_verify_hashes),
    "socks": Command(do_socks),
    "socks-test": Command(do_socks_test),
    "mode": Command(do_mode, most=1, flags=APPLY),
    "config": Command(do_config, most=1),
    **{name: Command(do_service) for name in SERVICES},
    "add-peer": Command(do_peer, most=-1, flags=frozenset({"apply", "force"})),
    "remove-peer": Command(do_peer, most=-1, flags=APPLY),
    "recover-transaction": Command(do_recover, flags=APPLY),
    "collect": Command(do_collect),
    "watch": Command(do_watch, most=2),
    "top": Command(do_watch, most=2),
    "notify": Command(do_notify, most=1),
    "alerts-forward": Command(do_alerts_forward),
    "backup": Command(do_backup, flags=frozenset({"full", "recipient"})),
    "restore": Command(do_restore, most=1, flags=APPLY),
    "snapshot": Command(do_snapshot),
    "diff": Command(do_diff, most=1),
    "doctor": Command(do_doctor),
    "report": Command(do_report),
    "research": Command(do_research, most=-1),
    "atlas": Command(do_atlas, most=-1),
    "logs": Command(do_logs, most=1),
    "events": Command(do_logs, most=1),
    "firewall-status": Command(do_firewall_status),
    "ping": Command(do_ping, most=1),
    "bench": Command(do_bench, most=1),
    "nodeinfo": Command(do_nodeinfo, most=1),
    "whois": Command(do_nodeinfo, most=1),
    "debug-remote": Command(do_debug_remote, most=-1),
    "peers-score": Command(do_peers_score),
    "survey": Command(do_survey),
    "traceroute": Command(do_survey, most=1),
    "discover": Command(do_discover),
    "nameserver": Command(do_unit_show, most=1),
    "timer": Command(do_unit_show, most=1),
}
LEGACY_DISABLED = ("purge", "rotate-key", "chaos", "upgrade", "baseline-update")


@logged
def dispatch(ctx, args):
    cmd, a = args.command, args.args
    spec = COMMANDS.get(cmd)
    if spec is not None and spec.most >= 0 and len(a) > spec.most:
        raise Failure("unexpected_arguments")
    flags = spec.flags if spec else frozenset()
    if args.apply and "apply" not in flags:
        raise Failure("apply_not_supported_here")
    if args.force and "force" not in flags:
        raise Failure("force_only_for_add_peer")
    if (args.full or args.recipient) and "full" not in flags:
        raise Failure("backup_options_only")
    if spec is None or spec.root:
        ctx.root()
    if spec is None:
        if cmd in LEGACY_DISABLED:
            raise Failure(
                "legacy_high_risk_operation_disabled_requires_separate_custody_review_and_tests"
            )
        raise Failure("unknown_command_use_help")
    if cmd in sandbox.ROLE_OF and not sandbox.inside() and ctx.p == Paths():
        # On the live system these run sandboxed as an unprivileged user (see sandbox.py).
        rc = sandbox.run(ctx, cmd, a, Path(__file__).resolve())
        if rc:
            raise Failure(f"sandboxed_{cmd}_failed:rc={rc}")
        return
    spec.handler(ctx, args, a)


# Only command words documented in HELP reach the run summary; anything else is "other".
RUN = {"command": "other"}


@logged
def run_label(command):
    documented = re.search(rf"(?<![\w-]){re.escape(command or '')}(?![\w-])", HELP)
    if re.fullmatch(r"[a-z][a-z-]{0,23}", command or "") and documented:
        return command
    return "other"


@logged
def interrupted(_signum, _frame):
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
    if args.help:
        args.command = "help"
    if args.trace:
        trace_live()
    RUN["command"] = run_label(args.command)
    signal.signal(signal.SIGTERM, interrupted)
    start = time.monotonic()
    try:
        dispatch(sandbox.worker_context() or Context(), args)
    except (Failure, OSError, ValueError, KeyError, TypeError) as exc:
        label = str(exc) if isinstance(exc, Failure) else "unavailable_or_invalid_data"
        print(
            f"FAIL {label}; processed=0 errors=1 elapsed={time.monotonic() - start:.2f}s",
            file=sys.stderr,
        )
        return 77 if label.startswith("root_required") else 1
    except KeyboardInterrupt:
        print("FAIL interrupted; rollback attempted if transaction active", file=sys.stderr)
        return 130
    print(f"[done] errors=0 elapsed={time.monotonic() - start:.2f}s")
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
