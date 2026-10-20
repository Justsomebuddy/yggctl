"""Sandboxed commands: atlas, research and the network commands that handle data from
other nodes run in a transient systemd unit as the unprivileged ygglab-worker user.

The root parent first runs what needs root (integrity for every role, the sockets check
for the commands that read it, the console lock for research), then serves the worker
read-only calls through broker.py. The worker
sees no node keys and only its own store; research has no network, the network commands
reach only localhost (the SOCKS proxy), atlas keeps TCP/UDP for the public-peer catalogue.
"""

import contextlib
import os
import re

import broker
import checks
from core import logged, trace_is_live

UNIT_PREFIX = "yggctl-sandbox-"
STATE = "/var/lib/yggdrasil-lab"
REMOTE_COMMANDS = (
    "ping",
    "bench",
    "socks-test",
    "nodeinfo",
    "whois",
    "debug-remote",
    "survey",
    "traceroute",
)
ROLE_OF = {"atlas": "atlas", "research": "research", **{c: "remote" for c in REMOTE_COMMANDS}}
COMMON = (
    f"User={broker.WORKER}",
    f"Group={broker.WORKER}",
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=EPERM",
    "UMask=0077",
    "TasksMax=64",
    "MemoryMax=2G",
    f"TemporaryFileSystem={STATE}:mode=0755",
    "InaccessiblePaths=/etc/yggdrasil-lab",
    "InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/ssh -/etc/sudoers -/etc/sudoers.d",
)
ROLES = {
    "atlas": (f"BindPaths={STATE}/atlas", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"),
    "research": (
        f"BindPaths={STATE}/research",
        "PrivateNetwork=yes",
        "RestrictAddressFamilies=AF_UNIX",
    ),
    "remote": (
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "IPAddressAllow=localhost",
        "IPAddressDeny=any",
    ),
}


@logged
def own_unit(cgroup="/proc/self/cgroup"):
    """(role, id) when this process runs in a yggctl sandbox unit, else None."""
    try:
        with open(cgroup, encoding="ascii", errors="replace") as f:
            text = f.read(65536)
    except OSError:
        return None
    for line in text.splitlines():
        m = re.search("/" + UNIT_PREFIX + r"(atlas|research|remote)-([0-9a-f]{8})\.service$", line)
        if m:
            return m[1], m[2]
    return None


@logged
def inside(cgroup="/proc/self/cgroup"):
    return own_unit(cgroup) is not None


@logged
def worker_context():
    """The broker-backed context of a sandboxed worker, or None outside a sandbox."""
    unit = own_unit()
    if unit is None or os.geteuid() == 0:
        return None
    return broker.WorkerContext(broker.BROKER_DIR / f"{unit[0]}-{unit[1]}.sock")


@logged
def properties(role):
    if role not in ROLES:
        raise ValueError("unknown sandbox role")
    return list(COMMON) + list(ROLES[role])


@logged
def command(role, cmd, args, main_path, unit_id, *, trace=False):
    """systemd-run argv for one sandboxed yggctl command, and the unit to stop on interrupt."""
    unit = f"{UNIT_PREFIX}{role}-{unit_id}.service"
    argv = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        f"--unit={unit}",
    ]
    for prop in properties(role):
        argv += ["-p", prop]
    argv += ["--", "/usr/bin/python3", "-I", "-B", str(main_path)]
    argv += ["--trace"] if trace else []
    argv += [cmd, *args]
    return unit, argv


@logged
def run(ctx, cmd, args, main_path):
    role = ROLE_OF[cmd]
    ctx.root()
    with contextlib.ExitStack() as stack:
        if role == "research":
            stack.enter_context(ctx.locked())  # research expects the console lock for its whole run
        with ctx.locked():
            # Every sandboxed role gets the integrity check the worker is told about.
            checks.integrity(ctx)
        if cmd in ("bench", "socks-test"):
            checks.sockets(ctx)
        served = stack.enter_context(broker.Broker(ctx, role))
        unit, argv = command(role, cmd, args, main_path, served.unit_id, trace=trace_is_live())
        return ctx.run_attached(argv, stop=["/usr/bin/systemctl", "stop", unit])
