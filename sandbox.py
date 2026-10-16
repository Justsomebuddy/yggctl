"""Atlas and research run in a transient systemd sandbox.

They keep uid 0 because they need the node admin socket and their root-only stores,
but they run without capabilities, on a read-only system, without the node keys,
and see only their own entries of the state directory. Research has no network;
atlas keeps TCP/UDP for the pinned public-peer catalogue.
"""
import re
import secrets
from pathlib import Path

from core import KEYS, logged, read_regular, trace_is_live

UNIT_PREFIX = "yggctl-sandbox-"
STATE = "/var/lib/yggdrasil-lab"
ETC = "/etc/yggdrasil-lab"
COMMON = (
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
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
    # Only the entries these commands use are visible in the state directory.
    f"TemporaryFileSystem={STATE}:mode=0755",
    f"BindPaths={STATE}/.console.lock",
    f"BindReadOnlyPaths=-{STATE}/metrics.jsonl",
    # The integrity gate needs the manifest and its members; the keys are never members.
    f"TemporaryFileSystem={ETC}:mode=0755",
    "InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/ssh -/etc/sudoers -/etc/sudoers.d",
)
ROLES = {
    "atlas": (f"BindPaths={STATE}/atlas", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"),
    "research": (f"BindPaths={STATE}/research", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX"),
}


@logged
def inside(cgroup="/proc/self/cgroup"):
    """True when this process already runs in a yggctl sandbox unit."""
    try:
        with open(cgroup, encoding="ascii", errors="replace") as f:
            text = f.read(65536)
    except OSError:
        return False
    return any(("/" + UNIT_PREFIX) in line for line in text.splitlines())


@logged
def etc_allowlist(ctx):
    """The manifest and its members under /etc/yggdrasil-lab, never a key file."""
    manifest = ctx.p.etc / "integrity.manifest"
    paths = {str(manifest)}
    for line in read_regular(manifest).decode().splitlines():
        m = re.fullmatch(r"[0-9a-f]{64}  (.+)", line)
        if m and m[1].startswith(str(ctx.p.etc) + "/") and not Path(m[1]).name.startswith(KEYS):
            paths.add(m[1])
    return sorted(paths)


@logged
def properties(role, etc_files=()):
    if role not in ROLES:
        raise ValueError("unknown sandbox role")
    return list(COMMON) + [f"BindReadOnlyPaths={p}" for p in etc_files] + list(ROLES[role])


@logged
def command(role, args, main_path, *, etc_files=(), trace=False):
    """systemd-run argv for one sandboxed yggctl command, and the unit to stop on interrupt."""
    unit = f"{UNIT_PREFIX}{role}-{secrets.token_hex(4)}.service"
    argv = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
            "--service-type=exec", f"--unit={unit}"]
    for prop in properties(role, etc_files):
        argv += ["-p", prop]
    argv += ["--", "/usr/bin/python3", "-I", "-B", str(main_path)]
    argv += ["--trace"] if trace else []
    argv += [role, *args]
    return unit, argv


@logged
def run(ctx, role, args, main_path):
    unit, argv = command(role, args, main_path, etc_files=etc_allowlist(ctx), trace=trace_is_live())
    return ctx.run_attached(argv, stop=["/usr/bin/systemctl", "stop", unit])
