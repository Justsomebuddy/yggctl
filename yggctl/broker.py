"""Privilege separation for sandboxed commands.

Sandboxed commands use separate role users. The root parent authenticates both the
kernel peer UID and its exact parent-selected systemd cgroup before serving
the worker a few read-only calls over a private Unix socket: allowlisted admin API
methods of the local node (output passed through as raw bytes, never parsed as root)
and, for research, the metrics file. The node admin socket itself stays root-only.
"""

import base64
import contextlib
import json
import os
import pwd
import re
import secrets
import socket
import stat
import struct
import subprocess  # nosec B404 # CompletedProcess only; process execution uses Context.
import threading
from pathlib import Path

from core import Context, Failure, event, logged, METRICS_LIMIT

USERS = {"research": "ygglab-research", "atlas": "ygglab-atlas", "remote": "ygglab-remote"}
BROKER_DIR = Path("/run/yggctl-broker")
LOCAL = frozenset({"getself", "getpeers", "gettree", "getpaths", "getsessions"})
REMOTE = frozenset(
    {"getnodeinfo", "debug_remotegetself", "debug_remotegetpeers", "debug_remotegettree"}
)
# The role is chosen by the parent, never by the worker's request.
# Atlas needs exactly its three debug reads; research cannot initiate remote queries.
ADMIN_METHODS = {
    "research": LOCAL,
    "atlas": LOCAL | (REMOTE - {"getnodeinfo"}),
    "remote": LOCAL | REMOTE,
}
LINE_LIMIT = 64 * 1024
REPLY_LIMIT = 24 * 1024 * 1024
# ceil(raw / 3) * 4, plus the exact compact {"data":""}\n envelope.
# Keep admin replies at their existing, smaller bound.
METRICS_REPLY_LIMIT = 4 * ((METRICS_LIMIT + 2) // 3) + 12


@logged
def worker_uid(role="research"):
    try:
        uid = pwd.getpwnam(USERS[role]).pw_uid
    except KeyError:
        raise Failure("sandbox_worker_user_missing") from None
    if uid <= 0:
        raise Failure("sandbox_worker_must_be_unprivileged")
    return uid


@logged
def process_cgroup(pid, proc=Path("/proc")):
    """Bounded kernel cgroup-v2 observation; never trust a request's role/PID."""
    if type(pid) is not int or pid <= 0:
        raise Failure("broker_peer_pid_invalid")
    event("external_start", "broker_peer_cgroup")
    # procfs reports st_size=0 even for nonempty files. Bound the actual read,
    # rather than using the regular-state-file size/equality contract.
    with open(proc / str(pid) / "cgroup", "rb") as stream:
        data = stream.read(8193)
    if len(data) > 8192:
        raise Failure("file_size_limit")
    # Hybrid hosts can also expose v1 controllers (e.g. net_cls). Only the
    # unique unified-hierarchy row is authoritative for the system unit.
    groups = [line[3:] for line in data.decode("ascii").splitlines() if line.startswith("0::/")]
    if len(groups) != 1:
        raise Failure("broker_peer_cgroup_invalid")
    event("external_exit", "broker_peer_cgroup", "observed")
    return groups[0]


@logged
def admin_argv(ctx, method, args, role):
    """Rebuild a role-allowlisted yggdrasilctl call with validated arguments."""
    name = method.lower() if isinstance(method, str) else ""
    if name not in ADMIN_METHODS.get(role, frozenset()):
        raise Failure("broker_call_not_allowed")
    if name in LOCAL and args == []:
        tail = []
    elif (
        name in REMOTE
        and isinstance(args, list)
        and len(args) == 1
        and isinstance(args[0], str)
        and re.fullmatch(r"key=[0-9a-fA-F]{64}", args[0])
    ):
        tail = [args[0]]
    else:
        raise Failure("broker_call_not_allowed")
    return [ctx.p.ctl, "-json", f"-endpoint=unix://{ctx.p.node_sock}", method, *tail]


class Broker:
    """One client from the selected role UID AND this launch's exact system unit."""

    @logged
    def __init__(self, ctx, role, uid=None, directory=BROKER_DIR, *, expected_cgroup=None):
        if role not in USERS:
            raise Failure("sandbox_unknown_role")
        self.ctx, self.role = ctx, role
        self.uid = worker_uid(role) if uid is None else uid
        self.unit_id = secrets.token_hex(4)
        self.cgroup = (
            expected_cgroup or f"/system.slice/yggctl-sandbox-{role}-{self.unit_id}.service"
        )
        directory.mkdir(mode=0o711, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise Failure("broker_directory_untrusted")
        os.chmod(directory, 0o711)  # nosec B103 # traversal only; socket is 0600 + kernel-authenticated.
        self.path = directory / f"{role}-{self.unit_id}.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path))
        os.chown(self.path, self.uid, -1)
        os.chmod(self.path, 0o600)
        self.server.listen(1)
        self.server.settimeout(0.5)
        self.stop = threading.Event()
        self.conn = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @logged
    def peer_allowed(self, conn):
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", creds)
            return uid == self.uid and process_cgroup(pid) == self.cgroup
        except (OSError, Failure, ValueError, UnicodeError, struct.error):
            event("state", "broker", "peer_identity_unavailable_rejected")
            return False

    @logged
    def accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return None
            if self.peer_allowed(conn):
                return conn
            event("state", "broker", "foreign_peer_rejected")
            conn.close()
        return None

    @logged
    def serve(self):
        conn = self.accept()
        if conn is None:
            return
        self.conn = conn
        try:
            with conn, conn.makefile("rb") as reader:
                while not self.stop.is_set():
                    line = reader.readline(LINE_LIMIT + 1)
                    if not line or len(line) > LINE_LIMIT:
                        return
                    conn.sendall(
                        json.dumps(self.handle(line), separators=(",", ":")).encode() + b"\n"
                    )
        except OSError:
            event("state", "broker", "connection_closed")

    @logged
    def handle(self, line):
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError()
            if request.get("call") == "admin":
                timeout = request.get("timeout", 20)
                if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 60:
                    raise Failure("broker_bad_timeout")
                argv = admin_argv(
                    self.ctx, request.get("method"), request.get("args", []), self.role
                )
                r = self.ctx.run(argv, timeout=timeout, check=False, cancel=self.stop)
                return {
                    "rc": r.returncode,
                    "stdout": base64.b64encode(r.stdout).decode(),
                    "stderr": base64.b64encode(r.stderr[:65536]).decode(),
                }
            if request.get("call") == "metrics" and self.role == "research":
                data = self.ctx.read_state("metrics.jsonl", METRICS_LIMIT)
                return {"data": None if data is None else base64.b64encode(data).decode()}
            raise Failure("broker_call_not_allowed")
        except Failure as exc:
            return {"error": str(exc)[:120]}
        except (ValueError, TypeError, OSError):
            return {"error": "broker_bad_request"}

    @logged
    def close(self):
        self.stop.set()
        with contextlib.suppress(OSError):
            self.server.close()
        if self.conn is not None:
            with contextlib.suppress(OSError):
                self.conn.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.path.unlink()
        # The admin subprocess is owned by this broker, not by the worker unit.
        # Do not return while its serving thread is still killing/reaping it.
        self.thread.join()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class WorkerContext(Context):
    """Worker side: parent checks integrity; sockets are checked for bench/socks-test."""

    parent_verified = frozenset({"integrity", "sockets"})

    @logged
    def __init__(self, sock_path, paths=None):
        super().__init__(paths=paths, require_root=False)
        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.conn.connect(str(sock_path))
        self.reader = self.conn.makefile("rb")
        self.call_lock = threading.Lock()

    @logged
    def root(self):
        return

    @contextlib.contextmanager
    def locked(self):
        # The parent holds the console lock for the roles that need it.
        yield

    @logged
    def call(self, request):
        line = json.dumps(request, separators=(",", ":")).encode()
        if len(line) > LINE_LIMIT:
            raise Failure("broker_request_too_large")
        reply_limit = METRICS_REPLY_LIMIT if request.get("call") == "metrics" else REPLY_LIMIT
        with self.call_lock:
            self.conn.sendall(line + b"\n")
            reply = self.reader.readline(reply_limit + 1)
        if not reply or len(reply) > reply_limit:
            raise Failure("broker_unavailable")
        try:
            value = json.loads(reply)
        except ValueError:
            raise Failure("broker_invalid_reply") from None
        if not isinstance(value, dict):
            raise Failure("broker_invalid_reply")
        if "error" in value:
            raise Failure(str(value["error"])[:120])
        return value

    @logged
    def run(self, argv, *, timeout=20, check=True, input=None, pass_fds=()):
        if str(argv[0]) != str(self.p.ctl):
            return super().run(argv, timeout=timeout, check=check, input=input, pass_fds=pass_fds)
        argv = [str(v) for v in argv]
        if len(argv) < 4 or argv[1] != "-json" or argv[2] != f"-endpoint=unix://{self.p.node_sock}":
            raise Failure("broker_call_not_allowed")
        event("external_start", "yggdrasilctl")
        reply = self.call(
            {"call": "admin", "method": argv[3], "args": argv[4:], "timeout": timeout}
        )
        try:
            r = subprocess.CompletedProcess(
                argv,
                int(reply["rc"]),
                base64.b64decode(reply["stdout"]),
                base64.b64decode(reply["stderr"]),
            )
        except (KeyError, TypeError, ValueError):
            raise Failure("broker_invalid_reply") from None
        event("external_exit", "yggdrasilctl", f"rc={r.returncode}")
        if check and r.returncode:
            raise Failure(f"external_failed:yggdrasilctl:rc={r.returncode}")
        return r

    @logged
    def read_state(self, name, limit):
        if name != "metrics.jsonl":
            raise Failure("state_not_available_in_sandbox")
        data = self.call({"call": "metrics"}).get("data")
        if data is None:
            return None
        try:
            raw = base64.b64decode(data)
        except (TypeError, ValueError):
            raise Failure("broker_invalid_reply") from None
        if len(raw) > limit:
            raise Failure("file_size_limit")
        return raw
