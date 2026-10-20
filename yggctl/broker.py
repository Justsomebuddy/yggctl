"""Privilege separation for sandboxed commands.

Sandboxed commands run as the unprivileged ygglab-worker user. The root parent serves
the worker a few read-only calls over a private Unix socket: admin API methods
allowlisted for that worker's role (local reads for every role, remote-node queries only
for the role whose unit may reach the network), with output passed through as raw bytes
and never parsed as root, and, for research, the metrics file. The node admin socket
itself stays root-only.
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

# Security review: mock-compatible result records; no process is spawned here
import subprocess  # nosec B404
import threading
from pathlib import Path

from core import Context, Failure, event, logged, METRICS_LIMIT

WORKER = "ygglab-worker"
BROKER_DIR = Path("/run/yggctl-broker")
LOCAL = frozenset({"getself", "getpeers", "gettree", "getpaths", "getsessions"})
REMOTE = frozenset(
    {"getnodeinfo", "debug_remotegetself", "debug_remotegetpeers", "debug_remotegettree"}
)
# Admin methods each sandbox role may ask the parent to run. Only the role whose
# unit is allowed network access may reach methods that talk to other nodes.
ADMIN_METHODS = {
    "research": LOCAL,
    "atlas": LOCAL,
    "remote": LOCAL | REMOTE,
}
LINE_LIMIT = 64 * 1024
REPLY_LIMIT = 24 * 1024 * 1024
# ceil(raw / 3) * 4, plus the exact compact {"data":""}\n envelope.
# Keep admin replies at their existing, smaller bound.
METRICS_REPLY_LIMIT = 4 * ((METRICS_LIMIT + 2) // 3) + 12


@logged
def worker_uid():
    try:
        return pwd.getpwnam(WORKER).pw_uid
    except KeyError:
        raise Failure("sandbox_worker_user_missing") from None


@logged
def admin_argv(ctx, method, args, role):
    """Rebuild a yggdrasilctl call from a method allowlisted for this sandbox role."""
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
    """Parent side: one private socket that serves one connection from the worker uid."""

    @logged
    def __init__(self, ctx, role, uid=None, directory=BROKER_DIR):
        self.ctx, self.role = ctx, role
        self.uid = worker_uid() if uid is None else uid
        self.unit_id = secrets.token_hex(4)
        directory.mkdir(mode=0o711, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise Failure("broker_directory_untrusted")
        # Security review: worker needs traversal only; socket is uid-owned 0600 and peer credentials checked
        os.chmod(directory, 0o711)  # nosec B103
        self.path = directory / f"{role}-{self.unit_id}.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path))
        os.chown(self.path, self.uid, -1)
        os.chmod(self.path, 0o600)
        self.server.listen(1)
        self.server.settimeout(0.5)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @logged
    def accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return None
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            if struct.unpack("3i", creds)[1] == self.uid:
                return conn
            event("state", "broker", "foreign_peer_rejected")
            conn.close()
        return None

    @logged
    def serve(self):
        conn = self.accept()
        if conn is None:
            return
        with conn, conn.makefile("rb") as reader:
            while not self.stop.is_set():
                line = reader.readline(LINE_LIMIT + 1)
                if not line or len(line) > LINE_LIMIT:
                    return
                conn.sendall(json.dumps(self.handle(line), separators=(",", ":")).encode() + b"\n")

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
                r = self.ctx.run(argv, timeout=timeout, check=False)
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
        with contextlib.suppress(OSError):
            self.path.unlink()
        self.thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class WorkerContext(Context):
    """Worker side: no root and no console lock.

    The parent runs the integrity check for every sandboxed role before starting the unit,
    and the sockets check for the commands that read it, so the worker does not repeat them.
    """

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
