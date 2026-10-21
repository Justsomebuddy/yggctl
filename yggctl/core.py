"""Trusted paths, secret-safe tracing, execution, parsing and atomic I/O."""

from __future__ import annotations

from typing import BinaryIO, TypedDict, cast

import collections
import contextlib
import dataclasses
import datetime as dt
import fcntl
import functools
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat

# Security review: argv-only process primitives; call sites reviewed below
import subprocess  # nosec B404
import syslog
import tempfile
import threading
import time
import urllib.parse

VERSION = "5.9.0"
# The reader accepts the writer's full pre-compaction retention window.
METRIC_RETENTION = 10000
METRIC_RECORD_LIMIT = METRIC_RETENTION * 6 // 5
METRICS_LIMIT = 32 * 1024 * 1024
NODE = "yggdrasil-lab.service"
STACK = "yggstack-lab.service"
TIMER = "ygg-metrics.timer"
FILES = ("yggdrasil-lab.conf", "yggstack.conf", "gate.nft", "gate-yggstack.nft", "mode")
KEYS = ("private.key", "yggstack-private.key")


class Failure(Exception):
    """A safe fixed-label error suitable for operator output."""

    pass


# Routine call tracing (entry/exit, successful external calls, the mutation lock)
# is held in memory and reaches syslog only with --trace or when the run fails;
# errors, alerts and other state changes are written at once. Every run ends with
# one summary line. The tracing sink itself is not traced.
TRACE_KEEP = 400
_ROUTINE = frozenset({"entry", "exit", "external_start", "external_exit"})
_ROUTINE_STATE = frozenset({"mutation_lock"})
_trace_lock = threading.Lock()


class _TraceState(TypedDict):
    live: bool
    quiet: bool
    held: int
    lines: collections.deque[str]


_trace: _TraceState = {
    "live": False,
    "quiet": False,
    "held": 0,
    "lines": collections.deque(maxlen=TRACE_KEEP),
}


def event(kind, label, result=""):
    """Only trusted identifiers/results, never function args or subprocess output."""
    line = f"yggctl {kind} {label} {result}"[:256]
    routine = kind in _ROUTINE or (kind == "state" and label in _ROUTINE_STATE)
    with _trace_lock:
        if (routine or _trace["quiet"]) and not _trace["live"]:
            _trace["held"] += 1
            _trace["lines"].append(line)
            return
    syslog.syslog(syslog.LOG_INFO, line)


def trace_is_live():
    with _trace_lock:
        return _trace["live"]


def trace_quiet(enabled=True):
    """Offline selftest: hold every event, the expected errors of negative tests included;
    they reach syslog only if the run fails."""
    with _trace_lock:
        _trace["quiet"] = enabled


def trace_live():
    """--trace: write the held trace now and every later event at once."""
    with _trace_lock:
        lines = list(_trace["lines"])
        _trace["lines"].clear()
        _trace["live"] = True
    for line in lines:
        syslog.syslog(syslog.LOG_INFO, line)


def finish_run(command, status):
    """Write the run summary; a failed run first writes its held trace."""
    with _trace_lock:
        held = _trace["held"]
        lines = list(_trace["lines"]) if status else []
        _trace["lines"].clear()
        _trace["held"] = 0
    for line in lines:
        syslog.syslog(syslog.LOG_INFO, line)
    summary = f"yggctl run {command} status={status} traced={held}"
    if status and held > len(lines):
        summary += f" trace_kept={len(lines)}"
    syslog.syslog(syslog.LOG_INFO, summary[:256])


def logged(fn):
    @functools.wraps(fn)
    def traced(*args, **kwargs):
        event("entry", fn.__name__)
        try:
            value = fn(*args, **kwargs)
        except BaseException as exc:
            event("error", fn.__name__, type(exc).__name__)
            raise
        event(
            "exit",
            fn.__name__,
            f"status={value}" if fn.__name__ == "main" and type(value) is int else "success",
        )
        return value

    return traced


@logged
def bounded_process(
    argv, *, input=None, stdout=None, stderr=None, timeout=20, env=None, pass_fds=(), check=False
):
    """Multiplex bounded pipes; no plaintext spooling and no unbounded communicate()."""
    # Security review: caller supplies reviewed argv; shell execution is not enabled
    proc = subprocess.Popen(  # nosec B603
        argv,
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        pass_fds=pass_fds,
        start_new_session=True,
        bufsize=0,
    )
    selector = selectors.DefaultSelector()
    data = {"out": bytearray(), "err": bytearray()}
    # PIPE streams exist by Popen construction; stdin exists only with input.
    outgoing = cast(BinaryIO, proc.stdout)
    errors = cast(BinaryIO, proc.stderr)
    incoming = cast(BinaryIO, proc.stdin)
    pending = memoryview(input or b"")
    deadline = time.monotonic() + timeout
    try:
        for stream, name in ((outgoing, "out"), (errors, "err")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if input is not None:
            os.set_blocking(incoming.fileno(), False)
            if pending:
                selector.register(incoming, selectors.EVENT_WRITE, "in")
            else:
                incoming.close()
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise subprocess.TimeoutExpired(Path(argv[0]).name, timeout)
            for item, _ in selector.select(min(left, 0.5)):
                if item.data == "in":
                    try:
                        count = os.write(item.fd, pending[:65536])
                        pending = pending[count:]
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        selector.unregister(item.fileobj)
                        incoming.close()
                else:
                    chunk = os.read(item.fd, 65536)
                    if not chunk:
                        selector.unregister(item.fileobj)
                        continue
                    data[item.data].extend(chunk)
                    cap = 16 * 1024 * 1024 if item.data == "out" else 1024 * 1024
                    if len(data[item.data]) > cap:
                        raise Failure("external_output_limit")
        rc = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(argv, rc, bytes(data["out"]), bytes(data["err"]))
    except BaseException:
        event("external_error", "bounded_process", "terminated_own_process_group")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        raise
    finally:
        selector.close()
        for cleanup_stream in (proc.stdin, proc.stdout, proc.stderr):
            if cleanup_stream is not None:
                cleanup_stream.close()
        proc.wait()


@logged
def attached_process(argv, *, stop):
    """Run a long child on this terminal's stdio. If this process is interrupted, stop
    the child's unit first, then wait for the child to exit."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    # Security review: caller supplies reviewed argv; shell execution is not enabled
    proc = subprocess.Popen(argv, env=env, close_fds=True)  # nosec B603
    try:
        return proc.wait()
    except BaseException:
        try:
            # Security review: caller supplies reviewed argv; shell execution is not enabled
            subprocess.run(  # nosec B603
                stop,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        finally:
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        raise


@dataclasses.dataclass(frozen=True)
class Paths:
    etc: Path = Path("/etc/yggdrasil-lab")
    units: Path = Path("/etc/systemd/system")
    state: Path = Path("/var/lib/yggdrasil-lab")
    runtime: Path = Path("/usr/local/libexec/yggdrasil-lab")
    node_sock: Path = Path("/run/yggdrasil-lab/admin.sock")
    stack_sock: Path = Path("/run/yggstack-lab/admin.sock")
    ctl: str = "/usr/sbin/yggdrasilctl"
    node: str = "/usr/sbin/yggdrasil"
    stack: str = "/usr/local/sbin/yggstack"
    decoder: str = "/usr/local/libexec/yggdrasil-lab/config-json"


class Context:
    # Checks a root parent already ran for a sandboxed worker (see broker.WorkerContext).
    parent_verified: frozenset[str] = frozenset()

    @logged
    def __init__(self, paths=None, runner=None, require_root=True, attached=None):
        self.p = paths or Paths()
        self.runner = runner or bounded_process
        self.attached = attached or attached_process
        self.require_root = require_root
        self.lock_depth = 0
        self.thread_lock = threading.RLock()

    @logged
    def root(self):
        if self.require_root and os.geteuid() != 0:
            raise Failure("root_required: run sudo yggctl")

    @logged
    def run(self, argv, *, timeout=20, check=True, input=None, pass_fds=()):
        executable = Path(argv[0]).name
        event("external_start", executable)
        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin",
            "LANG": "C.UTF-8",
            "HOME": "/root" if os.geteuid() == 0 else str(Path.home()),
        }
        try:
            r = self.runner(
                list(map(str, argv)),
                input=input,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=env,
                pass_fds=pass_fds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            event("external_error", executable, type(exc).__name__)
            raise Failure(f"external_unavailable:{executable}") from None
        event("external_exit", executable, f"rc={r.returncode}")
        if len(r.stdout) > 16 * 1024 * 1024 or len(r.stderr) > 1024 * 1024:
            raise Failure(f"external_output_limit:{executable}")
        if check and r.returncode:
            raise Failure(f"external_failed:{executable}:rc={r.returncode}")
        return r

    @logged
    def read_state(self, name, limit):
        """Contents of one state file, or None when it does not exist."""
        path = self.p.state / name
        return read_regular(path, limit) if path.exists() else None

    @logged
    def run_attached(self, argv, *, stop):
        executable = Path(argv[0]).name
        event("external_start", executable)
        try:
            rc = self.attached(list(map(str, argv)), stop=list(map(str, stop)))
        except OSError as exc:
            event("external_error", executable, type(exc).__name__)
            raise Failure(f"external_unavailable:{executable}") from None
        event("external_exit", executable, f"rc={rc}")
        return rc

    @logged
    def api(self, method, *, stack=False, **values):
        sock = self.p.stack_sock if stack else self.p.node_sock
        args = [self.p.ctl, "-json", f"-endpoint=unix://{sock}", method]
        args.extend(f"{k}={v}" for k, v in values.items())
        r = self.run(args)
        try:
            result = json.loads(r.stdout)
        except (ValueError, UnicodeError):
            raise Failure("admin_invalid_json") from None
        if not isinstance(result, dict) or result.get("error") or result.get("status") == "error":
            raise Failure("admin_error_response")
        return result

    @logged
    def unit(self, unit):
        r = self.run(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "--property=ActiveState,SubState,MainPID,NRestarts,UnitFileState,ExecMainStatus",
            ]
        )
        return dict(line.split("=", 1) for line in r.stdout.decode().splitlines() if "=" in line)

    @logged
    def config(self, name):
        content = read_regular(self.p.etc / name)
        r = self.run([self.p.decoder], input=content)
        try:
            data = json.loads(r.stdout)
        except ValueError:
            raise Failure("config_decoder_invalid_output") from None
        if not isinstance(data, dict):
            raise Failure("config_not_object")
        return data

    @logged
    def mode(self):
        value = read_regular(self.p.etc / "mode", limit=32).decode().strip()
        if value not in ("direct", "tunnel"):
            raise Failure("invalid_underlay_mode")
        return value

    @contextlib.contextmanager
    def locked(self):
        event("entry", "locked")
        try:
            with self.thread_lock:
                with self._locked():
                    yield
        except BaseException as exc:
            event("error", "locked", type(exc).__name__)
            raise
        finally:
            event("exit", "locked")

    @contextlib.contextmanager
    def _locked(self):
        event("entry", "_locked")
        self.root()
        if self.lock_depth:
            self.lock_depth += 1
            try:
                yield
            finally:
                self.lock_depth -= 1
                event("exit", "locked", "nested")
            return
        self.p.state.mkdir(mode=0o755, parents=True, exist_ok=True)
        path = self.p.state / ".console.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise Failure("unsafe_lock_file")
            if self.require_root and info.st_uid != 0:
                raise Failure("lock_not_root_owned")
            deadline = time.monotonic() + 20
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Failure("mutation_lock_timeout")
                    time.sleep(0.1)
            self.lock_depth = 1
            event("state", "mutation_lock", "acquired")
            yield
        except BaseException as exc:
            event("error", "locked", type(exc).__name__)
            raise
        finally:
            self.lock_depth = 0
            os.close(fd)
            event("state", "mutation_lock", "released")
            event("exit", "locked")


@logged
def read_regular(path, limit=1048576):
    # Reject FIFO/device input after fstat without blocking in open first.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Failure("not_regular_file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise Failure("file_size_limit")
        return data
    finally:
        os.close(fd)


@logged
def atomic(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir():
        raise Failure("unsafe_atomic_path")
    fd, tmp = tempfile.mkstemp(prefix=".yggctl-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# Only typed public pin/timing options may survive a peer's display identity.
# Unknown options (including encoded/case-varied credentials) discard ALL URI
# metadata, not only a guessed password value. Old safe labels remain stable.
PUBLIC_PEER_OPTIONS = {
    "key": r"[0-9a-fA-F]{64}",
    "maxbackoff": r"[0-9]{1,5}(?:ms|s|m|h)",
    "priority": r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
}
PUBLIC_PEER_SCHEMES = ("tls", "tcp", "quic", "ws", "wss")
URI_IN_TEXT = re.compile(r"(?:tls|tcp|quic|ws|wss)://[^\s\"'`<>()\[\],;]+")


@logged
def public_peer_uri(value):
    """Credential-free rendering of a peer URI, or None when value is not one."""
    if not isinstance(value, str) or len(value) > 4096 or re.search(r"[\s\x00-\x1f]", value):
        return None
    try:
        uri = urllib.parse.urlsplit(value)
        hostname = uri.hostname or ""
        if "%" in hostname:
            raise ValueError("scoped_endpoint_not_public_label")
        host = ipaddress.ip_address(hostname)
        port = uri.port
    except ValueError:
        return None
    if uri.scheme not in PUBLIC_PEER_SCHEMES or not port:
        return None
    authority = f"[{host}]" if host.version == 6 else str(host)
    endpoint = f"{uri.scheme}://{authority}:{port}"
    try:
        options = urllib.parse.parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return endpoint
    safe_options = len({k for k, _ in options}) == len(options) and all(
        re.fullmatch(PUBLIC_PEER_OPTIONS.get(k, r"(?!)"), v) for k, v in options
    )
    if (
        uri.username is None
        and uri.password is None
        and not uri.fragment
        and uri.path in ("", "/")
        and safe_options
    ):
        return value
    return endpoint


@logged
def _public_uri_in_text(match):
    """Redact one URI token inside free text, keeping trailing punctuation."""
    raw, trail = match.group(0), ""
    while raw and raw[-1] in ".:":
        trail, raw = raw[-1] + trail, raw[:-1]
    safe = public_peer_uri(raw)
    if safe is None:
        # Not a well-formed yggdrasil URI (for example a DNS name): still drop
        # credentials, fragment and query rather than echoing them.
        safe = raw.split("#", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1] or "[REDACTED-URI]"
    return safe + trail


@logged
def public_config(data):
    secret = {"privatekey", "grouppassword", "password", "token", "secret"}
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if k.lower() in secret and v else public_config(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [public_config(v) for v in data]
    if isinstance(data, str) and "://" in data:
        return URI_IN_TEXT.sub(_public_uri_in_text, data)
    return data


@logged
def peer_uri(uri, force=False):
    if not isinstance(uri, str) or len(uri) > 2048 or re.search(r"[\s\x00-\x1f]", uri):
        raise Failure("invalid_peer_uri")
    try:
        u = urllib.parse.urlsplit(uri)
        port = u.port
        host = u.hostname
    except ValueError:
        raise Failure("invalid_peer_uri") from None
    if (
        u.scheme not in ("tls", "tcp", "quic", "ws", "wss")
        or not host
        or not port
        or u.fragment
        or u.username
    ):
        raise Failure("invalid_peer_uri")
    try:
        addr = ipaddress.ip_address(host)
        if addr.version != 4:
            raise Failure("ipv4_literal_required")
    except ValueError:
        # --force permits WS/WSS, never unreviewed DNS off-tunnel selectors.
        raise Failure("ipv4_literal_required") from None
    if u.scheme in ("ws", "wss") and not force:
        raise Failure("ws_wss_require_force")
    try:
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise Failure("invalid_peer_query") from None
    if any(len(v) != 1 for v in q.values()) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", q.get("key", [""])[0]
    ):
        raise Failure("one_valid_key_pin_required")
    if u.scheme not in ("ws", "wss") and u.path not in ("", "/"):
        raise Failure("unexpected_peer_path")
    if any(k not in {"key", "sni", "maxbackoff", "priority", "origin"} for k in q):
        raise Failure("unsupported_peer_option")
    if "sni" in q and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", q["sni"][0]):
        raise Failure("invalid_sni")
    if "origin" in q:
        origin = q["origin"][0]
        try:
            o = urllib.parse.urlsplit(origin)
            _ = o.port  # Access validates malformed and out-of-range origin ports.
        except ValueError:
            raise Failure("invalid_origin") from None
        if (
            u.scheme not in ("ws", "wss")
            or len(origin) > 255
            or re.search(r"[\s\x00-\x1f]", origin)
            or o.scheme not in ("http", "https")
            or not o.hostname
            or o.username is not None
            or o.password is not None
            or o.query
            or o.fragment
            or o.path not in ("", "/")
        ):
            raise Failure("invalid_or_credential_bearing_origin")
    if "maxbackoff" in q and not re.fullmatch(r"[0-9]{1,5}(ms|s|m|h)", q["maxbackoff"][0]):
        raise Failure("invalid_maxbackoff")
    if "priority" in q and (
        not q["priority"][0].isdigit() or not 0 <= int(q["priority"][0]) <= 255
    ):
        raise Failure("invalid_priority")
    q["key"] = [q["key"][0].lower()]
    q.setdefault("maxbackoff", ["30s"])
    query = urllib.parse.urlencode(sorted((k, v[0]) for k, v in q.items()))
    canonical = urllib.parse.urlunsplit((u.scheme, f"{addr}:{port}", u.path, query, ""))
    return canonical, f"{addr}:{port}"


@logged
def endpoint(uri):
    u = urllib.parse.urlsplit(uri)
    return f"{u.hostname}:{u.port}"


@logged
def safe_config(config):
    errors = []
    if config.get("IfName") != "none":
        errors.append("TUN_not_none")
    if config.get("Listen") != []:
        errors.append("listeners_not_empty")
    if config.get("MulticastInterfaces") != []:
        errors.append("multicast_not_empty")
    if config.get("InterfacePeers") not in ({}, None):
        errors.append("interface_peers_nonempty")
    if config.get("PrivateKey"):
        errors.append("inline_private_key")
    if config.get("GroupPassword"):
        errors.append("inline_group_password")
    if config.get("NodeInfoPrivacy") is not True:
        errors.append("nodeinfo_privacy")
    if config.get("NodeInfo") not in ({}, None):
        errors.append("custom_nodeinfo")
    admin = config.get("AdminListen", "")
    if not isinstance(admin, str) or not admin.startswith("unix:///run/"):
        errors.append("unsafe_admin_endpoint")
    peers = config.get("Peers")
    if not isinstance(peers, list) or not peers:
        errors.append("missing_peers")
    else:
        for uri in peers:
            try:
                peer_uri(uri, force=True)
            except (Failure, ValueError):
                errors.append("invalid_peer")
    return errors


@logged
def digest(data):
    return hashlib.sha256(data).hexdigest()


@logged
def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


@logged
def bounded_number(value, lower, upper):
    try:
        if not str(value).isdigit() or not lower <= int(value) <= upper:
            raise Failure("numeric_argument_out_of_range")
        return int(value)
    except ValueError as exc:
        # isdigit() also accepts non-decimal glyphs; int() limits input length.
        raise Failure("numeric_argument_out_of_range") from exc
