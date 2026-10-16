"""Bounded, serialized samples and truthful missing-data reporting."""
import datetime as dt
import json
import os
import stat
import statistics
import time

from core import Failure, NODE, STACK, logged, read_regular, atomic, timestamp, event
from checks import peers


@logged
def rows(ctx, name="metrics.jsonl"):
    path = ctx.p.state / name
    if not path.exists(): return []
    data = read_regular(path, 32 * 1024 * 1024)
    # An append in progress (or one torn by a crash) leaves an incomplete last line; skip it.
    if not data.endswith(b"\n"): data = data[:data.rfind(b"\n") + 1]
    values = []
    for line in data.splitlines():
        try:
            item = json.loads(line)
            if not isinstance(item, dict): raise ValueError()
            values.append(item)
        except ValueError:
            raise Failure("corrupt_metric_record") from None
    return values


@logged
def append(ctx, name, row, keep=10000):
    """Append one row. The file is rewritten to the newest `keep` rows only once it has
    grown about 20 % past them (about every 1.4 days for the minute collector), not on
    every sample."""
    path = ctx.p.state / name
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode): raise Failure("metric_file_not_regular")
        if info.st_size and os.pread(fd, 1, info.st_size - 1) != b"\n":
            # Drop a line torn by a crash before appending after it.
            tail = os.pread(fd, min(info.st_size, 1 << 20), max(0, info.st_size - (1 << 20)))
            cut = tail.rfind(b"\n")
            if cut < 0 and info.st_size > len(tail): raise Failure("corrupt_metric_tail")
            os.ftruncate(fd, info.st_size - len(tail) + cut + 1)
        view = memoryview(line)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        size = os.fstat(fd).st_size
    finally:
        os.close(fd)
    os.chown(path, -1, ctx.p.state.stat().st_gid)
    if size > len(line) * keep * 6 // 5:
        values = rows(ctx, name)
        atomic(path, "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in values[-keep:]), 0o640)
        os.chown(path, -1, ctx.p.state.stat().st_gid)


@logged
def notify_state(ctx):
    p = ctx.p.state / "notify.state"
    state = read_regular(p, 16).decode().strip() if p.exists() else "off"
    if state not in ("on", "off"): raise Failure("invalid_notify_state")
    return state


@logged
def notify(ctx, action):
    ctx.root()
    with ctx.locked():
        if action in ("on", "off"):
            atomic(ctx.p.state / "notify.state", action + "\n", 0o644)
            event("state", "notify", action)
        elif action == "test":
            append(ctx, "alerts.jsonl", {"ts": timestamp(), "kind": "labelled-local-selftest"}, 1000)
            event("alert", "notify", "labelled_local_test")
        elif action != "show": raise Failure("notify_on_off_show_test")
        print(f"notify={notify_state(ctx)}; local journal + alerts.jsonl only; no SimpleX delivery/ACK")


@logged
def collect(ctx):
    ctx.root()
    with ctx.locked():
        sample = {"schema": 2, "ts": timestamp(), "mode": None, "act": "unknown", "up": None,
                  "peers": [], "stack_up": None, "errors": []}
        try:
            sample["mode"] = ctx.mode()
            for stack, unit in ((False, NODE), (True, STACK)):
                active = ctx.unit(unit).get("ActiveState", "unknown")
                ps = peers(ctx, stack)  # Exactly one coherent admin query per instance.
                if stack: sample["stack_up"] = sum(p["up"] for p in ps)
                else:
                    sample["act"] = active
                    sample["up"] = sum(p["up"] for p in ps)
                    sample["peers"] = [{"r": p.get("remote", ""), "up": p["up"],
                                        "rtt": p.get("latency", 0)/1e6,
                                        "rx": p.get("bytes_recvd", 0), "tx": p.get("bytes_sent", 0)} for p in ps]
                if active != "active": sample["errors"].append("stack_inactive" if stack else "node_inactive")
        except (Failure, OSError, ValueError) as exc:
            sample["errors"].append(str(exc) if isinstance(exc, Failure) else "metric_unavailable")
        if sample["up"] == 0 or sample["stack_up"] == 0: sample["errors"].append("no_up_peers")
        append(ctx, "metrics.jsonl", sample)
        if sample["errors"] and notify_state(ctx) == "on":
            key = "collect:" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")
            if not any(a.get("key") == key for a in rows(ctx, "alerts.jsonl")):
                append(ctx, "alerts.jsonl", {"ts": sample["ts"], "kind": "ygg-health", "key": key,
                                           "errors": sample["errors"]}, 1000)
                event("alert", "collect", "health_degraded_local_only")
        if sample["errors"]: raise Failure("sample_recorded_with_unknown_or_degraded_health")
        print("[1/1] sample recorded; processed=2 instances errors=0 remaining=0")
        return sample


@logged
def window(ctx, hours=24):
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=hours)
    found = []
    for r in rows(ctx):
        try:
            at = dt.datetime.fromisoformat(r["ts"])
            if at.tzinfo is None: raise ValueError()
        except (KeyError, ValueError, TypeError): raise Failure("metric_timestamp_invalid") from None
        if start <= at <= now: found.append((at, r))
    if not found: raise Failure("no_samples_in_window")
    return sorted(found, key=lambda x: x[0])


@logged
def stats(ctx, hours=24, graph=False):
    values = window(ctx, hours)
    unknown = sum(r.get("up") is None or bool(r.get("errors")) for _, r in values)
    gaps = sum(max(0, round((b[0]-a[0]).total_seconds()/60)-1) for a, b in zip(values, values[1:]))
    names = sorted({p["r"] for _, r in values for p in r.get("peers", [])})
    print(f"window={hours}h samples={len(values)} unknown_records={unknown} missing_minutes_between_samples={gaps}; observed availability is NOT wall-clock uptime")
    for name in names:
        matches = [next((p for p in r.get("peers", []) if p["r"] == name), None) for _, r in values]
        known = [p for p in matches if p is not None]
        up = sum(p["up"] for p in known)
        latency = [p["rtt"] for p in known if p["up"] and p.get("rtt", 0) > 0]
        print(f"{name}: observed_avail={100*up/len(known):.1f}% present={len(known)} absent={len(matches)-len(known)} median_ms={statistics.median(latency) if latency else 'unknown'}")
        if graph:
            # Bin the entire requested time window, not simply the last 60 samples.
            end = dt.datetime.now(dt.timezone.utc)
            begin = end - dt.timedelta(hours=hours)
            bins = [[] for _ in range(60)]
            span = max(1, (end-begin).total_seconds())
            for (at, _), p in zip(values, matches):
                bins[min(59, int((at-begin).total_seconds()*60/span))].append(p)
            print("".join("?" if not b or all(p is None for p in b) else "." if not any(p and p["up"] for p in b) else "#" for b in bins))
            print("60 time bins: # observed up, . observed down, ? unknown; NOT RTT bars")


@logged
def watch(ctx, count=5, interval=2):
    start = time.monotonic()
    for i in range(count):
        print(f"[{i+1}/{count}] node_up={sum(p['up'] for p in peers(ctx))} stack_up={sum(p['up'] for p in peers(ctx, True))} elapsed={time.monotonic()-start:.1f}s ETA={(count-i-1)*interval}s speed=1/{interval}s remaining={count-i-1}", flush=True)
        if i+1 < count: time.sleep(interval)
    print(f"processed={count} errors=0 elapsed={time.monotonic()-start:.1f}s")
