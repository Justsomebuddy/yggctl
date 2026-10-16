"""Bounded, serialized samples and truthful missing-data reporting."""
import datetime as dt
import hashlib
import json
import os
import secrets
import stat
import statistics
import time

from core import Failure, NODE, STACK, logged, read_regular, atomic, timestamp, event
from checks import peers


@logged
def rows(ctx, name="metrics.jsonl"):
    data = ctx.read_state(name, 32 * 1024 * 1024)
    if data is None: return []
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
            append(ctx, "alerts.jsonl", {"ts": timestamp(), "id": secrets.token_hex(8),
                                         "kind": "labelled-local-selftest"}, 1000)
            event("alert", "notify", "labelled_local_test")
        elif action != "show": raise Failure("notify_on_off_show_test")
        print(f"notify={notify_state(ctx)}; alerts.jsonl, then SimpleX via ygg-alert-forward (no ACK needed)")


PEER_DOWN_MINUTES = 10
UNSTABLE_RECONNECTS = 3    # reconnects within the last hour that make a peer "unstable"
UNSTABLE_REPEAT_HOURS = 6  # at most one "unstable" alert per peer in this time


@logged
def peer_alerts(ctx, sample, uptimes=None):
    """Changes worth an alert: a peer down for PEER_DOWN_MINUTES, its recovery, and a peer
    that reconnected UNSTABLE_RECONNECTS times within an hour (from the node's per-peer
    uptime, which also catches drops shorter than the sampling interval). State lives in
    alert-state.json and is rewritten only when something changes."""
    try:
        state = json.loads(ctx.read_state("alert-state.json", 65536) or b"{}")
    except ValueError:
        state = {}
    if not isinstance(state, dict):
        state = {}
    down = state.get("down", {}) if isinstance(state.get("down"), dict) else {}
    starts = state.get("starts", {}) if isinstance(state.get("starts"), dict) else {}
    unstable = state.get("unstable", {}) if isinstance(state.get("unstable"), dict) else {}
    now = dt.datetime.fromisoformat(sample["ts"])
    peers = [p for p in sample.get("peers", []) if isinstance(p.get("r"), str) and p.get("r")]
    up, total = sum(bool(p.get("up")) for p in peers), len(peers)
    changes, tracked = [], {}
    for p in peers:
        entry = down.get(p["r"]) if isinstance(down.get(p["r"]), dict) else {}
        try:
            since = dt.datetime.fromisoformat(entry.get("since", sample["ts"]))
        except (TypeError, ValueError):
            since = now
        minutes = max(0, int((now - since).total_seconds() // 60))
        if p.get("up"):
            if entry.get("alerted"):
                changes.append({"kind": "ygg-peer-up", "peer": p["r"], "minutes": minutes, "up": up, "total": total})
            continue
        alerted = bool(entry.get("alerted"))
        if not alerted and minutes >= PEER_DOWN_MINUTES:
            changes.append({"kind": "ygg-peer-down", "peer": p["r"], "minutes": minutes, "up": up, "total": total})
            alerted = True
        tracked[p["r"]] = {"since": since.isoformat(), "alerted": alerted}
    new_starts, new_unstable = reconnects(starts, unstable, uptimes or {}, now, peers, up, total, changes)
    new_state = {"down": tracked, "starts": new_starts, "unstable": new_unstable}
    if new_state != {"down": down, "starts": starts, "unstable": unstable}:
        atomic(ctx.p.state / "alert-state.json", json.dumps(new_state, sort_keys=True) + "\n", 0o600)
    return changes


@logged
def reconnects(starts, unstable, uptimes, now, peers, up, total, changes):
    """Record each connection start (now - uptime) once and flag peers that reconnect too often."""
    hour_ago = now - dt.timedelta(hours=1)
    new_starts, new_unstable = {}, {}
    for p in peers:
        uri = p["r"]
        seen = []
        for value in starts.get(uri, []) if isinstance(starts.get(uri), list) else []:
            try:
                at = dt.datetime.fromisoformat(value)
            except (TypeError, ValueError):
                continue
            if at >= hour_ago:
                seen.append(at)
        uptime = uptimes.get(uri)
        if p.get("up") and isinstance(uptime, (int, float)) and 0 <= uptime < 86400:
            start = now - dt.timedelta(seconds=uptime)
            if start >= hour_ago and not any(abs((start - at).total_seconds()) < 15 for at in seen):
                seen.append(start)
        if seen:
            new_starts[uri] = [at.isoformat() for at in sorted(seen)]
        try:
            last = dt.datetime.fromisoformat(unstable[uri]) if uri in unstable else None
        except (TypeError, ValueError):
            last = None
        if last and now - last < dt.timedelta(hours=UNSTABLE_REPEAT_HOURS):
            new_unstable[uri] = last.isoformat()
        elif len(seen) >= UNSTABLE_RECONNECTS:
            changes.append({"kind": "ygg-peer-unstable", "peer": uri, "count": len(seen), "up": up, "total": total})
            new_unstable[uri] = now.isoformat()
    return new_starts, new_unstable


SENDER = "/usr/local/bin/simplex-alert.sh"
MESSAGES = {
    "ygg-peer-down": ("Yggdrasil: пир недоступен", "Warning",
                      "Нода yggdrasil-lab: пир {peer} недоступен {minutes} мин; на связи {up} из {total}. "
                      "Проверка: sudo yggctl peers"),
    "ygg-peer-unstable": ("Yggdrasil: пир нестабилен", "Warning",
                          "Нода yggdrasil-lab: пир {peer} нестабилен — {count} разрывов за последний час; "
                          "на связи {up} из {total}. Проверка: sudo yggctl peers"),
    "ygg-peer-up": ("Yggdrasil: пир снова на связи", "Warning",
                    "Нода yggdrasil-lab: пир {peer} снова на связи после {minutes} мин; на связи {up} из {total}."),
    "ygg-health": ("Yggdrasil: сбой ноды", "Error",
                   "Нода yggdrasil-lab: {errors}. Проверка: sudo yggctl check"),
    "labelled-local-selftest": ("Yggdrasil: проверка доставки тревог", "Warning",
                                "Тестовая тревога yggctl (notify test); действий не требуется."),
}


@logged
def alert_id(alert):
    if isinstance(alert.get("id"), str):
        return alert["id"]
    return hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:16]


@logged
def alert_message(alert):
    default = ("Yggdrasil: тревога", "Warning", "Нода yggdrasil-lab: {kind}")
    rule, priority, text = MESSAGES.get(alert.get("kind"), default)
    fields = {k: str(v)[:120] for k, v in alert.items() if k in ("peer", "minutes", "up", "total", "kind", "count")}
    fields["errors"] = ", ".join(str(e)[:60] for e in alert.get("errors", [])[:5]) or "неизвестно"
    try:
        output = text.format(**fields)
    except KeyError:
        output = "Нода yggdrasil-lab: тревога " + str(alert.get("kind"))[:60]
    return {"rule": rule, "priority": priority, "output": output[:300], "source": "yggctl",
            "time": str(alert.get("ts", ""))[:40]}


@logged
def forward(ctx):
    """Hand new alerts to the root-owned SimpleX sender; history is never re-sent."""
    ctx.root()
    with ctx.locked():
        alerts = rows(ctx, "alerts.jsonl")
        ids = [alert_id(a) for a in alerts]
        raw = ctx.read_state("alerts-forwarded.json", 1 << 20)
        if raw is None:
            atomic(ctx.p.state / "alerts-forwarded.json", json.dumps({"sent": ids[-2000:]}) + "\n", 0o600)
            print(f"[1/1] forwarding initialised; {len(ids)} earlier alerts not sent")
            return
        try:
            sent = json.loads(raw).get("sent", [])
        except (ValueError, AttributeError):
            raise Failure("alerts_forwarded_state_invalid") from None
        done, failures, new = set(sent), 0, 0
        for alert, aid in zip(alerts, ids):
            if aid in done:
                continue
            new += 1
            r = ctx.run([SENDER], input=json.dumps(alert_message(alert), ensure_ascii=False).encode(),
                        timeout=30, check=False)
            if r.returncode == 0:
                done.add(aid)
            else:
                failures += 1
        kept = [i for i in ids if i in done][-2000:]
        atomic(ctx.p.state / "alerts-forwarded.json", json.dumps({"sent": kept}) + "\n", 0o600)
        print(f"[1/1] alerts forwarded; processed={new} errors={failures}")
        if failures:
            raise Failure(f"alert_forward_failed:count={failures}")


@logged
def collect(ctx):
    ctx.root()
    with ctx.locked():
        uptimes = {}
        sample = {"schema": 2, "ts": timestamp(), "mode": None, "act": "unknown", "up": None,
                  "peers": [], "stack_up": None, "errors": []}
        try:
            sample["mode"] = ctx.mode()
            for stack, unit in ((False, NODE), (True, STACK)):
                active = ctx.unit(unit).get("ActiveState", "unknown")
                ps = peers(ctx, stack)  # Exactly one coherent admin query per instance.
                if stack: sample["stack_up"] = sum(p["up"] for p in ps)
                else:
                    uptimes = {p.get("remote"): p.get("uptime") for p in ps}
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
        changes = peer_alerts(ctx, sample, uptimes)
        if notify_state(ctx) == "on":
            for change in changes:
                append(ctx, "alerts.jsonl", {"ts": sample["ts"], "id": secrets.token_hex(8), **change}, 1000)
                event("alert", "collect", change["kind"])
            if sample["errors"]:
                key = "collect:" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")
                if not any(a.get("key") == key for a in rows(ctx, "alerts.jsonl")):
                    append(ctx, "alerts.jsonl", {"ts": sample["ts"], "id": secrets.token_hex(8), "kind": "ygg-health",
                                               "key": key, "errors": sample["errors"]}, 1000)
                    event("alert", "collect", "health_degraded")
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
    print(f"window={hours}h samples={len(values)} unknown_records={unknown} "
          f"missing_minutes_between_samples={gaps}; observed availability is NOT wall-clock uptime")
    for name in names:
        matches = [next((p for p in r.get("peers", []) if p["r"] == name), None) for _, r in values]
        known = [p for p in matches if p is not None]
        up = sum(p["up"] for p in known)
        latency = [p["rtt"] for p in known if p["up"] and p.get("rtt", 0) > 0]
        median = statistics.median(latency) if latency else "unknown"
        print(f"{name}: observed_avail={100*up/len(known):.1f}% present={len(known)} "
              f"absent={len(matches)-len(known)} median_ms={median}")
        if graph:
            # Bin the entire requested time window, not simply the last 60 samples.
            end = dt.datetime.now(dt.timezone.utc)
            begin = end - dt.timedelta(hours=hours)
            bins = [[] for _ in range(60)]
            span = max(1, (end-begin).total_seconds())
            for (at, _), p in zip(values, matches):
                bins[min(59, int((at-begin).total_seconds()*60/span))].append(p)
            marks = ("?" if not b or all(p is None for p in b) else "." if not any(p and p["up"] for p in b) else "#"
                     for b in bins)
            print("".join(marks))
            print("60 time bins: # observed up, . observed down, ? unknown; NOT RTT bars")


@logged
def watch(ctx, count=5, interval=2):
    start = time.monotonic()
    for i in range(count):
        print(f"[{i+1}/{count}] node_up={sum(p['up'] for p in peers(ctx))} "
              f"stack_up={sum(p['up'] for p in peers(ctx, True))} elapsed={time.monotonic()-start:.1f}s "
              f"ETA={(count-i-1)*interval}s speed=1/{interval}s remaining={count-i-1}", flush=True)
        if i+1 < count: time.sleep(interval)
    print(f"processed={count} errors=0 elapsed={time.monotonic()-start:.1f}s")
