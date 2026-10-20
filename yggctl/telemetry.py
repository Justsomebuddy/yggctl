"""Bounded, serialized samples and truthful missing-data reporting."""

from typing import Any

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
    if data is None:
        return []
    # An append in progress (or one torn by a crash) leaves an incomplete last line; skip it.
    if not data.endswith(b"\n"):
        data = data[: data.rfind(b"\n") + 1]
    values = []
    for line in data.splitlines():
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError()
            values.append(item)
        except ValueError:
            raise Failure("corrupt_metric_record") from None
    return values


@logged
def metric_records(fd, size):
    """Count newlines in bounded chunks, without decoding every JSON record.

    A cached counter would need a crash/inode-coherent second durable state file.
    The <=32 MiB sequential cached scan is simpler and measurable at minute cadence.
    """
    count, offset = 0, 0
    while offset < size:
        data = os.pread(fd, min(1 << 20, size - offset), offset)
        if not data:
            raise Failure("metric_file_changed_during_count")
        count += data.count(b"\n")
        offset += len(data)
    return count


@logged
def append(ctx, name, row, keep=10000):
    """Compact at >120% of `keep` RECORDS, independent of the last row's size."""
    if type(keep) is not int or not 1 <= keep <= 10000:
        raise Failure("invalid_metric_retention")
    path = ctx.p.state / name
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    with ctx.locked():
        fd = os.open(
            path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Failure("metric_file_not_regular")
            if info.st_size + len(line) > 32 * 1024 * 1024:
                raise Failure("metric_file_size_limit")
            if info.st_size and os.pread(fd, 1, info.st_size - 1) != b"\n":
                tail = os.pread(fd, min(info.st_size, 1 << 20), max(0, info.st_size - (1 << 20)))
                cut = tail.rfind(b"\n")
                if cut < 0 and info.st_size > len(tail):
                    raise Failure("corrupt_metric_tail")
                os.ftruncate(fd, info.st_size - len(tail) + cut + 1)
                event("state", "metric_append", "torn_tail_removed")
            view = memoryview(line)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise Failure("metric_append_no_progress")
                view = view[written:]
            os.fsync(fd)
            count = metric_records(fd, os.fstat(fd).st_size)
        finally:
            os.close(fd)
        os.chown(path, -1, ctx.p.state.stat().st_gid)
        if count > keep * 6 // 5:
            values = rows(ctx, name)
            atomic(
                path,
                "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in values[-keep:]),
                0o640,
            )
            os.chown(path, -1, ctx.p.state.stat().st_gid)
            event("state", "metric_append", "compacted_by_record_count")


@logged
def notify_state(ctx):
    p = ctx.p.state / "notify.state"
    state = read_regular(p, 16).decode().strip() if p.exists() else "off"
    if state not in ("on", "off"):
        raise Failure("invalid_notify_state")
    return state


@logged
def notify(ctx, action):
    ctx.root()
    with ctx.locked():
        if action in ("on", "off"):
            atomic(ctx.p.state / "notify.state", action + "\n", 0o644)
            event("state", "notify", action)
        elif action == "test":
            append(
                ctx,
                "alerts.jsonl",
                {"ts": timestamp(), "id": secrets.token_hex(8), "kind": "labelled-local-selftest"},
                1000,
            )
            event("alert", "notify", "labelled_local_test")
        elif action != "show":
            raise Failure("notify_on_off_show_test")
        print(
            f"notify={notify_state(ctx)}; alerts.jsonl, then SimpleX via ygg-alert-forward (no ACK needed)"
        )


PEER_DOWN_MINUTES = 10
UNSTABLE_RECONNECTS = 3  # reconnects within the last hour that make a peer "unstable"
UNSTABLE_REPEAT_HOURS = 6  # at most one "unstable" alert per peer in this time
PEER_STATE_LIMIT = 1 << 20
PEER_PENDING_LIMIT = 1000  # no larger than the alert queue's retained record count
PEER_ALERT_KINDS = ("ygg-peer-down", "ygg-peer-up", "ygg-peer-unstable")


@logged
def load_peer_state(ctx):
    """Accept legacy state, but never silently discard a damaged durable outbox."""
    try:
        raw = ctx.read_state("alert-state.json", PEER_STATE_LIMIT)
        state = json.loads(b"{}" if raw is None else raw)
    except ValueError:
        raise Failure("alert_state_invalid") from None
    if not isinstance(state, dict):
        raise Failure("alert_state_invalid")
    pending = state.get("pending", [])
    if not isinstance(pending, list) or len(pending) > PEER_PENDING_LIMIT:
        raise Failure("alert_pending_invalid")
    seen = set()
    for item in pending:
        if (
            not isinstance(item, dict)
            or item.get("kind") not in PEER_ALERT_KINDS
            or not isinstance(item.get("ts"), str)
            or not isinstance(item.get("peer"), str)
            or "id" not in item
        ):
            raise Failure("alert_pending_invalid")
        aid = alert_id(item)
        if aid in seen:
            raise Failure("alert_pending_duplicate_id")
        seen.add(aid)
    return state


@logged
def save_peer_state(ctx, state):
    data = (json.dumps(state, sort_keys=True) + "\n").encode()
    if len(data) > PEER_STATE_LIMIT:
        raise Failure("alert_state_size_limit")
    atomic(ctx.p.state / "alert-state.json", data, 0o600)


@logged
def sync_alert_queue(ctx):
    """Even a complete record observed after a failed fsync needs a new durability barrier."""
    fd = os.open(
        ctx.p.state / "alerts.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Failure("alert_queue_not_regular")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(ctx.p.state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


@logged
def flush_peer_alerts(ctx):
    """Replay durable pending events under the shared producer/forwarder lock.

    A crash after append but before acknowledgement reuses the same ID, checks the
    queued content and syncs both queue and directory before clearing pending.
    This is queue recovery, not exactly-once external delivery or a human ACK.
    """
    with ctx.locked():
        state = load_peer_state(ctx)
        pending = state.get("pending", [])
        if not pending:
            return
        queued = {alert_id(row): row for row in rows(ctx, "alerts.jsonl")}
        for item in pending:
            aid = item["id"]
            if aid in queued:
                if queued[aid] != item:
                    raise Failure("alert_pending_id_conflict")
                event("state", "peer_outbox", "already_queued")
            else:
                append(ctx, "alerts.jsonl", item, PEER_PENDING_LIMIT)
                event("alert", "peer_outbox", item["kind"])
        sync_alert_queue(ctx)
        state["pending"] = []
        save_peer_state(ctx, state)
        event("state", "peer_outbox", "acknowledged")


@logged
def peer_alerts(ctx, sample, uptimes=None):
    with ctx.locked():
        return stage_peer_alerts(ctx, sample, uptimes)


@logged
def stage_peer_alerts(ctx, sample, uptimes=None):
    """Changes worth an alert: a peer down for PEER_DOWN_MINUTES, its recovery, and a peer
    that reconnected UNSTABLE_RECONNECTS times within an hour (from the node's per-peer
    uptime, which also catches drops shorter than the sampling interval). State lives in
    alert-state.json and is rewritten only when something changes. The caller holds
    ctx.locked(). When notifications are enabled, events and transitions are saved
    together in that one atomic file, before anything is appended to the queue."""
    state = load_peer_state(ctx)
    down = state.get("down", {}) if isinstance(state.get("down"), dict) else {}
    starts = state.get("starts", {}) if isinstance(state.get("starts"), dict) else {}
    unstable = state.get("unstable", {}) if isinstance(state.get("unstable"), dict) else {}
    now = dt.datetime.fromisoformat(sample["ts"])
    peers = [p for p in sample.get("peers", []) if isinstance(p.get("r"), str) and p.get("r")]
    up, total = sum(bool(p.get("up")) for p in peers), len(peers)
    changes, tracked = [], {}
    for p in peers:
        entry = candidate if isinstance(candidate := down.get(p["r"]), dict) else {}
        try:
            since = dt.datetime.fromisoformat(entry.get("since", sample["ts"]))
        except (TypeError, ValueError):
            since = now
        minutes = max(0, int((now - since).total_seconds() // 60))
        if p.get("up"):
            if entry.get("alerted"):
                changes.append(
                    {
                        "kind": "ygg-peer-up",
                        "peer": p["r"],
                        "minutes": minutes,
                        "up": up,
                        "total": total,
                    }
                )
            continue
        alerted = bool(entry.get("alerted"))
        if not alerted and minutes >= PEER_DOWN_MINUTES:
            changes.append(
                {
                    "kind": "ygg-peer-down",
                    "peer": p["r"],
                    "minutes": minutes,
                    "up": up,
                    "total": total,
                }
            )
            alerted = True
        tracked[p["r"]] = {"since": since.isoformat(), "alerted": alerted}
    new_starts, new_unstable = reconnects(
        starts, unstable, uptimes or {}, now, peers, up, total, changes
    )
    pending = state.get("pending", [])
    enqueue = bool(changes) and notify_state(ctx) == "on"
    if enqueue:
        if len(pending) + len(changes) > PEER_PENDING_LIMIT:
            raise Failure("alert_pending_limit")
        pending = pending + [
            {"ts": sample["ts"], "id": secrets.token_hex(16), **change} for change in changes
        ]
    new_state = {
        "down": tracked,
        "starts": new_starts,
        "unstable": new_unstable,
        "pending": pending,
    }
    if new_state != state:
        save_peer_state(ctx, new_state)
        event("state", "peer_outbox", "staged" if enqueue else "tracking_saved")
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
            changes.append(
                {
                    "kind": "ygg-peer-unstable",
                    "peer": uri,
                    "count": len(seen),
                    "up": up,
                    "total": total,
                }
            )
            new_unstable[uri] = now.isoformat()
    return new_starts, new_unstable


SENDER = "/usr/local/bin/simplex-alert.sh"
# The sender suppresses repeats within 300 s by priority and rule, so a peer alert names its peer in the rule.
MESSAGES = {
    "ygg-peer-down": (
        "Yggdrasil: пир {peer} недоступен",
        "Warning",
        "Нода yggdrasil-lab: пир {peer} недоступен {minutes} мин; на связи {up} из {total}. "
        "Проверка: sudo yggctl peers",
    ),
    "ygg-peer-unstable": (
        "Yggdrasil: пир {peer} нестабилен",
        "Warning",
        "Нода yggdrasil-lab: пир {peer} нестабилен — {count} разрывов за последний час; "
        "на связи {up} из {total}. Проверка: sudo yggctl peers",
    ),
    "ygg-peer-up": (
        "Yggdrasil: пир {peer} снова на связи",
        "Warning",
        "Нода yggdrasil-lab: пир {peer} снова на связи после {minutes} мин; на связи {up} из {total}.",
    ),
    "ygg-health": (
        "Yggdrasil: сбой ноды",
        "Error",
        "Нода yggdrasil-lab: {errors}. Проверка: sudo yggctl check",
    ),
    "labelled-local-selftest": (
        "Yggdrasil: проверка доставки тревог",
        "Warning",
        "Тестовая тревога yggctl (notify test); действий не требуется.",
    ),
}


@logged
def alert_id(alert):
    if "id" in alert:
        if not isinstance(alert["id"], str) or not 1 <= len(alert["id"]) <= 128:
            raise Failure("invalid_alert_id")
        return alert["id"]
    return hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:16]


@logged
def alert_message(alert):
    default = ("Yggdrasil: тревога", "Warning", "Нода yggdrasil-lab: {kind}")
    rule, priority, text = MESSAGES.get(alert.get("kind"), default)
    fields = {
        k: str(v)[:120]
        for k, v in alert.items()
        if k in ("peer", "minutes", "up", "total", "kind", "count")
    }
    fields["errors"] = ", ".join(str(e)[:60] for e in alert.get("errors", [])[:5]) or "неизвестно"
    try:
        rule = rule.format(**fields)
    except KeyError:
        rule = rule.replace(" {peer}", "")
    try:
        output = text.format(**fields)
    except KeyError:
        output = "Нода yggdrasil-lab: тревога " + str(alert.get("kind"))[:60]
    return {
        "rule": rule,
        "priority": priority,
        "output": output[:300],
        "source": "yggctl",
        "time": str(alert.get("ts", ""))[:40],
    }


FORWARD_BUDGET = 90  # includes acquisition of the shared 20 s lock; unit timeout is 120 s
FORWARD_RESERVE = 5  # normal local checkpoint/exit time, not a guarantee under hung storage


@logged
def forward(ctx):
    """Per-success durable handoff, NOT exactly-once delivery or a human ACK.

    SIGTERM/crash between sender success and fsync can still cause a duplicate.
    Existing sender rc0 may mean its rate-limit suppression, not actual delivery.
    """
    start = time.monotonic()
    deadline = start + FORWARD_BUDGET
    ctx.root()
    with ctx.locked():
        alerts = rows(ctx, "alerts.jsonl")
        ids = [alert_id(a) for a in alerts]
        raw = ctx.read_state("alerts-forwarded.json", 1 << 20)
        if raw is None:
            atomic(
                ctx.p.state / "alerts-forwarded.json",
                json.dumps({"sent": list(dict.fromkeys(ids))[-2000:]}) + "\n",
                0o600,
            )
            print(
                f"[1/1] forwarding initialised; processed={len(ids)} earlier alerts not sent; errors=0 "
                f"remaining=0 elapsed={time.monotonic() - start:.2f}s"
            )
            return
        try:
            sent = json.loads(raw)["sent"]
            if (
                not isinstance(sent, list)
                or len(sent) > 2000
                or any(not isinstance(a, str) or not 1 <= len(a) <= 128 for a in sent)
                or len(set(sent)) != len(sent)
            ):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise Failure("alerts_forwarded_state_invalid") from None
        done, failures, processed = set(sent), 0, 0
        pending = [(a, aid) for a, aid in zip(alerts, ids) if aid not in done]
        for alert, aid in pending:
            if aid in done:
                continue
            remaining = deadline - time.monotonic() - FORWARD_RESERVE
            if remaining < 5:
                event("state", "alert_forward", "budget_exhausted_retry_required")
                break
            processed += 1
            try:
                result = ctx.run(
                    [SENDER],
                    input=json.dumps(alert_message(alert), ensure_ascii=False).encode(),
                    timeout=min(30, remaining),
                    check=False,
                )
                success = result.returncode == 0
            except Failure:
                success = False
            if success:
                done.add(aid)
                # Do not defer this commit until a later message/normal process exit.
                kept = list(dict.fromkeys(i for i in ids if i in done))[-2000:]
                atomic(
                    ctx.p.state / "alerts-forwarded.json", json.dumps({"sent": kept}) + "\n", 0o600
                )
                event("state", "alert_forward", "sender_rc0_checkpointed")
            else:
                failures += 1
                event("error", "alert_forward", "sender_failed_pending")
            elapsed = time.monotonic() - start
            print(
                f"[{processed}/{len(pending)}] sender handoff; processed={processed} errors={failures} "
                f"remaining={len(pending) - processed} elapsed={elapsed:.2f}s "
                f"ETA<={max(0, deadline - time.monotonic()):.1f}s "
                f"speed={processed / max(0.001, elapsed):.2f}/s",
                flush=True,
            )
        left = sum(aid not in done for aid in set(ids))
        print(
            f"[1/1] alerts handoff finished; processed={processed} errors={failures} remaining={left} "
            f"elapsed={time.monotonic() - start:.2f}s; sender rc0 is NOT delivery/human ACK"
        )
        if failures:
            raise Failure(f"alert_forward_failed:count={failures}")
        if left:
            # Existing Restart=on-failure schedules backlog even without a new path event.
            raise Failure("alert_forward_budget_pending")


@logged
def collect(ctx):
    ctx.root()
    with ctx.locked():
        uptimes = {}
        sample = {
            "schema": 2,
            "ts": timestamp(),
            "mode": None,
            "act": "unknown",
            "up": None,
            "peers": [],
            "stack_up": None,
            "errors": [],
        }
        try:
            sample["mode"] = ctx.mode()
            for stack, unit in ((False, NODE), (True, STACK)):
                active = ctx.unit(unit).get("ActiveState", "unknown")
                ps = peers(ctx, stack)  # Exactly one coherent admin query per instance.
                if stack:
                    sample["stack_up"] = sum(p["up"] for p in ps)
                else:
                    uptimes = {p.get("remote"): p.get("uptime") for p in ps}
                    sample["act"] = active
                    sample["up"] = sum(p["up"] for p in ps)
                    sample["peers"] = [
                        {
                            "r": p.get("remote", ""),
                            "up": p["up"],
                            "rtt": p.get("latency", 0) / 1e6,
                            "rx": p.get("bytes_recvd", 0),
                            "tx": p.get("bytes_sent", 0),
                        }
                        for p in ps
                    ]
                if active != "active":
                    sample["errors"].append("stack_inactive" if stack else "node_inactive")
        except (Failure, OSError, ValueError) as exc:
            sample["errors"].append(str(exc) if isinstance(exc, Failure) else "metric_unavailable")
        if sample["up"] == 0 or sample["stack_up"] == 0:
            sample["errors"].append("no_up_peers")
        append(ctx, "metrics.jsonl", sample)
        enabled = notify_state(ctx) == "on"
        if enabled:
            # Drain first: a full recoverable outbox must not block its own retry.
            flush_peer_alerts(ctx)
        peer_alerts(ctx, sample, uptimes)
        if enabled:
            flush_peer_alerts(ctx)
            if sample["errors"]:
                key = "collect:" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")
                if not any(a.get("key") == key for a in rows(ctx, "alerts.jsonl")):
                    append(
                        ctx,
                        "alerts.jsonl",
                        {
                            "ts": sample["ts"],
                            "id": secrets.token_hex(8),
                            "kind": "ygg-health",
                            "key": key,
                            "errors": sample["errors"],
                        },
                        1000,
                    )
                    event("alert", "collect", "health_degraded")
        if sample["errors"]:
            raise Failure("sample_recorded_with_unknown_or_degraded_health")
        print("[1/1] sample recorded; processed=2 instances errors=0 remaining=0")
        return sample


@logged
def window(ctx, hours=24):
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=hours)
    found, invalid = [], 0
    for r in rows(ctx):
        try:
            at = dt.datetime.fromisoformat(r["ts"])
            if at.tzinfo is None:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            invalid += 1
            event("state", "metric_window", "invalid_timestamp_skipped")
            continue
        if start <= at <= now:
            found.append((at, r))
    if not found:
        raise Failure(f"no_samples_in_window:invalid_records={invalid}")
    return sorted(found, key=lambda x: x[0]), invalid


@logged
def stats(ctx, hours=24, graph=False):
    values, invalid = window(ctx, hours)
    unknown = sum(r.get("up") is None or bool(r.get("errors")) for _, r in values)
    gaps = sum(
        max(0, round((b[0] - a[0]).total_seconds() / 60) - 1) for a, b in zip(values, values[1:])
    )
    names = sorted({p["r"] for _, r in values for p in r.get("peers", [])})
    print(
        f"window={hours}h samples={len(values)} unknown_records={unknown} "
        f"invalid_records={invalid} missing_minutes_between_samples={gaps}; "
        f"observed availability is NOT wall-clock uptime"
    )
    for name in names:
        matches = [next((p for p in r.get("peers", []) if p["r"] == name), None) for _, r in values]
        known = [p for p in matches if p is not None]
        up = sum(p["up"] for p in known)
        latency = [p["rtt"] for p in known if p["up"] and p.get("rtt", 0) > 0]
        median = statistics.median(latency) if latency else "unknown"
        print(
            f"{name}: observed_avail={100 * up / len(known):.1f}% present={len(known)} "
            f"absent={len(matches) - len(known)} median_ms={median}"
        )
        if graph:
            # Bin the entire requested time window, not simply the last 60 samples.
            end = dt.datetime.now(dt.timezone.utc)
            begin = end - dt.timedelta(hours=hours)
            bins: list[list[dict[str, Any] | None]] = [[] for _ in range(60)]
            span = max(1, (end - begin).total_seconds())
            for (at, _), p in zip(values, matches):
                bins[min(59, int((at - begin).total_seconds() * 60 / span))].append(p)
            marks = (
                "?"
                if not b or all(p is None for p in b)
                else "."
                if not any(p and p["up"] for p in b)
                else "#"
                for b in bins
            )
            print("".join(marks))
            print("60 time bins: # observed up, . observed down, ? unknown; NOT RTT bars")


@logged
def watch(ctx, count=5, interval=2):
    start, errors = time.monotonic(), 0
    for i in range(count):
        try:
            node = sum(p["up"] for p in peers(ctx))
            stack = sum(p["up"] for p in peers(ctx, True))
        except (Failure, OSError, ValueError, KeyError):
            node = stack = "unknown"
            errors += 1
            event("error", "watch_sample", "unavailable_unknown")
        print(
            f"[{i + 1}/{count}] node_up={node} stack_up={stack} errors={errors} "
            f"elapsed={time.monotonic() - start:.1f}s ETA={(count - i - 1) * interval}s "
            f"speed=1/{interval}s remaining={count - i - 1}",
            flush=True,
        )
        if i + 1 < count:
            time.sleep(interval)
    print(f"processed={count} errors={errors} elapsed={time.monotonic() - start:.1f}s")
    if errors:
        raise Failure(f"watch_samples_failed:count={errors}")
