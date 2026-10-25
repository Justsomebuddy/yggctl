"""Bounded, serialized samples and truthful missing-data reporting."""

import datetime as dt
import hashlib
import json
import math
import os
import secrets
import stat
import statistics
import time
from collections import Counter
from typing import Any

from core import (
    Failure,
    NODE,
    STACK,
    logged,
    read_regular,
    atomic,
    timestamp,
    event,
    public_peer_uri,
    METRIC_RETENTION,
    METRICS_LIMIT,
)
from checks import identified, peers
import simplex_sender


@logged
def peer_label(value):
    """Credential-free literal endpoint; retain only proven public URI options.

    This is an output boundary, NOT permission to add credential-bearing peers.
    Existing queues/history are not rewritten: their IDs and delivery cursors
    must stay stable. Rendering applies this boundary again for legacy alerts.
    """
    return public_peer_uri(value) or "unknown-peer"


@logged
def ambiguous_peer_labels(peers):
    """Public labels are display-safe, but do not uniquely identify every link."""
    counts = Counter(
        peer_label(p["r"]) for p in peers if isinstance(p.get("r"), str) and p.get("r")
    )
    return {label for label, count in counts.items() if count > 1}


@logged
def rows(ctx, name="metrics.jsonl"):
    data = ctx.read_state(name, METRICS_LIMIT)
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
def metric_compact(ctx, name, row, keep, appended=False):
    """Newest complete records, bounded by BOTH count and bytes, including new row."""
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    if len(line) > METRICS_LIMIT:
        raise Failure("metric_record_size_limit")
    values = rows(ctx, name)
    if appended:
        values = values[:-1]
    if name == "alerts.jsonl":
        compact_alerts(ctx, values, row, keep)
        return
    retained, size = [line], len(line)
    for previous in reversed(values[-(keep - 1) :] if keep > 1 else []):
        encoded = (json.dumps(previous, separators=(",", ":")) + "\n").encode()
        if size + len(encoded) > METRICS_LIMIT:
            break
        retained.append(encoded)
        size += len(encoded)
    atomic(ctx.p.state / name, b"".join(reversed(retained)), 0o640)
    event("state", "metric_append", "compacted_by_byte_or_record_bound")


ALERT_RETENTION_KIND = "ygg-queue-retention"
ALERT_RETENTION_MAX = (1 << 63) - 1
ALERT_RETENTION_ID = "ygg-queue-retention"


@logged
def alert_retention(records):
    """Separate the one durable queue-loss marker from ordinary alerts."""
    notice = None
    ordinary = []
    for item in records:
        if item.get("kind") != ALERT_RETENTION_KIND:
            ordinary.append(item)
            continue
        if notice is not None or set(item) != {"kind", "id", "evicted_uncheckpointed_total"}:
            raise Failure("alert_retention_invalid")
        total = item["evicted_uncheckpointed_total"]
        if type(total) is not int or not 1 <= total <= ALERT_RETENTION_MAX:
            raise Failure("alert_retention_invalid")
        alert_id(item)
        notice = item
    return notice, ordinary


@logged
def forwarded_ids(ctx):
    """Read the existing cursor format; absence is not a delivery checkpoint."""
    raw = ctx.read_state("alerts-forwarded.json", 1 << 20)
    if raw is None:
        return None
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
    return sent


@logged
def alert_suffix(encoded, capacity, byte_budget):
    """Find the newest complete suffix within both queue limits."""
    used = 0
    start = len(encoded)
    while start > 0 and len(encoded) - start < capacity:
        size = len(encoded[start - 1])
        if used + size > byte_budget:
            break
        used += size
        start -= 1
    return start


@logged
def compact_alerts(ctx, values, row, keep):
    """Keep ordinary-alert capacity plus one loss marker within the same byte cap.

    Metadata must not steal a pending-event slot: a full recoverable outbox has
    to fit after a previous loss. The one marker is additional bounded metadata,
    never an alert or a delivery receipt. Byte pressure can still reduce capacity.
    """
    if row.get("kind") == ALERT_RETENTION_KIND:
        raise Failure("alert_retention_reserved")
    previous, ordinary = alert_retention(values)
    ordinary.append(row)
    encoded = [(json.dumps(item, separators=(",", ":")) + "\n").encode() for item in ordinary]
    sent = set(forwarded_ids(ctx) or ())

    start = alert_suffix(encoded, keep, METRICS_LIMIT)
    initial_evictions = sum(alert_id(item) not in sent for item in ordinary[:start])
    if previous is None and not initial_evictions:
        atomic(ctx.p.state / "alerts.jsonl", b"".join(encoded[start:]), 0o640)
        event("state", "metric_append", "compacted_by_byte_or_record_bound")
        return

    old_total = previous["evicted_uncheckpointed_total"] if previous else 0
    # Reserve the largest possible marker first, so the suffix and count are
    # selected once even when the counter crosses a decimal digit boundary.
    maximal = {
        "kind": ALERT_RETENTION_KIND,
        "id": ALERT_RETENTION_ID,
        "evicted_uncheckpointed_total": ALERT_RETENTION_MAX,
    }
    reserved = len((json.dumps(maximal, separators=(",", ":")) + "\n").encode())
    if reserved + len(encoded[-1]) > METRICS_LIMIT:
        raise Failure("alert_retention_capacity")
    start = alert_suffix(encoded, keep, METRICS_LIMIT - reserved)
    total = old_total + sum(alert_id(item) not in sent for item in ordinary[:start])
    if total > ALERT_RETENTION_MAX:
        raise Failure("alert_retention_overflow")
    notice = {
        "kind": ALERT_RETENTION_KIND,
        "id": ALERT_RETENTION_ID,
        "evicted_uncheckpointed_total": total,
    }
    marker = (json.dumps(notice, separators=(",", ":")) + "\n").encode()
    atomic(ctx.p.state / "alerts.jsonl", marker + b"".join(encoded[start:]), 0o640)
    event("state", "metric_append", "compacted_by_byte_or_record_bound")


@logged
def append(ctx, name, row, keep=METRIC_RETENTION):
    """Retain a newest suffix within 32 MiB; compact count at >120% of keep."""
    if type(keep) is not int or not 1 <= keep <= METRIC_RETENTION:
        raise Failure("invalid_metric_retention")
    if name == "alerts.jsonl" and row.get("kind") == ALERT_RETENTION_KIND:
        raise Failure("alert_retention_reserved")
    path = ctx.p.state / name
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    if len(line) > METRICS_LIMIT:
        raise Failure("metric_record_size_limit")
    with ctx.locked():
        fd = os.open(
            path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Failure("metric_file_not_regular")
            if info.st_size + len(line) > METRICS_LIMIT:
                metric_compact(ctx, name, row, keep)
                os.chown(path, -1, ctx.p.state.stat().st_gid)
                return
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
            metric_compact(ctx, name, row, keep, appended=True)
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
        if action == "show":
            warn_alert_admission(ctx)


PEER_DOWN_MINUTES = 10
UNSTABLE_RECONNECTS = 3  # reconnects within the last hour that make a peer "unstable"
UNSTABLE_REPEAT_HOURS = 6  # at most one "unstable" alert per peer in this time
PEER_STATE_LIMIT = 1 << 20
PEER_PENDING_LIMIT = 1000  # no larger than the queue's ordinary-alert retention capacity
PEER_ALERT_KINDS = ("ygg-peer-down", "ygg-peer-up", "ygg-peer-unstable")
HEALTH_ALERT_KIND = "ygg-health"


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
    if "admission_incomplete" in state and not isinstance(state["admission_incomplete"], bool):
        raise Failure("alert_state_invalid")
    pending = state.get("pending", [])
    if not isinstance(pending, list) or len(pending) > PEER_PENDING_LIMIT:
        raise Failure("alert_pending_invalid")
    seen = set()
    for item in pending:
        if not isinstance(item, dict) or not isinstance(item.get("ts"), str) or "id" not in item:
            raise Failure("alert_pending_invalid")
        if item.get("kind") == HEALTH_ALERT_KIND:
            if (
                set(item) != {"ts", "id", "kind", "key", "errors"}
                or not isinstance(item.get("key"), str)
                or len(item["key"]) != len("collect:2026010100")
                or not item["key"].startswith("collect:")
                or not item["key"][8:].isascii()
                or not item["key"][8:].isdigit()
                or not isinstance(item.get("errors"), list)
                or not item["errors"]
                or any(not isinstance(error, str) for error in item["errors"])
            ):
                raise Failure("alert_pending_invalid")
        elif item.get("kind") not in PEER_ALERT_KINDS or not isinstance(item.get("peer"), str):
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
def mark_alert_admission_incomplete(ctx, state):
    """Record a refused alert intent before returning the original capacity error."""
    if not state.get("admission_incomplete", False):
        state["admission_incomplete"] = True
        save_peer_state(ctx, state)


@logged
def warn_alert_admission(ctx):
    if load_peer_state(ctx).get("admission_incomplete", False):
        print(
            "WARNING alert_admission_incomplete=yes; notification_history_may_be_incomplete=yes",
            flush=True,
        )


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
            # Do not copy a legacy private credential into the group-readable
            # queue, or mutate its stable-ID payload implicitly during replay.
            if item["kind"] in PEER_ALERT_KINDS and item["peer"] != peer_label(item["peer"]):
                raise Failure("legacy_peer_pending_requires_privacy_review")
            aid = item["id"]
            if aid in queued:
                if queued[aid] != item:
                    raise Failure("alert_pending_id_conflict")
                event("state", "peer_outbox", "already_queued")
            else:
                append(ctx, "alerts.jsonl", item, PEER_PENDING_LIMIT)
                event("alert", "peer_outbox", item["kind"])
        # Appending a later event may compact away an earlier already-queued
        # pending event. Acknowledge against the final queue, not the snapshot
        # taken before these writes; retain exact IDs and payloads for retry.
        queued = {alert_id(row): row for row in rows(ctx, "alerts.jsonl")}
        remaining = [item for item in pending if queued.get(item["id"]) != item]
        sync_alert_queue(ctx)
        state["pending"] = remaining
        save_peer_state(ctx, state)
        if remaining:
            event("state", "peer_outbox", "retained_after_queue_rotation")
            raise Failure("alert_pending_retained_after_queue_rotation")
        event("state", "peer_outbox", "acknowledged")


@logged
def peer_alerts(ctx, sample, uptimes=None):
    with ctx.locked():
        return stage_peer_alerts(ctx, sample, uptimes)


@logged
def stage_health_alert(ctx, sample):
    """Save one original degraded observation per hour before queue I/O."""
    if not sample["errors"]:
        return
    key = "collect:" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")
    state = load_peer_state(ctx)
    pending = state.get("pending", [])
    if any(item.get("kind") == HEALTH_ALERT_KIND and item["key"] == key for item in pending):
        return
    if any(item.get("key") == key for item in rows(ctx, "alerts.jsonl")):
        return
    if len(pending) >= PEER_PENDING_LIMIT:
        mark_alert_admission_incomplete(ctx, state)
        raise Failure("alert_pending_limit")
    state["pending"] = pending + [
        {
            "ts": sample["ts"],
            "id": secrets.token_hex(8),
            "kind": HEALTH_ALERT_KIND,
            "key": key,
            "errors": sample["errors"],
        }
    ]
    save_peer_state(ctx, state)
    event("state", "health_outbox", "staged")


@logged
def stage_peer_alerts(ctx, sample, uptimes=None):
    """Changes worth an alert: a peer down for PEER_DOWN_MINUTES, its recovery, and a peer
    that reconnected UNSTABLE_RECONNECTS times within an hour (from the node's per-peer
    uptime, which also catches drops shorter than the sampling interval). State lives in
    alert-state.json and is rewritten only when something changes. The caller holds
    ctx.locked(). When notifications are enabled, events and transitions are saved
    together in that one atomic file, before anything is appended to the queue."""
    state = load_peer_state(ctx)
    # A failed query is not an observed empty peer set. Retain both tracking and
    # pending content; collect may still replay the durable outbox independently.
    # Legacy direct callers supplying an actual peer list remain observed.
    if sample.get("peers_observed", True) is not True:
        if not state.get("observation_gap"):
            state["observation_gap"] = True
            save_peer_state(ctx, state)
        event("state", "peer_observation", "unknown_tracking_retained")
        return []
    gap = bool(state.get("observation_gap"))
    down = state.get("down", {}) if isinstance(state.get("down"), dict) else {}
    starts = state.get("starts", {}) if isinstance(state.get("starts"), dict) else {}
    unstable = state.get("unstable", {}) if isinstance(state.get("unstable"), dict) else {}
    now = dt.datetime.fromisoformat(sample["ts"])
    peers = [
        dict(p, r=peer_label(p["r"]))
        for p in sample.get("peers", [])
        if isinstance(p.get("r"), str) and p.get("r")
    ]
    uptimes = {peer_label(k): v for k, v in (uptimes or {}).items()}
    ambiguous = ambiguous_peer_labels(peers)
    up, total = sum(bool(p.get("up")) for p in peers), len(peers)
    changes, tracked = [], {}
    observed = [p for p in peers if p["r"] not in ambiguous]
    # Do not let one link recover another link's episode or teach its uptime.
    # Retain durable tracking across ambiguity, just as across a missing query,
    # without withholding observations for unrelated unambiguous peers.
    for label in ambiguous:
        if isinstance(down.get(label), dict):
            tracked[label] = dict(down[label], observation_gap=True)
    if ambiguous:
        event("state", "peer_observation", "ambiguous_labels_tracking_retained")
    for p in observed:
        entry = candidate if isinstance(candidate := down.get(p["r"]), dict) else {}
        try:
            since = dt.datetime.fromisoformat(entry.get("since", sample["ts"]))
        except (TypeError, ValueError):
            since = now
        uncertain = bool(entry.get("observation_gap")) or gap
        if uncertain and not entry.get("alerted"):
            # No uninterrupted downtime can be proved across a missing query.
            # Keep already-alerted episodes to avoid a duplicate down event,
            # but start a fresh confirmation interval for unalerted episodes.
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
                if uncertain:
                    changes[-1]["observation_gap"] = True
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
        if alerted and uncertain:
            tracked[p["r"]]["observation_gap"] = True
    new_starts, new_unstable = reconnects(
        starts, unstable, uptimes or {}, now, observed, up, total, changes
    )
    for label in ambiguous:
        if label in starts:
            new_starts[label] = starts[label]
        if label in unstable:
            new_unstable[label] = unstable[label]
    pending = state.get("pending", [])
    enqueue = bool(changes) and notify_state(ctx) == "on"
    if enqueue:
        if len(pending) + len(changes) > PEER_PENDING_LIMIT:
            mark_alert_admission_incomplete(ctx, state)
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
    if "admission_incomplete" in state:
        new_state["admission_incomplete"] = state["admission_incomplete"]
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
# Legacy shared bridge path retained only to identify it in compatibility diagnostics;
# forward() never invokes it. Native Ygg handoff has no priority/rule suppression.
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
    if alert.get("kind") == "ygg-peer-up" and alert.get("observation_gap"):
        text = (
            "Нода yggdrasil-lab: пир {peer} снова наблюдается на связи; "
            "был разрыв наблюдений, непрерывный простой не подтверждён; "
            "на связи {up} из {total}."
        )
    fields = {
        k: str(v)[:120]
        for k, v in alert.items()
        if k in ("peer", "minutes", "up", "total", "kind", "count")
    }
    if "peer" in fields:
        fields["peer"] = peer_label(alert["peer"])[:120]
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
    """Checkpoint native-recorded receipts only; ambiguity remains pending.

    The separate durable attempt journal prevents blind resend after a crash or
    timeout. Neither local recording nor its receipt proves delivery/human ACK.
    Existing legacy cursor entries are preserved, not retroactively verified.
    """
    start = time.monotonic()
    deadline = start + FORWARD_BUDGET
    ctx.root()
    with ctx.locked():
        warn_alert_admission(ctx)
        notice, alerts = alert_retention(rows(ctx, "alerts.jsonl"))
        evicted = notice["evicted_uncheckpointed_total"] if notice else 0
        print(f"alert queue retention: evicted_uncheckpointed_total={evicted}", flush=True)
        ids = [alert_id(a) for a in alerts]
        sent = forwarded_ids(ctx)
        if sent is None:
            atomic(
                ctx.p.state / "alerts-forwarded.json",
                json.dumps({"sent": list(dict.fromkeys(ids))[-2000:]}) + "\n",
                0o600,
            )
            print(
                f"[1/1] forwarding initialised; processed={len(ids)} earlier alerts not sent; errors=0 "
                f"remaining=0 evicted_uncheckpointed_total={evicted} "
                f"elapsed={time.monotonic() - start:.2f}s"
            )
            return
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
                simplex_sender.handoff(ctx, aid, alert_message(alert), timeout=min(20, remaining))
                success = True
            except (Failure, OSError, ValueError, KeyError, simplex_sender.sqlite3.Error):
                success = False
            if success:
                done.add(aid)
                # Do not defer this commit until a later message/normal process exit.
                kept = list(dict.fromkeys(i for i in ids if i in done))[-2000:]
                atomic(
                    ctx.p.state / "alerts-forwarded.json", json.dumps({"sent": kept}) + "\n", 0o600
                )
                event("state", "alert_forward", "native_recorded_checkpointed")
            else:
                failures += 1
                event("error", "alert_forward", "native_unconfirmed_pending")
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
            f"evicted_uncheckpointed_total={evicted} "
            f"elapsed={time.monotonic() - start:.2f}s; native local recording is NOT delivery/human ACK"
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
            "peers_observed": False,
            "stack_up": None,
            "errors": [],
        }
        try:
            sample["mode"] = ctx.mode()
            for stack, unit in ((False, NODE), (True, STACK)):
                active = ctx.unit(unit).get("ActiveState", "unknown")
                ps = peers(ctx, stack)  # Exactly one coherent admin query per instance.
                if stack:
                    sample["stack_up"] = sum(identified(p) for p in ps)
                else:
                    uptimes = {peer_label(p.get("remote")): p.get("uptime") for p in ps}
                    sample["act"] = active
                    sample["up"] = sum(identified(p) for p in ps)
                    sample["peers"] = [
                        {
                            "r": peer_label(p.get("remote")),
                            "up": identified(p),
                            "rtt": p.get("latency", 0) / 1e6,
                            "rx": p.get("bytes_recvd", 0),
                            "tx": p.get("bytes_sent", 0),
                        }
                        for p in ps
                    ]
                    sample["peers_observed"] = True
                if active != "active":
                    sample["errors"].append("stack_inactive" if stack else "node_inactive")
        except (Failure, OSError, ValueError) as exc:
            sample["errors"].append(str(exc) if isinstance(exc, Failure) else "metric_unavailable")
        if sample["up"] == 0 or sample["stack_up"] == 0:
            sample["errors"].append("no_up_peers")
        if ambiguous_peer_labels(sample["peers"]):
            sample["errors"].append("ambiguous_peer_labels")
        metric_failed = False
        try:
            append(ctx, "metrics.jsonl", sample)
        except (Failure, OSError):
            metric_failed = True
            sample["errors"].append("metric_write_failed")
            event("error", "collect", "history_write_failed_alerts_continue")
        enabled = notify_state(ctx) == "on"
        if enabled:
            # Drain first: a full recoverable outbox must not block its own retry.
            try:
                flush_peer_alerts(ctx)
            except (Failure, OSError):
                # Queue recovery must not hide an observation already obtained.
                # Stage under the same lock, retaining pending IDs and all state
                # validation/capacity checks. Do not retry or acknowledge the
                # failed queue here; surface its original error after staging.
                peer_alerts(ctx, sample, uptimes)
                try:
                    stage_health_alert(ctx, sample)
                except (Failure, OSError) as exc:
                    event("error", "health_outbox", type(exc).__name__)
                raise
        peer_alerts(ctx, sample, uptimes)
        if enabled:
            stage_health_alert(ctx, sample)
            flush_peer_alerts(ctx)
        warn_alert_admission(ctx)
        if metric_failed:
            raise Failure("metric_write_failed_alerts_processed")
        if sample["errors"]:
            raise Failure("sample_recorded_with_unknown_or_degraded_health")
        print("[1/1] sample recorded; processed=2 instances errors=0 remaining=0")
        return sample


@logged
def window(ctx, hours=24, *, future=None):
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
        if future is not None and at > now:
            future.append(at)
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
    # One pass over the window instead of a scan of every record for every peer name.
    index: dict[str, dict[int, dict[str, Any]]] = {}
    for position, (_, row) in enumerate(values):
        for peer in row.get("peers", []):
            index.setdefault(peer["r"], {}).setdefault(position, peer)
    names = sorted(index)
    print(
        f"window={hours}h samples={len(values)} unknown_records={unknown} "
        f"invalid_records={invalid} missing_minutes_between_samples={gaps}; "
        f"observed availability is NOT wall-clock uptime"
    )
    for name in names:
        by_position = index[name]
        matches = [by_position.get(position) for position in range(len(values))]
        known = [p for p in matches if p is not None]
        up = sum(p["up"] for p in known)
        latency = [p["rtt"] for p in known if p["up"] and p.get("rtt", 0) > 0]
        median = statistics.median(latency) if latency else "unknown"
        print(
            f"{peer_label(name)}: observed_avail={100 * up / len(known):.1f}% present={len(known)} "
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


# Trend navigation: finite numeric boundary -> robust drift -> endpoint block ->
# one-pass historical report -> text projection. Thresholds are policy heuristics,
# not statistical confidence or a live health gate. Split by sample count, not time.
TREND_MIN_SAMPLES = 8
TREND_MIN_SPAN_MINUTES = 30
TREND_RTT_FLOOR_MS = 5.0
TREND_RTT_RATIO = 3.0
TREND_AVAILABILITY_FLOOR = 10.0
TREND_ERROR_FLOOR = 10.0
TREND_PEER_COUNT_FLOOR = 1.0
TREND_STALE_FACTOR = 3.0
TREND_MAX_UNOBSERVED_SHARE = 4


def trend_number(value, audit=None):
    """Finite non-negative float or None; per-call or caller-owned batch logging.

    An explicit local audit avoids per-value journal flooding without thread-global
    trace toggles. trend_drift logs the completed batch, including rejection counts.
    Direct calls log their own entry/result; raw stored values are never logged.
    """
    standalone = audit is None
    if standalone:
        event("entry", "trend_number")
        audit = {"checked": 0, "invalid": 0}
    result = None
    if type(value) in (int, float):
        try:
            number = float(value)
        except OverflowError:
            pass
        else:
            if math.isfinite(number) and number >= 0:
                result = number
    audit["checked"] += 1
    audit["invalid"] += result is None
    if standalone:
        if result is None:
            event("state", "trend_number", "invalid_value_not_comparable")
        event("exit", "trend_number", "finite" if result is not None else "not_comparable")
    return result


@logged
def trend_halves(line):
    """Equal oldest/newest sample-count halves; drop an odd middle sample."""
    half = len(line) // 2
    if not half:
        return [], []
    return line[:half], line[-half:]


@logged
def trend_single(value):
    """A one-element series for an already-aggregated per-half share."""
    return [] if value is None else [value]


@logged
def trend_median(values):
    """Median of a nonempty finite non-negative series, without midpoint overflow."""
    ranked = sorted(values)
    middle = len(ranked) // 2
    if len(ranked) % 2:
        return ranked[middle]
    lower, upper = ranked[middle - 1], ranked[middle]
    return lower + (upper - lower) / 2


@logged
def trend_drift(
    before,
    after,
    floor,
    ratio=TREND_RTT_RATIO,
    worse_higher=True,
    counts=None,
    reasons=None,
    audit=None,
):
    """Finite median/MAD comparison; missing/overflow is explicitly not comparable."""
    audit = {"checked": 0, "invalid": 0} if audit is None else audit
    filtered: list[list[float]] = [[], []]
    for side, values in enumerate((before, after)):
        for value in values:
            number = trend_number(value, audit)
            if number is not None:
                filtered[side].append(number)
    event(
        "state",
        "trend_numeric_validation",
        f"checked={audit['checked']} invalid={audit['invalid']}",
    )
    if not filtered[0] or not filtered[1]:
        if reasons is not None:
            reasons.append("no_valid_samples_in_one_half")
        event("state", "trend_drift", "no_valid_samples_in_one_half")
        return None
    first, second = (trend_median(values) for values in filtered)
    delta = second - first
    spread = trend_median([abs(value - first) for value in filtered[0]])
    threshold = max(floor, ratio * spread)
    if not math.isfinite(threshold):
        if reasons is not None:
            reasons.append("arithmetic_overflow")
        event("state", "trend_drift", "arithmetic_overflow_not_comparable")
        return None
    if abs(delta) < threshold:
        verdict = "stable"
    elif (delta > 0) == worse_higher:
        verdict = "degrading"
    else:
        verdict = "improving"
    return {
        "first": round(first, 3),
        "second": round(second, 3),
        "delta": round(delta, 3),
        "threshold": round(threshold, 3),
        "samples": list(counts) if counts else [len(filtered[0]), len(filtered[1])],
        "verdict": verdict,
    }


@logged
def trend_peer_block(present, up, rtt, answered, unknown, valid=None):
    """Availability conditional on present known-status rows, not all answered rows.

    Absence from an answered sample is exposed, not silently equated to down.
    Strict schema-2 booleans are projections, not raw identity or origin proof.
    """
    valid = present if valid is None else valid
    missing: dict[str, list[str]] = {"availability": [], "rtt_ms": []}
    audit = {"checked": 0, "invalid": 0}
    availability = trend_drift(
        trend_single(100.0 * up[0] / valid[0] if valid[0] else None),
        trend_single(100.0 * up[1] / valid[1] if valid[1] else None),
        TREND_AVAILABILITY_FLOOR,
        worse_higher=False,
        counts=valid,
        reasons=missing["availability"],
        audit=audit,
    )
    latency = trend_drift(
        rtt[0], rtt[1], TREND_RTT_FLOOR_MS, reasons=missing["rtt_ms"], audit=audit
    )
    return {
        "availability": availability,
        "rtt_ms": latency,
        "observed": list(valid),
        "present": list(present),
        "answered": list(answered),
        "absent": [answered[side] - present[side] for side in range(2)],
        "invalid_states": [present[side] - valid[side] for side in range(2)],
        "unobserved": list(unknown),
        "not_comparable": missing,
        "numeric_validation": audit,
    }


@logged
def trend_peer(line, seen=None):
    """Per-endpoint reference path; seen flags must be exact observed booleans."""
    flags = [True] * len(line) if seen is None else list(seen)
    if len(flags) != len(line):
        raise Failure("trend_observation_length_mismatch")
    present, valid, up = [0, 0], [0, 0], [0, 0]
    rtt: list[list[Any]] = [[], []]
    answered, unknown = [0, 0], [0, 0]
    for side, (half, known) in enumerate(zip(trend_halves(line), trend_halves(flags))):
        answered[side] = sum(flag is True for flag in known)
        unknown[side] = len(half) - answered[side]
        for row, flag in zip(half, known):
            if flag is not True or row is None:
                continue
            present[side] += 1
            if type(row.get("up")) is bool:
                valid[side] += 1
                if row["up"] is True:
                    up[side] += 1
                    rtt[side].append(row.get("rtt"))
    return trend_peer_block(present, up, rtt, answered, unknown, valid)


@logged
def trend(ctx, hours=24):
    """One bounded history snapshot; one fused aggregation, no API calls or writes."""
    future: list[dt.datetime] = []
    values, invalid = window(ctx, hours, future=future)
    stamps = [at for at, _ in values]
    span = (stamps[-1] - stamps[0]).total_seconds() / 60
    intervals = [(b - a).total_seconds() / 60 for a, b in zip(stamps, stamps[1:]) if b > a]
    cadence = statistics.median(intervals) if intervals else None
    age = (dt.datetime.now(dt.timezone.utc) - stamps[-1]).total_seconds() / 60
    observed = sum(row.get("peers_observed") is True for _, row in values)
    report = {
        "window_hours": hours,
        "samples": len(values),
        "distinct_samples": len(set(stamps)),
        "invalid_records": invalid,
        "future_samples": len(future),
        "span_minutes": round(span, 1),
        "sampling_minutes": round(cadence, 3) if cadence is not None else None,
        "collector_age_minutes": round(age, 1),
        "observed_samples": observed,
        "unobserved_samples": len(values) - observed,
        "peer_identity": "endpoint_not_key",
        "split": "equal_sample_count_drop_odd_middle",
        "rtt_semantics": "router_response_ewma_not_link_or_application_delay",
        "label_policy": "sanitized_display_endpoint_first_row_per_sample; unknown/colliding labels do not identify origins and are not compared",
        "provenance": {
            "status": "unverified_role_writable_history",
            "authenticated": False,
            "immutable_since_capture": False,
            "warning": "Stored metrics are role-writable and unauthenticated; trends do not attest origin, immutability or API truth.",
        },
        "collector": "stale",
        "verdict": "insufficient_history",
        "reasons": [],
        "node": {},
        "peers": [],
        "malformed_peer_samples": 0,
        "invalid_peer_rows": 0,
        "ambiguous_labels": [],
        "ambiguous_peer_samples": 0,
    }
    if future:
        report["collector"] = "future_timestamp"
        report["reasons"].append("future_samples_present")
    elif age > max(10.0, TREND_STALE_FACTOR * (cadence or 1)):
        report["reasons"].append("collector_stale_beyond_sampling_interval")
    else:
        report["collector"] = "fresh"
    if len(set(stamps)) < TREND_MIN_SAMPLES:
        report["reasons"].append(f"fewer_than_{TREND_MIN_SAMPLES}_samples")
    if span < TREND_MIN_SPAN_MINUTES:
        report["reasons"].append(f"span_below_{TREND_MIN_SPAN_MINUTES}_minutes")
    if not observed:
        report["reasons"].append("no_observed_samples")
    elif observed * TREND_MAX_UNOBSERVED_SHARE < len(values) * (TREND_MAX_UNOBSERVED_SHARE - 1):
        report["reasons"].append(f"unobserved_above_{100 // TREND_MAX_UNOBSERVED_SHARE}_percent")
    half, newer = len(values) // 2, len(values) - len(values) // 2
    node_up: list[list[Any]] = [[], []]
    node_fail: list[list[float]] = [[], []]
    present: dict[str, list[int]] = {}
    valid: dict[str, list[int]] = {}
    up: dict[str, list[int]] = {}
    rtt: dict[str, list[list[Any]]] = {}
    answered, unknown = [0, 0], [0, 0]
    labels: dict[str, str] = {}
    ambiguous: set[str] = set()
    ambiguous_samples = 0
    for position, (_, row) in enumerate(values):
        side = 0 if position < half else 1 if position >= newer else -1
        if side < 0:
            continue
        node_fail[side].append(1.0 if row.get("errors") else 0.0)
        if row.get("peers_observed") is not True:
            unknown[side] += 1
            continue
        answered[side] += 1
        node_up[side].append(row.get("up"))
        entries = row.get("peers")
        if not isinstance(entries, list):
            report["malformed_peer_samples"] += 1
            continue
        named: dict[str, dict[str, Any]] = {}
        seen: dict[str, int] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                report["invalid_peer_rows"] += 1
                continue
            raw = entry.get("r")
            if isinstance(raw, str):
                if raw not in labels:
                    labels[raw] = peer_label(raw)
                name = labels[raw]
            else:
                name = peer_label(raw)
            seen[name] = seen.get(name, 0) + 1
            named.setdefault(name, entry)
        if any(count > 1 for count in seen.values()):
            # One sanitized label can cover several links (different WebSocket
            # paths at one endpoint). Those rows observe different links and
            # must not be fused into one comparable series -- the same rule the
            # alert contract applies to duplicate labels. Other labels continue.
            ambiguous_samples += 1
            ambiguous.update(name for name, count in seen.items() if count > 1)
        for name, entry in named.items():
            if name not in present:
                present[name], valid[name], up[name], rtt[name] = [0, 0], [0, 0], [0, 0], [[], []]
            present[name][side] += 1
            if type(entry.get("up")) is bool:
                valid[name][side] += 1
                if entry["up"] is True:
                    up[name][side] += 1
                    rtt[name][side].append(entry.get("rtt"))
    failures = [100.0 * sum(part) / len(part) if part else None for part in node_fail]
    missing: dict[str, list[str]] = {"up_peers": [], "error_rate": []}
    audit = {"checked": 0, "invalid": 0}
    report["node"] = {
        "up_peers": trend_drift(
            node_up[0],
            node_up[1],
            TREND_PEER_COUNT_FLOOR,
            worse_higher=False,
            reasons=missing["up_peers"],
            audit=audit,
        ),
        "error_rate": trend_drift(
            trend_single(failures[0]),
            trend_single(failures[1]),
            TREND_ERROR_FLOOR,
            counts=[len(node_fail[0]), len(node_fail[1])],
            reasons=missing["error_rate"],
            audit=audit,
        ),
        "not_comparable": missing,
        "numeric_validation": audit,
    }
    for name in sorted(present):
        detail = trend_peer_block(
            present[name], up[name], rtt[name], answered, unknown, valid[name]
        )
        if name in ambiguous:
            # Fused halves of several links are not one comparable series, so no
            # drift claim is made for this label; counts stay visible.
            detail["availability"] = None
            detail["rtt_ms"] = None
            detail["not_comparable"]["availability"].append("ambiguous_peer_label")
            detail["not_comparable"]["rtt_ms"].append("ambiguous_peer_label")
        detail["peer"] = name
        report["peers"].append(detail)
    report["ambiguous_labels"] = sorted(ambiguous)
    report["ambiguous_peer_samples"] = ambiguous_samples
    observed_drifts = [report["node"]["up_peers"]]
    observed_drifts.extend(item["availability"] for item in report["peers"])
    observed_drifts.extend(item["rtt_ms"] for item in report["peers"])
    if not any(item is not None for item in observed_drifts):
        report["reasons"].append("no_comparable_observed_metric")
    if report["malformed_peer_samples"]:
        report["reasons"].append("malformed_peer_samples")
    if ambiguous_samples:
        report["reasons"].append("ambiguous_peer_labels")
    drifts = observed_drifts + [report["node"]["error_rate"]]
    verdicts = [item["verdict"] for item in drifts if item is not None]
    if report["reasons"]:
        report["verdict"] = "insufficient_history"
    elif "degrading" in verdicts:
        report["verdict"] = "degrading"
    elif "improving" in verdicts:
        report["verdict"] = "improving"
    else:
        report["verdict"] = "stable"
    event(
        "state", "trend", f"samples={len(values)} future={len(future)} verdict={report['verdict']}"
    )
    return report


@logged
def trend_line(detail):
    """One comparable line per metric; detailed absence/overflow reasons in report."""
    if detail is None:
        return "not_comparable (no valid samples in one half or arithmetic overflow)"
    return (
        f"{detail['first']} -> {detail['second']} delta={detail['delta']} "
        f"threshold={detail['threshold']} n={detail['samples'][0]}/{detail['samples'][1]} "
        f"verdict={detail['verdict']}"
    )


@logged
def trend_text(report):
    """Visible trust/measurement semantics on the deterministic text projection."""
    lines = [
        f"window={report['window_hours']}h samples={report['samples']} distinct={report['distinct_samples']} "
        f"observed={report['observed_samples']} unobserved={report['unobserved_samples']} "
        f"invalid_records={report['invalid_records']} future_samples={report['future_samples']} "
        f"span={report['span_minutes']}min sampling={report['sampling_minutes']}min "
        f"collector_age={report['collector_age_minutes']}min collector={report['collector']}",
        "provenance=unverified_role_writable_history authenticated=false immutable_since_capture=false",
        report["provenance"]["warning"],
        f"peer_identity={report['peer_identity']}; {report['label_policy']}",
        f"split={report['split']} (NOT equal elapsed-time halves or wall-clock uptime)",
        f"RTT={report['rtt_semantics']} (protocol router-response EWMA, NOT link/application delay)",
        f"ambiguous_labels={report['ambiguous_labels']} ambiguous_peer_samples={report['ambiguous_peer_samples']}",
        f"node up_peers: {trend_line(report['node']['up_peers'])}",
        f"node error_rate%: {trend_line(report['node']['error_rate'])}",
        f"node not_comparable={report['node']['not_comparable']} numeric_validation={report['node']['numeric_validation']}",
    ]
    for peer in report["peers"]:
        lines.append(f"{peer['peer']}: availability% {trend_line(peer['availability'])}")
        lines.append(f"{peer['peer']}: rtt_ms {trend_line(peer['rtt_ms'])}")
        lines.append(
            f"{peer['peer']}: present={peer['present']} answered={peer['answered']} "
            f"absent={peer['absent']} invalid_states={peer['invalid_states']} "
            f"not_comparable={peer['not_comparable']} numeric_validation={peer['numeric_validation']}"
        )
    if report["reasons"]:
        lines.append(f"trend={report['verdict']} reasons={','.join(report['reasons'])}")
    else:
        lines.append(f"trend={report['verdict']}")
    lines.append(
        "sample-count median drift/MAD policy thresholds; NOT statistical confidence, link health or a gate"
    )
    return lines


@logged
def watch(ctx, count=5, interval=2):
    start, errors = time.monotonic(), 0
    for i in range(count):
        try:
            node = sum(identified(p) for p in peers(ctx))
            stack = sum(identified(p) for p in peers(ctx, True))
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
