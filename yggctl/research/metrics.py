"""Historic sampling denominators and latency quantiles, not world capacity."""

from typing import Any

import datetime as dt
import hashlib
import urllib.parse

from core import Failure, logged
from .model import instant, latency, public_key


@logged
def quantiles(values):
    ordered = sorted(values)
    if not ordered:
        return {"n": 0, "min": None, "p50": None, "p95": None, "max": None}
    result = {"n": len(ordered), "min": ordered[0], "max": ordered[-1]}
    for name, q in (("p50", 0.5), ("p95", 0.95)):
        at = (len(ordered) - 1) * q
        i = int(at)
        result[name] = ordered[i] + (ordered[min(i + 1, len(ordered) - 1)] - ordered[i]) * (at - i)
    return result


@logged
def peer_identity(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise Failure("research_invalid_metric_peer_id")
    # Hash the endpoint string without exposing credentials in URI fields.
    label = hashlib.sha256(value.encode()).hexdigest()[:24]
    key = None
    try:
        keys = urllib.parse.parse_qs(urllib.parse.urlsplit(value).query).get("key", [])
        if len(keys) == 1:
            key = public_key(keys[0])
    except (ValueError, Failure):
        pass
    return label, key


@logged
def summary(records, hours, now):
    if type(hours) is not int or not 1 <= hours <= 72:
        raise Failure("research_invalid_window")
    if not isinstance(records, list) or len(records) > 10000:
        raise Failure("research_metric_record_limit")
    end = instant(now)
    begin = end - dt.timedelta(hours=hours)
    valid: list[tuple[dt.datetime, dict[str, Any]]] = []
    seen: dict[dt.datetime, int] = {}
    invalid, outside, duplicates = 0, 0, 0
    for r in records:
        try:
            if not isinstance(r, dict):
                raise Failure("research_metric_object_required")
            at = instant(r.get("ts"))
        except Failure:
            invalid += 1
            continue
        if not begin <= at <= end:
            outside += 1
            continue
        if at in seen:
            duplicates += 1
            index = seen[at]
            valid[index] = (
                at,
                dict(valid[index][1], act="unknown", errors=["duplicate_timestamp"]),
            )
            continue  # Conflicting timestamp downgraded, never counted twice.
        seen[at] = len(valid)
        valid.append((at, r))
    valid.sort(key=lambda pair: pair[0])
    slots = {min(hours * 60 - 1, int((at - begin).total_seconds() / 60)) for at, _ in valid}
    all_ids: dict[str, Any] = {}
    cache: dict[str, tuple[str, str | None]] = {}
    unknown_records, invalid_peers, peer_rows = 0, 0, 0
    for at, r in valid:
        known_record = (
            type(r.get("schema")) is int
            and r["schema"] == 2
            and r.get("act") == "active"
            and type(r.get("up")) is int
            and r["up"] >= 0
            and r.get("errors") == []
            and isinstance(r.get("peers"), list)
            and len(r["peers"]) <= 4096
        )
        by_id: dict[str, dict[str, Any] | None] = {}
        unidentified_row = False
        ps = (
            observed
            if isinstance(observed := r.get("peers"), list) and len(observed) <= 4096
            else []
        )
        for p in ps:
            peer_rows += 1
            if peer_rows > 100000:
                raise Failure("research_metric_peer_row_limit")
            try:
                if not isinstance(p, dict):
                    raise Failure("research_metric_peer_object_required")
                uri = p.get("r")
                if not isinstance(uri, str):
                    raise Failure("research_invalid_metric_peer_id")
                if uri not in cache:
                    cache[uri] = peer_identity(uri)
                label, key = cache[uri]
            except Failure:
                invalid_peers += 1
                unidentified_row = True
                continue
            if label not in all_ids:
                if len(all_ids) >= 4096:
                    raise Failure("research_metric_endpoint_limit")
                all_ids[label] = {
                    "key": key,
                    "up": 0,
                    "down": 0,
                    "unknown": 0,
                    "missing_latency": 0,
                    "latencies": [],
                }
            if label in by_id:
                by_id[label] = None  # Ambiguous duplicate peer row = unknown.
                invalid_peers += 1
            else:
                by_id[label] = p if known_record else None
        # An unreadable endpoint could be a peer we would otherwise mark
        # absent. Downgrade the record instead of inventing that absence.
        known_record = known_record and not unidentified_row
        if not known_record:
            unknown_records += 1
        if known_record:
            for label, observed_peer in by_id.items():
                counters = all_ids[label]
                if observed_peer is None or type(observed_peer.get("up")) is not bool:
                    counters["unknown"] += 1
                elif not observed_peer["up"]:
                    counters["down"] += 1
                else:
                    counters["up"] += 1
                    ms = latency(observed_peer.get("rtt"))
                    if ms is None:
                        counters["missing_latency"] += 1
                    else:
                        counters["latencies"].append(ms)
    results, pooled = [], []
    for label in sorted(all_ids):
        counters = all_ids[label]
        up, down = counters["up"], counters["down"]
        unknown = counters["unknown"] + unknown_records
        absent = len(valid) - up - down - unknown
        observed = counters["latencies"]
        pooled.extend(observed)
        results.append(
            {
                "endpoint_digest": label,
                "pinned_public_key": counters["key"],
                "up_samples": up,
                "down_samples": down,
                "unknown_samples": unknown,
                "absent_samples": absent,
                "availability_among_known_present_pct": 100 * up / (up + down)
                if up + down
                else None,
                "latency_ms": quantiles(observed),
                "missing_or_invalid_latency_on_up": counters["missing_latency"],
            }
        )
    return {
        "window_start": begin.isoformat(),
        "window_end": end.isoformat(),
        "hours": hours,
        "samples": len(valid),
        "unknown_records": unknown_records,
        "invalid_records": invalid,
        "outside_window_records": outside,
        "duplicate_timestamps_skipped": duplicates,
        "invalid_or_duplicate_peer_rows": invalid_peers,
        "nominal_cadence_s": 60,
        "minutes_with_timestamped_records": len(slots),
        "minutes_without_records": hours * 60 - len(slots),
        "timestamped_minute_coverage_pct": 100 * len(slots) / (hours * 60),
        "peers": results,
        "pooled_peer_sample_latency_ms": quantiles(pooled),
        "limits": [
            "sample ratios are not wall-clock or global availability",
            "absent/unknown is NOT down",
            "minute coverage includes degraded records, not healthy uptime",
            "latency is local peer transport estimate, not remote service RTT",
            "pooled quantiles weight peer samples, not geographic regions or world nodes",
            "endpoint pins do not prove historical identity; collector has no own-key/boot epoch",
            "missing/zero/invalid latency is not a zero-latency observation",
            "unidentified peer rows downgrade a record to unknown, not absence",
            "duplicate timestamps downgraded to unknown; no inference for unobserved time",
        ],
    }
