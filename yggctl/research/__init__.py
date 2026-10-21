"""Bounded local research commands; no external crawl or network mutation."""

import contextlib
import datetime as dt
import fcntl
import json
import os
import re
import stat
import time
import uuid

from core import Failure, logged, read_regular, atomic, timestamp, event, bounded_number
import checks
import telemetry
from . import model, metrics

VERSION = "1.0.1"
LIMIT = 256
BYTE_LIMIT = 2 * 1024 * 1024


@logged
def folder(ctx, create=False):
    path = ctx.p.state / "research"
    if ctx.require_root:
        checks.trusted(ctx.p.state)
    if not path.exists() and not path.is_symlink():
        if not create:
            return None
        path.mkdir(mode=0o700)
        event("state", "research_store", "created_private")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
        raise Failure("research_store_not_private_directory")
    if ctx.require_root:
        checks.trusted(path)
    return path


@logged
def snapshot_files(ctx):
    with ctx.locked():
        root = folder(ctx)
        if root is None:
            return []
        with store_locked(root):
            return scan_store(root)


@contextlib.contextmanager
def store_locked(root):
    # The worker must own this lock: its parent can die and release the
    # console lock while an atomic artifact write is still in progress.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure("research_store_busy") from None
        yield
    finally:
        os.close(fd)


@logged
def store_atomic(path, data):
    with store_locked(path.parent):
        atomic(path, data)


@logged
def scan_store(root):
    found, abandoned = [], []
    # Validate the entire bounded directory before removing anything.
    for i, path in enumerate(root.iterdir()):
        if i >= LIMIT * 3:
            raise Failure("research_store_entry_limit")
        if re.fullmatch(r"\.yggctl-[a-z0-9_]{8}", path.name):
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise Failure("research_unsafe_temporary_file")
            abandoned.append(path)
            continue
        if re.fullmatch(r"snapshot-[0-9a-f]{32}\.json", path.name):
            found.append(path)
        elif not re.fullmatch(
            r"(?:map-[0-9a-f]{32}\.dot|report-[0-9a-f]{32}\.(?:json|md))", path.name
        ):
            raise Failure("research_unrecognized_store_entry")
        if path.is_symlink() or not path.is_file():
            raise Failure("research_unsafe_store_entry")
    if len(found) > LIMIT:
        raise Failure("research_snapshot_limit")
    for path in abandoned:
        path.unlink()
        event("state", "research_store", "abandoned_atomic_removed")
    return found


@logged
def load(path):
    try:
        data = json.loads(read_regular(path, BYTE_LIMIT))
    except (ValueError, UnicodeError):
        raise Failure("research_invalid_snapshot_json") from None
    model.validate(data)
    if path.name != "snapshot-" + data["id"] + ".json":
        raise Failure("research_snapshot_filename_mismatch")
    return data


@logged
def snapshots(ctx):
    result = [load(p) for p in snapshot_files(ctx)]
    return sorted(result, key=lambda s: (model.instant(s["started"]), s["id"]))


@logged
def selected(ctx, value=None):
    if value is not None and not re.fullmatch(r"[0-9a-f]{32}", value):
        raise Failure("research_expected_snapshot_id")
    values = snapshots(ctx)
    if value is None:
        if not values:
            raise Failure("research_no_snapshots_capture_first")
        return values[-1]
    for s in values:
        if s["id"] == value:
            return s
    raise Failure("research_snapshot_not_found")


@logged
def capture(ctx):
    started = time.monotonic()
    ctx.root()
    with ctx.locked():
        checks.integrity(ctx)
        root = folder(ctx, create=True)
        if len(snapshot_files(ctx)) >= LIMIT:
            raise Failure("research_retention_review_required")
        result = {
            "schema": 1,
            "id": uuid.uuid4().hex,
            "instance": "node",
            "started": timestamp(),
            "finished": None,
            "identity_stable": None,
            "sources": {},
            "observations": {},
        }
        for i, name in enumerate(model.SOURCES, 1):
            elapsed = time.monotonic() - started
            print(
                f"[{i}/5] local admin {name}; processed={i - 1}/5 remaining={6 - i} elapsed={elapsed:.2f}s ETA<={(6 - i) * 20}s speed={(i - 1) / max(elapsed, 0.001):.2f}queries/s",
                flush=True,
            )
            try:
                reply = ctx.api(
                    {
                        "self": "getSelf",
                        "peers": "getPeers",
                        "tree": "getTree",
                        "paths": "getPaths",
                    }[name]
                )
            except (Failure, OSError, ValueError, TypeError):
                result["sources"][name], result["observations"][name] = "unavailable", None
            else:
                try:
                    result["observations"][name] = model.project(name, reply)
                except (Failure, ValueError, TypeError, OverflowError):
                    result["sources"][name], result["observations"][name] = "invalid", None
                else:
                    result["sources"][name] = "ok"
            event("state", "research_source", result["sources"][name])
        elapsed = time.monotonic() - started
        print(
            f"[5/5] verify local identity; processed=4/5 remaining=1 elapsed={elapsed:.2f}s ETA<=20s speed={4 / max(elapsed, 0.001):.2f}queries/s",
            flush=True,
        )
        try:
            end = model.project("self", ctx.api("getSelf"))
            if result["sources"]["self"] == "ok":
                result["identity_stable"] = end["key"] == result["observations"]["self"]["key"]
        except (Failure, OSError, ValueError, TypeError):
            pass
        result["finished"] = timestamp()
        model.validate(result)
        data = json.dumps(result, sort_keys=True, allow_nan=False)
        if len(data.encode()) > BYTE_LIMIT:
            raise Failure("research_projected_snapshot_size_limit")
        out = root / ("snapshot-" + result["id"] + ".json")
        store_atomic(out, data + "\n")
        event("state", "research_capture", "saved_allowlisted_projection")
        failures = sum(s != "ok" for s in result["sources"].values()) + int(
            result["identity_stable"] is not True
        )
        elapsed = time.monotonic() - started
        print(
            f"snapshot_id={result['id']} file={out}; processed=5/5 remaining=0 errors={failures} elapsed={elapsed:.2f}s speed={5 / max(elapsed, 0.001):.2f}queries/s"
        )
        if failures:
            raise Failure("research_partial_snapshot_saved_not_full_local_success")
        return {"snapshot_id": result["id"], "sequential_not_atomic": True, "world_coverage": None}


@logged
def topology_map(ctx, value=None):
    with ctx.locked():
        checks.integrity(ctx)
        snapshot = selected(ctx, value)
        data = model.graph(snapshot)
        out = folder(ctx) / ("map-" + snapshot["id"] + ".dot")
        store_atomic(out, model.dot(snapshot))
        return {
            "snapshot_id": snapshot["id"],
            "sources": snapshot["sources"],
            "identity_stable": snapshot["identity_stable"],
            "sequential_not_atomic": True,
            "dot_file": str(out),
            "graph": data,
            "world_coverage": None,
        }


@logged
def compare(ctx, value=None):
    with ctx.locked():
        checks.integrity(ctx)
        values = snapshots(ctx)
        if len(values) < 2:
            raise Failure("research_need_two_snapshots")
        before = selected(ctx, value) if value else values[-2]
        return model.difference(before, values[-1])


@logged
def markdown(report):
    topology = report["topology"]
    history = report["history"]
    lines = [
        "# Observed Yggdrasil network research",
        "",
        f"Generated: {report['generated']}",
        "",
        "## Scope / unknown",
        "Local node only; NOT a global census, packet trace or capacity benchmark.",
        "World node count, coverage fraction and throughput: UNKNOWN.",
        "Snapshots are sequential queries, not atomic topology cuts.",
        "Parent references are not confirmed live responders; tree edges are not transport links.",
        "",
        "## Topology",
        f"Snapshots in window: {topology['snapshots']}",
        f"Latest observed identities (including references): {topology['latest_observed_identities']}",
        f"Latest source status: {json.dumps(topology['latest_sources'], sort_keys=True)}",
        f"Local key stable during latest capture: {topology['latest_identity_stable']}",
        f"Comparable adjacent snapshots: {len(topology['changes'])}; skipped: {topology['skipped_comparisons']}",
        "Observation removals do NOT prove world nodes/links went offline.",
        "",
        "| Before → after | Source | Added/removed/changed observations |",
        "|---|---|---|",
    ]
    for change in topology["changes"]:
        for name, source in change["sources"].items():
            counts = (
                "/".join(str(len(source[f])) for f in ("added", "removed", "changed"))
                if source["known"]
                else "UNKNOWN"
            )
            lines.append(
                f"| {change['before'][:12]} → {change['after'][:12]} | {name} | {counts} |"
            )
    lines += ["", "## History"]
    if history is None:
        lines.append("UNKNOWN: metric stream unavailable or corrupt; not zero availability.")
    else:
        lines += [
            f"Samples: {history['samples']}; unknown records: {history['unknown_records']}; invalid records: {history['invalid_records']}",
            f"Timestamped minute coverage: {history['timestamped_minute_coverage_pct']:.2f}%; minutes without records: {history['minutes_without_records']}",
            "Sampling ratios are NOT wall-clock/global uptime; absent and unknown are NOT down.",
            "Endpoint digests hide raw URI/credentials. Historical own identity/boot epoch is unknown.",
            "Latency is local peer transport estimate, NOT remote service RTT.",
            "",
            "| Endpoint digest | Up/down/unknown/absent samples | Known-present availability % | Latency p50/p95 ms |",
            "|---|---|---|---|",
        ]
        for p in history["peers"]:
            availability = p["availability_among_known_present_pct"]
            q = p["latency_ms"]
            lines.append(
                f"| {p['endpoint_digest']} | {p['up_samples']}/{p['down_samples']}/{p['unknown_samples']}/{p['absent_samples']} | {availability if availability is not None else 'UNKNOWN'} | {q['p50']}/{q['p95']} |"
            )
    lines += [
        "",
        "## Artifact files",
        "Graph DOT: " + str(report["dot_file"]),
        "",
        "## Limitations",
    ]
    lines.extend("- " + label for label in report["limits"])
    return "\n".join(lines) + "\n"


@logged
def report(ctx, hours=24):
    start = time.monotonic()
    ctx.root()
    if type(hours) is not int or not 1 <= hours <= 72:
        raise Failure("research_invalid_window")
    with ctx.locked():
        checks.integrity(ctx)
        root = folder(ctx, create=True)
        snapshot_files(ctx)  # Revalidate caps/entries before any artifacts.
        if sum(p.name.startswith("report-") for p in root.iterdir()) >= 128:
            raise Failure("research_report_retention_review_required")
        now = timestamp()
        end = model.instant(now)
        begin = end - dt.timedelta(hours=hours)
        print("[1/3] read projected topology; processed=0/3 remaining=3", flush=True)
        values = [s for s in snapshots(ctx) if begin <= model.instant(s["finished"]) <= end]
        latest = values[-1] if values else None
        data = model.graph(latest) if latest else None
        changes, skipped = [], 0
        for a, b in zip(values, values[1:]):
            try:
                changes.append(model.difference(a, b))
            except Failure:
                skipped += 1
        elapsed = time.monotonic() - start
        print(
            f"[2/3] read bounded historical metrics; processed=1/3 remaining=2 elapsed={elapsed:.2f}s ETA=unknown/bounded-local-data speed={1 / max(elapsed, 0.001):.2f}stages/s",
            flush=True,
        )
        try:
            history = metrics.summary(telemetry.rows(ctx), hours, now)
        except (Failure, OSError, ValueError, TypeError, OverflowError):
            history = None
        identity_counts: dict[str, int] = {}
        for s in values:
            key = s["observations"]["self"]["key"] if s["observations"]["self"] else "unknown"
            identity_counts[key] = identity_counts.get(key, 0) + 1
        result = {
            "schema": 1,
            "module_version": VERSION,
            "generated": now,
            "instance": "node",
            "world_nodes": None,
            "global_coverage_fraction": None,
            "throughput_bps": None,
            "history": history,
            "dot_file": None,
            "topology": {
                "snapshots": len(values),
                "snapshots_by_identity": identity_counts,
                "latest_snapshot_id": latest["id"] if latest else None,
                "latest_sources": latest["sources"] if latest else None,
                "latest_identity_stable": latest["identity_stable"] if latest else None,
                "latest_observed_identities": len(data["nodes"]) if data else None,
                "latest": data,
                "changes": changes,
                "skipped_comparisons": skipped,
            },
            "limits": [
                "one local vantage; no remote crawl or country/ASN inference",
                "stored node snapshots only; stack identity never merged",
                "sequential admin reads; self key checked before/after, no atomic or boot-epoch guarantee",
                "no global completeness, live world count, unobserved reachability or bandwidth estimate",
                "history lacks local key/boot epoch; current snapshots cannot assign old samples to an identity",
                "partial sources are unknown, never fabricated empty; disappeared observations are not confirmed outages",
            ],
        }
        if latest:
            out = root / ("map-" + latest["id"] + ".dot")
            store_atomic(out, model.dot(latest))
            result["dot_file"] = str(out)
        identifier = uuid.uuid4().hex
        payload = json.dumps(result, sort_keys=True, allow_nan=False)
        if len(payload.encode()) > 16 * 1024 * 1024:
            raise Failure("research_report_size_limit")
        out = root / ("report-" + identifier)
        # Independent immutable UUID artifacts; no accepted-baseline mutation.
        store_atomic(out.with_suffix(".json"), payload + "\n")
        store_atomic(out.with_suffix(".md"), markdown(result))
        event("state", "research_report", "saved_scoped_artifacts")
        elapsed = time.monotonic() - start
        print(
            f"[3/3] processed=3/3 remaining=0 errors=0 elapsed={elapsed:.2f}s speed={3 / max(elapsed, 0.001):.2f}stages/s"
        )
        return {
            "json_file": str(out.with_suffix(".json")),
            "markdown_file": str(out.with_suffix(".md")),
            "snapshots": len(values),
            "metrics_samples": history["samples"] if history else None,
            "global_coverage_fraction": None,
            "unknown_history": history is None,
        }


@logged
def command(ctx, args):
    if not args or len(args) > 2 or args[0] not in ("capture", "map", "diff", "report"):
        raise Failure("research_capture_map_diff_report_optional_id_or_hours")
    action = args[0]
    value = args[1] if len(args) == 2 else None
    if action == "capture":
        if value is not None:
            raise Failure("research_capture_no_arguments")
        return capture(ctx)
    if action == "map":
        return topology_map(ctx, value)
    if action == "diff":
        return compare(ctx, value)
    return report(ctx, bounded_number(value, 1, 72) if value else 24)
