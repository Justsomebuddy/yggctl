"""Full discovered-key frontier in resumable time slices, with no sample quota."""

import json
import time
import uuid

from core import Failure, logged, timestamp, event
import checks
from research import model
from . import protocol
from .store import MAX_NODES


@logged
def local_snapshot(ctx):
    value = {
        "schema": 1,
        "id": uuid.uuid4().hex,
        "instance": "node",
        "started": timestamp(),
        "finished": None,
        "identity_stable": None,
        "sources": {},
        "observations": {},
    }
    for name in model.SOURCES:
        try:
            projected = model.project(
                name,
                ctx.api(
                    {
                        "self": "getSelf",
                        "peers": "getPeers",
                        "tree": "getTree",
                        "paths": "getPaths",
                    }[name]
                ),
            )
        except (Failure, ValueError, TypeError, OSError):
            value["sources"][name], value["observations"][name] = "unavailable", None
        else:
            value["sources"][name], value["observations"][name] = "ok", projected
    try:
        own = model.project("self", ctx.api("getSelf"))["key"]
        if value["observations"]["self"]:
            value["identity_stable"] = own == value["observations"]["self"]["key"]
    except (Failure, ValueError, TypeError, OSError):
        pass
    value["finished"] = timestamp()
    model.validate(value)
    if value["identity_stable"] is not True:
        raise Failure("atlas_local_identity_unknown_or_changed")
    return value


@logged
def new_run(ctx, store):
    catalogue = [
        json.loads(row[0]) for row in store.sql("SELECT payload FROM catalogue ORDER BY id")
    ]
    meta = store.meta("catalogue")
    if not meta or not catalogue:
        raise Failure("atlas_catalogue_first")
    with ctx.locked():
        checks.integrity(ctx)
        local = local_snapshot(ctx)
    own = local["observations"]["self"]["key"]
    run = uuid.uuid4().hex
    seed = {"local": local, "catalogue": catalogue, "catalogue_meta": meta}
    pinned = {model.public_key(k) for record in catalogue for k in record["pins"] if k != own}
    keys = {node["key"] for node in model.graph(local)["nodes"] if node["key"] != own}
    if len(pinned | keys) > MAX_NODES:
        raise Failure("atlas_storage_frontier_guard_checkpoint_not_complete")
    # Publish run, all seeds and current pointer together: no orphan generation.
    store.batch(
        [
            (
                "INSERT INTO runs VALUES(?,?,?,NULL,?,?)",
                (run, own, timestamp(), "checkpoint", json.dumps(seed, allow_nan=False)),
            )
        ]
        + [
            (
                "INSERT INTO targets(run,key,origin) VALUES(?,?,?)",
                (run, key, "catalogue_pin_claim" if key in pinned else "local_observation"),
            )
            for key in sorted(pinned | keys)
        ]
        + [("INSERT OR REPLACE INTO meta VALUES(?,?)", ("current", json.dumps(run)))]
    )
    event("state", "atlas_run", "new_deduplicated_frontier")
    return run


@logged
def status(store, run=None):
    run = run or store.meta("current")
    if not run:
        return {"run": None, "catalogue": store.meta("catalogue"), "world_coverage": None}
    rows = store.sql("SELECT own,started,finished,state FROM runs WHERE id=?", (run,))
    if not rows:
        raise Failure("atlas_missing_current_run")
    own, started, finished, state = rows[0]
    model.public_key(own)
    total, processed = store.sql(
        "SELECT COUNT(*),COALESCE(SUM(done),0) FROM targets WHERE run=?", (run,)
    )[0]
    counts = dict(
        store.sql("SELECT status,COUNT(*) FROM responses WHERE run=? GROUP BY status", (run,))
    )
    return {
        "run": run,
        "own": own,
        "started": started,
        "finished": finished,
        "state": state,
        "discovered_remote_keys": total,
        "processed_keys": processed,
        "remaining_keys": total - processed,
        "methods": counts,
        "world_coverage": None,
        "neighbour_list_completeness": None,
        "scope": "deduplicated discovered-key frontier, not the whole world",
    }


@logged
def payload(value, key, method):
    # A saved response is still untrusted data. Validate it before new requests.
    try:
        data = json.loads(value)
    except (ValueError, TypeError):
        raise Failure("atlas_invalid_saved_response") from None
    if method == "self":
        expected = protocol.projection(key, method, {protocol.address(key): data})
        if data != expected:
            raise Failure("atlas_invalid_saved_response")
    else:
        if not isinstance(data, dict) or set(data) != {
            "keys",
            "returned_rows",
            "duplicate_rows",
            "complete",
            "semantics",
        }:
            raise Failure("atlas_invalid_saved_response")
        expected = protocol.projection(key, method, {protocol.address(key): {"keys": data["keys"]}})
        for name in ("keys", "complete", "semantics"):
            if expected[name] != data[name]:
                raise Failure("atlas_invalid_saved_response")
        total, duplicates = (
            model.integer(data["returned_rows"]),
            model.integer(data["duplicate_rows"]),
        )
        if total > 4096 or total - len(data["keys"]) != duplicates:
            raise Failure("atlas_invalid_saved_response")
    return data


@logged
def crawl(ctx, store, minutes=120):
    if type(minutes) is not int or not 1 <= minutes <= 120:
        raise Failure("atlas_invalid_time_slice")
    run = store.meta("current") or new_run(ctx, store)
    before = status(store, run)
    if before["state"] == "frontier_exhausted":
        return before
    own = before["own"]
    start = time.monotonic()
    deadline = start + minutes * 60
    store.sql(
        "UPDATE responses SET status='interrupted_unknown' WHERE run=? AND status='inflight'",
        (run,),
    )
    store.sql("UPDATE runs SET state='running',finished=NULL WHERE id=?", (run,))
    print(
        "[1/3] resume full discovered-key frontier; processed=0/unknown remaining=unknown",
        flush=True,
    )
    state = "checkpoint"
    queries = 0
    try:
        while time.monotonic() < deadline:
            pending = store.sql(
                "SELECT key FROM targets WHERE run=? AND done=0 ORDER BY rowid LIMIT 1", (run,)
            )
            if not pending:
                state = "frontier_exhausted"
                break
            target = model.public_key(pending[0][0])
            if target == own:
                raise Failure("atlas_own_key_in_remote_frontier")
            live_own = model.public_key(ctx.api("getSelf").get("key"))
            if live_own != own:
                raise Failure("atlas_identity_changed_start_new_run")
            for method in protocol.METHODS:
                existing = store.sql(
                    "SELECT status,payload FROM responses WHERE run=? AND key=? AND method=?",
                    (run, target, method),
                )
                if existing:
                    result, raw = existing[0]
                    projected = payload(raw, target, method) if result == "ok" else None
                else:
                    if time.monotonic() >= deadline:
                        break
                    store.response(run, target, method, "inflight")
                    result, elapsed, projected = protocol.query(ctx, target, method)
                    store.response(run, target, method, result, elapsed, projected)
                    queries += 1
                if projected and method != "self":
                    store.seed(
                        run,
                        (k for k in projected["keys"] if k != own),
                        "remote_" + method + "_reference",
                    )
            count = store.sql(
                "SELECT COUNT(*) FROM responses WHERE run=? AND key=?", (run, target)
            )[0][0]
            if count == 3:
                store.sql("UPDATE targets SET done=1 WHERE run=? AND key=?", (run, target))
            progress = status(store, run)
            elapsed = time.monotonic() - start
            speed = queries / max(elapsed, 0.001)
            print(
                f"[2/3] frontier processed={progress['processed_keys']}/{progress['discovered_remote_keys']} remaining={progress['remaining_keys']} queries={queries} unknown={progress['methods'].get('unknown', 0)} elapsed={elapsed:.1f}s speed={speed:.2f}queries/s ETA=unknown/growing-frontier",
                flush=True,
            )
        # Hitting a time slice exactly as the final target commits is not
        # falsely reported as unfinished, nor is unknown reachability erased.
        if status(store, run)["remaining_keys"] == 0:
            state = "frontier_exhausted"
    finally:
        store.sql("UPDATE runs SET state=?,finished=? WHERE id=?", (state, timestamp(), run))
        event("state", "atlas_run", state)
        progress = status(store, run)
        elapsed = time.monotonic() - start
        print(
            f"[3/3] saved processed={progress['processed_keys']}/{progress['discovered_remote_keys']} remaining={progress['remaining_keys']} unknown={progress['methods'].get('unknown', 0)} elapsed={elapsed:.1f}s speed={queries / max(elapsed, 0.001):.2f}queries/s state={state}",
            flush=True,
        )
    return progress


@logged
def sweep(ctx, store):
    """Complete the discovered frontier; slices are checkpoints, not stop quotas."""
    while True:
        result = crawl(ctx, store, 120)
        if result["state"] == "frontier_exhausted":
            return result
        event("state", "atlas_sweep", "continue_checkpoint_without_retries")
