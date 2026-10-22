"""Typed, allowlisted observations; never persist raw admin replies."""

from typing import Any

import datetime as dt
import math
import re

from core import Failure, logged

SOURCES = ("self", "peers", "tree", "paths")
MAX_ENTRIES = 4096


@logged
def snapshot_provenance():
    """Generated trust contract, never an assertion read from a saved snapshot."""
    return {
        "status": "unverified_role_writable_history",
        "authenticated": False,
        "immutable_since_capture": False,
        "warning": "Stored snapshots are role-writable and unauthenticated; schema/source status and identity_stable do not verify origin, immutability or API truth.",
    }


@logged
def public_key(value, optional=False):
    if optional and value in (None, ""):
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise Failure("research_invalid_public_key")
    return value.lower()


@logged
def integer(value):
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        raise Failure("research_invalid_integer")
    return value


@logged
def latency(value, divisor=1):
    if (
        type(value) not in (int, float)
        or not 0 < value <= 86400000 * divisor
        or not math.isfinite(value)
    ):
        return None
    return value / divisor


@logged
def instant(value):
    if not isinstance(value, str) or len(value) > 64:
        raise Failure("research_invalid_timestamp")
    try:
        at = dt.datetime.fromisoformat(value)
    except ValueError:
        raise Failure("research_invalid_timestamp") from None
    if at.tzinfo is None:
        raise Failure("research_naive_timestamp")
    return at.astimezone(dt.timezone.utc)


@logged
def entries(reply, name):
    rows = reply.get(name) if isinstance(reply, dict) else None
    if (
        not isinstance(rows, list)
        or len(rows) > MAX_ENTRIES
        or any(not isinstance(p, dict) for p in rows)
    ):
        raise Failure("research_invalid_entries")
    return rows


@logged
def project(source, reply, stored=False):
    if source == "self":
        if not isinstance(reply, dict):
            raise Failure("research_invalid_self")
        return {
            "key": public_key(reply.get("key")),
            "routing_entries": integer(reply.get("routing_entries")),
        }
    rows, seen = [], set()
    for p in entries(reply, source):
        if source == "peers":
            if type(p.get("up")) is not bool or type(p.get("inbound")) is not bool:
                raise Failure("research_invalid_peer_state")
            # URI, last_error, build/metadata and arbitrary fields deliberately
            # excluded: they can contain passwords or untrusted free text.
            row = {
                "key": public_key(p.get("key"), optional=True),
                "up": p["up"],
                "inbound": p["inbound"],
                "port": integer(p.get("port")),
                "latency_ms": latency(p.get("latency_ms"))
                if stored
                else latency(p.get("latency"), 1e6),
            }
            # The daemon exposes no per-link identity: the same peer appears once per
            # transport (multilink) with the same key, port and direction, and every
            # unreachable peer reports the same empty key, port 0 and direction. Peer
            # rows are therefore not deduplicated at all; the reply stays bounded by
            # MAX_ENTRIES and by the snapshot byte limit.
            token = None
        elif source == "tree":
            row = {
                "key": public_key(p.get("key")),
                "parent": public_key(p.get("parent")),
                "sequence": integer(p.get("sequence")),
            }
            token = row["key"]
        elif source == "paths":
            path = p.get("path")
            if not isinstance(path, list) or len(path) > 256:
                raise Failure("research_invalid_path")
            row = {
                "key": public_key(p.get("key")),
                "path": [integer(n) for n in path],
                "sequence": integer(p.get("sequence")),
            }
            token = row["key"]
        else:
            raise Failure("research_unknown_source")
        if token is not None:
            if token in seen:
                raise Failure("research_duplicate_entry")
            seen.add(token)
        rows.append(row)
    return sorted(rows, key=lambda r: (r["key"] or "", r.get("port", 0), r.get("inbound", False)))


@logged
def validate(snapshot):
    """Validate structure only; this cannot authenticate origin or API truth."""
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema",
        "id",
        "instance",
        "started",
        "finished",
        "identity_stable",
        "sources",
        "observations",
    }:
        raise Failure("research_invalid_snapshot")
    if (
        type(snapshot["schema"]) is not int
        or snapshot["schema"] != 1
        or snapshot["instance"] != "node"
    ):
        raise Failure("research_unknown_schema_or_instance")
    if not isinstance(snapshot["id"], str) or not re.fullmatch(r"[0-9a-f]{32}", snapshot["id"]):
        raise Failure("research_invalid_snapshot_id")
    if instant(snapshot["finished"]) < instant(snapshot["started"]):
        raise Failure("research_reversed_time")
    if snapshot["identity_stable"] not in (True, False, None) or type(
        snapshot["identity_stable"]
    ) not in (bool, type(None)):
        raise Failure("research_invalid_consistency")
    if not isinstance(snapshot["sources"], dict) or set(snapshot["sources"]) != set(SOURCES):
        raise Failure("research_invalid_sources")
    obs = snapshot["observations"]
    if not isinstance(obs, dict) or set(obs) != set(SOURCES):
        raise Failure("research_invalid_observations")
    for name in SOURCES:
        status = snapshot["sources"][name]
        if status not in ("ok", "unavailable", "invalid"):
            raise Failure("research_invalid_source_status")
        if status != "ok":
            if obs[name] is not None:
                raise Failure("research_unavailable_has_data")
            continue
        value = obs[name]
        # Reconstruct the API projection, reject additional persisted fields.
        if name == "peers":
            if not isinstance(value, list):
                raise Failure("research_invalid_entries")
            for p in value:
                if not isinstance(p, dict) or set(p) != {
                    "key",
                    "up",
                    "inbound",
                    "port",
                    "latency_ms",
                }:
                    raise Failure("research_invalid_peer_projection")
                ms = p["latency_ms"]
                if ms is not None and latency(ms) is None:
                    raise Failure("research_invalid_latency")
            expected = project(name, {name: value}, stored=True)
        else:
            expected = project(name, value if name == "self" else {name: value})
        if expected != value:
            raise Failure("research_noncanonical_projection")
    if snapshot["identity_stable"] is True and snapshot["sources"]["self"] != "ok":
        raise Failure("research_consistency_without_self")
    return snapshot


@logged
def graph(snapshot):
    validate(snapshot)
    nodes: dict[str, set[str]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    obs = snapshot["observations"]
    own = obs["self"]["key"] if obs["self"] else None
    if own:
        nodes[own] = {"self"}
    for p in obs["peers"] or []:
        if not p["key"]:
            continue
        nodes.setdefault(p["key"], set()).add("peer")
        if own:
            token = ("direct_peer", own, p["key"])
            edge = edges.setdefault(
                token,
                {
                    "kind": "direct_peer",
                    "source": own,
                    "target": p["key"],
                    "links": 0,
                    "up_links": 0,
                },
            )
            edge["links"] += 1
            edge["up_links"] += int(p["up"])
    for p in obs["tree"] or []:
        nodes.setdefault(p["key"], set()).add("tree_entry")
        nodes.setdefault(p["parent"], set()).add("parent_reference")
        if p["key"] != p["parent"]:
            token = ("tree_parent", p["key"], p["parent"])
            edges[token] = {"kind": token[0], "source": token[1], "target": token[2]}
    for p in obs["paths"] or []:
        nodes.setdefault(p["key"], set()).add("path_entry")
    return {
        "provenance": snapshot_provenance(),
        "nodes": [{"key": k, "roles": sorted(nodes[k])} for k in sorted(nodes)],
        "edges": [edges[k] for k in sorted(edges)],
        "unknown_peer_keys": sum(p["key"] is None for p in obs["peers"] or []),
        "limits": "local observations; parent references are not responders; tree edges are not transport links; path coordinates are not packet traces",
    }


@logged
def peer_link_groups(rows):
    """Aggregate projected links, without inventing identities for duplicate tuples."""
    groups: dict[str, dict[str, int]] = {}
    for row in rows:
        if row["key"] is None:
            continue
        token = row["key"] + ":" + str(row["port"]) + ":" + str(row["inbound"])
        counts = groups.setdefault(token, {"links": 0, "up_links": 0})
        counts["links"] += 1
        counts["up_links"] += int(row["up"])
    return groups


@logged
def difference(before, after):
    validate(before)
    validate(after)
    if not before["identity_stable"] or not after["identity_stable"]:
        raise Failure("research_unstable_identity_not_comparable")
    if before["observations"]["self"]["key"] != after["observations"]["self"]["key"]:
        raise Failure("research_identity_change_not_topology_change")
    if instant(after["started"]) <= instant(before["finished"]):
        raise Failure("research_snapshots_not_sequential")
    result = {
        "provenance": snapshot_provenance(),
        "before": before["id"],
        "after": after["id"],
        "sources": {},
        "limits": "observation changes only; disappearance does not prove a world node/link went offline",
    }
    for source in ("peers", "tree", "paths"):
        if before["sources"][source] != "ok" or after["sources"][source] != "ok":
            result["sources"][source] = {
                "known": False,
                "added": None,
                "removed": None,
                "changed": None,
            }
            continue
        a, b = before["observations"][source], after["observations"][source]
        # Duplicate peer tuples have no stable per-link identity. Compare their
        # multiplicity/up-count, never an order-dependent last row or a fake link ID.
        if source == "peers":
            ka, kb = peer_link_groups(a), peer_link_groups(b)
        else:
            ka = {p["key"]: p for p in a}
            kb = {p["key"]: p for p in b}
        changed = []
        for key in sorted(ka.keys() & kb.keys()):
            fields = (
                ("links", "up_links")
                if source == "peers"
                else ("parent",)
                if source == "tree"
                else ("path",)
            )
            if any(ka[key][f] != kb[key][f] for f in fields):
                changed.append(key)
        result["sources"][source] = {
            "known": True,
            "added": sorted(kb.keys() - ka.keys()),
            "removed": sorted(ka.keys() - kb.keys()),
            "changed": changed,
        }
        if source == "peers":
            result["sources"][source].update(
                unidentified_before=sum(p["key"] is None for p in a),
                unidentified_after=sum(p["key"] is None for p in b),
            )
    return result


@logged
def dot(snapshot):
    data = graph(snapshot)
    lines = [
        "digraph observed {",
        '  label="Observed local topology — not global coverage\\nUNVERIFIED role-writable history; no authenticity/immutability guarantee or API truth attestation";',
    ]
    for n in data["nodes"]:
        shape = (
            "doublecircle"
            if "self" in n["roles"]
            else "box"
            if n["roles"] == ["parent_reference"]
            else "ellipse"
        )
        lines.append(f'  "{n["key"]}" [label="{n["key"][:12]}",shape={shape}];')
    for e in data["edges"]:
        attributes = (
            f'dir=none,label="peer {e["up_links"]}/{e["links"]} up"'
            if e["kind"] == "direct_peer"
            else 'style=dashed,label="observed parent"'
        )
        lines.append(f'  "{e["source"]}" -> "{e["target"]}" [{attributes}];')
    return "\n".join(lines + ["}", ""])
