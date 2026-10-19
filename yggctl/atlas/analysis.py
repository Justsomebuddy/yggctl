"""Provenance graph, query coverage, distributions and honest inter-run changes."""

from typing import Any

import json
import math
import re
import time
import uuid

from core import Failure, logged, timestamp, atomic
from research import model, metrics
from . import acquisition


@logged
def components(keys, edges):
    parent = {k: k for k in keys}
    for edge in edges:
        if edge["kind"] == "local_tree_parent":
            continue
        a, b = edge["source"], edge["target"]
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        while parent[b] != b:
            parent[b] = parent[parent[b]]
            b = parent[b]
        if a != b:
            parent[b] = a
    sizes: dict[str, int] = {}
    for key in parent:
        # Final traversal needs compression too: union order can leave a long chain.
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        sizes[key] = sizes.get(key, 0) + 1
    return sorted(sizes.values(), reverse=True)


@logged
def build(store, run=None):
    run = run or store.meta("current")
    if run:
        rows = store.sql("SELECT seed FROM runs WHERE id=?", (run,))
        if not rows:
            raise Failure("atlas_missing_run")
        seed = json.loads(rows[0][0])
        model.validate(seed["local"])
        catalogue = seed["catalogue"]
        meta = seed["catalogue_meta"]
        progress = acquisition.status(store, run)
    else:
        seed = None
        catalogue = [
            json.loads(row[0]) for row in store.sql("SELECT payload FROM catalogue ORDER BY id")
        ]
        meta = store.meta("catalogue")
        progress = {"run": None, "world_coverage": None}
    nodes: dict[str, dict[str, Any]] = {}
    relations: dict[tuple[str, str, str], dict[str, Any]] = {}
    method_rows, responders = {}, set()
    if run:
        for key, origin in store.sql("SELECT key,origin FROM targets WHERE run=?", (run,)):
            nodes[model.public_key(key)] = {"roles": {origin}, "methods": {}}
        own = seed["local"]["observations"]["self"]["key"]
        nodes[own] = {"roles": {"local_self"}, "methods": {}}
        for edge in model.graph(seed["local"])["edges"]:
            kind = "local_direct_peer" if edge["kind"] == "direct_peer" else "local_tree_parent"
            token = (kind, edge["source"], edge["target"])
            relations[token] = dict(
                edge, kind=kind, reporters=[own], semantics="local admin observation, not atomic"
            )
        for key, method, ts, status, elapsed, raw in store.sql(
            "SELECT key,method,ts,status,elapsed_ms,payload FROM responses WHERE run=?", (run,)
        ):
            key = model.public_key(key)
            model.instant(ts)
            if method not in acquisition.protocol.METHODS or status not in (
                "ok",
                "unknown",
                "inflight",
                "interrupted_unknown",
            ):
                raise Failure("atlas_invalid_response_status")
            if elapsed is not None and (
                type(elapsed) not in (int, float)
                or not math.isfinite(elapsed)
                or not 0 <= elapsed <= 86400000
            ):
                raise Failure("atlas_invalid_response_elapsed")
            nodes[key]["methods"][method] = {
                "status": status,
                "observed": ts,
                "api_elapsed_ms": elapsed,
            }
            data = acquisition.payload(raw, key, method) if status == "ok" else None
            method_rows[(key, method)] = (status, data)
            if not data:
                continue
            responders.add(key)
            nodes[key]["roles"].add("validated_payload_respondent")
            if method == "self":
                nodes[key]["routing_entries"] = data["routing_entries"]
            else:
                for other in data["keys"]:
                    nodes.setdefault(other, {"roles": set(), "methods": {}})["roles"].add(
                        "remote_" + method + "_reference"
                    )
                    if method != "peers" or other == key:
                        continue
                    source, target = sorted((key, other))
                    token = ("reported_peer", source, target)
                    edge = relations.setdefault(
                        token,
                        {
                            "kind": "reported_peer",
                            "source": source,
                            "target": target,
                            "reporters": [],
                            "semantics": "remote claim; NO up/latency/completeness proof",
                        },
                    )
                    if key not in edge["reporters"]:
                        edge["reporters"].append(key)
    geography: dict[str, set[str]] = {}
    transports: dict[str, int] = {}
    countries: dict[str, dict[str, Any]] = {}
    unknown_pin_endpoints = 0
    for record in catalogue:
        for pin in record["pins"]:
            nodes.setdefault(model.public_key(pin), {"roles": set(), "methods": {}})["roles"].add(
                "catalogue_pin_claim"
            )
        transports[record["transport"]] = transports.get(record["transport"], 0) + 1
        if not record["pins"]:
            unknown_pin_endpoints += 1
        for country in record["countries"]:
            item = countries.setdefault(
                country,
                {
                    "endpoints": 0,
                    "pin_keys": set(),
                    "registry_online": 0,
                    "registry_offline": 0,
                    "registry_unknown": 0,
                },
            )
            item["endpoints"] += 1
            item["pin_keys"].update(record["pins"])
            field = (
                "registry_online"
                if record["registry_online"] is True
                else "registry_offline"
                if record["registry_online"] is False
                else "registry_unknown"
            )
            item[field] += 1
            for pin in record["pins"]:
                geography.setdefault(pin, set()).add(country)
    countries = {c: dict(v, pin_keys=len(v["pin_keys"])) for c, v in sorted(countries.items())}
    edges = [relations[k] for k in sorted(relations)]
    adjacency: dict[str, set[str]] = {key: set() for key in nodes}
    for edge in edges:
        if edge["kind"] == "local_tree_parent":
            continue
        adjacency[edge["source"]].add(edge["target"])
        adjacency[edge["target"]].add(edge["source"])
    node_rows = []
    for key in sorted(nodes):
        node_rows.append(
            dict(
                nodes[key],
                key=key,
                roles=sorted(nodes[key]["roles"]),
                observed_peer_degree=len(adjacency[key]),
                country_claims=sorted(geography.get(key, set())),
                asn=None,
            )
        )
    timing = {}
    for method in acquisition.protocol.METHODS:
        rows = [n["methods"][method] for n in node_rows if method in n["methods"]]
        ok = [r for r in rows if r["status"] == "ok"]
        timing[method] = {
            "attempt_records": len(rows),
            "valid_payloads": len(ok),
            "unknown_or_interrupted": len(rows) - len(ok),
            "query_success_fraction": len(ok) / len(rows) if rows else None,
            "successful_api_elapsed_ms": metrics.quantiles(
                [r["api_elapsed_ms"] for r in ok if r["api_elapsed_ms"] is not None]
            ),
            "semantics": "mesh + local admin/client + responder processing, NOT transport RTT/uptime",
        }
    return {
        "schema": 1,
        "generated": timestamp(),
        "run": progress,
        "catalogue_meta": meta,
        "catalogue": catalogue,
        "nodes": node_rows,
        "edges": edges,
        "countries": countries,
        "transports": transports,
        "timing": timing,
        "observed_peer_component_sizes": components(nodes, edges),
        "respondent_keys": len(responders),
        "endpoints_without_public_pin": unknown_pin_endpoints,
        "world_nodes": None,
        "world_coverage": None,
        "throughput_bps": None,
        "limits": [
            "all catalogue endpoint records; endpoints are NOT unique nodes",
            "queue exhaustion is not complete world or neighbour coverage; inaccessible/unadvertised keys remain unknown",
            "remote peer/tree lists may silently truncate at MTU; remote tree keys do NOT disclose parents",
            "remote peers are self-reported claims without Up/latency; mutual reports are not simultaneous live-link proof",
            "one local vantage; sequential non-atomic acquisition with per-target own-key check, not boot-epoch proof",
            "geography is catalogue country claim for public pins, not owner/node position; ASN is unknown",
            "catalogue region labels may be non-geographic network names (e.g. lokinet); unplaced labels are NOT inferred countries",
            "registry status/7d uptime is third-party dated claim, NOT our measurement",
            "query success ratio and API elapsed time are not node uptime or transport RTT",
            "world node count, unobserved connectivity and network capacity remain unknown",
        ],
    }


@logged
def changes(store, run):
    values = store.sql("SELECT id,own FROM runs ORDER BY rowid")
    position = next((i for i, r in enumerate(values) if r[0] == run), None)
    if position is None or position == 0:
        return {"comparable": False, "reason": "need_previous_run"}
    previous, own = values[position - 1]
    if own != values[position][1]:
        return {"comparable": False, "reason": "local_identity_changed"}
    a = {
        (k, m): (s, p)
        for k, m, s, p in store.sql(
            "SELECT key,method,status,payload FROM responses WHERE run=?", (previous,)
        )
    }
    b = {
        (k, m): (s, p)
        for k, m, s, p in store.sql(
            "SELECT key,method,status,payload FROM responses WHERE run=?", (run,)
        )
    }
    comparable, changed, unknown = 0, [], 0
    for key, method in sorted(a.keys() | b.keys()):
        if (
            (key, method) not in a
            or (key, method) not in b
            or a[(key, method)][0] != "ok"
            or b[(key, method)][0] != "ok"
        ):
            unknown += 1
            continue
        if method == "self":
            continue  # Routing table size is not topology.
        left = set(acquisition.payload(a[(key, method)][1], key, method)["keys"])
        right = set(acquisition.payload(b[(key, method)][1], key, method)["keys"])
        comparable += 1
        if left != right:
            changed.append(
                {
                    "reporter": key,
                    "method": method,
                    "added": sorted(right - left),
                    "removed": sorted(left - right),
                }
            )
    return {
        "comparable": True,
        "before": previous,
        "after": run,
        "comparable_reporter_methods": comparable,
        "unknown_or_unpaired_reporter_methods": unknown,
        "changes": changed,
        "limits": "reported-key-list changes only; removed references are NOT confirmed outages; MTU truncation unknown",
    }


@logged
def dot(data):
    lines = [
        "graph atlas {",
        'label="Observed atlas: local + reported links; world completeness UNKNOWN";',
    ]
    for node in data["nodes"]:
        model.public_key(node["key"])
        lines.append(f'"{node["key"]}" [label="{node["key"][:10]}"];')
    for edge in data["edges"]:
        style = "dashed" if edge["kind"] == "local_tree_parent" else "solid"
        lines.append(
            f'"{edge["source"]}" -- "{edge["target"]}" [style={style},label="{edge["kind"]}"];'
        )
    return "\n".join(lines + ["}"]) + "\n"


@logged
def markdown(data):
    run = data["run"]
    total = run.get("discovered_remote_keys")
    processed = run.get("processed_keys")
    lines = [
        "# Yggdrasil observed world atlas",
        "",
        f"Generated: {data['generated']}",
        "World count/coverage/capacity: UNKNOWN.",
        f"Observed identities (includes claims/references): {len(data['nodes'])}; valid-payload respondents: {data['respondent_keys']}",
        f"Discovered frontier processed: {processed}/{total}; state: {run.get('state')}",
        f"Advertised endpoint records: {len(data['catalogue'])}; without public pin: {data['endpoints_without_public_pin']}",
        "",
        "## Provenance / limitations",
    ] + ["- " + s for s in data["limits"]]
    lines += [
        "",
        "## Acquisition / distributions",
        "| Method | Valid payloads / records | Unknown/interrupted | API elapsed p50/p95 ms |",
        "|---|---|---|---|",
    ]
    for method, counts in data["timing"].items():
        q = counts["successful_api_elapsed_ms"]
        lines.append(
            f"| {method} | {counts['valid_payloads']}/{counts['attempt_records']} | {counts['unknown_or_interrupted']} | {q['p50']}/{q['p95']} |"
        )
    lines += [
        "",
        "## Claimed public-endpoint geography",
        "| Country claim | Endpoint records | Pinned identities | Registry online/offline/unknown |",
        "|---|---|---|---|",
    ]
    for country, c in data["countries"].items():
        lines.append(
            f"| {country} | {c['endpoints']} | {c['pin_keys']} | {c['registry_online']}/{c['registry_offline']}/{c['registry_unknown']} |"
        )
    lines += [
        "",
        "## Topology changes",
        json.dumps(data.get("changes"), sort_keys=True),
        "",
        "Artifact JSON/DOT contains full observed data. Viewer layout limits do not limit acquisition.",
    ]
    return "\n".join(lines) + "\n"


@logged
def report(ctx, store):
    from .viewer import html

    start = time.monotonic()
    count = 0
    for i, path in enumerate(store.root.iterdir()):
        if i >= 512:
            raise Failure("atlas_export_directory_guard")
        if path.name in ("atlas.sqlite", "atlas.sqlite-wal", "atlas.sqlite-shm", ".writer.lock"):
            continue
        if (
            not re.fullmatch(r"atlas-[0-9a-f]{32}\.(json|md|dot|html)", path.name)
            or path.is_symlink()
            or not path.is_file()
        ):
            raise Failure("atlas_unsafe_export_entry")
        count += 1
    if count + 4 > 256:
        raise Failure("atlas_export_retention_review_required")
    print("[1/3] consistent atlas read; processed=0/3 remaining=3", flush=True)
    data = build(store)
    data["changes"] = (
        changes(store, data["run"]["run"])
        if data["run"]["run"]
        else {"comparable": False, "reason": "no_run"}
    )
    elapsed = time.monotonic() - start
    print(
        f"[2/3] full graph/claims/viewer; processed=1/3 remaining=2 elapsed={elapsed:.2f}s speed={1 / max(elapsed, 0.001):.2f}stages/s ETA=bounded-local-export",
        flush=True,
    )
    name = "atlas-" + uuid.uuid4().hex
    payload = json.dumps(data, sort_keys=True, allow_nan=False)
    if len(payload.encode()) > 64 * 1024 * 1024:
        raise Failure("atlas_export_guard_report_not_saved")
    files = {}
    for extension, value in (
        ("json", payload + "\n"),
        ("md", markdown(data)),
        ("dot", dot(data)),
        ("html", html(data)),
    ):
        path = store.root / (name + "." + extension)
        atomic(path, value)
        files[extension] = str(path)
    elapsed = time.monotonic() - start
    print(
        f"[3/3] processed=4/4 remaining=0 errors=0 elapsed={elapsed:.2f}s speed={4 / max(elapsed, 0.001):.2f}files/s",
        flush=True,
    )
    return dict(
        files,
        observed_identities=len(data["nodes"]),
        respondent_keys=data["respondent_keys"],
        world_coverage=None,
    )
