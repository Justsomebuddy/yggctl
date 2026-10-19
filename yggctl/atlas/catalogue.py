"""Whole fixed-source catalogue, parsed in RAM; never peer or resolve endpoints."""

from typing import Any

import hashlib
from html.parser import HTMLParser
import io
import ipaddress
import json
import re
import time
import urllib.parse
import zipfile

from core import Failure, logged, timestamp, event
from research.model import public_key

REPO = "https://github.com/yggdrasil-network/public-peers"
MONITOR = "https://publicpeers.neilalexander.dev/"
API = "https://api.github.com/repos/yggdrasil-network/public-peers/git/ref/heads/master"


@logged
def country(value):
    value = value.strip().lower().replace(" ", "-")
    if not re.fullmatch(r"[a-z][a-z-]{0,63}", value):
        raise Failure("atlas_invalid_country_claim")
    return value


@logged
def endpoint(uri):
    if not isinstance(uri, str) or not 1 <= len(uri) <= 2048 or any(ord(c) < 32 for c in uri):
        raise Failure("atlas_invalid_catalogue_endpoint")
    try:
        parts = urllib.parse.urlsplit(uri)
        if (
            parts.scheme not in ("tcp", "tls", "quic", "ws", "wss")
            or not parts.hostname
            or parts.port is None
        ):
            raise ValueError()
        host = parts.hostname.lower()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = host.encode("idna").decode("ascii")
            labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
            if len(host.rstrip(".")) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            ):
                raise ValueError() from None
        if not 1 <= parts.port <= 65535:
            raise ValueError()
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True, max_num_fields=64)
        keys = sorted({public_key(k) for k in query.get("key", [])})
    except (ValueError, UnicodeError, Failure):
        raise Failure("atlas_invalid_catalogue_endpoint") from None
    display = f"{parts.scheme}://{'[' + host + ']' if ':' in host else host}:{parts.port}"
    # No credentials, paths, arbitrary query strings or source prose persisted.
    return {
        "id": hashlib.sha256(uri.encode()).hexdigest(),
        "endpoint": display,
        "transport": parts.scheme,
        "pins": keys,
        "path_omitted": bool(parts.path),
        "authentication_omitted": bool(parts.username or "password" in query),
    }


class MonitorParser(HTMLParser):
    @logged
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.field = None
        self.buffer = []
        self.row = {}
        self.region = None
        self.rows = []
        self.invalid = 0
        self.updated = None

    @logged
    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = {}
        if tag in ("td", "th"):
            self.field = dict(attrs).get("id")
            self.buffer = []

    @logged
    def handle_data(self, data):
        if self.field:
            self.buffer.append(data)
        if re.fullmatch(r"\d{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2} UTC", data.strip()):
            self.updated = data.strip()

    @logged
    def handle_endtag(self, tag):
        if tag in ("td", "th"):
            text = "".join(self.buffer).strip()
            if self.field == "country":
                try:
                    self.region = country(text)
                except Failure:
                    self.region = None
            elif self.field:
                self.row[self.field] = text
            self.field = None
            self.buffer = []
        if tag == "tr" and "address" in self.row:
            if len(self.rows) >= 10000:
                raise Failure("atlas_monitor_record_limit")
            try:
                record = endpoint(self.row["address"])
                if self.region is None:
                    raise Failure("atlas_monitor_missing_country")
            except Failure:
                self.invalid += 1
                return
            status = self.row.get("status", "")
            uptime = self.row.get("reliability", "")
            pct = float(uptime[:-1]) if re.fullmatch(r"\d{1,3}(?:\.\d{1,2})?%", uptime) else None
            record.update(
                countries=[self.region],
                sources=["monitor"],
                registry_online=True
                if status.startswith("online ")
                else False
                if status.startswith("offline ")
                else None,
                registry_uptime7d_pct=pct if pct is not None and 0 <= pct <= 100 else None,
            )
            self.rows.append(record)


@logged
def repository_rows(payload, commit):
    records: list[dict[str, Any]] = []
    invalid, total = 0, 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            if len(archive.infolist()) > 1024:
                raise Failure("atlas_catalogue_archive_limit")
            for item in archive.infolist():
                parts = item.filename.split("/")
                if (
                    len(parts) != 3
                    or parts[0] != "public-peers-" + commit
                    or not parts[-1].endswith(".md")
                ):
                    continue
                if not re.fullmatch(r"[a-z-]+/[a-z-]+\.md", "/".join(parts[1:])):
                    continue
                total += item.file_size
                if item.file_size > 1024 * 1024 or total > 8 * 1024 * 1024:
                    raise Failure("atlas_catalogue_decompression_limit")
                region = country(parts[-1][:-3])
                body = archive.read(item).decode("utf-8")
                for uri in re.findall(r"`((?:tcp|tls|quic|ws|wss)://[^`\s]+)`", body):
                    if len(records) >= 10000:
                        raise Failure("atlas_catalogue_record_limit")
                    try:
                        record = endpoint(uri)
                    except Failure:
                        invalid += 1
                        continue
                    record.update(
                        countries=[region],
                        sources=["repository:" + "/".join(parts[1:])],
                        registry_online=None,
                        registry_uptime7d_pct=None,
                    )
                    records.append(record)
    except (zipfile.BadZipFile, UnicodeError, RuntimeError, OSError):
        raise Failure("atlas_invalid_catalogue_archive") from None
    if not records:
        raise Failure("atlas_empty_catalogue_archive")
    return records, invalid


@logged
def fetch(ctx, url):
    # Caller constructs URLs exclusively from fixed sources and a validated SHA.
    allowed = url in (API, MONITOR) or re.fullmatch(
        r"https://codeload\.github\.com/yggdrasil-network/public-peers/zip/[0-9a-f]{40}", url
    )
    if not allowed:
        raise Failure("atlas_nonfixed_source_rejected")
    result = ctx.run(
        [
            "/usr/bin/curl",
            "-q",
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--max-time",
            "25",
            "--max-filesize",
            "2097152",
            "--user-agent",
            "yggctl-atlas/1.0",
            url,
        ],
        timeout=27,
    )
    if len(result.stdout) > 2 * 1024 * 1024:
        raise Failure("atlas_catalogue_source_size_limit")
    return result.stdout


@logged
def acquire(ctx, store):
    started = time.monotonic()
    print("[1/3] fixed repository ref; processed=0/3 remaining=3", flush=True)
    try:
        commit = json.loads(fetch(ctx, API))["object"]["sha"]
    except (ValueError, KeyError, TypeError):
        raise Failure("atlas_invalid_repository_ref") from None
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Failure("atlas_invalid_repository_commit")
    elapsed = time.monotonic() - started
    print(
        f"[2/3] entire pinned public catalogue; processed=1/3 remaining=2 elapsed={elapsed:.2f}s speed={1 / max(elapsed, 0.001):.2f}sources/s ETA<=54s",
        flush=True,
    )
    zipped = fetch(ctx, "https://codeload.github.com/yggdrasil-network/public-peers/zip/" + commit)
    records, invalid = repository_rows(zipped, commit)
    elapsed = time.monotonic() - started
    print(
        f"[3/3] registry claims; processed=2/3 remaining=1 elapsed={elapsed:.2f}s speed={2 / max(elapsed, 0.001):.2f}sources/s ETA<=27s",
        flush=True,
    )
    monitor_status, monitor_hash, updated = "unknown", None, None
    try:
        body = fetch(ctx, MONITOR)
        parser = MonitorParser()
        parser.feed(body.decode("utf-8"))
        parser.close()
        if not parser.rows:
            raise Failure("atlas_empty_monitor")
        records += parser.rows
        invalid += parser.invalid
        monitor_status, monitor_hash, updated = (
            "ok",
            hashlib.sha256(body).hexdigest(),
            parser.updated,
        )
    except (Failure, ValueError, UnicodeError):
        pass
    merged: dict[str, dict[str, Any]] = {}
    for record in records:
        previous = merged.get(record["id"])
        if previous:
            record["countries"] = sorted(set(previous["countries"] + record["countries"]))
            record["sources"] = sorted(set(previous["sources"] + record["sources"]))
        merged[record["id"]] = record
    meta = {
        "captured": timestamp(),
        "commit": commit,
        "repository": REPO,
        "monitor": MONITOR,
        "repository_zip_sha256": hashlib.sha256(zipped).hexdigest(),
        "monitor_sha256": monitor_hash,
        "monitor_updated_claim": updated,
        "monitor_status": monitor_status,
        "invalid_entries": invalid,
        "endpoints": len(merged),
        "node_count": None,
        "country_semantics": "catalogue claim, not node/owner geolocation",
        "asn": None,
    }
    # Dataset and its provenance are one checkpoint, including on process death.
    store.batch(
        [("DELETE FROM catalogue", ())]
        + [
            ("INSERT INTO catalogue VALUES(?,?)", (key, json.dumps(value, allow_nan=False)))
            for key, value in sorted(merged.items())
        ]
        + [
            (
                "INSERT OR REPLACE INTO meta VALUES(?,?)",
                ("catalogue", json.dumps(meta, allow_nan=False)),
            )
        ]
    )
    event("state", "atlas_catalogue", "projected_all_catalogue_records")
    elapsed = time.monotonic() - started
    print(
        f"processed=3/3 remaining=0 errors={int(monitor_status != 'ok')} elapsed={elapsed:.2f}s speed={3 / max(elapsed, 0.001):.2f}sources/s endpoint_records={len(merged)}",
        flush=True,
    )
    return meta
