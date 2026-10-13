"""Allowlisted backups; no plaintext key archive or unrestricted extraction."""
import io
import json
import re
import tarfile
import uuid
from pathlib import Path

from core import (Failure, NODE, STACK, TIMER, FILES, KEYS, logged, read_regular,
                  atomic, digest, timestamp, safe_config, event)
from checks import integrity
from management import transaction, restart_pair


@logged
def members(ctx, full=False):
    result = {"config/" + name: read_regular(ctx.p.etc / name) for name in FILES}
    result.update({"units/" + name: read_regular(ctx.p.units / name) for name in (NODE, STACK, TIMER, "ygg-metrics.service")})
    for name in ("yggdrasil-lab.conf", "yggstack.conf"):
        if safe_config(ctx.config(name)): raise Failure("unsafe_config_backup_refused")
    if full: result.update({"keys/" + name: read_regular(ctx.p.etc / name, 4096) for name in KEYS})
    return result


@logged
def archive(files, full=False):
    manifest = {"schema": 1, "at": timestamp(), "keys": full,
                "sha256": {k: digest(v) for k, v in files.items()}}
    files = dict(files, **{"manifest.json": json.dumps(manifest).encode()})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(data), 0o600, 0, 0
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@logged
def backup(ctx, full=False, recipient=None):
    ctx.root()
    if full and not (recipient and re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", recipient)):
        raise Failure("full_backup_requires_explicit_GPG_recipient_fingerprint")
    if recipient and not full: raise Failure("recipient_requires_full")
    with ctx.locked():
        integrity(ctx)
        data = archive(members(ctx, full), full)
        if full:
            # User-provided complete fingerprint; never choose a package/vendor key.
            key = ctx.run(["/usr/bin/gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys", recipient]).stdout.decode()
            if not any(line.startswith("fpr:") and line.split(":")[9].lower() == recipient.lower() for line in key.splitlines()):
                raise Failure("recipient_fingerprint_not_found")
            data = ctx.run(["/usr/bin/gpg", "--batch", "--yes", "--trust-model", "always", "--encrypt", "--recipient", recipient], input=data, timeout=30).stdout
        folder = ctx.p.state / "backups"
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.is_symlink() or folder.stat().st_mode & 0o077: raise Failure("backup_directory_not_private")
        out = folder / ("ygg-" + uuid.uuid4().hex + (".tar.gz.gpg" if full else ".tar.gz"))
        atomic(out, data)
        atomic(Path(str(out) + ".sha256"), digest(data) + "\n")
        event("state", "backup", "encrypted_full" if full else "key_free")
        print(f"[1/1] backup={out} keys={'encrypted' if full else 'EXCLUDED'} processed=1 errors=0 remaining=0")
        return out


@logged
def inspect_archive(data):
    if len(data) > 4 * 1024 * 1024: raise Failure("backup_size_limit")
    allowed = {"config/" + n for n in FILES} | {"units/" + n for n in (NODE, STACK, TIMER, "ygg-metrics.service")} | {"keys/" + n for n in KEYS} | {"manifest.json"}
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for info in tar:
                if info.name not in allowed or info.name in files or not info.isfile() or info.size > 1048576:
                    raise Failure("unsafe_archive_member")
                source = tar.extractfile(info)
                if source is None: raise Failure("unreadable_archive_member")
                files[info.name] = source.read(1048577)
        manifest = json.loads(files.pop("manifest.json"))
        if manifest.get("schema") != 1 or set(manifest["sha256"]) != set(files): raise Failure("backup_manifest_mismatch")
        if any(digest(value) != manifest["sha256"][name] for name, value in files.items()): raise Failure("backup_member_hash_mismatch")
        base = allowed - {"manifest.json"} - {"keys/" + n for n in KEYS}
        if not base <= set(files): raise Failure("backup_members_missing")
        actual_keys = {k for k in files if k.startswith("keys/")}
        if actual_keys != ({"keys/" + n for n in KEYS} if manifest.get("keys") is True else set()):
            raise Failure("backup_key_flag_mismatch")
    except (tarfile.TarError, KeyError, ValueError, OSError):
        raise Failure("invalid_backup_archive") from None
    return files, bool(manifest.get("keys"))


@logged
def restore(ctx, path, apply=False):
    ctx.root()
    with ctx.locked():
        # Caller-selected archive is data only. No extraction, links, arbitrary paths or code execution.
        path = Path(path)
        data = read_regular(path, 4 * 1024 * 1024)
        expected = read_regular(Path(str(path) + ".sha256"), 128).decode().strip()
        if expected != digest(data): raise Failure("archive_digest_mismatch")
        if path.name.endswith(".gpg"):
            data = ctx.run(["/usr/bin/gpg", "--batch", "--decrypt"], input=data, timeout=30).stdout
        files, has_keys = inspect_archive(data)
        if has_keys: raise Failure("encrypted_custody_verified_key_restore_requires_separate_review")
        updates = {ctx.p.etc / n: files["config/" + n] for n in FILES}
        if updates[ctx.p.etc / "mode"].strip() != read_regular(ctx.p.etc / "mode").strip():
            raise Failure("restore_underlay_change_requires_separate_review")
        for n in (NODE, STACK, TIMER, "ygg-metrics.service"):
            if files["units/" + n] != read_regular(ctx.p.units / n): raise Failure("restore_unit_change_requires_separate_review")
        configs = []
        for name in ("yggdrasil-lab.conf", "yggstack.conf"):
            decoded = json.loads(ctx.run([ctx.p.decoder], input=updates[ctx.p.etc / name]).stdout)
            current = ctx.config(name)
            if safe_config(decoded) or any(decoded.get(k) != current.get(k) for k in ("AdminListen", "PrivateKeyPath")):
                raise Failure("restore_unsafe_config")
            configs.append(decoded)
        # Do not trust backup gate executable syntax: regenerate only the peer IP set.
        from management import gate_bytes
        updates[ctx.p.etc / "gate.nft"] = gate_bytes(configs, "ygglab")
        updates[ctx.p.etc / "gate-yggstack.nft"] = gate_bytes(configs, "yggstack-gate")
        print("VERIFIED key-free archive; live keys, units, mode and accepted firewall policy preserved")
        if apply: transaction(ctx, updates, lambda: restart_pair(ctx), lambda: restart_pair(ctx))
        else: print("PREVIEW only; --apply restarts both services after config restoration")


@logged
def snapshot(ctx):
    ctx.root()
    with ctx.locked():
        hashes = {name: digest(value) for name, value in members(ctx).items()}
        path = ctx.p.state / ("snapshot-" + uuid.uuid4().hex + ".json")
        atomic(path, json.dumps({"at": timestamp(), "sha256": hashes}))
        print(f"snapshot={path}; secret-free")
        return path


@logged
def diff(ctx, path=None):
    ctx.root()
    with ctx.locked():
        choices = sorted(ctx.p.state.glob("snapshot-*.json"), key=lambda p: p.stat().st_mtime_ns)
        if path is None and not choices: raise Failure("no_snapshot")
        saved = json.loads(read_regular(Path(path) if path else choices[-1]))["sha256"]
        current = {name: digest(value) for name, value in members(ctx).items()}
        changed = sorted(k for k in set(saved) | set(current) if saved.get(k) != current.get(k))
        print(json.dumps({"changed": changed, "unchanged": not changed}))
        if changed: raise Failure("snapshot_diff_detected")
