"""Native local-item handoff, never rendered CLI output, delivery or human ACK.

Only ordinary SQLite chat profiles are supported. Operator-owned private config
and the SAME lock used by every other writer of this profile are prerequisites.
A durable intent precedes every launch. An ambiguous attempt is NOT retried
automatically: absence of a native row cannot prove no network acceptance.
Receipts prove historical local recording, not delivery or a human ACK.
"""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import time

from core import Context, Failure, atomic, event, logged, read_regular

# Arm after changing identity, then compare the ORIGINAL parent PID to close
# the death-before-prctl race. exec preserves it for a non-setid native binary.
CHILD_GUARD = (
    "import ctypes,os,sys;"
    "lib=ctypes.CDLL(None,use_errno=True);"
    "rc=lib.prctl(1,9,0,0,0);"
    "ok=rc==0 and os.getppid()==int(sys.argv[1]);"
    "sys.exit(71) if not ok else os.execv(sys.argv[2],sys.argv[2:])"
)


@logged
def configuration(ctx):
    path = ctx.p.etc / "simplex-sender.json"
    info = path.lstat()
    if info.st_uid != (0 if ctx.require_root else os.geteuid()) or info.st_mode & 0o077:
        raise Failure("simplex_config_not_private")
    value = json.loads(read_regular(path, 16384))
    keys = {"database", "contact", "binary", "user", "lock"}
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or any(not isinstance(v, str) or not 1 <= len(v) <= 4096 for v in value.values())
    ):
        raise Failure("simplex_config_schema")
    if (
        not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value["user"])
        or len(value["contact"]) > 128
        or not value["database"].endswith("_chat.db")
        or any(not Path(value[k]).is_absolute() for k in ("database", "binary", "lock"))
    ):
        raise Failure("simplex_config_values")
    target = pwd.getpwnam(value["user"])
    database = Path(value["database"]).lstat()
    if database.st_uid != target.pw_uid or database.st_mode & 0o077:
        raise Failure("simplex_database_not_private")
    for key in ("database", "binary"):
        candidate = Path(value[key])
        if candidate.is_symlink() or not candidate.is_file():
            raise Failure("simplex_config_path")
    executable = Path(value["binary"]).stat()
    if (
        executable.st_uid != (0 if ctx.require_root else os.geteuid())
        or executable.st_mode & 0o6022
        or not executable.st_mode & 0o111
    ):
        raise Failure("simplex_binary_not_trusted")
    return value


@logged
def lookup(cfg, marker, text, deadline):
    """One consistent native snapshot, no write access and no plaintext output."""
    event("external_start", "simplex_native_query")
    with contextlib.closing(
        sqlite3.connect(Path(cfg["database"]).resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
    ) as db:
        db.execute("PRAGMA query_only=ON")

        @logged
        def expired():
            return int(time.monotonic() >= deadline)

        db.set_progress_handler(expired, 10000)
        db.execute("BEGIN")
        contacts = db.execute(
            """
            SELECT c.contact_id,c.user_id FROM contacts c JOIN users u ON u.user_id=c.user_id
            WHERE u.active_user=1 AND c.local_display_name=? AND c.is_user=0 AND c.deleted=0
            LIMIT 2
        """,
            (cfg["contact"],),
        ).fetchall()
        if len(contacts) != 1:
            raise Failure("simplex_contact_absent_or_ambiguous")
        contact, user = contacts[0]
        found = db.execute(
            """
            SELECT chat_item_id,item_text,item_content,item_content_tag,msg_content_tag,
                   item_deleted,COALESCE(item_edited,0),fwd_from_tag,group_id
            FROM chat_items WHERE contact_id=? AND user_id=? AND item_sent=1
            AND substr(item_text,1,?)=? ORDER BY chat_item_id DESC LIMIT 2
        """,
            (contact, user, len(marker), marker),
        ).fetchall()
        if len(found) > 1:
            raise Failure("simplex_existing_item_conflict")
        for item in found:
            item_id, body, content, kind, tag, deleted, edited, forwarded, group = item
            value = json.loads(content)
            if not isinstance(value, dict) or not isinstance(value.get("sndMsgContent"), dict):
                raise Failure("simplex_existing_item_conflict")
            message = value.get("sndMsgContent", {}).get("msgContent", {})
            if (
                type(item_id) is not int
                or item_id <= 0
                or body != text
                or kind != "sndMsgContent"
                or tag != "text"
                or deleted != 0
                or edited != 0
                or forwarded is not None
                or group is not None
                or message != {"type": "text", "text": text}
            ):
                raise Failure("simplex_existing_item_conflict")
        event("external_exit", "simplex_native_query", "recorded" if found else "absent")
        identity = Path(cfg["database"]).stat()
        binding = hashlib.sha256(
            json.dumps(
                [cfg, identity.st_dev, identity.st_ino, contact, user], sort_keys=True
            ).encode()
        ).hexdigest()
        return binding, int(contact), (int(found[0][0]) if found else None)


@contextlib.contextmanager
def profile_lock(path, deadline):
    event("entry", "simplex_profile_lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        # The deployed shared lock is root:root 0660. Root-group write is
        # trusted; an arbitrary writable group or any world write is not.
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o002
            or info.st_mode & 0o020
            and info.st_gid != 0
        ):
            raise Failure("simplex_lock_not_trusted")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # A nonblocking retry loop can starve behind continuously queued
            # shared senders. Wait in the kernel queue with a finite timeout.
            # flock acts on the inherited SAME open-file description, so its
            # successful lock remains held by our fd after the helper exits.
            wait = max(0.01, deadline - time.monotonic())
            event("external_start", "simplex_lock_wait")
            result = Context(require_root=False).run(
                ["/usr/bin/flock", "--exclusive", "--timeout", str(wait), str(fd)],
                timeout=wait + 0.5,
                check=False,
                pass_fds=(fd,),
            )
            event("external_exit", "simplex_lock_wait", "completed")
            if result.returncode:
                raise Failure("simplex_lock_timeout")
        event("state", "simplex_profile_lock", "acquired")
        yield fd
    except BaseException as exc:
        event("error", "simplex_profile_lock", type(exc).__name__)
        raise
    finally:
        os.close(fd)
        event("exit", "simplex_profile_lock", "released")


@logged
def load_journal(ctx):
    raw = ctx.read_state("simplex-attempts.json", 1 << 20)
    if raw is None:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict) or len(value) > 2000:
        raise Failure("simplex_journal_invalid")
    for key, row in value.items():
        if (
            not re.fullmatch(r"[0-9a-f]{64}", key)
            or not isinstance(row, dict)
            or set(row) != {"body", "binding", "status", "item_id"}
            or any(
                not isinstance(row[k], str) or not re.fullmatch(r"[0-9a-f]{64}", row[k])
                for k in ("body", "binding")
            )
            or row["status"] not in ("attempted", "native-recorded")
            or (row["status"] == "attempted" and row["item_id"] is not None)
            or (
                row["status"] == "native-recorded"
                and (type(row["item_id"]) is not int or row["item_id"] <= 0)
            )
        ):
            raise Failure("simplex_journal_invalid")
    return value


@logged
def save_journal(ctx, journal):
    event("state", "simplex_handoff", "durable_journal_commit")
    atomic(ctx.p.state / "simplex-attempts.json", json.dumps(journal) + "\n", 0o600)


@logged
def handoff(ctx, event_id, payload, timeout=20):
    ctx.root()
    if (
        not isinstance(payload, dict)
        or payload.get("source") != "yggctl"
        or not isinstance(event_id, str)
        or not 1 <= len(event_id) <= 128
        or any(not isinstance(payload.get(k), str) for k in ("rule", "output", "priority", "time"))
    ):
        raise Failure("simplex_event_schema")
    cfg = configuration(ctx)
    marker = "[yggctl:" + hashlib.sha256(event_id.encode()).hexdigest() + "]"
    text = marker + "\n" + payload["rule"] + "\n" + payload["output"]
    if len(text.encode()) > 4096:
        raise Failure("simplex_message_limit")
    deadline = time.monotonic() + min(20, timeout)
    with profile_lock(cfg["lock"], deadline) as lock_fd:
        binding, contact, item = lookup(cfg, marker, text, deadline)
        key = hashlib.sha256(event_id.encode()).hexdigest()
        body = hashlib.sha256(text.encode()).hexdigest()
        journal = load_journal(ctx)
        previous = journal.get(key)
        if previous is not None:
            if previous["body"] != body or previous["binding"] != binding:
                raise Failure("simplex_attempt_binding_conflict")
            if previous["status"] == "native-recorded":
                event("state", "simplex_handoff", "durable_receipt_reused")
                return previous["item_id"]
            if item is None:
                raise Failure("simplex_attempt_ambiguous_no_auto_retry")
        elif len(journal) >= 2000:
            raise Failure("simplex_journal_capacity_operator_review")
        if item is None:
            if deadline - time.monotonic() < 1:
                raise Failure("simplex_handoff_budget_before_attempt")
            # Commit BEFORE launching. A crash even before exec intentionally
            # sacrifices availability rather than risk a second network send.
            journal[key] = {
                "body": body,
                "binding": binding,
                "status": "attempted",
                "item_id": None,
            }
            save_journal(ctx, journal)
            command = f"/_send @{contact} json " + json.dumps(
                [{"msgContent": {"type": "text", "text": text}}], ensure_ascii=False
            )
            argv = [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                CHILD_GUARD,
                str(os.getpid()),
                cfg["binary"],
                "-d",
                cfg["database"][:-8],
                "-e",
                command,
            ]
            target = pwd.getpwnam(cfg["user"])
            if target.pw_uid != os.geteuid():
                argv = [
                    "/usr/bin/setpriv",
                    "--reuid",
                    str(target.pw_uid),
                    "--regid",
                    str(target.pw_gid),
                    "--init-groups",
                    "--reset-env",
                    "--",
                    *argv,
                ]
            event("external_start", "simplex_native_send")
            try:
                # A process error/timeout does NOT decide whether the item was
                # committed. Re-read native state after the bounded child is reaped.
                # Keep the profile's same open-file-description lock inherited
                # until the guarded native child exits, even if this parent dies.
                ctx.run(
                    argv,
                    timeout=max(0.1, min(12, deadline - time.monotonic())),
                    check=False,
                    pass_fds=(lock_fd,),
                )
            except Failure:
                event("error", "simplex_native_send", "process_failed_check_native_item")
            event("external_exit", "simplex_native_send", "checking_native_item")
            _, _, item = lookup(cfg, marker, text, deadline)
        else:
            event("state", "simplex_handoff", "existing_native_item_reused")
        if item is None:
            raise Failure("simplex_handoff_unconfirmed")
        journal[key] = {
            "body": body,
            "binding": binding,
            "status": "native-recorded",
            "item_id": item,
        }
        save_journal(ctx, journal)
    return item
