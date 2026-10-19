"""Private SQLite checkpoints; atlas writer lock never blocks the collector."""

from typing import cast

import fcntl
import json
import os
import sqlite3
import stat

from core import Failure, logged, event
import checks

MAX_NODES = 50000  # Storage safeguard, not an exploration sample quota.


class Store:
    @logged
    def __init__(self, ctx, write=False):
        self.ctx, self.write = ctx, write
        self.root = ctx.p.state / "atlas"
        self.connection = None
        self.fd = None

    @logged
    def __enter__(self):
        self.ctx.root()
        if self.ctx.require_root:
            checks.trusted(self.ctx.p.state)
        if not self.root.exists() and not self.root.is_symlink():
            if not self.write:
                raise Failure("atlas_missing_catalogue_or_crawl")
            self.root.mkdir(mode=0o700)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise Failure("atlas_store_not_private_directory")
        if self.ctx.require_root:
            checks.trusted(self.root)
        path = self.root / "atlas.sqlite"
        try:
            if self.write:
                self.fd = os.open(
                    self.root / ".writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
                )
                s = os.fstat(self.fd)
                if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o600:
                    raise Failure("atlas_unsafe_lock")
                if self.ctx.require_root and s.st_uid != 0:
                    raise Failure("atlas_lock_not_root_owned")
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Failure("atlas_writer_already_running") from None
            if not path.exists() and not path.is_symlink():
                if not self.write:
                    raise Failure("atlas_database_missing")
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            for p in (path, self.root / "atlas.sqlite-wal", self.root / "atlas.sqlite-shm"):
                if not p.exists() and not p.is_symlink():
                    continue
                s = p.lstat()
                if (
                    not stat.S_ISREG(s.st_mode)
                    or s.st_mode & 0o077
                    or s.st_size > 256 * 1024 * 1024
                ):
                    raise Failure("atlas_unsafe_or_oversized_database")
                if self.ctx.require_root:
                    checks.trusted(p)
            event("external_entry", "atlas_sqlite", "fixed_private_path")
            self.connection = sqlite3.connect(
                "file:" + str(path) + "?mode=rw", uri=True, timeout=2, isolation_level=None
            )
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.execute("PRAGMA busy_timeout=2000")
            if self.write:
                self.connection.execute("PRAGMA journal_mode=WAL")
                self.connection.execute("PRAGMA synchronous=FULL")
                self.connection.executescript("""
                    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS catalogue(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, own TEXT NOT NULL, started TEXT NOT NULL,
                        finished TEXT, state TEXT NOT NULL, seed TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS targets(run TEXT, key TEXT, origin TEXT, done INTEGER DEFAULT 0,
                        PRIMARY KEY(run,key));
                    CREATE TABLE IF NOT EXISTS responses(run TEXT, key TEXT, method TEXT, ts TEXT, status TEXT,
                        elapsed_ms REAL, payload TEXT, PRIMARY KEY(run,key,method));
                """)
                self.sql("INSERT OR IGNORE INTO meta VALUES('schema','1')")
            else:
                self.connection.execute("PRAGMA query_only=ON")
                self.connection.execute(
                    "BEGIN"
                )  # Consistent read snapshot while writer progresses.
            if self.meta("schema") != 1:
                raise Failure("atlas_unknown_database_schema")
            event("external_exit", "atlas_sqlite", "opened")
            return self
        except sqlite3.Error:
            self.close()
            raise Failure("atlas_database_open_failed") from None
        except BaseException:
            self.close()
            raise

    @logged
    def __exit__(self, kind, value, _tb):
        self.close()

    @logged
    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        event("state", "atlas_store", "released")

    @logged
    def sql(self, query, parameters=()):
        # No SQL/parameters or exception text in logger/output.
        event("external_entry", "atlas_sqlite_query")
        try:
            rows = cast(sqlite3.Connection, self.connection).execute(query, parameters).fetchall()
        except sqlite3.Error:
            raise Failure("atlas_database_operation_failed") from None
        event("external_exit", "atlas_sqlite_query", "success")
        return rows

    @logged
    def batch(self, statements):
        if not self.write:
            raise Failure("atlas_readonly_store")
        self.sql("BEGIN IMMEDIATE")
        try:
            for query, args in statements:
                self.sql(query, args)
            self.sql("COMMIT")
        except BaseException:
            self.sql("ROLLBACK")
            raise

    @logged
    def meta(self, key, value=None):
        if value is not None:
            self.sql(
                "INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value, allow_nan=False))
            )
            return value
        rows = self.sql("SELECT v FROM meta WHERE k=?", (key,))
        try:
            return json.loads(rows[0][0]) if rows else None
        except ValueError:
            raise Failure("atlas_invalid_checkpoint_json") from None

    @logged
    def seed(self, run, keys, origin):
        unique = set(keys)
        known = {r[0] for r in self.sql("SELECT key FROM targets WHERE run=?", (run,))}
        if len(known | unique) > MAX_NODES:
            raise Failure("atlas_storage_frontier_guard_checkpoint_not_complete")
        self.batch(
            [
                ("INSERT OR IGNORE INTO targets(run,key,origin) VALUES(?,?,?)", (run, key, origin))
                for key in sorted(unique)
            ]
        )

    @logged
    def response(self, run, key, method, status, elapsed=None, payload=None):
        from core import timestamp

        size = sum(
            p.stat().st_size
            for p in (self.root / "atlas.sqlite", self.root / "atlas.sqlite-wal")
            if p.exists()
        )
        if size > 256 * 1024 * 1024:
            raise Failure("atlas_database_storage_guard_checkpoint_not_complete")
        self.sql(
            "INSERT OR REPLACE INTO responses VALUES(?,?,?,?,?,?,?)",
            (run, key, method, timestamp(), status, elapsed, json.dumps(payload, allow_nan=False)),
        )
        event("state", "atlas_response", status)
