"""Standard-library SQLite store. Creates its table automatically (``CREATE TABLE IF NOT EXISTS``)."""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from .._util import to_iso, utcnow
from ..exceptions import StoreError
from ..models import KeyRecord
from .base import COLUMNS, record_to_row, row_to_record

__all__ = ["SQLiteStore", "SCHEMA_SQL"]

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS {t} (
    key_id        VARCHAR(16)  PRIMARY KEY,
    prefix        VARCHAR(32)  NOT NULL,
    hash          VARCHAR(255) NOT NULL,
    hash_alg      VARCHAR(32)  NOT NULL,
    secret_last4  CHAR(4)      NOT NULL,
    owner         VARCHAR(255) NOT NULL,
    name          VARCHAR(255) NOT NULL DEFAULT '',
    scopes        TEXT         NOT NULL DEFAULT '[]',
    created_at    TEXT         NOT NULL,
    expires_at    TEXT         NULL,
    revoked_at    TEXT         NULL,
    revoke_reason VARCHAR(255) NULL,
    last_used_at  TEXT         NULL,
    use_count     BIGINT       NOT NULL DEFAULT 0,
    rotated_from  VARCHAR(16)  NULL,
    rotated_to    VARCHAR(16)  NULL,
    ip_allowlist  TEXT         NOT NULL DEFAULT '[]',
    metadata      TEXT         NOT NULL DEFAULT '{{}}'
);
CREATE INDEX IF NOT EXISTS {t}_owner_idx ON {t} (owner);
CREATE INDEX IF NOT EXISTS {t}_expires_at_idx ON {t} (expires_at);
"""


class SQLiteStore:
    """Thread-safe (single connection + lock, ``check_same_thread=False``), WAL mode for file databases."""

    def __init__(self, path: Union[str, os.PathLike[str]] = ":memory:", *, table: str = "safe_api_keys",
                 timeout: float = 30.0) -> None:
        if not _IDENT.match(table):
            raise ValueError(f"invalid table name {table!r}")
        self.path = str(path)
        self.table = table
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=timeout,
                                         isolation_level=None)
            self._conn.row_factory = sqlite3.Row
            if self.path != ":memory:" and not self.path.startswith("file::memory:"):
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA_SQL.format(t=table))
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open SQLite database: {exc}") from exc
        self._sql = self._build_sql(table)

    @staticmethod
    def _build_sql(t: str) -> Dict[str, str]:
        # The table name is validated against _IDENT; every value is a bound parameter.
        cols = ", ".join(COLUMNS)
        marks = ", ".join(f":{c}" for c in COLUMNS)
        updates = ", ".join(f"{c}=excluded.{c}" for c in COLUMNS if c != "key_id")
        return {  # nosec B608
            "upsert": f"INSERT INTO {t} ({cols}) VALUES ({marks}) ON CONFLICT(key_id) DO UPDATE SET {updates}",  # nosec B608
            "get": f"SELECT * FROM {t} WHERE key_id = ?",  # nosec B608
            "touch": f"UPDATE {t} SET last_used_at = ?, use_count = use_count + 1 WHERE key_id = ?",  # nosec B608
            "select": f"SELECT * FROM {t}",  # nosec B608
            "delete": f"DELETE FROM {t} WHERE key_id = ?",  # nosec B608
            "purge": f"DELETE FROM {t} WHERE (revoked_at IS NOT NULL AND revoked_at < ?) "  # nosec B608
                     "OR (expires_at IS NOT NULL AND expires_at < ?)",
            "count": f"SELECT hash_alg, COUNT(*) AS n FROM {t} GROUP BY hash_alg",  # nosec B608
        }

    def _exec(self, sql: str, params: Any = (), *, many: bool = False) -> sqlite3.Cursor:
        try:
            with self._lock:
                if many:
                    self._conn.execute("BEGIN IMMEDIATE")
                    try:
                        cur = self._conn.executemany(sql, params)
                        self._conn.execute("COMMIT")
                    except BaseException:
                        self._conn.execute("ROLLBACK")
                        raise
                    return cur
                return self._conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise StoreError(f"SQLite error: {type(exc).__name__}") from exc

    def get(self, key_id: str) -> Optional[KeyRecord]:
        with self._lock:
            row = self._exec(self._sql["get"], (key_id,)).fetchone()
        return row_to_record(dict(row)) if row else None

    def save(self, record: KeyRecord) -> None:
        self._exec(self._sql["upsert"], record_to_row(record))

    def save_many(self, records: Iterable[KeyRecord]) -> None:
        self._exec(self._sql["upsert"], [record_to_row(r) for r in records], many=True)

    def touch(self, key_id: str, when: datetime) -> None:
        self._exec(self._sql["touch"], (to_iso(when), key_id))

    def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
             now: Optional[datetime] = None) -> List[KeyRecord]:
        where, params = [], []
        if owner is not None:
            where.append("owner = ?")
            params.append(owner)
        if not include_inactive:
            where.append("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)")
            params.append(to_iso(now or utcnow()))
        sql = self._sql["select"]
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at, key_id"
        with self._lock:
            rows = self._exec(sql, params).fetchall()
        return [row_to_record(dict(r)) for r in rows]

    def delete(self, key_id: str) -> None:
        self._exec(self._sql["delete"], (key_id,))

    def purge(self, *, before: datetime) -> int:
        b = to_iso(before)
        return int(self._exec(self._sql["purge"], (b, b)).rowcount)

    def count_by_hash_alg(self) -> Dict[str, int]:
        with self._lock:
            rows = self._exec(self._sql["count"]).fetchall()
        return {r["hash_alg"]: int(r["n"]) for r in rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __repr__(self) -> str:
        return f"SQLiteStore(path={self.path!r}, table={self.table!r})"
