"""Store protocols, the sync->async adapter, and row (de)serialisation shared by backends."""

from __future__ import annotations

import asyncio
import functools
import json
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, runtime_checkable

from .._util import UTC, from_iso, to_iso
from ..models import KeyRecord

__all__ = ["KeyStore", "AsyncKeyStore", "AsyncStoreAdapter", "record_to_row", "row_to_record", "COLUMNS",
           "ROTATION_FIELDS", "UPDATABLE_FIELDS", "rotation_fields", "fields_to_row", "is_active_at"]

COLUMNS = (
    "key_id", "prefix", "hash", "hash_alg", "secret_last4", "owner", "name", "scopes", "created_at",
    "expires_at", "revoked_at", "revoke_reason", "last_used_at", "use_count", "rotated_from", "rotated_to",
    "ip_allowlist", "metadata",
)
_DT_FIELDS = ("created_at", "expires_at", "revoked_at", "last_used_at")
_JSON_FIELDS = ("scopes", "ip_allowlist", "metadata")
#: The only columns ``save_rotation`` writes on the *old* key (a partial update, like ``touch``).
ROTATION_FIELDS = ("rotated_to", "expires_at", "revoked_at", "revoke_reason")
#: The columns ``KeyManager.update`` may change through ``update_fields``.
UPDATABLE_FIELDS = ("name", "scopes", "expires_at", "ip_allowlist", "metadata")


@runtime_checkable
class KeyStore(Protocol):
    """Required: ``get``/``save``/``touch``. Optional: ``list``, ``delete``, ``purge``, ``count_by_hash_alg``,
    ``save_many`` and ``save_rotation``.

    ``save_rotation(new, old) -> bool`` is what makes :meth:`KeyManager.rotate` safe against a concurrent
    ``revoke``: in one atomic step it must (1) refuse (return ``False`` and write nothing) when the stored
    ``old`` key already has ``revoked_at`` set, otherwise (2) apply only :data:`ROTATION_FIELDS` of ``old``
    as a partial update and (3) save ``new``. Every built-in store implements it.

    ``update_fields(key_id, fields) -> bool`` backs :meth:`KeyManager.update` the same way: a partial update
    of a subset of :data:`UPDATABLE_FIELDS` (values as :class:`KeyRecord` attributes) that is applied only
    while ``revoked_at`` is still unset, returning ``False`` (nothing written) otherwise or when the key is
    missing. Every built-in store implements it.
    """

    def get(self, key_id: str) -> Optional[KeyRecord]: ...

    def save(self, record: KeyRecord) -> None: ...

    def touch(self, key_id: str, when: datetime) -> None: ...


@runtime_checkable
class AsyncKeyStore(Protocol):
    async def get(self, key_id: str) -> Optional[KeyRecord]: ...

    async def save(self, record: KeyRecord) -> None: ...

    async def touch(self, key_id: str, when: datetime) -> None: ...


def is_active_at(record: KeyRecord, now: Optional[datetime]) -> bool:
    return record.is_active(now)


def rotation_fields(old: KeyRecord) -> Dict[str, Any]:
    """The partial update ``save_rotation`` applies to the old key (values as :class:`KeyRecord` attributes)."""
    return {name: getattr(old, name) for name in ROTATION_FIELDS}


def fields_to_row(fields: Mapping[str, Any], *, native_datetime: bool = False, native_json: bool = False,
                  allowed: Sequence[str] = COLUMNS) -> Dict[str, Any]:
    """Convert a subset of record attributes to row values (datetimes to ISO text, lists/dicts to JSON)."""
    row: Dict[str, Any] = {}
    for col, value in fields.items():
        if col not in allowed or col == "key_id":
            raise ValueError(f"cannot update column {col!r}")
        if col in _DT_FIELDS:
            if value is not None and not native_datetime:
                value = to_iso(value)
        elif col in _JSON_FIELDS:
            value = list(value) if isinstance(value, tuple) else dict(value)
            if not native_json:
                value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        row[col] = value
    return row


def record_to_row(record: KeyRecord, *, native_datetime: bool = False, native_json: bool = False) -> Dict[str, Any]:
    row = fields_to_row({col: getattr(record, col) for col in COLUMNS if col != "key_id"},
                        native_datetime=native_datetime, native_json=native_json)
    return {"key_id": record.key_id, **row}


def _dt(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, bytes):
        value = value.decode()
    text = str(value)
    if "T" not in text and " " in text:
        text = text.replace(" ", "T", 1)
    try:
        return from_iso(text)
    except ValueError:
        return datetime.fromisoformat(text).replace(tzinfo=UTC)


def _js(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (bytes, str)):
        return json.loads(value)
    return value


def row_to_record(row: Mapping[str, Any]) -> KeyRecord:
    data: Dict[str, Any] = {c: row.get(c) for c in COLUMNS}
    for col in _DT_FIELDS:
        data[col] = _dt(data[col])
    data["scopes"] = tuple(_js(data["scopes"], []))
    data["ip_allowlist"] = tuple(_js(data["ip_allowlist"], []))
    data["metadata"] = dict(_js(data["metadata"], {}))
    data["use_count"] = int(data["use_count"] or 0)
    data["name"] = data["name"] or ""
    return KeyRecord(**data)


class AsyncStoreAdapter:
    """Expose a synchronous store through the async protocol.

    Calls run in a worker thread (``asyncio.to_thread`` semantics) unless ``threaded=False``
    (fine for in-memory stores).
    """

    def __init__(self, store: Any, *, threaded: Optional[bool] = None) -> None:
        self._store = store
        if threaded is None:
            from .memory import MemoryStore

            threaded = not isinstance(store, MemoryStore)
        self._threaded = threaded
        for name in ("list", "delete", "purge", "count_by_hash_alg", "close", "save_many", "save_rotation",
                     "update_fields"):
            if callable(getattr(store, name, None)):
                setattr(self, name, functools.partial(self._run, name))

    @property
    def wrapped(self) -> Any:
        return self._store

    async def _run(self, name: str, *args: Any, **kwargs: Any) -> Any:
        fn = getattr(self._store, name)
        if not self._threaded:
            return fn(*args, **kwargs)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, functools.partial(fn, *args, **kwargs))

    async def get(self, key_id: str) -> Optional[KeyRecord]:
        result: Optional[KeyRecord] = await self._run("get", key_id)
        return result

    async def save(self, record: KeyRecord) -> None:
        await self._run("save", record)

    async def touch(self, key_id: str, when: datetime) -> None:
        await self._run("touch", key_id, when)

    def __repr__(self) -> str:
        return f"AsyncStoreAdapter({self._store!r})"


def filter_records(records: List[KeyRecord], owner: Optional[str], include_inactive: bool,
                   now: Optional[datetime]) -> List[KeyRecord]:
    out = [r for r in records if owner is None or r.owner == owner]
    if not include_inactive:
        out = [r for r in out if r.is_active(now)]
    return sorted(out, key=lambda r: (r.created_at, r.key_id))
