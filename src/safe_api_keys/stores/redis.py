"""Redis stores (redis-py >= 4, sync and ``redis.asyncio``).

Layout under ``namespace`` (default ``apikeys``):

* ``{ns}:key:{key_id}``  HASH with one field per column (JSON for lists/dicts, ISO-8601 for datetimes)
* ``{ns}:owner:{owner}`` SET of key ids
* ``{ns}:all``           SET of all key ids (for list()/purge()/count)

``EXPIREAT`` is set to ``expires_at`` (or ``revoked_at``) + ``retention`` purely as housekeeping;
state decisions never depend on Redis TTLs (S7).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from .._util import to_iso
from ..exceptions import MissingDependency, StoreError
from ..models import KeyRecord
from .base import COLUMNS, filter_records, record_to_row, row_to_record

try:
    from redis.exceptions import RedisError, WatchError
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[redis]") from exc

__all__ = ["RedisStore", "AsyncRedisStore"]

_NULL = ""


def _encode(record: KeyRecord) -> Dict[str, str]:
    row = record_to_row(record)
    return {k: (_NULL if v is None else str(v)) for k, v in row.items()}


def _decode(raw: Dict[Any, Any]) -> Optional[KeyRecord]:
    data = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in raw.items()}
    if not data.get("hash") or not data.get("key_id"):
        return None
    row: Dict[str, Any] = {c: (data.get(c) or None) for c in COLUMNS}
    row["name"] = data.get("name", "")
    row["use_count"] = int(data.get("use_count") or 0)
    return row_to_record(row)


class _Keys:
    def __init__(self, namespace: str, retention: Optional[timedelta]) -> None:
        if not namespace or any(ch.isspace() for ch in namespace):
            raise ValueError("invalid namespace")
        self.ns = namespace
        self.retention = retention

    def key(self, key_id: str) -> str:
        return f"{self.ns}:key:{key_id}"

    def owner(self, owner: str) -> str:
        return f"{self.ns}:owner:{owner}"

    @property
    def all(self) -> str:
        return f"{self.ns}:all"

    def expire_at(self, record: KeyRecord) -> Optional[int]:
        if self.retention is None:
            return None
        ends = [d for d in (record.expires_at, record.revoked_at) if d is not None]
        if not ends:
            return None
        return int((min(ends) + self.retention).timestamp())


def _queue_save(keys: _Keys, pipe: Any, record: KeyRecord) -> None:
    k = keys.key(record.key_id)
    pipe.hset(k, mapping=_encode(record))
    pipe.sadd(keys.owner(record.owner), record.key_id)
    pipe.sadd(keys.all, record.key_id)
    exp = keys.expire_at(record)
    if exp is None:
        pipe.persist(k)
    else:
        pipe.expireat(k, exp)


def _wrap(exc: Exception) -> StoreError:
    err = StoreError(f"Redis error: {type(exc).__name__}")
    err.__cause__ = exc
    return err


class RedisStore:
    def __init__(self, client: Any, *, namespace: str = "apikeys",
                 retention: Optional[timedelta] = timedelta(days=30)) -> None:
        self.client = client
        self._k = _Keys(namespace, retention)

    def get(self, key_id: str) -> Optional[KeyRecord]:
        try:
            return _decode(self.client.hgetall(self._k.key(key_id)))
        except RedisError as exc:
            raise _wrap(exc) from exc

    def save(self, record: KeyRecord) -> None:
        self.save_many([record])

    def save_many(self, records: Iterable[KeyRecord]) -> None:
        try:
            pipe = self.client.pipeline(transaction=True)
            for r in records:
                _queue_save(self._k, pipe, r)
            pipe.execute()
        except RedisError as exc:
            raise _wrap(exc) from exc

    def touch(self, key_id: str, when: datetime) -> None:
        # HSET + HINCRBY in one MULTI: atomic and contention-free, so concurrent touches never lose counts.
        k = self._k.key(key_id)
        try:
            if not self.client.hexists(k, "hash"):
                return
            pipe = self.client.pipeline(transaction=True)
            pipe.hset(k, "last_used_at", to_iso(when))
            pipe.hincrby(k, "use_count", 1)
            created, _ = pipe.execute()
            if created:  # the field was new: the record vanished in between; drop the stub we created
                self._drop_stub(k)
        except RedisError as exc:
            raise _wrap(exc) from exc

    def _drop_stub(self, k: str) -> None:
        with self.client.pipeline(transaction=True) as pipe:
            try:
                pipe.watch(k)
                if not pipe.hexists(k, "hash"):
                    pipe.multi()
                    pipe.delete(k)
                    pipe.execute()
            except WatchError:  # someone wrote the key meanwhile: it is a real record now
                pass

    def _ids(self, owner: Optional[str]) -> List[str]:
        members = self.client.smembers(self._k.owner(owner) if owner is not None else self._k.all)
        return sorted(m.decode() if isinstance(m, bytes) else m for m in members)

    def _load_many(self, ids: List[str]) -> List[KeyRecord]:
        if not ids:
            return []
        pipe = self.client.pipeline(transaction=False)
        for i in ids:
            pipe.hgetall(self._k.key(i))
        out, stale = [], []
        for i, raw in zip(ids, pipe.execute()):
            rec = _decode(raw) if raw else None
            if rec is None:
                stale.append(i)
            else:
                out.append(rec)
        if stale:  # hashes removed by EXPIREAT: drop dangling index entries
            self.client.srem(self._k.all, *stale)
        return out

    def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
             now: Optional[datetime] = None) -> List[KeyRecord]:
        try:
            return filter_records(self._load_many(self._ids(owner)), owner, include_inactive, now)
        except RedisError as exc:
            raise _wrap(exc) from exc

    def delete(self, key_id: str) -> None:
        try:
            rec = self.get(key_id)
            pipe = self.client.pipeline(transaction=True)
            pipe.delete(self._k.key(key_id))
            pipe.srem(self._k.all, key_id)
            if rec is not None:
                pipe.srem(self._k.owner(rec.owner), key_id)
            pipe.execute()
        except RedisError as exc:
            raise _wrap(exc) from exc

    def purge(self, *, before: datetime) -> int:
        n = 0
        for rec in self.list(include_inactive=True):
            if (rec.revoked_at is not None and rec.revoked_at < before) or \
                    (rec.expires_at is not None and rec.expires_at < before):
                self.delete(rec.key_id)
                n += 1
        return n

    def count_by_hash_alg(self) -> Dict[str, int]:
        return dict(Counter(r.hash_alg for r in self.list(include_inactive=True)))

    def close(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"RedisStore(namespace={self._k.ns!r})"


class AsyncRedisStore:
    def __init__(self, client: Any, *, namespace: str = "apikeys",
                 retention: Optional[timedelta] = timedelta(days=30)) -> None:
        self.client = client
        self._k = _Keys(namespace, retention)

    async def get(self, key_id: str) -> Optional[KeyRecord]:
        try:
            return _decode(await self.client.hgetall(self._k.key(key_id)))
        except RedisError as exc:
            raise _wrap(exc) from exc

    async def save(self, record: KeyRecord) -> None:
        await self.save_many([record])

    async def save_many(self, records: Iterable[KeyRecord]) -> None:
        try:
            pipe = self.client.pipeline(transaction=True)
            for r in records:
                _queue_save(self._k, pipe, r)  # only queues commands
            await pipe.execute()
        except RedisError as exc:
            raise _wrap(exc) from exc

    async def touch(self, key_id: str, when: datetime) -> None:
        k = self._k.key(key_id)
        try:
            if not await self.client.hexists(k, "hash"):
                return
            pipe = self.client.pipeline(transaction=True)
            pipe.hset(k, "last_used_at", to_iso(when))
            pipe.hincrby(k, "use_count", 1)
            created, _ = await pipe.execute()
            if created:
                await self._drop_stub(k)
        except RedisError as exc:
            raise _wrap(exc) from exc

    async def _drop_stub(self, k: str) -> None:
        async with self.client.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch(k)
                if not await pipe.hexists(k, "hash"):
                    pipe.multi()
                    pipe.delete(k)
                    await pipe.execute()
            except WatchError:
                pass

    async def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
                   now: Optional[datetime] = None) -> List[KeyRecord]:
        try:
            members = await self.client.smembers(self._k.owner(owner) if owner is not None else self._k.all)
            ids = sorted(m.decode() if isinstance(m, bytes) else m for m in members)
            if not ids:
                return []
            pipe = self.client.pipeline(transaction=False)
            for i in ids:
                pipe.hgetall(self._k.key(i))
            out, stale = [], []
            for i, raw in zip(ids, await pipe.execute()):
                rec = _decode(raw) if raw else None
                if rec is None:
                    stale.append(i)
                else:
                    out.append(rec)
            if stale:
                await self.client.srem(self._k.all, *stale)
            return filter_records(out, owner, include_inactive, now)
        except RedisError as exc:
            raise _wrap(exc) from exc

    async def delete(self, key_id: str) -> None:
        try:
            rec = await self.get(key_id)
            pipe = self.client.pipeline(transaction=True)
            pipe.delete(self._k.key(key_id))
            pipe.srem(self._k.all, key_id)
            if rec is not None:
                pipe.srem(self._k.owner(rec.owner), key_id)
            await pipe.execute()
        except RedisError as exc:
            raise _wrap(exc) from exc

    async def purge(self, *, before: datetime) -> int:
        n = 0
        for rec in await self.list(include_inactive=True):
            if (rec.revoked_at is not None and rec.revoked_at < before) or \
                    (rec.expires_at is not None and rec.expires_at < before):
                await self.delete(rec.key_id)
                n += 1
        return n

    async def count_by_hash_alg(self) -> Dict[str, int]:
        return dict(Counter(r.hash_alg for r in await self.list(include_inactive=True)))

    async def close(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"AsyncRedisStore(namespace={self._k.ns!r})"
