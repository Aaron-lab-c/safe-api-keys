"""In-process store (dict + RLock). For tests, demos and single-process tools."""

from __future__ import annotations

import threading
from collections import Counter
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional

from ..models import KeyRecord
from .base import filter_records

if TYPE_CHECKING:  # pragma: no cover
    from .base import AsyncStoreAdapter

__all__ = ["MemoryStore", "AsyncMemoryStore"]


class MemoryStore:
    def __init__(self) -> None:
        self._data: Dict[str, KeyRecord] = {}
        self._lock = threading.RLock()

    def get(self, key_id: str) -> Optional[KeyRecord]:
        with self._lock:
            rec = self._data.get(key_id)
            return rec.copy() if rec is not None else None

    def save(self, record: KeyRecord) -> None:
        with self._lock:
            self._data[record.key_id] = record.copy()

    def save_many(self, records: Iterable[KeyRecord]) -> None:
        with self._lock:
            for r in records:
                self._data[r.key_id] = r.copy()

    def touch(self, key_id: str, when: datetime) -> None:
        with self._lock:
            rec = self._data.get(key_id)
            if rec is not None:  # partial update: only usage fields change
                self._data[key_id] = rec.replace(last_used_at=when, use_count=rec.use_count + 1)

    def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
             now: Optional[datetime] = None) -> List[KeyRecord]:
        with self._lock:
            return [r.copy() for r in filter_records(list(self._data.values()), owner, include_inactive, now)]

    def delete(self, key_id: str) -> None:
        with self._lock:
            self._data.pop(key_id, None)

    def purge(self, *, before: datetime) -> int:
        with self._lock:
            doomed = [k for k, r in self._data.items()
                      if (r.revoked_at is not None and r.revoked_at < before)
                      or (r.expires_at is not None and r.expires_at < before)]
            for k in doomed:
                del self._data[k]
            return len(doomed)

    def count_by_hash_alg(self) -> Dict[str, int]:
        with self._lock:
            return dict(Counter(r.hash_alg for r in self._data.values()))

    def close(self) -> None:
        return None

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"MemoryStore(size={len(self._data)})"


def AsyncMemoryStore() -> AsyncStoreAdapter:  # noqa: N802 - factory that reads like a class
    from .base import AsyncStoreAdapter

    return AsyncStoreAdapter(MemoryStore(), threaded=False)
