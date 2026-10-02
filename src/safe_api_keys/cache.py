"""Optional per-process record cache (§7.4).

Caches *records* by ``key_id`` (never verification results): hash, revocation,
expiry, scope and IP checks still run on every request. Trade-off: a revocation
performed by **another process** takes up to ``ttl`` seconds to be seen here.
Revocations through the same manager invalidate immediately.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Optional, Tuple

from .models import KeyRecord

__all__ = ["VerifyCache"]


class VerifyCache:
    def __init__(self, ttl: float = 5.0, maxsize: int = 10_000,
                 timer: Callable[[], float] = time.monotonic) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be > 0")
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        self.ttl = float(ttl)
        self.maxsize = int(maxsize)
        self._timer = timer
        self._data: OrderedDict[str, Tuple[float, KeyRecord]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key_id: str) -> Optional[KeyRecord]:
        now = self._timer()
        with self._lock:
            item = self._data.get(key_id)
            if item is None or item[0] <= now:
                if item is not None:
                    del self._data[key_id]
                self.misses += 1
                return None
            self._data.move_to_end(key_id)
            self.hits += 1
            return item[1]

    def set(self, record: KeyRecord) -> None:
        with self._lock:
            self._data[record.key_id] = (self._timer() + self.ttl, record)
            self._data.move_to_end(record.key_id)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def update(self, record: KeyRecord) -> None:
        """Refresh an existing entry's value without extending its TTL."""
        with self._lock:
            item = self._data.get(record.key_id)
            if item is not None:
                self._data[record.key_id] = (item[0], record)

    def invalidate(self, key_id: str) -> None:
        with self._lock:
            self._data.pop(key_id, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"VerifyCache(ttl={self.ttl}, maxsize={self.maxsize}, size={len(self)})"
