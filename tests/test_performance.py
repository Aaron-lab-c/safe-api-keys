"""§17: verify hot path is cheap and does not leak memory (cache disabled)."""

import gc
import time
import tracemalloc

from safe_api_keys import KeyManager
from safe_api_keys.stores import MemoryStore

from .conftest import PEPPER


def test_no_memory_growth_and_fast():
    km = KeyManager(MemoryStore(), "sk_test", pepper=PEPPER, touch_interval=None, audit_success=False)
    raw = km.issue("o", scopes=["a"]).raw_key
    for _ in range(1000):
        km.verify(raw, scopes=["a"])
    gc.collect()
    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    start = time.perf_counter()
    n = 100_000
    for _ in range(n):
        km.verify(raw, scopes=["a"])
    elapsed = time.perf_counter() - start
    gc.collect()
    after, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert after - before < 64 * 1024
    assert elapsed / n < 500e-6  # generous bound under tracemalloc on slow CI machines
