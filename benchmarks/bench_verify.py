"""Verify hot-path benchmark (§17).

    python benchmarks/bench_verify.py [-n 100000]

Reports:
* pure CPU cost of parse + HMAC + decide (no store I/O)
* full ``KeyManager.verify`` against ``MemoryStore`` (touch disabled)
* memory growth across N verifications (tracemalloc), cache disabled
"""

from __future__ import annotations

import argparse
import gc
import platform
import sys
import time
import tracemalloc
from datetime import timedelta

from safe_api_keys import KeyManager
from safe_api_keys._logic import check_secret, decide, prepare_raw
from safe_api_keys.stores import MemoryStore

PEPPER = b"benchmark-pepper-32-bytes-xxxxxxxx"


def per_call_us(fn, n: int) -> float:
    start = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - start) / n * 1e6


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=100_000)
    args = ap.parse_args(argv)
    n = args.n

    km = KeyManager(MemoryStore(), "sk_live", pepper=PEPPER, touch_interval=None, audit_success=False)
    issued = km.issue("bench", scopes=["orders:read"], expires_in=timedelta(days=1))
    record = km.get(issued.key_id)
    raw = issued.raw_key
    now = km.now()

    def pure() -> None:
        parsed = prepare_raw(raw, km.key_format)
        check_secret(km.registry, parsed, record)
        decide(record, now, scopes=["orders:read"])

    def full() -> None:
        km.verify(raw, scopes=["orders:read"])

    for f in (pure, full):  # warm-up
        per_call_us(f, 2000)
    pure_us = per_call_us(pure, n)
    full_us = per_call_us(full, n)

    gc.collect()
    tracemalloc.start()
    per_call_us(full, 1000)
    gc.collect()
    before, _ = tracemalloc.get_traced_memory()
    per_call_us(full, n)
    gc.collect()
    after, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    growth = after - before

    print(f"Python {platform.python_version()} on {platform.machine()} / {platform.system()}")
    print(f"parse + hmac + decide : {pure_us:6.2f} µs/op  (target < 50 µs)")
    print(f"verify (MemoryStore)  : {full_us:6.2f} µs/op")
    print(f"memory growth over {n} verifies: {growth} bytes")
    ok = pure_us < 50 and growth < 64 * 1024
    print("OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
