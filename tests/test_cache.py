from unittest import mock

import pytest

from safe_api_keys import KeyManager, RevokedKey, VerifyCache
from safe_api_keys.stores import MemoryStore

from .conftest import PEPPER


class FakeTimer:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def make(clock, ttl=5.0):
    timer = FakeTimer()
    store = mock.Mock(wraps=MemoryStore())
    cache = VerifyCache(ttl=ttl, timer=timer)
    km = KeyManager(store, "sk_test", pepper=PEPPER, clock=clock, cache=cache, touch_interval=None)
    return km, store, cache, timer


def test_hit_miss_and_expiry(clock):
    km, store, cache, timer = make(clock)
    i = km.issue("o")
    store.get.reset_mock()
    km.verify(i.raw_key)
    km.verify(i.raw_key)
    assert store.get.call_count == 1 and cache.hits == 1
    timer.t = 5.0
    km.verify(i.raw_key)
    assert store.get.call_count == 2


def test_cache_still_checks_secret(clock):
    km, store, cache, timer = make(clock)
    i = km.issue("o")
    km.verify(i.raw_key)
    from safe_api_keys import UnknownKey

    with pytest.raises(UnknownKey):
        km.verify(km.key_format.build(i.key_id, "z" * 32)[0])


def test_revoke_rotate_delete_invalidate(clock):
    km, store, cache, timer = make(clock)
    a = km.issue("o")
    km.verify(a.raw_key)
    km.revoke(a.key_id)
    with pytest.raises(RevokedKey):
        km.verify(a.raw_key)  # same process: immediate despite ttl
    b = km.issue("o")
    km.verify(b.raw_key)
    km.rotate(b.key_id)
    assert km.verify(b.raw_key).rotated_to is not None
    km.delete(b.key_id)
    assert len([k for k in cache._data if k == b.key_id]) == 0


def test_other_process_revocation_delayed_by_ttl(clock):
    km, store, cache, timer = make(clock)
    i = km.issue("o")
    km.verify(i.raw_key)
    other = KeyManager(store, "sk_test", pepper=PEPPER, clock=clock)  # e.g. another worker
    other.revoke(i.key_id)
    km.verify(i.raw_key)  # stale cache: still accepted within ttl (documented trade-off)
    timer.t = 5.0
    with pytest.raises(RevokedKey):
        km.verify(i.raw_key)


def test_lru_and_validation():
    c = VerifyCache(ttl=10, maxsize=2)
    from tests.test_logic import rec

    for k in ("A" * 12, "B" * 12, "C" * 12):
        c.set(rec(key_id=k))
    assert c.get("A" * 12) is None and len(c) == 2
    c.clear()
    assert len(c) == 0
    with pytest.raises(ValueError):
        VerifyCache(ttl=0)
    with pytest.raises(ValueError):
        VerifyCache(maxsize=0)
