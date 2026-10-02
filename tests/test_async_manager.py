"""Native async tests. (The shared behaviour suite in test_manager.py also runs against AsyncKeyManager.)"""

import asyncio
from datetime import timedelta

import pytest

from safe_api_keys import AsyncKeyManager, AsyncKeyVerifier, RevokedKey, UnknownKey, VerifyCache
from safe_api_keys.stores import AsyncMemoryStore, AsyncStoreAdapter, MemoryStore, SQLiteStore

from .conftest import PEPPER


async def test_async_roundtrip(clock):
    km = AsyncKeyManager(AsyncMemoryStore(), "sk_test", pepper=PEPPER, clock=clock)
    issued = await km.issue("o", scopes=["a"])
    rec = await km.verify(issued.raw_key, scopes=["a"])
    assert rec.owner == "o"
    await km.revoke(issued.key_id)
    with pytest.raises(RevokedKey):
        await km.verify(issued.raw_key)
    assert (await km.check(issued.raw_key)).ok is False


async def test_sync_store_is_wrapped_and_threaded(tmp_path, clock):
    km = AsyncKeyManager(SQLiteStore(str(tmp_path / "k.db")), "sk_test", pepper=PEPPER, clock=clock)
    assert isinstance(km.store, AsyncStoreAdapter)
    issued = await km.issue("o")
    results = await asyncio.gather(*[km.verify(issued.raw_key) for _ in range(20)])
    assert {r.key_id for r in results} == {issued.key_id}
    assert [r.key_id for r in await km.list()] == [issued.key_id]
    await km.close()


async def test_async_verifier_and_cache(clock):
    store = MemoryStore()
    km = AsyncKeyManager(store, "sk_test", pepper=PEPPER, clock=clock)
    issued = await km.issue("o")
    cache = VerifyCache(ttl=30)
    v = AsyncKeyVerifier(store, "sk_test", pepper=PEPPER, clock=clock, cache=cache)
    await v.verify(issued.raw_key)
    await v.verify(issued.raw_key)
    assert cache.hits == 1
    with pytest.raises(UnknownKey):
        await v.verify(km.key_format.build("ZZZZZZZZZZZZ", "y" * 32)[0])
    assert not hasattr(v, "issue")


async def test_async_rotation_and_lineage(clock):
    km = AsyncKeyManager(AsyncMemoryStore(), "sk_test", pepper=PEPPER, clock=clock)
    a = await km.issue("o")
    b = await km.rotate(a.key_id, grace=timedelta(hours=1))
    assert [r.key_id for r in await km.lineage(a.key_id)] == [a.key_id, b.key_id]
    clock.advance(hours=1)
    assert await km.purge(older_than=timedelta(0)) == 0
    clock.advance(seconds=1)
    assert await km.purge(older_than=timedelta(0)) == 1
