import asyncio
from datetime import timedelta

import pytest

fakeredis = pytest.importorskip("fakeredis")

from safe_api_keys import AsyncKeyManager, KeyManager  # noqa: E402
from safe_api_keys.stores import AsyncRedisStore, RedisStore  # noqa: E402

from ..conftest import PEPPER  # noqa: E402
from .conformance import T0, StoreContract, SyncOverAsync, make_record  # noqa: E402


class TestRedisStore(StoreContract):
    supports_concurrency = True

    @pytest.fixture
    def store(self):
        # fixture dates are in the past; retention would (correctly) evict them immediately
        return RedisStore(fakeredis.FakeRedis(), namespace="t", retention=None)


class TestAsyncRedisStore(StoreContract):
    @pytest.fixture
    def store(self):
        loop = asyncio.new_event_loop()
        s = SyncOverAsync(AsyncRedisStore(fakeredis.FakeAsyncRedis(), namespace="t", retention=None), loop)
        yield s
        loop.close()


def test_layout_and_expireat():
    from safe_api_keys._util import utcnow

    client = fakeredis.FakeRedis()
    s = RedisStore(client, namespace="ns")
    now = utcnow()
    rec = make_record(created_at=now, expires_at=now + timedelta(days=1))
    s.save(rec)
    assert client.exists("ns:key:AAAAAAAAAAAA")
    assert client.sismember("ns:owner:owner-1", "AAAAAAAAAAAA") and client.sismember("ns:all", "AAAAAAAAAAAA")
    ttl = client.ttl("ns:key:AAAAAAAAAAAA")
    assert abs(ttl - timedelta(days=31).total_seconds()) < 5  # expires_at + 30 days retention
    s.save(rec.replace(expires_at=None))
    assert client.ttl("ns:key:AAAAAAAAAAAA") == -1  # persisted
    s.save(rec.replace(expires_at=None, revoked_at=now - timedelta(days=31)))
    assert not client.exists("ns:key:AAAAAAAAAAAA")  # past retention: housekeeping removes it


def test_dangling_index_cleaned():
    client = fakeredis.FakeRedis()
    s = RedisStore(client, namespace="ns", retention=None)
    s.save(make_record())
    client.delete("ns:key:AAAAAAAAAAAA")  # as if EXPIREAT fired
    assert s.list(include_inactive=True, now=T0) == []
    assert not client.sismember("ns:all", "AAAAAAAAAAAA")


def test_managers_on_redis():
    km = KeyManager(RedisStore(fakeredis.FakeRedis()), "sk_test", pepper=PEPPER)
    i = km.issue("o")
    assert km.verify(i.raw_key).use_count == 1

    async def run():
        akm = AsyncKeyManager(AsyncRedisStore(fakeredis.FakeAsyncRedis()), "sk_test", pepper=PEPPER)
        j = await akm.issue("o")
        return (await akm.verify(j.raw_key)).use_count

    assert asyncio.run(run()) == 1
