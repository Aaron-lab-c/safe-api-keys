import pytest

from safe_api_keys.stores import AsyncMemoryStore, MemoryStore

from .conformance import StoreContract, SyncOverAsync, make_record


class TestMemoryStore(StoreContract):
    supports_concurrency = True

    @pytest.fixture
    def store(self):
        return MemoryStore()


class TestAsyncMemoryStore(StoreContract):
    @pytest.fixture
    def store(self):
        s = SyncOverAsync(AsyncMemoryStore())
        yield s
        s.loop.close()


def test_memory_store_copies():
    s = MemoryStore()
    rec = make_record()
    s.save(rec)
    got = s.get(rec.key_id)
    got.metadata["team"] = "mutated"
    assert s.get(rec.key_id).metadata["team"] == "billing"
