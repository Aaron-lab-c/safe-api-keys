import asyncio

import pytest

sa = pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from safe_api_keys import AsyncKeyManager  # noqa: E402
from safe_api_keys.stores import AsyncSQLAlchemyStore  # noqa: E402

from ..conftest import PEPPER  # noqa: E402
from .conformance import StoreContract, SyncOverAsync  # noqa: E402


class TestAsyncSQLAlchemy(StoreContract):
    @pytest.fixture
    def store(self, tmp_path):
        loop = asyncio.new_event_loop()
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}")
        inner = AsyncSQLAlchemyStore(sessionmaker(engine, class_=AsyncSession, expire_on_commit=False))
        loop.run_until_complete(inner.create_table(engine))
        yield SyncOverAsync(inner, loop)
        loop.run_until_complete(engine.dispose())
        loop.close()


async def test_async_manager_with_async_sqlalchemy(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'b.db'}")
    store = AsyncSQLAlchemyStore(sessionmaker(engine, class_=AsyncSession, expire_on_commit=False))
    await store.create_table(engine)
    km = AsyncKeyManager(store, "sk_test", pepper=PEPPER)
    issued = await km.issue("o", scopes=["a"])
    new = await km.rotate(issued.key_id)  # save_many: one transaction
    assert (await km.verify(new.raw_key, scopes=["a"])).rotated_from == issued.key_id
    await engine.dispose()
