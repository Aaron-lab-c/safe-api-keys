import os

import pytest

sa = pytest.importorskip("sqlalchemy")
from sqlalchemy.orm import declarative_base, sessionmaker  # noqa: E402

from safe_api_keys import KeyManager  # noqa: E402
from safe_api_keys.stores import APIKeyMixin, SQLAlchemyStore, from_url, make_api_key_table  # noqa: E402

from ..conftest import PEPPER  # noqa: E402
from .conformance import StoreContract, make_record  # noqa: E402

PG_URL = os.environ.get("SAFE_API_KEYS_TEST_PG_URL")  # e.g. postgresql+psycopg://postgres:pg@localhost/test


def _store(url, **engine_kw):
    engine = sa.create_engine(url, **engine_kw)
    md = sa.MetaData()
    table = make_api_key_table(md)
    md.drop_all(engine)
    md.create_all(engine)
    return SQLAlchemyStore(sessionmaker(bind=engine), table=table), engine


class TestSQLAlchemySQLite(StoreContract):
    supports_concurrency = True

    @pytest.fixture
    def store(self, tmp_path):
        s, engine = _store(f"sqlite:///{tmp_path / 'sa.db'}", connect_args={"timeout": 30})
        yield s
        engine.dispose()


@pytest.mark.skipif(not PG_URL, reason="set SAFE_API_KEYS_TEST_PG_URL to run against PostgreSQL")
class TestSQLAlchemyPostgres(StoreContract):
    supports_concurrency = True

    @pytest.fixture
    def store(self):
        s, engine = _store(PG_URL)
        yield s
        engine.dispose()


def test_default_table_and_create_table(tmp_path):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'd.db'}")
    store = SQLAlchemyStore(sessionmaker(bind=engine))
    store.create_table(engine)
    store.create_table(engine)  # idempotent
    assert sa.inspect(engine).has_table("safe_api_keys")
    km = KeyManager(store, "sk_test", pepper=PEPPER)
    assert km.verify(km.issue("o").raw_key).owner == "o"
    engine.dispose()


def test_make_table_idempotent_and_named():
    md = sa.MetaData()
    t1 = make_api_key_table(md, "api_keys")
    assert make_api_key_table(md, "api_keys") is t1
    assert {c.name for c in t1.columns} >= {"key_id", "metadata", "ip_allowlist", "use_count"}
    assert t1.c.owner.index and t1.c.expires_at.index


def test_declarative_mixin(tmp_path):
    Base = declarative_base()

    class APIKey(APIKeyMixin, Base):
        __tablename__ = "my_api_keys"

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    store = SQLAlchemyStore(sessionmaker(bind=engine), table=APIKey)
    rec = make_record()
    store.save(rec)
    assert store.get(rec.key_id) == rec
    with sessionmaker(bind=engine)() as s:
        obj = s.get(APIKey, rec.key_id)
        assert obj.metadata_["team"] == "billing" and obj.owner == "owner-1"
    engine.dispose()


def test_from_url_creates_table(tmp_path):
    store = from_url(f"sqlalchemy+sqlite:///{tmp_path / 'u.db'}")
    store.save(make_record())
    assert store.get("AAAAAAAAAAAA") is not None
