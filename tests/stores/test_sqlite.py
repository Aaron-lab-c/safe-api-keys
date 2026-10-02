import sqlite3

import pytest

from safe_api_keys import StoreError
from safe_api_keys.stores import SQLiteStore, from_url

from .conformance import StoreContract, make_record


class TestSQLiteFile(StoreContract):
    supports_concurrency = True

    @pytest.fixture
    def store(self, tmp_path):
        s = SQLiteStore(str(tmp_path / "keys.db"))
        yield s
        s.close()


class TestSQLiteMemory(StoreContract):
    supports_concurrency = True

    @pytest.fixture
    def store(self):
        return SQLiteStore(":memory:", table="custom_keys")


def test_table_auto_created_and_wal(tmp_path):
    path = tmp_path / "k.db"
    s = SQLiteStore(str(path))
    s.save(make_record())
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    cols = [r[1] for r in conn.execute("PRAGMA table_info(safe_api_keys)")]
    assert cols[:3] == ["key_id", "prefix", "hash"] and "metadata" in cols
    row = conn.execute("SELECT created_at, scopes FROM safe_api_keys").fetchone()
    assert row[0] == "2026-03-04T05:06:07.123456+00:00" and row[1].startswith("[")
    conn.close()
    s.close()


def test_invalid_table_name():
    with pytest.raises(ValueError):
        SQLiteStore(":memory:", table="x; drop table y")


def test_errors_wrapped():
    s = SQLiteStore(":memory:")
    s.close()
    with pytest.raises(StoreError):
        s.get("AAAAAAAAAAAA")


def test_from_url(tmp_path):
    s = from_url(f"sqlite:///{tmp_path / 'u.db'}")
    assert isinstance(s, SQLiteStore)
    s.close()
    assert type(from_url("memory://")).__name__ == "MemoryStore"
