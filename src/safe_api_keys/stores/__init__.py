"""Storage backends.

``MemoryStore`` and ``SQLiteStore`` need only the standard library. The others import
their dependency lazily and raise :class:`MissingDependency` with the right ``pip install`` hint.
"""

from __future__ import annotations

import importlib
from typing import Any
from urllib.parse import unquote, urlparse

from ..exceptions import ConfigurationError
from .base import AsyncKeyStore, AsyncStoreAdapter, KeyStore
from .memory import AsyncMemoryStore, MemoryStore
from .sqlite import SQLiteStore

__all__ = [
    "KeyStore", "AsyncKeyStore", "AsyncStoreAdapter", "MemoryStore", "AsyncMemoryStore", "SQLiteStore",
    "SQLAlchemyStore", "AsyncSQLAlchemyStore", "make_api_key_table", "APIKeyMixin",
    "RedisStore", "AsyncRedisStore", "DjangoStore", "from_url",
]

_LAZY = {
    "SQLAlchemyStore": "sqlalchemy", "AsyncSQLAlchemyStore": "sqlalchemy", "make_api_key_table": "sqlalchemy",
    "APIKeyMixin": "sqlalchemy",
    "RedisStore": "redis", "AsyncRedisStore": "redis",
    "DjangoStore": "django",
}


def __getattr__(name: str) -> Any:
    mod = _LAZY.get(name)
    if mod is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(f"{__name__}.{mod}"), name)


def from_url(url: str, **kwargs: Any) -> Any:
    """Build a store from a URL.

    * ``memory://``
    * ``sqlite:///relative/path.db`` / ``sqlite:////abs/path.db`` / ``sqlite:///:memory:``
    * ``redis://host:6379/0`` (``rediss://`` too); ``?namespace=apikeys``
    * ``sqlalchemy+<dialect>://...`` e.g. ``sqlalchemy+postgresql://user:pw@host/db``;
      the table is created if missing.
    """
    if not url:
        raise ConfigurationError("store URL is empty")
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme == "memory":
        return MemoryStore()
    if scheme == "sqlite":
        path = unquote(url[len("sqlite:///"):]) if url.startswith("sqlite:///") else ""
        if not path:
            raise ConfigurationError("sqlite URL must look like sqlite:///path/to/db.sqlite")
        return SQLiteStore(path, **kwargs)
    if scheme in ("redis", "rediss", "unix"):
        try:
            import redis
        except ImportError:
            from ..exceptions import MissingDependency

            raise MissingDependency("pip install safe-api-keys[redis]") from None
        from urllib.parse import parse_qs

        from .redis import RedisStore

        qs = parse_qs(parsed.query)
        ns = qs.pop("namespace", ["apikeys"])[0]
        clean = url.split("?", 1)[0]
        return RedisStore(redis.Redis.from_url(clean), namespace=ns, **kwargs)
    if scheme.startswith("sqlalchemy+"):
        import sqlalchemy as sa
        from sqlalchemy.orm import sessionmaker

        from .sqlalchemy import SQLAlchemyStore

        engine = sa.create_engine(url[len("sqlalchemy+"):])
        store = SQLAlchemyStore(sessionmaker(bind=engine), **kwargs)
        store.create_table(engine)
        return store
    raise ConfigurationError(f"unsupported store URL scheme {parsed.scheme!r}")
