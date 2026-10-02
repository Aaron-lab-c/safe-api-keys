from __future__ import annotations

import asyncio
import inspect
import os
from datetime import datetime, timedelta, timezone

import pytest

from safe_api_keys import AsyncKeyManager, KeyManager
from safe_api_keys.stores import MemoryStore

UTC = timezone.utc
PEPPER = b"test-pepper-32-bytes-xxxxxxxxxxxxx"
START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

try:  # Django-dependent tests use pytest-django with these settings
    import django  # noqa: F401

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.django_settings")
except ImportError:  # pragma: no cover
    pass


class Clock:
    def __init__(self, start: datetime = START) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> datetime:
        self.now += timedelta(**kw)
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def km(store, clock) -> KeyManager:
    return KeyManager(store, "sk_test", pepper=PEPPER, clock=clock)


class SyncFacade:
    """Drive an AsyncKeyManager through the synchronous API so one test body covers both."""

    def __init__(self, inner):
        self._inner = inner
        self._loop = asyncio.new_event_loop()

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if inspect.iscoroutinefunction(attr):
            def run(*a, **kw):
                return self._loop.run_until_complete(attr(*a, **kw))
            return run
        return attr

    def close_loop(self):
        self._loop.close()


@pytest.fixture(params=["sync", "async"])
def anykm(request, clock):
    """A KeyManager or a sync-driven AsyncKeyManager over the same kind of store."""
    store = MemoryStore()
    if request.param == "sync":
        yield KeyManager(store, "sk_test", pepper=PEPPER, clock=clock)
        return
    facade = SyncFacade(AsyncKeyManager(store, "sk_test", pepper=PEPPER, clock=clock))
    yield facade
    facade.close_loop()


def make_km(store=None, *, clock=None, **kw) -> KeyManager:
    kw.setdefault("pepper", PEPPER)
    return KeyManager(store if store is not None else MemoryStore(), kw.pop("prefix", "sk_test"), clock=clock, **kw)
