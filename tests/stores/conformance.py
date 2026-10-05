"""``StoreContract``: behaviour every backend must satisfy (§12.2, §20.3).

Subclass it and provide a ``store`` fixture returning a *synchronous-looking* store
(async stores are wrapped with :class:`SyncOverAsync`).
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from datetime import datetime, timedelta, timezone

import pytest

from safe_api_keys.models import KeyRecord

UTC = timezone.utc
T0 = datetime(2026, 3, 4, 5, 6, 7, 123456, tzinfo=UTC)


class SyncOverAsync:
    def __init__(self, inner, loop=None):
        self.inner = inner
        self.loop = loop or asyncio.new_event_loop()

    def __getattr__(self, name):
        attr = getattr(self.inner, name)
        if callable(attr) and (inspect.iscoroutinefunction(attr) or name in
                               ("get", "save", "touch", "list", "delete", "purge", "count_by_hash_alg",
                                "save_many", "save_rotation", "update_fields", "close")):
            def run(*a, **kw):
                res = attr(*a, **kw)
                return self.loop.run_until_complete(res) if inspect.isawaitable(res) else res
            return run
        return attr


def make_record(key_id="AAAAAAAAAAAA", **kw) -> KeyRecord:
    data = dict(
        key_id=key_id, prefix="sk_test", hash="ab" * 32, hash_alg="hmac-sha256$v1", secret_last4="wxyz",
        owner="owner-1", created_at=T0, name="CI key — 測試", scopes=("orders:read", "reports:*"),
        expires_at=T0 + timedelta(days=30), revoked_at=None, revoke_reason=None, last_used_at=None, use_count=0,
        rotated_from=None, rotated_to=None, ip_allowlist=("10.0.0.0/8", "2001:db8::/32"),
        metadata={"team": "billing", "nested": {"a": [1, 2, {"b": True}]}, "n": 1.5},
    )
    data.update(kw)
    return KeyRecord(**data)


class StoreContract:
    supports_concurrency = False

    # -- basic --------------------------------------------------------------------
    def test_get_missing_returns_none(self, store):
        assert store.get("NOPENOPENOPE") is None

    def test_round_trip_preserves_types(self, store):
        rec = make_record(last_used_at=T0 + timedelta(seconds=1), use_count=7, revoked_at=T0 + timedelta(hours=1),
                          revoke_reason="compromised", rotated_from="PREVPREVPREV", rotated_to="NEXTNEXTNEXT")
        store.save(rec)
        got = store.get(rec.key_id)
        assert got == rec
        assert isinstance(got.scopes, tuple) and isinstance(got.ip_allowlist, tuple)
        assert isinstance(got.metadata, dict)
        for name in ("created_at", "expires_at", "revoked_at", "last_used_at"):
            v = getattr(got, name)
            assert v.tzinfo is not None and v.utcoffset() == timedelta(0)

    def test_round_trip_minimal(self, store):
        rec = make_record(name="", scopes=(), ip_allowlist=(), metadata={}, expires_at=None)
        store.save(rec)
        assert store.get(rec.key_id) == rec

    def test_save_is_upsert(self, store):
        rec = make_record()
        store.save(rec)
        store.save(rec.replace(name="renamed", scopes=("x",)))
        got = store.get(rec.key_id)
        assert got.name == "renamed" and got.scopes == ("x",)

    def test_save_many(self, store):
        if not callable(getattr(store, "save_many", None)):
            pytest.skip("no save_many")
        a, b = make_record("AAAAAAAAAAAA"), make_record("BBBBBBBBBBBB")
        store.save_many([a, b])
        assert store.get(a.key_id) == a and store.get(b.key_id) == b

    # -- touch ---------------------------------------------------------------------
    def test_touch_is_partial_update(self, store):
        rec = make_record()
        store.save(rec)
        store.save(rec.replace(revoked_at=T0 + timedelta(minutes=1), revoke_reason="r"))
        store.touch(rec.key_id, T0 + timedelta(minutes=2))
        got = store.get(rec.key_id)
        assert got.revoked_at == T0 + timedelta(minutes=1) and got.revoke_reason == "r"
        assert got.last_used_at == T0 + timedelta(minutes=2) and got.use_count == 1
        store.touch(rec.key_id, T0 + timedelta(minutes=3))
        assert store.get(rec.key_id).use_count == 2

    def test_touch_missing_is_noop(self, store):
        store.touch("MISSINGMISSI", T0)
        assert store.get("MISSINGMISSI") is None

    def test_concurrent_touch(self, store):
        if not self.supports_concurrency:
            pytest.skip("concurrency checked on SQL backends")
        rec = make_record()
        store.save(rec)
        errors = []

        def worker():
            try:
                for _ in range(100):
                    store.touch(rec.key_id, T0)
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert store.get(rec.key_id).use_count == 800

    # -- save_rotation -------------------------------------------------------------
    def test_save_rotation_is_partial_update(self, store):
        old = make_record("OLDOLDOLDOLD", expires_at=None)
        store.save(old)
        store.touch(old.key_id, T0 + timedelta(minutes=1))  # concurrent usage must survive the rotation write
        new = make_record("NEWNEWNEWNEW", rotated_from=old.key_id)
        planned = old.replace(rotated_to=new.key_id, expires_at=T0 + timedelta(days=1))
        assert store.save_rotation(new, planned) is True
        got = store.get(old.key_id)
        assert got.rotated_to == new.key_id and got.expires_at == T0 + timedelta(days=1)
        assert got.use_count == 1 and got.last_used_at == T0 + timedelta(minutes=1) and got.revoked_at is None
        assert store.get(new.key_id) == new
        # already rotated: a second rotation (double click / concurrent request) is refused, nothing written
        other = make_record("OTHEROTHEROT", rotated_from=old.key_id)
        assert store.save_rotation(other, got.replace(rotated_to=other.key_id)) is False
        assert store.get(old.key_id).rotated_to == new.key_id and store.get(other.key_id) is None
        # grace == 0: the plan revokes the old key in the same write
        old2 = make_record("OLD2OLD2OLD2", expires_at=None)
        store.save(old2)
        newer = make_record("NEWERNEWERNE", rotated_from=old2.key_id)
        planned = old2.replace(rotated_to=newer.key_id, revoked_at=T0 + timedelta(hours=2), revoke_reason="rotated")
        assert store.save_rotation(newer, planned) is True
        got = store.get(old2.key_id)
        assert got.rotated_to == newer.key_id and got.revoked_at == T0 + timedelta(hours=2)
        assert got.revoke_reason == "rotated" and store.get(newer.key_id) == newer

    def test_save_rotation_refuses_revoked_or_missing(self, store):
        old = make_record("OLDOLDOLDOLD")
        store.save(old.replace(revoked_at=T0 + timedelta(minutes=5), revoke_reason="compromised"))
        new = make_record("NEWNEWNEWNEW", rotated_from=old.key_id)
        planned = old.replace(rotated_to=new.key_id, expires_at=T0 + timedelta(days=1))
        assert store.save_rotation(new, planned) is False
        got = store.get(old.key_id)
        assert got.revoked_at == T0 + timedelta(minutes=5) and got.revoke_reason == "compromised"
        assert got.rotated_to is None and got.expires_at == old.expires_at   # untouched
        assert store.get(new.key_id) is None                                  # nothing written
        missing = make_record("GONEGONEGONE").replace(rotated_to=new.key_id)
        assert store.save_rotation(new, missing) is False
        assert store.get(new.key_id) is None

    # -- update_fields -------------------------------------------------------------
    def test_update_fields_is_partial_and_conditional(self, store):
        rec = make_record(expires_at=None)
        store.save(rec)
        store.touch(rec.key_id, T0 + timedelta(minutes=1))  # concurrent usage must survive the update
        ok = store.update_fields(rec.key_id, {"scopes": ("orders:write",), "expires_at": T0 + timedelta(days=2),
                                              "ip_allowlist": (), "name": "renamed", "metadata": {"k": [1]}},
                                 clock=lambda: T0)
        assert ok is True
        got = store.get(rec.key_id)
        assert got.scopes == ("orders:write",) and got.expires_at == T0 + timedelta(days=2)
        assert got.ip_allowlist == () and got.name == "renamed" and got.metadata == {"k": [1]}
        assert got.use_count == 1 and got.last_used_at == T0 + timedelta(minutes=1)
        assert got.hash == rec.hash and got.owner == rec.owner and got.revoked_at is None
        assert store.update_fields(rec.key_id, {}, clock=lambda: T0) is True                 # no-op on a live key
        assert store.update_fields("MISSINGMISSI", {"name": "x"}, clock=lambda: T0) is False
        # expired at write time: refused (the key must not be revived by moving its expiry)
        assert store.update_fields(rec.key_id, {"expires_at": T0 + timedelta(days=30)},
                                   clock=lambda: T0 + timedelta(days=2)) is False
        assert store.update_fields(rec.key_id, {}, clock=lambda: T0 + timedelta(days=2)) is False
        assert store.get(rec.key_id).expires_at == T0 + timedelta(days=2)
        # rotated meanwhile: refused (the grace period must not be extended)
        store.save(got.replace(rotated_to="NEXTNEXTNEXT"))
        assert store.update_fields(rec.key_id, {"expires_at": T0 + timedelta(days=30)}, clock=lambda: T0) is False
        assert store.get(rec.key_id).expires_at == T0 + timedelta(days=2)
        # revoked: refused
        store.save(got.replace(revoked_at=T0 + timedelta(hours=1), revoke_reason="r"))
        assert store.update_fields(rec.key_id, {"name": "after-revoke"}, clock=lambda: T0) is False
        assert store.get(rec.key_id).name == "renamed"
        with pytest.raises(ValueError):
            store.update_fields(rec.key_id, {"hash": "x" * 64}, clock=lambda: T0)             # not an updatable column

    # -- optional ops ------------------------------------------------------------
    def _seed(self, store):
        now = T0 + timedelta(days=10)
        recs = {
            "active": make_record("ACTIVEACTIVE", owner="u1", expires_at=None),
            "active2": make_record("ACTIVE2ACTIV", owner="u2", expires_at=now + timedelta(days=1),
                                   created_at=T0 + timedelta(seconds=1)),
            "expired": make_record("EXPIREDEXPIR", owner="u1", expires_at=now - timedelta(days=1)),
            "revoked": make_record("REVOKEDREVOK", owner="u1", expires_at=None, revoked_at=now - timedelta(days=3),
                                   hash_alg="hmac-sha256$v2"),
        }
        for r in recs.values():
            store.save(r)
        return now, recs

    def test_list(self, store):
        now, recs = self._seed(store)
        ids = lambda rows: sorted(r.key_id for r in rows)  # noqa: E731
        assert ids(store.list(now=now)) == sorted([recs["active"].key_id, recs["active2"].key_id])
        assert ids(store.list("u1", now=now)) == [recs["active"].key_id]
        assert ids(store.list("u1", include_inactive=True, now=now)) == sorted(
            [recs["active"].key_id, recs["expired"].key_id, recs["revoked"].key_id])
        assert len(store.list(include_inactive=True, now=now)) == 4
        assert store.list("nobody", include_inactive=True, now=now) == []
        assert all(isinstance(r, KeyRecord) for r in store.list(include_inactive=True, now=now))

    def test_delete(self, store):
        rec = make_record()
        store.save(rec)
        store.delete(rec.key_id)
        assert store.get(rec.key_id) is None
        store.delete(rec.key_id)  # idempotent
        assert store.list(include_inactive=True, now=T0) == []

    def test_purge(self, store):
        now, recs = self._seed(store)
        assert store.purge(before=now - timedelta(days=5)) == 0
        assert store.purge(before=now - timedelta(hours=12)) == 2  # expired (1d ago) + revoked (3d ago)
        remaining = sorted(r.key_id for r in store.list(include_inactive=True, now=now))
        assert remaining == sorted([recs["active"].key_id, recs["active2"].key_id])

    def test_count_by_hash_alg(self, store):
        self._seed(store)
        assert store.count_by_hash_alg() == {"hmac-sha256$v1": 3, "hmac-sha256$v2": 1}
