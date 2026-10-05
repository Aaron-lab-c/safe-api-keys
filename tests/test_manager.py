"""Manager behaviour. ``anykm`` runs each test against KeyManager and AsyncKeyManager (§20.2)."""

from datetime import timedelta
from unittest import mock

import pytest

from safe_api_keys import (
    AlreadyRotated,
    ExpiredKey,
    InsufficientScope,
    IPNotAllowed,
    IssuedKey,
    KeyManager,
    MalformedKey,
    NotSupported,
    RevokedKey,
    StoreError,
    UnknownKey,
)
from safe_api_keys.audit import CallbackAuditSink
from safe_api_keys.exceptions import INVALID_API_KEY_MESSAGE
from safe_api_keys.hashing import HmacSha256Hasher
from safe_api_keys.policy import KeyPolicy
from safe_api_keys.stores import MemoryStore

from .conftest import PEPPER, START, make_km


def test_issue_and_verify(anykm):
    issued = anykm.issue("user-1", scopes=["orders:read", "orders:read"], name="ci", metadata={"team": "x"},
                         expires_in=timedelta(days=30))
    assert isinstance(issued, IssuedKey)
    assert issued.record.scopes == ("orders:read",)
    assert issued.record.created_at == START and issued.record.expires_at == START + timedelta(days=30)
    rec = anykm.verify(issued.raw_key, scopes=["orders:read"])
    assert rec.owner == "user-1" and rec.metadata == {"team": "x"} and rec.use_count == 1


def test_issue_validation(anykm):
    with pytest.raises(ValueError):
        anykm.issue("")
    with pytest.raises(ValueError):
        anykm.issue("o", expires_in=timedelta(days=1), expires_at=START + timedelta(days=1))
    with pytest.raises(ValueError):
        anykm.issue("o", expires_at=START - timedelta(seconds=1))
    with pytest.raises(ValueError):
        anykm.issue("o", scopes=["BAD"])
    with pytest.raises(ValueError):
        anykm.issue("o", ip_allowlist=["nope"])
    with pytest.raises(ValueError):
        anykm.issue("o" * 256)
    import datetime as dt
    with pytest.raises(ValueError):
        anykm.issue("o", expires_at=dt.datetime(2030, 1, 1))  # naive


def test_injected_key_id(anykm):
    i = anykm.issue("o", key_id="ABCDEFGHIJKL")
    assert i.key_id == "ABCDEFGHIJKL"
    with pytest.raises(ValueError):
        anykm.issue("o", key_id="ABCDEFGHIJKL")


def test_key_id_collision_retry(km):
    taken = km.issue("o").key_id
    real = km.key_format.new_key_id
    # first value feeds the up-front validation pass, then two collisions, then a fresh id
    seq = iter(["VALIDATION00", taken, taken, "NEWNEWNEWNEW"])
    with mock.patch.object(type(km.key_format), "new_key_id", lambda self: next(seq)):
        assert km.issue("o").key_id == "NEWNEWNEWNEW"
    seq2 = iter([taken] * 4)
    with mock.patch.object(type(km.key_format), "new_key_id", lambda self: next(seq2)):
        with pytest.raises(StoreError):
            km.issue("o")
    assert real


def test_malformed_and_unknown_same_message(anykm):
    issued = anykm.issue("o")
    with pytest.raises(MalformedKey) as m:
        anykm.verify("sk_test_garbage")
    wrong = issued.raw_key[:20] + ("A" if issued.raw_key[20] != "A" else "B") + issued.raw_key[21:]
    with pytest.raises(MalformedKey):  # checksum catches it before the store
        anykm.verify(wrong)
    fmt = anykm.key_format
    forged, _ = fmt.build(issued.key_id, "x" * 32)
    with pytest.raises(UnknownKey) as u:
        anykm.verify(forged)
    assert u.value.reason == "bad_secret"
    unknown_raw, _ = fmt.build("ZZZZZZZZZZZZ", "y" * 32)
    with pytest.raises(UnknownKey) as u2:
        anykm.verify(unknown_raw)
    assert u2.value.reason == "unknown"
    assert str(m.value) == str(u.value) == str(u2.value) == INVALID_API_KEY_MESSAGE


def test_prefix_binding(store, clock):
    live = make_km(store, clock=clock, prefix="sk_live")
    test = make_km(store, clock=clock, prefix="sk_test")
    issued = live.issue("o")
    with pytest.raises(MalformedKey) as ei:
        test.verify(issued.raw_key)
    assert ei.value.reason == "prefix"


def test_checksum_failure_never_hits_store(clock):
    store = mock.Mock(wraps=MemoryStore())
    km = KeyManager(store, "sk_test", pepper=PEPPER, clock=clock)
    issued = km.issue("o")
    store.get.reset_mock()
    raw = issued.raw_key
    for i in range(len(raw)):
        bad = raw[:i] + ("0" if raw[i] != "0" else "1") + raw[i + 1:]
        with pytest.raises(MalformedKey):
            km.verify(bad)
    assert store.get.call_count == 0


class CountingHasher(HmacSha256Hasher):
    def __init__(self):
        super().__init__(PEPPER, "v1")
        self.calls = 0

    def verify(self, body, stored):
        self.calls += 1
        return super().verify(body, stored)


def test_unknown_and_wrong_secret_both_hash_once(clock):
    h = CountingHasher()
    km = KeyManager(MemoryStore(), "sk_test", hasher=h, clock=clock)
    issued = km.issue("o")
    with pytest.raises(UnknownKey):
        km.verify(km.key_format.build("ZZZZZZZZZZZZ", "y" * 32)[0])
    assert h.calls == 1
    with pytest.raises(UnknownKey):
        km.verify(km.key_format.build(issued.key_id, "y" * 32)[0])
    assert h.calls == 2


def test_revoked_and_expired(anykm, clock):
    a = anykm.issue("o", expires_in=timedelta(hours=1))
    b = anykm.issue("o")
    clock.advance(hours=1)
    with pytest.raises(ExpiredKey):
        anykm.verify(a.raw_key)
    rec = anykm.revoke(b.key_id, reason="compromised")
    assert rec.revoked_at == clock.now and rec.revoke_reason == "compromised"
    with pytest.raises(RevokedKey):
        anykm.verify(b.raw_key)


def test_reveal_state_false(clock):
    km = make_km(clock=clock, reveal_state=False)
    a = km.issue("o")
    km.revoke(a.key_id)
    with pytest.raises(UnknownKey) as ei:
        km.verify(a.raw_key)
    assert ei.value.error_code == "invalid_api_key" and ei.value.reason == "revoked"


def test_scope_and_ip(anykm):
    i = anykm.issue("o", scopes=["orders:*"], ip_allowlist=["10.0.0.0/8"])
    anykm.verify(i.raw_key, scopes=["orders:read"], client_ip="10.0.0.1")
    with pytest.raises(InsufficientScope) as ei:
        anykm.verify(i.raw_key, scopes=["users:read"], client_ip="10.0.0.1")
    assert ei.value.missing == ["users:read"]
    with pytest.raises(IPNotAllowed):
        anykm.verify(i.raw_key, client_ip="8.8.8.8")
    with pytest.raises(IPNotAllowed):
        anykm.verify(i.raw_key)


def test_check_does_not_raise(anykm):
    i = anykm.issue("o")
    ok = anykm.check(i.raw_key)
    assert ok.ok and ok.record.owner == "o" and bool(ok)
    bad = anykm.check("nope")
    assert not bad.ok and isinstance(bad.error, MalformedKey) and bad.record is None


def test_revoke_idempotent_and_by_raw(anykm, clock):
    i = anykm.issue("o")
    first = anykm.revoke(i.raw_key, reason="x")
    clock.advance(minutes=5)
    second = anykm.revoke(i.key_id, reason="y")
    assert first.revoked_at == second.revoked_at and second.revoke_reason == "x"
    with pytest.raises(UnknownKey):
        anykm.revoke("NOSUCHKEY123")


def test_rotate_grace(anykm, clock):
    old = anykm.issue("o", scopes=["a"], name="n", metadata={"m": 1}, ip_allowlist=["1.2.3.4"])
    new = anykm.rotate(old.key_id, grace=timedelta(hours=24), expires_in=timedelta(days=10))
    assert new.record.rotated_from == old.key_id and new.record.owner == "o"
    assert new.record.scopes == ("a",) and new.record.name == "n" and new.record.metadata == {"m": 1}
    assert new.record.ip_allowlist == ("1.2.3.4/32",)
    assert new.record.expires_at == START + timedelta(days=10)
    old_rec = anykm.get(old.key_id)
    assert old_rec.rotated_to == new.key_id and old_rec.expires_at == START + timedelta(hours=24)
    anykm.verify(old.raw_key, client_ip="1.2.3.4")
    anykm.verify(new.raw_key, client_ip="1.2.3.4")
    clock.advance(hours=24)
    with pytest.raises(ExpiredKey):
        anykm.verify(old.raw_key, client_ip="1.2.3.4")
    anykm.verify(new.raw_key, client_ip="1.2.3.4")


def test_rotate_keeps_earlier_expiry_and_zero_grace(anykm):
    a = anykm.issue("o", expires_in=timedelta(hours=1))
    anykm.rotate(a.key_id, grace=timedelta(days=2))
    assert anykm.get(a.key_id).expires_at == START + timedelta(hours=1)
    b = anykm.issue("o")
    nb = anykm.rotate(b.raw_key, grace=timedelta(0))
    with pytest.raises(RevokedKey):
        anykm.verify(b.raw_key)
    anykm.verify(nb.raw_key)
    with pytest.raises(RevokedKey):
        anykm.rotate(b.key_id)
    with pytest.raises(UnknownKey):
        anykm.rotate("NOSUCHKEY123")


def test_rotate_inherits_lifetime_by_default(anykm, clock):
    """The new key gets the old key's lifetime counted from now, unless told otherwise."""
    a = anykm.issue("o", expires_in=timedelta(days=30))
    clock.advance(days=20)
    na = anykm.rotate(a.key_id)
    assert na.record.expires_at == START + timedelta(days=50)        # 30 days from the rotation, not 10
    nb = anykm.rotate(na.key_id, expires_in=timedelta(days=90))      # explicit lifetime still wins
    assert nb.record.expires_at == START + timedelta(days=110)
    perpetual = anykm.issue("o")
    assert anykm.rotate(perpetual.key_id).record.expires_at is None  # no expiry -> policy default (none here)


def test_rotate_inherited_lifetime_capped_by_policy(clock):
    km = make_km(clock=clock, policy=KeyPolicy(max_ttl=timedelta(days=365)))
    a = km.issue("o", expires_in=timedelta(days=300))
    km.policy = KeyPolicy(max_ttl=timedelta(days=30))                 # policy tightened after issuance
    assert km.rotate(a.key_id).record.expires_at == START + timedelta(days=30)


def test_rotate_refuses_expired_key(anykm, clock):
    a = anykm.issue("o", expires_in=timedelta(hours=1))
    clock.advance(hours=1)
    with pytest.raises(ExpiredKey):
        anykm.rotate(a.key_id)
    assert anykm.get(a.key_id).rotated_to is None
    assert anykm.list("o", include_inactive=True) == [anykm.get(a.key_id)]  # no replacement was written


def test_rotate_refuses_already_rotated_key(anykm):
    a = anykm.issue("o", expires_in=timedelta(days=90))
    b = anykm.rotate(a.key_id, grace=timedelta(hours=24))
    with pytest.raises(AlreadyRotated) as ei:                      # still valid in its grace period, but...
        anykm.rotate(a.key_id)
    assert ei.value.key_id == a.key_id and ei.value.rotated_to == b.key_id
    assert anykm.get(a.key_id).rotated_to == b.key_id               # lineage intact, no orphan key
    assert len(anykm.list("o", include_inactive=True)) == 2
    anykm.rotate(b.key_id)                                           # the replacement rotates normally


def test_rotate_loses_to_concurrent_revoke(clock):
    """revoke() between rotate()'s read and its write must win: the old key stays revoked, no new key."""
    store = MemoryStore()
    km = make_km(store, clock=clock)
    old = km.issue("o")
    real_get = store.get

    def get_then_revoke_elsewhere(key_id):
        rec = real_get(key_id)
        if rec is not None and rec.key_id == old.key_id and rec.revoked_at is None:
            store.save(rec.replace(revoked_at=clock(), revoke_reason="compromised"))  # another process
        return rec

    store.get = get_then_revoke_elsewhere
    with pytest.raises(RevokedKey):
        km.rotate(old.key_id)
    after = real_get(old.key_id)
    assert after.revoked_at is not None and after.revoke_reason == "compromised" and after.rotated_to is None
    assert len(store.list(include_inactive=True)) == 1


def test_rotate_loses_to_concurrent_revoke_without_save_rotation(clock):
    """Stores without save_rotation() get a best-effort re-check right before the write."""

    class Plain(MemoryStore):
        save_many = save_rotation = None

    store = Plain()
    km = make_km(store, clock=clock)
    old = km.issue("o")
    real_get = store.get
    calls = []

    def racy_get(key_id):
        rec = real_get(key_id)
        if rec is not None and rec.key_id == old.key_id:
            calls.append(key_id)
            if len(calls) == 1:  # revoked after rotate() read it, before it re-checks
                store.save(rec.replace(revoked_at=clock(), revoke_reason="compromised"))
        return rec

    store.get = racy_get
    with pytest.raises(RevokedKey):
        km.rotate(old.key_id)
    assert real_get(old.key_id).revoked_at is not None and len(store.list(include_inactive=True)) == 1


def test_lineage(anykm):
    a = anykm.issue("o")
    b = anykm.rotate(a.key_id)
    c = anykm.rotate(b.key_id)
    for k in (a, b, c):
        assert [r.key_id for r in anykm.lineage(k.key_id)] == [a.key_id, b.key_id, c.key_id]


def test_list_delete_purge_count(anykm, clock):
    a = anykm.issue("u1")
    b = anykm.issue("u1", expires_in=timedelta(days=1))
    c = anykm.issue("u2")
    anykm.revoke(c.key_id)
    assert {r.key_id for r in anykm.list()} == {a.key_id, b.key_id}
    assert {r.key_id for r in anykm.list("u1")} == {a.key_id, b.key_id}
    assert {r.key_id for r in anykm.list(include_inactive=True)} == {a.key_id, b.key_id, c.key_id}
    clock.advance(days=2)
    assert {r.key_id for r in anykm.list()} == {a.key_id}
    assert anykm.purge(older_than=timedelta(days=3)) == 0
    clock.advance(days=5)
    assert anykm.purge(older_than=timedelta(days=3)) == 2
    assert anykm.count_by_hash_alg() == {"hmac-sha256$v1": 1}
    anykm.delete(a.key_id)
    assert anykm.get(a.key_id) is None


def test_touch_throttled(clock):
    store = mock.Mock(wraps=MemoryStore())
    km = KeyManager(store, "sk_test", pepper=PEPPER, clock=clock, touch_interval=60)
    i = km.issue("o")
    for _ in range(5):
        km.verify(i.raw_key)
    assert store.touch.call_count == 1
    clock.advance(seconds=60)
    km.verify(i.raw_key)
    assert store.touch.call_count == 2
    km.verify(i.raw_key, touch=False)
    assert store.touch.call_count == 2
    rec = km.get(i.key_id)
    assert rec.use_count == 2 and rec.last_used_at == clock.now


def test_touch_modes(clock):
    km0 = make_km(clock=clock, touch_interval=0)
    i = km0.issue("o")
    for _ in range(3):
        km0.verify(i.raw_key)
    assert km0.get(i.key_id).use_count == 3
    kmn = make_km(clock=clock, touch_interval=None)
    j = kmn.issue("o")
    kmn.verify(j.raw_key)
    assert kmn.get(j.key_id).use_count == 0
    with pytest.raises(Exception):
        make_km(touch_interval=-1)


def test_touch_failure_is_swallowed(clock):
    events = []

    class BrokenTouch(MemoryStore):
        def touch(self, key_id, when):
            raise RuntimeError("db down")

    km = make_km(BrokenTouch(), clock=clock, audit=CallbackAuditSink(events.append))
    i = km.issue("o")
    assert km.verify(i.raw_key).owner == "o"
    assert "key.touch_failed" in [e.type for e in events]


def test_store_errors_wrapped(clock):
    class Broken(MemoryStore):
        def get(self, key_id):
            raise ConnectionError("boom")

    km = make_km(Broken(), clock=clock)
    with pytest.raises(StoreError) as ei:
        km.verify(km.key_format.build("ZZZZZZZZZZZZ", "y" * 32)[0])
    assert isinstance(ei.value.__cause__, ConnectionError)
    with pytest.raises(StoreError):
        km.check(km.key_format.build("ZZZZZZZZZZZZ", "y" * 32)[0])


def test_not_supported(clock):
    class Minimal:
        def __init__(self):
            self.m = MemoryStore()

        def get(self, k):
            return self.m.get(k)

        def save(self, r):
            self.m.save(r)

        def touch(self, k, w):
            self.m.touch(k, w)

    km = make_km(Minimal(), clock=clock)
    i = km.issue("o")
    assert km.verify(i.raw_key)
    for call in (lambda: km.list(), lambda: km.delete("x"), lambda: km.purge(older_than=timedelta(1)),
                 lambda: km.count_by_hash_alg()):
        with pytest.raises(NotSupported):
            call()


def test_rotate_partial_failure(clock):
    events = []

    class FailSecondSave(MemoryStore):
        save_many = save_rotation = None  # force the non-transactional path

        def save(self, record):
            if record.rotated_to:
                raise RuntimeError("write failed")
            super().save(record)

    store = FailSecondSave()
    km = make_km(store, clock=clock, audit=CallbackAuditSink(events.append))
    old = km.issue("o")
    with pytest.raises(StoreError):
        km.rotate(old.key_id)
    assert "key.rotate_partial" in [e.type for e in events]
    new_id = [e for e in events if e.type == "key.rotate_partial"][0].extra["rotated_to"]
    assert store.get(new_id) is not None  # new key valid; caller can revoke(old)
