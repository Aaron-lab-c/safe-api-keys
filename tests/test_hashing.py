import warnings
from datetime import timedelta

import pytest

from safe_api_keys import (
    Argon2Hasher,
    ConfigurationError,
    HmacSha256Hasher,
    KeyManager,
    KeyPolicy,
    Sha256Hasher,
    UnknownKey,
)
from safe_api_keys.audit import CallbackAuditSink
from safe_api_keys.hashing import DUMMY_HASH, HasherRegistry
from safe_api_keys.stores import MemoryStore

from .conftest import PEPPER

BODY = "sk_test_AAAAAAAAAAAA_" + "b" * 32


def test_hmac_deterministic_and_peppered():
    a = HmacSha256Hasher(PEPPER, "v1")
    b = HmacSha256Hasher(b"another-pepper-of-32-bytes-xxxxxx", "v1")
    assert a.hash(BODY) == a.hash(BODY)
    assert a.hash(BODY) != b.hash(BODY)
    assert len(a.hash(BODY)) == 64 and a.hash(BODY) == a.hash(BODY).lower()
    assert a.verify(BODY, a.hash(BODY)) and not a.verify(BODY, b.hash(BODY))
    assert a.alg_id == "hmac-sha256$v1"
    assert "pepper" not in repr(a).lower() or PEPPER.decode() not in repr(a)


def test_sha256_fallback():
    h = Sha256Hasher()
    assert h.alg_id == "sha256$v0" and h.verify(BODY, h.hash(BODY))


@pytest.mark.parametrize("pepper", [b"short", b"x" * 15, "a-string-pepper-that-is-long-enough"])
def test_short_or_str_pepper_rejected(pepper):
    with pytest.raises(ConfigurationError):
        HmacSha256Hasher(pepper)  # type: ignore[arg-type]


def test_registry_build_validation():
    with pytest.raises(ConfigurationError):
        HasherRegistry.build(peppers={"v1": PEPPER, "v2": PEPPER})  # current required
    with pytest.raises(ConfigurationError):
        HasherRegistry.build(peppers={"v1": PEPPER}, current_pepper="v9")
    with pytest.raises(ConfigurationError):
        HasherRegistry.build(pepper=PEPPER, peppers={"v1": PEPPER})
    reg, has = HasherRegistry.build(peppers={"v2": PEPPER, "v1": PEPPER}, current_pepper="v2")
    assert has and reg.current.alg_id == "hmac-sha256$v2" and reg.get("hmac-sha256$v1") is not None


def test_alg_id_written_to_record(km):
    rec = km.issue("o").record
    assert rec.hash_alg == "hmac-sha256$v1" and len(rec.hash) == 64


def test_multi_pepper_rotation(clock):
    store = MemoryStore()
    old = KeyManager(store, "sk_test", peppers={"v1": PEPPER}, current_pepper="v1", clock=clock)
    k1 = old.issue("o")
    new = KeyManager(store, "sk_test", peppers={"v2": b"brand-new-pepper-v2-xxxxxxxxxxxxx", "v1": PEPPER},
                     current_pepper="v2", clock=clock)
    k2 = new.issue("o")
    assert k2.record.hash_alg == "hmac-sha256$v2"
    assert new.verify(k1.raw_key).key_id == k1.key_id  # v1 key still verifies
    assert new.count_by_hash_alg() == {"hmac-sha256$v1": 1, "hmac-sha256$v2": 1}

    events = []
    dropped = KeyManager(store, "sk_test", peppers={"v2": b"brand-new-pepper-v2-xxxxxxxxxxxxx"},
                         clock=clock, audit=CallbackAuditSink(events.append))
    with pytest.raises(UnknownKey) as ei:
        dropped.verify(k1.raw_key)
    assert ei.value.reason == "pepper_version_missing"
    assert events[-1].type == "key.rejected" and events[-1].reason == "pepper_version_missing"
    assert dropped.verify(k2.raw_key)


def test_no_pepper_requires_explicit_opt_out():
    with pytest.raises(ConfigurationError):
        KeyManager(MemoryStore(), "sk_test")
    with pytest.warns(UserWarning, match="pepper"):
        km = KeyManager(MemoryStore(), "sk_test", policy=KeyPolicy(require_pepper=False))
    rec = km.issue("o").record
    assert rec.hash_alg == "sha256$v0"


def test_dummy_hash_constant():
    assert len(DUMMY_HASH) == 64


def test_argon2_hasher(clock):
    pytest.importorskip("argon2")
    h = Argon2Hasher(PEPPER, time_cost=1, memory_cost=8, parallelism=1)
    stored = h.hash(BODY)
    assert h.verify(BODY, stored) and not h.verify(BODY + "x", stored) and not h.verify(BODY, "garbage")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        km = KeyManager(MemoryStore(), "sk_test", hasher=h, clock=clock)
    issued = km.issue("o", expires_in=timedelta(days=1))
    assert issued.record.hash_alg == "argon2id$v1"
    assert km.verify(issued.raw_key).owner == "o"
    with pytest.raises(UnknownKey):
        km.verify(km.key_format.build(issued.key_id, "A" * 32)[0])
