import pytest

from safe_api_keys import ConfigurationError, KeyManager, KeyVerifier, UnknownKey
from safe_api_keys.stores import MemoryStore

from .conftest import PEPPER


class GetTouchOnly:
    """Least-privilege store: only what a verifier needs."""

    def __init__(self, inner):
        self.inner = inner

    def get(self, key_id):
        return self.inner.get(key_id)

    def touch(self, key_id, when):
        self.inner.touch(key_id, when)


def test_verifier_needs_only_get_and_touch(clock):
    store = MemoryStore()
    issued = KeyManager(store, "sk_test", pepper=PEPPER, clock=clock).issue("o", scopes=["a"])
    v = KeyVerifier(GetTouchOnly(store), "sk_test", pepper=PEPPER, clock=clock)
    assert v.verify(issued.raw_key, scopes=["a"]).owner == "o"
    assert store.get(issued.key_id).use_count == 1
    assert v.mask(issued.raw_key) == issued.record.masked
    assert v.parse(issued.raw_key).key_id == issued.key_id
    assert not hasattr(v, "issue") and not hasattr(v, "revoke")
    with pytest.raises(UnknownKey):
        v.verify(v.key_format.build("ZZZZZZZZZZZZ", "q" * 32)[0])


def test_verifier_requires_pepper():
    with pytest.raises(ConfigurationError):
        KeyVerifier(MemoryStore(), "sk_test")
    with pytest.warns(UserWarning):
        KeyVerifier(MemoryStore(), "sk_test", require_pepper=False)


def test_construction_validation():
    with pytest.raises(ConfigurationError):
        KeyManager(MemoryStore(), "Bad Prefix", pepper=PEPPER)
    with pytest.raises(ConfigurationError):
        KeyManager(None, "sk", pepper=PEPPER)
    with pytest.raises(ConfigurationError):
        KeyManager(MemoryStore(), "sk", peppers={"v1": PEPPER}, current_pepper="v2")
    with pytest.raises(ConfigurationError):
        KeyManager(MemoryStore(), "sk", pepper=b"short")


def test_from_env(clock):
    km = KeyManager.from_env(MemoryStore(), "sk_test", environ={"SAFE_API_KEYS_PEPPER": "p" * 32}, clock=clock)
    assert km.registry.current.alg_id == "hmac-sha256$v1"
    km2 = KeyManager.from_env(MemoryStore(), "sk_test",
                              environ={"SAFE_API_KEYS_PEPPERS": "v2:" + "a" * 32 + ",v1:" + "b" * 32,
                                       "SAFE_API_KEYS_CURRENT_PEPPER": "v2"})
    assert km2.registry.current.alg_id == "hmac-sha256$v2"
    assert set(km2.registry.alg_ids) >= {"hmac-sha256$v1", "hmac-sha256$v2"}
    with pytest.raises(ConfigurationError):
        KeyManager.from_env(MemoryStore(), "sk_test", environ={})
