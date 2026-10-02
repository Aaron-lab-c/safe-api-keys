from datetime import timedelta

import pytest

from safe_api_keys import KeyPolicy, PolicyViolation
from safe_api_keys.policy import validate_metadata

from .conftest import START, make_km


def test_require_expiry(clock):
    km = make_km(clock=clock, policy=KeyPolicy(require_expiry=True))
    with pytest.raises(PolicyViolation):
        km.issue("o")
    assert km.issue("o", expires_in=timedelta(days=1)).record.expires_at == START + timedelta(days=1)


def test_max_ttl(clock):
    km = make_km(clock=clock, policy=KeyPolicy(max_ttl=timedelta(days=30)))
    with pytest.raises(PolicyViolation):
        km.issue("o", expires_in=timedelta(days=31))
    assert km.issue("o").record.expires_at == START + timedelta(days=30)  # capped at max_ttl
    km.issue("o", expires_in=timedelta(days=30))
    strict = make_km(clock=clock, policy=KeyPolicy(max_ttl=timedelta(days=30), require_expiry=True))
    with pytest.raises(PolicyViolation):
        strict.issue("o")


def test_default_ttl(clock):
    km = make_km(clock=clock, policy=KeyPolicy(default_ttl=timedelta(days=7)))
    assert km.issue("o").record.expires_at == START + timedelta(days=7)
    assert km.issue("o", expires_in=timedelta(days=1)).record.expires_at == START + timedelta(days=1)


def test_allowed_scopes_with_wildcards(clock):
    km = make_km(clock=clock, policy=KeyPolicy(allowed_scopes={"orders:read", "reports:*"}))
    km.issue("o", scopes=["orders:read", "reports:daily", "reports:*"])
    with pytest.raises(PolicyViolation):
        km.issue("o", scopes=["orders:write"])
    with pytest.raises(PolicyViolation):
        km.issue("o", scopes=["orders:*"])  # broader than allowed


def test_max_active_keys_per_owner(clock):
    km = make_km(clock=clock, policy=KeyPolicy(max_active_keys_per_owner=2))
    a = km.issue("o")
    km.issue("o")
    with pytest.raises(PolicyViolation):
        km.issue("o")
    km.issue("other")
    km.revoke(a.key_id)
    km.issue("o")  # revoked keys don't count


def test_allow_no_scope(clock):
    km = make_km(clock=clock, policy=KeyPolicy(allow_no_scope=False))
    with pytest.raises(PolicyViolation):
        km.issue("o")
    km.issue("o", scopes=["a"])


def test_policy_not_applied_on_verify(store, clock):
    loose = make_km(store, clock=clock)
    issued = loose.issue("o", scopes=["orders:write"])
    strict = make_km(store, clock=clock, policy=KeyPolicy(allowed_scopes={"orders:read"}, require_expiry=True))
    assert strict.verify(issued.raw_key).owner == "o"


def test_metadata_limits():
    assert validate_metadata({"a": {"b": {"c": 1}}}) == {"a": {"b": {"c": 1}}}
    with pytest.raises(PolicyViolation):
        validate_metadata({"a": {"b": {"c": {"d": 1}}}})
    with pytest.raises(PolicyViolation):
        validate_metadata({"x": "y" * 9000})
    with pytest.raises(ValueError):
        validate_metadata({"x": object()})
    with pytest.raises(ValueError):
        validate_metadata(["not", "a", "dict"])  # type: ignore[arg-type]


def test_from_mapping():
    p = KeyPolicy.from_mapping({"max_ttl": "365d", "default_ttl": 3600, "allowed_scopes": ["a", "b:*"]})
    assert p.max_ttl == timedelta(days=365) and p.default_ttl == timedelta(hours=1)
    assert p.allowed_scopes == {"a", "b:*"}
    with pytest.raises(ValueError):
        KeyPolicy.from_mapping({"nope": 1})
    with pytest.raises(ValueError):
        KeyPolicy(max_ttl=timedelta(days=1), default_ttl=timedelta(days=2))
