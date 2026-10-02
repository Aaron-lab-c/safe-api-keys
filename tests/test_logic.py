from datetime import datetime, timedelta, timezone

import pytest

from safe_api_keys import ExpiredKey, InsufficientScope, IPNotAllowed, KeyRecord, RevokedKey
from safe_api_keys._logic import decide, ip_allowed, normalize_allowlist, plan_rotation, should_touch

UTC = timezone.utc
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def rec(**kw) -> KeyRecord:
    base = dict(key_id="AAAAAAAAAAAA", prefix="sk_test", hash="0" * 64, hash_alg="hmac-sha256$v1",
                secret_last4="abcd", owner="o", created_at=NOW - timedelta(days=1))
    base.update(kw)
    return KeyRecord(**base)


def test_active_passes():
    decide(rec(scopes=("a",)), NOW, scopes=["a"])


def test_order_revoked_before_expired_before_scope_before_ip():
    everything_wrong = rec(revoked_at=NOW, expires_at=NOW, scopes=(), ip_allowlist=("10.0.0.0/8",))
    with pytest.raises(RevokedKey):
        decide(everything_wrong, NOW, scopes=["x"], client_ip="1.1.1.1")
    with pytest.raises(ExpiredKey):
        decide(everything_wrong.replace(revoked_at=None), NOW, scopes=["x"], client_ip="1.1.1.1")
    with pytest.raises(InsufficientScope):
        decide(everything_wrong.replace(revoked_at=None, expires_at=None), NOW, scopes=["x"], client_ip="1.1.1.1")
    with pytest.raises(IPNotAllowed):
        decide(everything_wrong.replace(revoked_at=None, expires_at=None), NOW, client_ip="1.1.1.1")


def test_expires_at_equal_now_is_expired():
    with pytest.raises(ExpiredKey):
        decide(rec(expires_at=NOW), NOW)
    decide(rec(expires_at=NOW + timedelta(microseconds=1)), NOW)


def test_scope_all_and_any():
    r = rec(scopes=("orders:read", "reports:*"))
    decide(r, NOW, scopes=["orders:read"], any_scopes=["admin", "reports:x"])
    with pytest.raises(InsufficientScope) as ei:
        decide(r, NOW, scopes=["orders:read", "orders:write"])
    assert ei.value.missing == ["orders:write"] and ei.value.required == ["orders:read", "orders:write"]
    with pytest.raises(InsufficientScope) as ei:
        decide(r, NOW, any_scopes=["admin", "users:read"])
    assert ei.value.missing == ["admin", "users:read"]


def test_ip_rules():
    r = rec(ip_allowlist=normalize_allowlist(["10.0.0.0/8", "2001:db8::/32", "192.168.1.5"]))
    decide(r, NOW, client_ip="10.2.3.4")
    decide(r, NOW, client_ip="::ffff:10.2.3.4")  # IPv4-mapped normalised
    decide(r, NOW, client_ip="2001:db8::1")
    decide(r, NOW, client_ip="192.168.1.5")
    with pytest.raises(IPNotAllowed) as ei:
        decide(r, NOW)
    assert ei.value.reason == "no_client_ip"
    with pytest.raises(IPNotAllowed):
        decide(r, NOW, client_ip="192.168.1.6")
    assert not ip_allowed(["10.0.0.0/8"], "not-an-ip")
    with pytest.raises(ValueError):
        normalize_allowlist(["999.1.1.1"])


def test_naive_datetime_rejected():
    with pytest.raises(ValueError):
        decide(rec(), datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        rec(created_at=datetime(2026, 1, 1))


def test_should_touch():
    r = rec()
    assert should_touch(r, NOW, 60)
    r2 = r.replace(last_used_at=NOW - timedelta(seconds=30))
    assert not should_touch(r2, NOW, 60) and should_touch(r2, NOW, 0) and should_touch(r2, NOW, 30)
    assert not should_touch(r, NOW, None)


def test_plan_rotation():
    r = rec(expires_at=NOW + timedelta(hours=1))
    assert plan_rotation(r, "B" * 12, NOW, timedelta(hours=24)).expires_at == NOW + timedelta(hours=1)
    assert plan_rotation(rec(), "B" * 12, NOW, timedelta(hours=2)).expires_at == NOW + timedelta(hours=2)
    z = plan_rotation(rec(), "B" * 12, NOW, timedelta(0))
    assert z.revoked_at == NOW and z.rotated_to == "B" * 12
    with pytest.raises(ValueError):
        plan_rotation(rec(), "B" * 12, NOW, timedelta(seconds=-1))
