from datetime import datetime, timezone

import pytest

from safe_api_keys import (
    ExpiredKey,
    InsufficientScope,
    IPNotAllowed,
    MalformedKey,
    MissingKey,
    RevokedKey,
    StoreError,
    UnknownKey,
)
from safe_api_keys.http import error_response, path_matches, resolve_client_ip, sunset_headers

from ..test_logic import rec


@pytest.mark.parametrize("exc,status,code", [
    (MissingKey(), 401, "missing_api_key"),
    (MalformedKey(), 401, "invalid_api_key"),
    (UnknownKey(), 401, "invalid_api_key"),
    (RevokedKey(), 401, "revoked_api_key"),
    (ExpiredKey(), 401, "expired_api_key"),
    (InsufficientScope(required=["a"], missing=["a"]), 403, "insufficient_scope"),
    (IPNotAllowed(), 403, "ip_not_allowed"),
    (StoreError("db"), 503, "auth_unavailable"),
])
def test_decision_table(exc, status, code):
    s, headers, body = error_response(exc)
    assert s == status and body["error"] == code
    if status in (401, 403):
        assert headers["Cache-Control"] == "no-store"
    if status == 401:
        assert headers["WWW-Authenticate"] == 'Bearer realm="api", error="invalid_token"'
    else:
        assert "WWW-Authenticate" not in headers
    if code == "insufficient_scope":
        assert body["required"] == ["a"] and body["missing"] == ["a"]


def test_messages():
    assert error_response(MalformedKey())[2]["message"] == error_response(UnknownKey())[2]["message"] == \
        "Invalid API key"
    assert error_response(MissingKey())[2]["message"] == "No API key provided"
    assert error_response(UnknownKey(), scheme="ApiKey")[1]["WWW-Authenticate"] == 'ApiKey realm="api"'


def test_sunset_headers():
    assert sunset_headers(rec()) == {}
    r = rec(rotated_to="B" * 12, expires_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    assert sunset_headers(r) == {"Deprecation": "true", "Sunset": "Fri, 02 Jan 2026 03:04:05 GMT"}


def test_client_ip_default_ignores_xff():
    assert resolve_client_ip("10.0.0.1", "1.2.3.4") == "10.0.0.1"
    assert resolve_client_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert resolve_client_ip(None) is None
    assert resolve_client_ip("not-an-ip") is None


def test_client_ip_trust_proxy_one_hop():
    # client -> proxy(10.0.0.1) -> app : proxy appended the real client
    assert resolve_client_ip("10.0.0.1", "203.0.113.7", trust_proxy=True) == "203.0.113.7"
    # a client-forged entry on the left is ignored: the proxy-appended hop wins
    assert resolve_client_ip("10.0.0.1", "198.51.100.1, 203.0.113.7", trust_proxy=True) == "203.0.113.7"


def test_client_ip_trusted_proxies_chain():
    proxies = ["10.0.0.0/8", "172.16.0.5"]
    xff = "198.51.100.1, 203.0.113.7, 172.16.0.5"
    assert resolve_client_ip("10.1.1.1", xff, trusted_proxies=proxies) == "203.0.113.7"
    # request did not come from a trusted proxy -> XFF ignored
    assert resolve_client_ip("8.8.8.8", xff, trusted_proxies=proxies) == "8.8.8.8"
    # all hops trusted -> left-most
    assert resolve_client_ip("10.1.1.1", "10.2.2.2, 10.3.3.3", trusted_proxies=proxies) == "10.2.2.2"
    assert resolve_client_ip("10.1.1.1", "garbage", trusted_proxies=proxies) == "10.1.1.1"


def test_path_matches():
    assert path_matches("/api/orders", ["/api/"])
    assert path_matches("/api", ["/api/"])
    assert path_matches("/api/health", ["/api/health"])
    assert path_matches("/api/health/x", ["/api/health"])
    assert not path_matches("/api/healthz", ["/api/health"])
    assert not path_matches("/apiary", ["/api/"])
