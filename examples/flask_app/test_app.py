# examples/flask_app/test_app.py
from datetime import datetime, timedelta, timezone

import pytest
from app import ORDERS, build_manager, build_policy, create_app
from sqlalchemy import create_engine, inspect

from safe_api_keys import KeyManager
from safe_api_keys.stores import MemoryStore

PEPPER = b"test-pepper-32-bytes-xxxxxxxxxxxxx"


class FrozenClock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def km(clock):
    return KeyManager(MemoryStore(), prefix="acme_test", pepper=PEPPER, clock=clock)


@pytest.fixture
def client(km):
    ORDERS.clear()
    app = create_app(km)
    return app.test_client()


def bearer(raw):
    return {"Authorization": f"Bearer {raw}"}


def test_spec_snippet(km, client):
    issued = km.issue(owner="u1", scopes=["orders:read"])
    resp = client.get("/api/orders", headers={"Authorization": f"Bearer {issued.raw_key}"})
    assert resp.status_code == 200
    resp = client.post("/api/orders", headers={"Authorization": f"Bearer {issued.raw_key}"})
    assert resp.status_code == 403 and resp.json["missing"] == ["orders:write"]


def test_self_service_lifecycle(client, clock):
    # not logged in -> account endpoints refuse
    assert client.post("/account/api-keys", json={}).status_code == 401
    client.post("/login", json={"user_id": 42})

    # 1) create a key (raw key returned once)
    r = client.post("/account/api-keys", json={"name": "laptop", "scopes": ["orders:read", "orders:write"]})
    assert r.status_code == 201
    raw, key_id = r.json["api_key"], r.json["key_id"]
    assert raw.startswith("acme_test_") and r.json["masked"].endswith(raw[-10:-6])

    # 2) use it
    assert client.post("/api/orders", headers=bearer(raw), json={"item": "book"}).status_code == 201
    assert client.get("/api/orders", headers={"X-API-Key": raw}).json == [{"id": 1, "owner": "42", "item": "book"}]
    assert client.get("/api/health").json == {"ok": True}

    # 3) insufficient scope -> 403
    r = client.get("/api/reports/daily", headers=bearer(raw))
    assert r.status_code == 403 and r.json["error"] == "insufficient_scope"

    # listing shows masked only
    listed = client.get("/account/api-keys").json
    assert listed[0]["key_id"] == key_id and raw not in str(listed)

    # 4) rotate: old + new both valid during grace, old carries Deprecation/Sunset
    r = client.post(f"/account/api-keys/{key_id}/rotate", json={})
    new_raw = r.json["api_key"]
    old_resp = client.get("/api/orders", headers=bearer(raw))
    assert old_resp.status_code == 200 and old_resp.headers["Deprecation"] == "true" and "Sunset" in old_resp.headers
    assert "Deprecation" not in client.get("/api/orders", headers=bearer(new_raw)).headers
    clock.now += timedelta(hours=24)
    assert client.get("/api/orders", headers=bearer(raw)).json["error"] == "expired_api_key"
    assert client.get("/api/orders", headers=bearer(new_raw)).status_code == 200

    # 5) revoke -> 401
    new_id = r.json["key_id"]
    assert client.delete(f"/account/api-keys/{new_id}", json={}).status_code == 204
    r = client.get("/api/orders", headers=bearer(new_raw))
    assert r.status_code == 401 and r.json["error"] == "revoked_api_key"
    assert r.headers["WWW-Authenticate"].startswith("Bearer")

    # cannot touch someone else's key
    client.post("/login", json={"user_id": 7})
    assert client.delete(f"/account/api-keys/{key_id}", json={}).status_code == 404


def test_session_endpoints_reject_non_json_csrf(client):
    """A cross-site HTML form can only send form/text bodies; those are refused (CSRF hardening)."""
    client.post("/login", json={"user_id": 42})
    r = client.post("/account/api-keys", data='{"scopes": ["orders:read"]}', content_type="text/plain")
    assert r.status_code == 415
    r = client.post("/account/api-keys", data={"name": "x"})  # application/x-www-form-urlencoded
    assert r.status_code == 415
    assert client.post("/login", data="user_id=1", content_type="text/plain").status_code == 415
    raw = client.post("/account/api-keys", json={}).json["api_key"]
    assert client.get("/api/orders", headers=bearer(raw)).status_code == 200  # API key calls unaffected


def test_missing_and_invalid_key(client):
    r = client.get("/api/orders")
    assert r.status_code == 401 and r.json == {"error": "missing_api_key", "message": "No API key provided"}
    assert r.headers["Cache-Control"] == "no-store"
    r = client.get("/api/orders", headers=bearer("acme_test_nope"))
    assert r.status_code == 401 and r.json["error"] == "invalid_api_key"


def test_policy_enforced(km):
    client = create_app(KeyManager(MemoryStore(), prefix="acme_test", pepper=PEPPER,
                                   policy=build_policy())).test_client()
    client.post("/login", json={"user_id": 1})
    r = client.post("/account/api-keys", json={"scopes": ["admin"]})  # not in allowed_scopes
    assert r.status_code == 400 and "not allowed" in r.json["message"]
    r = client.post("/account/api-keys", json={"days": 400})  # > max_ttl
    assert r.status_code == 400
    for _ in range(10):
        assert client.post("/account/api-keys", json={}).status_code == 201
    assert client.post("/account/api-keys", json={}).status_code == 400  # max_active_keys_per_owner


def test_tables_are_created_automatically(tmp_path, monkeypatch):
    """build_manager() runs metadata.create_all(): the table and all columns exist afterwards."""
    monkeypatch.setenv("SAFE_API_KEYS_PEPPER", PEPPER.decode())
    url = f"sqlite:///{tmp_path / 'auto.db'}"
    km = build_manager(url)
    cols = {c["name"] for c in inspect(create_engine(url)).get_columns("safe_api_keys")}
    assert cols == {"key_id", "prefix", "hash", "hash_alg", "secret_last4", "owner", "name", "scopes",
                    "created_at", "expires_at", "revoked_at", "revoke_reason", "last_used_at", "use_count",
                    "rotated_from", "rotated_to", "ip_allowlist", "metadata"}
    build_manager(url)  # idempotent: create_all skips existing tables
    client = create_app(km).test_client()
    client.post("/login", json={"user_id": 5})
    raw = client.post("/account/api-keys", json={"scopes": ["orders:read"]}).json["api_key"]
    assert client.get("/api/orders", headers=bearer(raw)).status_code == 200
