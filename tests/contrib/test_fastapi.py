from datetime import timedelta
from typing import Optional

import pytest

pytest.importorskip("fastapi")
from fastapi import Depends, FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from safe_api_keys import AsyncKeyManager, ExtractConfig, KeyRecord  # noqa: E402
from safe_api_keys.contrib.fastapi import APIKeyAuth, APIKeyMiddleware  # noqa: E402
from safe_api_keys.stores import MemoryStore  # noqa: E402

from ..conftest import PEPPER, make_km  # noqa: E402


def build(km, **auth_kw):
    auth = APIKeyAuth(km, **auth_kw)
    app = FastAPI()
    auth.install(app)

    @app.get("/plain")
    def plain(key: KeyRecord = Depends(auth)):
        return {"owner": key.owner}

    @app.get("/orders")
    def orders(key: KeyRecord = Depends(auth.scopes("orders:read"))):
        return {"owner": key.owner}

    @app.post("/orders")
    def create(key: KeyRecord = Depends(auth.scopes("orders:write"))):
        return {"ok": True}

    @app.get("/reports")
    def reports(key: KeyRecord = Depends(auth.any_scopes("admin", "reports:*"))):
        return {"ok": True}

    @app.get("/maybe")
    def maybe(request: Request, key: Optional[KeyRecord] = Depends(auth.optional())):
        return {"owner": key.owner if key else None,
                "state": getattr(request.state, "api_key", None) is not None}

    @app.get("/ip")
    def ip(request: Request, key: KeyRecord = Depends(auth)):
        return {"ok": True}

    return app, auth


@pytest.fixture
def setup(clock):
    km = make_km(clock=clock)
    app, _ = build(km)
    return km, TestClient(app)


def bearer(raw):
    return {"Authorization": f"Bearer {raw}"}


def test_missing_and_invalid(setup):
    km, c = setup
    r = c.get("/plain")
    assert r.status_code == 401 and r.json() == {"error": "missing_api_key", "message": "No API key provided"}
    assert r.headers["www-authenticate"].startswith("Bearer") and r.headers["cache-control"] == "no-store"
    r = c.get("/plain", headers=bearer("sk_test_nope"))
    assert r.status_code == 401 and r.json()["error"] == "invalid_api_key"


def test_success_scopes_and_header(setup):
    km, c = setup
    i = km.issue("u1", scopes=["orders:read"])
    assert c.get("/plain", headers=bearer(i.raw_key)).json() == {"owner": "u1"}
    assert c.get("/orders", headers={"X-API-Key": i.raw_key}).status_code == 200
    r = c.post("/orders", headers=bearer(i.raw_key))
    assert r.status_code == 403 and r.json()["missing"] == ["orders:write"]
    assert r.headers["cache-control"] == "no-store"
    assert c.get("/reports", headers=bearer(i.raw_key)).status_code == 403
    j = km.issue("u1", scopes=["reports:daily", "reports:*"])
    assert c.get("/reports", headers=bearer(j.raw_key)).status_code == 200


def test_optional(setup):
    km, c = setup
    assert c.get("/maybe").json() == {"owner": None, "state": False}
    assert c.get("/maybe", headers=bearer("garbage")).status_code == 401
    i = km.issue("u1")
    assert c.get("/maybe", headers=bearer(i.raw_key)).json() == {"owner": "u1", "state": True}


def test_revoked_expired_and_sunset(setup, clock):
    km, c = setup
    i = km.issue("u1")
    new = km.rotate(i.key_id, grace=timedelta(hours=1))
    r = c.get("/plain", headers=bearer(i.raw_key))
    assert r.status_code == 200 and r.headers["deprecation"] == "true" and "GMT" in r.headers["sunset"]
    assert "deprecation" not in c.get("/plain", headers=bearer(new.raw_key)).headers
    clock.advance(hours=1)
    assert c.get("/plain", headers=bearer(i.raw_key)).json()["error"] == "expired_api_key"
    km.revoke(new.key_id)
    assert c.get("/plain", headers=bearer(new.raw_key)).json()["error"] == "revoked_api_key"


def test_sunset_can_be_disabled(clock):
    km = make_km(clock=clock)
    app, _ = build(km, sunset_headers=False)
    i = km.issue("u")
    km.rotate(i.key_id)
    assert "deprecation" not in TestClient(app).get("/plain", headers=bearer(i.raw_key)).headers


def test_openapi_security(setup):
    km, c = setup
    spec = c.get("/openapi.json").json()
    schemes = spec["components"]["securitySchemes"]
    assert schemes["ApiKeyAuth"] == {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    assert schemes["ApiKeyAuthBearer"] == {"type": "http", "scheme": "bearer"}
    sec = spec["paths"]["/orders"]["get"]["security"]
    assert {"ApiKeyAuthBearer": ["orders:read"]} in sec and {"ApiKeyAuth": ["orders:read"]} in sec


def test_trust_proxy_and_ip_allowlist(clock):
    km = make_km(clock=clock)
    i = km.issue("u", ip_allowlist=["203.0.113.7"])
    plain_app, _ = build(km)
    c = TestClient(plain_app)  # testclient peer is "testclient" (not an IP)
    assert c.get("/ip", headers={**bearer(i.raw_key), "X-Forwarded-For": "203.0.113.7"}).status_code == 403
    proxied, _ = build(km, trust_proxy=True)
    c2 = TestClient(proxied)
    assert c2.get("/ip", headers={**bearer(i.raw_key), "X-Forwarded-For": "203.0.113.7"}).status_code == 200
    assert c2.get("/ip", headers={**bearer(i.raw_key), "X-Forwarded-For": "8.8.8.8"}).status_code == 403


def test_async_manager_and_on_rejected(clock):
    seen = []
    km = AsyncKeyManager(MemoryStore(), "sk_test", pepper=PEPPER, clock=clock)
    app, auth = build(km, on_rejected=lambda ip, key_id: seen.append((ip, key_id)))
    import asyncio

    i = asyncio.new_event_loop().run_until_complete(km.issue("u", scopes=["orders:read"]))
    c = TestClient(app)
    assert c.get("/orders", headers=bearer(i.raw_key)).status_code == 200
    assert c.post("/orders", headers=bearer(i.raw_key)).status_code == 403
    assert seen and seen[-1][1] == i.key_id


def test_without_install_degrades_to_detail(clock):
    km = make_km(clock=clock)
    auth = APIKeyAuth(km)
    app = FastAPI()

    @app.get("/x")
    def x(key=Depends(auth)):
        return {}

    r = TestClient(app).get("/x")
    assert r.status_code == 401 and r.json() == {"detail": "No API key provided"}
    assert r.headers["www-authenticate"].startswith("Bearer")


def test_auto_error_false(clock):
    km = make_km(clock=clock)
    auth = APIKeyAuth(km, auto_error=False)
    app = FastAPI()

    @app.get("/x")
    def x(key: Optional[KeyRecord] = Depends(auth)):
        return {"authenticated": key is not None}

    c = TestClient(app)
    assert c.get("/x").json() == {"authenticated": False}
    assert c.get("/x", headers=bearer("garbage")).json() == {"authenticated": False}
    assert c.get("/x", headers=bearer(km.issue("u").raw_key)).json() == {"authenticated": True}


def test_middleware_protect_exempt_and_dependency_reuse(clock):
    km = make_km(clock=clock)
    auth = APIKeyAuth(km)
    app = FastAPI()
    auth.install(app)
    app.add_middleware(APIKeyMiddleware, km=km, protect=("/api/",), exempt=("/api/health",))

    @app.get("/api/orders")
    def orders(request: Request, key: KeyRecord = Depends(auth.scopes("orders:read"))):
        return {"owner": request.state.api_key.owner}

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/public")
    def public():
        return {"ok": True}

    c = TestClient(app)
    assert c.get("/api/health").status_code == 200
    assert c.get("/public").status_code == 200
    r = c.get("/api/orders")
    assert r.status_code == 401 and r.json()["error"] == "missing_api_key"
    i = km.issue("u", scopes=["orders:read"])
    j = km.issue("u")
    assert c.get("/api/orders", headers=bearer(i.raw_key)).json() == {"owner": "u"}
    assert c.get("/api/orders", headers=bearer(j.raw_key)).status_code == 403
    assert km.get(i.key_id).use_count == 1  # verified once (middleware), dependency only re-checked scopes


def test_query_param_scheme(clock):
    km = make_km(clock=clock)
    app, _ = build(km, extract=ExtractConfig(query_param="api_key"))
    i = km.issue("u")
    c = TestClient(app)
    assert c.get(f"/plain?api_key={i.raw_key}").status_code == 200
    assert "ApiKeyAuthQuery" in c.get("/openapi.json").json()["components"]["securitySchemes"]
