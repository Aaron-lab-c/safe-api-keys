from datetime import timedelta

import pytest

pytest.importorskip("flask")
from flask import Blueprint, Flask, g  # noqa: E402

from safe_api_keys.contrib.flask import APIKeys  # noqa: E402

from ..conftest import make_km  # noqa: E402


@pytest.fixture
def env(clock):
    km = make_km(clock=clock)
    seen = []
    keys = APIKeys(km, on_rejected=lambda ip, kid: seen.append((ip, kid)))
    app = Flask(__name__)
    keys.init_app(app)

    @app.get("/plain")
    @keys.required
    def plain():
        return {"owner": g.api_key.owner}

    @app.get("/orders")
    @keys.required(scopes=["orders:read"])
    def orders():
        return {"owner": g.api_key.owner}

    @app.post("/orders")
    @keys.required(scopes=["orders:write"])
    def create():
        return {"ok": True}, 201

    @app.get("/reports")
    @keys.required(any_scopes=["reports:*", "admin"])
    def reports():
        return {"ok": True}

    bp = Blueprint("api", __name__, url_prefix="/api")

    @bp.get("/me")
    def me():
        return {"owner": g.api_key.owner}

    @bp.get("/scoped")
    @keys.required(scopes=["orders:read"])
    def scoped():
        return {"ok": True}

    @bp.get("/health")
    def health():
        return {"ok": True}

    keys.protect_blueprint(bp, exempt=["/api/health"])
    app.register_blueprint(bp)
    return km, app.test_client(), seen


def auth(raw):
    return {"Authorization": f"Bearer {raw}"}


def test_decorator_flow(env):
    km, c, seen = env
    r = c.get("/plain")
    assert r.status_code == 401 and r.json == {"error": "missing_api_key", "message": "No API key provided"}
    assert r.headers["WWW-Authenticate"].startswith("Bearer") and r.headers["Cache-Control"] == "no-store"
    i = km.issue("u1", scopes=["orders:read"])
    assert c.get("/plain", headers=auth(i.raw_key)).json == {"owner": "u1"}
    assert c.get("/orders", headers={"X-API-Key": i.raw_key}).status_code == 200
    r = c.post("/orders", headers=auth(i.raw_key))
    assert r.status_code == 403 and r.json["missing"] == ["orders:write"]
    assert c.get("/reports", headers=auth(i.raw_key)).status_code == 403
    assert seen[-1][1] == i.key_id


def test_blueprint_protection(env):
    km, c, _ = env
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/me").status_code == 401
    i = km.issue("u1")
    assert c.get("/api/me", headers=auth(i.raw_key)).json == {"owner": "u1"}
    r = c.get("/api/scoped", headers=auth(i.raw_key))
    assert r.status_code == 403
    j = km.issue("u1", scopes=["orders:read"])
    assert c.get("/api/scoped", headers=auth(j.raw_key)).status_code == 200
    assert km.get(j.key_id).use_count == 1  # blueprint verified; decorator only re-checked scopes


def test_blueprint_options_requires_key(env):
    """OPTIONS is authenticated like any other method; only a CORS preflight is answered without the view."""
    km, client, _ = env
    assert client.options("/api/me").status_code == 401
    r = client.options("/api/me", headers={"Origin": "https://app.example", "Access-Control-Request-Method": "GET"})
    assert r.status_code == 200 and "GET" in r.headers["Allow"] and not r.data.strip()  # no view body
    assert client.options("/api/me", headers={"Access-Control-Request-Method": "GET"}).status_code == 401
    i = km.issue("u1")
    assert client.options("/api/me", headers={"Authorization": f"Bearer {i.raw_key}"}).status_code == 200
    assert client.options("/api/health").status_code == 200


def test_revoke_rotate_sunset(env, clock):
    km, c, _ = env
    i = km.issue("u1")
    new = km.rotate(i.key_id, grace=timedelta(hours=24))
    r = c.get("/plain", headers=auth(i.raw_key))
    assert r.status_code == 200 and r.headers["Deprecation"] == "true" and "Sunset" in r.headers
    clock.advance(hours=25)
    assert c.get("/plain", headers=auth(i.raw_key)).json["error"] == "expired_api_key"
    km.revoke(new.key_id)
    assert c.get("/plain", headers=auth(new.raw_key)).json["error"] == "revoked_api_key"


def test_trust_proxy(clock):
    km = make_km(clock=clock)
    app = Flask(__name__)
    keys = APIKeys(km, app, trust_proxy=True)

    @app.get("/ip")
    @keys.required
    def ip():
        return {"ok": True}

    i = km.issue("u", ip_allowlist=["203.0.113.7"])
    c = app.test_client()
    assert c.get("/ip", headers={**auth(i.raw_key), "X-Forwarded-For": "203.0.113.7"}).status_code == 200
    assert c.get("/ip", headers={**auth(i.raw_key), "X-Forwarded-For": "1.1.1.1"}).status_code == 403
