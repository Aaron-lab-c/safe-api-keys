from datetime import timedelta

import pytest

pytest.importorskip("starlette")
from starlette.applications import Starlette  # noqa: E402
from starlette.middleware import Middleware  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from safe_api_keys import StoreError  # noqa: E402
from safe_api_keys.contrib.starlette import APIKeyMiddleware  # noqa: E402
from safe_api_keys.stores import MemoryStore  # noqa: E402

from ..conftest import make_km  # noqa: E402


async def whoami(request):
    return JSONResponse({"owner": request.state.api_key.owner})


async def health(request):
    return JSONResponse({"ok": True})


def make_app(km, **kw):
    return Starlette(routes=[Route("/api/me", whoami), Route("/api/health", health), Route("/open", health)],
                     middleware=[Middleware(APIKeyMiddleware, km=km, **kw)])


def test_pure_middleware(clock):
    km = make_km(clock=clock)
    c = TestClient(make_app(km))
    assert c.get("/api/health").status_code == 200 and c.get("/open").status_code == 200
    r = c.get("/api/me")
    assert r.status_code == 401 and r.headers["cache-control"] == "no-store"
    i = km.issue("u")
    assert c.get("/api/me", headers={"X-API-Key": i.raw_key}).json() == {"owner": "u"}
    km.rotate(i.key_id, grace=timedelta(hours=1))
    r = c.get("/api/me", headers={"X-API-Key": i.raw_key})
    assert r.headers["deprecation"] == "true" and r.headers["sunset"].endswith("GMT")


def test_middleware_scopes(clock):
    km = make_km(clock=clock)
    c = TestClient(make_app(km, scopes=["admin"]))
    r = c.get("/api/me", headers={"X-API-Key": km.issue("u").raw_key})
    assert r.status_code == 403 and r.json()["missing"] == ["admin"]


def test_store_error_is_503(clock):
    class Down(MemoryStore):
        def get(self, key_id):
            raise StoreError("down")

    km = make_km(Down(), clock=clock)
    raw = km.key_format.build("ZZZZZZZZZZZZ", "y" * 32)[0]
    r = TestClient(make_app(km)).get("/api/me", headers={"X-API-Key": raw})
    assert r.status_code == 503 and r.json()["error"] == "auth_unavailable"


def test_custom_error_formatter(clock):
    def problem(exc):
        return (getattr(exc, "status_code", 401), {"Content-Type": "application/problem+json"},
                {"type": "about:blank", "title": exc.public_message, "status": exc.status_code})

    km = make_km(clock=clock)
    r = TestClient(make_app(km, error_formatter=problem)).get("/api/me")
    assert r.json() == {"type": "about:blank", "title": "No API key provided", "status": 401}
