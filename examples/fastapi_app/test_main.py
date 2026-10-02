# examples/fastapi_app/test_main.py
import main
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    with TestClient(main.app) as c:          # runs lifespan: creates the table
        yield c


def test_issue_and_use_key(client):
    assert client.post("/account/api-keys").status_code == 401
    r = client.post("/account/api-keys", headers={"X-Demo-User": "42"})
    assert r.status_code == 201
    raw = r.json()["api_key"]
    main.ORDERS["42"] = [{"id": 1, "item": "book"}]
    assert client.get("/api/orders", headers={"Authorization": f"Bearer {raw}"}).json() == [{"id": 1, "item": "book"}]
    r = client.get("/api/orders")
    assert r.status_code == 401 and r.json()["error"] == "missing_api_key"
    assert r.headers["www-authenticate"].startswith("Bearer") and r.headers["cache-control"] == "no-store"


def test_openapi_documents_security(client):
    spec = client.get("/openapi.json").json()
    assert "ApiKeyAuth" in spec["components"]["securitySchemes"]
    assert {"ApiKeyAuth": ["orders:read"]} in spec["paths"]["/api/orders"]["get"]["security"]
