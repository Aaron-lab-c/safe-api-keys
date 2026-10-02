import json
import re
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.db import connection

from safe_api_keys.contrib.django import get_manager, reset_manager

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def fresh_manager():
    reset_manager()
    yield
    reset_manager()


# --- the snippet from the spec (§13.6.3), verbatim -------------------------------------------
def test_orders_requires_scope(client):
    km = get_manager()
    issued = km.issue(owner="1", scopes=["orders:read"])
    r = client.get("/api/orders/", HTTP_AUTHORIZATION=f"Bearer {issued.raw_key}")
    assert r.status_code == 200
    r = client.post("/api/orders/create/", HTTP_AUTHORIZATION=f"Bearer {issued.raw_key}")
    assert r.status_code == 403
    r = client.get("/api/orders/")
    assert r.status_code == 401 and r["WWW-Authenticate"].startswith("Bearer")


# --- end-to-end: create -> use -> 403 -> rotate -> revoke ----------------------------------------
@pytest.fixture
def user_client(client, django_user_model):
    user = django_user_model.objects.create_user("alice", password="pw-for-tests-only")
    client.force_login(user)
    return client, user


def bearer(raw):
    return {"HTTP_AUTHORIZATION": f"Bearer {raw}"}


def test_full_lifecycle(user_client):
    client, user = user_client
    r = client.post("/account/api-keys/create/", json.dumps({"name": "laptop", "scopes": ["orders:read",
                                                                                           "orders:write"]}),
                    content_type="application/json")
    assert r.status_code == 201
    raw, key_id = r.json()["api_key"], r.json()["key_id"]

    r = client.post("/api/orders/create/", json.dumps({"item": "book", "qty": 2}), content_type="application/json",
                    **bearer(raw))
    assert r.status_code == 201
    assert client.get("/api/orders/", HTTP_X_API_KEY=raw).json() == [{"id": 1, "item": "book", "qty": 2}]
    assert client.get("/api/v2/orders/", **bearer(raw)).json() == [{"id": 1, "item": "book", "qty": 2}]
    assert client.get("/api/health/").json() == {"ok": True}

    r = client.get("/api/reports/daily/", **bearer(raw))
    assert r.status_code == 403 and r.json()["missing"] == ["reports:*", "admin"]

    listed = client.get("/account/api-keys/").json()
    assert listed[0]["key_id"] == key_id and raw not in json.dumps(listed)

    r = client.post(f"/account/api-keys/{key_id}/rotate/")
    new_raw = r.json()["api_key"]
    old = client.get("/api/orders/", **bearer(raw))
    assert old.status_code == 200 and old["Deprecation"] == "true" and old["Sunset"].endswith("GMT")
    assert client.get("/api/orders/", **bearer(new_raw)).status_code == 200

    assert client.post(f"/account/api-keys/{r.json()['key_id']}/revoke/").status_code == 204
    r = client.get("/api/orders/", **bearer(new_raw))
    assert r.status_code == 401 and r.json()["error"] == "revoked_api_key"


def test_csrf_enforced_like_a_real_server(django_user_model):
    """Django's test client skips CSRF by default; a real server does not. Session endpoints need X-CSRFToken."""
    from django.test import Client

    client = Client(enforce_csrf_checks=True)
    client.force_login(django_user_model.objects.create_user("bob", password="pw-for-tests-only"))
    r = client.post("/account/api-keys/create/", "{}", content_type="application/json")
    assert r.status_code == 403                                   # no token
    assert client.get("/account/csrf/").status_code == 204        # sets the csrftoken cookie
    token = client.cookies["csrftoken"].value
    r = client.post("/account/api-keys/create/", "{}", content_type="application/json", HTTP_X_CSRFTOKEN=token)
    assert r.status_code == 201
    raw = r.json()["api_key"]
    # API-key endpoints don't use cookies and are csrf_exempt: no token needed
    anon = Client(enforce_csrf_checks=True)
    r = anon.post("/api/orders/create/", "{}", content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {raw}")
    assert r.status_code == 403 and r.json()["error"] == "insufficient_scope"   # API key checked, not CSRF
    assert anon.get("/api/orders/", HTTP_AUTHORIZATION=f"Bearer {raw}").status_code == 200


def test_cannot_manage_other_users_keys(user_client, django_user_model):
    client, user = user_client
    other = get_manager().issue(owner="999", scopes=["orders:read"])
    assert client.post(f"/account/api-keys/{other.key_id}/revoke/").status_code == 404


def test_policy_violations_are_400(user_client):
    client, _ = user_client
    r = client.post("/account/api-keys/create/", json.dumps({"scopes": ["admin"]}), content_type="application/json")
    assert r.status_code == 400


def test_drf_user_resolver(user_client):
    client, user = user_client
    issued = get_manager().issue(owner=str(user.pk), scopes=["orders:read"])
    assert client.get("/api/v2/orders/", **bearer(issued.raw_key)).status_code == 200
    r = client.get("/api/v2/orders/", **bearer(get_manager().issue(owner=str(user.pk)).raw_key))
    assert r.status_code == 403 and r["Cache-Control"] == "no-store"


# --- the database table is created by `migrate` ---------------------------------------------------
def test_migrate_created_api_key_table():
    assert "safe_api_keys_apikey" in connection.introspection.table_names()
    with connection.cursor() as cur:
        cols = {c.name for c in connection.introspection.get_table_description(cur, "safe_api_keys_apikey")}
    assert {"key_id", "hash", "owner", "scopes", "expires_at", "revoked_at", "use_count", "metadata"} <= cols
    out = StringIO()
    call_command("makemigrations", "--check", "--dry-run", stdout=out)  # models and migrations in sync
    assert "No changes detected" in out.getvalue()


def test_django_store_persists_in_table(settings):
    """Production setting (STORE=None -> DjangoStore): keys live in safe_api_keys_apikey."""
    from safe_api_keys.contrib.django.models import APIKey

    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "STORE": None}
    km = get_manager()
    issued = km.issue(owner="1", scopes=["orders:read"], expires_in=timedelta(days=30))
    row = APIKey.objects.get(pk=issued.key_id)
    assert row.owner == "1" and row.scopes == ["orders:read"] and row.secret_last4 == issued.raw_key[-10:-6]
    assert issued.raw_key not in row.hash
    km.verify(issued.raw_key)
    assert APIKey.objects.get(pk=issued.key_id).use_count == 1


def test_management_commands(settings):
    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "STORE": None}
    out, err = StringIO(), StringIO()
    call_command("apikey", "issue", "--owner", "svc-billing", "--scopes", "reports:*", "--expires", "365d",
                 "--name", "billing batch", stdout=out, stderr=err)
    raw = out.getvalue().strip()
    key_id = raw.split("_")[2]
    out = StringIO()
    call_command("apikey", "list", "--owner", "svc-billing", stdout=out)
    assert key_id in out.getvalue() and not re.search(r"[0-9A-Za-z]{32}", out.getvalue())
    out, err = StringIO(), StringIO()
    call_command("apikey", "rotate", key_id, "--grace", "24h", stdout=out, stderr=err)
    call_command("apikey", "revoke", key_id, "--reason", "compromised", stdout=StringIO())
    assert get_manager().get(key_id).revoke_reason == "compromised"
