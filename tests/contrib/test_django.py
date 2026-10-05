import re
from datetime import timedelta
from io import StringIO

import pytest

pytest.importorskip("django")
pytest.importorskip("pytest_django")

from django.core.exceptions import ImproperlyConfigured  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.core.management.base import CommandError  # noqa: E402

from safe_api_keys.contrib.django import get_manager, reset_manager  # noqa: E402
from safe_api_keys.contrib.django.conf import validate_settings  # noqa: E402
from safe_api_keys.contrib.django.models import APIKey  # noqa: E402

pytestmark = pytest.mark.django_db
SECRET_RE = re.compile(r"[0-9A-Za-z]{32}")
CSRF_RE = re.compile(r'name="csrfmiddlewaretoken" value="[^"]+"')


def scrub(html: str) -> str:
    """Drop Django's CSRF tokens (64 alnum chars) before scanning for leaked secrets."""
    return CSRF_RE.sub("", html)


@pytest.fixture(autouse=True)
def fresh_manager():
    reset_manager()
    yield
    reset_manager()


def bearer(raw):
    return {"HTTP_AUTHORIZATION": f"Bearer {raw}"}


def test_manager_uses_django_store():
    km = get_manager()
    i = km.issue("u1", scopes=["orders:read"])
    row = APIKey.objects.get(pk=i.key_id)
    assert row.owner == "u1" and row.scopes == ["orders:read"] and row.hash != ""
    assert row.masked == i.record.masked and row.state == "active"
    assert get_manager() is km


def test_decorator(client):
    km = get_manager()
    r = client.get("/orders/")
    assert r.status_code == 401 and r.json()["error"] == "missing_api_key"
    assert r["WWW-Authenticate"].startswith("Bearer") and r["Cache-Control"] == "no-store"
    i = km.issue("u1", scopes=["orders:read"])
    assert client.get("/orders/", **bearer(i.raw_key)).json() == {"owner": "u1"}
    assert client.get("/plain/", HTTP_X_API_KEY=i.raw_key).status_code == 200
    r = client.get("/reports/", **bearer(i.raw_key))
    assert r.status_code == 403 and r.json()["missing"] == ["reports:*", "admin"]
    assert client.get("/async-orders/", **bearer(i.raw_key)).json() == {"owner": "u1"}
    km.revoke(i.key_id)
    assert client.get("/orders/", **bearer(i.raw_key)).json()["error"] == "revoked_api_key"


def test_expired_and_sunset(client):
    km = get_manager()
    i = km.issue("u1")
    km.rotate(i.key_id, grace=timedelta(hours=1))
    r = client.get("/plain/", **bearer(i.raw_key))
    assert r.status_code == 200 and r["Deprecation"] == "true" and r["Sunset"].endswith("GMT")
    APIKey.objects.filter(pk=i.key_id).update(expires_at=km.now() - timedelta(seconds=1))
    assert client.get("/plain/", **bearer(i.raw_key)).json()["error"] == "expired_api_key"


def test_middleware_protect_exempt(client):
    km = get_manager()
    assert client.get("/mw/health/").json() == {"ok": True, "has_key": False}
    assert client.get("/mw/any/").status_code == 401
    i = km.issue("u1")
    assert client.get("/mw/any/", **bearer(i.raw_key)).json() == {"owner": "u1"}
    assert client.get("/mw/orders/", **bearer(i.raw_key)).status_code == 403
    j = km.issue("u1", scopes=["orders:read"])
    assert client.get("/mw/orders/", **bearer(j.raw_key)).status_code == 200
    assert APIKey.objects.get(pk=j.key_id).use_count == 1  # middleware verified; decorator re-checked scopes


def test_middleware_authenticates_options(client):
    """A view behind PROTECT never runs for an OPTIONS request without a key (CORS layers go above us)."""
    km = get_manager()
    r = client.options("/mw/any/")
    assert r.status_code == 401 and r.json()["error"] == "missing_api_key"
    r = client.options("/mw/any/", HTTP_ORIGIN="https://app.example", HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET")
    assert r.status_code == 401
    i = km.issue("u1")
    assert client.options("/mw/any/", **bearer(i.raw_key)).json() == {"owner": "u1"}
    assert client.options("/mw/health/").status_code == 200


def test_cors_preflight_setting(client, settings):
    preflight = {"HTTP_ORIGIN": "https://app.example", "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "GET"}
    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "CORS_PREFLIGHT": "respond"}
    r = client.options("/mw/any/", **preflight)
    assert r.status_code == 204 and not r.content                      # answered here, view never ran
    assert client.options("/mw/any/").status_code == 401                # plain OPTIONS still needs a key
    assert client.options("/mw/any/", HTTP_ORIGIN="https://app.example").status_code == 401
    assert client.get("/mw/any/", **preflight).status_code == 401       # only OPTIONS is a preflight
    assert client.options("/mw/health/", **preflight).status_code == 200  # exempt paths untouched
    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "CORS_PREFLIGHT": "nope"}
    with pytest.raises(ImproperlyConfigured):
        validate_settings()


def test_request_user_from_resolver(client, django_user_model):
    km = get_manager()
    django_user_model.objects.create(username="alice")
    i = km.issue("alice")
    j = km.issue("nobody")
    for path in ("/whoami/", "/mw/whoami/"):                   # decorator and middleware alike
        assert client.get(path, **bearer(i.raw_key)).json() == {"owner": "alice", "user": "alice",
                                                                 "authenticated": True}
        r = client.get(path, **bearer(j.raw_key)).json()          # resolver finds nobody: user left alone
        assert r["owner"] == "nobody" and r["authenticated"] is False


def test_api_key_identity_replaces_session_user(client, django_user_model):
    """C: a request authenticated by a key never keeps the session user as a second identity."""
    import django

    km = get_manager()
    alice = django_user_model.objects.create(username="alice")
    django_user_model.objects.create(username="bob")
    client.force_login(alice)
    bob_key = km.issue("bob")
    nobody_key = km.issue("nobody")
    assert client.get("/whoami/", **bearer(bob_key.raw_key)).json()["user"] == "bob"
    r = client.get("/whoami/", **bearer(nobody_key.raw_key)).json()
    assert r["user"] == "AnonymousUser" and r["authenticated"] is False   # not alice
    if django.VERSION >= (5, 0):
        assert client.get("/async-whoami/", **bearer(bob_key.raw_key)).json() == {"request_user": "bob",
                                                                                   "auser": "bob"}
        r = client.get("/async-whoami/", **bearer(nobody_key.raw_key)).json()
        assert r == {"request_user": "AnonymousUser", "auser": "AnonymousUser"}


def test_request_user_untouched_without_resolver(client, settings, django_user_model):
    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "USER_RESOLVER": None}
    km = get_manager()
    django_user_model.objects.create(username="alice")
    i = km.issue("alice")
    assert client.get("/whoami/", **bearer(i.raw_key)).json()["authenticated"] is False


def test_system_check_warns_without_pepper(settings, monkeypatch):
    from django.core import checks

    from safe_api_keys.contrib.django.checks import E001, W001, check_pepper

    assert check_pepper() == []                                   # PEPPERS configured in the test settings
    monkeypatch.delenv("SAFE_API_KEYS_PEPPER", raising=False)
    monkeypatch.delenv("SAFE_API_KEYS_PEPPERS", raising=False)
    settings.SAFE_API_KEYS = {"PREFIX": "sk"}
    found = check_pepper()
    assert [m.id for m in found] == [W001] and isinstance(found[0], checks.Warning)
    assert "SAFE_API_KEYS_PEPPER" in found[0].msg
    assert W001 in {m.id for m in checks.run_checks(tags=[checks.Tags.security])}  # registered with Django
    monkeypatch.setenv("SAFE_API_KEYS_PEPPERS", "garbage-without-version")
    found = check_pepper()
    assert [m.id for m in found] == [E001] and isinstance(found[0], checks.Error)
    monkeypatch.delenv("SAFE_API_KEYS_PEPPERS")
    monkeypatch.setenv("SAFE_API_KEYS_PEPPER", "short123")                   # E: too short must be E001 too
    found = check_pepper()
    assert [m.id for m in found] == [E001] and "16" in found[0].hint
    monkeypatch.setenv("SAFE_API_KEYS_PEPPER", "x" * 40)
    assert check_pepper() == []


def test_drf(client, django_user_model):
    km = get_manager()
    django_user_model.objects.create(username="alice")
    r = client.get("/drf/orders/")
    assert r.status_code == 401 and r.json()["error"] == "missing_api_key"
    assert r["WWW-Authenticate"].startswith("Bearer") and r["Cache-Control"] == "no-store"
    i = km.issue("alice", scopes=["orders:read"])
    assert client.get("/drf/orders/", **bearer(i.raw_key)).json() == {"owner": "alice", "user": "alice"}
    r = client.get("/drf/any/", **bearer(i.raw_key))
    assert r.status_code == 403 and r.json()["error"] == "insufficient_scope" and r["Cache-Control"] == "no-store"
    j = km.issue("bob", scopes=["admin"])
    assert client.get("/drf/any/", **bearer(j.raw_key)).status_code == 200
    assert client.get("/drf/plain/", **bearer(j.raw_key)).json() == {"owner": "bob"}
    r = client.get("/drf/plain/", **bearer("sk_test_bad"))
    assert r.status_code == 401 and r.json()["error"] == "invalid_api_key"
    # DRF composition: the second permission is tried when the first fails
    assert client.get("/drf/composed/", **bearer(j.raw_key)).status_code == 200      # admin
    assert client.get("/drf/composed/", **bearer(i.raw_key)).status_code == 200      # orders:read
    k = km.issue("carol", scopes=["other"])
    r = client.get("/drf/composed/", **bearer(k.raw_key))
    assert r.status_code == 403 and r.json()["error"] == "insufficient_scope"
    assert client.get("/drf/composed/").status_code == 401


def test_reveal_state_setting(client, settings):
    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "REVEAL_STATE": False}
    km = get_manager()
    i = km.issue("u")
    km.revoke(i.key_id)
    assert client.get("/plain/", **bearer(i.raw_key)).json()["error"] == "invalid_api_key"


def test_memory_store_setting(settings):
    settings.SAFE_API_KEYS = {**settings.SAFE_API_KEYS, "STORE": "memory"}
    km = get_manager()
    km.issue("u")
    assert APIKey.objects.count() == 0


def test_settings_validation(settings, monkeypatch):
    settings.SAFE_API_KEYS = {"PREFIX": "Bad Prefix"}
    with pytest.raises(ImproperlyConfigured):
        validate_settings()
    settings.SAFE_API_KEYS = {"PREFIX": "sk", "NOPE": 1}
    with pytest.raises(ImproperlyConfigured):
        validate_settings()
    settings.SAFE_API_KEYS = {"PREFIX": "sk", "POLICY": {"max_ttl": "soon"}}
    with pytest.raises(ImproperlyConfigured):
        validate_settings()
    settings.SAFE_API_KEYS = {"PREFIX": "sk", "TOUCH_INTERVAL": "60"}
    with pytest.raises(ImproperlyConfigured):
        validate_settings()
    # missing pepper only fails when the manager is actually needed (migrate still works)
    monkeypatch.delenv("SAFE_API_KEYS_PEPPER", raising=False)
    monkeypatch.delenv("SAFE_API_KEYS_PEPPERS", raising=False)
    settings.SAFE_API_KEYS = {"PREFIX": "sk"}
    validate_settings()
    with pytest.raises(ImproperlyConfigured, match="pepper"):
        get_manager()
    monkeypatch.setenv("SAFE_API_KEYS_PEPPER", "x" * 40)
    settings.SAFE_API_KEYS = {"PREFIX": "sk", "POLICY": {"max_ttl": "30d"}}
    km = get_manager()
    assert km.policy.max_ttl == timedelta(days=30)


def test_management_command():
    out, err = StringIO(), StringIO()
    call_command("apikey", "issue", "--owner", "svc-billing", "--scopes", "reports:*", "--expires", "365d",
                 "--name", "billing batch", stdout=out, stderr=err)
    raw = out.getvalue().strip()
    assert raw.startswith("sk_test_") and "not be shown again" in err.getvalue()
    key_id = get_manager().parse(raw).key_id
    out = StringIO()
    call_command("apikey", "list", "--owner", "svc-billing", stdout=out)
    assert key_id in out.getvalue() and not SECRET_RE.search(out.getvalue())
    out = StringIO()
    call_command("apikey", "verify", raw, "--scopes", "reports:daily", stdout=out)
    assert out.getvalue().startswith("valid:") and not SECRET_RE.search(out.getvalue())
    out, err = StringIO(), StringIO()
    call_command("apikey", "rotate", key_id, "--grace", "24h", stdout=out, stderr=err)
    new_raw = out.getvalue().strip()
    assert new_raw != raw and get_manager().verify(new_raw).rotated_from == key_id
    out = StringIO()
    call_command("apikey", "revoke", key_id, "--reason", "compromised", stdout=out)
    assert "revoked" in out.getvalue()
    with pytest.raises(CommandError) as ei:
        call_command("apikey", "verify", raw, stdout=StringIO())
    assert ei.value.returncode == 1
    out = StringIO()
    call_command("apikey", "list", "--all", "--json", stdout=out)
    assert '"state": "revoked"' in out.getvalue() and not SECRET_RE.search(out.getvalue())
    out = StringIO()
    call_command("apikey", "purge", "--older-than", "90d", stdout=out)
    assert "purged 0" in out.getvalue()


def _staff(django_user_model, name, *codenames):
    from django.contrib.auth.models import Permission

    user = django_user_model.objects.create_user(name, password="pw-for-tests-only", is_staff=True)
    for codename in codenames:
        user.user_permissions.add(Permission.objects.get(codename=codename))
    return user


def test_admin_actions_require_permissions(client, django_user_model):
    """A: view-only staff can neither rotate (which hands out a key) nor revoke anyone's keys."""
    km = get_manager()
    victim = km.issue("service-a", scopes=["*"])
    rotate = {"action": "rotate_selected", "_selected_action": [victim.key_id]}
    revoke = {"action": "revoke_selected", "_selected_action": [victim.key_id]}

    client.force_login(_staff(django_user_model, "viewer", "view_apikey"))
    page = client.get("/admin/safe_api_keys/apikey/").content.decode()
    assert "rotate_selected" not in page and "revoke_selected" not in page
    r = client.post("/admin/safe_api_keys/apikey/", rotate, follow=True)
    assert r.status_code == 200 and not SECRET_RE.search(scrub(r.content.decode()))
    assert APIKey.objects.get(pk=victim.key_id).rotated_to is None and APIKey.objects.count() == 1
    client.post("/admin/safe_api_keys/apikey/", revoke, follow=True)
    assert APIKey.objects.get(pk=victim.key_id).revoked_at is None

    client.force_login(_staff(django_user_model, "editor", "view_apikey", "change_apikey"))
    page = client.get("/admin/safe_api_keys/apikey/").content.decode()
    assert "revoke_selected" in page and "rotate_selected" not in page
    r = client.post("/admin/safe_api_keys/apikey/", rotate, follow=True)
    assert not SECRET_RE.search(scrub(r.content.decode())) and APIKey.objects.count() == 1  # change != rotate

    client.force_login(_staff(django_user_model, "rotator", "view_apikey", "rotate_apikey"))
    assert "rotate_selected" in client.get("/admin/safe_api_keys/apikey/").content.decode()
    r = client.post("/admin/safe_api_keys/apikey/", rotate, follow=True)
    shown = re.search(r"sk_test_[0-9A-Za-z]{12}_[0-9A-Za-z]{38}", r.content.decode())
    assert shown and km.verify(shown.group(0)).rotated_from == victim.key_id

    client.force_login(_staff(django_user_model, "editor2", "view_apikey", "change_apikey"))
    client.post("/admin/safe_api_keys/apikey/", revoke, follow=True)
    assert APIKey.objects.get(pk=victim.key_id).revoked_at is not None


@pytest.fixture
def admin_client_logged_in(client, django_user_model):
    user = django_user_model.objects.create_superuser("admin", "a@example.com", "pw-for-tests-only")
    client.force_login(user)
    return client


def test_admin(admin_client_logged_in):
    c = admin_client_logged_in
    km = get_manager()
    existing = km.issue("u1", scopes=["orders:read"], name="existing")
    secret = km.parse(existing.raw_key).secret
    page = scrub(c.get("/admin/safe_api_keys/apikey/").content.decode())
    assert existing.record.masked in page and secret not in page and not SECRET_RE.search(page)
    change = scrub(c.get(f"/admin/safe_api_keys/apikey/{existing.key_id}/change/").content.decode())
    assert secret not in change and existing.record.hash not in change and not SECRET_RE.search(change)
    assert 'name="hash"' not in change and 'name="hash_alg"' not in change and 'name="owner"' not in change

    r = c.post("/admin/safe_api_keys/apikey/add/", {"owner": "svc", "name": "batch", "scopes_text": "reports:*",
                                                    "expires_in_days": "30", "ip_allowlist_text": ""}, follow=True)
    html = r.content.decode()
    new = APIKey.objects.get(owner="svc")
    shown = re.search(r"sk_test_[0-9A-Za-z]{12}_[0-9A-Za-z]{38}", html)
    assert shown and "not be shown again" in html
    assert km.verify(shown.group(0)).key_id == new.key_id
    assert r.status_code == 200 and not r.redirect_chain                   # rendered directly, no redirect
    cookies = " ".join(f"{k}={v.value}" for k, v in c.cookies.items())
    assert shown.group(0) not in cookies and "messages" not in c.cookies    # never in the messages cookie
    again = c.get("/admin/safe_api_keys/apikey/").content.decode()
    assert shown.group(0) not in again  # only shown once

    bad = c.post("/admin/safe_api_keys/apikey/add/", {"owner": "svc", "scopes_text": "BAD SCOPE"})
    assert bad.status_code == 200 and "invalid scope" in bad.content.decode()

    r = c.post("/admin/safe_api_keys/apikey/", {"action": "rotate_selected", "_selected_action": [new.key_id]},
               follow=True)
    rotated = re.search(r"sk_test_[0-9A-Za-z]{12}_[0-9A-Za-z]{38}", r.content.decode())
    assert rotated and km.verify(rotated.group(0)).rotated_from == new.key_id
    assert not r.redirect_chain and rotated.group(0) not in " ".join(v.value for v in c.cookies.values())
    assert rotated.group(0) not in c.get("/admin/safe_api_keys/apikey/").content.decode()
    # deleting leaves no audit trail: the admin only revokes
    assert c.get(f"/admin/safe_api_keys/apikey/{new.key_id}/delete/").status_code == 403
    assert "delete_selected" not in c.get("/admin/safe_api_keys/apikey/").content.decode()
    c.post("/admin/safe_api_keys/apikey/", {"action": "delete_selected", "_selected_action": [new.key_id]})
    assert APIKey.objects.filter(pk=new.key_id).exists()
    c.post("/admin/safe_api_keys/apikey/", {"action": "revoke_selected", "_selected_action": [existing.key_id]})
    assert APIKey.objects.get(pk=existing.key_id).revoked_at is not None
    c.post(f"/admin/safe_api_keys/apikey/{existing.key_id}/change/", {"name": "renamed"})
    assert APIKey.objects.get(pk=existing.key_id).name == "renamed"
