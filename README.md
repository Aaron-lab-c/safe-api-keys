# safe-api-keys

Framework-agnostic API key lifecycle for Python: **issue, verify, revoke, rotate, expire, purge and audit** —
with adapters for **FastAPI / Starlette, Flask, Django / DRF** and a framework-free CLI.

- Stripe/GitHub-style keys: `acme_live_7Hk3bQ9zTm2w_Qx9f…` with a public `key_id` and an offline checksum
- Only an HMAC-SHA256 (peppered) hash is stored; the raw key is shown **once**
- Constant-time checks, dummy hashing for unknown ids, prefix binding between environments
- Scopes with wildcards, IP allow-lists, expiry, rotation with grace period + `Deprecation`/`Sunset` headers
- Stores: Memory, SQLite, SQLAlchemy (sync/async), Redis (sync/async), Django ORM
- Zero dependencies in the core; sync and async managers share one rule set

> 中文摘要在[最後一節](#中文摘要)。資料表建立流程（Flask / Django）請見 [docs/database-setup.md](docs/database-setup.md)。

## Contents

1. [Quick start](#quick-start-30-seconds)
2. [Developer guide: three steps](#developer-guide-three-steps)
3. [Flask end-to-end example](#flask-end-to-end-example)
4. [Django end-to-end example](#django-end-to-end-example)
5. [FastAPI example](#fastapi-example)
6. [Best practices](#best-practices)
7. [Key format and design](#key-format-and-design)
8. [Security model](#security-model)
9. [Storage backends and table creation](#storage-backends-and-table-creation)
10. [Rotation, pepper rotation, revocation and cleanup](#rotation-pepper-rotation-revocation-and-cleanup)
11. [Scopes and policies](#scopes-and-policies)
12. [Audit events](#audit-events)
13. [CLI](#cli)
14. [Migrating from djangorestframework-api-key](#migrating-from-djangorestframework-api-key)
15. [FAQ](#faq)
16. [Benchmarks](#benchmarks)
17. [中文摘要](#中文摘要)

## Quick start (30 seconds)

```bash
pip install safe-api-keys
```

<!-- run -->
```python
from safe_api_keys import KeyManager
from safe_api_keys.stores import MemoryStore

km = KeyManager(MemoryStore(), prefix="sk_test", pepper=b"use-32+-random-bytes-from-env!!!")
issued = km.issue("user-1", scopes=["orders:read"])
print(issued.raw_key)                      # give this to the user once; never store it
record = km.verify(issued.raw_key, scopes=["orders:read"])
assert record.owner == "user-1"
```

In real code the pepper comes from the environment (`KeyManager.from_env(store, "sk_live")` reads
`SAFE_API_KEYS_PEPPER`). Without any pepper construction fails on purpose.

## Developer guide: three steps

1. **Configure once** — create a `KeyManager`: where keys are stored, the prefix, where the pepper comes from,
   and the issuance policy. Django does this from `settings.SAFE_API_KEYS`.
2. **Hand out keys** — in your "Account settings → API keys" page call `km.issue()` and show `raw_key` once;
   operators can issue keys to internal services with the CLI or the Django admin.
3. **Protect endpoints** — decorators for Flask/Django, `Depends` for FastAPI, or a middleware for a whole path
   prefix. On success read `owner` and `scopes` from `g.api_key` / `request.api_key` / the dependency value and
   use them for data isolation.

Clients call every framework the same way:

```bash
curl -H "Authorization: Bearer acme_live_7Hk3bQ9zTm2w_Qx9f...K7c9" https://api.example.com/api/orders
# or
curl -H "X-API-Key: acme_live_7Hk3bQ9zTm2w_Qx9f...K7c9" https://api.example.com/api/orders
```

Failures:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api", error="invalid_token"
Cache-Control: no-store
{"error": "invalid_api_key", "message": "Invalid API key"}

HTTP/1.1 403 Forbidden
{"error": "insufficient_scope", "message": "Insufficient scope", "required": ["orders:write"], "missing": ["orders:write"]}
```

| Situation | Exception | HTTP | `error` |
|---|---|---|---|
| no key | `MissingKey` | 401 | `missing_api_key` |
| bad format / checksum / prefix | `MalformedKey` | 401 | `invalid_api_key` |
| unknown id or wrong secret | `UnknownKey` | 401 | `invalid_api_key` |
| revoked | `RevokedKey` | 401 | `revoked_api_key` (`invalid_api_key` with `reveal_state=False`) |
| expired | `ExpiredKey` | 401 | `expired_api_key` (`invalid_api_key` with `reveal_state=False`) |
| missing scope | `InsufficientScope` | 403 | `insufficient_scope` |
| IP not allowed | `IPNotAllowed` | 403 | `ip_not_allowed` |
| store down | `StoreError` | 503 | `auth_unavailable` |

## Flask end-to-end example

Runnable project: [`examples/flask_app`](examples/flask_app) (CI runs its tests).

```bash
pip install "safe-api-keys[flask,sqlalchemy]"
export SAFE_API_KEYS_PEPPER="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
cd examples/flask_app && flask --app app run      # create_app() is discovered automatically
```

<!-- include: examples/flask_app/app.py -->
```python
# examples/flask_app/app.py
import os
from datetime import timedelta

from flask import Blueprint, Flask, abort, g, jsonify, request, session
from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import sessionmaker

from safe_api_keys import KeyManager, KeyPolicy
from safe_api_keys.contrib.flask import APIKeys
from safe_api_keys.stores import SQLAlchemyStore, make_api_key_table


# ---- 1. 設定一次 -------------------------------------------------------------
def build_manager(database_url=None):
    engine = create_engine(database_url or os.environ.get("DATABASE_URL", "sqlite:///flask_example.db"))
    SessionLocal = sessionmaker(bind=engine)

    metadata = MetaData()
    make_api_key_table(metadata)              # 定義 safe_api_keys 資料表
    metadata.create_all(engine)               # 正式專案改交給 Alembic autogenerate（見 docs/database-setup.md）

    return KeyManager(
        SQLAlchemyStore(SessionLocal),
        prefix="acme_live",                   # 測試環境另建一個 prefix="acme_test" 的 manager
        pepper=os.environ["SAFE_API_KEYS_PEPPER"].encode(),
        policy=build_policy(),
    )


def build_policy():
    return KeyPolicy(
        max_ttl=timedelta(days=365),
        allowed_scopes={"orders:read", "orders:write", "reports:*"},
        max_active_keys_per_owner=10,
    )


# ---- 示範用的業務資料與登入（換成你自己的 model / 登入機制）-------------------------
ORDERS = {}  # owner -> list of orders


def get_logged_in_user_or_401():
    user_id = session.get("user_id")
    if user_id is None:
        abort(401)
    return type("User", (), {"id": user_id})()


def load_orders(owner):
    return ORDERS.get(owner, [])


def create_order_for(owner, payload):
    order = {"id": len(ORDERS.get(owner, [])) + 1, "owner": owner, **(payload or {})}
    ORDERS.setdefault(owner, []).append(order)
    return order


def build_report(owner, name):
    return {"report": name, "owner": owner, "orders": len(load_orders(owner))}


def create_app(km=None):
    km = km or build_manager()
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # 跨站請求不帶 session cookie（CSRF 第一道防線）
    app.extensions["km"] = km
    keys = APIKeys(km)                        # 註冊 errorhandler，提供裝飾器
    keys.init_app(app)

    @app.errorhandler(ValueError)             # PolicyViolation / 非法 scope 等輸入錯誤 → 400
    def bad_request(exc):
        return jsonify(error="bad_request", message=str(exc)), 400

    # ---- CSRF：用 session cookie 登入的端點（/login、/account/*）只接受 application/json ----
    # 跨站網頁只能用 HTML 表單送 form/text 內容；要送 JSON 必須經過 CORS 預檢，預設會被瀏覽器擋下。
    # 若前端用傳統表單，請改用 Flask-WTF 的 CSRFProtect。受 API key 保護的 /api/* 不靠 cookie，不需要 CSRF。
    @app.before_request
    def require_json_for_session_endpoints():
        session_path = request.path == "/login" or request.path.startswith("/account/")
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and session_path and not request.is_json:
            return jsonify(error="unsupported_media_type", message="Content-Type must be application/json"), 415
        return None

    @app.post("/login")                       # 示範：以 session 登入（正式專案用你原本的登入）
    def login():
        session["user_id"] = str(request.get_json()["user_id"])
        return "", 204

    # ---- 2. 讓登入中的使用者管理自己的 key（這些端點用你原本的 session 登入保護）------
    def current_owner() -> str:
        # 以你自己的登入機制取得使用者，owner 建議用不可變的主鍵字串
        user = get_logged_in_user_or_401()
        return str(user.id)

    @app.post("/account/api-keys")
    def create_key():
        body = request.get_json()
        issued = km.issue(
            owner=current_owner(),
            name=body.get("name", ""),
            scopes=body.get("scopes", ["orders:read"]),
            expires_in=timedelta(days=body.get("days", 90)),
        )
        # raw_key 只會出現這一次；前端要顯示「請立即複製，之後無法再查看」
        return jsonify(
            api_key=issued.raw_key,
            key_id=issued.record.key_id,
            masked=issued.record.masked,
            expires_at=issued.record.expires_at.isoformat(),
        ), 201

    @app.get("/account/api-keys")
    def list_keys():
        rows = km.list(owner=current_owner())
        return jsonify([
            {"key_id": r.key_id, "masked": r.masked, "name": r.name, "scopes": list(r.scopes),
             "created_at": r.created_at.isoformat(),
             "expires_at": r.expires_at.isoformat() if r.expires_at else None,
             "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
             "state": r.state()}
            for r in rows
        ])

    def _own_key_or_404(key_id: str):
        rec = km.get(key_id)
        if rec is None or rec.owner != current_owner():
            abort(404)                        # 不洩漏別人的 key 是否存在
        return rec

    @app.delete("/account/api-keys/<key_id>")
    def revoke_key(key_id):
        _own_key_or_404(key_id)
        km.revoke(key_id, reason="user_request")
        return "", 204

    @app.post("/account/api-keys/<key_id>/rotate")
    def rotate_key(key_id):
        _own_key_or_404(key_id)
        issued = km.rotate(key_id, grace=timedelta(hours=24))   # 舊 key 24 小時後失效
        return jsonify(api_key=issued.raw_key, key_id=issued.record.key_id, masked=issued.record.masked), 201

    # ---- 3. 受 API key 保護的對外 API -------------------------------------------------
    api = Blueprint("api", __name__, url_prefix="/api")

    @api.get("/orders")
    @keys.required(scopes=["orders:read"])
    def orders():
        owner = g.api_key.owner               # 用 owner 做資料隔離，絕不信任 body 裡的 user id
        return jsonify(load_orders(owner=owner))

    @api.post("/orders")
    @keys.required(scopes=["orders:write"])
    def create_order():
        return jsonify(create_order_for(g.api_key.owner, request.get_json(silent=True))), 201

    @api.get("/reports/<name>")
    @keys.required(any_scopes=["reports:*", "admin"])
    def report(name):
        return jsonify(build_report(g.api_key.owner, name))

    @api.get("/health")                      # 不需要 key 的端點就不要加裝飾器
    def health():
        return {"ok": True}

    # 替代寫法：整個 blueprint 一律需要有效 key（scope 仍可在各 view 用 keys.required 細分）
    # keys.protect_blueprint(api, exempt=["/api/health"])

    app.register_blueprint(api)
    return app


if __name__ == "__main__":
    create_app().run(debug=True)
```

Tests use a `MemoryStore` and an injected clock:

<!-- include: examples/flask_app/test_app.py -->
```python
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
```

The table is created by `metadata.create_all(engine)` in `build_manager()`; for production use Alembic
(see [docs/database-setup.md](docs/database-setup.md#方式-b正式環境用-alembic-autogenerate建議), verified by
`examples/flask_app/test_migrations.py`).

## Django end-to-end example

Runnable project: [`examples/django_app`](examples/django_app).

```bash
pip install "safe-api-keys[django,drf]"
cd examples/django_app
python manage.py migrate                   # creates the safe_api_keys_apikey table
export SAFE_API_KEYS_PEPPER="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
python manage.py runserver
```

<!-- include: examples/django_app/settings.py -->
```python
# examples/django_app/settings.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-change-me")
DEBUG = True
ALLOWED_HOSTS = ["*"]
USE_TZ = True
ROOT_URLCONF = "shop.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",                       # 選用
    "safe_api_keys.contrib.django",         # 提供 APIKey model、admin、管理指令
    "shop",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "safe_api_keys.contrib.django.middleware.APIKeyMiddleware",   # 選用：用 PROTECT/EXEMPT 一次保護路徑
]

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
STATIC_URL = "static/"

SAFE_API_KEYS = {
    "PREFIX": "acme_live",
    "PEPPER_ENV": "SAFE_API_KEYS_PEPPER",   # 從環境變數讀；絕不寫死在 settings
    "EXTRACT": {"bearer": True, "header": "X-API-Key"},
    "POLICY": {"max_ttl": "365d", "allowed_scopes": ["orders:read", "orders:write", "reports:*"],
               "max_active_keys_per_owner": 10},
    "PROTECT": ["/api/"],
    "EXEMPT": ["/api/health/"],
    "USER_RESOLVER": "shop.auth.user_from_owner",   # DRF：把 owner 還原成 User
}

# DRF 錯誤回應也帶 Cache-Control: no-store 與 §13.2 的 JSON 格式
REST_FRAMEWORK = {"EXCEPTION_HANDLER": "safe_api_keys.contrib.django.drf.exception_handler"}
```

<!-- include: examples/django_app/shop/auth.py -->
```python
# shop/auth.py
from django.contrib.auth import get_user_model


def user_from_owner(owner: str):
    return get_user_model().objects.filter(pk=owner).first()   # owner 存的是 user.pk 字串
```

<!-- include: examples/django_app/shop/views_account.py -->
```python
# shop/views_account.py — 登入使用者管理自己的 key（用 Django session 登入保護）
#
# CSRF：這些端點靠 session cookie 認證，所以 Django 的 CsrfViewMiddleware 會檢查 POST/DELETE。
# 前端先 GET /account/csrf/ 取得 csrftoken cookie，之後每個 POST/DELETE 帶 header
#   X-CSRFToken: <csrftoken cookie 的值>
# 沒帶會得到 403（Django 測試客戶端預設不檢查 CSRF，真實伺服器會）。
# 只給 API key 呼叫的端點（views_api.py）不靠 cookie，用 @csrf_exempt 即可。
import json
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods

from safe_api_keys import PolicyViolation
from safe_api_keys.contrib.django import get_manager


def km():
    return get_manager()                    # 由 settings.SAFE_API_KEYS 建好的單例


@ensure_csrf_cookie
def csrf(request):
    """讓 SPA／前端取得 csrftoken cookie。"""
    return HttpResponse(status=204)


@login_required
@require_http_methods(["POST"])
def create_key(request):
    body = json.loads(request.body or "{}")
    try:
        issued = km().issue(
            owner=str(request.user.pk),
            name=body.get("name", ""),
            scopes=body.get("scopes", ["orders:read"]),
            expires_in=timedelta(days=body.get("days", 90)),
        )
    except (PolicyViolation, ValueError) as exc:
        return JsonResponse({"error": "bad_request", "message": str(exc)}, status=400)
    return JsonResponse(
        {"api_key": issued.raw_key, "key_id": issued.record.key_id, "masked": issued.record.masked,
         "expires_at": issued.record.expires_at.isoformat()},
        status=201,
    )


@login_required
def list_keys(request):
    rows = km().list(owner=str(request.user.pk))
    return JsonResponse([{"key_id": r.key_id, "masked": r.masked, "name": r.name,
                          "scopes": list(r.scopes), "state": r.state()} for r in rows], safe=False)


def _own_key_or_404(request, key_id):
    rec = km().get(key_id)
    if rec is None or rec.owner != str(request.user.pk):
        raise Http404
    return rec


@login_required
@require_http_methods(["POST", "DELETE"])
def revoke_key(request, key_id):
    _own_key_or_404(request, key_id)
    km().revoke(key_id, reason="user_request")
    return HttpResponse(status=204)


@login_required
@require_http_methods(["POST"])
def rotate_key(request, key_id):
    _own_key_or_404(request, key_id)
    issued = km().rotate(key_id, grace=timedelta(hours=24))
    return JsonResponse({"api_key": issued.raw_key, "key_id": issued.record.key_id}, status=201)
```

<!-- include: examples/django_app/shop/views_api.py -->
```python
# shop/views_api.py — 受 API key 保護的對外 API（純 Django view，用裝飾器）
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from safe_api_keys.contrib.django import require_api_key

from .models import Order


@require_api_key(scopes=["orders:read"])
def orders(request):
    owner = request.api_key.owner           # 以 owner 做資料隔離
    return JsonResponse(list(Order.objects.filter(owner_id=owner).values("id", "item", "qty")), safe=False)


@csrf_exempt                                # API key 請求不帶 session cookie，不需 CSRF
@require_http_methods(["POST"])
@require_api_key(scopes=["orders:write"])
def create_order(request):
    body = json.loads(request.body or "{}")
    order = Order.objects.create(owner_id=request.api_key.owner, item=body.get("item", "?"), qty=body.get("qty", 1))
    return JsonResponse({"id": order.id, "item": order.item, "qty": order.qty}, status=201)


@require_api_key(any_scopes=["reports:*", "admin"])
def report(request, name):
    return JsonResponse({"report": name, "orders": Order.objects.filter(owner_id=request.api_key.owner).count()})


def health(request):
    return JsonResponse({"ok": True})
```

<!-- include: examples/django_app/shop/api_drf.py -->
```python
# shop/api_drf.py — 同一件事的 DRF 寫法
from rest_framework.response import Response
from rest_framework.views import APIView

from safe_api_keys.contrib.django.drf import APIKeyAuthentication, HasAPIKeyScope

from .models import Order


class OrdersView(APIView):
    # request.user 由 USER_RESOLVER 解析，request.auth 是 KeyRecord
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [HasAPIKeyScope("orders:read")]

    def get(self, request):
        return Response(list(Order.objects.filter(owner_id=request.auth.owner).values("id", "item", "qty")))
```

<!-- include: examples/django_app/shop/urls.py -->
```python
# shop/urls.py
from django.contrib import admin
from django.urls import path

from . import views_account, views_api
from .api_drf import OrdersView
from .views_api import health

urlpatterns = [
    path("admin/", admin.site.urls),                                   # API keys 頁面：發行 / 撤銷 / 輪替
    path("account/csrf/", views_account.csrf),                         # GET：設定 csrftoken cookie
    path("account/api-keys/", views_account.list_keys),               # GET
    path("account/api-keys/create/", views_account.create_key),       # POST
    path("account/api-keys/<str:key_id>/revoke/", views_account.revoke_key),
    path("account/api-keys/<str:key_id>/rotate/", views_account.rotate_key),
    path("api/orders/", views_api.orders),
    path("api/orders/create/", views_api.create_order),
    path("api/reports/<str:name>/", views_api.report),
    path("api/health/", health),                                      # 在 EXEMPT 內，不需 key
    path("api/v2/orders/", OrdersView.as_view()),
]
```

Operators can issue keys to internal services without the web UI:

```bash
python manage.py apikey issue --owner svc-billing --scopes "reports:*" --expires 365d --name "billing batch"
python manage.py apikey list --owner svc-billing
python manage.py apikey rotate <key_id> --grace 24h
python manage.py apikey revoke <key_id> --reason compromised
```

…or press **Add API key** in the Django admin: the raw key is shown once in the success message.

Test settings and tests:

<!-- include: examples/django_app/settings_test.py -->
```python
# examples/django_app/settings_test.py
from .settings import *  # noqa: F401,F403
from .settings import SAFE_API_KEYS

SAFE_API_KEYS = {**SAFE_API_KEYS, "STORE": "memory", "PEPPERS": {"v1": b"test-pepper-32-bytes-xxxxxxxxxxxxx"},
                 "CURRENT_PEPPER": "v1"}
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
```

<!-- include: examples/django_app/tests/test_shop.py -->
```python
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
```

## FastAPI example

Runnable project: [`examples/fastapi_app`](examples/fastapi_app).

<!-- include: examples/fastapi_app/main.py -->
```python
# examples/fastapi_app/main.py
import os
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from safe_api_keys import AsyncKeyManager, KeyRecord
from safe_api_keys.contrib.fastapi import APIKeyAuth
from safe_api_keys.stores import AsyncSQLAlchemyStore

engine = create_async_engine(os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///fastapi_example.db"))
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
PEPPER = os.environ["SAFE_API_KEYS_PEPPER"].encode()

store = AsyncSQLAlchemyStore(async_session)
km = AsyncKeyManager(store, prefix="acme_live", pepper=PEPPER)
auth = APIKeyAuth(km)


@asynccontextmanager
async def lifespan(app):
    await store.create_table(engine)          # 開發用；正式專案交給 Alembic（見 docs/database-setup.md）
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)
auth.install(app)                             # 錯誤回應採 {"error", "message"} JSON 格式


# ---- 示範用：換成你自己的登入與資料存取 ------------------------------------------------
ORDERS = {}


async def current_user(x_demo_user: str = Header(default=None)):
    if not x_demo_user:
        raise HTTPException(401, "login required")
    return type("User", (), {"id": x_demo_user})()


async def load_orders(owner):
    return ORDERS.get(owner, [])


# ---- 發 key 與受保護端點 ----------------------------------------------------------------
@app.post("/account/api-keys", status_code=201)
async def create_key(user=Depends(current_user)):
    issued = await km.issue(owner=str(user.id), scopes=["orders:read"], expires_in=timedelta(days=90))
    return {"api_key": issued.raw_key, "key_id": issued.record.key_id}


@app.get("/api/orders")
async def orders(key: KeyRecord = Depends(auth.scopes("orders:read"))):
    return await load_orders(owner=key.owner)
```

`auth.scopes(...)`, `auth.any_scopes(...)` and `auth.optional()` build dependencies; FastAPI's OpenAPI document
lists the `securitySchemes` and each operation's required scopes. `APIKeyMiddleware(app, km, protect=("/api/",),
exempt=("/api/health",))` protects a whole prefix. Call `auth.install(app)` so errors use the JSON body above
(without it FastAPI renders `{"detail": ...}` but status codes and headers are the same).

## Best practices

- Use an **immutable** identifier as `owner` (user primary key, tenant id), never an email.
- Filter every protected query by `api_key.owner`; never trust user ids in the request body.
- Protect the self-service endpoints (create/list/revoke/rotate) with your normal login and check that the
  key's `owner` is the current user before acting. Those endpoints use **cookie sessions, so they need CSRF
  protection** — see [CSRF](#csrf-session-endpoints-vs-api-key-endpoints).
- Separate environments with different prefixes (`acme_live` / `acme_test`) **and** different peppers.
- Keep the pepper in an environment variable or secret manager; rotate it with versions (see below), never by
  replacing it in place. Hard-coding a pepper in source is not allowed.
- Show the raw key with a *copy* button and a "will not be shown again" warning; lists show `masked` only.
- Rotation flow: user clicks rotate → gets new key → updates client → within the 24 h grace the old key still
  works and responses carry `Deprecation`/`Sunset` → then it expires.
- Suspected leak: `revoke(reason="compromised")` is immediate (with `VerifyCache`, other processes may accept
  it for up to `cache.ttl` seconds).
- Run `purge(older_than=timedelta(days=90))` periodically, or keep records for audit.
- Rate-limit outside the adapter (`slowapi`, `flask-limiter`, `django-ratelimit`) keyed by `key_id`; adapters
  accept `on_rejected(client_ip, key_id)` for failure counting.

### CSRF: session endpoints vs API-key endpoints

Two kinds of endpoints live side by side and need different protection:

| Endpoint | Authenticated by | CSRF protection |
|---|---|---|
| `/api/*` (called with an API key) | `Authorization` / `X-API-Key` header | **not needed** — browsers never attach these headers automatically. In Django mark them `@csrf_exempt` if they accept POST. |
| `/account/api-keys/*` (users manage their own keys) | session cookie | **required** — otherwise another site can make a logged-in user's browser rotate or revoke keys. |

- **Django**: `CsrfViewMiddleware` already enforces it. The front-end first calls `GET /account/csrf/`
  (`@ensure_csrf_cookie`) and then sends `X-CSRFToken: <csrftoken cookie>` on every POST/DELETE; without it a
  real server answers 403. Django's test client skips CSRF by default — test with
  `Client(enforce_csrf_checks=True)` (the example does).
- **Flask** has no CSRF protection by default. The example sets `SESSION_COOKIE_SAMESITE="Lax"` and only accepts
  `Content-Type: application/json` on `/login` and `/account/*` (an HTML form on another site cannot send JSON
  without a CORS preflight; other bodies get 415). If your front-end posts classic HTML forms, use
  Flask-WTF's `CSRFProtect` instead.
- **FastAPI**: same rule as Flask when the self-service endpoints use cookies; API-key endpoints need nothing.

Both examples were also exercised on real servers (`flask run`, `manage.py runserver`, `uvicorn`), where
missing CSRF tokens are rejected as described.

## Key format and design

```
acme_live_7Hk3bQ9zTm2w_Qx9fLm2...pR3K7c9a1B2c
└──┬────┘ └────┬─────┘ └──────┬──────┘└──┬──┘
 prefix     key_id      secret (32)   checksum (6)
 env/product 12 base62  ≥180 bits     CRC32, base62
```

- `prefix` identifies product and environment; one manager accepts one prefix (keys from another environment
  are rejected as malformed).
- `key_id` is public and indexed: it shows up in logs, admin and audit events and lets us find the record
  with one primary-key lookup.
- `checksum` lets us reject typos and random guesses **without touching the database**.
- Parsing uses `rsplit("_", 2)`, so prefixes may contain `_`.

**Why HMAC-SHA256 and not bcrypt/argon2?** The secret is 190 random bits; brute-forcing it is impossible
whatever the hash. Slow password hashes protect *low-entropy* passwords and would add 50–300 ms per request.
HMAC with a server-side pepper additionally makes a stolen database useless without the pepper.
`Argon2Hasher` (`[argon2]` extra) exists for policies that demand it.

**Why store `key_id` in clear?** It is not secret (like a username) and enables O(1) lookup, log
correlation and per-key rate limiting.

## Security model

- Raw keys exist only in the `issue`/`rotate` return value. `KeyRecord` has no secret field; reprs, logs,
  exceptions, audit events, admin pages and CLI output show `masked` (tests scan every output for any
  32-character base62 run).
- Keys are generated with `secrets`; only `HMAC-SHA256(pepper, prefix_keyid_secret)` is stored, tagged with a
  versioned `hash_alg`.
- Comparisons use `hmac.compare_digest`; an unknown `key_id` still performs a dummy hash, and malformed /
  unknown keys produce the same message.
- Length, charset and checksum are validated before any database access.
- State decisions (revoked → expired → scope → IP) happen in the core, never via backend TTLs.
- Usage tracking (`touch`) is a throttled partial update; failures never fail authentication.
- 401 responses carry `WWW-Authenticate`; 401/403 carry `Cache-Control: no-store`.
- `X-Forwarded-For` is ignored unless `trust_proxy=True` / `trusted_proxies=[...]`; keys in query strings
  are off by default.

Threat model (see [SECURITY.md](SECURITY.md)): protects against database leaks, brute-force guessing,
environment mix-ups and gives a clear incident procedure. It does not protect against missing TLS or keys
embedded in browser/mobile front-ends.

## Storage backends and table creation

| Store | Install | Notes |
|---|---|---|
| `MemoryStore()` | core | tests, single process |
| `SQLiteStore(path)` | core | creates its table automatically, WAL mode |
| `SQLAlchemyStore(sessionmaker)` / `AsyncSQLAlchemyStore(async_sessionmaker)` | `[sqlalchemy]` | `make_api_key_table(metadata)` or `APIKeyMixin`; Alembic-friendly |
| `RedisStore(client)` / `AsyncRedisStore(client)` | `[redis]` | hashes + owner sets; EXPIREAT as housekeeping only |
| `DjangoStore()` | `[django]` | `python manage.py migrate` creates `safe_api_keys_apikey` |
| `from_url(url)` | | `memory://`, `sqlite:///path`, `redis://…`, `sqlalchemy+postgresql://…` |

Step-by-step table creation for **Flask (create_all / Alembic / Flask-SQLAlchemy / Flask-Migrate)** and
**Django (migrate / custom model / existing databases)**: [docs/database-setup.md](docs/database-setup.md).

## Rotation, pepper rotation, revocation and cleanup

```python
new = km.rotate(old_key_id, grace=timedelta(hours=24))   # new key inherits owner/name/scopes/metadata/IPs
# old key: expires_at = min(original, now + 24h), rotated_to = new.key_id
# grace=timedelta(0) revokes the old key immediately
km.lineage(new.key_id)                                     # whole chain, oldest first
```

During the grace period, verifying the old key emits `key.verified` with `extra["rotated_to"]` (monitor who still
uses it) and adapters add `Deprecation: true` and `Sunset: <expires_at>` to responses.

**Pepper rotation** — add a new version, keep the old one for verification:

```python
km = KeyManager(store, "acme_live", peppers={"v2": new_pepper, "v1": old_pepper}, current_pepper="v2")
km.count_by_hash_alg()   # {"hmac-sha256$v1": 120, "hmac-sha256$v2": 30}; drop v1 when its count is 0
```
Env vars: `SAFE_API_KEYS_PEPPERS="v2:…,v1:…"` and `SAFE_API_KEYS_CURRENT_PEPPER=v2`.

**Revocation** is immediate and irreversible (the record is kept for audit). `delete()` and
`purge(older_than=...)` actually remove rows.

## Scopes and policies

Scopes look like `orders:read`, `reports.v2:export-csv`; `orders:*` covers `orders:read` and
`orders:items:write` but not `orders`; `*` covers everything. `verify(scopes=[...])` requires all,
`any_scopes=[...]` at least one.

Suggested design: `<resource>:<action>` (`orders:read`, `orders:write`), wildcards for internal services,
a separate `admin` scope, and least privilege by default.

```python
KeyPolicy(
    require_expiry=False,
    max_ttl=timedelta(days=365),          # no explicit expiry -> capped at max_ttl
    default_ttl=timedelta(days=90),
    allowed_scopes={"orders:read", "orders:write", "reports:*"},
    max_active_keys_per_owner=10,
    allow_no_scope=False,
)
```
Policies apply to `issue`/`rotate` only, so tightening a policy never breaks keys already issued.

## Audit events

`key.issued`, `key.verified`, `key.rejected` (with `reason`: malformed/checksum/prefix/unknown/bad_secret/
pepper_version_missing/revoked/expired/scope/ip), `key.revoked`, `key.rotated`, `key.rotate_partial`,
`key.touch_failed`, `key.purged`. Sinks never raise.

```python
import logging
from safe_api_keys import LoggingAuditSink, CallbackAuditSink

km = KeyManager(store, "acme_live", pepper=PEPPER, audit=LoggingAuditSink("myapp.audit"),
                audit_success=False)            # skip key.verified noise

# OpenTelemetry: one span event per audit event
from opentelemetry import trace

def to_otel(event):
    span = trace.get_current_span()
    span.add_event(event.type, {k: str(v) for k, v in event.as_dict().items() if v is not None})

km = KeyManager(store, "acme_live", pepper=PEPPER, audit=CallbackAuditSink(to_otel))
```

## CLI

```bash
export SAFE_API_KEYS_PEPPER=...  SAFE_API_KEYS_STORE=sqlite:///keys.db
safe-api-keys issue  --prefix acme_live --owner svc --scopes reports:* --expires 90d
safe-api-keys verify --prefix acme_live acme_live_...      # exit 0 valid / 1 invalid
safe-api-keys list   [--owner O] [--all] [--json]
safe-api-keys rotate --prefix acme_live KEY_ID --grace 24h
safe-api-keys revoke KEY_ID --reason compromised
safe-api-keys purge  --older-than 90d
safe-api-keys parse  acme_live_...                         # no store needed
```
Exit codes: 0 ok, 1 invalid/not found, 2 usage/config error, 3 store error. Only `issue`/`rotate` print a raw key.

## Migrating from djangorestframework-api-key

The two libraries use different key formats and hashes, so existing keys cannot be converted; migrate by
running both side by side:

1. Add `safe_api_keys.contrib.django` and `migrate`.
2. Put `APIKeyAuthentication` first and keep the old permission as a fallback:
   `permission_classes = [HasAPIKeyScope("orders:read") | OldHasAPIKey]`.
3. Issue new keys (admin or `manage.py apikey issue`) with an owner and scopes for each client.
4. Monitor old-key usage, then remove the old package and revoke the old keys.

## FAQ

**JWT or API keys?** JWTs are short-lived, self-contained tokens for user sessions/federation. API keys are
long-lived credentials for machines, revocable server-side and attributable to an owner.

**Should I enable `VerifyCache`?** Only for very high traffic. It saves one read per request but a revocation
done in another process takes up to `ttl` seconds to be seen (same-process revocations are immediate).

**Multi-tenant?** Use the tenant id as `owner` (or put `tenant_id` in `metadata`) and filter by it.

**Why is the query-string source off?** URLs end up in access logs, proxies and browser history.

**Custom error format (RFC 9457)?**

```python
def problem(exc):
    status = getattr(exc, "status_code", 401)
    return status, {"Content-Type": "application/problem+json", "Cache-Control": "no-store"}, {
        "type": f"https://example.com/errors/{exc.error_code}", "title": exc.public_message, "status": status}

APIKeyAuth(km, error_formatter=problem)        # also APIKeys(...) for Flask, APIKeyMiddleware(...)
```

## Benchmarks

`python benchmarks/bench_verify.py` (Python 3.11, Windows x86-64, one core):

| Path | Time |
|---|---|
| parse + HMAC + decide (no I/O) | **7.3 µs/op** (target < 50 µs) |
| `KeyManager.verify` with `MemoryStore` | 14.6 µs/op |
| memory growth over 100 000 verifies | 28 bytes |

## 中文摘要

**safe-api-keys** 是框架無關的 API key 生命週期函式庫：發行、驗證、撤銷、輪替、到期、清理、稽核，並提供
FastAPI／Starlette、Flask、Django／DRF 轉接器與 CLI。

- Key 格式 `prefix_keyid_secret+checksum`：`key_id` 公開可查、checksum 不查資料庫即可擋掉打錯或亂猜的 key。
- 資料庫只存 HMAC-SHA256（加 pepper）雜湊；raw key 只在發行／輪替時回傳一次。
- 常數時間比對、不存在的 key 也做一次假雜湊；格式錯誤與查無 key 的訊息一致。
- 支援 scope 萬用字元、IP 白名單、到期、含 grace 期的輪替（回應帶 `Deprecation`／`Sunset`）、pepper 多版本。
- 儲存後端：Memory、SQLite、SQLAlchemy（同步／非同步）、Redis（同步／非同步）、Django ORM。
- 三個可執行範例：`examples/flask_app`、`examples/django_app`、`examples/fastapi_app`，CI 每次都會執行，
  README 中的範例程式碼由 `tools/readme_examples.py --check` 保證與範例檔完全一致。
- **資料表建立流程**：Flask（`create_all`、Alembic autogenerate、Flask-SQLAlchemy／Flask-Migrate）與 Django
  （`migrate`、自訂 model、既有資料庫）請見 [docs/database-setup.md](docs/database-setup.md)。

License: MIT.
