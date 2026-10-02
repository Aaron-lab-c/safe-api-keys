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
