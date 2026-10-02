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
