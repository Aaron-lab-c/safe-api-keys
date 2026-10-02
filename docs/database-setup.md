# 資料表建立與欄位自動化：Flask 與 Django 操作流程

本文件說明 safe-api-keys 的 API key 資料表**如何自動建立**、**正式環境如何用 migration 管理**，以及**如何驗證欄位已正確建立**。
文中每個流程都有對應的自動化測試（見各節最後的「驗證」），CI 會實際跑過。

- [共通：資料表長什麼樣子](#共通資料表長什麼樣子)
- [Flask（SQLAlchemy）](#flasksqlalchemy)
  - [方式 A：開發期一行 `create_all()`](#方式-a開發期一行-create_all)
  - [方式 B：正式環境用 Alembic autogenerate（建議）](#方式-b正式環境用-alembic-autogenerate建議)
  - [方式 C：Flask-SQLAlchemy / Flask-Migrate](#方式-cflask-sqlalchemy--flask-migrate)
  - [方式 D：自訂表名 / 宣告式 model（`APIKeyMixin`）](#方式-d自訂表名--宣告式-modelapikeymixin)
  - [不用 SQLAlchemy：`SQLiteStore` 自動建表](#不用-sqlalchemysqlitestore-自動建表)
- [Django](#django)
  - [標準流程：`INSTALLED_APPS` + `migrate`](#標準流程installed_apps--migrate)
  - [自訂 model（`AbstractAPIKey`）](#自訂-modelabstractapikey)
  - [既有資料庫 / 無法跑 migrate 的環境](#既有資料庫--無法跑-migrate-的環境)
- [升級套件時的 schema 變更](#升級套件時的-schema-變更)
- [常見問題](#常見問題)

---

## 共通：資料表長什麼樣子

所有 SQL 後端（SQLite、SQLAlchemy、Django）使用同一組欄位（規格 §12.4）：

| 欄位 | 型別 | 說明 |
|---|---|---|
| `key_id` | VARCHAR(16) **PK** | 公開識別碼，可出現在 log |
| `prefix` | VARCHAR(32) | 例如 `acme_live` |
| `hash` | VARCHAR(255) | HMAC-SHA256 十六進位（64 碼）；保留 255 以容納 Argon2 |
| `hash_alg` | VARCHAR(32) | 例如 `hmac-sha256$v1`，pepper 輪替用 |
| `secret_last4` | CHAR(4) | 顯示用 `masked` |
| `owner` | VARCHAR(255) **INDEX** | 持有者（建議 user 主鍵字串） |
| `name` | VARCHAR(255) | 人類可讀標籤 |
| `scopes` | JSON | 例如 `["orders:read"]` |
| `created_at` / `expires_at`(**INDEX**) / `revoked_at` / `last_used_at` | 時間（UTC） | PostgreSQL 為 `TIMESTAMPTZ`；MySQL 為 `DATETIME(6)`；SQLite 為 ISO 文字 |
| `revoke_reason` | VARCHAR(255) | |
| `use_count` | BIGINT | 節流更新 |
| `rotated_from` / `rotated_to` | VARCHAR(16) | 輪替鏈 |
| `ip_allowlist` | JSON | CIDR 陣列 |
| `metadata` | JSON | ≤ 8 KB、深度 ≤ 3 |

> 表中**沒有** raw key 或 secret 欄位，只有 hash。

---

## Flask（SQLAlchemy）

安裝：

```bash
pip install "safe-api-keys[flask,sqlalchemy]"
```

套件提供 `make_api_key_table(metadata, name="safe_api_keys")`，把資料表**定義**掛到你的 `MetaData` 上。
「定義」與「建立」分開：你決定要用 `create_all()`（開發）還是 Alembic（正式）建立它。

### 方式 A：開發期一行 `create_all()`

```python
import os
from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import sessionmaker
from safe_api_keys import KeyManager
from safe_api_keys.stores import SQLAlchemyStore, make_api_key_table

engine = create_engine("sqlite:///app.db")          # 或 postgresql+psycopg://...
metadata = MetaData()
make_api_key_table(metadata)                         # 1) 定義 safe_api_keys 資料表
metadata.create_all(engine)                          # 2) 不存在才建立（可重複執行）

km = KeyManager(SQLAlchemyStore(sessionmaker(bind=engine)), prefix="acme_live",
                pepper=os.environ["SAFE_API_KEYS_PEPPER"].encode())
```

`create_all()` 是冪等的：表已存在就跳過，所以放在應用程式啟動流程裡沒有問題。
這正是 [`examples/flask_app/app.py`](../examples/flask_app/app.py) 的 `build_manager()` 做法。

也可以只建這一張表（不碰其他表）：

```python
store = SQLAlchemyStore(sessionmaker(bind=engine))
store.create_table(engine)                           # = table.create(engine, checkfirst=True)
```

> ⚠️ `create_all()` **只會建立不存在的表，不會修改既有表的欄位**。正式環境請用方式 B。

**驗證**：`examples/flask_app/test_app.py::test_tables_are_created_automatically` 會呼叫 `build_manager()`，
再用 `sqlalchemy.inspect()` 確認 18 個欄位全部存在，並第二次呼叫確認冪等。

### 方式 B：正式環境用 Alembic autogenerate（建議）

1. 安裝並初始化 Alembic：

   ```bash
   pip install alembic
   alembic init migrations
   ```

2. 把 API key 資料表掛到你專案的 `MetaData`（與其他 model 共用同一個）：

   ```python
   # myapp/models.py
   from sqlalchemy import MetaData
   from safe_api_keys.stores import make_api_key_table

   metadata = MetaData()                    # 若你用 declarative Base，請用 Base.metadata
   api_keys = make_api_key_table(metadata)
   ```

3. 在 `migrations/env.py` 指定 `target_metadata`：

   ```python
   from myapp.models import metadata
   target_metadata = metadata
   ```

4. 在 `alembic.ini` 設定 `sqlalchemy.url`（或在 `env.py` 從環境變數讀）。

5. 產生並套用 migration：

   ```bash
   alembic revision --autogenerate -m "add api keys table"
   alembic upgrade head
   alembic check            # 應輸出 "No new upgrade operations detected."
   ```

   產生的 migration 會包含 `op.create_table('safe_api_keys', ...)` 與 `owner`、`expires_at` 兩個索引。
   欄位只使用 SQLAlchemy 內建型別（`sa.String`、`sa.JSON`、`sa.DateTime(timezone=True)` 加 MySQL 的
   `DATETIME(fsp=6)` variant），**不需要**在 migration 檔手動 import 本套件。

6. 部署時跑 `alembic upgrade head` 即可。

**驗證**：`examples/flask_app/test_migrations.py::test_alembic_autogenerate_flow` 會以程式方式完整跑一次
`alembic init → 設定 target_metadata → revision --autogenerate → upgrade head → check`，並用建出來的表發行、驗證一把 key。

### 方式 C：Flask-SQLAlchemy / Flask-Migrate

```python
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import sessionmaker
from safe_api_keys.stores import SQLAlchemyStore, make_api_key_table

db = SQLAlchemy(app)
api_keys = make_api_key_table(db.metadata)           # 掛到 Flask-SQLAlchemy 的 metadata

with app.app_context():
    db.create_all()                                  # 開發期：自動建表
    km = KeyManager(SQLAlchemyStore(sessionmaker(bind=db.engine), table=api_keys), prefix="acme_live",
                    pepper=os.environ["SAFE_API_KEYS_PEPPER"].encode())
```

使用 Flask-Migrate 時，因為表已在 `db.metadata` 上，照常執行即可：

```bash
flask db init          # 第一次
flask db migrate -m "add api keys table"
flask db upgrade
```

> `SQLAlchemyStore` 每次操作都開自己的短交易，因此傳入的是 `sessionmaker(bind=db.engine)`，
> 而不是 `db.session`（scoped session 由 Flask-SQLAlchemy 管理生命週期）。

**驗證**：`examples/flask_app/test_migrations.py::test_flask_sqlalchemy_create_all`。

### 方式 D：自訂表名 / 宣告式 model（`APIKeyMixin`）

```python
make_api_key_table(metadata, "my_api_keys")                       # 自訂表名
store = SQLAlchemyStore(SessionLocal, table=metadata.tables["my_api_keys"])
```

或用 declarative：

```python
from sqlalchemy.orm import declarative_base
from safe_api_keys.stores import APIKeyMixin, SQLAlchemyStore

Base = declarative_base()

class APIKey(APIKeyMixin, Base):
    __tablename__ = "api_keys"
    # metadata 是 declarative 保留字，因此該欄位的 Python 屬性名稱為 metadata_（資料庫欄位仍叫 metadata）

Base.metadata.create_all(engine)          # 或交給 Alembic（Base.metadata 當 target_metadata）
store = SQLAlchemyStore(SessionLocal, table=APIKey)
```

### 不用 SQLAlchemy：`SQLiteStore` 自動建表

只用標準庫時，`SQLiteStore(path)` 在建構時執行 `CREATE TABLE IF NOT EXISTS` 與索引，並啟用 WAL：

```python
from safe_api_keys.stores import SQLiteStore
store = SQLiteStore("keys.db")            # 第一次建構即建表；之後重用
```

CLI 也是如此：`safe-api-keys issue --store sqlite:///keys.db ...`；`--store sqlalchemy+postgresql://...`
則會在表不存在時自動建立。

---

## Django

安裝：

```bash
pip install "safe-api-keys[django]"        # 使用 DRF 再加 [drf]
```

### 標準流程：`INSTALLED_APPS` + `migrate`

1. `settings.py`：

   ```python
   INSTALLED_APPS = [
       # ...
       "safe_api_keys.contrib.django",       # app label 為 safe_api_keys
   ]

   SAFE_API_KEYS = {
       "PREFIX": "acme_live",
       "PEPPER_ENV": "SAFE_API_KEYS_PEPPER",
   }
   ```

2. 建表：

   ```bash
   python manage.py migrate
   ```

   套件內附 `safe_api_keys/0001_initial` migration，會建立 **`safe_api_keys_apikey`** 資料表與 `owner`、
   `expires_at` 索引。你**不需要**對這個 app 跑 `makemigrations`。

3. 確認：

   ```bash
   python manage.py showmigrations safe_api_keys
   #  [X] 0001_initial
   python manage.py sqlmigrate safe_api_keys 0001      # 看實際的 CREATE TABLE SQL
   ```

4. 設定 pepper 後即可發 key：

   ```bash
   export SAFE_API_KEYS_PEPPER="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
   python manage.py apikey issue --owner svc-billing --scopes "reports:*" --expires 365d
   ```

> `migrate` **不需要** pepper：設定檢查在 `AppConfig.ready()` 只驗證格式，pepper 是在第一次需要
> `KeyManager` 時才檢查，因此 CI / 部署腳本可以先 migrate 再注入祕密。

**驗證**：
- `examples/django_app/tests/test_shop.py::test_migrate_created_api_key_table`：確認測試資料庫中存在
  `safe_api_keys_apikey` 與必要欄位，並執行 `makemigrations --check` 確認 model 與 migration 一致。
- `examples/django_app/tests/test_shop.py::test_django_store_persists_in_table`：以正式設定（`STORE=None`）
  確認 key 寫入該表、`use_count` 會更新。
- `tests/contrib/test_django.py`、`tests/stores/test_django.py`：DjangoStore 的完整一致性測試。

### 自訂 model（`AbstractAPIKey`）

需要額外欄位（例如外鍵到 tenant）時，繼承抽象 model：

```python
# accounts/models.py
from django.db import models
from safe_api_keys.contrib.django.models import AbstractAPIKey

class TenantAPIKey(AbstractAPIKey):
    tenant = models.ForeignKey("tenants.Tenant", null=True, on_delete=models.CASCADE)
```

```python
SAFE_API_KEYS = {..., "MODEL": "accounts.TenantAPIKey"}
```

```bash
python manage.py makemigrations accounts     # 這次是「你的」app，需要 makemigrations
python manage.py migrate
```

> 預設的 `safe_api_keys_apikey` 表仍會由 `safe_api_keys` app 建立（未使用時為空表），這是無害的。
> 內建 admin 頁面只管理預設 model；自訂 model 請自行註冊 admin（可繼承 `APIKeyAdmin`）。

### 既有資料庫 / 無法跑 migrate 的環境

- 先用 `python manage.py sqlmigrate safe_api_keys 0001` 取得 SQL，交給 DBA 執行；
- 之後在每個環境執行 `python manage.py migrate safe_api_keys 0001 --fake`，讓 Django 記錄此 migration 已套用。

---

## 升級套件時的 schema 變更

`hash_alg` 字串與欄位定義屬於相容性承諾（規格 §18）：變更會升主版號並在 CHANGELOG 附遷移說明。

- **Django**：升級後執行 `python manage.py migrate`，新 migration 隨套件發佈。
- **SQLAlchemy/Alembic**：升級後執行 `alembic revision --autogenerate` 產生差異，檢視後 `alembic upgrade head`。
- **SQLiteStore**：只會 `CREATE TABLE IF NOT EXISTS`，欄位變更請依 CHANGELOG 的 SQL 手動處理。

---

## 常見問題

**Q：可以只在第一次啟動時自動建表嗎？**
可以。方式 A 的 `create_all()` / `store.create_table(engine)` 與 `SQLiteStore` 都是冪等的。
正式環境仍建議交給 migration 工具，讓 schema 變更可追蹤、可審查。

**Q：PostgreSQL / MySQL 有什麼要注意？**
時間欄位一律存 UTC：PostgreSQL 使用 `TIMESTAMPTZ`；MySQL 使用 `DATETIME(6)`（保留微秒）並以 UTC 寫入、讀出時標為 UTC。
JSON 欄位在三種資料庫都使用原生 JSON 型別（SQLite 為 JSON 文字）。

**Q：為什麼 Django 不用跑 `makemigrations safe_api_keys`？**
migration 已隨套件發佈，CI 以 `makemigrations --check` 保證 model 與 migration 一致。

**Q：多個環境（live/test）要分不同表嗎？**
不需要。不同 prefix 的 key 互不相認（S6）；但建議 live 與 test 使用不同資料庫與不同 pepper。
