"""SQLAlchemy (1.4 / 2.0) stores, sync and async.

Table creation options (see docs/database-setup.md):

* ``make_api_key_table(metadata)`` then ``metadata.create_all(engine)`` (or Alembic autogenerate);
* ``APIKeyMixin`` for declarative models;
* ``SQLAlchemyStore(...).create_table(engine)`` as a one-off convenience.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional

from ..exceptions import MissingDependency, StoreError
from ..models import KeyRecord
from .base import COLUMNS, record_to_row, row_to_record

try:
    import sqlalchemy as sa
    from sqlalchemy.exc import SQLAlchemyError
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[sqlalchemy]") from exc

from .._util import UTC, utcnow

__all__ = ["make_api_key_table", "APIKeyMixin", "SQLAlchemyStore", "AsyncSQLAlchemyStore", "DEFAULT_TABLE_NAME"]

DEFAULT_TABLE_NAME = "safe_api_keys"


def _dt_type() -> Any:
    """``TIMESTAMPTZ`` on PostgreSQL, ``DATETIME(6)`` on MySQL/MariaDB, ``DATETIME`` (ISO text) on SQLite.

    Only stock SQLAlchemy types are used so Alembic autogenerate renders importable migrations.
    Values are written as UTC (naive UTC on dialects without time zones) and re-tagged as UTC on load.
    """
    from sqlalchemy.dialects import mysql

    # chained calls: passing several dialect names to one with_variant() needs SQLAlchemy 2.0
    return (sa.DateTime(timezone=True)
            .with_variant(mysql.DATETIME(fsp=6), "mysql")
            .with_variant(mysql.DATETIME(fsp=6), "mariadb"))


def _columns() -> List[sa.Column]:  # type: ignore[type-arg]
    # ``hash`` is 255 wide (not 64) so Argon2Hasher's encoded output also fits.
    return [
        sa.Column("key_id", sa.String(16), primary_key=True),
        sa.Column("prefix", sa.String(32), nullable=False),
        sa.Column("hash", sa.String(255), nullable=False),
        sa.Column("hash_alg", sa.String(32), nullable=False),
        sa.Column("secret_last4", sa.String(4), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("scopes", sa.JSON, nullable=False),
        sa.Column("created_at", _dt_type(), nullable=False),
        sa.Column("expires_at", _dt_type(), nullable=True, index=True),
        sa.Column("revoked_at", _dt_type(), nullable=True),
        sa.Column("revoke_reason", sa.String(255), nullable=True),
        sa.Column("last_used_at", _dt_type(), nullable=True),
        sa.Column("use_count", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("rotated_from", sa.String(16), nullable=True),
        sa.Column("rotated_to", sa.String(16), nullable=True),
        sa.Column("ip_allowlist", sa.JSON, nullable=False),
        sa.Column("metadata", sa.JSON, nullable=False),
    ]


def make_api_key_table(metadata: sa.MetaData, name: str = DEFAULT_TABLE_NAME, *,
                       schema: Optional[str] = None) -> sa.Table:
    """Define the API key table on ``metadata`` (idempotent: returns the existing one if defined)."""
    key = f"{schema}.{name}" if schema else name
    if key in metadata.tables:
        return metadata.tables[key]
    return sa.Table(name, metadata, *_columns(), schema=schema)


class APIKeyMixin:
    """Declarative mixin. ``metadata`` is reserved by declarative, so that column is ``metadata_``.

    class APIKey(APIKeyMixin, Base):
        __tablename__ = "safe_api_keys"
    """

    key_id = sa.Column("key_id", sa.String(16), primary_key=True)
    prefix = sa.Column("prefix", sa.String(32), nullable=False)
    hash = sa.Column("hash", sa.String(255), nullable=False)
    hash_alg = sa.Column("hash_alg", sa.String(32), nullable=False)
    secret_last4 = sa.Column("secret_last4", sa.String(4), nullable=False)
    owner = sa.Column("owner", sa.String(255), nullable=False, index=True)
    name = sa.Column("name", sa.String(255), nullable=False, server_default="")
    scopes = sa.Column("scopes", sa.JSON, nullable=False)
    created_at = sa.Column("created_at", _dt_type(), nullable=False)
    expires_at = sa.Column("expires_at", _dt_type(), nullable=True, index=True)
    revoked_at = sa.Column("revoked_at", _dt_type(), nullable=True)
    revoke_reason = sa.Column("revoke_reason", sa.String(255), nullable=True)
    last_used_at = sa.Column("last_used_at", _dt_type(), nullable=True)
    use_count = sa.Column("use_count", sa.BigInteger, nullable=False, server_default="0")
    rotated_from = sa.Column("rotated_from", sa.String(16), nullable=True)
    rotated_to = sa.Column("rotated_to", sa.String(16), nullable=True)
    ip_allowlist = sa.Column("ip_allowlist", sa.JSON, nullable=False)
    metadata_ = sa.Column("metadata", sa.JSON, nullable=False)


def _resolve_table(table: Any) -> sa.Table:
    if table is None:
        return make_api_key_table(sa.MetaData())
    if isinstance(table, sa.Table):
        return table
    if hasattr(table, "__table__"):
        return table.__table__  # type: ignore[no-any-return]
    if isinstance(table, str):
        return make_api_key_table(sa.MetaData(), table)
    raise TypeError("table must be None, a Table, a table name or a declarative model")


class _Statements:
    def __init__(self, table: Any) -> None:
        self.table = t = _resolve_table(table)
        self.c = t.c
        self.naive: Optional[bool] = None  # strip tzinfo before binding? decided from the dialect

    def configure(self, bind: Any) -> None:
        if self.naive is None:
            self.naive = getattr(getattr(bind, "dialect", None), "name", "") != "postgresql"

    def dt(self, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        value = value.astimezone(UTC)
        return value.replace(tzinfo=None) if self.naive else value

    def row(self, record: KeyRecord) -> Dict[str, Any]:
        row = record_to_row(record, native_datetime=True, native_json=True)
        for k in ("created_at", "expires_at", "revoked_at", "last_used_at"):
            row[k] = self.dt(row[k])
        return row

    def get(self, key_id: str) -> Any:
        return sa.select(self.table).where(self.c.key_id == key_id)

    def update_all(self, row: Dict[str, Any]) -> Any:
        values = {k: v for k, v in row.items() if k != "key_id"}
        return sa.update(self.table).where(self.c.key_id == row["key_id"]).values(**values)

    def insert(self, row: Dict[str, Any]) -> Any:
        return sa.insert(self.table).values(**row)

    def touch(self, key_id: str, when: datetime) -> Any:
        # Partial update (S8): never overwrites revoked_at & co.
        return (sa.update(self.table).where(self.c.key_id == key_id)
                .values(last_used_at=self.dt(when), use_count=self.c.use_count + 1))

    def list(self, owner: Optional[str], include_inactive: bool, now: Optional[datetime]) -> Any:
        stmt = sa.select(self.table)
        if owner is not None:
            stmt = stmt.where(self.c.owner == owner)
        if not include_inactive:
            now = self.dt(now or utcnow())
            stmt = stmt.where(self.c.revoked_at.is_(None)).where(
                sa.or_(self.c.expires_at.is_(None), self.c.expires_at > now))
        return stmt.order_by(self.c.created_at, self.c.key_id)

    def delete(self, key_id: str) -> Any:
        return sa.delete(self.table).where(self.c.key_id == key_id)

    def purge(self, before: datetime) -> Any:
        before = self.dt(before)  # type: ignore[assignment]
        return sa.delete(self.table).where(sa.or_(
            sa.and_(self.c.revoked_at.isnot(None), self.c.revoked_at < before),
            sa.and_(self.c.expires_at.isnot(None), self.c.expires_at < before)))

    def count(self) -> Any:
        return sa.select(self.c.hash_alg, sa.func.count()).group_by(self.c.hash_alg)


def _to_record(mapping: Any) -> KeyRecord:
    return row_to_record({c: mapping[c] for c in COLUMNS})


class SQLAlchemyStore:
    """``session_factory`` is a ``sessionmaker`` (each operation uses its own short transaction)."""

    def __init__(self, session_factory: Callable[[], Any], *, table: Any = None) -> None:
        self._factory = session_factory
        self._q = _Statements(table)

    @property
    def table(self) -> sa.Table:
        return self._q.table

    def create_table(self, bind: Any) -> None:
        """Create the table if missing (dev/test convenience; use Alembic in production)."""
        try:
            self._q.table.create(bind, checkfirst=True)
        except SQLAlchemyError as exc:
            raise StoreError(f"create_table failed: {type(exc).__name__}") from exc

    def _tx(self, fn: Callable[[Any], Any]) -> Any:
        try:
            with self._factory() as session:
                self._q.configure(session.get_bind())
                with session.begin():
                    return fn(session)
        except SQLAlchemyError as exc:
            raise StoreError(f"SQLAlchemy error: {type(exc).__name__}") from exc

    def _upsert(self, session: Any, record: KeyRecord) -> None:
        row = self._q.row(record)
        if session.execute(self._q.update_all(row)).rowcount == 0:
            session.execute(self._q.insert(row))

    def get(self, key_id: str) -> Optional[KeyRecord]:
        m = self._tx(lambda s: s.execute(self._q.get(key_id)).mappings().first())
        return _to_record(m) if m else None

    def save(self, record: KeyRecord) -> None:
        self._tx(lambda s: self._upsert(s, record))

    def save_many(self, records: Iterable[KeyRecord]) -> None:
        recs = list(records)

        def run(s: Any) -> None:
            for r in recs:
                self._upsert(s, r)
        self._tx(run)

    def touch(self, key_id: str, when: datetime) -> None:
        self._tx(lambda s: s.execute(self._q.touch(key_id, when)))

    def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
             now: Optional[datetime] = None) -> List[KeyRecord]:
        rows = self._tx(lambda s: s.execute(self._q.list(owner, include_inactive, now)).mappings().all())
        return [_to_record(m) for m in rows]

    def delete(self, key_id: str) -> None:
        self._tx(lambda s: s.execute(self._q.delete(key_id)))

    def purge(self, *, before: datetime) -> int:
        return int(self._tx(lambda s: s.execute(self._q.purge(before)).rowcount))

    def count_by_hash_alg(self) -> Dict[str, int]:
        rows = self._tx(lambda s: s.execute(self._q.count()).all())
        return {r[0]: int(r[1]) for r in rows}

    def close(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"SQLAlchemyStore(table={self._q.table.name!r})"


class AsyncSQLAlchemyStore:
    """``async_session_factory`` is an ``async_sessionmaker`` (or ``sessionmaker(class_=AsyncSession)``)."""

    def __init__(self, async_session_factory: Callable[[], Any], *, table: Any = None) -> None:
        self._factory = async_session_factory
        self._q = _Statements(table)

    @property
    def table(self) -> sa.Table:
        return self._q.table

    async def create_table(self, async_engine: Any) -> None:
        try:
            async with async_engine.begin() as conn:
                await conn.run_sync(lambda sync_conn: self._q.table.create(sync_conn, checkfirst=True))
        except SQLAlchemyError as exc:
            raise StoreError(f"create_table failed: {type(exc).__name__}") from exc

    async def _tx(self, fn: Callable[[Any], Any]) -> Any:
        try:
            async with self._factory() as session:
                self._q.configure(session.sync_session.get_bind())
                async with session.begin():
                    return await fn(session)
        except SQLAlchemyError as exc:
            raise StoreError(f"SQLAlchemy error: {type(exc).__name__}") from exc

    async def _upsert(self, session: Any, record: KeyRecord) -> None:
        row = self._q.row(record)
        if (await session.execute(self._q.update_all(row))).rowcount == 0:
            await session.execute(self._q.insert(row))

    async def get(self, key_id: str) -> Optional[KeyRecord]:
        async def run(s: Any) -> Any:
            return (await s.execute(self._q.get(key_id))).mappings().first()
        m = await self._tx(run)
        return _to_record(m) if m else None

    async def save(self, record: KeyRecord) -> None:
        await self._tx(lambda s: self._upsert(s, record))

    async def save_many(self, records: Iterable[KeyRecord]) -> None:
        recs = list(records)

        async def run(s: Any) -> None:
            for r in recs:
                await self._upsert(s, r)
        await self._tx(run)

    async def touch(self, key_id: str, when: datetime) -> None:
        await self._tx(lambda s: s.execute(self._q.touch(key_id, when)))

    async def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
                   now: Optional[datetime] = None) -> List[KeyRecord]:
        async def run(s: Any) -> Any:
            return (await s.execute(self._q.list(owner, include_inactive, now))).mappings().all()
        return [_to_record(m) for m in await self._tx(run)]

    async def delete(self, key_id: str) -> None:
        await self._tx(lambda s: s.execute(self._q.delete(key_id)))

    async def purge(self, *, before: datetime) -> int:
        async def run(s: Any) -> int:
            return int((await s.execute(self._q.purge(before))).rowcount)
        return int(await self._tx(run))

    async def count_by_hash_alg(self) -> Dict[str, int]:
        async def run(s: Any) -> Any:
            return (await s.execute(self._q.count())).all()
        return {r[0]: int(r[1]) for r in await self._tx(run)}

    async def close(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"AsyncSQLAlchemyStore(table={self._q.table.name!r})"
