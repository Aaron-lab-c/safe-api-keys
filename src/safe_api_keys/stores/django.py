"""Django ORM store. Default model: ``safe_api_keys.contrib.django.models.APIKey``."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from .._util import UTC, utcnow
from ..exceptions import MissingDependency, StoreError
from ..models import KeyRecord
from .base import COLUMNS, row_to_record

try:
    from django.conf import settings
    from django.db import DatabaseError, transaction
    from django.db.models import Count, F, Q
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[django]") from exc

__all__ = ["DjangoStore"]

_DT = ("created_at", "expires_at", "revoked_at", "last_used_at")


def _resolve_model(model: Any) -> Any:
    if model is None:
        from ..contrib.django.models import APIKey

        return APIKey
    if isinstance(model, str):
        from django.apps import apps

        return apps.get_model(model)
    return model


class DjangoStore:
    def __init__(self, model: Any = None, *, using: Optional[str] = None) -> None:
        self._model_ref = model
        self._model: Any = None
        self.using = using

    @property
    def model(self) -> Any:
        if self._model is None:  # resolve lazily so the store can be built before apps are ready
            self._model = _resolve_model(self._model_ref)
        return self._model

    def _qs(self) -> Any:
        qs = self.model._default_manager
        return qs.using(self.using) if self.using else qs.all()

    @staticmethod
    def _db_dt(value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        value = value.astimezone(UTC)
        return value if getattr(settings, "USE_TZ", True) else value.replace(tzinfo=None)

    def _to_record(self, obj: Any) -> KeyRecord:
        row = {c: getattr(obj, c) for c in COLUMNS}
        return row_to_record(row)

    def _fields(self, record: KeyRecord) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        for c in COLUMNS:
            v = getattr(record, c)
            if c in _DT:
                v = self._db_dt(v)
            elif c in ("scopes", "ip_allowlist"):
                v = list(v)
            elif c == "metadata":
                v = dict(v)
            data[c] = v
        return data

    def _run(self, fn: Any) -> Any:
        try:
            return fn()
        except DatabaseError as exc:
            raise StoreError(f"Django database error: {type(exc).__name__}") from exc

    def get(self, key_id: str) -> Optional[KeyRecord]:
        obj = self._run(lambda: self._qs().filter(pk=key_id).first())
        return self._to_record(obj) if obj is not None else None

    def save(self, record: KeyRecord) -> None:
        self.save_many([record])

    def save_many(self, records: Iterable[KeyRecord]) -> None:
        recs = list(records)

        def run() -> None:
            with transaction.atomic(using=self.using):
                for r in recs:
                    self.model(**self._fields(r)).save(using=self.using)
        self._run(run)

    def touch(self, key_id: str, when: datetime) -> None:
        # Queryset UPDATE with F(): atomic partial update (S8), equivalent to save(update_fields=...)
        # without the read-modify-write race on use_count.
        self._run(lambda: self._qs().filter(pk=key_id).update(
            last_used_at=self._db_dt(when), use_count=F("use_count") + 1))

    def list(self, owner: Optional[str] = None, *, include_inactive: bool = False,
             now: Optional[datetime] = None) -> List[KeyRecord]:
        def run() -> List[Any]:
            qs = self._qs()
            if owner is not None:
                qs = qs.filter(owner=owner)
            if not include_inactive:
                n = self._db_dt(now or utcnow())
                qs = qs.filter(revoked_at__isnull=True).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=n))
            return list(qs.order_by("created_at", "key_id"))
        return [self._to_record(o) for o in self._run(run)]

    def delete(self, key_id: str) -> None:
        self._run(lambda: self._qs().filter(pk=key_id).delete())

    def purge(self, *, before: datetime) -> int:
        b = self._db_dt(before)
        deleted = self._run(lambda: self._qs().filter(
            Q(revoked_at__isnull=False, revoked_at__lt=b) | Q(expires_at__isnull=False, expires_at__lt=b)).delete())
        return int(deleted[0])

    def count_by_hash_alg(self) -> Dict[str, int]:
        rows = self._run(lambda: list(self._qs().values("hash_alg").annotate(n=Count("pk")).order_by()))
        return {r["hash_alg"]: int(r["n"]) for r in rows}

    def close(self) -> None:
        return None

    def __repr__(self) -> str:
        ref = self._model_ref if isinstance(self._model_ref, str) else getattr(self._model_ref, "__name__", "APIKey")
        return f"DjangoStore(model={ref!r})"
