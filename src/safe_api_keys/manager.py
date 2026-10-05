"""Synchronous :class:`KeyVerifier` and :class:`KeyManager`."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, TypeVar

from ._logic import (
    KEY_ID_RETRIES,
    Clock,
    _Core,
    build_new_key,
    check_rotatable,
    check_secret,
    decide,
    inherited_expiry,
    key_id_from,
    plan_revoke,
    plan_rotation,
    prepare_raw,
    should_touch,
)
from ._util import to_iso
from .audit import AuditSink
from .cache import VerifyCache
from .exceptions import APIKeyError, RevokedKey, StoreError, UnknownKey
from .format import KeyFormat
from .hashing import Hasher
from .models import IssuedKey, KeyRecord, ParsedKey, VerifyResult
from .policy import KeyPolicy

__all__ = ["KeyVerifier", "KeyManager"]

T = TypeVar("T")
_LINEAGE_LIMIT = 1000


class KeyVerifier(_Core):
    """Verify-only facade (least privilege): needs a store with ``get`` and ``touch``."""

    def __init__(
        self,
        store: Any,
        prefix: str,
        *,
        peppers: Optional[Mapping[str, bytes]] = None,
        current_pepper: Optional[str] = None,
        pepper: Optional[bytes] = None,
        hasher: Optional[Hasher] = None,
        key_format: Optional[KeyFormat] = None,
        touch_interval: Optional[float] = 60.0,
        cache: Optional[VerifyCache] = None,
        audit: Optional[AuditSink] = None,
        clock: Optional[Clock] = None,
        reveal_state: bool = True,
        audit_success: bool = True,
        require_pepper: bool = True,
    ) -> None:
        super().__init__(store, prefix, peppers=peppers, current_pepper=current_pepper, pepper=pepper,
                         hasher=hasher, key_format=key_format, touch_interval=touch_interval, cache=cache,
                         audit=audit, clock=clock, reveal_state=reveal_state, audit_success=audit_success,
                         require_pepper=require_pepper)

    # -- store I/O ---------------------------------------------------------------
    def _call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if self._is_passthrough(exc):
                raise
            raise self._wrap_store_error(exc) from exc

    def _load(self, key_id: str) -> Optional[KeyRecord]:
        if self.cache is not None:
            cached = self.cache.get(key_id)
            if cached is not None:
                return cached
        record: Optional[KeyRecord] = self._call(self.store.get, key_id)
        if record is not None and self.cache is not None:
            self.cache.set(record)
        return record

    # -- public API -------------------------------------------------------------
    def verify(self, raw_key: str, *, scopes: Optional[Sequence[str]] = None,
               any_scopes: Optional[Sequence[str]] = None, client_ip: Optional[str] = None,
               touch: bool = True) -> KeyRecord:
        """Verify a raw key following the fixed order of §7.1. Returns the :class:`KeyRecord`."""
        now = self.now()
        parsed: Optional[ParsedKey] = None
        record: Optional[KeyRecord] = None
        try:
            parsed = prepare_raw(raw_key, self.key_format)                 # 1-3
            record = self._load(parsed.key_id)                             # 4-5
            record = check_secret(self.registry, parsed, record)           # 5-6
            decide(record, now, scopes=scopes, any_scopes=any_scopes, client_ip=client_ip)  # 7-10
        except APIKeyError as exc:
            raise self._reject(exc, parsed, record, scopes, any_scopes, client_ip) from None
        if touch and should_touch(record, now, self.touch_interval):      # 11
            try:
                self.store.touch(record.key_id, now)
                record = self._touched(record, now)
            except Exception as exc:
                self._touch_failed(record, exc)
        self._verified(record, scopes, any_scopes, client_ip)              # 12
        return record

    def check(self, raw_key: str, **kwargs: Any) -> VerifyResult:
        """Like :meth:`verify` but returns a :class:`VerifyResult` instead of raising (except StoreError)."""
        try:
            return VerifyResult(True, self.verify(raw_key, **kwargs), None)
        except APIKeyError as exc:
            return VerifyResult(False, None, exc)

    def get(self, key_id: str) -> Optional[KeyRecord]:
        record: Optional[KeyRecord] = self._call(self.store.get, key_id)
        return record

    def close(self) -> None:
        fn = getattr(self.store, "close", None)
        if callable(fn):
            self._call(fn)


class KeyManager(KeyVerifier):
    """Full lifecycle manager: issue, verify, revoke, rotate, list, delete, purge."""

    _is_manager = True

    def __init__(
        self,
        store: Any,
        prefix: str,
        *,
        peppers: Optional[Mapping[str, bytes]] = None,
        current_pepper: Optional[str] = None,
        pepper: Optional[bytes] = None,
        hasher: Optional[Hasher] = None,
        key_format: Optional[KeyFormat] = None,
        policy: Optional[KeyPolicy] = None,
        touch_interval: Optional[float] = 60.0,
        cache: Optional[VerifyCache] = None,
        audit: Optional[AuditSink] = None,
        clock: Optional[Clock] = None,
        reveal_state: bool = True,
        audit_success: bool = True,
    ) -> None:
        _Core.__init__(self, store, prefix, peppers=peppers, current_pepper=current_pepper, pepper=pepper,
                       hasher=hasher, key_format=key_format, policy=policy, touch_interval=touch_interval,
                       cache=cache, audit=audit, clock=clock, reveal_state=reveal_state,
                       audit_success=audit_success)

    # -- issue ------------------------------------------------------------------
    def _new_unique(self, now: datetime, key_id: Optional[str], **kwargs: Any) -> IssuedKey:
        # store.save() is an upsert, so uniqueness is checked explicitly before saving.
        for _ in range(KEY_ID_RETRIES):
            issued = build_new_key(key_format=self.key_format, hasher=self.registry.current, policy=self.policy,
                                   now=now, key_id=key_id, **kwargs)
            if self._call(self.store.get, issued.record.key_id) is None:
                return issued
            if key_id is not None:
                raise ValueError(f"key_id {key_id!r} already exists")
        raise StoreError("could not allocate a unique key_id")

    def issue(self, owner: str, *, scopes: Iterable[str] = (), expires_at: Optional[datetime] = None,
              expires_in: Optional[timedelta] = None, name: str = "", metadata: Optional[Mapping[str, Any]] = None,
              ip_allowlist: Iterable[str] = (), key_id: Optional[str] = None) -> IssuedKey:
        now = self.now()
        kwargs = dict(owner=owner, scopes=scopes, expires_at=expires_at, expires_in=expires_in, name=name,
                      metadata=metadata, ip_allowlist=ip_allowlist)
        # Validate everything (cheap, no I/O) before touching the store.
        build_new_key(key_format=self.key_format, hasher=self.registry.current, policy=self.policy, now=now,
                      key_id=key_id, **kwargs)  # type: ignore[arg-type]
        if self.policy.max_active_keys_per_owner is not None:
            self.policy.check_active_count(len(self.list(owner)))
        issued = self._new_unique(now, key_id, **kwargs)
        self._call(self.store.save, issued.record)
        rec = issued.record
        self._event("key.issued", at=now, key_id=rec.key_id, owner=rec.owner,
                    extra={"scopes": list(rec.scopes), "expires_at": rec.expires_at.isoformat()
                           if rec.expires_at else None, "name": rec.name})
        return issued

    # -- revoke / rotate --------------------------------------------------------
    def revoke(self, key_id_or_raw: str, *, reason: Optional[str] = None) -> KeyRecord:
        key_id = key_id_from(key_id_or_raw, self.key_format)
        record = self.get(key_id)
        if record is None:
            raise UnknownKey(reason="unknown", key_id=key_id)
        if record.revoked_at is not None:
            return record
        now = self.now()
        updated = plan_revoke(record, now, reason)
        self._call(self.store.save, updated)
        self._invalidate(key_id)
        self._event("key.revoked", at=now, key_id=key_id, owner=record.owner, reason=updated.revoke_reason)
        return updated

    def rotate(self, key_id_or_raw: str, *, grace: timedelta = timedelta(hours=24),
               expires_in: Optional[timedelta] = None, expires_at: Optional[datetime] = None) -> IssuedKey:
        """Replace a live key. Without ``expires_in``/``expires_at`` the new key keeps the old key's expiry
        (a rotation never extends a key's lifetime). Revoked or expired keys cannot be rotated, and a key
        revoked while the rotation is in flight stays revoked (``RevokedKey``, nothing is written)."""
        key_id = key_id_from(key_id_or_raw, self.key_format)
        old = self.get(key_id)
        if old is None:
            raise UnknownKey(reason="unknown", key_id=key_id)
        now = self.now()
        check_rotatable(old, now)
        if expires_at is None and expires_in is None:
            expires_at = inherited_expiry(old, now, self.policy)
        plan_rotation(old, "x" * self.key_format.key_id_len, now, grace)  # validate grace first
        # max_active_keys_per_owner is not enforced here: rotation replaces a key, it doesn't add one.
        issued = self._new_unique(now, None, owner=old.owner, scopes=old.scopes, expires_at=expires_at,
                                  expires_in=expires_in, name=old.name, metadata=old.metadata,
                                  ip_allowlist=old.ip_allowlist, rotated_from=old.key_id)
        updated_old = plan_rotation(old, issued.record.key_id, now, grace)
        self._save_rotation(issued.record, updated_old)
        self._invalidate(old.key_id)
        self._event("key.rotated", at=now, key_id=old.key_id, owner=old.owner,
                    extra={"rotated_to": issued.record.key_id,
                           "old_expires_at": updated_old.expires_at.isoformat() if updated_old.expires_at else None})
        return issued

    def _save_rotation(self, new: KeyRecord, old: KeyRecord) -> None:
        save_rotation = getattr(self.store, "save_rotation", None)
        if callable(save_rotation):  # atomic + conditional: a concurrent revoke wins and nothing is written
            if not self._call(save_rotation, new, old):
                raise self._rotation_refused(old.key_id)
            return
        # Stores without save_rotation: re-check right before writing. A small window remains; implement
        # save_rotation (see stores.base.KeyStore) to close it.
        current = self.get(old.key_id)
        if current is None or current.revoked_at is not None:
            raise self._rotation_refused(old.key_id)
        save_many = getattr(self.store, "save_many", None)
        if callable(save_many):  # transactional backends: both or neither
            self._call(save_many, [new, old])
            return
        self._call(self.store.save, new)
        try:
            self._call(self.store.save, old)
        except StoreError:
            self._event("key.rotate_partial", key_id=old.key_id, owner=old.owner,
                        extra={"rotated_to": new.key_id})
            raise

    def _rotation_refused(self, key_id: str) -> APIKeyError:
        if self.get(key_id) is None:
            return UnknownKey(reason="unknown", key_id=key_id)
        return RevokedKey(key_id=key_id)

    # -- listing / maintenance --------------------------------------------------
    def list(self, owner: Optional[str] = None, *, include_inactive: bool = False) -> List[KeyRecord]:
        fn = self._require("list")
        now = self.now()
        rows: List[KeyRecord] = self._call(fn, owner, include_inactive=include_inactive, now=now)
        if not include_inactive:
            rows = [r for r in rows if r.is_active(now)]
        return rows

    def delete(self, key_id: str) -> None:
        fn = self._require("delete")
        self._call(fn, key_id)
        self._invalidate(key_id)

    def purge(self, *, older_than: timedelta) -> int:
        if not isinstance(older_than, timedelta) or older_than < timedelta(0):
            raise ValueError("older_than must be a non-negative timedelta")
        fn = self._require("purge")
        now = self.now()
        before = now - older_than
        count = int(self._call(fn, before=before))
        if self.cache is not None:
            self.cache.clear()
        self._event("key.purged", at=now, extra={"count": count, "before": to_iso(before)})
        return count

    def count_by_hash_alg(self) -> Dict[str, int]:
        fn = self._require("count_by_hash_alg")
        return dict(self._call(fn))

    def lineage(self, key_id: str) -> List[KeyRecord]:
        """Whole rotation chain (oldest first) containing ``key_id``."""
        start = self.get(key_id)
        if start is None:
            raise UnknownKey(reason="unknown", key_id=key_id)
        chain, seen = [start], {start.key_id}
        cur = start
        while cur.rotated_from and len(chain) < _LINEAGE_LIMIT:
            prev = self.get(cur.rotated_from)
            if prev is None or prev.key_id in seen:
                break
            chain.insert(0, prev)
            seen.add(prev.key_id)
            cur = prev
        cur = start
        while cur.rotated_to and len(chain) < _LINEAGE_LIMIT:
            nxt = self.get(cur.rotated_to)
            if nxt is None or nxt.key_id in seen:
                break
            chain.append(nxt)
            seen.add(nxt.key_id)
            cur = nxt
        return chain
