"""Data model: :class:`KeyRecord`, :class:`ParsedKey`, :class:`IssuedKey`, :class:`VerifyResult`."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Tuple

from ._util import ensure_aware, optional_aware, utcnow
from .exceptions import APIKeyError

__all__ = ["KeyRecord", "KeyState", "ParsedKey", "IssuedKey", "VerifyResult", "ACTIVE", "EXPIRED", "REVOKED"]

KeyState = str
ACTIVE: KeyState = "active"
EXPIRED: KeyState = "expired"
REVOKED: KeyState = "revoked"


def mask_parts(prefix: str, key_id: str, last4: str) -> str:
    return f"{prefix}_{key_id}_…{last4}"


@dataclass(frozen=True, repr=False)
class KeyRecord:
    """One stored key. There is deliberately **no** ``secret`` field (§5.1)."""

    key_id: str
    prefix: str
    hash: str
    hash_alg: str
    secret_last4: str
    owner: str
    created_at: datetime
    name: str = ""
    scopes: Tuple[str, ...] = ()
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None
    last_used_at: Optional[datetime] = None
    use_count: int = 0
    rotated_from: Optional[str] = None
    rotated_to: Optional[str] = None
    ip_allowlist: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalise types so every store round-trips to identical objects.
        object.__setattr__(self, "created_at", ensure_aware(self.created_at, "created_at"))
        for name in ("expires_at", "revoked_at", "last_used_at"):
            object.__setattr__(self, name, optional_aware(getattr(self, name), name))
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "ip_allowlist", tuple(self.ip_allowlist))
        object.__setattr__(self, "metadata", dict(self.metadata or {}))
        object.__setattr__(self, "use_count", int(self.use_count or 0))
        object.__setattr__(self, "name", self.name or "")

    # -- derived ---------------------------------------------------------------
    @property
    def masked(self) -> str:
        return mask_parts(self.prefix, self.key_id, self.secret_last4)

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = ensure_aware(now, "now") if now is not None else utcnow()
        return self.expires_at is not None and self.expires_at <= now

    def is_active(self, now: Optional[datetime] = None) -> bool:
        return not self.is_revoked and not self.is_expired(now)

    def state(self, now: Optional[datetime] = None) -> KeyState:
        if self.is_revoked:
            return REVOKED
        if self.is_expired(now):
            return EXPIRED
        return ACTIVE

    def replace(self, **changes: Any) -> KeyRecord:
        return replace(self, **changes)

    def copy(self) -> KeyRecord:
        return replace(self, metadata=copy.deepcopy(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        """Serialisable view for APIs/CLI. Excludes ``hash`` and contains no secret."""
        def iso(v: Optional[datetime]) -> Optional[str]:
            return v.isoformat() if v else None

        return {
            "key_id": self.key_id,
            "masked": self.masked,
            "prefix": self.prefix,
            "owner": self.owner,
            "name": self.name,
            "scopes": list(self.scopes),
            "state": self.state(),
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
            "revoked_at": iso(self.revoked_at),
            "revoke_reason": self.revoke_reason,
            "last_used_at": iso(self.last_used_at),
            "use_count": self.use_count,
            "rotated_from": self.rotated_from,
            "rotated_to": self.rotated_to,
            "ip_allowlist": list(self.ip_allowlist),
            "metadata": copy.deepcopy(self.metadata),
            "hash_alg": self.hash_alg,
        }

    def __repr__(self) -> str:
        # ``hash`` is intentionally omitted: it is not secret, but there's no reason to spread it.
        return (f"KeyRecord(key_id={self.key_id!r}, masked={self.masked!r}, owner={self.owner!r}, "
                f"name={self.name!r}, scopes={self.scopes!r}, state={self.state()!r})")

    __str__ = __repr__


@dataclass(frozen=True, repr=False)
class ParsedKey:
    prefix: str
    key_id: str
    secret: str
    checksum: str
    checksum_ok: bool
    body: str

    @property
    def masked(self) -> str:
        return mask_parts(self.prefix, self.key_id, self.secret[-4:])

    def __repr__(self) -> str:
        return f"ParsedKey(masked={self.masked!r}, checksum_ok={self.checksum_ok!r})"

    __str__ = __repr__


@dataclass(frozen=True, repr=False)
class IssuedKey:
    """Returned by ``issue``/``rotate``. ``raw_key`` exists only here, only once."""

    raw_key: str
    record: KeyRecord

    @property
    def key_id(self) -> str:
        return self.record.key_id

    @property
    def masked(self) -> str:
        return self.record.masked

    def __repr__(self) -> str:
        return f"IssuedKey(masked={self.record.masked!r})"

    __str__ = __repr__


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    record: Optional[KeyRecord] = None
    error: Optional[APIKeyError] = None

    def __bool__(self) -> bool:
        return self.ok


def _record_fields() -> Tuple[str, ...]:
    return tuple(KeyRecord.__dataclass_fields__)


RECORD_FIELDS: Tuple[str, ...] = _record_fields()


def record_from_mapping(data: Mapping[str, Any]) -> KeyRecord:
    return KeyRecord(**{k: data[k] for k in RECORD_FIELDS if k in data})
