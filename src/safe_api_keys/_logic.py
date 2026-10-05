"""Pure decision logic shared by the sync and async managers (§2.4).

Every rule (verification order, policy, rotation maths, IP matching) lives here
exactly once. The managers only add I/O around these functions.
"""

from __future__ import annotations

import ipaddress
import logging
import warnings
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence, Tuple, Union

from ._util import ensure_aware, optional_aware, utcnow
from .audit import AuditEvent, AuditSink, NullAuditSink, safe_emit
from .cache import VerifyCache
from .exceptions import (
    APIKeyError,
    ConfigurationError,
    ExpiredKey,
    InsufficientScope,
    IPNotAllowed,
    MalformedKey,
    RevokedKey,
    SafeAPIKeysError,
    StoreError,
    UnknownKey,
)
from .format import MAX_RAW_KEY_LENGTH, KeyFormat, generate_key, parse_key, validate_prefix
from .hashing import Hasher, HasherRegistry
from .models import IssuedKey, KeyRecord, ParsedKey
from .policy import KeyPolicy, validate_metadata
from .scopes import missing_scopes, normalize_scopes, scope_covers

__all__ = [
    "IPNetwork",
    "normalize_ip",
    "normalize_allowlist",
    "ip_allowed",
    "prepare_raw",
    "check_secret",
    "decide",
    "check_scopes",
    "check_ip",
    "should_touch",
    "build_new_key",
    "plan_revoke",
    "plan_rotation",
    "check_rotatable",
    "inherited_expiry",
    "key_id_from",
    "KEY_ID_RETRIES",
]

logger = logging.getLogger("safe_api_keys")
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddr = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
KEY_ID_RETRIES = 3
Clock = Callable[[], datetime]


# ---------------------------------------------------------------------------- IP
def normalize_ip(value: str) -> IPAddr:
    """Parse an address; IPv4-mapped IPv6 (``::ffff:1.2.3.4``) becomes IPv4 (§7.3)."""
    addr = ipaddress.ip_address(str(value).strip().split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_network(value: str) -> IPNetwork:
    net = ipaddress.ip_network(str(value).strip(), strict=False)
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None \
            and net.prefixlen >= 96:
        return ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return net


def normalize_allowlist(entries: Optional[Iterable[str]]) -> Tuple[str, ...]:
    if entries is None:
        return ()
    if isinstance(entries, str):
        entries = [entries]
    out = []
    for e in entries:
        try:
            out.append(str(_parse_network(e)))
        except ValueError:
            raise ValueError(f"invalid IP/CIDR in ip_allowlist: {e!r}") from None
    return tuple(sorted(set(out)))


def ip_allowed(allowlist: Iterable[str], client_ip: str) -> bool:
    try:
        addr = normalize_ip(client_ip)
    except ValueError:
        return False
    for entry in allowlist:
        try:
            net = _parse_network(entry)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


# ---------------------------------------------------------------------------- verify steps
def prepare_raw(raw_key: Any, key_format: KeyFormat) -> ParsedKey:
    """Steps 1-3: length/ASCII, parse + checksum, prefix binding. Never touches the store."""
    if not isinstance(raw_key, str):
        raise MalformedKey(reason="malformed")
    raw = raw_key.strip()
    if len(raw) > MAX_RAW_KEY_LENGTH or not raw.isascii():
        raise MalformedKey(reason="malformed")
    parsed = parse_key(raw, key_format)
    if parsed.prefix != key_format.prefix:
        raise MalformedKey(reason="prefix", key_id=parsed.key_id)
    return parsed


def check_secret(registry: HasherRegistry, parsed: ParsedKey, record: Optional[KeyRecord]) -> KeyRecord:
    """Steps 5-6. Unknown ids burn a dummy hash so timing matches a wrong secret (§4.3)."""
    if record is None:
        registry.dummy_verify()
        raise UnknownKey(reason="unknown", key_id=parsed.key_id)
    hasher = registry.get(record.hash_alg)
    if hasher is None:
        registry.dummy_verify()
        raise UnknownKey(reason="pepper_version_missing", key_id=parsed.key_id)
    if not hasher.verify(parsed.body, record.hash) or record.prefix != parsed.prefix:
        raise UnknownKey(reason="bad_secret", key_id=parsed.key_id)
    return record


def check_scopes(record: KeyRecord, scopes: Optional[Sequence[str]], any_scopes: Optional[Sequence[str]]) -> None:
    required = tuple(scopes or ())
    missing = missing_scopes(record.scopes, required)
    any_req = tuple(any_scopes or ())
    if any_req and not any(scope_covers(g, r) for g in record.scopes for r in any_req):
        missing = missing + [r for r in any_req if r not in missing]
    if missing:
        raise InsufficientScope(required=list(required) + [r for r in any_req if r not in required],
                                missing=missing, key_id=record.key_id)


def check_ip(record: KeyRecord, client_ip: Optional[str]) -> None:
    if not record.ip_allowlist:
        return
    if not client_ip:
        raise IPNotAllowed(reason="no_client_ip", key_id=record.key_id)
    if not ip_allowed(record.ip_allowlist, client_ip):
        raise IPNotAllowed(reason="ip", key_id=record.key_id)


def decide(record: KeyRecord, now: datetime, *, scopes: Optional[Sequence[str]] = None,
           any_scopes: Optional[Sequence[str]] = None, client_ip: Optional[str] = None) -> None:
    """Steps 7-10 in fixed order: revoked -> expired -> scope -> ip (§5.2)."""
    now = ensure_aware(now, "now")
    if record.revoked_at is not None:
        raise RevokedKey(key_id=record.key_id)
    if record.expires_at is not None and record.expires_at <= now:
        raise ExpiredKey(key_id=record.key_id)
    check_scopes(record, scopes, any_scopes)
    check_ip(record, client_ip)


def should_touch(record: KeyRecord, now: datetime, interval: Optional[float]) -> bool:
    if interval is None:
        return False
    if record.last_used_at is None:
        return True
    return (now - record.last_used_at).total_seconds() >= interval


def key_id_from(value: str, key_format: KeyFormat) -> str:
    """Accept either a key_id or a raw key (key ids never contain ``_``)."""
    value = (value or "").strip()
    if "_" in value:
        return prepare_raw(value, key_format).key_id
    if not value:
        raise UnknownKey(reason="unknown")
    return value


# ---------------------------------------------------------------------------- issue / rotate
def _resolve_expiry(now: datetime, expires_at: Optional[datetime],
                    expires_in: Optional[timedelta]) -> Optional[datetime]:
    if expires_at is not None and expires_in is not None:
        raise ValueError("expires_at and expires_in are mutually exclusive")
    if expires_in is not None:
        if not isinstance(expires_in, timedelta):
            raise TypeError("expires_in must be a timedelta")
        if expires_in <= timedelta(0):
            raise ValueError("expires_in must be positive")
        return now + expires_in
    expires_at = optional_aware(expires_at, "expires_at")
    if expires_at is not None and expires_at <= now:
        raise ValueError("expires_at must be in the future")
    return expires_at


def _validate_text(value: Any, name: str, *, required: bool) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if required and not value.strip():
        raise ValueError(f"{name} is required")
    if len(value) > 255:
        raise ValueError(f"{name} must be at most 255 characters")
    return value


def build_new_key(
    *,
    key_format: KeyFormat,
    hasher: Hasher,
    policy: KeyPolicy,
    now: datetime,
    owner: str,
    scopes: Iterable[str] = (),
    expires_at: Optional[datetime] = None,
    expires_in: Optional[timedelta] = None,
    name: str = "",
    metadata: Optional[Mapping[str, Any]] = None,
    ip_allowlist: Iterable[str] = (),
    key_id: Optional[str] = None,
    rotated_from: Optional[str] = None,
) -> IssuedKey:
    """Validate + apply policy + generate + hash. Pure: does not persist."""
    owner = _validate_text(owner, "owner", required=True)
    name = _validate_text(name, "name", required=False)
    norm_scopes = normalize_scopes(scopes)
    policy.check_scopes(norm_scopes)
    exp = policy.resolve_expiry(now, _resolve_expiry(now, expires_at, expires_in))
    meta = validate_metadata(metadata, policy.max_metadata_bytes)
    allow = normalize_allowlist(ip_allowlist)
    raw, parsed = generate_key(key_format, key_id)
    record = KeyRecord(
        key_id=parsed.key_id, prefix=key_format.prefix, hash=hasher.hash(parsed.body), hash_alg=hasher.alg_id,
        secret_last4=parsed.secret[-4:], owner=owner, created_at=now, name=name, scopes=norm_scopes,
        expires_at=exp, ip_allowlist=allow, metadata=meta, rotated_from=rotated_from,
    )
    return IssuedKey(raw_key=raw, record=record)


def plan_revoke(record: KeyRecord, now: datetime, reason: Optional[str]) -> KeyRecord:
    if reason is not None:
        reason = _validate_text(reason, "reason", required=False) or None
    return record.replace(revoked_at=now, revoke_reason=reason)


def check_rotatable(old: KeyRecord, now: datetime) -> None:
    """Only a live key can be rotated: a revoked or expired one must not get a working replacement."""
    now = ensure_aware(now, "now")
    if old.revoked_at is not None:
        raise RevokedKey(key_id=old.key_id)
    if old.expires_at is not None and old.expires_at <= now:
        raise ExpiredKey(key_id=old.key_id)


def inherited_expiry(old: KeyRecord, now: datetime, policy: KeyPolicy) -> Optional[datetime]:
    """Default expiry of a replacement key: the old key's lifetime (``expires_at - created_at``) counted from
    ``now``, capped at ``policy.max_ttl`` in case the policy was tightened since the key was issued.
    ``None`` (a key without expiry) falls through to the policy defaults in :func:`build_new_key`."""
    if old.expires_at is None:
        return None
    now = ensure_aware(now, "now")
    lifetime = old.expires_at - old.created_at
    if policy.max_ttl is not None:
        lifetime = min(lifetime, policy.max_ttl)
    return now + lifetime


def plan_rotation(old: KeyRecord, new_key_id: str, now: datetime, grace: timedelta) -> KeyRecord:
    """Old key: ``expires_at = min(original, now + grace)``; ``grace == 0`` revokes immediately."""
    if not isinstance(grace, timedelta) or grace < timedelta(0):
        raise ValueError("grace must be a non-negative timedelta")
    if grace == timedelta(0):
        return old.replace(rotated_to=new_key_id, revoked_at=now, revoke_reason="rotated")
    cutoff = now + grace
    exp = cutoff if old.expires_at is None else min(old.expires_at, cutoff)
    return old.replace(rotated_to=new_key_id, expires_at=exp)


# ---------------------------------------------------------------------------- shared manager core
class _Core:
    """Configuration, validation and audit plumbing shared by every manager/verifier."""

    _is_manager = False

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
        require_pepper: Optional[bool] = None,
    ) -> None:
        if store is None:
            raise ConfigurationError("store is required")
        validate_prefix(prefix)
        if key_format is None:
            key_format = KeyFormat(prefix)
        elif key_format.prefix != prefix:
            raise ConfigurationError("key_format.prefix must equal prefix")
        if touch_interval is not None and touch_interval < 0:
            raise ConfigurationError("touch_interval must be >= 0 or None")
        self.policy = policy or KeyPolicy()
        self.registry, self.has_pepper = HasherRegistry.build(
            peppers=peppers, current_pepper=current_pepper, pepper=pepper, hasher=hasher)
        if require_pepper is None:
            require_pepper = self.policy.require_pepper
        if not self.has_pepper and hasher is None:
            if require_pepper:
                raise ConfigurationError(
                    "a pepper is required (pass pepper=/peppers= or set SAFE_API_KEYS_PEPPER); "
                    "to allow unpeppered SHA-256 explicitly use KeyPolicy(require_pepper=False)")
            warnings.warn("safe_api_keys: no pepper configured; falling back to unpeppered SHA-256. "
                          "Configure a pepper for production.", UserWarning, stacklevel=3)
        self.store = store
        self.prefix = prefix
        self.key_format = key_format
        self.touch_interval = touch_interval
        self.cache = cache
        self.audit: AuditSink = audit if audit is not None else NullAuditSink()
        self._clock = clock or utcnow
        self.reveal_state = reveal_state
        self.audit_success = audit_success

    @classmethod
    def from_env(cls, store: Any, prefix: str, **overrides: Any) -> Any:
        """Build with peppers from ``SAFE_API_KEYS_PEPPER(S)`` / ``SAFE_API_KEYS_CURRENT_PEPPER``."""
        from .env import from_env

        return from_env(cls, store, prefix, **overrides)

    # -- helpers --------------------------------------------------------------
    def now(self) -> datetime:
        return ensure_aware(self._clock(), "clock()")

    def _event(self, type_: str, **kw: Any) -> None:
        if "at" not in kw:
            kw["at"] = self.now()
        safe_emit(self.audit, AuditEvent(type=type_, **kw))

    def _require(self, name: str) -> Callable[..., Any]:
        from .exceptions import NotSupported

        fn = getattr(self.store, name, None)
        if fn is None or not callable(fn):
            raise NotSupported(f"{type(self.store).__name__} does not support {name}()")
        return fn  # type: ignore[no-any-return]

    @staticmethod
    def _wrap_store_error(exc: BaseException) -> StoreError:
        if isinstance(exc, StoreError):
            return exc
        err = StoreError(f"store operation failed: {type(exc).__name__}")
        err.__cause__ = exc
        return err

    @staticmethod
    def _is_passthrough(exc: BaseException) -> bool:
        return isinstance(exc, SafeAPIKeysError) and not isinstance(exc, StoreError)

    def parse(self, raw_key: str) -> ParsedKey:
        return prepare_raw(raw_key, self.key_format)

    def mask(self, raw_key: str) -> str:
        return self.parse(raw_key).masked

    def _reject(self, exc: APIKeyError, parsed: Optional[ParsedKey], record: Optional[KeyRecord],
                scopes: Optional[Sequence[str]], any_scopes: Optional[Sequence[str]],
                client_ip: Optional[str]) -> APIKeyError:
        """Audit a rejection and map revealing errors when ``reveal_state=False``."""
        req = tuple(scopes or ()) + tuple(any_scopes or ())
        self._event("key.rejected", key_id=exc.key_id or (parsed.key_id if parsed else None),
                    owner=record.owner if record else None, reason=exc.reason,
                    scopes_required=req or None, client_ip=client_ip)
        if not self.reveal_state and isinstance(exc, (RevokedKey, ExpiredKey)):
            hidden = UnknownKey(reason=exc.reason, key_id=exc.key_id)
            hidden.__suppress_context__ = True
            return hidden
        return exc

    def _verified(self, record: KeyRecord, scopes: Optional[Sequence[str]],
                  any_scopes: Optional[Sequence[str]], client_ip: Optional[str]) -> None:
        if not self.audit_success:
            return
        extra = {"rotated_to": record.rotated_to} if record.rotated_to else {}
        req = tuple(scopes or ()) + tuple(any_scopes or ())
        self._event("key.verified", key_id=record.key_id, owner=record.owner,
                    scopes_required=req or None, client_ip=client_ip, extra=extra)

    def authorize(self, record: KeyRecord, *, scopes: Optional[Sequence[str]] = None,
                  any_scopes: Optional[Sequence[str]] = None, client_ip: Optional[str] = None) -> KeyRecord:
        """Scope check for an already-verified record (e.g. set by middleware). No I/O."""
        try:
            check_scopes(record, scopes, any_scopes)
        except APIKeyError as exc:
            raise self._reject(exc, None, record, scopes, any_scopes, client_ip) from None
        return record

    def _touched(self, record: KeyRecord, now: datetime) -> KeyRecord:
        updated = record.replace(last_used_at=now, use_count=record.use_count + 1)
        if self.cache is not None:
            self.cache.update(updated)
        return updated

    def _touch_failed(self, record: KeyRecord, exc: BaseException) -> None:
        logger.warning("touch failed for key_id=%s: %s", record.key_id, type(exc).__name__)
        self._event("key.touch_failed", key_id=record.key_id, owner=record.owner,
                    reason=type(exc).__name__)

    def _invalidate(self, key_id: str) -> None:
        if self.cache is not None:
            self.cache.invalidate(key_id)

    def _issue_check_policy_count(self, active: int) -> None:
        self.policy.check_active_count(active)

    def __repr__(self) -> str:
        return (f"{type(self).__name__}(prefix={self.prefix!r}, store={type(self.store).__name__}, "
                f"hash_alg={self.registry.current.alg_id!r})")
