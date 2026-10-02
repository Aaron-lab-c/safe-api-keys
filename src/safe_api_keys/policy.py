"""Issuance policy (§9). Checked on ``issue``/``rotate`` only, never on ``verify``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Mapping, Optional, Set

from ._util import parse_duration
from .exceptions import PolicyViolation
from .scopes import normalize_scopes, scope_covers

__all__ = ["KeyPolicy", "validate_metadata", "MAX_METADATA_DEPTH"]

MAX_METADATA_DEPTH = 3


@dataclass(frozen=True)
class KeyPolicy:
    require_expiry: bool = False
    max_ttl: Optional[timedelta] = None
    default_ttl: Optional[timedelta] = None
    allowed_scopes: Optional[Set[str]] = None
    max_active_keys_per_owner: Optional[int] = None
    require_pepper: bool = True
    allow_no_scope: bool = True
    max_metadata_bytes: int = 8192

    def __post_init__(self) -> None:
        for name in ("max_ttl", "default_ttl"):
            v = getattr(self, name)
            if v is not None:
                v = parse_duration(v)
                if v <= timedelta(0):
                    raise ValueError(f"{name} must be positive")
                object.__setattr__(self, name, v)
        if self.max_ttl and self.default_ttl and self.default_ttl > self.max_ttl:
            raise ValueError("default_ttl must not exceed max_ttl")
        if self.allowed_scopes is not None:
            object.__setattr__(self, "allowed_scopes", set(normalize_scopes(self.allowed_scopes)))
        if self.max_active_keys_per_owner is not None and self.max_active_keys_per_owner < 1:
            raise ValueError("max_active_keys_per_owner must be >= 1")

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> KeyPolicy:
        """Build from settings-style dicts (durations as ``"90d"`` or seconds)."""
        data = dict(data or {})
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown policy fields: {sorted(unknown)}")
        for name in ("max_ttl", "default_ttl"):
            if data.get(name) is not None:
                data[name] = parse_duration(data[name])
        if data.get("allowed_scopes") is not None:
            data["allowed_scopes"] = set(data["allowed_scopes"])
        return cls(**data)

    # -- checks ------------------------------------------------------------------
    def resolve_expiry(self, now: datetime, expires_at: Optional[datetime]) -> Optional[datetime]:
        """explicit expiry -> ``default_ttl`` -> (``require_expiry`` fails) -> capped at ``max_ttl`` -> never."""
        if expires_at is None and self.default_ttl is not None:
            expires_at = now + self.default_ttl
        if expires_at is None:
            if self.require_expiry:
                raise PolicyViolation("an expiry is required by policy")
            # A non-expiring key would exceed max_ttl, so it gets the longest lifetime allowed.
            return now + self.max_ttl if self.max_ttl is not None else None
        if self.max_ttl is not None and expires_at - now > self.max_ttl:
            raise PolicyViolation(f"expiry exceeds max_ttl ({self.max_ttl})")
        return expires_at

    def check_scopes(self, scopes: Iterable[str]) -> None:
        scopes = tuple(scopes)
        if not scopes and not self.allow_no_scope:
            raise PolicyViolation("at least one scope is required by policy")
        if self.allowed_scopes is not None:
            bad = [s for s in scopes if not any(scope_covers(a, s) for a in self.allowed_scopes)]
            if bad:
                raise PolicyViolation(f"scopes not allowed by policy: {bad}")

    def check_active_count(self, active: int) -> None:
        if self.max_active_keys_per_owner is not None and active >= self.max_active_keys_per_owner:
            raise PolicyViolation(
                f"owner already has {active} active keys (max {self.max_active_keys_per_owner})")


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, (list, tuple)):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def validate_metadata(metadata: Optional[Mapping[str, Any]], max_bytes: int = 8192) -> Dict[str, Any]:
    """JSON-serialisable dict, depth <= 3, serialised size <= ``max_bytes`` (S14)."""
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise ValueError("metadata must be a mapping")
    data = dict(metadata)
    try:
        encoded = json.dumps(data, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"metadata must be JSON-serialisable: {exc}") from None
    if len(encoded.encode("utf-8")) > max_bytes:
        raise PolicyViolation(f"metadata exceeds {max_bytes} bytes")
    if _depth(data) > MAX_METADATA_DEPTH:
        raise PolicyViolation(f"metadata nesting deeper than {MAX_METADATA_DEPTH}")
    copied: Dict[str, Any] = json.loads(encoded)  # deep copy with JSON-native types
    return copied
