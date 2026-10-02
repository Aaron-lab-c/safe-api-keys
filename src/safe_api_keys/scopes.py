"""Scope grammar and matching (§8)."""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

__all__ = ["validate_scope", "normalize_scopes", "has_scope", "missing_scopes", "scope_covers", "WILDCARD"]

WILDCARD = "*"
_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,62}(:\*)?$")


def validate_scope(scope: str) -> str:
    if not isinstance(scope, str) or not (scope == WILDCARD or _SCOPE_RE.match(scope)):
        raise ValueError(f"invalid scope {scope!r}")
    return scope


def normalize_scopes(scopes: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Validate, de-duplicate and sort."""
    if scopes is None:
        return ()
    if isinstance(scopes, str):
        scopes = [scopes]
    return tuple(sorted({validate_scope(s) for s in scopes}))


def scope_covers(granted: str, required: str) -> bool:
    """``orders:*`` covers ``orders:read`` and ``orders:items:write`` but not ``orders``."""
    if granted == required or granted == WILDCARD:
        return True
    return granted.endswith(":*") and required.startswith(granted[:-1])


def has_scope(granted: Iterable[str], required: str) -> bool:
    return any(scope_covers(g, required) for g in granted)


def missing_scopes(granted: Iterable[str], required_all: Iterable[str]) -> List[str]:
    g = tuple(granted)
    return [r for r in required_all if not has_scope(g, r)]
