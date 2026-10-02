"""Pull the raw key out of request headers / query string (§13.1). Shared by all adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple

__all__ = ["ExtractConfig", "extract_key"]

_SOURCES = ("bearer", "header", "query")


@dataclass(frozen=True)
class ExtractConfig:
    bearer: bool = True
    header: Optional[str] = "X-API-Key"
    query_param: Optional[str] = None  # off by default: query strings end up in access logs
    order: Tuple[str, ...] = _SOURCES

    def __post_init__(self) -> None:
        bad = [s for s in self.order if s not in _SOURCES]
        if bad:
            raise ValueError(f"unknown extract sources: {bad}")
        object.__setattr__(self, "order", tuple(self.order))

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> ExtractConfig:
        data = dict(data or {})
        if "order" in data:
            data["order"] = tuple(data["order"])
        return cls(**data)


def _get_ci(headers: Any, name: str) -> Optional[str]:
    """Case-insensitive header lookup for plain dicts as well as framework header objects."""
    getter = getattr(headers, "get", None)
    if getter is not None:
        v = getter(name)
        if v is not None:
            return str(v)
    items: Iterable[Any] = headers.items() if hasattr(headers, "items") else headers
    lname = name.lower()
    for k, v in items:
        if isinstance(k, bytes):
            k = k.decode("latin-1")
        if str(k).lower() == lname:
            return v.decode("latin-1") if isinstance(v, bytes) else str(v)
    return None


def _bearer(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    parts = value.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None  # anything but exactly "Bearer <one-token>" counts as not provided
    return parts[1]


def extract_key(headers: Any, query: Optional[Mapping[str, Any]] = None,
                config: Optional[ExtractConfig] = None) -> Optional[str]:
    config = config or ExtractConfig()
    for source in config.order:
        value: Optional[str] = None
        if source == "bearer" and config.bearer:
            value = _bearer(_get_ci(headers, "Authorization"))
        elif source == "header" and config.header:
            value = _get_ci(headers, config.header)
        elif source == "query" and config.query_param and query is not None:
            raw = query.get(config.query_param)
            if isinstance(raw, (list, tuple)):
                raw = raw[0] if raw else None
            value = str(raw) if raw is not None else None
        if value is not None:
            value = value.strip()
            if value:
                return value
    return None
