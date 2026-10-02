"""Small shared helpers (time, durations). Zero dependencies."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Optional, Union

UTC = timezone.utc

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw]?)\s*$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_aware(value: datetime, name: str = "datetime") -> datetime:
    """Reject naive datetimes (§2.5) and normalise to UTC."""
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{name} must be timezone-aware (UTC); got naive datetime")
    return value.astimezone(UTC)


def optional_aware(value: Optional[datetime], name: str) -> Optional[datetime]:
    return None if value is None else ensure_aware(value, name)


def parse_duration(value: Union[str, int, float, timedelta]) -> timedelta:
    """Parse ``"90d"``, ``"24h"``, ``"30m"``, ``"45s"``, ``"2w"`` or a number of seconds."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, bool):
        raise ValueError(f"invalid duration: {value!r}")
    if isinstance(value, (int, float)):
        return timedelta(seconds=value)
    m = _DURATION_RE.match(str(value))
    if not m:
        raise ValueError(f"invalid duration: {value!r} (expected e.g. 90d, 24h, 30m, 45s)")
    return timedelta(seconds=int(m.group(1)) * _UNITS[m.group(2)])


def parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; ``Z`` suffix accepted; must carry a timezone."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return ensure_aware(datetime.fromisoformat(text), "timestamp")


def to_iso(value: datetime) -> str:
    """Fixed-width UTC ISO-8601 (lexicographically sortable): ``YYYY-MM-DDTHH:MM:SS.ffffff+00:00``."""
    return ensure_aware(value).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def from_iso(value: str) -> datetime:
    return parse_datetime(value)


def rfc1123(value: datetime) -> str:
    return format_datetime(ensure_aware(value), usegmt=True)
