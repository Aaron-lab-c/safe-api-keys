"""Audit events and sinks (§11). Events never carry raw keys or secrets."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple, Union, runtime_checkable

__all__ = [
    "AuditEvent",
    "AuditSink",
    "NullAuditSink",
    "LoggingAuditSink",
    "CallbackAuditSink",
    "safe_emit",
    "EVENT_TYPES",
]

_log = logging.getLogger("safe_api_keys")

EVENT_TYPES = (
    "key.issued", "key.verified", "key.rejected", "key.revoked", "key.rotated",
    "key.rotate_partial", "key.touch_failed", "key.purged",
)


@dataclass(frozen=True)
class AuditEvent:
    type: str
    at: datetime
    key_id: Optional[str] = None
    owner: Optional[str] = None
    reason: Optional[str] = None
    scopes_required: Optional[Tuple[str, ...]] = None
    client_ip: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type, "at": self.at.isoformat(), "key_id": self.key_id, "owner": self.owner,
            "reason": self.reason,
            "scopes_required": list(self.scopes_required) if self.scopes_required is not None else None,
            "client_ip": self.client_ip, "extra": dict(self.extra),
        }


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class NullAuditSink:
    def emit(self, event: AuditEvent) -> None:
        return None


class LoggingAuditSink:
    """Logs each event with structured fields under ``record.audit`` (and flattened ``audit_*``)."""

    def __init__(self, logger: Union[logging.Logger, str, None] = None, level: int = logging.INFO,
                 rejected_level: Optional[int] = None) -> None:
        if logger is None or isinstance(logger, str):
            logger = logging.getLogger(logger or "safe_api_keys.audit")
        self.logger = logger
        self.level = level
        self.rejected_level = rejected_level if rejected_level is not None else level

    def emit(self, event: AuditEvent) -> None:
        try:
            data = event.as_dict()
            level = self.rejected_level if event.type == "key.rejected" else self.level
            extra = {"audit": data, **{f"audit_{k}": v for k, v in data.items() if k != "extra"}}
            self.logger.log(level, "%s key_id=%s owner=%s reason=%s", event.type, event.key_id, event.owner,
                            event.reason, extra=extra)
        except Exception:  # pragma: no cover - logging must never break auth
            _log.exception("LoggingAuditSink failed")


class CallbackAuditSink:
    def __init__(self, fn: Callable[[AuditEvent], Any]) -> None:
        self.fn = fn

    def emit(self, event: AuditEvent) -> None:
        try:
            self.fn(event)
        except Exception:
            _log.exception("audit callback failed for %s", event.type)


def safe_emit(sink: Optional[AuditSink], event: AuditEvent) -> None:
    """Emit without ever propagating an exception (sinks MUST NOT raise)."""
    if sink is None:
        return
    try:
        sink.emit(event)
    except Exception:
        _log.exception("audit sink %r raised for %s", type(sink).__name__, event.type)
