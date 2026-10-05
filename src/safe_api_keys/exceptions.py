"""Exception hierarchy.

Messages never contain raw keys or secrets; at most the public ``key_id``.
"""

from __future__ import annotations

from typing import Optional, Sequence

__all__ = [
    "SafeAPIKeysError",
    "ConfigurationError",
    "MissingDependency",
    "NotSupported",
    "StoreError",
    "PolicyViolation",
    "AlreadyRotated",
    "APIKeyError",
    "MissingKey",
    "MalformedKey",
    "UnknownKey",
    "RevokedKey",
    "ExpiredKey",
    "InsufficientScope",
    "IPNotAllowed",
    "INVALID_API_KEY_MESSAGE",
]

#: Shared text for MalformedKey and UnknownKey so callers cannot tell them apart (§4.3).
INVALID_API_KEY_MESSAGE = "invalid API key"


class SafeAPIKeysError(Exception):
    """Base class of every exception raised by this package."""


class ConfigurationError(SafeAPIKeysError, ValueError):
    """Invalid construction parameters (bad prefix, short pepper, missing pepper...)."""


class MissingDependency(SafeAPIKeysError, ImportError):
    """An optional backend/adapter was used without its extra installed."""


class NotSupported(SafeAPIKeysError):
    """The configured store does not implement an optional operation."""


class StoreError(SafeAPIKeysError):
    """The storage backend failed. HTTP adapters map this to 503."""

    status_code = 503
    error_code = "auth_unavailable"
    public_message = "Authentication temporarily unavailable"


class PolicyViolation(SafeAPIKeysError, ValueError):
    """``issue``/``rotate`` parameters violate the configured :class:`KeyPolicy`."""


class AlreadyRotated(SafeAPIKeysError):
    """``rotate`` was called on a key that already has a replacement (``rotated_to`` is set).

    The key still verifies during its grace period, so this is a lifecycle error, not a verification
    failure: rotate ``rotated_to`` instead.
    """

    def __init__(self, key_id: str, rotated_to: str) -> None:
        self.key_id = key_id
        self.rotated_to = rotated_to
        super().__init__(f"key {key_id} was already rotated to {rotated_to}; rotate that key instead")


class APIKeyError(SafeAPIKeysError):
    """Base class of all verification failures.

    Attributes:
        reason: machine-readable internal reason (used for audit; never shown to clients
            beyond the public ``error_code``).
        key_id: public key id if it could be parsed, else ``None``.
    """

    status_code = 401
    error_code = "invalid_api_key"
    public_message = "Invalid API key"
    default_reason = "invalid"

    def __init__(self, message: Optional[str] = None, *, reason: Optional[str] = None,
                 key_id: Optional[str] = None) -> None:
        self.reason = reason or self.default_reason
        self.key_id = key_id
        super().__init__(message or self.default_message())

    def default_message(self) -> str:
        return self.public_message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(reason={self.reason!r}, key_id={self.key_id!r})"


class MissingKey(APIKeyError):
    """No key was supplied with the request (raised by HTTP adapters only)."""

    error_code = "missing_api_key"
    public_message = "No API key provided"
    default_reason = "missing"


class MalformedKey(APIKeyError):
    default_reason = "malformed"

    def default_message(self) -> str:
        return INVALID_API_KEY_MESSAGE


class UnknownKey(APIKeyError):
    default_reason = "unknown"

    def default_message(self) -> str:
        return INVALID_API_KEY_MESSAGE


class RevokedKey(APIKeyError):
    error_code = "revoked_api_key"
    public_message = "This API key has been revoked"
    default_reason = "revoked"


class ExpiredKey(APIKeyError):
    error_code = "expired_api_key"
    public_message = "This API key has expired"
    default_reason = "expired"


class InsufficientScope(APIKeyError):
    status_code = 403
    error_code = "insufficient_scope"
    public_message = "Insufficient scope"
    default_reason = "scope"

    def __init__(self, message: Optional[str] = None, *, required: Sequence[str] = (),
                 missing: Sequence[str] = (), key_id: Optional[str] = None,
                 reason: Optional[str] = None) -> None:
        self.required = list(required)
        self.missing = list(missing)
        super().__init__(message, reason=reason, key_id=key_id)


class IPNotAllowed(APIKeyError):
    status_code = 403
    error_code = "ip_not_allowed"
    public_message = "Request IP not allowed for this key"
    default_reason = "ip"
