"""safe-api-keys: framework-agnostic API key lifecycle management.

Quick start::

    from safe_api_keys import KeyManager
    from safe_api_keys.stores import MemoryStore

    km = KeyManager(MemoryStore(), prefix="sk_test", pepper=b"change-me-32-bytes-of-randomness!")
    issued = km.issue("user-1", scopes=["orders:read"])
    record = km.verify(issued.raw_key, scopes=["orders:read"])
"""

from .amanager import AsyncKeyManager, AsyncKeyVerifier
from .audit import AuditEvent, AuditSink, CallbackAuditSink, LoggingAuditSink, NullAuditSink
from .cache import VerifyCache
from .exceptions import (
    AlreadyRotated,
    APIKeyError,
    ConfigurationError,
    ExpiredKey,
    InsufficientScope,
    IPNotAllowed,
    MalformedKey,
    MissingDependency,
    MissingKey,
    NotSupported,
    PolicyViolation,
    RevokedKey,
    SafeAPIKeysError,
    StoreError,
    UnknownKey,
)
from .extract import ExtractConfig, extract_key
from .format import KeyFormat, mask_key, parse_key
from .hashing import DUMMY_HASH, Argon2Hasher, Hasher, HmacSha256Hasher, Sha256Hasher
from .manager import KeyManager, KeyVerifier
from .models import IssuedKey, KeyRecord, ParsedKey, VerifyResult
from .policy import KeyPolicy
from .scopes import has_scope, missing_scopes

__version__ = "0.3.0"

__all__ = [
    "KeyManager", "KeyVerifier", "AsyncKeyManager", "AsyncKeyVerifier",
    "KeyRecord", "IssuedKey", "ParsedKey", "VerifyResult", "KeyFormat", "KeyPolicy", "VerifyCache",
    "Hasher", "HmacSha256Hasher", "Sha256Hasher", "Argon2Hasher", "DUMMY_HASH",
    "AuditEvent", "AuditSink", "NullAuditSink", "LoggingAuditSink", "CallbackAuditSink",
    "ExtractConfig", "extract_key", "parse_key", "mask_key", "has_scope", "missing_scopes",
    "SafeAPIKeysError", "APIKeyError", "MissingKey", "MalformedKey", "UnknownKey", "RevokedKey", "ExpiredKey",
    "InsufficientScope", "IPNotAllowed", "StoreError", "PolicyViolation", "ConfigurationError",
    "MissingDependency", "NotSupported", "AlreadyRotated",
    "__version__",
]
