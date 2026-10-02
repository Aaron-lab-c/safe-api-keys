"""Key format (§3): ``prefix_keyid_secretCHECKSUM``."""

from __future__ import annotations

import re
import secrets
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from .exceptions import ConfigurationError, MalformedKey
from .models import ParsedKey, mask_parts

__all__ = [
    "BASE62_ALPHABET",
    "KeyFormat",
    "MAX_RAW_KEY_LENGTH",
    "base62_encode",
    "compute_checksum",
    "generate_key",
    "parse_key",
    "validate_prefix",
    "mask_key",
]

BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
CHECKSUM_LEN = 6
MAX_RAW_KEY_LENGTH = 512
_BASE62_SET = frozenset(BASE62_ALPHABET)
_PREFIX_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|_(?!_))*$")


def base62_encode(value: Union[int, bytes], width: int = 0) -> str:
    """Encode a non-negative int (or big-endian bytes) as base62, left-padded with ``0`` to ``width``."""
    n = int.from_bytes(value, "big") if isinstance(value, (bytes, bytearray)) else int(value)
    if n < 0:
        raise ValueError("base62_encode() requires a non-negative value")
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(BASE62_ALPHABET[r])
    return "".join(reversed(out)).rjust(width, "0") or "0"


def _random_base62(length: int) -> str:
    # Uniform per character via ``secrets`` (§3.2 / S2). Equivalent to encoding
    # token_bytes() and truncating, but without the leading-digit bias of truncation.
    return "".join(secrets.choice(BASE62_ALPHABET) for _ in range(length))


def compute_checksum(body: str) -> str:
    return base62_encode(zlib.crc32(body.encode("ascii")) & 0xFFFFFFFF, CHECKSUM_LEN)


def validate_prefix(prefix: str) -> str:
    if not isinstance(prefix, str) or not (1 <= len(prefix) <= 32) or not _PREFIX_RE.match(prefix) \
            or prefix.endswith("_"):
        raise ConfigurationError(
            f"invalid prefix {prefix!r}: 1-32 chars of a-z 0-9 _, not starting/ending with '_' and no '__'")
    return prefix


@dataclass(frozen=True)
class KeyFormat:
    prefix: str
    key_id_len: int = 12
    secret_len: int = 32
    checksum: bool = True

    def __post_init__(self) -> None:
        validate_prefix(self.prefix)
        if self.key_id_len < 8:
            raise ConfigurationError("key_id_len must be >= 8")
        if not 24 <= self.secret_len <= 64:
            raise ConfigurationError("secret_len must be between 24 and 64")

    @property
    def length(self) -> int:
        return len(self.prefix) + 1 + self.key_id_len + 1 + self.secret_len + (CHECKSUM_LEN if self.checksum else 0)

    def new_key_id(self) -> str:
        return _random_base62(self.key_id_len)

    def new_secret(self) -> str:
        return _random_base62(self.secret_len)

    def build(self, key_id: str, secret: str) -> Tuple[str, str]:
        """Return ``(raw_key, body)``."""
        body = f"{self.prefix}_{key_id}_{secret}"
        return body + (compute_checksum(body) if self.checksum else ""), body

    def parse(self, raw: str) -> ParsedKey:
        return parse_key(raw, self)


def generate_key(key_format: KeyFormat, key_id: Optional[str] = None) -> Tuple[str, ParsedKey]:
    """Generate a fresh key. ``key_id`` may be injected (tests only)."""
    kid = key_id if key_id is not None else key_format.new_key_id()
    if len(kid) != key_format.key_id_len or not set(kid) <= _BASE62_SET:
        raise ValueError(f"key_id must be {key_format.key_id_len} base62 characters")
    secret = key_format.new_secret()
    raw, body = key_format.build(kid, secret)
    checksum = raw[len(body):]
    return raw, ParsedKey(key_format.prefix, kid, secret, checksum, True, body)


def _malformed(reason: str, key_id: Optional[str] = None) -> MalformedKey:
    return MalformedKey(reason=reason, key_id=key_id)


def parse_key(raw: str, key_format: Optional[KeyFormat] = None, *, strict_checksum: bool = True) -> ParsedKey:
    """Pure parser (§3.3). Never touches a store.

    With ``key_format=None`` (e.g. the ``parse`` CLI) any valid prefix/length combination is accepted.
    Raises :class:`MalformedKey`; checksum mismatch raises with ``reason="checksum"``.
    """
    if not isinstance(raw, str):
        raise _malformed("malformed")
    if len(raw) > MAX_RAW_KEY_LENGTH * 2:
        raise _malformed("malformed")
    raw = raw.strip()
    if len(raw) > MAX_RAW_KEY_LENGTH or not raw.isascii():
        raise _malformed("malformed")
    parts = raw.rsplit("_", 2)
    if len(parts) != 3:
        raise _malformed("malformed")
    prefix, key_id, tail = parts
    if not prefix or not _PREFIX_RE.match(prefix) or prefix.endswith("_") or len(prefix) > 32:
        raise _malformed("malformed")
    use_checksum = key_format.checksum if key_format else True
    csum_len = CHECKSUM_LEN if use_checksum else 0
    secret = tail[: len(tail) - csum_len] if csum_len else tail
    checksum = tail[len(tail) - csum_len:] if csum_len else ""
    if key_format is not None:
        if len(key_id) != key_format.key_id_len or len(secret) != key_format.secret_len:
            raise _malformed("malformed")
    elif len(key_id) < 8 or not 24 <= len(secret) <= 64:
        raise _malformed("malformed")
    if not set(key_id) <= _BASE62_SET or not set(tail) <= _BASE62_SET:
        raise _malformed("malformed")
    body = f"{prefix}_{key_id}_{secret}"
    ok = (not use_checksum) or secrets.compare_digest(compute_checksum(body), checksum)
    if not ok and strict_checksum:
        raise _malformed("checksum", key_id)
    return ParsedKey(prefix, key_id, secret, checksum, ok, body)


def mask_key(raw: str, key_format: Optional[KeyFormat] = None) -> str:
    p = parse_key(raw, key_format)
    return mask_parts(p.prefix, p.key_id, p.secret[-4:])
