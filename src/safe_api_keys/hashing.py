"""Secret hashing (§4).

Default is HMAC-SHA256 keyed with a server-side pepper. The secret already carries
>= 180 bits of entropy, so slow password hashes add latency without security; an
:class:`Argon2Hasher` is available behind the ``[argon2]`` extra for policies that require one.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple, runtime_checkable

from .exceptions import ConfigurationError, MissingDependency

__all__ = [
    "Hasher",
    "HmacSha256Hasher",
    "Sha256Hasher",
    "Argon2Hasher",
    "HasherRegistry",
    "DUMMY_HASH",
    "MIN_PEPPER_BYTES",
]

MIN_PEPPER_BYTES = 16
#: Hashed when a key_id does not exist so "unknown" and "wrong secret" cost the same (§4.3).
DUMMY_HASH = hashlib.sha256(b"safe-api-keys:dummy").hexdigest()
_DUMMY_BODY = "dummy_000000000000_00000000000000000000000000000000"


@runtime_checkable
class Hasher(Protocol):
    alg_id: str

    def hash(self, body: str) -> str: ...

    def verify(self, body: str, stored: str) -> bool: ...


def _check_pepper(pepper: bytes, label: str = "pepper") -> bytes:
    if isinstance(pepper, str):
        raise ConfigurationError(f"{label} must be bytes (use .encode())")
    if not isinstance(pepper, (bytes, bytearray)) or len(pepper) < MIN_PEPPER_BYTES:
        raise ConfigurationError(f"{label} must be at least {MIN_PEPPER_BYTES} bytes")
    return bytes(pepper)


def _check_version(version: str) -> str:
    if not version or "$" in version or len(version) > 16 or not version.isascii():
        raise ConfigurationError(f"invalid pepper version {version!r}")
    return version


class HmacSha256Hasher:
    def __init__(self, pepper: bytes, version: str = "v1") -> None:
        self._pepper = _check_pepper(pepper, f"pepper {version!r}")
        self.version = _check_version(version)
        self.alg_id = f"hmac-sha256${self.version}"

    def hash(self, body: str) -> str:
        return hmac.new(self._pepper, body.encode("ascii"), hashlib.sha256).hexdigest()

    def verify(self, body: str, stored: str) -> bool:
        return hmac.compare_digest(self.hash(body), stored or "")

    def __repr__(self) -> str:  # never show the pepper
        return f"HmacSha256Hasher(alg_id={self.alg_id!r})"


class Sha256Hasher:
    """Unpeppered fallback (``sha256$v0``). Only used when no pepper is configured."""

    alg_id = "sha256$v0"

    def hash(self, body: str) -> str:
        return hashlib.sha256(body.encode("ascii")).hexdigest()

    def verify(self, body: str, stored: str) -> bool:
        return hmac.compare_digest(self.hash(body), stored or "")

    def __repr__(self) -> str:
        return "Sha256Hasher()"


class Argon2Hasher:
    """Argon2id (``pip install safe-api-keys[argon2]``). Adds ~50-300 ms per verify.

    The stored value is an argon2 encoded string (~100 chars), which is why SQL backends
    size the ``hash`` column at 255 rather than 64.
    """

    def __init__(self, pepper: Optional[bytes] = None, version: str = "v1", **params: Any) -> None:
        try:
            from argon2 import PasswordHasher
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise MissingDependency("pip install safe-api-keys[argon2]") from exc
        self._ph = PasswordHasher(**params)
        self._pepper = _check_pepper(pepper) if pepper is not None else b""
        self.alg_id = f"argon2id${_check_version(version)}"

    def _material(self, body: str) -> bytes:
        if self._pepper:
            return hmac.new(self._pepper, body.encode("ascii"), hashlib.sha256).digest()
        return body.encode("ascii")

    def hash(self, body: str) -> str:
        return str(self._ph.hash(self._material(body)))

    def verify(self, body: str, stored: str) -> bool:
        from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

        try:
            return bool(self._ph.verify(stored, self._material(body)))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def __repr__(self) -> str:
        return f"Argon2Hasher(alg_id={self.alg_id!r})"


class HasherRegistry:
    """Maps ``hash_alg`` strings to hashers; ``current`` is used for newly issued keys (§4.2)."""

    def __init__(self, current: Hasher, others: Mapping[str, Hasher] = ()) -> None:  # type: ignore[assignment]
        self.current = current
        self._by_alg: Dict[str, Hasher] = dict(others or {})
        self._by_alg[current.alg_id] = current
        self._dummy_stored: Optional[str] = None

    @classmethod
    def build(
        cls,
        *,
        peppers: Optional[Mapping[str, bytes]] = None,
        current_pepper: Optional[str] = None,
        pepper: Optional[bytes] = None,
        hasher: Optional[Hasher] = None,
    ) -> Tuple[HasherRegistry, bool]:
        """Return ``(registry, has_pepper)``."""
        if pepper is not None and peppers is not None:
            raise ConfigurationError("pass either pepper= or peppers=, not both")
        if pepper is not None:
            peppers, current_pepper = {"v1": pepper}, "v1"
        hmacs: Dict[str, Hasher] = {}
        if peppers:
            if current_pepper is None:
                if len(peppers) != 1:
                    raise ConfigurationError("current_pepper is required when several peppers are configured")
                current_pepper = next(iter(peppers))
            if current_pepper not in peppers:
                raise ConfigurationError(f"current_pepper {current_pepper!r} is not in peppers")
            for version, value in peppers.items():
                h = HmacSha256Hasher(value, version)
                hmacs[h.alg_id] = h
        elif current_pepper is not None:
            raise ConfigurationError("current_pepper given without peppers")
        has_pepper = bool(hmacs)
        if hasher is not None:
            current: Hasher = hasher
        elif has_pepper:
            current = hmacs[f"hmac-sha256${current_pepper}"]
        else:
            current = Sha256Hasher()
        return cls(current, hmacs), has_pepper

    def get(self, alg_id: str) -> Optional[Hasher]:
        return self._by_alg.get(alg_id)

    def dummy_verify(self) -> None:
        """Burn the same work as a real comparison (result intentionally ignored)."""
        if isinstance(self.current, (HmacSha256Hasher, Sha256Hasher)):
            stored = DUMMY_HASH
        else:
            # Slow/custom hashers need a well-formed stored value to do equivalent work.
            if self._dummy_stored is None:
                self._dummy_stored = self.current.hash(_DUMMY_BODY)
            stored = self._dummy_stored
        self.current.verify(_DUMMY_BODY + "x", stored)

    @property
    def alg_ids(self) -> Tuple[str, ...]:
        return tuple(self._by_alg)

    def __repr__(self) -> str:
        return f"HasherRegistry(current={self.current.alg_id!r}, algs={self.alg_ids!r})"
