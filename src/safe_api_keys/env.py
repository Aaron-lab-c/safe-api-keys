"""Read pepper configuration from environment variables (§15)."""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional

from .exceptions import ConfigurationError

__all__ = ["pepper_kwargs_from_env", "PEPPER_ENV", "PEPPERS_ENV", "CURRENT_PEPPER_ENV", "STORE_ENV"]

PEPPER_ENV = "SAFE_API_KEYS_PEPPER"
PEPPERS_ENV = "SAFE_API_KEYS_PEPPERS"
CURRENT_PEPPER_ENV = "SAFE_API_KEYS_CURRENT_PEPPER"
STORE_ENV = "SAFE_API_KEYS_STORE"


def parse_peppers(value: str) -> Dict[str, bytes]:
    """``"v2:secret2,v1:secret1"`` -> ``{"v2": b"secret2", "v1": b"secret1"}`` (order kept)."""
    out: Dict[str, bytes] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        version, sep, secret = part.partition(":")
        if not sep or not version.strip() or not secret:
            raise ConfigurationError(f"{PEPPERS_ENV} entries must look like 'v2:<secret>'")
        out[version.strip()] = secret.encode("utf-8")
    return out


def pepper_kwargs_from_env(environ: Optional[Mapping[str, str]] = None, *,
                           pepper_env: str = PEPPER_ENV) -> Dict[str, Any]:
    """Return ``{"peppers": ..., "current_pepper": ...}`` (or ``{}`` if nothing is set).

    The pepper string is used as-is (its UTF-8 bytes); base64/hex strings are fine.
    """
    env = os.environ if environ is None else environ
    multi = env.get(PEPPERS_ENV)
    if multi:
        peppers = parse_peppers(multi)
        current = env.get(CURRENT_PEPPER_ENV) or next(iter(peppers))
        return {"peppers": peppers, "current_pepper": current}
    single = env.get(pepper_env)
    if single:
        return {"peppers": {"v1": single.encode("utf-8")}, "current_pepper": "v1"}
    return {}


def from_env(cls: Any, store: Any, prefix: str, *, environ: Optional[Mapping[str, str]] = None,
             pepper_env: str = PEPPER_ENV, **overrides: Any) -> Any:
    kwargs = pepper_kwargs_from_env(environ, pepper_env=pepper_env)
    if "pepper" in overrides or "peppers" in overrides:
        kwargs = {}
    kwargs.update(overrides)
    return cls(store, prefix, **kwargs)
