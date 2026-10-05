"""System checks (``python manage.py check`` / ``runserver`` start-up).

The pepper is read lazily so ``migrate`` works before it is set; this check makes a missing or invalid
pepper visible *before* the first request fails instead of only then.
"""

from __future__ import annotations

from typing import Any, List

from django.core.checks import Error, Tags, Warning, register

from ...exceptions import ConfigurationError

__all__ = ["check_pepper"]

W001 = "safe_api_keys.W001"
E001 = "safe_api_keys.E001"


@register(Tags.security)
def check_pepper(app_configs: Any = None, **kwargs: Any) -> List[Any]:
    from ...hashing import MIN_PEPPER_BYTES, HasherRegistry
    from .conf import _peppers, get_settings

    cfg = get_settings()
    env = cfg["PEPPER_ENV"] or "SAFE_API_KEYS_PEPPER"
    try:
        kwargs = _peppers(cfg)
        if kwargs:  # the same validation KeyManager applies (length >= MIN_PEPPER_BYTES, versions, current)
            HasherRegistry.build(**kwargs)
    except (ConfigurationError, ValueError) as exc:
        return [Error(f"SAFE_API_KEYS: invalid pepper configuration: {exc}",
                      hint=f"Fix the {env} environment variable or SAFE_API_KEYS['PEPPERS'] "
                           f"(at least {MIN_PEPPER_BYTES} bytes; 32 random bytes recommended).", id=E001)]
    if kwargs:
        return []
    return [Warning(
        f"SAFE_API_KEYS: no pepper configured ({env} is not set and SAFE_API_KEYS['PEPPERS'] is empty).",
        hint="Every request needing an API key will fail with ImproperlyConfigured until a pepper is set. "
             f"Export {env} (at least {MIN_PEPPER_BYTES} bytes; 32 random bytes recommended) or set "
             "SAFE_API_KEYS['PEPPERS'].",
        id=W001)]
