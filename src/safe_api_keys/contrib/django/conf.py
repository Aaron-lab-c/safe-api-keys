"""``settings.SAFE_API_KEYS``: defaults, validation and the singleton manager."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from ...env import pepper_kwargs_from_env
from ...exceptions import ConfigurationError
from ...extract import ExtractConfig
from ...policy import KeyPolicy

__all__ = ["DEFAULTS", "get_settings", "validate_settings", "get_manager", "reset_manager", "get_adapter",
           "resolve_user", "lookup_user"]

DEFAULTS: Dict[str, Any] = {
    "PREFIX": None,
    "PEPPERS": None,
    "PEPPER_ENV": "SAFE_API_KEYS_PEPPER",
    "CURRENT_PEPPER": None,
    "EXTRACT": {"bearer": True, "header": "X-API-Key", "query_param": None},
    "TOUCH_INTERVAL": 60,
    "TRUST_PROXY": False,
    "TRUSTED_PROXIES": [],
    "MODEL": "safe_api_keys.APIKey",
    "STORE": None,
    "POLICY": {},
    "REVEAL_STATE": True,
    "SUNSET_HEADERS": True,
    "PROTECT": [],
    "EXEMPT": [],
    "CORS_PREFLIGHT": "authenticate",   # or "respond": answer browser preflights with 204, no key, no view
    "USER_RESOLVER": None,
    "AUDIT": "safe_api_keys.audit.LoggingAuditSink",
    "CACHE": None,               # e.g. {"ttl": 5, "maxsize": 10000}
    "AUTH_SCHEME": "Bearer",
}

_TYPES: Dict[str, Any] = {
    "PREFIX": str, "PEPPERS": (dict, type(None)), "PEPPER_ENV": (str, type(None)),
    "CURRENT_PEPPER": (str, type(None)), "EXTRACT": dict, "TOUCH_INTERVAL": (int, float, type(None)),
    "TRUST_PROXY": bool, "TRUSTED_PROXIES": (list, tuple), "MODEL": str, "STORE": (str, type(None), object),
    "POLICY": (dict, type(None)), "REVEAL_STATE": bool, "SUNSET_HEADERS": bool, "PROTECT": (list, tuple),
    "EXEMPT": (list, tuple), "CORS_PREFLIGHT": str, "USER_RESOLVER": (str, type(None)),
    "AUDIT": (str, type(None), object),
    "CACHE": (dict, type(None)), "AUTH_SCHEME": str,
}

_lock = threading.RLock()
_manager: Any = None
_adapter: Any = None
_user_resolver: Any = None


def get_settings() -> Dict[str, Any]:
    user = getattr(settings, "SAFE_API_KEYS", None)
    if user is None:
        user = {}
    if not isinstance(user, dict):
        raise ImproperlyConfigured("SAFE_API_KEYS must be a dict")
    unknown = sorted(set(user) - set(DEFAULTS))
    if unknown:
        raise ImproperlyConfigured(f"SAFE_API_KEYS has unknown keys: {unknown}")
    merged = {**DEFAULTS, **user}
    merged["EXTRACT"] = {**DEFAULTS["EXTRACT"], **(user.get("EXTRACT") or {})}
    return merged


def validate_settings() -> Dict[str, Any]:
    """Type/shape validation (called from ``AppConfig.ready``). The pepper itself is checked lazily,
    so ``migrate`` works before the pepper environment variable is set."""
    cfg = get_settings()
    if cfg["PREFIX"] is None:
        raise ImproperlyConfigured("SAFE_API_KEYS['PREFIX'] is required (e.g. 'sk_live')")
    for key, types in _TYPES.items():
        if not isinstance(cfg[key], types):
            raise ImproperlyConfigured(f"SAFE_API_KEYS[{key!r}] has invalid type {type(cfg[key]).__name__}")
    try:
        from ...format import validate_prefix

        validate_prefix(cfg["PREFIX"])
        ExtractConfig.from_mapping(cfg["EXTRACT"])
        KeyPolicy.from_mapping(cfg["POLICY"])
        if cfg["TOUCH_INTERVAL"] is not None and cfg["TOUCH_INTERVAL"] < 0:
            raise ValueError("TOUCH_INTERVAL must be >= 0")
        if "." not in cfg["MODEL"]:
            raise ValueError("MODEL must be 'app_label.ModelName'")
        if cfg["CORS_PREFLIGHT"] not in ("authenticate", "respond"):
            raise ValueError("CORS_PREFLIGHT must be 'authenticate' or 'respond'")
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(f"SAFE_API_KEYS: {exc}") from exc
    return cfg


def _peppers(cfg: Dict[str, Any]) -> Dict[str, Any]:
    if cfg["PEPPERS"]:
        peppers = {str(k): (v.encode("utf-8") if isinstance(v, str) else v) for k, v in cfg["PEPPERS"].items()}
        return {"peppers": peppers, "current_pepper": cfg["CURRENT_PEPPER"]}
    if cfg["PEPPER_ENV"]:
        return pepper_kwargs_from_env(os.environ, pepper_env=cfg["PEPPER_ENV"])
    return {}


def _store(cfg: Dict[str, Any]) -> Any:
    spec = cfg["STORE"]
    if spec is None:
        from ...stores.django import DjangoStore

        return DjangoStore(cfg["MODEL"])
    if spec == "memory":
        from ...stores import MemoryStore

        return MemoryStore()
    if isinstance(spec, str) and "://" in spec:
        from ...stores import from_url

        return from_url(spec)
    if isinstance(spec, str):
        obj = import_string(spec)
        return obj() if callable(obj) else obj
    return spec


def _audit(cfg: Dict[str, Any]) -> Any:
    spec = cfg["AUDIT"]
    if spec is None:
        return None
    obj = import_string(spec) if isinstance(spec, str) else spec
    return obj() if isinstance(obj, type) else obj


def build_manager(cfg: Optional[Dict[str, Any]] = None) -> Any:
    from ...cache import VerifyCache
    from ...manager import KeyManager

    cfg = cfg or validate_settings()
    kwargs = _peppers(cfg)
    if not kwargs:
        raise ImproperlyConfigured(
            f"SAFE_API_KEYS: no pepper configured. Set the {cfg['PEPPER_ENV'] or 'SAFE_API_KEYS_PEPPER'} "
            "environment variable or SAFE_API_KEYS['PEPPERS'].")
    try:
        return KeyManager(
            _store(cfg), cfg["PREFIX"], policy=KeyPolicy.from_mapping(cfg["POLICY"]),
            touch_interval=cfg["TOUCH_INTERVAL"], audit=_audit(cfg), reveal_state=cfg["REVEAL_STATE"],
            cache=VerifyCache(**cfg["CACHE"]) if cfg["CACHE"] else None, **kwargs)
    except ConfigurationError as exc:
        raise ImproperlyConfigured(f"SAFE_API_KEYS: {exc}") from exc


def get_manager() -> Any:
    global _manager
    if _manager is None:
        with _lock:
            if _manager is None:
                _manager = build_manager()
    return _manager


def get_adapter() -> Any:
    """Adapter settings (extract/proxy/sunset) bound to the singleton manager."""
    global _adapter
    if _adapter is None:
        with _lock:
            if _adapter is None:
                from .._common import AdapterBase

                cfg = validate_settings()
                _adapter = AdapterBase(
                    None, extract=ExtractConfig.from_mapping(cfg["EXTRACT"]), trust_proxy=cfg["TRUST_PROXY"],
                    trusted_proxies=cfg["TRUSTED_PROXIES"], sunset_headers=cfg["SUNSET_HEADERS"],
                    auth_scheme=cfg["AUTH_SCHEME"])
    _adapter.km = get_manager()
    return _adapter


def lookup_user(owner: str) -> Any:
    """``USER_RESOLVER(owner)`` or ``None`` (no resolver configured, or it found nobody)."""
    global _user_resolver
    path = get_settings()["USER_RESOLVER"]
    if not path:
        return None
    if _user_resolver is None:
        _user_resolver = import_string(path)
    return _user_resolver(owner)


def resolve_user(owner: str) -> Any:
    """Like :func:`lookup_user` but falls back to ``AnonymousUser`` (what DRF puts in ``request.user``)."""
    user = lookup_user(owner)
    if user is None:
        from django.contrib.auth.models import AnonymousUser

        user = AnonymousUser()
    return user


def reset_manager() -> None:
    global _manager, _adapter, _user_resolver
    with _lock:
        if _manager is not None:
            try:
                _manager.close()
            except Exception:  # best effort on reset; never mask the caller
                logging.getLogger("safe_api_keys").debug("closing manager failed", exc_info=True)
        _manager = _adapter = _user_resolver = None


def _on_setting_changed(*, setting: str, **_: Any) -> None:
    if setting == "SAFE_API_KEYS":
        reset_manager()


def connect_signals() -> None:
    from django.test.signals import setting_changed

    setting_changed.connect(_on_setting_changed, dispatch_uid="safe_api_keys_setting_changed")
