"""Django integration (§13.5).

Add ``"safe_api_keys.contrib.django"`` to ``INSTALLED_APPS`` and run ``python manage.py migrate``.
"""

from typing import Any, Callable, Optional, Sequence

__all__ = ["get_manager", "require_api_key", "reset_manager"]


def get_manager() -> Any:
    """Singleton :class:`~safe_api_keys.KeyManager` built from ``settings.SAFE_API_KEYS``."""
    from .conf import get_manager as _get

    return _get()


def reset_manager() -> None:
    from .conf import reset_manager as _reset

    _reset()


def require_api_key(view: Optional[Callable[..., Any]] = None, *, scopes: Optional[Sequence[str]] = None,
                    any_scopes: Optional[Sequence[str]] = None) -> Any:
    """View decorator; sets ``request.api_key``. Usable bare or with ``scopes=``/``any_scopes=``."""
    from .decorators import require_api_key as _dec

    return _dec(view, scopes=scopes, any_scopes=any_scopes)
