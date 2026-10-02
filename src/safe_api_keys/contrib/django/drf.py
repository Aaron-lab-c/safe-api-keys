"""Django REST framework integration.

    class OrdersView(APIView):
        authentication_classes = [APIKeyAuthentication]
        permission_classes = [HasAPIKeyScope("orders:read")]

``request.auth`` is the :class:`KeyRecord`; ``request.user`` comes from ``SAFE_API_KEYS['USER_RESOLVER']``
(``AnonymousUser`` by default). For ``Cache-Control: no-store`` on DRF's error responses, set
``REST_FRAMEWORK["EXCEPTION_HANDLER"] = "safe_api_keys.contrib.django.drf.exception_handler"``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ...exceptions import APIKeyError, MissingDependency, MissingKey, StoreError
from ...models import KeyRecord

try:
    from rest_framework import exceptions as drf_exceptions
    from rest_framework.authentication import BaseAuthentication
    from rest_framework.permissions import BasePermission
    from rest_framework.views import exception_handler as drf_exception_handler
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[drf]") from exc

from .conf import get_adapter, resolve_user
from .decorators import authenticate_request

__all__ = ["APIKeyAuthentication", "HasAPIKey", "HasAPIKeyScope", "HasAnyAPIKeyScope", "APIKeyFailed",
           "exception_handler"]


class APIKeyFailed(drf_exceptions.APIException):
    """Carries the §13.2 body/headers through DRF's exception handling."""

    def __init__(self, error: BaseException) -> None:
        status, headers, body = get_adapter().format_error(error)
        self.status_code = status
        self.error = error
        self.extra_headers: Dict[str, str] = headers
        self.auth_header = headers.get("WWW-Authenticate")  # picked up by DRF's default handler
        super().__init__(detail=body)


def _wrap(exc: BaseException) -> APIKeyFailed:
    return APIKeyFailed(exc)


class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request: Any) -> Optional[Tuple[Any, KeyRecord]]:
        django_request = request._request
        try:
            record = authenticate_request(django_request, optional=True)
        except (APIKeyError, StoreError) as exc:
            raise _wrap(exc) from None
        if record is None:
            return None  # let other authenticators try; permissions decide
        return resolve_user(record.owner), record

    def authenticate_header(self, request: Any) -> str:
        adapter = get_adapter()
        if adapter.auth_scheme.lower() == "bearer":
            return f'Bearer realm="{adapter.realm}"'
        return f'{adapter.auth_scheme} realm="{adapter.realm}"'


_ERR_ATTR = "_safe_api_keys_error"


def _remember(request: Any, error: APIKeyError) -> None:
    setattr(getattr(request, "_request", request), _ERR_ATTR, error)


class HasAPIKey(BasePermission):
    """Requires a verified API key (and optionally scopes).

    Returns ``False`` rather than raising, so DRF composition (``|``, ``&``, ``~``) works; DRF then raises
    ``NotAuthenticated`` (401) / ``PermissionDenied`` (403) and :func:`exception_handler` renders the
    §13.2 body for the recorded reason.
    """

    required: Tuple[str, ...] = ()
    any_required: Tuple[str, ...] = ()
    message = MissingKey.public_message

    def has_permission(self, request: Any, view: Any) -> bool:
        record = getattr(request, "auth", None)
        if not isinstance(record, KeyRecord):
            _remember(request, MissingKey())
            return False
        if self.required or self.any_required:
            try:
                get_adapter().km.authorize(record, scopes=self.required or None,
                                           any_scopes=self.any_required or None)
            except APIKeyError as exc:
                _remember(request, exc)
                self.message = exc.public_message
                return False
        return True


def HasAPIKeyScope(*scopes: str) -> type:  # noqa: N802 - reads like a class in permission_classes
    """Permission class requiring *all* of ``scopes``."""
    return type("HasAPIKeyScope", (HasAPIKey,), {"required": tuple(scopes)})


def HasAnyAPIKeyScope(*scopes: str) -> type:  # noqa: N802
    """Permission class requiring *at least one* of ``scopes``."""
    return type("HasAnyAPIKeyScope", (HasAPIKey,), {"any_required": tuple(scopes)})


def exception_handler(exc: Exception, context: Dict[str, Any]) -> Any:
    """``REST_FRAMEWORK["EXCEPTION_HANDLER"]``: §13.2 bodies/headers for API key failures."""
    response = drf_exception_handler(exc, context)
    if response is None:
        return None
    error: Optional[BaseException] = exc.error if isinstance(exc, APIKeyFailed) else None
    if error is None and isinstance(exc, (drf_exceptions.NotAuthenticated, drf_exceptions.PermissionDenied)):
        request = context.get("request")
        error = getattr(getattr(request, "_request", request), _ERR_ATTR, None)
    if error is not None:
        status, headers, body = get_adapter().format_error(error)
        response.status_code = status
        response.data = body
        for k, v in headers.items():
            response[k] = v
    elif response.status_code in (401, 403):
        response["Cache-Control"] = "no-store"
    return response
