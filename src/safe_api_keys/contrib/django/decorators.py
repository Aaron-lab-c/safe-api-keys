"""``@require_api_key`` and the request-level helpers shared by the middleware and DRF classes."""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Optional, Sequence

from django.http import HttpRequest, HttpResponse, JsonResponse

from ...exceptions import APIKeyError, MissingKey, StoreError
from ...extract import extract_key
from ...http import sunset_headers
from ...models import KeyRecord
from .conf import get_adapter

__all__ = ["require_api_key", "authenticate_request", "attach_user", "error_response_for", "apply_sunset",
           "client_ip_of"]

_USER_ATTR = "_safe_api_keys_user"


def client_ip_of(request: HttpRequest, adapter: Any = None) -> Optional[str]:
    adapter = adapter or get_adapter()
    ip: Optional[str] = adapter.client_ip(request.META.get("REMOTE_ADDR"), request.META.get("HTTP_X_FORWARDED_FOR"))
    return ip


def authenticate_request(request: HttpRequest, scopes: Optional[Sequence[str]] = None,
                         any_scopes: Optional[Sequence[str]] = None, *, optional: bool = False) -> Optional[KeyRecord]:
    """Verify (or, if middleware already did, scope-check) and set ``request.api_key``."""
    adapter = get_adapter()
    ip = client_ip_of(request, adapter)
    existing = getattr(request, "api_key", None)
    try:
        if isinstance(existing, KeyRecord):
            record: KeyRecord = adapter.km.authorize(existing, scopes=scopes, any_scopes=any_scopes, client_ip=ip)
        else:
            raw = extract_key(request.headers, request.GET, adapter.extract)
            if raw is None:
                if optional:
                    return None
                raise MissingKey()
            record = adapter.km.verify(raw, scopes=scopes, any_scopes=any_scopes, client_ip=ip)
    except (APIKeyError, StoreError) as exc:
        adapter.rejected(exc, ip)
        raise
    request.api_key = record  # type: ignore[attr-defined]
    if not isinstance(existing, KeyRecord):
        attach_user(request, record)
    return record


def attach_user(request: HttpRequest, record: KeyRecord) -> Any:
    """With ``USER_RESOLVER`` configured, make the key's owner the request's identity.

    ``request.user`` *and* ``request.auser()`` (Django 5 async views) are set to the resolved user, or to
    ``AnonymousUser`` when the resolver finds nobody, so a request authenticated by an API key never keeps a
    session user as a second identity. Without a resolver nothing is touched. The resolver result (or
    ``None``) is cached on the request so DRF does not look it up twice.
    """
    from .conf import get_settings, lookup_user

    if hasattr(request, _USER_ATTR):
        return getattr(request, _USER_ATTR)
    if not get_settings()["USER_RESOLVER"]:
        setattr(request, _USER_ATTR, None)
        return None
    user = lookup_user(record.owner)
    setattr(request, _USER_ATTR, user)
    if user is None:
        from django.contrib.auth.models import AnonymousUser

        identity: Any = AnonymousUser()
    else:
        identity = user
    request.user = identity

    async def auser() -> Any:
        return identity

    request.auser = auser  # type: ignore[attr-defined]
    return user


def error_response_for(exc: Any) -> JsonResponse:
    status, headers, body = get_adapter().format_error(exc)
    resp = JsonResponse(body, status=status)
    for k, v in headers.items():
        resp[k] = v
    return resp


def apply_sunset(response: HttpResponse, request: HttpRequest) -> HttpResponse:
    record = getattr(request, "api_key", None)
    if isinstance(record, KeyRecord) and get_adapter().sunset_headers:
        for k, v in sunset_headers(record).items():
            if not response.has_header(k):
                response[k] = v
    return response


def require_api_key(view: Optional[Callable[..., Any]] = None, *, scopes: Optional[Sequence[str]] = None,
                    any_scopes: Optional[Sequence[str]] = None) -> Any:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if asyncio.iscoroutinefunction(fn):
            from asgiref.sync import sync_to_async

            @functools.wraps(fn)
            async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
                try:
                    await sync_to_async(authenticate_request)(request, scopes, any_scopes)
                except (APIKeyError, StoreError) as exc:
                    return error_response_for(exc)
                return apply_sunset(await fn(request, *args, **kwargs), request)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            try:
                authenticate_request(request, scopes, any_scopes)
            except (APIKeyError, StoreError) as exc:
                return error_response_for(exc)
            return apply_sunset(fn(request, *args, **kwargs), request)
        return wrapper

    return decorator(view) if view is not None else decorator
