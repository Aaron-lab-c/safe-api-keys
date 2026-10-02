"""``APIKeyMiddleware``: protect ``SAFE_API_KEYS['PROTECT']`` path prefixes (minus ``EXEMPT``)."""

from __future__ import annotations

from typing import Any, Callable

from django.http import HttpRequest, HttpResponse

from ...exceptions import APIKeyError, StoreError
from ...http import path_matches
from .conf import get_settings
from .decorators import apply_sunset, authenticate_request, error_response_for

__all__ = ["APIKeyMiddleware"]


class APIKeyMiddleware:
    sync_capable = True
    async_capable = False

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> Any:
        cfg = get_settings()
        if request.method != "OPTIONS" and path_matches(request.path, cfg["PROTECT"]) \
                and not path_matches(request.path, cfg["EXEMPT"]):
            try:
                authenticate_request(request)
            except (APIKeyError, StoreError) as exc:
                return error_response_for(exc)
        response = self.get_response(request)
        return apply_sunset(response, request)
