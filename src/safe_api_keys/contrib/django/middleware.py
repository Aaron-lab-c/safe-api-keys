"""``APIKeyMiddleware``: protect ``SAFE_API_KEYS['PROTECT']`` path prefixes (minus ``EXEMPT``).

Every method is authenticated, ``OPTIONS`` included: a view behind ``PROTECT`` must never run without a
valid key, whatever the method. CORS preflights carry no credentials; either answer them *before* this
middleware (``corsheaders.middleware.CorsMiddleware`` above it in ``MIDDLEWARE``, the default
``CORS_PREFLIGHT = "authenticate"``) or set ``CORS_PREFLIGHT = "respond"`` to have this middleware answer a
genuine preflight (``OPTIONS`` + ``Origin`` + ``Access-Control-Request-Method``) with an empty 204 itself,
without a key and without running the view. A CORS middleware *above* it still adds the CORS headers.
"""

from __future__ import annotations

from typing import Any, Callable

from django.http import HttpRequest, HttpResponse

from ...exceptions import APIKeyError, StoreError
from ...http import is_cors_preflight, path_matches
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
        if path_matches(request.path, cfg["PROTECT"]) and not path_matches(request.path, cfg["EXEMPT"]):
            if cfg["CORS_PREFLIGHT"] == "respond" and is_cors_preflight(request.method, request.headers):
                return HttpResponse(status=204)  # never the view: preflights cannot carry credentials
            try:
                authenticate_request(request)
            except (APIKeyError, StoreError) as exc:
                return error_response_for(exc)
        response = self.get_response(request)
        return apply_sunset(response, request)
