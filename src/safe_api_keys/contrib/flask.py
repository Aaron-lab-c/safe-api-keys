"""Flask adapter (§13.4).

    keys = APIKeys(km); keys.init_app(app)

    @app.get("/orders")
    @keys.required(scopes=["orders:read"])
    def orders(): return {"owner": g.api_key.owner}
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional, Sequence, TypeVar, cast

from ..exceptions import APIKeyError, MissingDependency, MissingKey, StoreError
from ..extract import ExtractConfig, extract_key
from ..http import ErrorFormatter, is_cors_preflight, path_matches, sunset_headers
from ..models import KeyRecord
from ._common import AdapterBase, OnRejected

try:
    from flask import Flask, current_app, g, jsonify, request
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[flask]") from exc

__all__ = ["APIKeys"]

F = TypeVar("F", bound=Callable[..., Any])
_EXT = "safe_api_keys"


class APIKeys(AdapterBase):
    def __init__(
        self,
        km: Any = None,
        app: Optional[Flask] = None,
        *,
        extract: Optional[ExtractConfig] = None,
        trust_proxy: bool = False,
        trusted_proxies: Sequence[str] = (),
        error_formatter: Optional[ErrorFormatter] = None,
        sunset_headers: bool = True,
        on_rejected: Optional[OnRejected] = None,
        auth_scheme: str = "Bearer",
    ) -> None:
        super().__init__(km, extract=extract, trust_proxy=trust_proxy, trusted_proxies=trusted_proxies,
                         error_formatter=error_formatter, sunset_headers=sunset_headers,
                         on_rejected=on_rejected, auth_scheme=auth_scheme)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask, km: Any = None) -> None:
        if km is not None:
            self.km = km
        app.extensions[_EXT] = self
        app.register_error_handler(APIKeyError, self._handle_error)
        app.register_error_handler(StoreError, self._handle_error)
        app.after_request(self._after_request)

    # -- internals ---------------------------------------------------------------------
    @property
    def manager(self) -> Any:
        if self.km is None:
            raise RuntimeError("APIKeys has no KeyManager; pass one to APIKeys(km) or init_app(app, km)")
        return self.km

    def _client_ip(self) -> Optional[str]:
        return self.client_ip(request.remote_addr, request.headers.get("X-Forwarded-For"))

    def _handle_error(self, exc: Exception) -> Any:
        status, headers, body = self.format_error(cast(Any, exc))
        resp = jsonify(body)
        resp.status_code = status
        for k, v in headers.items():
            resp.headers[k] = v
        return resp

    def _after_request(self, response: Any) -> Any:
        record = g.get("api_key")
        if self.sunset_headers and isinstance(record, KeyRecord):
            for k, v in sunset_headers(record).items():
                response.headers.setdefault(k, v)
        return response

    def authenticate(self, scopes: Optional[Sequence[str]] = None,
                     any_scopes: Optional[Sequence[str]] = None) -> KeyRecord:
        """Verify the current request (or re-check scopes if already verified); sets ``g.api_key``."""
        ip = self._client_ip()
        existing = g.get("api_key")
        try:
            if isinstance(existing, KeyRecord):
                record: KeyRecord = self.manager.authorize(existing, scopes=scopes, any_scopes=any_scopes,
                                                           client_ip=ip)
            else:
                raw = extract_key(request.headers, request.args, self.extract)
                if raw is None:
                    raise MissingKey()
                record = self.manager.verify(raw, scopes=scopes, any_scopes=any_scopes, client_ip=ip)
        except (APIKeyError, StoreError) as exc:
            self.rejected(exc, ip)
            raise
        g.api_key = record
        return record

    # -- public decorators -------------------------------------------------------------
    def required(self, fn: Optional[F] = None, *, scopes: Optional[Sequence[str]] = None,
                 any_scopes: Optional[Sequence[str]] = None) -> Any:
        """``@keys.required`` or ``@keys.required(scopes=[...], any_scopes=[...])``."""

        def decorator(view: F) -> F:
            @functools.wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                self.authenticate(scopes, any_scopes)
                return current_app.ensure_sync(view)(*args, **kwargs)
            return cast(F, wrapper)

        return decorator(fn) if fn is not None else decorator

    def protect_blueprint(self, bp: Any, *, scopes: Optional[Sequence[str]] = None,
                          any_scopes: Optional[Sequence[str]] = None, exempt: Sequence[str] = ()) -> None:
        """Require a valid key for every request routed to ``bp`` (except ``exempt`` paths/endpoints)."""
        exempt_paths = tuple(e for e in exempt if e.startswith("/"))
        exempt_endpoints = {e for e in exempt if not e.startswith("/")}

        def guard() -> Any:
            if request.endpoint in exempt_endpoints or path_matches(request.path, exempt_paths):
                return None
            if is_cors_preflight(request.method, request.headers):
                # CORS preflight: browsers send it without credentials, so it cannot carry a key. Answer it
                # with Flask's standard OPTIONS response (Flask-CORS decorates it) *without* running the view.
                return current_app.make_default_options_response()
            self.authenticate(scopes, any_scopes)  # every other method, plain OPTIONS included
            return None

        bp.before_request(guard)
