"""FastAPI adapter (§13.3).

    auth = APIKeyAuth(km)
    auth.install(app)            # JSON error bodies per §13.2 (see note below)

    @app.get("/orders")
    def orders(key: KeyRecord = Depends(auth.scopes("orders:read"))): ...

The schemes are registered via FastAPI's own ``HTTPBearer``/``APIKeyHeader``/``APIKeyQuery`` so
OpenAPI shows ``securitySchemes`` and per-operation ``security`` (with the required scopes).

Without ``install(app)`` failures still get the right status code and headers, but FastAPI's
default handler renders the body as ``{"detail": "<message>"}``.
"""

from __future__ import annotations

import inspect
from typing import Any, List, Optional, Sequence

from ..exceptions import APIKeyError, MissingDependency, MissingKey, StoreError
from ..extract import ExtractConfig, extract_key
from ..http import ErrorFormatter, sunset_headers
from ..models import KeyRecord
from ._common import AdapterBase, OnRejected

try:
    from fastapi import HTTPException, Request, Response, Security
    from fastapi.responses import JSONResponse
    from fastapi.security import APIKeyHeader, APIKeyQuery, HTTPBearer
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[fastapi]") from exc

from .starlette import APIKeyMiddleware, verify_with

__all__ = ["APIKeyAuth", "APIKeyMiddleware", "APIKeyHTTPException", "api_key_exception_handler",
           "install_exception_handlers"]


class APIKeyHTTPException(HTTPException):
    """Carries the formatted error. Subclasses HTTPException so it degrades gracefully."""

    def __init__(self, status_code: int, headers: dict, body: dict, error: BaseException) -> None:
        super().__init__(status_code=status_code, detail=body.get("message", ""), headers=headers)
        self.body = body
        self.error = error


async def api_key_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, APIKeyHTTPException):  # pragma: no cover - only registered for that type
        raise exc
    return JSONResponse(exc.body, status_code=exc.status_code, headers=exc.headers)


def install_exception_handlers(app: Any) -> None:
    app.add_exception_handler(APIKeyHTTPException, api_key_exception_handler)


class _Dependency:
    def __init__(self, auth: APIKeyAuth, scopes: Sequence[str], any_scopes: Sequence[str], optional: bool) -> None:
        self.auth = auth
        self.required = tuple(scopes)
        self.any_required = tuple(any_scopes)
        self.optional = optional
        sec_scopes = list(self.required) + [s for s in self.any_required if s not in self.required]
        params = [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            inspect.Parameter("response", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Response),
        ]
        for i, scheme in enumerate(auth._schemes):
            params.append(inspect.Parameter(f"_safe_api_keys_scheme_{i}", inspect.Parameter.KEYWORD_ONLY,
                                            default=Security(scheme, scopes=sec_scopes), annotation=Any))
        self.__signature__ = inspect.Signature(params)

    async def __call__(self, request: Request, response: Response, **_: Any) -> Optional[KeyRecord]:
        return await self.auth._authenticate(request, response, self.required, self.any_required, self.optional)


class APIKeyAuth(AdapterBase):
    def __init__(
        self,
        km_or_verifier: Any,
        *,
        extract: Optional[ExtractConfig] = None,
        scheme_name: str = "ApiKeyAuth",
        auto_error: bool = True,
        trust_proxy: bool = False,
        trusted_proxies: Sequence[str] = (),
        error_formatter: Optional[ErrorFormatter] = None,
        sunset_headers: bool = True,
        on_rejected: Optional[OnRejected] = None,
        auth_scheme: str = "Bearer",
        app: Any = None,
    ) -> None:
        super().__init__(km_or_verifier, extract=extract, trust_proxy=trust_proxy,
                         trusted_proxies=trusted_proxies, error_formatter=error_formatter,
                         sunset_headers=sunset_headers, on_rejected=on_rejected, auth_scheme=auth_scheme)
        self.scheme_name = scheme_name
        self.auto_error = auto_error
        self._schemes: List[Any] = []
        cfg = self.extract
        for source in cfg.order:
            if source == "header" and cfg.header:
                self._schemes.append(APIKeyHeader(name=cfg.header, scheme_name=scheme_name, auto_error=False))
            elif source == "bearer" and cfg.bearer:
                self._schemes.append(HTTPBearer(scheme_name=f"{scheme_name}Bearer", auto_error=False))
            elif source == "query" and cfg.query_param:
                self._schemes.append(APIKeyQuery(name=cfg.query_param, scheme_name=f"{scheme_name}Query",
                                                 auto_error=False))
        self._default = _Dependency(self, (), (), False)
        self.__signature__ = self._default.__signature__
        if app is not None:
            self.install(app)

    def install(self, app: Any) -> APIKeyAuth:
        install_exception_handlers(app)
        return self

    # -- dependency factories -------------------------------------------------------
    async def __call__(self, request: Request, response: Response, **_: Any) -> Optional[KeyRecord]:
        return await self._default(request, response)

    def scopes(self, *scopes: str) -> _Dependency:
        return _Dependency(self, scopes, (), False)

    def any_scopes(self, *scopes: str) -> _Dependency:
        return _Dependency(self, (), scopes, False)

    def optional(self, *, scopes: Sequence[str] = (), any_scopes: Sequence[str] = ()) -> _Dependency:
        return _Dependency(self, scopes, any_scopes, True)

    def require(self, *, scopes: Sequence[str] = (), any_scopes: Sequence[str] = ()) -> _Dependency:
        return _Dependency(self, scopes, any_scopes, False)

    # -- core -----------------------------------------------------------------------------
    def _http_error(self, exc: Any) -> APIKeyHTTPException:
        status, headers, body = self.format_error(exc)
        return APIKeyHTTPException(status, headers, body, exc)

    async def _authenticate(self, request: Request, response: Response, scopes: Sequence[str],
                            any_scopes: Sequence[str], optional: bool) -> Optional[KeyRecord]:
        client = request.client
        ip = self.client_ip(client.host if client else None, request.headers.get("x-forwarded-for"))
        existing = getattr(request.state, "api_key", None)
        try:
            if isinstance(existing, KeyRecord):  # already verified by APIKeyMiddleware
                record = self.km.authorize(existing, scopes=scopes, any_scopes=any_scopes, client_ip=ip)
            else:
                raw = extract_key(request.headers, request.query_params, self.extract)
                if raw is None:
                    if optional:
                        return None
                    raise MissingKey()
                record = await verify_with(self, raw, scopes=scopes or None, any_scopes=any_scopes or None,
                                           client_ip=ip)
        except (APIKeyError, StoreError) as exc:
            self.rejected(exc, ip)
            if not self.auto_error and isinstance(exc, APIKeyError):
                return None
            raise self._http_error(exc) from None
        request.state.api_key = record
        if self.sunset_headers:
            for k, v in sunset_headers(record).items():
                response.headers[k] = v
        return record
