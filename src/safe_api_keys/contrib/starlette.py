"""Starlette adapter: a pure-ASGI :class:`APIKeyMiddleware` (also used by the FastAPI adapter)."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, MutableMapping, Optional, Sequence

from ..exceptions import APIKeyError, MissingDependency, MissingKey, StoreError
from ..extract import ExtractConfig, extract_key
from ..http import ErrorFormatter, path_matches, sunset_headers
from ..models import KeyRecord
from ._common import AdapterBase, OnRejected

try:
    from starlette.concurrency import run_in_threadpool
    from starlette.datastructures import Headers, MutableHeaders, QueryParams
    from starlette.responses import JSONResponse
except ImportError as exc:  # pragma: no cover - depends on extras
    raise MissingDependency("pip install safe-api-keys[starlette]") from exc

__all__ = ["APIKeyMiddleware", "verify_with", "json_error_response"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


async def verify_with(adapter: AdapterBase, raw: str, *, scopes: Optional[Sequence[str]] = None,
                      any_scopes: Optional[Sequence[str]] = None, client_ip: Optional[str] = None) -> KeyRecord:
    """Await an async manager, or run a sync manager in the threadpool."""
    if adapter.is_async:
        record: KeyRecord = await adapter.km.verify(raw, scopes=scopes, any_scopes=any_scopes, client_ip=client_ip)
        return record
    return await run_in_threadpool(adapter.km.verify, raw, scopes=scopes, any_scopes=any_scopes,
                                   client_ip=client_ip)


def json_error_response(adapter: AdapterBase, exc: Any) -> JSONResponse:
    status, headers, body = adapter.format_error(exc)
    return JSONResponse(body, status_code=status, headers=headers)


def client_ip_from_scope(adapter: AdapterBase, scope: Scope, headers: Headers) -> Optional[str]:
    client = scope.get("client")
    return adapter.client_ip(client[0] if client else None, headers.get("x-forwarded-for"))


class APIKeyMiddleware(AdapterBase):
    """Protect path prefixes. Sets ``request.state.api_key`` on success, responds directly on failure.

    app.add_middleware(APIKeyMiddleware, km=km, protect=("/api/",), exempt=("/api/health",))
    """

    def __init__(
        self,
        app: Any,
        km: Any,
        *,
        protect: Sequence[str] = ("/api/",),
        exempt: Sequence[str] = ("/api/health",),
        scopes: Optional[Sequence[str]] = None,
        any_scopes: Optional[Sequence[str]] = None,
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
        self.app = app
        self.protect = tuple(protect)
        self.exempt = tuple(exempt)
        self.scopes = scopes
        self.any_scopes = any_scopes

    def _protected(self, path: str) -> bool:
        return path_matches(path, self.protect) and not path_matches(path, self.exempt)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._protected(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        ip = client_ip_from_scope(self, scope, headers)
        try:
            raw = extract_key(headers, QueryParams(scope.get("query_string", b"")), self.extract)
            if raw is None:
                raise MissingKey()
            record = await verify_with(self, raw, scopes=self.scopes, any_scopes=self.any_scopes, client_ip=ip)
        except (APIKeyError, StoreError) as exc:
            self.rejected(exc, ip)
            await json_error_response(self, exc)(scope, receive, send)
            return
        scope.setdefault("state", {})["api_key"] = record
        extra: Dict[str, str] = sunset_headers(record) if self.sunset_headers else {}
        if not extra:
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                for k, v in extra.items():
                    h[k] = v
            await send(message)

        await self.app(scope, receive, send_with_headers)
