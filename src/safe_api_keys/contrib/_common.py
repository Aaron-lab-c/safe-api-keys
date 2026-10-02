"""Shared plumbing for HTTP adapters: config, error formatting, client IP, on_rejected hook."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Sequence, Union

from ..exceptions import APIKeyError, StoreError
from ..extract import ExtractConfig
from ..http import ErrorFormatter, ErrorResponse, error_response, resolve_client_ip

__all__ = ["AdapterBase", "OnRejected"]

_log = logging.getLogger("safe_api_keys")
OnRejected = Callable[[Optional[str], Optional[str]], Any]


class AdapterBase:
    def __init__(
        self,
        km: Any = None,
        *,
        extract: Optional[ExtractConfig] = None,
        trust_proxy: bool = False,
        trusted_proxies: Sequence[str] = (),
        error_formatter: Optional[ErrorFormatter] = None,
        sunset_headers: bool = True,
        on_rejected: Optional[OnRejected] = None,
        auth_scheme: str = "Bearer",
        realm: str = "api",
    ) -> None:
        self.km = km
        self.extract = extract or ExtractConfig()
        self.trust_proxy = trust_proxy
        self.trusted_proxies = tuple(trusted_proxies)
        self.error_formatter = error_formatter
        self.sunset_headers = sunset_headers
        self.on_rejected = on_rejected
        self.auth_scheme = auth_scheme
        self.realm = realm

    @property
    def is_async(self) -> bool:
        from ..amanager import AsyncKeyVerifier

        return isinstance(self.km, AsyncKeyVerifier)

    def format_error(self, exc: Union[APIKeyError, StoreError]) -> ErrorResponse:
        if self.error_formatter is not None:
            return self.error_formatter(exc)
        return error_response(exc, scheme=self.auth_scheme, realm=self.realm)

    def client_ip(self, remote_addr: Optional[str], forwarded_for: Optional[str]) -> Optional[str]:
        return resolve_client_ip(remote_addr, forwarded_for, trust_proxy=self.trust_proxy,
                                 trusted_proxies=self.trusted_proxies)

    def rejected(self, exc: BaseException, client_ip: Optional[str]) -> None:
        """S13: failure counting hook for external rate limiting. Never raises."""
        if isinstance(exc, APIKeyError):
            _log.info("API key rejected: error=%s reason=%s key_id=%s", exc.error_code, exc.reason, exc.key_id)
        if self.on_rejected is None or not isinstance(exc, APIKeyError):
            return
        try:
            self.on_rejected(client_ip, exc.key_id)
        except Exception:
            _log.exception("on_rejected hook failed")
