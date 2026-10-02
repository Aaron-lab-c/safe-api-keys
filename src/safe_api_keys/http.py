"""Framework-neutral HTTP helpers: error responses (§7.2, §13.2), sunset headers, client IP (§7.3)."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from ._logic import _parse_network, normalize_ip
from ._util import rfc1123
from .exceptions import APIKeyError, InsufficientScope, StoreError
from .models import KeyRecord

__all__ = [
    "ErrorResponse",
    "ErrorFormatter",
    "error_response",
    "sunset_headers",
    "resolve_client_ip",
    "TrustedProxies",
    "path_matches",
]

ErrorResponse = Tuple[int, Dict[str, str], Dict[str, Any]]
ErrorFormatter = Callable[[BaseException], ErrorResponse]


def error_response(exc: Union[APIKeyError, StoreError], *, scheme: str = "Bearer",
                   realm: str = "api") -> ErrorResponse:
    """Map an exception to ``(status, headers, json_body)``."""
    status = int(getattr(exc, "status_code", 401))
    code = str(getattr(exc, "error_code", "invalid_api_key"))
    message = str(getattr(exc, "public_message", "Invalid API key"))
    headers = {"Cache-Control": "no-store"}
    if status == 401:
        if scheme.lower() == "bearer":
            headers["WWW-Authenticate"] = f'Bearer realm="{realm}", error="invalid_token"'
        else:
            headers["WWW-Authenticate"] = f'{scheme} realm="{realm}"'
    body: Dict[str, Any] = {"error": code, "message": message}
    if isinstance(exc, InsufficientScope):
        body["required"] = list(exc.required)
        body["missing"] = list(exc.missing)
    return status, headers, body


def sunset_headers(record: Optional[KeyRecord]) -> Dict[str, str]:
    """``Deprecation``/``Sunset`` headers for a key that has been rotated (§10)."""
    if record is None or not record.rotated_to:
        return {}
    headers = {"Deprecation": "true"}
    if record.expires_at is not None:
        headers["Sunset"] = rfc1123(record.expires_at)
    return headers


class TrustedProxies:
    def __init__(self, proxies: Iterable[str] = ()) -> None:
        self.networks = [_parse_network(p) for p in proxies]

    def __bool__(self) -> bool:
        return bool(self.networks)

    def __contains__(self, ip: str) -> bool:
        try:
            addr = normalize_ip(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.networks)


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(normalize_ip(value))
    except ValueError:
        return None


def resolve_client_ip(remote_addr: Optional[str], forwarded_for: Optional[str] = None, *,
                      trust_proxy: bool = False, trusted_proxies: Sequence[str] = ()) -> Optional[str]:
    """Resolve the client IP.

    Default: the direct peer address; ``X-Forwarded-For`` is ignored (S10).

    With ``trust_proxy=True`` or ``trusted_proxies``, the chain ``XFF + [peer]`` is walked from
    the right, skipping trusted hops, and the first untrusted address is returned. That is the
    left-most address that was appended by infrastructure we trust; anything further left was
    supplied by the client and could be forged (taking the literal left-most XFF entry would let
    a client spoof an allow-listed IP). ``trust_proxy=True`` without a list trusts exactly one
    hop: the direct peer.
    """
    peer = _valid_ip(remote_addr) if remote_addr else None
    if not (trust_proxy or trusted_proxies) or not forwarded_for:
        return peer
    trusted = TrustedProxies(trusted_proxies)
    if trusted and (peer is None or peer not in trusted):
        return peer  # the request didn't come through a trusted proxy
    hops: List[str] = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        ip = _valid_ip(hop)
        if ip is None:
            return peer
        if trusted and ip in trusted:
            continue
        return ip
    return _valid_ip(hops[0]) if hops else peer


def path_matches(path: str, prefixes: Iterable[str]) -> bool:
    for p in prefixes:
        if not p:
            continue
        if path == p or path.startswith(p if p.endswith("/") else p + "/") or (p.endswith("/") and path == p[:-1]):
            return True
    return False

