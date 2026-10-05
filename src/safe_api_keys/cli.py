"""``safe-api-keys`` command line tool (§14).

Exit codes: 0 success, 1 verification failed / not found, 2 bad arguments or configuration, 3 store error.
Only ``issue``/``rotate`` ever print a raw key (once); everything else is masked.

``verify`` and ``parse`` read the raw key from **stdin** when it is omitted (or given as ``-``): a key on the
command line is visible to every user on the host (``ps``) and lands in the shell history.
"""

from __future__ import annotations

import argparse
import getpass
import io
import json
import os
import sys
import warnings
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, TextIO

from ._util import parse_datetime, parse_duration, utcnow
from .env import STORE_ENV, pepper_kwargs_from_env
from .exceptions import (
    APIKeyError,
    ConfigurationError,
    MissingDependency,
    NotSupported,
    PolicyViolation,
    StoreError,
)
from .format import parse_key
from .models import KeyRecord

__all__ = ["main", "build_parser", "add_commands", "execute", "EXIT_OK", "EXIT_FAIL", "EXIT_USAGE", "EXIT_STORE"]

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_STORE = 0, 1, 2, 3
SAVE_WARNING = "Store this key now: it will not be shown again. (請立刻保存，不會再顯示)"
RAW_KEY_HELP = ("raw key; omit it or pass '-' to read it from stdin (recommended: an argument shows up in "
                "`ps` and the shell history)")
_NO_STORE = ("parse",)
_NEEDS_PEPPER = ("issue", "verify", "rotate")


class UsageError(Exception):
    pass


def _expiry(value: Optional[str], now: datetime) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        return {"expires_in": parse_duration(value)}
    except ValueError:
        pass
    try:
        return {"expires_at": parse_datetime(value)}
    except ValueError:
        raise UsageError(f"invalid --expires {value!r}: use 90d / 24h or an ISO-8601 timestamp") from None


def _meta(items: Optional[Sequence[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or ():
        k, sep, v = item.partition("=")
        if not sep or not k:
            raise UsageError(f"invalid --meta {item!r}: expected key=value")
        out[k] = v
    return out


def _split(values: Optional[Sequence[str]]) -> List[str]:
    out: List[str] = []
    for v in values or ():
        out.extend(p for p in v.replace(",", " ").split() if p)
    return out


def _row(r: KeyRecord) -> str:
    exp = r.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.expires_at else "-"
    used = r.last_used_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.last_used_at else "-"
    return "\t".join([r.key_id, r.masked, r.owner, r.name or "-", ",".join(r.scopes) or "-", r.state(), exp, used])


# --------------------------------------------------------------------------- parser
def add_commands(sub: Any, *, standalone: bool = True) -> None:
    def common(p: argparse.ArgumentParser, *, prefix: bool) -> None:
        if not standalone:
            return
        p.add_argument("--store", default=os.environ.get(STORE_ENV),
                       help=f"store URL (default: ${STORE_ENV}); memory://, sqlite:///path, redis://, sqlalchemy+...")
        if prefix:
            p.add_argument("--prefix", required=True, help="key prefix, e.g. sk_live")
        p.add_argument("--pepper-env", default="SAFE_API_KEYS_PEPPER", help="env var holding the pepper")

    p = sub.add_parser("issue", help="issue a new key (prints the raw key once)")
    common(p, prefix=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--scopes", nargs="*", default=[])
    p.add_argument("--expires", help="90d, 24h ... or ISO-8601 timestamp")
    p.add_argument("--name", default="")
    p.add_argument("--ip", nargs="*", default=[], help="allowed IP/CIDR")
    p.add_argument("--meta", nargs="*", default=[], help="metadata key=value")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("verify", help="verify a raw key (exit 0 valid / 1 invalid); reads stdin by default")
    common(p, prefix=True)
    p.add_argument("raw_key", nargs="?", default=None, help=RAW_KEY_HELP)
    p.add_argument("--scopes", nargs="*", default=[])
    p.add_argument("--ip", default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("revoke", help="revoke a key")
    common(p, prefix=False)
    p.add_argument("key_id")
    p.add_argument("--reason", default=None)

    p = sub.add_parser("rotate", help="rotate a key (prints the new raw key once)")
    common(p, prefix=True)
    p.add_argument("key_id")
    p.add_argument("--grace", default="24h")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("list", help="list keys")
    common(p, prefix=False)
    p.add_argument("--owner", default=None)
    p.add_argument("--all", action="store_true", help="include revoked/expired")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("purge", help="delete revoked/expired keys older than a duration")
    common(p, prefix=False)
    p.add_argument("--older-than", required=True)

    if standalone:
        p = sub.add_parser("parse", help="parse a raw key without touching any store; reads stdin by default")
        p.add_argument("raw_key", nargs="?", default=None, help=RAW_KEY_HELP)
        p.add_argument("--json", action="store_true")


def build_parser(prog: str = "safe-api-keys") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Manage API keys (safe-api-keys).")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    add_commands(sub, standalone=True)
    return parser


# --------------------------------------------------------------------------- execution
def _raw_key(args: argparse.Namespace, stdin: Optional[TextIO], err: TextIO) -> str:
    """The raw key argument, or (when omitted / ``-``) one line from stdin — without echo on a terminal."""
    value = getattr(args, "raw_key", None)
    if value is not None and value != "-":
        return str(value)
    stream = sys.stdin if stdin is None else stdin
    if stream is None:
        raise UsageError("no raw key: pass it on stdin")
    if getattr(stream, "isatty", lambda: False)():
        return getpass.getpass("API key: ", stream=err)
    line = stream.readline()
    if not line:
        raise UsageError("no raw key: pass it on stdin (or as an argument)")
    return line.strip()


def _manager_from_args(args: argparse.Namespace) -> Any:
    from .manager import KeyManager
    from .policy import KeyPolicy
    from .stores import from_url

    if not args.store:
        raise UsageError(f"--store is required (or set ${STORE_ENV})")
    kwargs = pepper_kwargs_from_env(pepper_env=args.pepper_env)
    if not kwargs and args.command in _NEEDS_PEPPER:
        raise UsageError(f"no pepper: set ${args.pepper_env} (or SAFE_API_KEYS_PEPPERS)")
    if not kwargs:
        kwargs["policy"] = KeyPolicy(require_pepper=False)
    prefix = getattr(args, "prefix", None) or "cli"
    store = from_url(args.store)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return KeyManager(store, prefix, **kwargs)


def execute(args: argparse.Namespace, km_factory: Callable[[argparse.Namespace], Any],
            out: TextIO, err: TextIO, stdin: Optional[TextIO] = None) -> int:
    def say(text: str = "") -> None:
        out.write(text + "\n")

    def dump(obj: Any) -> None:
        say(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))

    cmd = args.command
    try:
        if cmd == "parse":
            p = parse_key(_raw_key(args, stdin, err), strict_checksum=False)
            info = {"prefix": p.prefix, "key_id": p.key_id, "masked": p.masked, "checksum_ok": p.checksum_ok}
            if args.json:
                dump(info)
            else:
                for k, v in info.items():
                    say(f"{k}: {v}")
            return EXIT_OK if p.checksum_ok else EXIT_FAIL

        km = km_factory(args)
        if cmd == "issue":
            now = utcnow()
            issued = km.issue(args.owner, scopes=_split(args.scopes), name=args.name, ip_allowlist=_split(args.ip),
                              metadata=_meta(args.meta), **_expiry(args.expires, now))
            err.write(SAVE_WARNING + "\n")
            if args.json:
                dump({"raw_key": issued.raw_key, "key": issued.record.to_dict()})
            else:
                say(issued.raw_key)
                err.write(f"key_id={issued.record.key_id} masked={issued.record.masked}\n")
            return EXIT_OK

        if cmd == "verify":
            raw = _raw_key(args, stdin, err)
            try:
                rec = km.verify(raw, scopes=_split(args.scopes) or None, client_ip=args.ip, touch=False)
            except APIKeyError as exc:
                if args.json:
                    dump({"ok": False, "error": exc.error_code, "reason": exc.reason, "key_id": exc.key_id})
                else:
                    say(f"invalid: {exc.error_code} ({exc.reason})")
                return EXIT_FAIL
            if args.json:
                dump({"ok": True, "key": rec.to_dict()})
            else:
                say(f"valid: {rec.masked} owner={rec.owner} scopes={','.join(rec.scopes) or '-'} state={rec.state()}")
            return EXIT_OK

        if cmd == "revoke":
            rec = km.revoke(args.key_id, reason=args.reason)
            say(f"revoked: {rec.masked}")
            return EXIT_OK

        if cmd == "rotate":
            issued = km.rotate(args.key_id, grace=parse_duration(args.grace))
            err.write(SAVE_WARNING + "\n")
            if args.json:
                dump({"raw_key": issued.raw_key, "key": issued.record.to_dict(), "rotated_from": args.key_id})
            else:
                say(issued.raw_key)
                err.write(f"key_id={issued.record.key_id} replaces {args.key_id}\n")
            return EXIT_OK

        if cmd == "list":
            rows = km.list(args.owner, include_inactive=args.all)
            if args.json:
                dump([r.to_dict() for r in rows])
            else:
                say("\t".join(["KEY_ID", "MASKED", "OWNER", "NAME", "SCOPES", "STATE", "EXPIRES", "LAST_USED"]))
                for r in rows:
                    say(_row(r))
            return EXIT_OK

        if cmd == "purge":
            n = km.purge(older_than=parse_duration(args.older_than))
            say(f"purged {n} key(s)")
            return EXIT_OK
    except APIKeyError as exc:
        err.write(f"error: {exc} ({exc.reason})\n")
        return EXIT_FAIL
    except StoreError as exc:
        err.write(f"store error: {exc}\n")
        return EXIT_STORE
    except (UsageError, ConfigurationError, PolicyViolation, NotSupported, MissingDependency, ValueError) as exc:
        err.write(f"error: {exc}\n")
        return EXIT_USAGE
    err.write(f"unknown command {cmd!r}\n")
    return EXIT_USAGE


def _utf8(stream: TextIO) -> TextIO:
    if not stream.isatty() and isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(encoding="utf-8", newline="\n")
    elif isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(errors="replace")
    return stream


def main(argv: Optional[Sequence[str]] = None) -> int:
    out, err = _utf8(sys.stdout), _utf8(sys.stderr)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    return execute(args, _manager_from_args, out, err)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
