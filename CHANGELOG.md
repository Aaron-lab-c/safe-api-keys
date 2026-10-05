# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning; the key
format and `hash_alg` strings are part of the compatibility contract.

## 0.2.0 — 2026-10-05

Security fixes from an external review, plus the rotation semantics they led to. Several of these change
behaviour, hence the minor bump.

### Security

- **Django `APIKeyMiddleware` no longer skips `OPTIONS`** (high). Every method on a `PROTECT` path is
  authenticated, so a view behind the middleware never runs without a valid key. CORS preflights carry no
  credentials: answer them with a CORS middleware placed *above* `APIKeyMiddleware`, or they get a 401.
  The Flask `protect_blueprint` guard had the same bypass; it now answers only a genuine CORS preflight
  (`Access-Control-Request-Method` present) with Flask's default `OPTIONS` response, without running the
  view, and authenticates everything else.
- **A concurrent `revoke()` can no longer be undone by `rotate()`** (medium). Every built-in store
  implements `save_rotation(new, old) -> bool`: one atomic, conditional write that updates only the rotation
  fields of the old key, refuses once `revoked_at` is set, and saves the replacement only then. `rotate()`
  raises `RevokedKey` and writes nothing when it refuses. Custom stores get a best-effort re-check before the
  write; implement `save_rotation` to close the window.
- **Rotation no longer produces a perpetual key and refuses dead keys** (medium). Without
  `expires_in`/`expires_at` the replacement gets the old key's lifetime (`expires_at - created_at`) counted
  from the rotation, capped at `policy.max_ttl`. Expired keys raise `ExpiredKey`.
- **Django admin never puts a raw key into `django.contrib.messages`** (low): new and rotated keys are
  rendered on a result page (`safe_api_keys/admin/show_keys.html`) in that response only, instead of the
  signed-but-unencrypted messages cookie.
- **Missing pepper is reported by `manage.py check`** (low): system check `safe_api_keys.W001` (not
  configured) / `safe_api_keys.E001` (invalid), also shown at `runserver` start-up.
- **Django admin cannot delete keys** (low): a delete leaves no audit trail; revoke instead and clean up with
  `purge`.
- **CLI `verify`/`parse` read the raw key from stdin** (low) when it is omitted or `-` (`getpass` prompt on a
  terminal), so it does not appear in `ps` or the shell history. The positional argument still works.

### Changed

- `rotate()` refuses a key that already has a replacement: `AlreadyRotated(key_id, rotated_to)` (new
  exception, exported from `safe_api_keys`). Rotate the key named in `rotated_to` instead.
- The example apps' self-service rotate endpoints return 409 for revoked, expired or already rotated keys.
- `KeyStore` documents the optional `save_rotation` method; `AsyncStoreAdapter` forwards it.

### Upgrade notes

- If browsers call protected Django paths cross-origin, make sure your CORS middleware precedes
  `APIKeyMiddleware`.
- Callers of `rotate()` should handle `ExpiredKey` and `AlreadyRotated` (and `RevokedKey` from a race), and
  expect the replacement to expire when the old key did.
- Scripts that passed the raw key to `safe-api-keys verify` on the command line keep working; switch them to
  stdin.

## 0.1.0 — 2026-10-02

First release.

- Key format `prefix_keyid_secret+checksum` (base62, CRC32 checksum), `KeyFormat` customisation.
- `KeyManager` / `KeyVerifier` and async counterparts sharing one rule set (`_logic`).
- HMAC-SHA256 hashing with versioned peppers; optional `Argon2Hasher`.
- Lifecycle: issue, verify, check, revoke, rotate (grace, lineage), list, delete, purge, `count_by_hash_alg`.
- `KeyPolicy` (expiry rules, allowed scopes, per-owner limit, metadata limits); with `max_ttl` and no explicit
  expiry, keys are capped at `max_ttl`.
- Scopes with `:*` / `*` wildcards; IP allow-lists (IPv4/IPv6, CIDR).
- Optional `VerifyCache`; audit events with Null/Logging/Callback sinks.
- Stores: Memory, SQLite, SQLAlchemy (sync/async), Redis (sync/async), Django ORM; `from_url()`.
- Adapters: FastAPI (dependencies, OpenAPI security), Starlette middleware, Flask extension, Django
  (model, migration, settings, decorator, middleware, DRF, admin, `apikey` command).
- `safe-api-keys` CLI.
- Runnable examples for Flask, Django and FastAPI; database setup guide (`docs/database-setup.md`).
- Examples and README document CSRF for cookie-session endpoints (Django `X-CSRFToken`, Flask JSON-only +
  `SameSite=Lax`); API-key endpoints don't need CSRF.
