# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning; the key
format and `hash_alg` strings are part of the compatibility contract.

## 0.3.0 — unreleased

### Added

- `KeyManager.update(key_id, *, name=, scopes=, expires_at=|expires_in=, ip_allowlist=, metadata=)` (and the
  async counterpart): change a live key in place under the same policy checks as `issue()`. Emits
  `key.updated` with the changed field names. Backed by a new optional store method
  `update_fields(key_id, fields) -> bool` (partial, conditional on `revoked_at` being unset) that every
  built-in store implements.
- Django `SAFE_API_KEYS["CORS_PREFLIGHT"]`: `"authenticate"` (default, as in 0.2.0) or `"respond"`, which makes
  `APIKeyMiddleware` answer a genuine browser preflight (`OPTIONS` + `Origin` + `Access-Control-Request-Method`)
  with an empty 204 without a key and without running the view, for CORS layers that only add headers in the
  response phase.
- Django: with `USER_RESOLVER` set, `APIKeyMiddleware` and `@require_api_key` now put the resolved user into
  `request.user` (previously DRF only). When the resolver finds nobody, `request.user` is left untouched.
  `safe_api_keys.contrib.django.conf.lookup_user()` returns the resolver result or `None`.

### Changed

- `AlreadyRotated` is now an `APIKeyError` (`status_code` 409, `error_code` `already_rotated`,
  `reason` `rotated`), so an existing `except APIKeyError` around `rotate()` catches it instead of turning
  into a 500. The README lists every exception `rotate()` can raise.
- The Flask blueprint guard recognises a CORS preflight only when `Origin` is present too (as the Django
  middleware does); `safe_api_keys.http.is_cors_preflight()` is the shared check.

### Documentation

- `use_count` counts throttled touches (at most one per `touch_interval`), not requests; it is not suitable
  for billing or rate limiting.
- Whether a `key_id` exists is observable through a ~0.1 ms timing difference and is not treated as a secret.

## 0.2.0 — 2026-10-05

Security fixes from an external review, plus the rotation semantics they led to. Several of these change
behaviour, hence the minor bump.

**Breaking:** `OPTIONS` requests on Django `PROTECT` paths (and Flask `protect_blueprint`) now require a key.
Cross-origin callers break unless a CORS middleware above `APIKeyMiddleware` answers the preflight (or, from
0.3.0, `CORS_PREFLIGHT = "respond"` is set). `rotate()` raises `ExpiredKey`/`AlreadyRotated` where it used to
succeed, and the replacement key now expires.

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
