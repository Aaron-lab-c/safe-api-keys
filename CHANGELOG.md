# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning; the key
format and `hash_alg` strings are part of the compatibility contract.

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
