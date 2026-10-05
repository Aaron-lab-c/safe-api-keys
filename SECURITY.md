# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories ("Report a vulnerability") on the
repository rather than in public issues. We aim to acknowledge within 3 business days.

## Threat model

### Assets
- **Raw API keys** held by clients (bearer credentials).
- **Pepper(s)** held by the server (environment / secret manager).
- **Key records** in the database (hashes, owners, scopes, state).

### In scope — what the library defends against

| Threat | Mitigation |
|---|---|
| Database dump / backup leak | Only `HMAC-SHA256(pepper, body)` is stored; without the pepper hashes are useless. Secrets have ≥ 180 bits of entropy, so even unpeppered hashes cannot be brute-forced. No raw key or secret column exists. |
| Online guessing / brute force | 190-bit secret; checksum rejects random strings before any DB access; constant-time comparison; unknown `key_id` performs a dummy hash; identical messages for malformed/unknown keys; `on_rejected` hook for external rate limiting keyed by IP / `key_id`. |
| Timing side channels | `hmac.compare_digest` everywhere; equal hashing work for unknown ids and wrong secrets. |
| Environment mix-ups (test key against prod) | Prefix binding (`acme_live` vs `acme_test`) plus separate peppers. |
| Key leakage through logs/UI | `masked` everywhere; reprs/exceptions/audit events/CLI/admin never print secrets (enforced by tests scanning for 32-char base62 runs). Query-string extraction is off by default. |
| Leaked key | `revoke()` is immediate (≤ `VerifyCache.ttl` across processes when the optional cache is enabled); rotation with grace period; audit trail (`key.rejected` with reasons, `rotated_to` usage). |
| IP spoofing via `X-Forwarded-For` | Ignored unless `trust_proxy`/`trusted_proxies` is configured; the resolver walks the chain from the right and never trusts client-supplied left-most entries. |
| Lost revocations under concurrency | `touch` is a partial update and cannot overwrite `revoked_at`; `rotate` writes the old key with an atomic, conditional partial update (`save_rotation`) that refuses once `revoked_at` is set, so a concurrent `revoke` always wins and no replacement key is written. |
| Rotation resurrecting a dead key | Revoked and expired keys cannot be rotated; the replacement gets the old key's lifetime counted from the rotation (capped at `max_ttl`), so a time-limited key never becomes perpetual. |
| Unauthenticated access through `OPTIONS` | The Django middleware and the Flask blueprint guard authenticate every method; only a CORS preflight (no credentials by design) is answered by Flask's default `OPTIONS` response without running the view. Put CORS middleware above `APIKeyMiddleware` in Django. |
| Raw key exposure on the operator's side | The Django admin renders a new key straight into the result page, never into the `messages` cookie; admin rows cannot be deleted (revoke keeps the audit trail); `safe-api-keys verify`/`parse` read the key from stdin instead of the command line (`ps`, shell history). |
| Deploying without a pepper | `python manage.py check` reports `safe_api_keys.W001` (missing) / `E001` (invalid); non-Django code fails at construction (`ConfigurationError`). |
| Pepper compromise / rotation | Versioned `hash_alg` (`hmac-sha256$v2`), multiple peppers, `count_by_hash_alg()` to know when an old pepper can be dropped. |

### Out of scope

- Missing TLS: keys are bearer tokens; anyone who can read traffic can use them.
- Keys embedded in browser or mobile front-ends, or committed to repositories.
- A compromised application server (it holds the pepper and sees raw keys in requests).
- Rate limiting / quotas (hooks only).
- Authorization beyond scopes and owner isolation (your queries must filter by `owner`).

## Incident response for a leaked key

1. `km.revoke(key_id, reason="compromised")` (or `safe-api-keys revoke KEY_ID --reason compromised`).
2. Search audit logs for `key_id` (`key.verified` / `key.rejected`) to scope the impact.
3. Issue a replacement (`rotate` with `grace=timedelta(0)` revokes and replaces in one step).
4. If the pepper may have leaked: add a new pepper version, rotate keys, drop the old version when
   `count_by_hash_alg()` shows none left.

## Operational requirements

- Pepper ≥ 16 bytes (recommend ≥ 32 random bytes), from the environment or a secret manager — never in code.
- Different prefix **and** pepper per environment.
- Run behind TLS; keep `query_param` extraction disabled unless unavoidable.
