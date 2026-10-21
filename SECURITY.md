# Security policy and deployment checklist

## Reporting a vulnerability

Do not open a public issue for a suspected BPC vulnerability. Contact the repository owner privately through GitHub security advisories or a trusted out-of-band channel with reproduction details, affected version, and impact assessment.

## Threat model

BPC protects a server from unapproved pair use, request tampering, stale request replay, body/path substitution, and many concurrent replay races. It does **not** replace TLS, authorization policy, rate limiting, endpoint-level anti-abuse controls, host compromise protection, or secure storage of client private keys and registration secrets.

## Mandatory production controls

### Client keys and registration secrets

- Keep P-256 signing keys in a KMS/HSM/platform secure store where possible. `BpcKeyPair` is an in-memory convenience wrapper, not a key-custody system.
- Generate production registration secrets with `generate_high_assurance_registration_secret()` and store them in a separate client-side secret manager. This produces exactly 32 random bytes; legacy password-policy-compliant strings are for BPC v1 compatibility only and do not establish high assurance.
- Never log registration secrets or place them in browser/mobile bundles. The server derives/stores only an HMAC verifier key, so an approval workflow must retain evidence that the underlying client secret came from the approved provisioning path.
- Log key fingerprints, not raw JWKs, signed payloads, HMAC values, or signatures.
- Rotate pairs using `sign_rotation_at`/`verify_and_rotate_at`; do not mutate public keys in place.

### PostgreSQL

- Apply `PostgresPairAuthority::migrate()` using a migration/provisioning role, not your normal runtime account.
- Use `PostgresPairAuthority::connect_tls` and `PostgresAuditLog::connect_tls`, not a raw PostgreSQL client. These constructors require TLS 1.2 or newer and use certificate plus hostname verification; they reject `sslmode=disable` and Unix-socket targets. Use the database certificate's DNS SAN as the URL host.
- Configure `PostgresTlsConfig` with the managed/internal database CA PEM where it is not already in the platform trust store. Do not disable certificate or hostname verification.
- Never enable the `postgres-insecure-tests` feature in an application build. Its deliberately named plaintext constructors exist only for isolated local integration tests.
- Encrypt database volumes, snapshots, and backups. Pair rows hold verifier HMAC material needed for request verification.
- Limit runtime privileges to the selected schema/tables. Do not grant DDL, table ownership, or superuser access to the application role.
- Monitor serialization failures, transaction latency, lock waits, failed approvals, and rejected state-fence claims.
- Back up and restore-test lifecycle/audit data. Test an application restart and PostgreSQL failover under your real managed-service settings.

### Redis replay protection

- Use the `GovernedRedisNonceStore`, not a bare `SET NX` implementation.
- Use only `GovernedRedisNonceStore::connect_tls` or `connect_tls_with_config` in an application build. Both accept one `rediss://` TCP endpoint through Rustls; they reject plaintext/Unix/alternate or multi-host URLs and all URL fragments, including `#insecure`.
- Do not enable Redis's insecure TLS-verification feature or bypass certificate/hostname verification. Use the Redis certificate's DNS SAN in `BPC_REDIS_URL`. For an internal/private CA or Redis mTLS, configure bounded root and paired client-key material through `RedisTlsConfig`; use `with_system_roots(false)` when a private CA must be the complete trust set.
- Never enable `redis-insecure-tests` in an application build. Its deliberately named `connect_loopback_for_tests` constructor accepts only a pinned local plaintext address and exists solely for isolated integration tests.
- Require Redis TLS, ACL authentication, dedicated tenancy/database, bounded client queues, and `maxmemory-policy noeviction`.
- Allow the service principal to read `CONFIG GET maxmemory-policy` or provide an equivalent controlled preflight; failure to prove no-eviction must keep authorization closed.
- Call `provision_epoch` and then `reconcile` before accepting traffic. New/mismatched epochs intentionally quarantine for the configured replay retention horizon.
- Reconcile on a serialized periodic cadence shorter than nonce retention and after any connectivity, failover, restore, snapshot, or configuration incident.
- Alert on quarantine state, continuity mismatch, Redis command failures/timeouts, replay rate, and memory pressure. A timeout is an ambiguous nonce outcome and must remain fail-closed.

### HTTP integration

- Terminate TLS before the Axum app. Do not permit plain HTTP outside an isolated local-development boundary.
- Decide exactly what string clients sign (`path_and_query()` in this integration) and preserve it through proxies. Avoid independent path/query decoding, canonicalization, or rewrites.
- Configure a conservative `max_body_bytes`. For streaming requests, design a separate, versioned digest protocol instead of disabling body binding.
- Do not trust client-provided forwarding headers for source IP. Only derive client IP from a validated trusted-proxy boundary.
- Rate-limit before expensive P-256 work, including unknown pair IDs and malformed signed payloads.
- Keep `BpcVerifierConfig::lockout_after` at its default of `0`. Automatic lockout keyed by a pair ID lets unauthenticated malformed traffic become a credential-specific denial-of-service attack. Use edge throttles, protected telemetry, canary pairs, and operator-approved lifecycle actions instead.
- Return generic stable BPC error codes publicly. Keep details such as canary class, storage status, policy snapshot, and raw parsing failures in protected telemetry only.

### Audit

- Preserve the append-only audit-chain tables. Do not grant update/delete permissions to the runtime application role.
- Export/signed-anchor audit heads to independently controlled durable storage. A chain stored only in the same database does not prove protection from a privileged database rollback or fork.
- Keep audit `detail` sanitized and bounded. Treat source IPs/user agents/paths as potential PII and apply retention/access policies.

## Security-sensitive behavior guaranteed by this crate

- Strict payload shape and exact canonical JSON before signature verification.
- Strict P-256 public point, base64url, UUID-v4 nonce, safe integer, method/scope, and exact-body validation.
- Constant-time HMAC comparison through the RustCrypto `Mac::verify_slice` primitive.
- Fixed-width P1363 signature validation.
- Nonce consumption only after full cryptographic verification; replay failure does not authorize.
- Redis ambiguity, continuity mismatch, policy drift, or unsupported eviction policy fail closed.
- Final durable use claims compare an authorization version/policy snapshot and update counters/lifecycle atomically.
- Ghost pairs consume validated nonces but cannot authorize.
- Rotation atomically retires the old pair and inserts the replacement.

## Versioning changes

Changes that alter canonical payload bytes, signature encoding, nonce semantics, signed path form, JWK acceptance rules, or error-code meanings require a new protocol version. Do not silently relax or tighten those behaviors in a v1 deployment without cross-language test vectors and a migration plan.
