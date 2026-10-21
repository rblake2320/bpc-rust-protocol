# Security policy and deployment checklist

## Reporting a vulnerability

Do not open a public issue for a suspected BPC vulnerability. Contact the repository owner privately through GitHub security advisories or a trusted out-of-band channel with reproduction details, affected version, and impact assessment.

## Threat model

BPC protects a server from unapproved pair use, request tampering, stale request replay, body/path substitution, and many concurrent replay races. It does **not** replace TLS, authorization policy, rate limiting, endpoint-level anti-abuse controls, host compromise protection, or secure storage of client private keys and registration secrets.

## Mandatory production controls

### Client keys and registration secrets

- Keep P-256 signing keys in a KMS/HSM/platform secure store where possible. `BpcKeyPair` is an in-memory convenience wrapper, not a key-custody system.
- Store registration secrets in a secret manager. Never log them or place them in browser/mobile bundles.
- Log key fingerprints, not raw JWKs, signed payloads, HMAC values, or signatures.
- Give every pair a precise, non-secret BPC audience and configure `BpcVerifierConfig::new(audience, mode)` at every verifier. `BpcVerifier::default()` is restricted to `bpc://localhost/development`; it is not a production configuration.
- Rotate pairs using `sign_rotation_at`/`verify_and_rotate_at`; do not mutate public keys in place. Rotation is dual-factor: it requires the previous signing key and a domain-separated HMAC from the registration secret, and its replacement key must differ.

### PostgreSQL

- Apply `PostgresPairAuthority::migrate()` using a migration/provisioning role, not your normal runtime account.
- Use `PostgresPairAuthority::connect_tls` / `PostgresAuditLog::connect_tls` with `sslmode=verify-full`; plaintext constructors reject non-loopback endpoints. The TLS constructor verifies certificate chains and server names against the system trust store.
- Supply `PostgresSecretProtector` with a unique AES-256 data key from a KMS/secret manager. BPC encrypts verifier HMAC material and pending registrations before persistence, but the data-encryption key, volumes, snapshots, and backups still need independent encryption and rotation controls.
- Leave `require_synchronous_replication` at its secure default (`true`) for authorization state. PostgreSQL must have a configured synchronous standby; the authority requests `remote_apply` before acknowledging a mutation. `false` is only a deliberately isolated test/single-node development exception.
- Limit runtime privileges to the selected schema/tables. Do not grant DDL, table ownership, or superuser access to the application role.
- Monitor serialization failures, transaction latency, lock waits, failed approvals, and rejected state-fence claims.
- Back up and restore-test lifecycle/audit data. Test an application restart and PostgreSQL failover under your real managed-service settings.

### Redis replay protection

- Use the `GovernedRedisNonceStore`, not a bare `SET NX` implementation.
- `GovernedRedisNonceStore` requires `rediss://` by default. Plain `redis://` is only available after the explicit `allow_insecure_loopback` test/development opt-in and only for literal loopback hosts. Also require ACL authentication, dedicated tenancy/database, bounded client queues, and `maxmemory-policy noeviction`.
- Leave `min_replica_acks` at its secure default (`1`) for production. Redis must acknowledge each fresh nonce write to the configured replica quorum before it can authorize. The replay backend separately checks the signed timestamp against Redis server time.
- Allow the service principal to read `CONFIG GET maxmemory-policy` or provide an equivalent controlled preflight; failure to prove no-eviction must keep authorization closed.
- Redis cannot prove its own nonce history. Use an independently durable, monotonic `RedisContinuityAnchor` outside Redis's backup/restore domain. After fencing/draining verifiers for any restore, promotion, replacement, or persistence uncertainty, advance the anchor, call `provision_current_generation`, wait its full quarantine, then call `reconcile` before accepting traffic.
- Reconcile on a serialized periodic cadence shorter than nonce retention and after any connectivity, failover, restore, snapshot, or configuration incident. A static deployment epoch is not a continuity proof.
- Alert on quarantine state, continuity mismatch, Redis command failures/timeouts, replay rate, and memory pressure. A timeout is an ambiguous nonce outcome and must remain fail-closed.

### HTTP integration

- Terminate TLS before the Axum app. Do not permit plain HTTP outside an isolated local-development boundary.
- Decide exactly what string clients sign (`path_and_query()` in this integration) and preserve it through proxies. Avoid independent path/query decoding, canonicalization, or rewrites.
- Configure a conservative `max_body_bytes`. For streaming requests, design a separate, versioned digest protocol instead of disabling body binding.
- Configure `with_body_collection_limit`, `with_body_collection_timeout`, `with_verification_limit`, and upstream connection/header/body-read timeouts. The adapter bounds concurrent buffered requests and synchronous verifier jobs; timed-out blocking jobs retain their permit until they actually finish, but a reverse proxy/server must still defend the network edge from slow-client exhaustion.
- Do not trust client-provided forwarding headers for source IP. Only derive client IP from a validated trusted-proxy boundary.
- Rate-limit before expensive P-256 work, including unknown pair IDs and malformed signed payloads.
- Return generic stable BPC error codes publicly. Keep details such as canary class, storage status, policy snapshot, and raw parsing failures in protected telemetry only.

### Audit

- Preserve the append-only audit-chain tables. Do not grant update/delete permissions to the runtime application role.
- Export/signed-anchor audit heads to independently controlled durable storage. A chain stored only in the same database does not prove protection from a privileged database rollback or fork.
- Keep audit `detail` sanitized and bounded. Treat source IPs/user agents/paths as potential PII and apply retention/access policies.

## Security-sensitive behavior guaranteed by this crate

- Strict BPC v2 payload shape and exact canonical JSON before signature verification; both factors bind audience, mode, pair ID, purpose, method, exact path, body digest, nonce, timestamp, and version.
- Strict P-256 public point, base64url, UUID-v4 nonce, safe integer, method/scope, and exact-body validation.
- Constant-time HMAC comparison through the RustCrypto `Mac::verify_slice` primitive.
- Fixed-width P1363 signature validation.
- Nonce consumption only after full cryptographic verification; replay failure does not authorize.
- Pair-scoped nonce identity, strict verifier audience/mode comparison, and maximum five-minute freshness-window enforcement.
- Redis ambiguity, continuity mismatch, policy drift, or unsupported eviction policy fail closed.
- Final durable use claims compare an authorization version/policy snapshot and update counters/lifecycle atomically.
- Ghost pairs consume validated nonces but cannot authorize.
- Rotation atomically retires the old pair and inserts the replacement; predecessor revocation traverses successor lineage.
- The supplied Axum adapter defaults to generic public denials, performs declared-size preflight, bounds and times out body buffering, and prevents timed-out blocking verification work from bypassing its concurrency limit.
- The supplied Reqwest transport pins one origin, rejects authority/path normalization forms before signing, never follows redirects carrying BPC headers, and has bounded connect/total/read timeouts.
- PostgreSQL pair verifier material and pending enrollment records are AES-256-GCM envelopes bound to their exact pair/token context. Public pair/enrollment domain types are non-serializable and redact verifier material from debug output.
- Audit verification has a fixed maximum work bound and PostgreSQL audit verification compares the chain to its persisted head inside a repeatable-read snapshot.

## Versioning changes

Changes that alter canonical payload bytes, signature encoding, nonce semantics, signed path form, JWK acceptance rules, or error-code meanings require a new protocol version. BPC v1 must not be accepted as a fallback after a BPC v2 failure; migrate with fresh BPC v2 enrollment and cross-language test vectors.
