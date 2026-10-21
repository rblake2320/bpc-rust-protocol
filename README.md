# BPC Protocol for Rust

A hardened Rust implementation of **BPC v1 (Bound Pair Credentials)**: signed HTTP requests that bind an approved pair ID, a P-256 public key, a per-request HMAC, exact method/path/body bytes, a UUID-v4 nonce, and a timestamp.

The crate is designed for interoperability with the existing BPC TypeScript and Python implementations while offering a production Rust stack for Axum, Redis, and PostgreSQL.

> **Status:** BPC v1 compatibility implementation with hardened authority, replay, transport, and adapter boundaries. Version 0.2 is an intentional security API break: every pair has a trusted audience, every verifier has an explicit audience/mode policy, and rotation requires both factors. Review [`SECURITY.md`](SECURITY.md), the [cryptographic assurance and v2 design](docs/BPC_CRYPTOGRAPHIC_ASSURANCE.md), and the [peer-review package](docs/PEER_REVIEW.md) before production rollout.

## What it protects

Each accepted request proves all of the following before application authorization runs:

- The request uses an approved, active pair with the required method scope.
- The caller knows the registered secret-derived request HMAC material.
- The request has a valid P-256/SHA-256 **P1363** signature over exact canonical JSON.
- The signature binds the exact uppercase method, `path_and_query`, and raw body SHA-256 digest.
- The nonce is a UUID v4 and is fresh; durable Redis protection admits it once only.
- The pair policy did not change while cryptography/replay checks were in progress; a final version-fenced claim succeeds atomically.
- The loaded pair is bound to the verifier's exact configured audience and operating mode; production credentials do not work through the local-development default.

## Features

| Feature | Purpose |
| --- | --- |
| Core (default) | Canonical BPC v1 payloads, P-256 signing/verification, HKDF/HMAC, strict JWK checks, memory stores for development/tests |
| `axum` | Exact-body Axum middleware that restores body bytes and injects `AuthSnapshot` only on success |
| `redis-store` | Governed Redis nonce backend with continuity epoch, fixed horizon, quarantine, `noeviction` enforcement, and fail-closed ambiguity handling |
| `postgres-store` | Serializable PostgreSQL pair authority, one-time hashed approval tokens, atomic capacity approval/rotation/final claims, and a transactional audit chain |
| `reqwest-client` | HTTPS-capable client transport that signs exact transmitted body bytes |
| `production` | All runtime integrations |
| `live-integration` | Real Redis/PostgreSQL test gate; requires `BPC_TEST_REDIS_URL` and `BPC_TEST_POSTGRES_URL` |

## Install

```toml
[dependencies]
bpc-protocol = { git = "https://github.com/rblake2320/bpc-rust-protocol", features = ["production"] }
```

## Core request flow

```rust
use std::sync::Arc;
use bpc_protocol::{
    derive_request_hmac_key, generate_registration_secret, sign_request, BpcKeyPair, BpcRequest, BpcVerifier,
    MemoryNonceStore, MemoryPairRegistry, PairKind, PairMode, PairRecord, PairStatus, Scope,
};

let key_pair = BpcKeyPair::generate()?;
let secret = generate_registration_secret()?; // Store only in the client's secret manager.
let pairs = MemoryPairRegistry::default();
pairs.insert(PairRecord {
    id: "pair_example".into(), name: "example".into(),
    scope: Scope::ReadWrite, mode: PairMode::Development,
    audience: "bpc://localhost/development".into(),
    request_hmac_key: derive_request_hmac_key(&secret)?,
    public_jwk: key_pair.public_jwk().clone(), status: PairStatus::Active,
    created_at_ms: bpc_protocol::unix_ms()?, expires_at_ms: None, max_requests: None,
    requests: 0, failed_signatures: 0, authorization_version: 1,
    kind: PairKind::Legitimate, canary_class: None, replaced_by: None,
})?;

let body = br#"{"action":"create"}"#;
let (_, headers) = sign_request(
    key_pair.signing_key(), "pair_example", &secret, "POST", "/v1/widgets", body,
)?;
let decision = BpcVerifier::default().verify(
    BpcRequest {
        pair_id: &headers.pair_id, signature: &headers.signature,
        signed_data: &headers.signed_data, version: &headers.version,
        method: "POST", path: "/v1/widgets", body,
    },
    &pairs,
    &MemoryNonceStore::default(),
);
assert!(decision.ok);
# Ok::<(), bpc_protocol::BpcError>(())
```

`generate_registration_secret()` combines a fixed policy-compliant prefix with an unfiltered 256-bit operating-system-random component. Store the returned secret only in the signing client’s secret manager; the server stores a derived verifier key, not the source secret.

The in-memory stores are deliberately limited to one process. Do **not** use them behind multiple replicas.

## Production setup

### 1. PostgreSQL authority

Provision schema with a dedicated migration role, then give the runtime role only the narrow DML privileges it needs. `PostgresPairAuthority` uses `SERIALIZABLE` transactions, a transaction advisory lock for capacity decisions, row locks/version fencing, one-way lifecycle transitions, and SHA-256-hashed approval tokens. It encrypts the BPC HMAC verifier and pending enrollment material with AES-256-GCM before they enter PostgreSQL.

```rust
use bpc_protocol::{PostgresAuthorityConfig, PostgresPairAuthority, PostgresSecretProtector};

let data_key = PostgresSecretProtector::from_base64url(
    "kms-key-generation-2026-10",
    &std::env::var("BPC_POSTGRES_DATA_KEY_B64URL")?,
)?;
let authority = PostgresPairAuthority::connect_tls(
    &std::env::var("BPC_DATABASE_URL")?,
    PostgresAuthorityConfig::new(data_key),
)?;
authority.migrate()?; // Run during controlled provisioning, not every app start.
```

`connect_tls` requires `sslmode=verify-full` in the PostgreSQL URL and validates the hostname/certificate chain against the system trust store. `connect` is limited to literal loopback endpoints for isolated tests. `PostgresAuthorityConfig::new` requires a configured synchronous PostgreSQL standby and `remote_apply` acknowledgement for security-state mutations; do not set `require_synchronous_replication = false` outside a deliberately isolated test/single-node development environment. Keep the envelope key in a KMS/secret manager, rotate it with a controlled re-encryption migration, and separately encrypt volumes/backups with least-privilege database roles.

### 2. Governed Redis replay defense

The Redis store will only operate when `maxmemory-policy=noeviction`; an eviction-capable Redis instance is unsafe for replay prevention. It requires verified `rediss://` in production; `redis://` is available only after an explicit `allow_insecure_loopback` opt-in for a literal loopback development endpoint. Its production default requires one Redis replica acknowledgement for every fresh nonce (`min_replica_acks = 1`) and independently checks the signed timestamp against Redis server time. Configure ACL/authentication, dedicated tenancy, replication, and the `CONFIG GET maxmemory-policy` permission needed for the safety check.

```rust
use bpc_protocol::{GovernedRedisNonceConfig, GovernedRedisNonceStore};

let cfg = GovernedRedisNonceConfig::new("payments-prod", "deploy-epoch-2026-10", 60_000)?;
let nonce_store = GovernedRedisNonceStore::connect(&std::env::var("BPC_REDIS_URL")?, cfg)?; // rediss://...

// On a new namespace or epoch mismatch this deliberately returns a quarantine error.
// After the configured horizon, run this from a serialized readiness/reconciliation task.
nonce_store.provision_epoch()?;
nonce_store.reconcile()?;
```

A Redis timeout has an ambiguous outcome: Redis may have consumed the nonce after the client timed out. The store closes a local gate on any such error and must be explicitly reconciled; it never retries/accepts an uncertain nonce operation.

### 3. Axum

The middleware signs and compares `uri.path_and_query()` verbatim. Keep upstream proxy rewriting and client path construction consistent; do not independently normalize percent encoding, trailing slashes, query strings, or dot segments.

```rust
use std::sync::Arc;
use axum::{middleware, Router};
use bpc_protocol::{bpc_axum_middleware, BpcAxumState, BpcVerifier};

# let protector = bpc_protocol::PostgresSecretProtector::new("tests", [1; 32])?;
# let authority = Arc::new(bpc_protocol::PostgresPairAuthority::connect("postgres://postgres:postgres@127.0.0.1/postgres", bpc_protocol::PostgresAuthorityConfig::new(protector))?);
# let mut redis_config = bpc_protocol::GovernedRedisNonceConfig::new("example", "epoch-1", 60_000)?;
# redis_config.allow_insecure_loopback = true;
# let nonce_store = Arc::new(bpc_protocol::GovernedRedisNonceStore::connect("redis://127.0.0.1:6379/", redis_config)?);
let state = BpcAxumState::new(BpcVerifier::default(), authority, nonce_store);
let app = Router::new().layer(middleware::from_fn_with_state(state, bpc_axum_middleware));
# Ok::<(), bpc_protocol::BpcError>(())
```

`AuthSnapshot` is inserted into request extensions only after successful final authorization. The adapter defaults to generic public authentication failures, rejects oversized declared bodies before buffering, bounds concurrent body collection, enforces a body-read deadline, and bounds deadline-aware blocking verifier jobs. Set `state.max_body_bytes`, `state.with_body_collection_limit(...)`, `state.with_body_collection_timeout(...)`, and `state.with_verification_limit(...)` for expected request volume; retain server/proxy header, body-read, connection, and trusted-source rate limits. Ordinary BPC v1 requests must have a precomputed exact-body digest, so streaming uploads need an explicit protocol design.

## Pair lifecycle and rotation

`PairAuthority` separates untrusted registration from an authorized approval action:

1. `request_pairing` validates public P-256 material and stores a short-lived pending request.
2. An authenticated management service calls `approve_pairing` after human/policy approval.
3. Only the returned pair ID is exposed; management list views are redacted and never include HMAC material.
4. `sign_rotation_at` generates a canonical UUID-v4 nonce-bound transcript and authenticates it with both the old P-256 key and a domain-separated HMAC derived from the registration secret.
5. `verify_and_rotate_at` validates both factors, freshness, binding, and an actual key change before atomically retiring the old pair and activating the successor. Revoking any pair revokes every reachable successor in its stored lineage.

An authorization version fence means a request cryptographically checked before a concurrent revoke/rotation/policy mutation cannot complete the final claim as though the old policy still applied.

## Canary pairs

A `PairKind::Ghost` requires a `CanaryClass`. It fully verifies cryptography and consumes the nonce, then always returns `ghost_pair_denied`; it never authorizes. Emit a critical, sanitized incident signal from your HTTP/application layer when that error appears. Do not expose canary classification or other internal response detail to an attacker.

## Audit chain

`MemoryAuditLog` and `PostgresAuditLog` append records as a SHA-256 chain over stable JSON-array evidence preimages. The PostgreSQL version locks a singleton head row in a serializable transaction so writers receive contiguous sequence numbers. Verify with `audit.verify(Some(&external_anchor))`.

A database-only chain cannot prevent a privileged rollback/fork/tail truncation. Periodically sign/export `{sequence, chain_hash, count}` to an independent KMS/WORM/monitoring system and verify against that external anchor. Keep audit data sanitized and bounded; never place registration secrets, raw signatures, signed payloads, or raw JWKs in `detail`.

## Continuous integration

The repository includes the full Redis/PostgreSQL service-tested GitHub Actions definition at [`ci/github-actions-ci.yml`](ci/github-actions-ci.yml). It pins actions to commit SHAs, service images to immutable digests, uses read-only permissions, disables persisted checkout credentials, locks the Rust dependency graph, and runs both `cargo-audit` and the explicit [`deny.toml`](deny.toml) policy. Promote that file to `.github/workflows/ci.yml` to activate it in GitHub Actions, then require it in branch protection.

Before calling an application or a BPC–TSK composition production-vetted, satisfy the evidence requirements in [`docs/PRODUCTION_RELEASE_GATES.md`](docs/PRODUCTION_RELEASE_GATES.md). They deliberately include controls that cannot be delivered by a protocol crate alone.

## Interoperability and validation

The test suite covers:

- Rust request signing and verification;
- 64-way concurrent same-nonce replay (exactly one succeeds);
- invalid-signature nonce preservation;
- ghost-pair fail-closed behavior;
- signed rotation and replay prevention;
- audience/mode isolation, pair-scoped nonce identities, expiry-capacity release, revocation lineage, and dual-factor rotation rejection;
- tamper-evident audit verification;
- Node WebCrypto → Rust golden fixture;
- Rust → Node WebCrypto independent verification;
- Axum body restoration;
- live Redis continuity/replay and live PostgreSQL authority/audit tests.

Run the full gate locally after setting service URLs:

```bash
export BPC_TEST_REDIS_URL='redis://127.0.0.1:6379/'
export BPC_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres'
cargo test --all-features --all-targets
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo audit --deny warnings
cargo deny check all
node scripts/verify-node-interop.mjs
```

## Compatibility contract

- Canonical payload fields are exactly: `body_hash`, `method`, `nonce`, `pair_id`, `path`, `secret_hmac`, `timestamp`, and `version`.
- Signatures are fixed-width 64-byte P-256 P1363 values, base64url without padding.
- Body commitment is `sha256:<base64url SHA-256>` over exact body bytes.
- Timestamps/counters are restricted to JavaScript-safe integers.
- Public keys are strict EC P-256 JWKs. Safe WebCrypto `key_ops:["verify"]` and `ext:true` metadata is accepted; private/unknown fields are rejected.

## License

MIT. See [LICENSE](LICENSE).
