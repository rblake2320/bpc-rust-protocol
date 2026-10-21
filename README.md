# BPC Protocol for Rust

A hardened Rust implementation of **BPC v1 (Bound Pair Credentials)**: signed HTTP requests that bind an approved pair ID, a P-256 public key, a per-request HMAC, exact method/path/body bytes, a UUID-v4 nonce, and a timestamp.

The crate is designed for interoperability with the existing BPC TypeScript and Python implementations while offering a production Rust stack for Axum, Redis, and PostgreSQL.

> **Status:** BPC v1 implementation with real Axum, Redis, PostgreSQL, Reqwest, audit-chain, rotation, canary-pair, and cross-language compatibility coverage. Review `SECURITY.md` before production rollout.

## What it protects

Each accepted request proves all of the following before application authorization runs:

- The request uses an approved, active pair with the required method scope.
- The caller knows the registered secret-derived request HMAC material.
- The request has a valid P-256/SHA-256 **P1363** signature over exact canonical JSON.
- The signature binds the exact uppercase method, `path_and_query`, and raw body SHA-256 digest.
- The nonce is a UUID v4 and is fresh; durable Redis protection admits it once only.
- The pair policy did not change while cryptography/replay checks were in progress; a final version-fenced claim succeeds atomically.

For a high-assurance deployment, the HMAC factor must originate from `generate_high_assurance_registration_secret()`: a canonical, independently random 32-byte secret. The legacy `validate_secret` policy exists only for BPC v1 compatibility and must not be used as evidence of 128- or 256-bit entropy. The server stores only the derived HMAC key, so the pairing control plane must separately record and approve the trusted provisioning path.

## Features

| Feature | Purpose |
| --- | --- |
| Core (default) | Canonical BPC v1 payloads, P-256 signing/verification, HKDF/HMAC, strict JWK checks, memory stores for development/tests |
| `axum` | Exact-body Axum middleware that restores body bytes and injects `AuthSnapshot` only on success |
| `redis-store` | Governed Redis nonce backend with continuity epoch, fixed horizon, quarantine, `noeviction` enforcement, and fail-closed ambiguity handling |
| `postgres-store` | TLS-required PostgreSQL pair authority and audit chain with certificate/hostname verification, serializable lifecycle transactions, and one-time hashed approval tokens |
| `postgres-insecure-tests` | **Test-only:** exposes clearly named `connect_insecure_for_tests` APIs for an isolated local plaintext PostgreSQL service; never enable in production |
| `reqwest-client` | HTTPS-capable client transport that signs exact transmitted body bytes |
| `production` | All runtime integrations |
| `live-integration` | Real Redis/PostgreSQL test gate; enables `postgres-insecure-tests` and requires `BPC_TEST_REDIS_URL` and `BPC_TEST_POSTGRES_URL` |

## Install

```toml
[dependencies]
bpc-protocol = { git = "https://github.com/rblake2320/bpc-rust-protocol", features = ["production"] }
```

## Core request flow

```rust
use std::sync::Arc;
use bpc_protocol::{
    derive_request_hmac_key, sign_request, BpcKeyPair, BpcRequest, BpcVerifier,
    MemoryNonceStore, MemoryPairRegistry, PairKind, PairMode, PairRecord, PairStatus, Scope,
};

let key_pair = BpcKeyPair::generate()?;
let secret = "A production registration secret belongs in a secret manager";
let pairs = MemoryPairRegistry::default();
pairs.insert(PairRecord {
    id: "pair_example".into(), name: "example".into(),
    scope: Scope::ReadWrite, mode: PairMode::Development,
    request_hmac_key: derive_request_hmac_key(secret)?,
    public_jwk: key_pair.public_jwk().clone(), status: PairStatus::Active,
    created_at_ms: bpc_protocol::unix_ms()?, expires_at_ms: None, max_requests: None,
    requests: 0, failed_signatures: 0, authorization_version: 1,
    kind: PairKind::Legitimate, canary_class: None,
})?;

let body = br#"{"action":"create"}"#;
let (_, headers) = sign_request(
    key_pair.signing_key(), "pair_example", secret, "POST", "/v1/widgets", body,
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

The in-memory stores are deliberately limited to one process. Do **not** use them behind multiple replicas.

### High-assurance registration secret

```rust
use bpc_protocol::{
    derive_high_assurance_request_hmac_key, generate_high_assurance_registration_secret,
};

let registration_secret = generate_high_assurance_registration_secret();
let request_hmac_key = derive_high_assurance_request_hmac_key(&registration_secret)?;
// Store the secret only in the client factor's separate secret manager.
# Ok::<(), bpc_protocol::BpcError>(())
```

`BpcVerifierConfig::default()` disables automatic pair lockout. An attacker who knows a pair ID can otherwise submit malformed requests until an automatic lockout causes denial of service. Use per-source and per-pair edge throttles, protected telemetry, and an explicit operator-approved revocation/lock workflow instead. `lockout_after > 0` is an opt-in legacy behavior and is not recommended for exposed endpoints.

## Production setup

### 1. PostgreSQL authority

Provision schema with a dedicated migration role, then give the runtime role only the narrow DML privileges it needs. `PostgresPairAuthority` uses `SERIALIZABLE` transactions, a transaction advisory lock for capacity decisions, row locks/version fencing, one-way lifecycle transitions, and SHA-256-hashed approval tokens.

```rust
use bpc_protocol::{PostgresAuthorityConfig, PostgresPairAuthority, PostgresTlsConfig};

let tls = PostgresTlsConfig::default().with_additional_root_certificate_pem(
    std::fs::read("/run/secrets/postgres-ca.pem")?,
);
let authority = PostgresPairAuthority::connect_tls(
    &std::env::var("BPC_DATABASE_URL")?, // e.g. postgres://app@db.example/bpc?sslmode=require
    PostgresAuthorityConfig::default(),
    tls,
)?;
authority.migrate()?; // Run during controlled provisioning, not every app start.
```

`connect_tls` always forces TLS 1.2 or newer, certificate verification, and hostname verification. It rejects `sslmode=disable`, Unix-socket URLs, and targets without a hostname. It uses platform trust roots plus any PEM CA certificate added through `PostgresTlsConfig`; use the DNS name present in the database certificate SAN, not an arbitrary load-balancer/IP alias. `PostgresAuditLog::connect_tls` has the same policy. The database necessarily contains verifier HMAC material; encrypt volumes/backups, apply least privilege, and use a managed/KMS-backed database encryption posture for your environment.

For an isolated local plaintext PostgreSQL test service only, enable `postgres-insecure-tests` and call the deliberately named `connect_insecure_for_tests` constructors. The normal `postgres-store` and `production` feature sets do not expose a plaintext connection constructor.

### 2. Governed Redis replay defense

The Redis store will only operate when `maxmemory-policy=noeviction`; an eviction-capable Redis instance is unsafe for replay prevention. Configure ACL/TLS/authentication, dedicate the database/cluster tenancy, and grant the `CONFIG GET maxmemory-policy` permission needed for the safety check.

```rust
use bpc_protocol::{GovernedRedisNonceConfig, GovernedRedisNonceStore};

let cfg = GovernedRedisNonceConfig::new("payments-prod", "deploy-epoch-2026-10", 60_000)?;
let nonce_store = GovernedRedisNonceStore::connect(&std::env::var("BPC_REDIS_URL")?, cfg)?;

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

# let authority = Arc::new(bpc_protocol::PostgresPairAuthority::connect_tls("postgres://app@db.example/bpc?sslmode=require", bpc_protocol::PostgresAuthorityConfig::default(), bpc_protocol::PostgresTlsConfig::default())?);
# let nonce_store = Arc::new(bpc_protocol::GovernedRedisNonceStore::connect("redis://...", bpc_protocol::GovernedRedisNonceConfig::new("example", "epoch-1", 60_000)?)?);
let state = BpcAxumState::new(BpcVerifier::default(), authority, nonce_store);
let app = Router::new().layer(middleware::from_fn_with_state(state, bpc_axum_middleware));
# Ok::<(), bpc_protocol::BpcError>(())
```

`AuthSnapshot` is inserted into request extensions only after successful final authorization. Limit buffered body size with `state.max_body_bytes`; ordinary BPC v1 requests must have a precomputed exact-body digest, so streaming uploads need an explicit protocol design.

## Pair lifecycle and rotation

`PairAuthority` separates untrusted registration from an authorized approval action:

1. `request_pairing` validates public P-256 material and stores a short-lived pending request.
2. An authenticated management service calls `approve_pairing` after human/policy approval.
3. Only the returned pair ID is exposed; management list views are redacted and never include HMAC material.
4. `sign_rotation_at` signs a canonical rotation payload with the old key.
5. `verify_and_rotate_at` validates the old signature and atomically retires the old pair before activating the successor.

An authorization version fence means a request cryptographically checked before a concurrent revoke/rotation/policy mutation cannot complete the final claim as though the old policy still applied.

## Canary pairs

A `PairKind::Ghost` requires a `CanaryClass`. It fully verifies cryptography and consumes the nonce, then always returns `ghost_pair_denied`; it never authorizes. Emit a critical, sanitized incident signal from your HTTP/application layer when that error appears. Do not expose canary classification or other internal response detail to an attacker.

## Audit chain

`MemoryAuditLog` and `PostgresAuditLog` append records as a SHA-256 chain over stable JSON-array evidence preimages. The PostgreSQL version locks a singleton head row in a serializable transaction so writers receive contiguous sequence numbers. Verify with `audit.verify(Some(&external_anchor))`.

A database-only chain cannot prevent a privileged rollback/fork/tail truncation. Periodically sign/export `{sequence, chain_hash, count}` to an independent KMS/WORM/monitoring system and verify against that external anchor. Keep audit data sanitized and bounded; never place registration secrets, raw signatures, signed payloads, or raw JWKs in `detail`.

## Continuous integration

The repository includes the full Redis/PostgreSQL service-tested GitHub Actions definition at [`ci/github-actions-ci.yml`](ci/github-actions-ci.yml). Promote that file to `.github/workflows/ci.yml` to activate it in GitHub Actions. The initial publication credential used for this repository lacks GitHub’s `workflows` permission, so it cannot create workflow files remotely; the template is otherwise ready to run unchanged.

## Interoperability and validation

The test suite covers:

- Rust request signing and verification;
- 64-way concurrent same-nonce replay (exactly one succeeds);
- invalid-signature nonce preservation;
- ghost-pair fail-closed behavior;
- signed rotation and replay prevention;
- tamper-evident audit verification;
- Node WebCrypto → Rust golden fixture;
- Rust → Node WebCrypto independent verification;
- Axum body restoration;
- live Redis continuity/replay and live PostgreSQL authority/audit tests.

Run the full gate locally after setting service URLs:

```bash
export BPC_TEST_REDIS_URL='redis://127.0.0.1:6379/'
# `live-integration` deliberately enables `postgres-insecure-tests`; do not use
# this URL or feature set for an application build.
export BPC_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres'
cargo test --all-features --all-targets
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
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
