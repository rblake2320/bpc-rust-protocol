# BPC Protocol for Rust

A hardened Rust implementation of **BPC v2 (Bound Pair Credentials)**: two-factor HTTP request authentication built from P-256/SHA-256 signatures plus a secret-derived HMAC, with exact request binding, replay defense, and explicit lifecycle policy.

> **Security release:** v2 is a deliberately breaking pre-1.0 release. BPC v1 did not cryptographically bind its request HMAC to the full request core; it is not accepted by the default verifier. Re-enroll clients as fresh v2 pairs rather than upgrading a credential in place.

## What BPC v2 authenticates

Every successful authorization requires an active approved pair, a valid method scope, a short freshness window, a UUID-v4 one-use nonce, and a successful final lifecycle claim. Both factors cover a canonical v2 core:

```json
{"audience":"bpc://api.example.test/production","body_hash":"sha256:<43-char-base64url-digest>","method":"POST","mode":"production","nonce":"<canonical UUID-v4>","pair_id":"pair_...","path":"/v1/widgets?exact=query","purpose":"http-request","timestamp":1740000000000,"version":"2.0"}
```

The client derives `K_v2 = HKDF-SHA-256(registration_secret, salt="bpc-protocol-hmac-salt-v2", info="bpc-v2-request-hmac-key", L=32)`, calculates `X-BPC-HMAC = HMAC-SHA-256(K_v2, "BPC-HMAC-v2\0" || canonical_core)`, and signs `"BPC-SIGN-v2\0" || canonical_core || "\0" || X-BPC-HMAC` using P-256/SHA-256 P1363. It sends exactly five BPC headers:

- `X-BPC-HMAC`
- `X-BPC-Pair-ID`
- `X-BPC-Signature`
- `X-BPC-Signed-Data`
- `X-BPC-Version: 2.0`

This prevents reuse of a captured HMAC tag when a request field is modified, including `audience`, `mode`, method, path, body commitment, timestamp, nonce, pair ID, purpose, or version. A P-256 signing-key compromise still requires the independent v2 HMAC factor.

## Install

```toml
[dependencies]
bpc-protocol = { git = "https://github.com/rblake2320/bpc-rust-protocol", features = ["production"] }
```

## Core request flow

```rust
use bpc_protocol::{
    derive_request_hmac_key, generate_registration_secret, sign_request, BpcKeyPair,
    BpcRequest, BpcSigningContext, BpcVerifier, MemoryNonceStore, MemoryPairRegistry,
    PairKind, PairMode, PairRecord, PairRequestProtocol, PairStatus, Scope,
};

let key_pair = BpcKeyPair::generate()?;
let secret = generate_registration_secret()?; // Client secret manager only.
let audience = "bpc://localhost/development";
let pairs = MemoryPairRegistry::default();
pairs.insert(PairRecord {
    id: "pair_example".into(), name: "example".into(), scope: Scope::ReadWrite,
    mode: PairMode::Development, audience: audience.into(),
    request_hmac_key: derive_request_hmac_key(&secret)?, request_protocol: PairRequestProtocol::V2,
    public_jwk: key_pair.public_jwk().clone(), status: PairStatus::Active,
    created_at_ms: bpc_protocol::unix_ms()?, expires_at_ms: None, max_requests: None,
    requests: 0, failed_signatures: 0, authorization_version: 1,
    kind: PairKind::Legitimate, canary_class: None, replaced_by: None,
})?;
let body = br#"{"action":"create"}"#;
let (_, headers) = sign_request(
    key_pair.signing_key(), "pair_example", &secret,
    &BpcSigningContext::new(audience, PairMode::Development)?, "POST", "/v1/widgets", body,
)?;
let decision = BpcVerifier::default().verify(BpcRequest {
    hmac: &headers.hmac, pair_id: &headers.pair_id, signature: &headers.signature,
    signed_data: &headers.signed_data, version: &headers.version,
    method: "POST", path: "/v1/widgets", body,
}, &pairs, &MemoryNonceStore::default());
assert!(decision.ok);
# Ok::<(), bpc_protocol::BpcError>(())
```

`SecretRequestHmacKey` is deliberately non-serializable and has redacted `Debug`; applications should use `RedactedPair` for management output. PostgreSQL encrypts active verifier material and separately encrypted non-secret pending metadata with AES-256-GCM and pair/token-specific authenticated data.

## Production deployment

### PostgreSQL authority

Use `PostgresPairAuthority::connect_tls` with `sslmode=verify-full`, a trusted CA, a hostname-matching certificate, least-privilege runtime credentials, and `PostgresAuthorityConfig::new` (which requires synchronous `remote_apply` replication). `migrate()` labels pre-v2 active records as `v1-compatibility` and discards unapproved old pending records; the v2 verifier rejects those legacy records. Existing clients must be re-enrolled with a new key pair and random registration secret.

`PostgresSecretProtector` needs a 32-byte key from a KMS/HSM-backed secret manager. Never commit, print, or place it in the database URL.

### Redis replay defense

`GovernedRedisNonceStore` requires an independent `RedisContinuityAnchor`. The anchor must be durable, linearizable, monotonic per namespace, and in a backup/restore domain independent of Redis. Redis itself cannot prove that its nonce history was not rolled back.

On Redis restore, promotion, persistence uncertainty, or planned replacement: fence/drain verifiers, call the controlled recovery role's `advance_after_fencing`, call `provision_current_generation`, wait a complete quarantine horizon, then call `reconcile` before serving. Every nonce acceptance rechecks the anchor generation, Redis `noeviction` policy, fixed retention policy, Redis server-time freshness, and configured replica acknowledgement quorum. Any error closes the local gate.

`InMemoryContinuityAnchor` exists only for isolated development/tests. Production requires a real independently durable anchor implementation; a static deployment epoch is intentionally not supported.

### HTTP adapters

The Axum middleware rejects duplicate/missing BPC headers, buffers exact body bytes with a bounded size/concurrency/deadline, retains generic public errors by default, and restores the exact bytes only after authorization. The Reqwest client pins one origin, disables redirects, requires a trusted `BpcSigningContext`, and applies connect/total/read timeouts.

## Validation and CI

The audited CI template at [`ci/github-actions-ci.yml`](ci/github-actions-ci.yml) runs Rust 1.85.0 format/lint/core/adapter/Node checks, real Redis/PostgreSQL tests, a real CA-signed hostname-verified PostgreSQL TLS test, and a separate Rust 1.88.0 advisory/dependency-policy job. Actions and service images are immutable-pinned. Promote that exact file to `.github/workflows/ci.yml` using a GitHub token with the `workflows` permission, then require it in branch protection.

Local full validation requires real services and the mandatory TLS endpoint variables:

```bash
export BPC_TEST_REDIS_URL='redis://127.0.0.1:6379/'
export BPC_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres'
export SSL_CERT_FILE=/path/to/test-ca.crt
export BPC_TEST_POSTGRES_TLS_URL='postgresql://postgres:postgres@localhost:5433/postgres?sslmode=verify-full'
export BPC_TEST_POSTGRES_TLS_BAD_HOST_URL='postgresql://postgres:postgres@127.0.0.1:5433/postgres?sslmode=verify-full'
cargo test --locked --all-features --all-targets
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo audit --deny warnings
cargo deny check all
node scripts/verify-node-interop.mjs
```

Read [SECURITY.md](SECURITY.md), [production release gates](docs/PRODUCTION_RELEASE_GATES.md), [cryptographic assurance](docs/BPC_CRYPTOGRAPHIC_ASSURANCE.md), and the [peer review package](docs/PEER_REVIEW.md) before describing a deployment as production ready.

## BPC–TSK composition

Keep BPC and TSK standalone. Any bridge must require BPC v2, use a server-controlled binding, preserve each factor’s secret domain and replay semantics, and never call the combination a new encryption primitive. See [the version-pinned handoff](docs/BPC_TSK_COMPOSITION_HANDOFF.md).

## License

MIT. See [LICENSE](LICENSE).
