# Independent security peer review package

This document is intentionally written for a hostile, independent reviewer. Treat the Rust crate as security-sensitive authentication infrastructure. Do not trust this checklist as a substitute for finding novel failures.

## Review target

- Repository: `https://github.com/rblake2320/bpc-rust-protocol`
- Package: `bpc-protocol`
- Compatibility base: BPC v1 request signing, with hardened authority and transport adapters.
- Primary source: `src/`
- Security regressions: `tests/protocol.rs`, `tests/axum_integration.rs`, `tests/live_backends.rs`, `tests/untrusted_input_properties.rs`
- Fuzzer: `fuzz/fuzz_targets/untrusted_input.rs`

Review the specific commit supplied with the review request, not an unpinned branch state. The repository is private at the time this document was written; a reviewer must be granted repository access or be given an audited source archive.

## Required review posture

Assume an attacker may:

1. Send arbitrarily malformed, oversized, ambiguous, duplicate, or slow HTTP requests.
2. Know a pair ID, public P-256 key, old request headers, a request HMAC tag, or an old signed payload.
3. Replay valid traffic concurrently and attempt cross-pair nonce collision.
4. Compromise a non-authoritative application tier, a network path, a Redis primary, or a PostgreSQL node.
5. Attempt origin/path/request-target confusion, redirect header exfiltration, audience/environment confusion, rotation races, audit tampering, database ciphertext swapping, CI dependency substitution, and secret exfiltration.
6. Exploit language boundaries between Rust, Node WebCrypto, database schema behavior, and HTTP framework behavior.

Find and demonstrate any way to obtain authorization, weaken replay protection, persist an authorization after revocation, create an unsafe lifecycle transition, create an unbounded resource sink, disclose credential state, or bypass intended transport/at-rest protections.

## Mandatory attack checklist

### Protocol and cryptography

- Fuzz all public parsing and canonicalization boundaries; search for panics, overflows, allocation amplification, parser differentials, noncanonical encodings, Unicode confusion, and P-256 signature malleability.
- Verify the exact body, method, path-and-query, nonce, timestamp, and protocol version binding independently of the crate.
- Attempt to forge or transplant request HMACs, rotation HMACs, P-256 signatures, key fingerprints, JWK metadata, and public-key encodings.
- Verify that the rotation transcript is canonical, signed, UUID-v4 nonce-bound, HMAC-bound under a distinct domain label, key-changing, freshness-bounded, and cannot be applied twice.
- Confirm that the legacy BPC v1 wire format remains an interoperability mode, not a post-quantum claim. Review the separately documented versioned PQ migration design before accepting any `v2` claim.

### Authorization lifecycle and concurrency

- Race verify, revoke, rotate, expire, capacity checks, and request-count limits under high concurrency.
- Prove or break the authorization-version fence from signature verification through final use claim.
- Verify an ancestor revoke revokes every reachable successor through the `replaced_by` lineage.
- Verify expired pairs leave capacity and never regain authorization.
- Verify pair-scoped nonce namespacing permits two distinct pairs to use the same UUID but rejects replay for either individual pair.
- Ensure invalid or replayed traffic cannot lock a credential; control abuse should be handled by a trusted, source-aware edge limiter.

### Service adapters and durability

- Send slow/chunked, mismatched-length, malformed-header, compressed, or oversize requests through Axum. Verify the body and blocking-verification permit bounds remain effective even after a timeout.
- Verify BPC outbound headers cannot leave the pinned HTTPS origin through redirects or URL/path normalization tricks, and that all requests have bounded connect, total, and read timeouts.
- Attempt Redis restart, partial replication, write loss, configuration drift, eviction, server-time rollback, and failover during nonce claim. A production configuration must use TLS, positive replica acknowledgements, and fail closed on uncertainty.
- Attempt PostgreSQL plaintext remote transport, weak TLS, ciphertext cut-and-paste, schema injection, transaction anomaly, replication lag, and audit head divergence. Production must use verified TLS, KMS-supplied envelope keys, and synchronous replication enabled in `PostgresAuthorityConfig`.

### Supply chain and release integrity

- Independently inspect `Cargo.lock`, `deny.toml`, package contents, Git history, fixtures, source provenance, pinned CI actions/images, and the external CI activation path.
- Re-run all security commands below in a clean checkout. Do not treat green tests as proof of security; report coverage gaps or assumptions.

## Reproduction commands

Use a clean checkout and stable Rust 1.85 or later for supported builds. The fuzzer requires nightly.

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --all-targets
cargo test --doc
cargo audit --deny warnings
cargo deny check all
node scripts/verify-node-interop.mjs
cargo +nightly fuzz run untrusted_input -- -max_total_time=300 -timeout=5
```

The real Redis/PostgreSQL tests deliberately fail instead of silently skipping when their endpoints are absent. For isolated local proof only, start disposable loopback services and use:

```bash
export BPC_TEST_REDIS_URL='redis://127.0.0.1:6381/'
export BPC_TEST_POSTGRES_URL='postgresql://bpcitest:bpcitest@127.0.0.1:5432/bpcitest'
cargo test --locked --all-features --test live_backends -- --nocapture
```

Use production TLS services and leave `min_replica_acks >= 1` plus `require_synchronous_replication = true` for a production deployment review. The loopback settings in the live test are explicit test-only exceptions, never a production recipe.

## Review-report template

For each issue include: exact pinned commit, severity and impact, preconditions, minimal reproduction, affected files/lines, whether it was independently verified, and a safe remediation. Do not include source secrets or live credentials in the report.
