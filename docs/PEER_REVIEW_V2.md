# Independent adversarial peer review: BPC Rust v2

Review the exact commit linked from this document's repository history. Treat every claim as untrusted. Do not accept documentation, passing unit tests, or an earlier review as proof.

## Scope

This is a Rust implementation of BPC v2, a two-factor HTTP request authentication protocol. The repository must remain standalone; a future BPC–TSK bridge is out of scope except where BPC’s public contract affects it.

### Primary review targets

1. **BPC v2 request transcript.** Confirm that a request’s canonical core has exactly these ordered JSON fields: `audience`, `body_hash`, `method`, `mode`, `nonce`, `pair_id`, `path`, `purpose`, `timestamp`, `version`. Check that the HMAC covers `BPC-HMAC-v2\0 || core`, and the P-256 P1363 signature covers `BPC-SIGN-v2\0 || core || \0 || X-BPC-HMAC`. Attempt tag transplant after each field change, including with a simulated P-256 key compromise. Verify no untrusted version fallback accepts a v1 payload.
2. **Parsing and HTTP boundaries.** Attack duplicate/missing headers, alternate Base64, JSON duplicate keys/reordering/whitespace/escaping, invalid UUID variants, alternate body hashes, percent-encoding/path confusion, request-target mismatch, host/origin redirects, very large headers/bodies, and stalled bodies. Verify exact raw method/path/body handling from Axum and Reqwest.
3. **Credential exposure.** Prove that `PairRecord`, `PairRegistration`, and `PendingPairing` cannot emit request-HMAC verifier material through `Debug`, `Display`, Serde, errors, redacted management APIs, or a PostgreSQL pending registration JSON blob. Review clones and decrypted temporary buffers for secret handling.
4. **Replay/durability.** Test races, fresh/replay/timeout paths, pair-scoped nonce identity, ghost pairs, Redis eviction policy, replica acknowledgements, Redis server time, missing/changed marker/config, and a marker-preserved nonce-key rollback. Confirm that Redis does not claim to prove its own history and that only a durable anchor independent of Redis backup/restore can establish a recovery generation. Look for race windows between anchor advance, Redis generation checks, and in-flight consumers.
5. **Authority/lifecycle.** Test enrollment capacity/expiry, approval token handling, PostgreSQL migration on an existing database, at-rest AEAD contexts, revocation lineage, rotation, audience/mode/request-protocol changes racing final claim, usage caps, and finalization failures after nonce consumption. A rejected final claim must not suggest replaying signed headers.
6. **Crypto and dependency design.** Review P-256 P1363 parsing, HKDF labels, HMAC constant-time comparison, AES-GCM nonce and AAD construction, RustCrypto versions, unsafe surface, MSRV 1.85.0, Cargo lock/policy, workflow SHA/image pins, and test vector compatibility. Do not label this P-256 profile post-quantum or “unbreakable.”

## Required review method

- Read `README.md`, `SECURITY.md`, `docs/PRODUCTION_RELEASE_GATES.md`, and `docs/BPC_CRYPTOGRAPHIC_ASSURANCE.md` first, then compare claims to implementation.
- Run the full commands below in a clean checkout. Build a local CA-signed PostgreSQL endpoint with `DNS:localhost` only; test both `localhost` (success) and `127.0.0.1` (hostname failure).
- Add or run property/fuzz tests around every parser and byte boundary. Use independent Node WebCrypto or another interoperable implementation to reproduce the exact v2 HMAC and signature transcript.
- If you find a defect, give a minimal reproducible test and rate impact, exploit prerequisites, affected boundary, and a patch proposal. Do not report hypothetical concerns without locating the relevant code path.

```bash
cargo +1.85.0 fmt --check
cargo +1.85.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.85.0 test --locked --test protocol --features axum --test axum_integration --test untrusted_input_properties
node scripts/generate-node-fixture.mjs
node scripts/verify-node-interop.mjs
# Set all three real-service endpoint variables described in README, then:
cargo test --locked --features live-integration --test live_backends
cargo test --locked --features live-integration --test postgres_tls
cargo audit --deny warnings
cargo deny check all
cargo fuzz run untrusted_input -- -max_total_time=300 -timeout=5
```

## Ready-to-paste review prompt

```text
Perform an adversarial, evidence-based security review of the BPC Rust v2 repository at the exact commit I provide. Assume that a serious defect may remain. Do not merely summarize. Clone it, compile it, run the stated tests, inspect every authentication/persistence/HTTP/replay code path, and write additional targeted tests or fuzz cases where useful.

Try to break BPC v2 request binding by changing every canonical field while reusing a captured HMAC, including a scenario where the P-256 signing key is compromised. Attack downgrade/version dispatch, parser canonicalization, duplicate headers, raw path/body handling, HMAC-key exposure through Rust APIs/Serde/Debug/logging, PostgreSQL AEAD/migrations, rotation/revocation/finalization races, Redis rollback and anchor generation logic, CI/supply-chain controls, and TLS hostname verification.

Report only reproducible findings with severity, exact file/line/code path, exploit conditions, proof/test, and concrete patch. Explicitly distinguish properties a protocol crate proves from operational assumptions it cannot prove. Do not call P-256 “post-quantum,” “unbreakable,” or an encryption primitive.
```
