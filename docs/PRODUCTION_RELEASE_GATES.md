# Production release gates

## Status

This crate is a security-hardened implementation and test artifact. It is **not** an authorization to claim that a deployment, a BPC–TSK composition, or a downstream application is independently security-vetted. Passing the repository test suite validates the exercised invariants; it does not replace an independent audit, a real infrastructure review, or operational drills.

## Gates required before a production release claim

All items below need recorded evidence for the exact release commit and deployment configuration.

1. **Repository integrity and review**
   - Activate the reviewed CI definition at `.github/workflows/ci.yml`, require it in branch protection, and require review by a security owner for `src/crypto.rs`, `src/verifier.rs`, `src/postgres_store.rs`, `src/redis_store.rs`, `src/axum.rs`, and protocol-vector changes.
   - Keep actions pinned to commit SHAs and service images pinned to digests. Use a reviewed dependency-update workflow and investigate every advisory before release.
   - Generate and retain an SBOM, release provenance, signed release artifacts, exact `Cargo.lock`, and the Node/Python/TypeScript compatibility reference revisions.

2. **Independent security assessment**
   - Commission a cryptographic/application security review of the exact protocol version, Rust implementation, HTTP adapters, error behavior, and deployment configuration.
   - Perform source-assisted penetration testing that covers pair enrollment, secret/key custody, proxy behavior, redirect handling, replay, race conditions, denial of service, canaries, management operations, and incident response.
   - Add a responsible disclosure contact and triage/revocation runbook before public deployment.

3. **Transport, identity, and custody**
   - Use `connect_tls` with PostgreSQL `sslmode=verify-full`, a trusted CA, hostname verification, least-privilege roles, connection/statement timeouts, backups, and restore/failover drills.
   - Use a dedicated Redis tenancy with `rediss://`, ACLs, `noeviction`, persistence/failover policy, continuity epoch management, alarms, and restore/epoch-mismatch drills.
   - Obtain the `PostgresSecretProtector` AES-256 key from a KMS/HSM-backed secret manager; define an auditable re-encryption key-rotation procedure. Keep P-256 private keys and registration secrets out of source, logs, browser bundles, and ordinary process configuration where stronger custody is available.

4. **Edge resilience and HTTP behavior**
   - Put an authenticated, rate-limited management/enrollment boundary in front of `request_pairing`; the global pending cap is only a final backstop.
   - Enforce reverse-proxy/server connection, header, request-body-read, and upstream timeouts; trusted-source/IP rate limits; request concurrency limits; and body-size limits before expensive verification.
   - Preserve BPC's exact raw `path_and_query` and body bytes across TLS termination and proxies. Do not deploy streaming uploads under BPC v1 without a separately reviewed, versioned digest protocol.

5. **Audit, monitoring, and incident response**
   - Wire verified/rejected requests, ghost-pair hits, pair lifecycle operations, replay-store quarantine, and security alerts to a sanitized protected telemetry sink. Never record registration secrets, raw signatures, signed payloads, request bodies, or raw verifier keys.
   - Externally anchor audit heads in independent/KMS/WORM-controlled storage and alert on anchor delay, mismatch, tail loss, or verification failure. Prove the runtime role cannot update or delete audit rows.
   - Drill key compromise, secret compromise, ghost-pair detection, pair revocation, Redis continuity failure, PostgreSQL ambiguous outcome/failover, and restore scenarios.

6. **Evidence-driven testing**
   - Run the locked all-feature suite with real Redis/PostgreSQL, Node WebCrypto interoperability, format, Clippy, and advisory scans.
   - Add pinned randomized differential vectors against maintained TypeScript and Python BPC references; include malformed JWK/base64/canonical JSON/UUID/path mutation corpora.
   - Run property/fuzz testing for untrusted parser and header input, concurrency/race stress for final claims/revoke/rotation, load tests for rate limits/body buffering, and fault injection for Redis/PostgreSQL timeouts, failover, and ambiguous commit outcomes.

## BPC–TSK composition rule

BPC and TSK must remain independently versioned, reviewed, deployed, and revocable. Neither project is eligible for a high-assurance combined release unless each standalone repository has the same class of evidence: documented cryptographic work factors and algorithm limits, real durable-backend tests where it claims durable behavior, replay/race/failure-injection coverage, transport/key-custody controls, canary/tamper/incident controls where applicable, supply-chain gates, fuzz/property testing, and an independent assessment of its exact release.

A combined policy must require each factor's final verification result and bind the same request identity, audience/origin, environment, time window, nonce/replay semantics, operation ID, and failure policy. Do not share private keys, registration secrets, mutable counters, or durable databases by convenience. The composed protocol requires a new threat model, test vectors, downgrade/confusion tests, and an independent review; it is not automatically secured by either standalone crate.
