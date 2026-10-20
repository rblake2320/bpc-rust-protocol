# BPC + TSK Rust composition handoff

## Starting point

Use these two **standalone** protocol repositories as immutable baselines for the composition work:

| Component | Repository | Pin for the new chat |
| --- | --- | --- |
| BPC Rust | <https://github.com/rblake2320/bpc-rust-protocol> | `c4779b592e3340da3fed002e13e8655ddd423941` |
| TSK Rust | <https://github.com/rblake2320/tsk-rust-protocol> | `c050aa17361afdf819700029f09669e9cbbc576f` |

Both repositories are private. The BPC repository is a self-contained BPC v1 crate with production Axum/Redis/PostgreSQL adapters. The current TSK Rust checkpoint is deliberately **not production-ready**; its own README lists parity gates that must remain visible in any combined release decision.

## Target architecture

Create a **third, private bridge repository** — recommended name: `bpc-tsk-bridge` — instead of merging BPC and TSK into either protocol crate.

```text
bpc-protocol (standalone)  ─┐
                            ├── bpc-tsk-bridge (combined policy + adapters)
 tsk-rust-protocol (standalone) ─┘
```

The bridge may depend on the pinned releases of both crates. Neither standalone crate may depend on the other, import the other’s secret types, or change its v1 wire format merely to support composition. The bridge owns HTTP orchestration, durable principal/binding policy, combined audit records, and application-facing authorization snapshots.

## Non-negotiable security contract

1. **Do not invent a new “ultra encryption” primitive.** This is defense in depth through independent authenticators. Use TLS 1.3 for transport confidentiality; use standard AEAD/KMS only for separately stored encrypted data. Never concatenate, XOR, or cross-derive BPC and TSK secrets.
2. **Keep secret domains separate.** BPC registration secret/HMAC material, BPC private P-256 keys, and TSK shared credentials remain in their own stores, access controls, rotation processes, and logs.
3. **Use a server-controlled identity binding.** Persist an append-only/revisioned mapping of `{bpc_pair_id, tsk_client_id, principal_id, binding_revision, status}` in the bridge authority. It must be created by privileged control-plane workflow, never asserted by client headers.
4. **Require both factors.** On a protected combined endpoint: validate BPC first against exact raw method, `path_and_query`, and body bytes; load the durable active binding; require the submitted TSK client ID to equal the mapped ID; validate/commit TSK; then expose a combined application snapshot. Any failure denies the request.
5. **No rollback of spent security artifacts.** A valid BPC nonce or TSK HOTP value consumed before the other factor fails remains consumed. Do not retry or compensate it. The business side effect happens only after both factors succeed and must use a separate server-side idempotency/transaction boundary.
6. **Be precise about request binding.** BPC v1 cryptographically binds method/path/body. The current TSK v1 checkpoint authenticates its header credential but does not independently bind those request fields. The bridge must describe TSK as an independent second factor — not a second message signature. Any TSK request-context binding requires a versioned TSK protocol evolution with explicit cross-language vectors.
7. **Fail closed on authority uncertainty.** Preserve BPC’s Redis continuity quarantine and PostgreSQL final-claim semantics. Port TSK’s required durable/HA gates before claiming the combined bridge is production-ready. Do not use process-local maps or mock-only tests as authority.
8. **Audit without secrets.** Emit one correlation ID and a domain-separated request-context digest to protected audit systems. Never record raw BPC signatures, signed payloads, JWKs, registration secrets, or TSK keys.

## Required bridge surfaces

The new chat should implement, test, and document these boundaries:

- `BindingStore`: atomic lookup/revision/revoke of BPC-pair ↔ TSK-client ↔ principal mappings.
- `CombinedVerifier`: an HTTP-agnostic coordinator accepting exact request data and producing either a generic denial or immutable `{principal_id, bpc_snapshot, tsk_client_id, binding_revision, correlation_id}`.
- HTTP adapter: reject duplicate authentication headers, preserve raw body bytes, never disclose factor-specific errors to untrusted callers, and add protected telemetry only.
- Durable storage: PostgreSQL migration/readiness/least-privilege plan; Redis only where a verifier’s real replay/fencing semantics require it.
- Lifecycle: revocation/rotation of either factor immediately invalidates the binding; principal/binding revision is rechecked at final decision time.
- Audit/outbox: record combined outcomes and failure classes without secrets; define handling for ambiguous database commits and delivery retries.

## Required test gate

Do not release the combined bridge until it has real-service tests covering at minimum:

- valid BPC + valid mapped TSK; each factor alone; factor-ID swap; inactive/revoked/revision-mismatched binding;
- altered body/path/method, duplicate headers, malformed payloads, stale BPC timestamps, TSK HOTP replay, BPC nonce replay, and concurrent mixed replays;
- both ordering cases where a successfully consumed first factor is followed by a failed second factor;
- concurrent revocation/rotation/binding revision races against verification;
- PostgreSQL serialization/ambiguous-commit behavior and Redis continuity loss/quarantine;
- audit redaction, correlation, and external-anchor verification;
- JavaScript/TypeScript reference interoperability plus Rust unit/integration tests.

## Ready-to-paste prompt for the new chat

```text
Build a third private Rust repository named bpc-tsk-bridge that composes, but does not merge, these standalone repositories:

- BPC: https://github.com/rblake2320/bpc-rust-protocol at commit c4779b592e3340da3fed002e13e8655ddd423941
- TSK: https://github.com/rblake2320/tsk-rust-protocol at commit c050aa17361afdf819700029f09669e9cbbc576f

Read docs/BPC_TSK_COMPOSITION_HANDOFF.md from the BPC repository before coding. Preserve both protocol crates as standalone packages with no circular dependency. The new bridge owns a durable server-controlled mapping from BPC pair ID to TSK client ID to principal ID, combined verification, generic public failures, protected audit correlation, and real PostgreSQL/Redis tests.

Use BPC first to bind exact method/path/body and consume its nonce; then check the active binding and TSK credential. Both factors are required. Do not combine or derive cryptographic secrets across protocols, do not call it “ultra encryption,” do not roll back a consumed nonce/HOTP value, and do not claim production readiness until TSK’s documented durable/HA parity gates have been completed. Use TLS 1.3 for transport confidentiality and standard AEAD/KMS only for separately encrypted storage.

Deliver the bridge as a third private repo with architecture docs, an ADR, threat model, migration plan, CI, independent vectors, adversarial race tests, and a production-readiness checklist.
```
