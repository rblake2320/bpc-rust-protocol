# BPC cryptographic assurance and future high-assurance design

BPC v1 is a layered request-authentication protocol. A request needs a registered public key, the client-held registration-secret factor, exact method/path/body binding, a fresh nonce and timestamp, an allowed scope, and a successful final durable-use claim. The Redis continuity guard, PostgreSQL authorization fencing, rotation, canary pairs, generic public errors, audit chain, and transport controls are part of that defense. They are not replaced by stronger mathematics.

This document states the actual work factors of legacy v1 and implemented v2, then records a future post-quantum high-assurance proposal. It does not certify a deployment and does not call any algorithm “unhackable.”

## Legacy v1 work factors

BPC v1 uses ECDSA P-256 with SHA-256 for the request signature. NIST assigns P-256 approximately 128 bits of classical security; generic discrete-log recovery uses work on the order of the square root of a roughly 256-bit group order, or about \(2^{128}\) group operations. NIST assigns P-521 approximately 256 bits because its group order is at least 512 bits.[1] [2]

The request-HMAC key is 32 bytes and BPC emits the full 32-byte HMAC-SHA-256 tag. A direct blind tag forgery has probability approximately \(q / 2^{256}\) after \(q\) independent classical attempts. That is only a 256-bit claim when the source secret/key is itself unpredictable at 256 bits. HKDF preserves and separates source entropy; it cannot create entropy from a memorable phrase. NIST likewise ties MAC assurance to the HMAC key, underlying hash, tag length, and number of failed verification attempts.[3]

SHA-256 gives about \(2^{256}\) generic preimage or fixed-target second-preimage work, but a generic collision costs about \(2^{128}\). The current `body_hash` is collision-sensitive request binding, and ECDSA signs a SHA-256 digest. For that reason v1 cannot honestly claim 256-bit arbitrary-message integrity even when its HMAC factor is generated randomly.

The UUID-v4 nonce, timestamp, and 60-second freshness window are crucial replay controls. They are not secret entropy: an attacker can choose a fresh syntactically valid nonce and current timestamp. The actual online HMAC guess budget is defined by rate limiting at the edge and verifier boundary.

Here are transparent scale conversions, not hardware forecasts. \(2^{128}\) is approximately \(3.40\times10^{38}\) operations. Even at an imaginary sustained \(10^{18}\) relevant operations per second, it corresponds to about \(1.08\times10^{13}\) years. \(2^{256}\) is approximately \(1.16\times10^{77}\) operations, or about \(3.67\times10^{51}\) years at the same rate. Those figures do not establish a security guarantee: cryptanalytic advances, endpoint compromise, side channels, leaked verifier material, supply-chain compromise, and quantum algorithms do not behave like brute-force throughput.

The factors are independent only when their secrets and custody boundaries are independent. With no factor leakage, recovering a P-256 signing key and a truly random 256-bit HMAC source costs roughly \(2^{128}+2^{256}\), dominated by the latter. That is not a 256-bit signature claim. If the server-held HMAC verifier leaks, it is directly usable to compute HMACs and the remaining public-key barrier is P-256 at 128 bits. If a human-selected source secret is weak, its entropy \(e\), not the 32-byte HKDF output length, bounds an offline source-secret search at approximately \(2^e\).

The Rust crate now improves this immediately. `generate_registration_secret()` produces `Aa0!!` followed by an unfiltered encoding of 32 operating-system-random bytes. The fixed prefix satisfies the legacy v1 character policy without rejection sampling, so the random component retains exactly 256 bits. The Rust signer, direct HKDF helper, and Reqwest client reject source secrets that do not meet the documented legacy policy. This is a real improvement, but already-enrolled pairs and non-Rust clients need explicit rotation/adoption; the server sees only a derived verifier key and cannot prove a client chose a random source secret.

## Implemented BPC v2 profile and its honest limits

The released BPC v2 profile fixes v1’s request-HMAC transplant weakness without misrepresenting a future algorithm migration. It keeps ECDSA P-256/SHA-256, SHA-256 body commitments, 32-byte HMAC-SHA-256 verifier keys, and UUID-v4 nonces. Its required canonical core is `audience`, `body_hash`, `method`, `mode`, `nonce`, `pair_id`, `path`, `purpose`, `timestamp`, and `version`; `version` is `2.0` and `purpose` is `http-request`.

It calculates `HMAC-SHA-256(K_v2, "BPC-HMAC-v2\\0" || canonical_core)`, where `K_v2` is an HKDF-SHA-256 derivation with v2-specific salt/info labels. The P-256 P1363 signature authenticates `"BPC-SIGN-v2\\0" || canonical_core || "\\0" || base64url(hmac)`. Thus modifying any core field requires both factors; possession of a P-256 key alone cannot transplant a captured HMAC. BPC v2 rejects v1 by default and pair policy is stored server-side.

This is still approximately a **128-bit classical** public-key profile and it is **not post-quantum**. If the server-held HMAC verifier leaks, the signature path remains P-256; if the client P-256 key leaks, the HMAC source remains the independent barrier. Endpoint compromise, rate-limit failure, secret custody failure, and a cryptographically relevant quantum computer remain outside a mathematical brute-force claim.

## Concrete v1 limits that required a versioned change

The current wire format does not cryptographically bind an audience/origin. The bundled Reqwest transport pins an HTTPS origin, but a raw v1 signature does not carry the intended service/tenant/environment. Pair credentials must therefore never be copied across audiences, and the BPC–TSK bridge must bind a server-controlled audience outside the v1 signature until v2 is available.

The v1 HMAC covers only `nonce || decimal(timestamp)`. It proves possession of the HMAC factor but does not independently bind method, path, body hash, audience, or scope. If an attacker has the P-256 private key or a signing oracle and captures a still-fresh legitimate HMAC, the attacker can re-sign an altered payload using that HMAC and race it as the first use of the nonce. That is a reason to protect both factors and use one-time replay storage now. It is also a reason for v2 to MAC the complete request transcript.

The stable display fingerprint is intentionally truncated to 20 base64url characters, or 120 bits. It is acceptable for logs and UI correlation only. It must never become an authorization decision, key-equality check, or approval identifier.

NIST states that FIPS 186-5 signature algorithms are not expected to resist a large-scale quantum computer.[2] A cryptographically relevant quantum computer would use Shor’s algorithm against P-256 and P-521 rather than merely halve their security. Ideal Grover-style search changes a 256-bit symmetric/preimage search to order \(2^{128}\) coherent evaluations, while generic collision algorithms have different bounds. This document makes no timeline claim about quantum hardware.

## Future high-assurance BPC v3 proposal (not implemented)

A future BPC-HYB v3 profile must be a new parser, header family, registry record, test-vector corpus, and deployment cutover. It must never be implemented as optional v2 fields, a fallback after v3 verification fails, or an algorithm negotiated from unauthenticated request data.

The primary high-assurance suite is:

```text
suite = BPC-HYB-v2-P521-SHA512-MLDSA87-PURE
classical signature = ECDSA P-521 / SHA-512, 132-byte fixed-width P1363 r || s
post-quantum signature = ML-DSA-87, pure signing mode, fixed nonempty context
body commitment = SHA-512
request MAC = HMAC-SHA-512 with a 64-byte randomly generated source secret
nonce = 32 random bytes, encoded base64url
```

P-521 with SHA-512 removes the v1 P-256/SHA-256 128-bit classical ceiling for the classical signature path. ML-DSA-87 is the FIPS 204 category-5 parameter set. Its public key is 2,592 bytes and its signature is 4,627 bytes, so v2 must explicitly support bounded larger headers or a structured authenticated envelope; it cannot fit v1’s signature limits.[3]

A hybrid is accepted only if every component verifies:

\[
\operatorname{accept} \iff \operatorname{Verify}_{P521}(T,\sigma_c) \land \operatorname{Verify}_{MLDSA87}(T,\sigma_{pq}) \land \operatorname{Verify}_{HMAC}(C,\tau).
\]

The expression is not additive “512-bit security.” It requires an adversary to defeat both signature components for a signature forgery, while the surviving component defines protection after the other algorithm is broken. It also increases implementation complexity, which must be independently reviewed.[4]

## Future v3 transcript and request binding

The future v3 profile must construct a flat, length-bounded, byte-for-byte canonical core object `C` with these required fields:

```text
algorithm_suite, audience, body_hash, environment, keyset_id, method,
nonce, pair_id, path, purpose, timestamp, version
```

`audience` is a locally configured exact service/tenant identity such as `bpc://api.example.example/tenant-42`. `environment` separates production, staging, and other security domains. `purpose` is the exact operation family such as `http-request`. Wildcards, untrusted routing headers, and caller-supplied expected audiences are prohibited.

The request MAC is calculated over the complete canonical core, not only nonce/time:

```text
mac_input = "BPC-HMAC-v2\0" || canonical(C)
secret_hmac = base64url(HMAC-SHA-512(hmac_key, mac_input))
T = "BPC-SIGN-v2\0" || canonical(C) || "\0" || secret_hmac
```

Both signatures authenticate the exact same `T`. The ML-DSA-87 context is a fixed, nonempty context derived from the literal suite and purpose. A streaming or prehashed profile must have another immutable suite identifier and follow FIPS 204’s dedicated HashML-DSA rules; it cannot silently sign an arbitrary application digest with a pure-ML-DSA key.[3]

The verifier must load an authorized dual-keyset record by `pair_id`, compare `keyset_id`, suite, audience, environment, and v2-only policy before expensive verification, then require valid HMAC, SHA-512 body commitment, P-521 signature, ML-DSA signature, freshness, scope, and atomic nonce claim. Any missing, malformed, unknown, or failed component is a generic fail-closed denial.

## Enrollment, downgrade, and custody rules

A dual-keyset record binds exactly one pair ID, one suite, one P-521 public key, one ML-DSA-87 public key, one keyset hash, one audience, one environment, activation/retirement epochs, and a minimum protocol version. A key ID is only a lookup hint. The authority record, not attacker-supplied headers, binds both keys to the same principal.

Once a pair becomes v3-active, v2 is rejected for that pair. A v3 failure must never retry as v2. Capability negotiation, if needed, belongs in an authenticated enrollment/control-plane exchange and its resulting suite/version policy belongs in the authority record. Existing v2 credentials need a separately approved rotation/re-enrollment ceremony; there is no safe transparent upgrade from a P-256-only public key to a hybrid keyset.

Generate the P-521 key, ML-DSA seed/key, and HMAC source independently. Do not derive multiple factor secrets from a shared seed or reuse a signing key for another purpose. Keep each secret in a separate access-controlled custody domain where possible. Treat the ML-DSA seed as full private-key material. Audit keyset changes, enforce dual control for high-value changes, and make revocation and rotation actionable without waiting for model-assisted triage.

Laya may classify sanitized, post-decision security telemetry for a human queue. It must never choose a cryptographic suite, authorize a request, handle key material, decide replay validity, or downgrade a failure. A model confidence value is not cryptographic evidence.[5]

## Implementation release gate

Do not add an unaudited pure-Rust post-quantum crate to the production BPC path merely because it compiles. The current RustCrypto `ml-dsa` documentation explicitly says it has not been independently audited.[6] A v2 implementation needs a reviewed signing provider, final NIST ACVP vectors for P-521 and ML-DSA-87, independent cross-implementation vectors, malformed key/signature/parser fuzzing, mixed-keyset substitution tests, audience/environment/purpose mutation tests, replay/race tests, downgrade tests, header/proxy-size tests, performance/load tests, and an independent cryptographic/application review of the exact release.

The standalone BPC and TSK repositories must each meet equivalent evidence gates before any bridge is called high assurance. A combined BPC–TSK service adds a third threat model and must require both standalone final decisions over the same audience, environment, operation identity, time window, and failure policy. It must not reuse their keys, secrets, nonce stores, databases, or mutable counters for convenience.

## References

[1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf "NIST SP 800-186 elliptic curve domain parameters"
[2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf "FIPS 186-5 Digital Signature Standard"
[3]: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf "FIPS 204 Module-Lattice-Based Digital Signature Standard"
[4]: https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF "NSA CNSA Suite 2.0 and Quantum Computing FAQ"
[5]: https://huggingface.co/convaiinnovations/laya "Laya model card"
[6]: https://docs.rs/ml-dsa/latest/ml_dsa/ "RustCrypto ML-DSA documentation"
