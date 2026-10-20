use uuid::{Uuid, Variant, Version};

use crate::{
    AuthSnapshot, BPC_PROTOCOL_VERSION, BpcRequest, NonceStore, PairKind, PairRegistry, PairStatus,
    SuccessClaim, VerificationError, VerificationResult, body_hash, is_valid_pair_id,
    parse_canonical_payload, verify_payload_bytes, verify_request_hmac,
};

const MAX_SIGNATURE_LEN: usize = 256;
const MAX_SIGNED_DATA_LEN: usize = 4096;

/// Portable BPC verifier settings.
#[derive(Clone, Debug)]
pub struct BpcVerifierConfig {
    /// Permitted difference between verifier and client clocks, in milliseconds.
    pub signature_window_ms: u64,
    /// Number of invalid P-256 signatures with a valid secret-HMAC factor before
    /// a pair locks. Zero disables credential lockout; edge rate limiting still
    /// applies to every denial.
    pub lockout_after: u32,
}

impl Default for BpcVerifierConfig {
    fn default() -> Self {
        Self {
            signature_window_ms: 60_000,
            lockout_after: 10,
        }
    }
}

/// Framework-independent BPC verifier.
///
/// It deliberately does not parse HTTP headers or perform rate limiting. HTTP
/// adapters should pass the exact method, path, and unmodified body bytes, and
/// should apply their own rate controls before calling this verifier.
#[derive(Clone, Debug, Default)]
pub struct BpcVerifier {
    config: BpcVerifierConfig,
}

impl BpcVerifier {
    pub fn new(config: BpcVerifierConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &BpcVerifierConfig {
        &self.config
    }

    /// Verifies against the current Unix time.
    pub fn verify<R: PairRegistry, N: NonceStore>(
        &self,
        request: BpcRequest<'_>,
        registry: &R,
        nonce_store: &N,
    ) -> VerificationResult {
        match crate::unix_ms() {
            Ok(now_ms) => self.verify_at(request, registry, nonce_store, now_ms),
            Err(_) => VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidSignedData,
            ),
        }
    }

    /// Verifies at a supplied Unix timestamp for deterministic integrations and tests.
    pub fn verify_at<R: PairRegistry, N: NonceStore>(
        &self,
        request: BpcRequest<'_>,
        registry: &R,
        nonce_store: &N,
        now_ms: u64,
    ) -> VerificationResult {
        if request.pair_id.is_empty()
            || request.signature.is_empty()
            || request.signed_data.is_empty()
        {
            return VerificationResult::denied(None, VerificationError::MissingHeaders);
        }
        if !is_allowed_method(request.method) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidMethod,
            );
        }
        if !is_valid_pair_id(request.pair_id)
            || request.signature.len() > MAX_SIGNATURE_LEN
            || request.signed_data.len() > MAX_SIGNED_DATA_LEN
        {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidSignedData,
            );
        }
        if request.version != BPC_PROTOCOL_VERSION {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::VersionMismatch,
            );
        }

        let pair = match registry.get(request.pair_id) {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::UnknownPair,
                );
            }
            Err(_) => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::PairStateChanged,
                );
            }
        };
        match pair.status {
            PairStatus::Active => {}
            PairStatus::Revoked => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::PairRevoked,
                );
            }
            PairStatus::Locked => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::PairLocked,
                );
            }
            PairStatus::Expired => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::PairExpired,
                );
            }
            PairStatus::Rotated => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::PairRotated,
                );
            }
        }
        if self.config.lockout_after > 0 && pair.failed_signatures >= self.config.lockout_after {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairLocked,
            );
        }
        if pair
            .expires_at_ms
            .is_some_and(|expires_at| now_ms > expires_at)
        {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairExpired,
            );
        }
        if pair
            .max_requests
            .is_some_and(|cap| cap > 0 && pair.requests >= cap)
        {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairUsageCapExceeded,
            );
        }

        let (payload, canonical) = match parse_canonical_payload(request.signed_data) {
            Ok(parsed) => parsed,
            Err(_) => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::InvalidSignedData,
                );
            }
        };
        match Uuid::parse_str(&payload.nonce) {
            Ok(nonce)
                if nonce.get_version() == Some(Version::Random)
                    && nonce.get_variant() == Variant::RFC4122 => {}
            _ => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::InvalidSignedData,
                );
            }
        };
        if !verify_request_hmac(
            &pair.request_hmac_key,
            &payload.nonce,
            payload.timestamp,
            &payload.secret_hmac,
        ) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidSecretHmac,
            );
        }
        if now_ms.abs_diff(payload.timestamp) > self.config.signature_window_ms {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::TimestampExpired,
            );
        }
        if payload.method != request.method || payload.path != request.path {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::MethodPathMismatch,
            );
        }
        if payload.pair_id != request.pair_id {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairIdMismatch,
            );
        }
        if !pair.scope.allows(request.method) || !pair.scope.allows(&payload.method) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::ScopeViolation,
            );
        }
        if payload.body_hash.is_empty() {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::MissingBodyHash,
            );
        }
        if payload.body_hash != body_hash(request.body) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidBodyHash,
            );
        }
        let verifying_key = match pair.public_jwk.to_verifying_key() {
            Ok(key) => key,
            Err(_) => {
                return self.reject_authenticated_signature_failure(
                    registry,
                    request.pair_id,
                    VerificationError::InvalidSignature,
                );
            }
        };
        if !verify_payload_bytes(&verifying_key, &canonical, request.signature) {
            return self.reject_authenticated_signature_failure(
                registry,
                request.pair_id,
                VerificationError::InvalidSignature,
            );
        }

        // Only a fully verified request is permitted to consume its nonce.
        let ttl_ms = self
            .config
            .signature_window_ms
            .saturating_mul(2)
            .saturating_add(10_000);
        let replay = match nonce_store.check_and_consume(&payload.nonce, now_ms, ttl_ms) {
            Ok(replay) => replay,
            Err(_) => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::ReplayStoreUnavailable,
                );
            }
        };
        if replay {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::ReplayDetected,
            );
        }

        // A canary request proves credential exposure. Its nonce is intentionally
        // spent after full verification, but it never produces authorization.
        if pair.kind == PairKind::Ghost {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::GhostPairDenied,
            );
        }

        // Reclaim registry state atomically after crypto verification. A durable
        // registry should re-check expiry/status/usage under its own transaction.
        match registry.claim_success(&pair, now_ms) {
            Ok(SuccessClaim::Claimed) => VerificationResult::authorized(AuthSnapshot {
                pair_id: request.pair_id.to_owned(),
                scope: pair.scope,
                mode: pair.mode,
                kind: pair.kind,
                canary_class: pair.canary_class,
                verified_at_ms: now_ms,
            }),
            Ok(SuccessClaim::Expired) => {
                VerificationResult::denied(Some(request.pair_id), VerificationError::PairExpired)
            }
            Ok(SuccessClaim::UsageExhausted) => VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairUsageCapExceeded,
            ),
            Ok(SuccessClaim::StateChanged) | Err(_) => VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairStateChanged,
            ),
        }
    }

    /// Only a request that has already proven the independent secret-HMAC
    /// factor may affect credential-wide signature lockout state. All earlier
    /// malformed or unauthenticated traffic must be handled by edge/source rate
    /// limits, never by a pair-ID-controlled persistent lockout.
    fn reject_authenticated_signature_failure<R: PairRegistry>(
        &self,
        registry: &R,
        pair_id: &str,
        error: VerificationError,
    ) -> VerificationResult {
        let _ = registry.record_failure(pair_id, self.config.lockout_after);
        VerificationResult::denied(Some(pair_id), error)
    }
}

fn is_allowed_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE"
    )
}
