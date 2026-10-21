use uuid::{Uuid, Variant, Version};

use crate::{
    AuthSnapshot, BPC_V2_PROTOCOL_VERSION, BpcError, BpcRequest, NonceStore, PairKind, PairMode,
    PairRegistry, PairRequestProtocol, PairStatus, Result, SuccessClaim, VerificationError,
    VerificationResult, body_hash_matches, is_valid_audience, is_valid_pair_id,
    parse_canonical_payload, verify_payload_bytes, verify_request_hmac,
};

const MAX_SIGNATURE_LEN: usize = 256;
const MAX_SIGNED_DATA_LEN: usize = 4096;
const MAX_HMAC_LEN: usize = 64;
/// Five minutes permits operational clock skew while bounding replay retention.
pub const MAX_SIGNATURE_WINDOW_MS: u64 = 5 * 60 * 1_000;

/// Portable BPC verifier settings. The default accepts only BPC v2.
#[derive(Clone, Debug)]
pub struct BpcVerifierConfig {
    signature_window_ms: u64,
    expected_audience: String,
    expected_mode: PairMode,
}

impl Default for BpcVerifierConfig {
    fn default() -> Self {
        Self::new("bpc://localhost/development", PairMode::Development)
            .expect("static local-development verifier configuration is valid")
    }
}

impl BpcVerifierConfig {
    /// Builds a verifier configuration bound to exactly one audience and mode.
    pub fn new(expected_audience: impl Into<String>, expected_mode: PairMode) -> Result<Self> {
        let expected_audience = expected_audience.into();
        if !is_valid_audience(&expected_audience) {
            return Err(BpcError::InvalidPayload("BPC audience is invalid".into()));
        }
        Ok(Self {
            signature_window_ms: 60_000,
            expected_audience,
            expected_mode,
        })
    }

    /// Sets a bounded request freshness window (1 ms through five minutes).
    pub fn with_signature_window_ms(mut self, value: u64) -> Result<Self> {
        if value == 0 || value > MAX_SIGNATURE_WINDOW_MS {
            return Err(BpcError::InvalidPayload(format!(
                "signature window must be between 1 and {MAX_SIGNATURE_WINDOW_MS} ms"
            )));
        }
        self.signature_window_ms = value;
        Ok(self)
    }

    pub fn signature_window_ms(&self) -> u64 {
        self.signature_window_ms
    }
    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }
    pub fn expected_mode(&self) -> PairMode {
        self.expected_mode
    }
}

/// Framework-independent BPC v2 verifier.
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

    /// Verifies at a supplied Unix timestamp for deterministic integrations/tests.
    pub fn verify_at<R: PairRegistry, N: NonceStore>(
        &self,
        request: BpcRequest<'_>,
        registry: &R,
        nonce_store: &N,
        now_ms: u64,
    ) -> VerificationResult {
        if request.pair_id.is_empty()
            || request.hmac.is_empty()
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
            || request.hmac.len() > MAX_HMAC_LEN
            || request.signature.len() > MAX_SIGNATURE_LEN
            || request.signed_data.len() > MAX_SIGNED_DATA_LEN
        {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidSignedData,
            );
        }
        // Version selection is closed: there is no downgrade fallback from a failed v2 request.
        if request.version != BPC_V2_PROTOCOL_VERSION {
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
        if pair.request_protocol != PairRequestProtocol::V2 {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::VersionMismatch,
            );
        }
        if pair.audience != self.config.expected_audience || pair.mode != self.config.expected_mode
        {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::AudienceMismatch,
            );
        }
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
                    && nonce.get_variant() == Variant::RFC4122
                    && nonce.to_string() == payload.nonce => {}
            _ => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::InvalidSignedData,
                );
            }
        }
        // The HMAC covers every canonical field below, including pair identity,
        // audience, mode, method, path, body commitment, purpose, and version.
        if !verify_request_hmac(&pair.request_hmac_key, &canonical, request.hmac) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidSecretHmac,
            );
        }
        if payload.audience != pair.audience
            || payload.audience != self.config.expected_audience
            || payload.mode != pair.mode
            || payload.mode != self.config.expected_mode
        {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::AudienceMismatch,
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
        if !body_hash_matches(&payload, request.body) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidBodyHash,
            );
        }
        let verifying_key = match pair.public_jwk.to_verifying_key() {
            Ok(key) => key,
            Err(_) => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::InvalidSignature,
                );
            }
        };
        if !verify_payload_bytes(&verifying_key, &canonical, request.hmac, request.signature) {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::InvalidSignature,
            );
        }
        let ttl_ms = match self
            .config
            .signature_window_ms
            .checked_mul(2)
            .and_then(|value| value.checked_add(10_000))
        {
            Some(value) => value,
            None => {
                return VerificationResult::denied(
                    Some(request.pair_id),
                    VerificationError::ReplayStoreUnavailable,
                );
            }
        };
        let replay = match nonce_store.check_and_consume(
            request.pair_id,
            &payload.nonce,
            payload.timestamp,
            now_ms,
            ttl_ms,
        ) {
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
        if pair.kind == PairKind::Ghost {
            return VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::GhostPairDenied,
            );
        }
        match registry.claim_success(&pair, now_ms) {
            Ok(SuccessClaim::Claimed) => VerificationResult::authorized(AuthSnapshot {
                pair_id: request.pair_id.to_owned(),
                scope: pair.scope,
                mode: pair.mode,
                audience: pair.audience.clone(),
                request_protocol: pair.request_protocol,
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
            Ok(SuccessClaim::StateChanged) => VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairStateChanged,
            ),
            Err(_) => VerificationResult::denied(
                Some(request.pair_id),
                VerificationError::PairFinalizationUnavailable,
            ),
        }
    }
}

fn is_allowed_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE"
    )
}
