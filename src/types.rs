use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::compute_fingerprint;
use crate::{BpcError, Result};

/// Legacy BPC wire version retained only for an explicit migration build.
pub const BPC_V1_PROTOCOL_VERSION: &str = "1.0";
/// Secure-default BPC request wire version.
pub const BPC_V2_PROTOCOL_VERSION: &str = "2.0";
/// The secure-default BPC request protocol version implemented by this crate.
pub const BPC_PROTOCOL_VERSION: &str = BPC_V2_PROTOCOL_VERSION;
/// Largest integer that remains exactly representable in JavaScript and JSON.
pub const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum length of a locally configured BPC audience identifier.
pub const MAX_AUDIENCE_LEN: usize = 256;

/// The protocol selected when a pair is enrolled. A pair accepts one protocol,
/// never an unauthenticated fallback between versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PairRequestProtocol {
    /// Existing v1 credentials; compatibility-only and never the default.
    V1Compatibility,
    /// Request-bound BPC v2 credentials.
    V2,
}

/// Derived 32-byte request-HMAC verifier material.
///
/// This is a credential factor, not a password hash. It has no public string,
/// display, or Serde surface; only persistence adapters inside this crate can
/// access its canonical base64url representation.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretRequestHmacKey(Zeroizing<String>);

impl SecretRequestHmacKey {
    pub fn from_base64url(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_request_hmac_key(&value)?;
        Ok(Self(Zeroizing::new(value)))
    }

    pub(crate) fn encoded(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretRequestHmacKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretRequestHmacKey([REDACTED])")
    }
}

/// A public ECDSA P-256 JWK accepted by BPC v1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    /// Optional WebCrypto verification usage metadata accepted by BPC v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    /// Optional WebCrypto extractability marker; only `true` is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
}

impl PublicJwk {
    /// Builds a strict BPC P-256 JWK from a verifying key.
    pub fn from_verifying_key(key: &VerifyingKey) -> Result<Self> {
        let point = key.to_encoded_point(false);
        let x = point
            .x()
            .ok_or_else(|| BpcError::InvalidJwk("P-256 point is missing x".into()))?;
        let y = point
            .y()
            .ok_or_else(|| BpcError::InvalidJwk("P-256 point is missing y".into()))?;
        Ok(Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
            key_ops: None,
            ext: None,
        })
    }

    /// Imports the JWK as a P-256 verifying key after validating every field.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(BpcError::InvalidJwk(
                "only an EC P-256 public JWK is permitted".into(),
            ));
        }
        if self
            .key_ops
            .as_ref()
            .is_some_and(|ops| ops.len() != 1 || ops[0] != "verify")
            || self.ext.is_some_and(|ext| !ext)
        {
            return Err(BpcError::InvalidJwk(
                "JWK key_ops must be [\"verify\"] and ext may only be true".into(),
            ));
        }
        let x = decode_coordinate(&self.x, "x")?;
        let y = decode_coordinate(&self.y, "y")?;
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| BpcError::InvalidJwk("point is not on P-256".into()))
    }

    /// Compares only public key material, intentionally ignoring harmless
    /// WebCrypto metadata presence in signed rotation bindings.
    pub fn same_key_material(&self, other: &Self) -> bool {
        self.kty == other.kty && self.crv == other.crv && self.x == other.x && self.y == other.y
    }
}

fn decode_coordinate(value: &str, label: &str) -> Result<Vec<u8>> {
    if value.len() != 43 || !value.bytes().all(is_b64url) {
        return Err(BpcError::InvalidJwk(format!(
            "{label} must be an unpadded 32-byte base64url coordinate"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BpcError::InvalidJwk(format!("{label} is not base64url")))?;
    if bytes.len() != 32 {
        return Err(BpcError::InvalidJwk(format!(
            "{label} must decode to 32 bytes"
        )));
    }
    Ok(bytes)
}

fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || byte == b'-'
        || byte == b'_'
}

/// An ECDSA P-256 key pair used by a BPC client.
///
/// The private key remains in memory. For production custody, load it from an
/// application-managed key store, KMS, HSM, or platform-specific secure store.
pub struct BpcKeyPair {
    signing_key: SigningKey,
    public_jwk: PublicJwk,
    fingerprint: String,
}

impl BpcKeyPair {
    /// Creates a fresh ECDSA P-256 key pair.
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    /// Wraps an existing P-256 signing key for BPC use.
    pub fn from_signing_key(signing_key: SigningKey) -> Result<Self> {
        let verifying_key = VerifyingKey::from(&signing_key);
        let public_jwk = PublicJwk::from_verifying_key(&verifying_key)?;
        let fingerprint = compute_fingerprint(&public_jwk)?;
        Ok(Self {
            signing_key,
            public_jwk,
            fingerprint,
        })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.signing_key)
    }

    pub fn public_jwk(&self) -> &PublicJwk {
        &self.public_jwk
    }

    /// First 20 base64url characters of SHA-256 over the canonical public JWK.
    ///
    /// This 120-bit truncated value is for display and log correlation only;
    /// it must never be used as an authorization, approval, or key-equality
    /// identifier.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Exactly the canonical BPC v2 signed request core.
///
/// Field declaration order is alphabetical and is the canonical JSON order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpcPayload {
    pub audience: String,
    pub body_hash: String,
    pub method: String,
    pub mode: PairMode,
    pub nonce: String,
    pub pair_id: String,
    pub path: String,
    pub purpose: String,
    pub timestamp: u64,
    pub version: String,
}

/// Headers a BPC client attaches to an HTTP request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHeaders {
    /// Base64url BPC v2 request HMAC over the canonical core.
    pub hmac: String,
    pub pair_id: String,
    pub signature: String,
    pub signed_data: String,
    pub version: String,
}

impl SignedHeaders {
    /// Returns the five HTTP header/value pairs required by BPC v2.
    pub fn as_http_headers(&self) -> [(&'static str, &str); 5] {
        [
            ("X-BPC-HMAC", &self.hmac),
            ("X-BPC-Pair-ID", &self.pair_id),
            ("X-BPC-Signature", &self.signature),
            ("X-BPC-Signed-Data", &self.signed_data),
            ("X-BPC-Version", &self.version),
        ]
    }
}

/// Closed BPC HTTP-method scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Read,
    ReadWrite,
    Admin,
}

impl Scope {
    pub fn allows(self, method: &str) -> bool {
        match self {
            Self::Read => matches!(method, "GET" | "HEAD" | "OPTIONS"),
            Self::ReadWrite => matches!(
                method,
                "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH"
            ),
            Self::Admin => matches!(
                method,
                "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE"
            ),
        }
    }
}

/// Pair operating mode stored with a BPC registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairMode {
    Development,
    Production,
}

/// Lifecycle state stored with a BPC registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairStatus {
    Active,
    Locked,
    Expired,
    Rotated,
    Revoked,
}

/// Whether a pair is a normal credential or an intentionally planted canary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairKind {
    #[default]
    Legitimate,
    Ghost,
}

/// Leak surface represented by a ghost/canary pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryClass {
    EnvFile,
    Docs,
    RegistryExfil,
}

/// Pair metadata required by the portable BPC verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct PairRecord {
    pub id: String,
    pub name: String,
    pub scope: Scope,
    pub mode: PairMode,
    /// Locally configured trust domain, for example
    /// `bpc://api.example.test/tenant-a/production`.
    pub audience: String,
    /// HKDF-derived verifier material. It cannot be serialized or printed.
    pub request_hmac_key: SecretRequestHmacKey,
    /// Exactly one protocol policy is accepted for a pair.
    pub request_protocol: PairRequestProtocol,
    pub public_jwk: PublicJwk,
    pub status: PairStatus,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    /// `None` or `Some(0)` means unlimited usage.
    pub max_requests: Option<u64>,
    pub requests: u64,
    pub failed_signatures: u32,
    /// Increments whenever authorization-relevant policy changes. Final claims
    /// use this fence to avoid authorizing against a stale snapshot.
    pub authorization_version: u64,
    pub kind: PairKind,
    pub canary_class: Option<CanaryClass>,
    /// Successor created by a rotation. This lineage is traversed for a
    /// credential-family revocation.
    pub replaced_by: Option<String>,
}

impl std::fmt::Debug for PairRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("scope", &self.scope)
            .field("mode", &self.mode)
            .field("audience", &self.audience)
            .field("request_hmac_key", &"[REDACTED]")
            .field("request_protocol", &self.request_protocol)
            .field("public_jwk", &self.public_jwk)
            .field("status", &self.status)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("max_requests", &self.max_requests)
            .field("requests", &self.requests)
            .field("failed_signatures", &self.failed_signatures)
            .field("authorization_version", &self.authorization_version)
            .field("kind", &self.kind)
            .field("canary_class", &self.canary_class)
            .field("replaced_by", &self.replaced_by)
            .finish()
    }
}

impl PairRecord {
    /// Validates the registration data that affects request authorization.
    pub fn validate(&self) -> Result<()> {
        if !is_valid_pair_id(&self.id) {
            return Err(BpcError::PairRegistry("pair ID is invalid".into()));
        }
        if self.name.is_empty()
            || self.name.chars().count() > 128
            || !is_valid_audience(&self.audience)
            || self.created_at_ms > MAX_JS_SAFE_INTEGER
            || self
                .expires_at_ms
                .is_some_and(|value| value > MAX_JS_SAFE_INTEGER)
            || self
                .max_requests
                .is_some_and(|value| value > MAX_JS_SAFE_INTEGER)
        {
            return Err(BpcError::PairRegistry(
                "pair lifecycle fields are invalid or not JavaScript-safe integers".into(),
            ));
        }
        self.public_jwk.to_verifying_key()?;
        if matches!(self.kind, PairKind::Ghost) != self.canary_class.is_some() {
            return Err(BpcError::PairRegistry(
                "ghost pairs require a canary class and legitimate pairs cannot have one".into(),
            ));
        }
        Ok(())
    }
}

/// Verification-time request data. The body must be the exact bytes sent on the wire.
#[derive(Clone, Copy, Debug)]
pub struct BpcRequest<'a> {
    pub hmac: &'a str,
    pub pair_id: &'a str,
    pub signature: &'a str,
    pub signed_data: &'a str,
    pub version: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
}

/// Success snapshot returned only after cryptographic verification and nonce consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSnapshot {
    pub pair_id: String,
    pub scope: Scope,
    pub mode: PairMode,
    /// Cryptographically authenticated v2 audience, retained for handlers.
    pub audience: String,
    pub request_protocol: PairRequestProtocol,
    pub kind: PairKind,
    pub canary_class: Option<CanaryClass>,
    pub verified_at_ms: u64,
}

/// Stable verifier error codes intended for HTTP adapters and telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    MissingHeaders,
    InvalidMethod,
    InvalidSignedData,
    VersionMismatch,
    UnknownPair,
    AudienceMismatch,
    PairRevoked,
    PairLocked,
    PairExpired,
    PairRotated,
    PairUsageCapExceeded,
    InvalidSecretHmac,
    TimestampExpired,
    MethodPathMismatch,
    PairIdMismatch,
    ScopeViolation,
    MissingBodyHash,
    InvalidBodyHash,
    InvalidSignature,
    ReplayDetected,
    ReplayStoreUnavailable,
    /// The nonce was consumed but the durable final authorization claim failed.
    /// Do not retry these signed headers; obtain state and sign a new request.
    PairFinalizationUnavailable,
    PairStateChanged,
    GhostPairDenied,
}

impl VerificationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingHeaders => "missing_headers",
            Self::InvalidMethod => "invalid_method",
            Self::InvalidSignedData => "invalid_signed_data",
            Self::VersionMismatch => "version_mismatch",
            Self::UnknownPair => "unknown_pair",
            Self::AudienceMismatch => "audience_mismatch",
            Self::PairRevoked => "pair_revoked",
            Self::PairLocked => "pair_locked",
            Self::PairExpired => "pair_expired",
            Self::PairRotated => "pair_rotated",
            Self::PairUsageCapExceeded => "pair_usage_cap_exceeded",
            Self::InvalidSecretHmac => "invalid_secret_hmac",
            Self::TimestampExpired => "timestamp_expired",
            Self::MethodPathMismatch => "method_path_mismatch",
            Self::PairIdMismatch => "pair_id_mismatch",
            Self::ScopeViolation => "scope_violation",
            Self::MissingBodyHash => "missing_body_hash",
            Self::InvalidBodyHash => "invalid_body_hash",
            Self::InvalidSignature => "invalid_signature",
            Self::ReplayDetected => "replay_detected",
            Self::ReplayStoreUnavailable => "replay_store_unavailable",
            Self::PairFinalizationUnavailable => "pair_finalization_unavailable",
            // The nonce was spent before the final authorization claim. Retrying
            // the same signed request can only be a replay.
            Self::PairStateChanged => "pair_state_changed",
            Self::GhostPairDenied => "ghost_pair_denied",
        }
    }
}

/// Result of BPC request verification. Authorization requires `ok == true`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    pub ok: bool,
    pub pair_id: Option<String>,
    pub snapshot: Option<AuthSnapshot>,
    pub error: Option<VerificationError>,
}

impl VerificationResult {
    pub fn authorized(snapshot: AuthSnapshot) -> Self {
        Self {
            ok: true,
            pair_id: Some(snapshot.pair_id.clone()),
            snapshot: Some(snapshot),
            error: None,
        }
    }

    pub fn denied(pair_id: Option<&str>, error: VerificationError) -> Self {
        Self {
            ok: false,
            pair_id: pair_id.map(ToOwned::to_owned),
            snapshot: None,
            error: Some(error),
        }
    }
}

/// Result of atomically recording a successful BPC use in a pair registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessClaim {
    Claimed,
    StateChanged,
    Expired,
    UsageExhausted,
}

/// Pair persistence contract required by [`crate::BpcVerifier`].
///
/// Production implementations should use a durable transactional store. The
/// in-memory implementation below is for one-process development and tests.
pub trait PairRegistry: Send + Sync {
    fn get(&self, pair_id: &str) -> Result<Option<PairRecord>>;
    fn record_failure(&self, pair_id: &str, lockout_after: u32) -> Result<()>;
    fn claim_success(&self, expected: &PairRecord, now_ms: u64) -> Result<SuccessClaim>;
}

/// Atomic nonce first-use contract. Returning `true` means this authenticated
/// pair has already consumed the nonce.
pub trait NonceStore: Send + Sync {
    fn check_and_consume(
        &self,
        pair_id: &str,
        nonce: &str,
        signed_timestamp_ms: u64,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<bool>;
}

/// One-process, mutex-protected pair registry. It is not a durable production store.
#[derive(Default)]
pub struct MemoryPairRegistry {
    pairs: Mutex<HashMap<String, PairRecord>>,
}

impl MemoryPairRegistry {
    pub fn insert(&self, pair: PairRecord) -> Result<()> {
        pair.validate()?;
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        pairs.insert(pair.id.clone(), pair);
        Ok(())
    }

    pub fn update_status(&self, pair_id: &str, status: PairStatus) -> Result<()> {
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        let pair = pairs
            .get_mut(pair_id)
            .ok_or_else(|| BpcError::PairRegistry("pair not found".into()))?;
        if pair.status != status {
            pair.status = status;
            pair.authorization_version = pair.authorization_version.saturating_add(1);
        }
        Ok(())
    }

    /// Returns the number of active pairs. Intended for bounded development registries.
    pub fn active_count(&self) -> Result<usize> {
        let pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        Ok(pairs
            .values()
            .filter(|pair| pair.status == PairStatus::Active)
            .count())
    }

    /// Transitions elapsed active pairs and returns the remaining active count
    /// while holding one registry lock. A pair is valid at its exact expiry
    /// millisecond and expires immediately after it.
    pub fn expire_due_and_active_count(&self, now_ms: u64) -> Result<usize> {
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        for pair in pairs.values_mut() {
            if pair.status == PairStatus::Active
                && pair
                    .expires_at_ms
                    .is_some_and(|expires_at| now_ms > expires_at)
            {
                pair.status = PairStatus::Expired;
                pair.authorization_version = pair.authorization_version.saturating_add(1);
            }
        }
        Ok(pairs
            .values()
            .filter(|pair| pair.status == PairStatus::Active)
            .count())
    }

    /// Atomically expires elapsed pairs, checks capacity, and inserts one
    /// approved active pair. This keeps the in-memory development authority
    /// aligned with production's transactional capacity semantics.
    pub fn insert_approved_if_capacity(
        &self,
        pair: PairRecord,
        max_active_pairs: usize,
        now_ms: u64,
    ) -> Result<()> {
        pair.validate()?;
        if pair.status != PairStatus::Active {
            return Err(BpcError::PairRegistry(
                "approved memory pair must be active".into(),
            ));
        }
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        for existing in pairs.values_mut() {
            if existing.status == PairStatus::Active
                && existing
                    .expires_at_ms
                    .is_some_and(|expires_at| now_ms > expires_at)
            {
                existing.status = PairStatus::Expired;
                existing.authorization_version = existing.authorization_version.saturating_add(1);
            }
        }
        if pairs
            .values()
            .filter(|existing| existing.status == PairStatus::Active)
            .count()
            >= max_active_pairs
        {
            return Err(BpcError::PairRegistry(format!(
                "maximum pair capacity ({max_active_pairs}) reached"
            )));
        }
        if pairs.contains_key(&pair.id) {
            return Err(BpcError::PairRegistry("pair ID already exists".into()));
        }
        pairs.insert(pair.id.clone(), pair);
        Ok(())
    }

    /// Atomically revokes a pair and all rotation descendants.
    pub fn revoke_lineage(&self, pair_id: &str) -> Result<bool> {
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        if !pairs.contains_key(pair_id) {
            return Ok(false);
        }
        let mut pending = vec![pair_id.to_owned()];
        let mut changed = false;
        while let Some(current_id) = pending.pop() {
            let successor = pairs
                .get(&current_id)
                .and_then(|pair| pair.replaced_by.clone());
            if let Some(pair) = pairs.get_mut(&current_id) {
                if pair.status != PairStatus::Revoked {
                    pair.status = PairStatus::Revoked;
                    pair.authorization_version = pair.authorization_version.saturating_add(1);
                    changed = true;
                }
            }
            if let Some(successor) = successor {
                pending.push(successor);
            }
        }
        Ok(changed)
    }

    /// Returns detached pair records for trusted in-process management logic.
    /// Do not serialize these records to an untrusted caller because they contain
    /// public-key and verifier-key metadata.
    pub fn list_internal(&self) -> Result<Vec<PairRecord>> {
        let pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        Ok(pairs.values().cloned().collect())
    }

    /// Atomically replaces an active pair with its rotation successor.
    pub fn rotate_pair(&self, expected_old: &PairRecord, replacement: PairRecord) -> Result<bool> {
        replacement.validate()?;
        if expected_old.id == replacement.id || replacement.status != PairStatus::Active {
            return Err(BpcError::PairRegistry(
                "invalid rotation replacement".into(),
            ));
        }
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        let Some(current) = pairs.get(&expected_old.id) else {
            return Ok(false);
        };
        if current != expected_old
            || current.status != PairStatus::Active
            || pairs.contains_key(&replacement.id)
        {
            return Ok(false);
        }
        let mut retired = current.clone();
        retired.status = PairStatus::Rotated;
        retired.authorization_version = retired.authorization_version.saturating_add(1);
        retired.replaced_by = Some(replacement.id.clone());
        pairs.insert(retired.id.clone(), retired);
        pairs.insert(replacement.id.clone(), replacement);
        Ok(true)
    }
}

impl PairRegistry for MemoryPairRegistry {
    fn get(&self, pair_id: &str) -> Result<Option<PairRecord>> {
        let pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        Ok(pairs.get(pair_id).cloned())
    }

    fn record_failure(&self, pair_id: &str, lockout_after: u32) -> Result<()> {
        if lockout_after == 0 {
            return Ok(());
        }
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        if let Some(pair) = pairs.get_mut(pair_id) {
            pair.failed_signatures = pair.failed_signatures.saturating_add(1);
            if lockout_after > 0
                && pair.failed_signatures >= lockout_after
                && pair.status == PairStatus::Active
            {
                pair.status = PairStatus::Locked;
                pair.authorization_version = pair.authorization_version.saturating_add(1);
            }
        }
        Ok(())
    }

    fn claim_success(&self, expected: &PairRecord, now_ms: u64) -> Result<SuccessClaim> {
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        let Some(pair) = pairs.get_mut(&expected.id) else {
            return Ok(SuccessClaim::StateChanged);
        };
        if pair.authorization_version != expected.authorization_version
            || pair.status != expected.status
            || pair.scope != expected.scope
            || pair.mode != expected.mode
            || pair.audience != expected.audience
            || pair.request_hmac_key != expected.request_hmac_key
            || pair.request_protocol != expected.request_protocol
            || pair.public_jwk != expected.public_jwk
            || pair.expires_at_ms != expected.expires_at_ms
            || pair.max_requests != expected.max_requests
        {
            return Ok(SuccessClaim::StateChanged);
        }
        if pair.status != PairStatus::Active {
            return Ok(SuccessClaim::StateChanged);
        }
        if pair
            .expires_at_ms
            .is_some_and(|expires_at| now_ms > expires_at)
        {
            pair.status = PairStatus::Expired;
            pair.authorization_version = pair.authorization_version.saturating_add(1);
            return Ok(SuccessClaim::Expired);
        }
        if pair
            .max_requests
            .is_some_and(|cap| cap > 0 && pair.requests >= cap)
        {
            pair.status = PairStatus::Expired;
            pair.authorization_version = pair.authorization_version.saturating_add(1);
            return Ok(SuccessClaim::UsageExhausted);
        }
        pair.requests = pair.requests.saturating_add(1);
        pair.failed_signatures = 0;
        if pair
            .max_requests
            .is_some_and(|cap| cap > 0 && pair.requests >= cap)
        {
            pair.status = PairStatus::Expired;
            pair.authorization_version = pair.authorization_version.saturating_add(1);
        }
        Ok(SuccessClaim::Claimed)
    }
}

/// One-process, mutex-protected replay store. It is not shared across nodes.
#[derive(Default)]
pub struct MemoryNonceStore {
    nonces: Mutex<HashMap<String, u64>>,
}

impl MemoryNonceStore {
    pub fn len(&self) -> Result<usize> {
        let nonces = self
            .nonces
            .lock()
            .map_err(|_| BpcError::NonceStore("memory nonce store lock poisoned".into()))?;
        Ok(nonces.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

impl NonceStore for MemoryNonceStore {
    fn check_and_consume(
        &self,
        pair_id: &str,
        nonce: &str,
        _signed_timestamp_ms: u64,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<bool> {
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| BpcError::NonceStore("memory nonce store lock poisoned".into()))?;
        nonces.retain(|_, expires_at| *expires_at > now_ms);
        let identity = format!("{pair_id}:{nonce}");
        if nonces.contains_key(&identity) {
            return Ok(true);
        }
        nonces.insert(identity, now_ms.saturating_add(ttl_ms));
        Ok(false)
    }
}

/// BPC pair IDs must be short URL-safe identifiers to be safely used in headers and stores.
pub fn is_valid_pair_id(pair_id: &str) -> bool {
    !pair_id.is_empty()
        && pair_id.len() <= 64
        && pair_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validates the exact base64url representation of a 32-byte BPC request-HMAC
/// verifier before attempting a decoded allocation.
pub fn validate_request_hmac_key(value: &str) -> Result<()> {
    if value.len() != 43 || !value.bytes().all(is_b64url) {
        return Err(BpcError::PairRegistry(
            "request HMAC key must be a 43-character unpadded base64url value".into(),
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BpcError::PairRegistry("request HMAC key is not base64url".into()))?;
    if decoded.len() != 32 {
        return Err(BpcError::PairRegistry(
            "request HMAC key must decode to 32 bytes".into(),
        ));
    }
    Ok(())
}

/// Validates a locally configured BPC audience. It deliberately permits no
/// whitespace, query, fragment, or control characters so it cannot be
/// confused with an HTTP request target.
pub fn is_valid_audience(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUDIENCE_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'_' | b'-')
        })
}
