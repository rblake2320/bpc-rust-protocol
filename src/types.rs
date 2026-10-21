use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::compute_fingerprint;
use crate::{BpcError, Result};

/// The BPC request protocol version implemented by this crate.
pub const BPC_PROTOCOL_VERSION: &str = "1.0";
/// Largest integer that remains exactly representable in JavaScript and JSON.
pub const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

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
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Exactly the canonical BPC v1 signed request payload.
///
/// Field declaration order is alphabetical and is the canonical JSON order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpcPayload {
    pub body_hash: String,
    pub method: String,
    pub nonce: String,
    pub pair_id: String,
    pub path: String,
    pub secret_hmac: String,
    pub timestamp: u64,
    pub version: String,
}

/// Headers a BPC client attaches to an HTTP request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHeaders {
    pub pair_id: String,
    pub signature: String,
    pub signed_data: String,
    pub version: String,
}

impl SignedHeaders {
    /// Returns the four HTTP header/value pairs required by BPC v1.
    pub fn as_http_headers(&self) -> [(&'static str, &str); 4] {
        [
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRecord {
    pub id: String,
    pub name: String,
    pub scope: Scope,
    pub mode: PairMode,
    /// Base64url HKDF-derived request HMAC key. It is verifier material, not a password hash.
    pub request_hmac_key: String,
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
}

impl PairRecord {
    /// Validates the registration data that affects request authorization.
    pub fn validate(&self) -> Result<()> {
        if !is_valid_pair_id(&self.id) {
            return Err(BpcError::PairRegistry("pair ID is invalid".into()));
        }
        if self.name.is_empty()
            || self.name.chars().count() > 128
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
        let hmac_key = URL_SAFE_NO_PAD
            .decode(&self.request_hmac_key)
            .map_err(|_| BpcError::PairRegistry("request HMAC key is not base64url".into()))?;
        if hmac_key.len() != 32 {
            return Err(BpcError::PairRegistry(
                "request HMAC key must decode to 32 bytes".into(),
            ));
        }
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
            Self::PairStateChanged => "pair_state_changed_retry",
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

/// Atomic nonce first-use contract. Returning `true` means the nonce was already consumed.
pub trait NonceStore: Send + Sync {
    fn check_and_consume(&self, nonce: &str, now_ms: u64, ttl_ms: u64) -> Result<bool>;
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

    /// Atomically inserts a new active pair subject to a capacity limit, or
    /// returns the current record at that ID. This is crate-private lifecycle
    /// plumbing for [`crate::MemoryPairAuthority`]; callers must apply their
    /// own authorization-relevant equality policy to an existing record.
    pub(crate) fn insert_if_absent_with_capacity(
        &self,
        pair: PairRecord,
        max_active_pairs: usize,
    ) -> Result<Option<PairRecord>> {
        pair.validate()?;
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| BpcError::PairRegistry("memory registry lock poisoned".into()))?;
        if let Some(existing) = pairs.get(&pair.id) {
            return Ok(Some(existing.clone()));
        }
        let active = pairs
            .values()
            .filter(|stored| stored.status == PairStatus::Active)
            .count();
        if active >= max_active_pairs {
            return Err(BpcError::PairRegistry(format!(
                "maximum pair capacity ({max_active_pairs}) reached"
            )));
        }
        pairs.insert(pair.id.clone(), pair);
        Ok(None)
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
            if pair.failed_signatures >= lockout_after && pair.status == PairStatus::Active {
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
            || pair.request_hmac_key != expected.request_hmac_key
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
    fn check_and_consume(&self, nonce: &str, now_ms: u64, ttl_ms: u64) -> Result<bool> {
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| BpcError::NonceStore("memory nonce store lock poisoned".into()))?;
        nonces.retain(|_, expires_at| *expires_at > now_ms);
        if nonces.contains_key(nonce) {
            return Ok(true);
        }
        nonces.insert(nonce.to_owned(), now_ms.saturating_add(ttl_ms));
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
