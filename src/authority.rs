use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    BpcError, CanaryClass, MAX_JS_SAFE_INTEGER, MAX_SIGNATURE_WINDOW_MS, PairKind, PairMode,
    PairRecord, PairRegistry, PairRequestProtocol, PairStatus, PublicJwk, Result, Scope,
    SecretRequestHmacKey, SuccessClaim, b64url_encode, is_valid_audience, is_valid_pair_id,
    rotation_hmac, sign_rotation_payload, verify_rotation_hmac, verify_rotation_payload,
};

/// Validated BPC enrollment data. It contains verifier material and is neither
/// serializable nor printable.
#[derive(Clone, PartialEq, Eq)]
pub struct PairRegistration {
    pub name: String,
    pub scope: Scope,
    pub mode: PairMode,
    /// Locally configured trust domain for this credential, such as
    /// `bpc://api.example.test/tenant-a/production`.
    pub audience: String,
    /// 32-byte HKDF-derived request-HMAC verifier material.
    pub request_hmac_key: SecretRequestHmacKey,
    /// New enrollment is secure-default BPC v2 only.
    pub request_protocol: PairRequestProtocol,
    pub public_jwk: PublicJwk,
    pub expires_at_ms: Option<u64>,
    pub max_requests: Option<u64>,
    pub kind: PairKind,
    pub canary_class: Option<CanaryClass>,
}

impl std::fmt::Debug for PairRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairRegistration")
            .field("name", &self.name)
            .field("scope", &self.scope)
            .field("mode", &self.mode)
            .field("audience", &self.audience)
            .field("request_hmac_key", &"[REDACTED]")
            .field("request_protocol", &self.request_protocol)
            .field("public_jwk", &self.public_jwk)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("max_requests", &self.max_requests)
            .field("kind", &self.kind)
            .field("canary_class", &self.canary_class)
            .finish()
    }
}

impl PairRegistration {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty()
            || self.name.chars().count() > 128
            || !is_valid_audience(&self.audience)
        {
            return Err(BpcError::PairRegistry(
                "registration name must contain 1 to 128 characters".into(),
            ));
        }
        if self
            .expires_at_ms
            .is_some_and(|value| value > MAX_JS_SAFE_INTEGER)
            || self
                .max_requests
                .is_some_and(|value| value > MAX_JS_SAFE_INTEGER)
        {
            return Err(BpcError::PairRegistry(
                "registration lifecycle values must be JavaScript-safe integers".into(),
            ));
        }
        self.public_jwk.to_verifying_key()?;
        if self.request_protocol != PairRequestProtocol::V2 {
            return Err(BpcError::PairRegistry(
                "new registrations must use request-bound BPC v2".into(),
            ));
        }
        if matches!(self.kind, PairKind::Ghost) != self.canary_class.is_some() {
            return Err(BpcError::PairRegistry(
                "ghost registrations require a canary class and legitimate registrations cannot have one".into(),
            ));
        }
        Ok(())
    }
}

/// A registration request awaiting an authorized out-of-band approval decision.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingPairing {
    pub token: String,
    pub registration: PairRegistration,
    pub requested_at_ms: u64,
}

impl std::fmt::Debug for PendingPairing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingPairing")
            .field("token", &"[REDACTED]")
            .field("registration", &self.registration)
            .field("requested_at_ms", &self.requested_at_ms)
            .finish()
    }
}

/// Public, non-sensitive view suitable for a privileged management API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RedactedPair {
    pub id: String,
    pub name: String,
    pub scope: Scope,
    pub mode: PairMode,
    pub audience: String,
    pub status: PairStatus,
    pub created_at_ms: u64,
    pub requests: u64,
}

/// Atomic lifecycle interface required by registration approval and signed rotation.
///
/// Implementations must make approval and rotation a single authoritative state
/// transition. Production deployments should use [`crate::PostgresPairAuthority`]
/// with a transactionally protected PostgreSQL database.
pub trait PairAuthority: PairRegistry {
    fn request_pairing(&self, registration: PairRegistration, now_ms: u64) -> Result<String>;
    fn approve_pairing(&self, token: &str, now_ms: u64) -> Result<String>;
    fn revoke(&self, pair_id: &str) -> Result<bool>;
    fn rotate_pair(&self, expected_old: &PairRecord, replacement: PairRecord) -> Result<bool>;
    fn list_redacted(&self) -> Result<Vec<RedactedPair>>;
}

/// Single-process development authority. The production backend is PostgreSQL.
pub struct MemoryPairAuthority {
    registry: Arc<crate::MemoryPairRegistry>,
    pending: Mutex<HashMap<String, PendingPairing>>,
    max_active_pairs: usize,
}

impl MemoryPairAuthority {
    pub fn new(registry: Arc<crate::MemoryPairRegistry>, max_active_pairs: usize) -> Result<Self> {
        if max_active_pairs == 0 {
            return Err(BpcError::PairRegistry(
                "max_active_pairs must be positive".into(),
            ));
        }
        Ok(Self {
            registry,
            pending: Mutex::new(HashMap::new()),
            max_active_pairs,
        })
    }

    pub fn registry(&self) -> &Arc<crate::MemoryPairRegistry> {
        &self.registry
    }
}

impl PairRegistry for MemoryPairAuthority {
    fn get(&self, pair_id: &str) -> Result<Option<PairRecord>> {
        self.registry.get(pair_id)
    }

    fn record_failure(&self, pair_id: &str, lockout_after: u32) -> Result<()> {
        self.registry.record_failure(pair_id, lockout_after)
    }

    fn claim_success(&self, expected: &PairRecord, now_ms: u64) -> Result<SuccessClaim> {
        self.registry.claim_success(expected, now_ms)
    }
}

impl PairAuthority for MemoryPairAuthority {
    fn request_pairing(&self, registration: PairRegistration, now_ms: u64) -> Result<String> {
        registration.validate()?;
        if now_ms > MAX_JS_SAFE_INTEGER {
            return Err(BpcError::PairRegistry(
                "approval timestamp must be a JavaScript-safe integer".into(),
            ));
        }
        if self.registry.expire_due_and_active_count(now_ms)? >= self.max_active_pairs {
            return Err(BpcError::PairRegistry(format!(
                "maximum pair capacity ({}) reached",
                self.max_active_pairs
            )));
        }
        let token = format!("approval_{}", Uuid::new_v4().simple());
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| BpcError::PairRegistry("pending registry lock poisoned".into()))?;
        pending.insert(
            token.clone(),
            PendingPairing {
                token: token.clone(),
                registration,
                requested_at_ms: now_ms,
            },
        );
        Ok(token)
    }

    fn approve_pairing(&self, token: &str, now_ms: u64) -> Result<String> {
        if now_ms > MAX_JS_SAFE_INTEGER {
            return Err(BpcError::PairRegistry(
                "approval timestamp must be a JavaScript-safe integer".into(),
            ));
        }
        let pending_pairing = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| BpcError::PairRegistry("pending registry lock poisoned".into()))?;
            pending.remove(token).ok_or_else(|| {
                BpcError::PairRegistry("pending approval token was not found".into())
            })?
        };
        if pending_pairing
            .registration
            .expires_at_ms
            .is_some_and(|expires_at| now_ms > expires_at)
        {
            return Err(BpcError::PairRegistry(
                "pair registration has already expired".into(),
            ));
        }
        if self.registry.expire_due_and_active_count(now_ms)? >= self.max_active_pairs {
            // This development implementation fails closed: the request remains unapproved.
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| BpcError::PairRegistry("pending registry lock poisoned".into()))?;
            pending.insert(token.to_owned(), pending_pairing);
            return Err(BpcError::PairRegistry(format!(
                "maximum pair capacity ({}) reached",
                self.max_active_pairs
            )));
        }
        let id = format!("pair_{}", Uuid::new_v4().simple());
        let registration = pending_pairing.registration.clone();
        let pair = PairRecord {
            id: id.clone(),
            name: registration.name,
            scope: registration.scope,
            mode: registration.mode,
            audience: registration.audience,
            request_hmac_key: registration.request_hmac_key,
            request_protocol: registration.request_protocol,
            public_jwk: registration.public_jwk,
            status: PairStatus::Active,
            created_at_ms: now_ms,
            expires_at_ms: registration.expires_at_ms,
            max_requests: registration.max_requests,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind: registration.kind,
            canary_class: registration.canary_class,
            replaced_by: None,
        };
        if let Err(error) =
            self.registry
                .insert_approved_if_capacity(pair, self.max_active_pairs, now_ms)
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| BpcError::PairRegistry("pending registry lock poisoned".into()))?;
            pending.insert(token.to_owned(), pending_pairing);
            return Err(error);
        }
        Ok(id)
    }

    fn revoke(&self, pair_id: &str) -> Result<bool> {
        self.registry.revoke_lineage(pair_id)
    }

    fn rotate_pair(&self, expected_old: &PairRecord, replacement: PairRecord) -> Result<bool> {
        self.registry.rotate_pair(expected_old, replacement)
    }

    fn list_redacted(&self) -> Result<Vec<RedactedPair>> {
        Ok(self
            .registry
            .list_internal()?
            .into_iter()
            .map(|pair| RedactedPair {
                id: pair.id,
                name: pair.name,
                scope: pair.scope,
                mode: pair.mode,
                audience: pair.audience,
                status: pair.status,
                created_at_ms: pair.created_at_ms,
                requests: pair.requests,
            })
            .collect::<Vec<_>>())
    }
}

/// The signed contents of a BPC key-rotation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPayload {
    pub new_pub_jwk_json: String,
    pub nonce: String,
    pub old_pair_id: String,
    pub purpose: String,
    pub timestamp: u64,
}

/// HTTP/API material that carries a signed BPC rotation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRequest {
    pub old_pair_id: String,
    pub new_public_jwk: PublicJwk,
    pub nonce: String,
    pub secret_hmac: String,
    pub signature: String,
    pub signed_data: String,
    pub timestamp: u64,
}

/// Builds a signed, canonically encoded key rotation request.
pub fn sign_rotation_at(
    signing_key: &SigningKey,
    registration_secret: &str,
    old_pair_id: &str,
    new_public_jwk: &PublicJwk,
    nonce: Uuid,
    timestamp_ms: u64,
) -> Result<RotationRequest> {
    if !is_valid_pair_id(old_pair_id) {
        return Err(BpcError::InvalidPayload("invalid old pair ID".into()));
    }
    new_public_jwk.to_verifying_key()?;
    let new_pub_jwk_json = serde_json::to_string(new_public_jwk)?;
    let payload = RotationPayload {
        new_pub_jwk_json,
        nonce: nonce.to_string(),
        old_pair_id: old_pair_id.to_owned(),
        purpose: "rotation".into(),
        timestamp: timestamp_ms,
    };
    let canonical = canonical_rotation_bytes(&payload)?;
    let signature = sign_rotation_payload(signing_key, &payload)?;
    let request_hmac_key = crate::derive_request_hmac_key(registration_secret)?;
    let secret_hmac = rotation_hmac(&request_hmac_key, &canonical)?;
    Ok(RotationRequest {
        old_pair_id: old_pair_id.to_owned(),
        new_public_jwk: new_public_jwk.clone(),
        nonce: payload.nonce,
        secret_hmac,
        signature,
        signed_data: b64url_encode(canonical),
        timestamp: timestamp_ms,
    })
}

/// Verifies a signed rotation and atomically switches the authority to its successor.
pub fn verify_and_rotate_at<A: PairAuthority>(
    authority: &A,
    request: &RotationRequest,
    now_ms: u64,
    signature_window_ms: u64,
) -> Result<String> {
    if !is_valid_pair_id(&request.old_pair_id)
        || request.signed_data.len() > 4096
        || request.signature.len() > 256
        || request.secret_hmac.len() != 43
        || signature_window_ms == 0
        || signature_window_ms > MAX_SIGNATURE_WINDOW_MS
        || now_ms.abs_diff(request.timestamp) > signature_window_ms
    {
        return Err(BpcError::InvalidPayload(
            "rotation request is invalid or stale".into(),
        ));
    }
    request.new_public_jwk.to_verifying_key()?;
    let old_pair = authority
        .get(&request.old_pair_id)?
        .ok_or_else(|| BpcError::PairRegistry("old pair does not exist".into()))?;
    if old_pair.status != PairStatus::Active {
        return Err(BpcError::PairRegistry("old pair is not active".into()));
    }
    let (payload, canonical) = parse_canonical_rotation(&request.signed_data)?;
    let rotation_nonce = Uuid::parse_str(&payload.nonce)
        .map_err(|_| BpcError::InvalidPayload("rotation nonce is invalid".into()))?;
    if rotation_nonce.get_version() != Some(uuid::Version::Random)
        || rotation_nonce.get_variant() != uuid::Variant::RFC4122
    {
        return Err(BpcError::InvalidPayload(
            "rotation nonce must be UUID v4".into(),
        ));
    }
    if !verify_rotation_hmac(&old_pair.request_hmac_key, &canonical, &request.secret_hmac) {
        return Err(BpcError::InvalidHmacKey);
    }
    if !verify_rotation_payload(
        &old_pair.public_jwk.to_verifying_key()?,
        &canonical,
        &request.signature,
    ) {
        return Err(BpcError::InvalidSignature);
    }
    if payload.purpose != "rotation"
        || payload.old_pair_id != request.old_pair_id
        || payload.nonce != request.nonce
        || payload.timestamp != request.timestamp
    {
        return Err(BpcError::InvalidPayload(
            "rotation payload is not bound to its request".into(),
        ));
    }
    let payload_jwk: PublicJwk = serde_json::from_str(&payload.new_pub_jwk_json)
        .map_err(|_| BpcError::InvalidPayload("rotation JWK JSON is invalid".into()))?;
    payload_jwk.to_verifying_key()?;
    if !payload_jwk.same_key_material(&request.new_public_jwk) {
        return Err(BpcError::InvalidPayload(
            "rotation JWK is not bound to its request".into(),
        ));
    }
    if old_pair
        .public_jwk
        .same_key_material(&request.new_public_jwk)
    {
        return Err(BpcError::InvalidPayload(
            "rotation replacement key must differ from the old key".into(),
        ));
    }
    let new_pair_id = format!("pair_{}", Uuid::new_v4().simple());
    let replacement = PairRecord {
        id: new_pair_id.clone(),
        name: old_pair.name.clone(),
        scope: old_pair.scope,
        mode: old_pair.mode,
        audience: old_pair.audience.clone(),
        request_hmac_key: old_pair.request_hmac_key.clone(),
        request_protocol: old_pair.request_protocol,
        public_jwk: request.new_public_jwk.clone(),
        status: PairStatus::Active,
        created_at_ms: now_ms,
        expires_at_ms: old_pair.expires_at_ms,
        max_requests: old_pair.max_requests,
        requests: 0,
        failed_signatures: 0,
        authorization_version: 1,
        kind: old_pair.kind,
        canary_class: old_pair.canary_class,
        replaced_by: None,
    };
    if !authority.rotate_pair(&old_pair, replacement)? {
        return Err(BpcError::PairRegistry(
            "rotation conflicted with a concurrent lifecycle change".into(),
        ));
    }
    Ok(new_pair_id)
}

pub(crate) fn canonical_rotation_bytes(payload: &RotationPayload) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(payload)?)
}

pub(crate) fn parse_canonical_rotation(signed_data: &str) -> Result<(RotationPayload, Vec<u8>)> {
    if signed_data.is_empty()
        || signed_data.len() > 4096
        || !signed_data
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(BpcError::InvalidPayload(
            "rotation signed data is invalid".into(),
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(signed_data)
        .map_err(|_| BpcError::InvalidBase64)?;
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    let object = value
        .as_object()
        .ok_or_else(|| BpcError::InvalidPayload("rotation payload must be an object".into()))?;
    const KEYS: [&str; 5] = [
        "new_pub_jwk_json",
        "nonce",
        "old_pair_id",
        "purpose",
        "timestamp",
    ];
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(BpcError::InvalidPayload(
            "rotation payload must contain exactly five fields".into(),
        ));
    }
    if object
        .values()
        .any(|value| value.is_array() || value.is_object())
    {
        return Err(BpcError::InvalidPayload(
            "rotation payload must be flat".into(),
        ));
    }
    let payload: RotationPayload = serde_json::from_value(value)?;
    if payload.new_pub_jwk_json.is_empty()
        || !is_valid_pair_id(&payload.old_pair_id)
        || Uuid::parse_str(&payload.nonce).is_err()
    {
        return Err(BpcError::InvalidPayload(
            "rotation payload fields are invalid".into(),
        ));
    }
    let canonical = canonical_rotation_bytes(&payload)?;
    if raw != canonical {
        return Err(BpcError::InvalidPayload(
            "rotation payload is not canonical JSON".into(),
        ));
    }
    Ok((payload, raw))
}
