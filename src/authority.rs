use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    BpcError, CanaryClass, MAX_JS_SAFE_INTEGER, PairKind, PairMode, PairRecord, PairRegistry,
    PairStatus, PublicJwk, Result, Scope, SuccessClaim, b64url_decode, b64url_encode,
    is_valid_pair_id, sign_rotation_payload, verify_rotation_payload,
};

/// Data submitted for a BPC pairing request. It intentionally contains only public material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRegistration {
    pub name: String,
    pub scope: Scope,
    pub mode: PairMode,
    /// 32-byte HKDF-derived request HMAC key encoded as unpadded base64url.
    pub request_hmac_key: String,
    pub public_jwk: PublicJwk,
    pub expires_at_ms: Option<u64>,
    pub max_requests: Option<u64>,
    #[serde(default)]
    pub kind: PairKind,
    pub canary_class: Option<CanaryClass>,
}

impl PairRegistration {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.chars().count() > 128 {
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
        let key = b64url_decode(&self.request_hmac_key)
            .map_err(|_| BpcError::PairRegistry("request HMAC key is not base64url".into()))?;
        if self.request_hmac_key.len() != 43 || key.len() != 32 {
            return Err(BpcError::PairRegistry(
                "request HMAC key must be a full 32-byte base64url value".into(),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPairing {
    pub token: String,
    pub registration: PairRegistration,
    pub requested_at_ms: u64,
}

/// Public, non-sensitive view suitable for a privileged management API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RedactedPair {
    pub id: String,
    pub name: String,
    pub scope: Scope,
    pub mode: PairMode,
    pub status: PairStatus,
    pub created_at_ms: u64,
    pub requests: u64,
}

/// Result of an authenticated control-plane provisioning reconciliation.
///
/// `Created` means a new active pair was durably approved. `Existing` means
/// the requested pair ID was already active with exactly the same
/// authorization-relevant registration. Both outcomes are successful and let
/// callers safely retry after a timeout or restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionPairOutcome {
    Created,
    Existing,
}

/// Atomic lifecycle interface required by registration approval and signed rotation.
///
/// Implementations must make approval and rotation a single authoritative state
/// transition. Production deployments should use [`crate::PostgresPairAuthority`]
/// with a transactionally protected PostgreSQL database.
pub trait PairAuthority: PairRegistry {
    fn request_pairing(&self, registration: PairRegistration, now_ms: u64) -> Result<String>;
    fn approve_pairing(&self, token: &str, now_ms: u64) -> Result<String>;
    /// Atomically creates and approves a pair with a caller-selected ID, or
    /// confirms an identical active pair already exists at that ID.
    ///
    /// This is for an already authenticated control plane, not an untrusted
    /// registration endpoint. Implementations must reject material changes or
    /// a non-active existing pair rather than silently replacing a credential.
    fn provision_pair(
        &self,
        pair_id: &str,
        registration: PairRegistration,
        now_ms: u64,
    ) -> Result<ProvisionPairOutcome>;
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
        if self.registry.active_count()? >= self.max_active_pairs {
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
        let pending_pairing = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| BpcError::PairRegistry("pending registry lock poisoned".into()))?;
            pending.remove(token).ok_or_else(|| {
                BpcError::PairRegistry("pending approval token was not found".into())
            })?
        };
        if self.registry.active_count()? >= self.max_active_pairs {
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
        let pair = PairRecord {
            id: id.clone(),
            name: pending_pairing.registration.name,
            scope: pending_pairing.registration.scope,
            mode: pending_pairing.registration.mode,
            request_hmac_key: pending_pairing.registration.request_hmac_key,
            public_jwk: pending_pairing.registration.public_jwk,
            status: PairStatus::Active,
            created_at_ms: now_ms,
            expires_at_ms: pending_pairing.registration.expires_at_ms,
            max_requests: pending_pairing.registration.max_requests,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind: pending_pairing.registration.kind,
            canary_class: pending_pairing.registration.canary_class,
        };
        self.registry.insert(pair)?;
        Ok(id)
    }

    fn provision_pair(
        &self,
        pair_id: &str,
        registration: PairRegistration,
        now_ms: u64,
    ) -> Result<ProvisionPairOutcome> {
        registration.validate()?;
        if !is_valid_pair_id(pair_id) || now_ms > MAX_JS_SAFE_INTEGER {
            return Err(BpcError::PairRegistry(
                "provisioning pair ID or timestamp is invalid".into(),
            ));
        }
        let pair = PairRecord {
            id: pair_id.to_owned(),
            name: registration.name,
            scope: registration.scope,
            mode: registration.mode,
            request_hmac_key: registration.request_hmac_key,
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
        };
        if let Some(existing) = self
            .registry
            .insert_if_absent_with_capacity(pair.clone(), self.max_active_pairs)?
        {
            if existing.status == PairStatus::Active && pair_matches_pair(&existing, &pair) {
                return Ok(ProvisionPairOutcome::Existing);
            }
            return Err(BpcError::PairRegistry(
                "requested pair ID belongs to a different or inactive registration".into(),
            ));
        }
        Ok(ProvisionPairOutcome::Created)
    }

    fn revoke(&self, pair_id: &str) -> Result<bool> {
        if self.registry.get(pair_id)?.is_none() {
            return Ok(false);
        }
        self.registry.update_status(pair_id, PairStatus::Revoked)?;
        Ok(true)
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
                status: pair.status,
                created_at_ms: pair.created_at_ms,
                requests: pair.requests,
            })
            .collect::<Vec<_>>())
    }
}

pub(crate) fn pair_matches_registration(
    pair: &PairRecord,
    registration: &PairRegistration,
) -> bool {
    pair.name == registration.name
        && pair.scope == registration.scope
        && pair.mode == registration.mode
        && pair.request_hmac_key == registration.request_hmac_key
        && pair.public_jwk == registration.public_jwk
        && pair.expires_at_ms == registration.expires_at_ms
        && pair.max_requests == registration.max_requests
        && pair.kind == registration.kind
        && pair.canary_class == registration.canary_class
}

fn pair_matches_pair(left: &PairRecord, right: &PairRecord) -> bool {
    left.name == right.name
        && left.scope == right.scope
        && left.mode == right.mode
        && left.request_hmac_key == right.request_hmac_key
        && left.public_jwk == right.public_jwk
        && left.expires_at_ms == right.expires_at_ms
        && left.max_requests == right.max_requests
        && left.kind == right.kind
        && left.canary_class == right.canary_class
}

/// The signed contents of a BPC key-rotation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPayload {
    pub new_pub_jwk_json: String,
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
    pub signature: String,
    pub signed_data: String,
    pub timestamp: u64,
}

/// Builds a signed, canonically encoded key rotation request.
pub fn sign_rotation_at(
    signing_key: &SigningKey,
    old_pair_id: &str,
    new_public_jwk: &PublicJwk,
    timestamp_ms: u64,
) -> Result<RotationRequest> {
    if !is_valid_pair_id(old_pair_id) {
        return Err(BpcError::InvalidPayload("invalid old pair ID".into()));
    }
    new_public_jwk.to_verifying_key()?;
    let new_pub_jwk_json = serde_json::to_string(new_public_jwk)?;
    let payload = RotationPayload {
        new_pub_jwk_json,
        old_pair_id: old_pair_id.to_owned(),
        purpose: "rotation".into(),
        timestamp: timestamp_ms,
    };
    let canonical = canonical_rotation_bytes(&payload)?;
    let signature = sign_rotation_payload(signing_key, &payload)?;
    Ok(RotationRequest {
        old_pair_id: old_pair_id.to_owned(),
        new_public_jwk: new_public_jwk.clone(),
        signature,
        signed_data: b64url_encode(canonical),
        timestamp: timestamp_ms,
    })
}

/// Verifies a signed rotation and atomically switches the authority to its successor.
pub fn verify_and_rotate_at<A: PairAuthority + ?Sized>(
    authority: &A,
    request: &RotationRequest,
    now_ms: u64,
    signature_window_ms: u64,
) -> Result<String> {
    if !is_valid_pair_id(&request.old_pair_id)
        || request.signed_data.len() > 4096
        || request.signature.len() > 256
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
    if !verify_rotation_payload(
        &old_pair.public_jwk.to_verifying_key()?,
        &canonical,
        &request.signature,
    ) {
        return Err(BpcError::InvalidSignature);
    }
    if payload.purpose != "rotation"
        || payload.old_pair_id != request.old_pair_id
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
    let new_pair_id = format!("pair_{}", Uuid::new_v4().simple());
    let replacement = PairRecord {
        id: new_pair_id.clone(),
        name: old_pair.name.clone(),
        scope: old_pair.scope,
        mode: old_pair.mode,
        request_hmac_key: old_pair.request_hmac_key.clone(),
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
    const KEYS: [&str; 4] = ["new_pub_jwk_json", "old_pair_id", "purpose", "timestamp"];
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(BpcError::InvalidPayload(
            "rotation payload must contain exactly four fields".into(),
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
    if payload.new_pub_jwk_json.is_empty() || !is_valid_pair_id(&payload.old_pair_id) {
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
