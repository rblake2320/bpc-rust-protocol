use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use uuid::{Uuid, Variant, Version};

use crate::{
    BPC_V2_PROTOCOL_VERSION, BpcError, BpcPayload, PairMode, Result, SignedHeaders, body_hash,
    canonical_payload_bytes, derive_request_hmac_key, is_valid_audience, is_valid_pair_id,
    request_hmac, sign_payload, validate_payload_shape,
};

/// Trusted signing context supplied by enrollment/configuration, never inferred
/// from a caller-controlled host header or request URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpcSigningContext {
    pub audience: String,
    pub mode: PairMode,
}

impl BpcSigningContext {
    pub fn new(audience: impl Into<String>, mode: PairMode) -> Result<Self> {
        let audience = audience.into();
        if !is_valid_audience(&audience) {
            return Err(BpcError::InvalidPayload("BPC audience is invalid".into()));
        }
        Ok(Self { audience, mode })
    }
}

/// Builds BPC v2 request headers using a caller-supplied nonce and timestamp.
/// Supplying time and nonce makes the operation deterministic for test vectors.
#[allow(clippy::too_many_arguments)]
pub fn sign_request_at(
    signing_key: &SigningKey,
    pair_id: &str,
    registration_secret: &str,
    context: &BpcSigningContext,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: Uuid,
    timestamp_ms: u64,
) -> Result<(BpcPayload, SignedHeaders)> {
    if !is_valid_pair_id(pair_id) || method.is_empty() || path.is_empty() {
        return Err(BpcError::InvalidPayload(
            "pair ID, method, or path is invalid".into(),
        ));
    }
    if nonce.get_version() != Some(Version::Random) || nonce.get_variant() != Variant::RFC4122 {
        return Err(BpcError::InvalidPayload("BPC nonce must be UUID v4".into()));
    }
    let payload = BpcPayload {
        audience: context.audience.clone(),
        body_hash: body_hash(body),
        method: method.to_owned(),
        mode: context.mode,
        nonce: nonce.to_string(),
        pair_id: pair_id.to_owned(),
        path: path.to_owned(),
        purpose: "http-request".into(),
        timestamp: timestamp_ms,
        version: BPC_V2_PROTOCOL_VERSION.into(),
    };
    validate_payload_shape(&payload)?;
    let canonical = canonical_payload_bytes(&payload)?;
    let hmac_key = derive_request_hmac_key(registration_secret)?;
    let hmac = request_hmac(&hmac_key, &canonical)?;
    let signature = sign_payload(signing_key, &payload, &hmac)?;
    let headers = SignedHeaders {
        hmac,
        pair_id: pair_id.to_owned(),
        signature,
        signed_data: URL_SAFE_NO_PAD.encode(canonical),
        version: BPC_V2_PROTOCOL_VERSION.into(),
    };
    Ok((payload, headers))
}

/// Builds BPC v2 request headers using the current Unix time and a random UUID v4 nonce.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    signing_key: &SigningKey,
    pair_id: &str,
    registration_secret: &str,
    context: &BpcSigningContext,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(BpcPayload, SignedHeaders)> {
    sign_request_at(
        signing_key,
        pair_id,
        registration_secret,
        context,
        method,
        path,
        body,
        Uuid::new_v4(),
        crate::unix_ms()?,
    )
}
