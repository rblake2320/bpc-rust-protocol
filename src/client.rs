use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use uuid::{Uuid, Variant, Version};

use crate::{
    BPC_PROTOCOL_VERSION, BpcError, BpcPayload, Result, SignedHeaders, body_hash,
    canonical_payload_bytes, derive_request_hmac_key, sign_payload, validate_payload_shape,
};

/// Builds BPC v1 request headers using a caller-supplied nonce and timestamp.
///
/// Supplying time and nonce makes the operation deterministic for test vectors.
#[allow(clippy::too_many_arguments)]
pub fn sign_request_at(
    signing_key: &SigningKey,
    pair_id: &str,
    registration_secret: &str,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: Uuid,
    timestamp_ms: u64,
) -> Result<(BpcPayload, SignedHeaders)> {
    if !crate::is_valid_pair_id(pair_id) || method.is_empty() || path.is_empty() {
        return Err(BpcError::InvalidPayload(
            "pair ID, method, or path is invalid".into(),
        ));
    }
    if nonce.get_version() != Some(Version::Random) || nonce.get_variant() != Variant::RFC4122 {
        return Err(BpcError::InvalidPayload("BPC nonce must be UUID v4".into()));
    }
    let hmac_key = derive_request_hmac_key(registration_secret)?;
    let nonce = nonce.to_string();
    let secret_hmac = crate::request_hmac(&hmac_key, &nonce, timestamp_ms)?;
    let payload = BpcPayload {
        body_hash: body_hash(body),
        method: method.to_owned(),
        nonce,
        pair_id: pair_id.to_owned(),
        path: path.to_owned(),
        secret_hmac,
        timestamp: timestamp_ms,
        version: BPC_PROTOCOL_VERSION.into(),
    };
    validate_payload_shape(&payload)?;
    let canonical = canonical_payload_bytes(&payload)?;
    let signature = sign_payload(signing_key, &payload)?;
    let headers = SignedHeaders {
        pair_id: pair_id.to_owned(),
        signature,
        signed_data: URL_SAFE_NO_PAD.encode(canonical),
        version: BPC_PROTOCOL_VERSION.into(),
    };
    Ok((payload, headers))
}

/// Builds BPC v1 request headers using the current Unix time and a random UUID v4 nonce.
pub fn sign_request(
    signing_key: &SigningKey,
    pair_id: &str,
    registration_secret: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(BpcPayload, SignedHeaders)> {
    sign_request_at(
        signing_key,
        pair_id,
        registration_secret,
        method,
        path,
        body,
        Uuid::new_v4(),
        crate::unix_ms()?,
    )
}
