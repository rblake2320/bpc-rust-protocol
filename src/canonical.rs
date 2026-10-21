use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use uuid::{Uuid, Variant, Version};

use crate::{
    BPC_V2_PROTOCOL_VERSION, BpcError, BpcPayload, MAX_JS_SAFE_INTEGER, Result, body_hash,
    is_valid_audience, is_valid_pair_id,
};

const REQUIRED_FIELDS: [&str; 10] = [
    "audience",
    "body_hash",
    "method",
    "mode",
    "nonce",
    "pair_id",
    "path",
    "purpose",
    "timestamp",
    "version",
];
const FORBIDDEN_KEYS: [&str; 7] = [
    "__proto__",
    "constructor",
    "prototype",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

/// Serializes a BPC v2 request core in exact alphabetical compact JSON form.
pub fn canonical_payload_bytes(payload: &BpcPayload) -> Result<Vec<u8>> {
    validate_payload_shape(payload)?;
    Ok(serde_json::to_vec(payload)?)
}

/// Serializes a BPC v2 request core in exact alphabetical compact JSON form.
pub fn canonical_payload(payload: &BpcPayload) -> Result<String> {
    String::from_utf8(canonical_payload_bytes(payload)?)
        .map_err(|_| BpcError::InvalidPayload("canonical JSON was not UTF-8".into()))
}

/// Decodes, structurally validates, and requires byte-for-byte canonical BPC v2 JSON.
pub fn parse_canonical_payload(signed_data: &str) -> Result<(BpcPayload, Vec<u8>)> {
    if signed_data.is_empty() || signed_data.len() > 4096 || !signed_data.bytes().all(is_b64url) {
        return Err(BpcError::InvalidPayload(
            "signed data must be compact base64url with a bounded length".into(),
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(signed_data)
        .map_err(|_| BpcError::InvalidBase64)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| BpcError::InvalidPayload("payload is not UTF-8 JSON".into()))?;
    if FORBIDDEN_KEYS
        .iter()
        .any(|key| text.contains(&format!("\"{key}\"")))
    {
        return Err(BpcError::InvalidPayload(
            "payload contains a forbidden object key".into(),
        ));
    }
    let value: Value = serde_json::from_slice(&raw)?;
    let object = value
        .as_object()
        .ok_or_else(|| BpcError::InvalidPayload("payload must be a JSON object".into()))?;
    if object.len() != REQUIRED_FIELDS.len()
        || REQUIRED_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(BpcError::InvalidPayload(
            "payload must contain exactly the ten BPC v2 fields".into(),
        ));
    }
    if object.iter().any(|(key, value)| {
        FORBIDDEN_KEYS.contains(&key.as_str()) || value.is_array() || value.is_object()
    }) {
        return Err(BpcError::InvalidPayload(
            "payload must be flat and cannot contain forbidden keys".into(),
        ));
    }
    let payload: BpcPayload = serde_json::from_value(value)?;
    validate_payload_shape(&payload)?;
    let canonical = serde_json::to_vec(&payload)?;
    if raw != canonical {
        return Err(BpcError::InvalidPayload(
            "payload is not exactly canonical JSON".into(),
        ));
    }
    Ok((payload, raw))
}

/// Validates fields that are independent of the received HTTP request.
pub fn validate_payload_shape(payload: &BpcPayload) -> Result<()> {
    if payload.version != BPC_V2_PROTOCOL_VERSION || payload.purpose != "http-request" {
        return Err(BpcError::InvalidPayload(
            "unsupported BPC v2 payload purpose or version".into(),
        ));
    }
    if payload.timestamp > MAX_JS_SAFE_INTEGER
        || !is_valid_audience(&payload.audience)
        || !is_valid_pair_id(&payload.pair_id)
        || !is_allowed_method(&payload.method)
        || !is_safe_path(&payload.path)
    {
        return Err(BpcError::InvalidPayload(
            "BPC v2 core fields are invalid".into(),
        ));
    }
    let nonce = Uuid::parse_str(&payload.nonce)
        .map_err(|_| BpcError::InvalidPayload("BPC nonce is invalid".into()))?;
    if nonce.get_version() != Some(Version::Random)
        || nonce.get_variant() != Variant::RFC4122
        || nonce.to_string() != payload.nonce
    {
        return Err(BpcError::InvalidPayload(
            "BPC nonce must be canonical UUID v4".into(),
        ));
    }
    if !is_body_hash(&payload.body_hash) {
        return Err(BpcError::InvalidPayload("BPC body hash is invalid".into()));
    }
    Ok(())
}

/// Compares a computed body hash to a v2 core with a fixed, strict encoding form.
pub fn body_hash_matches(payload: &BpcPayload, body: &[u8]) -> bool {
    payload.body_hash == body_hash(body)
}

fn is_body_hash(value: &str) -> bool {
    value.len() == 50
        && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(|byte| is_b64url(*byte))
}

fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['\\', '#', '\r', '\n'])
}

fn is_allowed_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || byte == b'-'
        || byte == b'_'
}
