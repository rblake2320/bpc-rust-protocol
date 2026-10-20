use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::{BPC_PROTOCOL_VERSION, BpcError, BpcPayload, MAX_JS_SAFE_INTEGER, Result};

const REQUIRED_FIELDS: [&str; 8] = [
    "body_hash",
    "method",
    "nonce",
    "pair_id",
    "path",
    "secret_hmac",
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

/// Serializes a BPC request payload in the required alphabetical, compact JSON form.
pub fn canonical_payload_bytes(payload: &BpcPayload) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(payload)?)
}

/// Serializes a BPC request payload in the required alphabetical, compact JSON form.
pub fn canonical_payload(payload: &BpcPayload) -> Result<String> {
    String::from_utf8(canonical_payload_bytes(payload)?)
        .map_err(|_| BpcError::InvalidPayload("canonical JSON was not UTF-8".into()))
}

/// Decodes, structurally validates, and requires byte-for-byte canonical BPC JSON.
///
/// Requiring the encoded payload to equal its canonical re-serialization rejects
/// duplicate keys, whitespace variants, alternate escaping, and reordered fields
/// before cryptographic verification.
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

    // This raw-string scan is defense in depth; exact-key validation below is authoritative.
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
            "payload must contain exactly the eight BPC v1 fields".into(),
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
    let canonical = canonical_payload_bytes(&payload)?;
    if raw != canonical {
        return Err(BpcError::InvalidPayload(
            "payload is not exactly canonical JSON".into(),
        ));
    }
    Ok((payload, raw))
}

/// Performs field-level validation independent of a particular HTTP request.
pub fn validate_payload_shape(payload: &BpcPayload) -> Result<()> {
    if payload.version != BPC_PROTOCOL_VERSION {
        return Err(BpcError::InvalidPayload(
            "unsupported payload version".into(),
        ));
    }
    if payload.timestamp > MAX_JS_SAFE_INTEGER {
        return Err(BpcError::InvalidPayload(
            "timestamp must be a JavaScript-safe integer".into(),
        ));
    }
    if payload.method.is_empty() || payload.path.is_empty() || payload.pair_id.is_empty() {
        return Err(BpcError::InvalidPayload(
            "method, path, and pair ID must be non-empty".into(),
        ));
    }
    if payload.body_hash.is_empty() || payload.secret_hmac.is_empty() {
        return Err(BpcError::InvalidPayload(
            "body hash and secret HMAC must be non-empty".into(),
        ));
    }
    Ok(())
}

fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || byte == b'-'
        || byte == b'_'
}
