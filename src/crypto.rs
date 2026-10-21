use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::authority::canonical_rotation_bytes;
use crate::canonical::canonical_payload_bytes;
use crate::{BpcError, BpcPayload, PublicJwk, Result, RotationPayload};

const HKDF_SALT: &[u8] = b"bpc-protocol-hmac-salt-v1";
const HKDF_INFO: &[u8] = b"bpc-v1-hmac-key";
const ROTATION_HMAC_DOMAIN: &[u8] = b"bpc-rotation-hmac-v2\0";

/// Base64url-encodes bytes without padding, as required by BPC v1.
pub fn b64url_encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded base64url data. Padded and standard-base64 variants are rejected.
pub fn b64url_decode(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(BpcError::InvalidBase64);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BpcError::InvalidBase64)
}

/// SHA-256 body commitment in BPC's `sha256:<base64url-digest>` form.
pub fn body_hash(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha256:{}", b64url_encode(digest))
}

/// Derives the BPC request-HMAC key with HKDF-SHA-256.
///
/// The server receives only this derived verifier and cannot estimate source
/// secret entropy, so Rust callers must pass a source secret that satisfies the
/// BPC policy. Prefer [`generate_registration_secret`] over a human value.
pub fn derive_request_hmac_key(secret: &str) -> Result<String> {
    validate_secret(secret)?;
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), secret.as_bytes());
    let mut output = [0_u8; 32];
    hkdf.expand(HKDF_INFO, &mut output)
        .map_err(|_| BpcError::InvalidHmacKey)?;
    Ok(b64url_encode(output))
}

/// Computes the BPC request HMAC over `nonce || decimal(timestamp)`.
pub fn request_hmac(request_hmac_key: &str, nonce: &str, timestamp: u64) -> Result<String> {
    let key = b64url_decode(request_hmac_key)?;
    if key.len() != 32 {
        return Err(BpcError::InvalidHmacKey);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| BpcError::InvalidHmacKey)?;
    mac.update(nonce.as_bytes());
    mac.update(timestamp.to_string().as_bytes());
    Ok(b64url_encode(mac.finalize().into_bytes()))
}

/// Constant-time validates a full BPC request HMAC.
pub fn verify_request_hmac(
    request_hmac_key: &str,
    nonce: &str,
    timestamp: u64,
    provided_hmac: &str,
) -> bool {
    if provided_hmac.len() != 43
        || !provided_hmac
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return false;
    }
    let Ok(key) = b64url_decode(request_hmac_key) else {
        return false;
    };
    if key.len() != 32 {
        return false;
    }
    let Ok(tag) = b64url_decode(provided_hmac) else {
        return false;
    };
    if tag.len() != 32 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&key) else {
        return false;
    };
    mac.update(nonce.as_bytes());
    mac.update(timestamp.to_string().as_bytes());
    mac.verify_slice(&tag).is_ok()
}

/// Computes the second factor for a rotation over the exact canonical rotation
/// transcript under an unambiguous domain label. Unlike the legacy request
/// HMAC, a captured request tag cannot be transplanted into this operation.
pub fn rotation_hmac(request_hmac_key: &str, canonical_rotation: &[u8]) -> Result<String> {
    let key = b64url_decode(request_hmac_key)?;
    if key.len() != 32 {
        return Err(BpcError::InvalidHmacKey);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| BpcError::InvalidHmacKey)?;
    mac.update(ROTATION_HMAC_DOMAIN);
    mac.update(canonical_rotation);
    Ok(b64url_encode(mac.finalize().into_bytes()))
}

/// Constant-time validates the domain-separated full-rotation transcript HMAC.
pub fn verify_rotation_hmac(
    request_hmac_key: &str,
    canonical_rotation: &[u8],
    provided_hmac: &str,
) -> bool {
    if provided_hmac.len() != 43
        || !provided_hmac
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return false;
    }
    let Ok(key) = b64url_decode(request_hmac_key) else {
        return false;
    };
    let Ok(tag) = b64url_decode(provided_hmac) else {
        return false;
    };
    if key.len() != 32 || tag.len() != 32 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&key) else {
        return false;
    };
    mac.update(ROTATION_HMAC_DOMAIN);
    mac.update(canonical_rotation);
    mac.verify_slice(&tag).is_ok()
}

/// Signs canonical BPC JSON with ECDSA P-256/SHA-256 and returns a 64-byte P1363 base64url signature.
pub fn sign_payload(signing_key: &SigningKey, payload: &BpcPayload) -> Result<String> {
    let message = canonical_payload_bytes(payload)?;
    let signature: Signature = signing_key.sign(&message);
    Ok(b64url_encode(signature.to_bytes()))
}

/// Signs a canonical BPC key-rotation payload with P-256/SHA-256 P1363 encoding.
pub fn sign_rotation_payload(
    signing_key: &SigningKey,
    payload: &RotationPayload,
) -> Result<String> {
    let message = canonical_rotation_bytes(payload)?;
    let signature: Signature = signing_key.sign(&message);
    Ok(b64url_encode(signature.to_bytes()))
}

/// Verifies a 64-byte P1363 BPC signature over canonical JSON.
pub fn verify_payload(verifying_key: &VerifyingKey, payload: &BpcPayload, signature: &str) -> bool {
    let Ok(message) = canonical_payload_bytes(payload) else {
        return false;
    };
    verify_payload_bytes(verifying_key, &message, signature)
}

/// Verifies a 64-byte P1363 BPC signature over prevalidated canonical JSON bytes.
pub fn verify_payload_bytes(
    verifying_key: &VerifyingKey,
    canonical_bytes: &[u8],
    signature: &str,
) -> bool {
    let Ok(bytes) = b64url_decode(signature) else {
        return false;
    };
    if bytes.len() != 64 {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    verifying_key.verify(canonical_bytes, &signature).is_ok()
}

/// Verifies an already-canonical key-rotation payload with a P1363 signature.
pub fn verify_rotation_payload(
    verifying_key: &VerifyingKey,
    canonical_bytes: &[u8],
    signature: &str,
) -> bool {
    verify_payload_bytes(verifying_key, canonical_bytes, signature)
}

/// Stable 20-character public-key fingerprint shared with the JavaScript and Python implementations.
pub fn compute_fingerprint(jwk: &PublicJwk) -> Result<String> {
    jwk.to_verifying_key()?;
    // The required-member field order is intentionally the reference implementation's order.
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    Ok(b64url_encode(Sha256::digest(canonical.as_bytes()))
        .chars()
        .take(20)
        .collect())
}

/// Enforces the reference project's registration-secret policy.
pub fn validate_secret(secret: &str) -> Result<()> {
    let length = secret.chars().count();
    if !(16..=128).contains(&length) {
        return Err(BpcError::SecretPolicy(
            "secret must contain between 16 and 128 characters".into(),
        ));
    }
    if !secret.chars().any(char::is_uppercase) {
        return Err(BpcError::SecretPolicy(
            "secret must contain an uppercase character".into(),
        ));
    }
    if !secret.chars().any(char::is_lowercase) {
        return Err(BpcError::SecretPolicy(
            "secret must contain a lowercase character".into(),
        ));
    }
    if !secret.chars().any(char::is_numeric) {
        return Err(BpcError::SecretPolicy("secret must contain a digit".into()));
    }
    if secret.chars().filter(|ch| !ch.is_alphanumeric()).count() < 2 {
        return Err(BpcError::SecretPolicy(
            "secret must contain at least two special characters".into(),
        ));
    }
    Ok(())
}

/// Generates a registration secret with an exact 256-bit OS-random component.
///
/// A fixed `Aa0!!` prefix satisfies BPC v1's legacy composition policy without
/// conditioning the random bytes. This is preferable to human-selected
/// secrets: rejection sampling a base64url string for character categories
/// would reduce its entropy below 256 bits. Store the returned value in a
/// secret manager and expose it only to the intended signing client.
pub fn generate_registration_secret() -> Result<String> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = format!("Aa0!!{}", b64url_encode(bytes));
    validate_secret(&secret)?;
    Ok(secret)
}
