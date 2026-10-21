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
/// Entropy required for a production BPC registration-secret input.
pub const HIGH_ASSURANCE_REGISTRATION_SECRET_BYTES: usize = 32;

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
pub fn derive_request_hmac_key(secret: &str) -> Result<String> {
    if secret.is_empty() {
        return Err(BpcError::EmptySecret);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), secret.as_bytes());
    let mut output = [0_u8; 32];
    hkdf.expand(HKDF_INFO, &mut output)
        .map_err(|_| BpcError::InvalidHmacKey)?;
    Ok(b64url_encode(output))
}

/// Generate an independent, uniformly random 256-bit registration secret in
/// canonical unpadded base64url form.
///
/// Store the returned value in a client-side secret manager or HSM-backed
/// secret store. It is an authentication factor, not a user password, and must
/// never be logged, embedded in browser/mobile bundles, or reused for another
/// protocol.
pub fn generate_high_assurance_registration_secret() -> String {
    let mut bytes = [0_u8; HIGH_ASSURANCE_REGISTRATION_SECRET_BYTES];
    OsRng.fill_bytes(&mut bytes);
    b64url_encode(bytes)
}

/// Validate the canonical 256-bit registration-secret representation required
/// by high-assurance BPC deployments.
///
/// This does not prove that an arbitrary derived server HMAC key originated
/// from this function. The pairing control plane must therefore record and
/// approve the trusted secret-provisioning path out of band.
pub fn validate_high_assurance_registration_secret(secret: &str) -> Result<()> {
    let bytes = b64url_decode(secret)?;
    if secret.len() != 43
        || bytes.len() != HIGH_ASSURANCE_REGISTRATION_SECRET_BYTES
        || b64url_encode(&bytes) != secret
    {
        return Err(BpcError::SecretPolicy(
            "high-assurance registration secret must be exactly 32 random bytes encoded as canonical unpadded base64url".into(),
        ));
    }
    Ok(())
}

/// Derive a BPC request-HMAC key only after enforcing the high-assurance
/// 256-bit registration-secret representation.
pub fn derive_high_assurance_request_hmac_key(secret: &str) -> Result<String> {
    validate_high_assurance_registration_secret(secret)?;
    derive_request_hmac_key(secret)
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
