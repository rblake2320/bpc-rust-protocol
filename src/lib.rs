//! # bpc-protocol
//!
//! A Rust implementation of BPC (Bound Pair Credentials) v1 HTTP request
//! signing and verification. BPC binds a request to an ECDSA P-256 key, a
//! separately derived HMAC factor, an exact body digest, a short freshness
//! window, and a one-use UUID v4 nonce.
//!
//! This crate implements the portable v1 request format from the reference
//! BPC specification. It intentionally does not claim hardware key custody,
//! distributed replay safety, or a complete application authorization system.
//! Production deployments should provide durable transactional pair storage and
//! an atomic shared nonce backend.
//!
//! ## Quick start
//!
//! ```
//! use bpc_protocol::{
//!     derive_request_hmac_key, sign_request_at, BpcKeyPair, BpcRequest,
//!     BpcVerifier, MemoryNonceStore, MemoryPairRegistry, PairMode, PairRecord,
//!     PairStatus, Scope,
//! };
//! use uuid::Uuid;
//!
//! let key_pair = BpcKeyPair::generate()?;
//! let secret = "ExampleSecret9!@";
//! let pair_id = "pair_example";
//! let registry = MemoryPairRegistry::default();
//! registry.insert(PairRecord {
//!     id: pair_id.into(), name: "example".into(), scope: Scope::ReadWrite,
//!     mode: PairMode::Development, request_hmac_key: derive_request_hmac_key(secret)?,
//!     public_jwk: key_pair.public_jwk().clone(), status: PairStatus::Active,
//!     created_at_ms: 1_700_000_000_000, expires_at_ms: None, max_requests: None,
//!     requests: 0, failed_signatures: 0, authorization_version: 1,
//!     kind: bpc_protocol::PairKind::Legitimate, canary_class: None,
//! })?;
//! let (_payload, headers) = sign_request_at(
//!     key_pair.signing_key(), pair_id, secret, "POST", "/v1/widgets", b"{}",
//!     Uuid::parse_str("a8098c1a-f86e-4aef-9f0f-80e4b6c6c6c6")?, 1_700_000_000_000,
//! )?;
//! let result = BpcVerifier::default().verify_at(BpcRequest {
//!     pair_id: &headers.pair_id, signature: &headers.signature, signed_data: &headers.signed_data,
//!     version: &headers.version, method: "POST", path: "/v1/widgets", body: b"{}",
//! }, &registry, &MemoryNonceStore::default(), 1_700_000_000_000);
//! assert!(result.ok);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod audit;
mod authority;
#[cfg(feature = "axum")]
mod axum;
mod canonical;
mod client;
mod crypto;
mod error;
#[cfg(feature = "postgres-store")]
mod postgres_store;
#[cfg(feature = "redis-store")]
mod redis_store;
#[cfg(feature = "reqwest-client")]
mod reqwest_client;
mod types;
mod verifier;

use std::time::{SystemTime, UNIX_EPOCH};

pub use audit::{
    AuditAction, AuditEntry, AuditEvent, AuditHead, AuditLog, AuditSeverity, AuditVerification,
    GENESIS_HASH, MemoryAuditLog, audit_hash, verify_audit_entries,
};
pub use authority::{
    MemoryPairAuthority, PairAuthority, PairRegistration, PendingPairing, RedactedPair,
    RotationPayload, RotationRequest, sign_rotation_at, verify_and_rotate_at,
};
pub use canonical::{
    canonical_payload, canonical_payload_bytes, parse_canonical_payload, validate_payload_shape,
};
pub use client::{sign_request, sign_request_at};
pub use crypto::{
    b64url_decode, b64url_encode, body_hash, compute_fingerprint, derive_request_hmac_key,
    generate_registration_secret, request_hmac, sign_payload, sign_rotation_payload,
    validate_secret, verify_payload, verify_payload_bytes, verify_request_hmac,
    verify_rotation_payload,
};
pub use error::{BpcError, Result};
pub use types::{
    AuthSnapshot, BPC_PROTOCOL_VERSION, BpcKeyPair, BpcPayload, BpcRequest, CanaryClass,
    MAX_JS_SAFE_INTEGER, MemoryNonceStore, MemoryPairRegistry, NonceStore, PairKind, PairMode,
    PairRecord, PairRegistry, PairStatus, PublicJwk, Scope, SignedHeaders, SuccessClaim,
    VerificationError, VerificationResult, is_valid_pair_id,
};
pub use verifier::{BpcVerifier, BpcVerifierConfig};

#[cfg(feature = "axum")]
pub use axum::{BpcAxumState, BpcPublicErrorDisclosure, auth_snapshot, bpc_axum_middleware};

#[cfg(feature = "redis-store")]
pub use redis_store::{GovernedRedisNonceConfig, GovernedRedisNonceStore};

#[cfg(feature = "postgres-store")]
pub use postgres_store::{
    POSTGRES_SCHEMA, PostgresAuditLog, PostgresAuthorityConfig, PostgresPairAuthority,
    PostgresSecretProtector,
};

#[cfg(feature = "reqwest-client")]
pub use reqwest_client::BpcHttpClient;

/// Returns the current Unix timestamp in milliseconds.
pub fn unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BpcError::ClockBeforeEpoch)?;
    u64::try_from(duration.as_millis()).map_err(|_| BpcError::ClockBeforeEpoch)
}
