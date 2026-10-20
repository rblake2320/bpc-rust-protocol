use thiserror::Error;

/// Errors returned while constructing or validating BPC protocol data.
#[derive(Debug, Error)]
pub enum BpcError {
    #[error("invalid base64url data")]
    InvalidBase64,
    #[error("invalid BPC payload: {0}")]
    InvalidPayload(String),
    #[error("invalid public JWK: {0}")]
    InvalidJwk(String),
    #[error("invalid ECDSA signature")]
    InvalidSignature,
    #[error("invalid HMAC key material")]
    InvalidHmacKey,
    #[error("the registration secret must not be empty")]
    EmptySecret,
    #[error("secret policy violation: {0}")]
    SecretPolicy(String),
    #[error("nonce store error: {0}")]
    NonceStore(String),
    #[error("pair registry error: {0}")]
    PairRegistry(String),
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, BpcError>;
