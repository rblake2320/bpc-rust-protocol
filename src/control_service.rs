//! HTTPS/mTLS lifecycle control plane for BPC pairs.
//!
//! This module deliberately accepts no BPC private key or registration secret.
//! It accepts a strict public JWK and already-derived request HMAC key, then
//! uses only [`PairAuthority`] lifecycle methods to create, reconcile, revoke,
//! or signed-rotate durable pairs.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use crate::{
    BpcError, PairAuthority, PairKind, PairMode, PairRegistration, PostgresAuthorityConfig,
    PostgresPairAuthority, PostgresTlsConfig, ProvisionPairOutcome, PublicJwk, RotationRequest,
    Scope, is_valid_pair_id, unix_ms, verify_and_rotate_at,
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const BUNDLE_ID_MAX_BYTES: usize = 96;
const PAIR_NAME_PREFIX: &str = "keyforge-control:";

/// Error category returned by strict control-service startup validation.
///
/// It intentionally carries no path, token, URL, certificate, or database
/// detail, so it is safe for a process supervisor to print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    InvalidArguments,
    InvalidConfigFile,
    InvalidConfig,
    TlsConfiguration,
    DatabaseConnection,
    Bind,
    Serve,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::InvalidArguments => "invalid command arguments",
            Self::InvalidConfigFile => "invalid protected configuration file",
            Self::InvalidConfig => "invalid control-service configuration",
            Self::TlsConfiguration => "invalid TLS configuration",
            Self::DatabaseConnection => "database connection could not be established",
            Self::Bind => "TLS listener could not be bound",
            Self::Serve => "TLS listener failed",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for ControlError {}

/// Strict file locations used to configure mutually authenticated TLS.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFileConfig {
    pub certificate_chain_pem_path: PathBuf,
    pub private_key_pem_path: PathBuf,
    pub client_ca_pem_path: PathBuf,
}

/// Controlled authority settings. Runtime schema migration is intentionally
/// absent: migrations should be performed by a separate migration role.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFileConfig {
    #[serde(default = "default_max_active_pairs")]
    pub max_active_pairs: u64,
    #[serde(default = "default_approval_ttl_ms")]
    pub approval_ttl_ms: u64,
    #[serde(default = "default_schema")]
    pub schema: String,
}

impl Default for AuthorityFileConfig {
    fn default() -> Self {
        Self {
            max_active_pairs: default_max_active_pairs(),
            approval_ttl_ms: default_approval_ttl_ms(),
            schema: default_schema(),
        }
    }
}

impl AuthorityFileConfig {
    fn to_protocol(&self) -> PostgresAuthorityConfig {
        PostgresAuthorityConfig {
            max_active_pairs: self.max_active_pairs,
            approval_ttl_ms: self.approval_ttl_ms,
            schema: self.schema.clone(),
        }
    }
}

const fn default_max_active_pairs() -> u64 {
    2_000
}

const fn default_approval_ttl_ms() -> u64 {
    15 * 60 * 1_000
}

fn default_schema() -> String {
    "public".into()
}

/// Strictly parsed process configuration.
///
/// The file must be an absolute, regular, non-symlink, single-hard-link file
/// with mode exactly `0600`. `allow_non_loopback_bind` must be explicitly set
/// for any public/non-loopback bind address.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub bind_addr: SocketAddr,
    #[serde(default)]
    pub allow_non_loopback_bind: bool,
    pub bearer_token: String,
    pub database_url: String,
    pub postgres_ca_pem_path: PathBuf,
    pub tls: TlsFileConfig,
    #[serde(default)]
    pub authority: AuthorityFileConfig,
}

impl ServiceConfig {
    /// Reads one protected TOML configuration file without following a final
    /// symlink. Parsing and validation errors intentionally do not expose input
    /// values, including the database URL or bearer token.
    pub fn load_from_path(path: &Path) -> Result<Self, ControlError> {
        if !path.is_absolute() {
            return Err(ControlError::InvalidConfigFile);
        }
        let contents = read_protected_config(path)?;
        let text = std::str::from_utf8(&contents).map_err(|_| ControlError::InvalidConfigFile)?;
        let config: Self = toml::from_str(text).map_err(|_| ControlError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ControlError> {
        if !self.bind_addr.ip().is_loopback() && !self.allow_non_loopback_bind {
            return Err(ControlError::InvalidConfig);
        }
        if !valid_bearer_token(&self.bearer_token)
            || self.database_url.is_empty()
            || self.database_url.len() > 4 * 1024
            || !is_absolute_file_path(&self.postgres_ca_pem_path)
            || !is_absolute_file_path(&self.tls.certificate_chain_pem_path)
            || !is_absolute_file_path(&self.tls.private_key_pem_path)
            || !is_absolute_file_path(&self.tls.client_ca_pem_path)
            || self.authority.max_active_pairs == 0
            || self.authority.approval_ttl_ms == 0
            || !valid_schema_name(&self.authority.schema)
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(())
    }
}

fn read_protected_config(path: &Path) -> Result<Vec<u8>, ControlError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ControlError::InvalidConfigFile)?;
    let metadata = file
        .metadata()
        .map_err(|_| ControlError::InvalidConfigFile)?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || mode != 0o600 {
        return Err(ControlError::InvalidConfigFile);
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ControlError::InvalidConfigFile);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or_default());
    file.read_to_end(&mut bytes)
        .map_err(|_| ControlError::InvalidConfigFile)?;
    if bytes.len() > usize::try_from(MAX_CONFIG_BYTES).expect("constant fits usize") {
        return Err(ControlError::InvalidConfigFile);
    }
    Ok(bytes)
}

fn read_tls_file(path: &Path, require_mode_600: bool) -> Result<Vec<u8>, ControlError> {
    let mut file = open_tls_file(path, require_mode_600)?;
    let metadata = file
        .metadata()
        .map_err(|_| ControlError::TlsConfiguration)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ControlError::TlsConfiguration)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| ControlError::TlsConfiguration)?;
    if bytes.is_empty() || bytes.len() > usize::try_from(MAX_TLS_FILE_BYTES).expect("constant fits")
    {
        return Err(ControlError::TlsConfiguration);
    }
    Ok(bytes)
}

/// Opens a configuration-controlled TLS input without accepting symlinks,
/// hard links, replacement races, or an overly permissive private key.
fn open_tls_file(path: &Path, require_mode_600: bool) -> Result<File, ControlError> {
    if !is_absolute_file_path(path) {
        return Err(ControlError::TlsConfiguration);
    }
    let before = std::fs::symlink_metadata(path).map_err(|_| ControlError::TlsConfiguration)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_TLS_FILE_BYTES
        || (require_mode_600 && (before.permissions().mode() & 0o777) != 0o600)
    {
        return Err(ControlError::TlsConfiguration);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ControlError::TlsConfiguration)?;
    let after = file
        .metadata()
        .map_err(|_| ControlError::TlsConfiguration)?;
    if !after.file_type().is_file()
        || after.nlink() != 1
        || after.len() == 0
        || after.len() > MAX_TLS_FILE_BYTES
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || (require_mode_600 && (after.permissions().mode() & 0o777) != 0o600)
    {
        return Err(ControlError::TlsConfiguration);
    }
    Ok(file)
}

fn is_absolute_file_path(path: &Path) -> bool {
    path.is_absolute() && path.components().count() > 1
}

fn valid_bearer_token(value: &str) -> bool {
    (32..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_schema_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && (byte.is_ascii_alphabetic() || byte == b'_'))
                || (index > 0 && (byte.is_ascii_alphanumeric() || byte == b'_'))
        })
}

/// Builds a TLS 1.3-only server configuration that requires and verifies a
/// client certificate against the configured client CA roots.
pub fn load_tls_server_config(config: &TlsFileConfig) -> Result<ServerConfig, ControlError> {
    let certificate_chain = load_certificates(&config.certificate_chain_pem_path)?;
    let private_key = load_private_key(&config.private_key_pem_path)?;
    let client_ca_certificates = load_certificates(&config.client_ca_pem_path)?;

    let mut client_roots = RootCertStore::empty();
    let (added, _) = client_roots.add_parsable_certificates(client_ca_certificates);
    if added == 0 {
        return Err(ControlError::TlsConfiguration);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|_| ControlError::TlsConfiguration)?;
    let provider = rustls::crypto::ring::default_provider();
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ControlError::TlsConfiguration)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|_| ControlError::TlsConfiguration)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ControlError> {
    let certificates = CertificateDer::pem_reader_iter(open_tls_file(path, false)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControlError::TlsConfiguration)?;
    if certificates.is_empty() {
        return Err(ControlError::TlsConfiguration);
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ControlError> {
    PrivateKeyDer::from_pem_reader(open_tls_file(path, true)?)
        .map_err(|_| ControlError::TlsConfiguration)
}

/// Runs the durable production control service. This function never calls a
/// plaintext authority constructor and never performs schema migration with a
/// runtime credential.
pub async fn run(config: ServiceConfig) -> Result<(), ControlError> {
    let authority_config = config.clone();
    let authority = tokio::task::spawn_blocking(move || connect_authority(&authority_config))
        .await
        .map_err(|_| ControlError::DatabaseConnection)??;
    let tls_config = load_tls_server_config(&config.tls)?;
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .map_err(|_| ControlError::Bind)?;
    serve(
        listener,
        app(Arc::new(authority), &config.bearer_token),
        tls_config,
    )
    .await
}

/// Runs the idempotent BPC authority migration without binding a listener.
/// Operators must invoke this using a migration-only database role, then start
/// the normal listener with its separate verifier/runtime role.
pub fn migrate(config: &ServiceConfig) -> Result<(), ControlError> {
    connect_authority(config)?
        .migrate()
        .map_err(|_| ControlError::DatabaseConnection)
}

fn connect_authority(config: &ServiceConfig) -> Result<PostgresPairAuthority, ControlError> {
    let postgres_ca = read_tls_file(&config.postgres_ca_pem_path, false)?;
    let authority = PostgresPairAuthority::connect_tls(
        &config.database_url,
        config.authority.to_protocol(),
        PostgresTlsConfig::default()
            .with_system_roots(false)
            .with_additional_root_certificate_pem(postgres_ca),
    )
    .map_err(|_| ControlError::DatabaseConnection)?;
    Ok(authority)
}

/// Serves an already constructed application using TLS 1.3 mutual TLS. A TLS
/// handshake failure never reaches HTTP routing and is logged only as a generic
/// local event.
pub async fn serve(
    listener: TcpListener,
    application: Router,
    tls_config: ServerConfig,
) -> Result<(), ControlError> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    loop {
        let (stream, _) = listener.accept().await.map_err(|_| ControlError::Serve)?;
        let acceptor = acceptor.clone();
        let application = application.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(_) => {
                    eprintln!("bpc lifecycle control: TLS client authentication rejected");
                    return;
                }
            };
            let service = service_fn(move |request| application.clone().oneshot(request));
            let connection = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service)
                .await;
            if connection.is_err() {
                eprintln!("bpc lifecycle control: HTTPS connection closed with an error");
            }
        });
    }
}

#[derive(Clone)]
struct ControlState {
    authority: Arc<dyn PairAuthority>,
    bearer_token_hash: [u8; 32],
}

/// Creates the HTTP application used inside the mandatory mTLS listener.
///
/// This public constructor permits in-memory authorities only in unit tests.
/// [`run`] always constructs a durable [`PostgresPairAuthority`] over verified
/// TLS before opening a listener.
pub fn app(authority: Arc<dyn PairAuthority>, bearer_token: &str) -> Router {
    let bearer_token_hash: [u8; 32] = Sha256::digest(bearer_token.as_bytes()).into();
    Router::new()
        .route("/v1/control/bpc/provision", post(provision))
        .route("/v1/control/bpc/revoke", post(revoke))
        .route("/v1/control/bpc/rotate", post(rotate))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(ControlState {
            authority,
            bearer_token_hash,
        })
}

/// Exact, secret-free Keyforge-compatible provisioning input.
///
/// `bundleId` is optional non-authority metadata. It is only accepted as a
/// bounded public identifier, then discarded; it is never stored, compared,
/// logged, or returned. Unknown properties are rejected, preventing private
/// signing keys and registration secrets from being accepted by this service.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvisionRequest {
    pub pair_id: String,
    pub public_jwk: PublicJwk,
    pub request_hmac_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

impl ProvisionRequest {
    fn registration(&self) -> Result<PairRegistration, ApiError> {
        if !is_valid_pair_id(&self.pair_id) || !valid_bundle_id(self.bundle_id.as_deref()) {
            return Err(ApiError::Malformed);
        }
        let registration = PairRegistration {
            name: format!("{PAIR_NAME_PREFIX}{}", self.pair_id),
            scope: Scope::Admin,
            mode: PairMode::Production,
            request_hmac_key: self.request_hmac_key.clone(),
            public_jwk: self.public_jwk.clone(),
            expires_at_ms: None,
            max_requests: None,
            kind: PairKind::Legitimate,
            canary_class: None,
        };
        registration.validate().map_err(|_| ApiError::Malformed)?;
        Ok(registration)
    }
}

fn valid_bundle_id(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    (1..=BUNDLE_ID_MAX_BYTES).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokeRequest {
    pair_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotateRequest {
    #[serde(flatten)]
    request: RotationRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvisionResponse {
    pair_id: String,
    outcome: ProvisionPairOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeResponse {
    pair_id: String,
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotateResponse {
    pair_id: String,
}

async fn provision(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ProvisionResponse>, ApiError> {
    authorize(&headers, &state)?;
    let request: ProvisionRequest = parse_json(&headers, &body)?;
    let registration = request.registration()?;
    let pair_id = request.pair_id;
    let now = unix_ms().map_err(|_| ApiError::Unavailable)?;
    let authority = Arc::clone(&state.authority);
    let provision_pair_id = pair_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        authority.provision_pair(&provision_pair_id, registration, now)
    })
    .await
    .map_err(|_| ApiError::Unavailable)?
    .map_err(map_provision_error)?;
    Ok(Json(ProvisionResponse { pair_id, outcome }))
}

async fn revoke(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RevokeResponse>, ApiError> {
    authorize(&headers, &state)?;
    let request: RevokeRequest = parse_json(&headers, &body)?;
    if !is_valid_pair_id(&request.pair_id) {
        return Err(ApiError::Malformed);
    }
    // A missing ID is not a successful convergence: the intended authority
    // record was never found. An already-revoked pair remains a 200, making
    // repeated revocation idempotent after an acknowledged first request.
    let authority = Arc::clone(&state.authority);
    let pair_id = request.pair_id;
    let revoke_pair_id = pair_id.clone();
    let revoked = tokio::task::spawn_blocking(move || -> crate::Result<bool> {
        if authority.get(&revoke_pair_id)?.is_none() {
            return Ok(false);
        }
        authority.revoke(&revoke_pair_id)?;
        Ok(true)
    })
    .await
    .map_err(|_| ApiError::Unavailable)?
    .map_err(|_| ApiError::Unavailable)?;
    if !revoked {
        return Err(ApiError::NotFound);
    }
    Ok(Json(RevokeResponse {
        pair_id,
        status: "revoked",
    }))
}

async fn rotate(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RotateResponse>, ApiError> {
    authorize(&headers, &state)?;
    let request: RotateRequest = parse_json(&headers, &body)?;
    let now = unix_ms().map_err(|_| ApiError::Unavailable)?;
    let authority = Arc::clone(&state.authority);
    let pair_id = tokio::task::spawn_blocking(move || {
        verify_and_rotate_at(authority.as_ref(), &request.request, now, 60_000)
    })
    .await
    .map_err(|_| ApiError::Unavailable)?
    .map_err(map_rotation_error)?;
    Ok(Json(RotateResponse { pair_id }))
}

fn parse_json<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> Result<T, ApiError> {
    let values = headers.get_all(header::CONTENT_TYPE);
    let mut values = values.iter();
    let Some(content_type) = values.next() else {
        return Err(ApiError::Malformed);
    };
    if values.next().is_some()
        || content_type
            .to_str()
            .ok()
            .and_then(|value| value.split(';').next())
            .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(ApiError::Malformed);
    }
    serde_json::from_slice(body).map_err(|_| ApiError::Malformed)
}

fn authorize(headers: &HeaderMap, state: &ControlState) -> Result<(), ApiError> {
    let values = headers.get_all(header::AUTHORIZATION);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Err(ApiError::Unauthorized);
    };
    if values.next().is_some() {
        return Err(ApiError::Unauthorized);
    }
    let Ok(value) = value.to_str() else {
        return Err(ApiError::Unauthorized);
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(ApiError::Unauthorized);
    };
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ApiError::Unauthorized);
    }
    let supplied_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if state
        .bearer_token_hash
        .as_slice()
        .ct_eq(supplied_hash.as_slice())
        .into()
    {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

fn map_provision_error(error: BpcError) -> ApiError {
    match error {
        BpcError::PairRegistry(message)
            if message == "requested pair ID belongs to a different or inactive registration" =>
        {
            ApiError::Conflict
        }
        BpcError::PairRegistry(message) if message.starts_with("maximum active pair capacity") => {
            ApiError::Conflict
        }
        _ => ApiError::Unavailable,
    }
}

fn map_rotation_error(error: BpcError) -> ApiError {
    match error {
        BpcError::InvalidBase64 | BpcError::InvalidJwk(_) | BpcError::InvalidPayload(_) => {
            ApiError::Malformed
        }
        BpcError::InvalidSignature => ApiError::Conflict,
        BpcError::PairRegistry(_) => ApiError::Conflict,
        _ => ApiError::Unavailable,
    }
}

#[derive(Clone, Copy)]
enum ApiError {
    Unauthorized,
    Malformed,
    NotFound,
    Conflict,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "pair_not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "lifecycle_conflict"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
        };
        (status, Json(json!({ "error": { "code": code } }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{MemoryPairAuthority, MemoryPairRegistry, PairRegistry, PairStatus};

    const TOKEN: &str = "control_token_abcdefghijklmnopqrstuvwxyz0123456789";

    fn authority() -> Arc<MemoryPairAuthority> {
        Arc::new(
            MemoryPairAuthority::new(Arc::new(MemoryPairRegistry::default()), 10)
                .expect("memory authority"),
        )
    }

    fn valid_payload(pair_id: &str) -> serde_json::Value {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let public_jwk = PublicJwk::from_verifying_key(&verifying_key).expect("public JWK");
        json!({
            "pairId": pair_id,
            "publicJwk": public_jwk,
            "requestHmacKey": URL_SAFE_NO_PAD.encode([7_u8; 32]),
            "bundleId": "keyforge_bundle_123"
        })
    }

    fn request(body: serde_json::Value, authorized: bool) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/control/bpc/provision")
            .header(header::CONTENT_TYPE, "application/json");
        if authorized {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("request construction")
    }

    #[tokio::test]
    async fn provision_denies_absent_bearer_token() {
        let authority = authority();
        let response = app(authority.clone(), TOKEN)
            .oneshot(request(valid_payload("pair_auth_denied"), false))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(authority.get("pair_auth_denied").expect("get").is_none());
    }

    #[tokio::test]
    async fn provision_rejects_private_or_unknown_input_fields() {
        let authority = authority();
        let mut payload = valid_payload("pair_malformed");
        payload["privateSigningKey"] = json!("must-not-be-accepted");
        let response = app(authority.clone(), TOKEN)
            .oneshot(request(payload, true))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(authority.get("pair_malformed").expect("get").is_none());
    }

    #[test]
    fn provision_schema_is_explicitly_secret_free() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let request = ProvisionRequest {
            pair_id: "pair_schema".into(),
            public_jwk: PublicJwk::from_verifying_key(&verifying_key).expect("public JWK"),
            request_hmac_key: URL_SAFE_NO_PAD.encode([8_u8; 32]),
            bundle_id: None,
        };
        let encoded = serde_json::to_string(&request).expect("serialize schema");
        assert!(!encoded.contains("private"));
        assert!(!encoded.contains("secret"));
        assert!(encoded.contains("requestHmacKey"));
    }

    #[tokio::test]
    async fn provision_is_durable_authority_reconciliation() {
        let authority = authority();
        let payload = valid_payload("pair_reconcile");
        let first = app(authority.clone(), TOKEN)
            .oneshot(request(payload.clone(), true))
            .await
            .expect("first response");
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = to_bytes(first.into_body(), MAX_REQUEST_BYTES)
            .await
            .expect("first body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&first_body).expect("first JSON")["outcome"],
            "created"
        );
        let stored = authority
            .get("pair_reconcile")
            .expect("authority lookup")
            .expect("created pair");
        assert_eq!(stored.status, PairStatus::Active);
        assert_eq!(stored.mode, PairMode::Production);
        assert_eq!(stored.scope, Scope::Admin);

        let second = app(authority.clone(), TOKEN)
            .oneshot(request(payload, true))
            .await
            .expect("second response");
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = to_bytes(second.into_body(), MAX_REQUEST_BYTES)
            .await
            .expect("second body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&second_body).expect("second JSON")["outcome"],
            "existing"
        );
    }

    #[test]
    fn protected_config_requires_exact_mode_0600_and_no_hardlinks() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("bpc-control-{suffix}.toml"));
        let config = format!(
            "bind_addr = \"127.0.0.1:8443\"\nbearer_token = \"{TOKEN}\"\ndatabase_url = \"postgres://db.example/bpc\"\npostgres_ca_pem_path = \"/tmp/ca.pem\"\n[tls]\ncertificate_chain_pem_path = \"/tmp/cert.pem\"\nprivate_key_pem_path = \"/tmp/key.pem\"\nclient_ca_pem_path = \"/tmp/client-ca.pem\"\n"
        );
        fs::write(&path, config).expect("write config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set mode");
        assert!(matches!(
            ServiceConfig::load_from_path(&path),
            Err(ControlError::InvalidConfigFile)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set mode");
        assert!(ServiceConfig::load_from_path(&path).is_ok());
        fs::remove_file(path).expect("remove config");
    }
}
