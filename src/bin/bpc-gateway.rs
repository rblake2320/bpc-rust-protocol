//! Deployable BPC v2 gateway.
//!
//! This process intentionally starts closed. A privileged migration/recovery
//! controller must provision the independent PostgreSQL continuity anchor and
//! complete the Redis quarantine before `serve` will accept traffic.

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bpc_protocol::{
    AuthSnapshot, BpcAxumState, BpcError, BpcVerifier, BpcVerifierConfig, ContinuityGeneration,
    GovernedRedisNonceConfig, GovernedRedisNonceStore, PairAuthority, PairKind, PairMode,
    PairRegistration, PairRequestProtocol, PostgresAuthorityConfig, PostgresPairAuthority,
    PostgresSecretProtector, PublicJwk, RedisContinuityAnchor, Result as BpcResult, Scope,
    SecretRequestHmacKey, bpc_axum_middleware, unix_ms,
};
use clap::{Parser, Subcommand};
use postgres::{Client, NoTls};
use postgres_rustls::{MakeTlsConnector, set_postgresql_alpn};
use serde_json::json;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

const ANCHOR_TABLE: &str = "bpc_gateway_continuity";

#[derive(Parser, Debug)]
#[command(
    name = "bpc-gateway",
    version,
    about = "BPC v2 request-authentication gateway"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create or update BPC and independent continuity-anchor schemas.
    Migrate,
    /// Initialize a new replay namespace after all verifier instances are fenced.
    InitializeReplay {
        /// Required acknowledgement that every verifier for this namespace is drained.
        #[arg(long)]
        fenced: bool,
    },
    /// Advance the durable replay generation after a restore, promotion, or continuity incident.
    AdvanceReplay {
        /// Required acknowledgement that every verifier for this namespace is drained.
        #[arg(long)]
        fenced: bool,
    },
    /// Submit a BPC v2 enrollment from a mode-600 local JSON file.
    Enroll {
        #[arg(long)]
        input: PathBuf,
    },
    /// Approve one pending BPC enrollment token from the privileged control plane.
    Approve {
        #[arg(long)]
        token: String,
    },
    /// List only redacted durable credential metadata.
    ListPairs,
    /// Revoke a pair and its full successor lineage.
    Revoke {
        #[arg(long)]
        pair_id: String,
    },
    /// Serve health, readiness, and BPC-protected API routes.
    Serve,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayMode {
    Development,
    Production,
}

impl GatewayMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "development" => Ok(Self::Development),
            "production" => Ok(Self::Production),
            _ => Err("BPC_GATEWAY_MODE must be development or production".into()),
        }
    }
    fn pair_mode(self) -> PairMode {
        match self {
            Self::Development => PairMode::Development,
            Self::Production => PairMode::Production,
        }
    }
}

#[derive(Clone, Debug)]
struct GatewayConfig {
    mode: GatewayMode,
    bind_addr: SocketAddr,
    audience: String,
    signature_window_ms: u64,
    max_body_bytes: usize,
    max_body_in_flight: usize,
    max_verifications: usize,
    postgres_url: String,
    postgres_schema: String,
    data_key_id: String,
    data_key_b64: String,
    redis_url: String,
    redis_namespace: String,
    anchor_postgres_url: String,
    anchor_schema: String,
    min_replica_acks: usize,
    allow_insecure_loopback: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentInput {
    name: String,
    scope: Scope,
    mode: PairMode,
    audience: String,
    request_hmac_key: String,
    public_jwk: PublicJwk,
    expires_at_ms: Option<u64>,
    max_requests: Option<u64>,
    kind: PairKind,
    canary_class: Option<bpc_protocol::CanaryClass>,
}

impl GatewayConfig {
    fn from_env() -> Result<Self, String> {
        let mode = GatewayMode::parse(&required("BPC_GATEWAY_MODE")?)?;
        let bind_addr = required("BPC_GATEWAY_BIND_ADDR")?
            .parse()
            .map_err(|_| "BPC_GATEWAY_BIND_ADDR must be a socket address".to_owned())?;
        let signature_window_ms = optional_u64("BPC_GATEWAY_SIGNATURE_WINDOW_MS", 60_000)?;
        let max_body_bytes = optional_usize("BPC_GATEWAY_MAX_BODY_BYTES", 1_048_576)?;
        let max_body_in_flight = optional_usize("BPC_GATEWAY_MAX_BODY_IN_FLIGHT", 32)?;
        let max_verifications = optional_usize("BPC_GATEWAY_MAX_VERIFICATIONS", 32)?;
        let allow_insecure_loopback = optional_bool("BPC_GATEWAY_ALLOW_INSECURE_LOOPBACK", false)?;
        if max_body_bytes == 0 || max_body_bytes > 8 * 1024 * 1024 {
            return Err("BPC_GATEWAY_MAX_BODY_BYTES must be between 1 and 8388608".into());
        }
        if max_body_in_flight == 0 || max_verifications == 0 {
            return Err("BPC gateway concurrency limits must be greater than zero".into());
        }
        if mode == GatewayMode::Production && allow_insecure_loopback {
            return Err("production gateway cannot enable insecure loopback backends".into());
        }
        let min_replica_acks = optional_usize(
            "BPC_GATEWAY_REDIS_MIN_REPLICA_ACKS",
            if mode == GatewayMode::Production {
                1
            } else {
                0
            },
        )?;
        if mode == GatewayMode::Production && min_replica_acks == 0 {
            return Err(
                "production gateway requires at least one Redis replica acknowledgement".into(),
            );
        }
        let config = Self {
            mode,
            bind_addr,
            audience: required("BPC_GATEWAY_AUDIENCE")?,
            signature_window_ms,
            max_body_bytes,
            max_body_in_flight,
            max_verifications,
            postgres_url: required("BPC_GATEWAY_POSTGRES_URL")?,
            postgres_schema: required("BPC_GATEWAY_POSTGRES_SCHEMA")?,
            data_key_id: required("BPC_GATEWAY_DATA_KEY_ID")?,
            data_key_b64: required("BPC_GATEWAY_DATA_KEY_B64")?,
            redis_url: required("BPC_GATEWAY_REDIS_URL")?,
            redis_namespace: required("BPC_GATEWAY_REDIS_NAMESPACE")?,
            anchor_postgres_url: required("BPC_GATEWAY_ANCHOR_POSTGRES_URL")?,
            anchor_schema: required("BPC_GATEWAY_ANCHOR_SCHEMA")?,
            min_replica_acks,
            allow_insecure_loopback,
        };
        validate_schema(&config.postgres_schema)?;
        validate_schema(&config.anchor_schema)?;
        if config.mode == GatewayMode::Production {
            require_verify_full(&config.anchor_postgres_url)?;
            if config.postgres_url == config.anchor_postgres_url {
                return Err(
                    "authority and replay-anchor database URLs must differ in production".into(),
                );
            }
        } else {
            require_loopback(&config.postgres_url)?;
            require_loopback(&config.anchor_postgres_url)?;
        }
        Ok(config)
    }

    fn authority_config(&self) -> BpcResult<PostgresAuthorityConfig> {
        let protector =
            PostgresSecretProtector::from_base64url(&self.data_key_id, &self.data_key_b64)?;
        let mut config = PostgresAuthorityConfig::new(protector);
        config.schema = self.postgres_schema.clone();
        config.require_synchronous_replication = self.mode == GatewayMode::Production;
        Ok(config)
    }

    fn redis_config(&self) -> BpcResult<GovernedRedisNonceConfig> {
        let mut config =
            GovernedRedisNonceConfig::new(&self.redis_namespace, self.signature_window_ms)?;
        config.min_replica_acks = self.min_replica_acks;
        config.allow_insecure_loopback = self.allow_insecure_loopback;
        config.command_timeout = Duration::from_secs(2);
        config.validate()?;
        Ok(config)
    }
}

fn required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("required environment variable {key} is not set"))
}
fn optional_u64(key: &str, default: u64) -> Result<u64, String> {
    env::var(key).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| format!("{key} must be an unsigned integer"))
    })
}
fn optional_usize(key: &str, default: usize) -> Result<usize, String> {
    env::var(key).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| format!("{key} must be an unsigned integer"))
    })
}
fn optional_bool(key: &str, default: bool) -> Result<bool, String> {
    env::var(key).map_or(Ok(default), |value| match value.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{key} must be true or false")),
    })
}

fn read_enrollment(path: &PathBuf, config: &GatewayConfig) -> BpcResult<PairRegistration> {
    let metadata = fs::metadata(path)
        .map_err(|_| BpcError::PairRegistry("could not read enrollment input file".into()))?;
    if metadata.len() == 0 || metadata.len() > 16 * 1024 {
        return Err(BpcError::PairRegistry(
            "enrollment input must be 1 to 16384 bytes".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(BpcError::PairRegistry(
                "enrollment input file must not be group/world accessible".into(),
            ));
        }
    }
    let bytes = fs::read(path)
        .map_err(|_| BpcError::PairRegistry("could not read enrollment input file".into()))?;
    let input: EnrollmentInput = serde_json::from_slice(&bytes)
        .map_err(|_| BpcError::PairRegistry("enrollment input JSON is invalid".into()))?;
    if input.mode != config.mode.pair_mode() || input.audience != config.audience {
        return Err(BpcError::PairRegistry(
            "enrollment audience or mode differs from gateway policy".into(),
        ));
    }
    let registration = PairRegistration {
        name: input.name,
        scope: input.scope,
        mode: input.mode,
        audience: input.audience,
        request_hmac_key: SecretRequestHmacKey::from_base64url(input.request_hmac_key)?,
        request_protocol: PairRequestProtocol::V2,
        public_jwk: input.public_jwk,
        expires_at_ms: input.expires_at_ms,
        max_requests: input.max_requests,
        kind: input.kind,
        canary_class: input.canary_class,
    };
    registration.validate()?;
    Ok(registration)
}

/// Separate PostgreSQL authority used only for the durable, monotonic Redis
/// continuity generation. It must be independently backed up/restored from
/// Redis; production startup refuses an identical authority/anchor URL.
struct PostgresContinuityAnchor {
    client: Mutex<Client>,
    schema: String,
    require_sync: bool,
}

impl PostgresContinuityAnchor {
    fn connect(config: &GatewayConfig) -> BpcResult<Self> {
        let mut client = if config.mode == GatewayMode::Production {
            connect_tls(&config.anchor_postgres_url)?
        } else {
            Client::connect(&config.anchor_postgres_url, NoTls).map_err(anchor_pg_error)?
        };
        set_schema(&mut client, &config.anchor_schema)?;
        Ok(Self {
            client: Mutex::new(client),
            schema: config.anchor_schema.clone(),
            require_sync: config.mode == GatewayMode::Production,
        })
    }

    fn migrate(&self) -> BpcResult<()> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::NonceStore("anchor client lock poisoned".into()))?;
        let schema = quote_identifier(&self.schema)?;
        client.batch_execute(&format!(
            "CREATE SCHEMA IF NOT EXISTS {schema}; SET search_path TO {schema};\
             CREATE TABLE IF NOT EXISTS {ANCHOR_TABLE} (\
               namespace VARCHAR(64) PRIMARY KEY CHECK (namespace ~ '^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$'),\
               generation BIGINT NOT NULL CHECK (generation > 0),\
               updated_at TIMESTAMPTZ NOT NULL DEFAULT now()\
             );"
        )).map_err(anchor_pg_error)
    }

    fn initialize_after_fencing(&self, namespace: &str) -> BpcResult<ContinuityGeneration> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::NonceStore("anchor client lock poisoned".into()))?;
        let mut tx = self.begin(&mut client)?;
        tx.execute(
            &format!("INSERT INTO {ANCHOR_TABLE} (namespace, generation) VALUES ($1, 1) ON CONFLICT (namespace) DO NOTHING"),
            &[&namespace],
        ).map_err(anchor_pg_error)?;
        let generation: i64 = tx
            .query_one(
                &format!("SELECT generation FROM {ANCHOR_TABLE} WHERE namespace = $1 FOR UPDATE"),
                &[&namespace],
            )
            .map_err(anchor_pg_error)?
            .get(0);
        tx.commit().map_err(anchor_pg_error)?;
        generation_from_i64(generation)
    }

    fn begin<'a>(&self, client: &'a mut Client) -> BpcResult<postgres::Transaction<'a>> {
        let mut tx = client.transaction().map_err(anchor_pg_error)?;
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET LOCAL statement_timeout = '5s'; SET LOCAL lock_timeout = '2s';")
            .map_err(anchor_pg_error)?;
        if self.require_sync {
            let configured: String = tx
                .query_one("SHOW synchronous_standby_names", &[])
                .map_err(anchor_pg_error)?
                .get(0);
            if configured.trim().is_empty() {
                return Err(BpcError::NonceStore("synchronous PostgreSQL replication is required for the replay continuity anchor".into()));
            }
            tx.batch_execute("SET LOCAL synchronous_commit = 'remote_apply';")
                .map_err(anchor_pg_error)?;
        }
        Ok(tx)
    }
}

impl RedisContinuityAnchor for PostgresContinuityAnchor {
    fn current_generation(&self, namespace: &str) -> BpcResult<ContinuityGeneration> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::NonceStore("anchor client lock poisoned".into()))?;
        let row = client
            .query_opt(
                &format!("SELECT generation FROM {ANCHOR_TABLE} WHERE namespace = $1"),
                &[&namespace],
            )
            .map_err(anchor_pg_error)?;
        let value: i64 = row
            .ok_or_else(|| {
                BpcError::NonceStore("replay continuity generation has not been initialized".into())
            })?
            .get(0);
        generation_from_i64(value)
    }

    fn advance_after_fencing(&self, namespace: &str) -> BpcResult<ContinuityGeneration> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::NonceStore("anchor client lock poisoned".into()))?;
        let mut tx = self.begin(&mut client)?;
        let current: i64 = tx
            .query_opt(
                &format!("SELECT generation FROM {ANCHOR_TABLE} WHERE namespace = $1 FOR UPDATE"),
                &[&namespace],
            )
            .map_err(anchor_pg_error)?
            .ok_or_else(|| {
                BpcError::NonceStore("replay continuity generation has not been initialized".into())
            })?
            .get(0);
        let next = current
            .checked_add(1)
            .ok_or_else(|| BpcError::NonceStore("replay continuity generation exhausted".into()))?;
        tx.execute(
            &format!(
                "UPDATE {ANCHOR_TABLE} SET generation = $2, updated_at = now() WHERE namespace = $1"
            ),
            &[&namespace, &next],
        )
        .map_err(anchor_pg_error)?;
        tx.commit().map_err(anchor_pg_error)?;
        generation_from_i64(next)
    }
}

fn generation_from_i64(value: i64) -> BpcResult<ContinuityGeneration> {
    let value = u64::try_from(value)
        .map_err(|_| BpcError::NonceStore("negative continuity generation".into()))?;
    ContinuityGeneration::new(value)
}
fn anchor_pg_error(_error: postgres::Error) -> BpcError {
    BpcError::NonceStore("PostgreSQL continuity-anchor operation failed".into())
}
fn validate_schema(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(
            "PostgreSQL schema must be 1-63 ASCII alphanumeric or underscore characters".into(),
        );
    }
    Ok(())
}
fn quote_identifier(value: &str) -> BpcResult<String> {
    validate_schema(value).map_err(BpcError::NonceStore)?;
    Ok(format!("\"{value}\""))
}
fn set_schema(client: &mut Client, schema: &str) -> BpcResult<()> {
    client
        .batch_execute(&format!("SET search_path TO {}", quote_identifier(schema)?))
        .map_err(anchor_pg_error)
}
fn require_loopback(connection_url: &str) -> Result<(), String> {
    let url = Url::parse(connection_url).map_err(|_| "database URL is invalid".to_owned())?;
    if !matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("::1") | Some("localhost")
    ) {
        return Err("development databases must use literal loopback or localhost".into());
    }
    Ok(())
}
fn require_verify_full(connection_url: &str) -> Result<(), String> {
    let url =
        Url::parse(connection_url).map_err(|_| "anchor database URL is invalid".to_owned())?;
    if !url
        .query_pairs()
        .any(|(key, value)| key == "sslmode" && value.eq_ignore_ascii_case("verify-full"))
    {
        return Err("production anchor database URL must use sslmode=verify-full".into());
    }
    Ok(())
}
fn connect_tls(connection_url: &str) -> BpcResult<Client> {
    require_verify_full(connection_url).map_err(BpcError::NonceStore)?;
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() {
        return Err(BpcError::NonceStore(
            "could not load complete anchor TLS trust store".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in loaded.certs {
        roots
            .add(certificate)
            .map_err(|_| BpcError::NonceStore("could not add anchor TLS trust root".into()))?;
    }
    if roots.is_empty() {
        return Err(BpcError::NonceStore(
            "anchor TLS trust store is empty".into(),
        ));
    }
    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    set_postgresql_alpn(&mut tls);
    let mut url = Url::parse(connection_url)
        .map_err(|_| BpcError::NonceStore("anchor database URL is invalid".into()))?;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (key, value) in pairs {
            query.append_pair(&key, if key == "sslmode" { "require" } else { &value });
        }
    }
    Client::connect(
        url.as_str(),
        MakeTlsConnector::new(TlsConnector::from(Arc::new(tls))),
    )
    .map_err(anchor_pg_error)
}

fn connect_authority(config: &GatewayConfig) -> BpcResult<PostgresPairAuthority> {
    let authority_config = config.authority_config()?;
    match config.mode {
        GatewayMode::Production => {
            PostgresPairAuthority::connect_tls(&config.postgres_url, authority_config)
        }
        GatewayMode::Development => {
            PostgresPairAuthority::connect(&config.postgres_url, authority_config)
        }
    }
}
fn connect_replay(
    config: &GatewayConfig,
    anchor: Arc<PostgresContinuityAnchor>,
) -> BpcResult<GovernedRedisNonceStore> {
    GovernedRedisNonceStore::connect(&config.redis_url, config.redis_config()?, anchor)
}

#[derive(Clone)]
struct ReadinessState {
    store: Arc<GovernedRedisNonceStore>,
    permits: Arc<Semaphore>,
}

async fn live() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}
async fn ready(state: ReadinessState) -> Response {
    let permit = match Arc::clone(&state.permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    match tokio::task::spawn_blocking(move || {
        // Retain the permit with the potentially stalled synchronous Redis
        // operation rather than permitting queued blocking jobs to accumulate.
        let _permit = permit;
        state.store.reconcile()
    })
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":{"code":"not_ready"}})),
        )
            .into_response(),
    }
}
async fn echo(Extension(snapshot): Extension<AuthSnapshot>) -> impl IntoResponse {
    Json(json!({
        "authenticated": true,
        "pair_id": snapshot.pair_id,
        "audience": snapshot.audience,
        "scope": format!("{:?}", snapshot.scope).to_ascii_lowercase(),
        "mode": format!("{:?}", snapshot.mode).to_ascii_lowercase(),
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config =
        GatewayConfig::from_env().map_err(|error| format!("configuration rejected: {error}"))?;
    match cli.command {
        Command::Migrate => {
            let authority = connect_authority(&config)?;
            authority.migrate()?;
            let anchor = PostgresContinuityAnchor::connect(&config)?;
            anchor.migrate()?;
            println!("BPC gateway schemas migrated");
        }
        Command::InitializeReplay { fenced } => {
            if !fenced {
                return Err("refusing replay initialization without --fenced".into());
            }
            let anchor = Arc::new(PostgresContinuityAnchor::connect(&config)?);
            anchor.migrate()?;
            let generation = anchor.initialize_after_fencing(&config.redis_namespace)?;
            let replay = connect_replay(&config, anchor)?;
            replay.provision_current_generation()?;
            println!("replay generation initialized: {generation:?}");
        }
        Command::AdvanceReplay { fenced } => {
            if !fenced {
                return Err("refusing replay-generation advance without --fenced".into());
            }
            let anchor = Arc::new(PostgresContinuityAnchor::connect(&config)?);
            let generation = anchor.advance_after_fencing(&config.redis_namespace)?;
            let replay = connect_replay(&config, anchor)?;
            replay.provision_current_generation()?;
            println!("replay generation advanced: {generation:?}");
        }
        Command::Enroll { input } => {
            let authority = connect_authority(&config)?;
            let registration = read_enrollment(&input, &config)?;
            let token = authority.request_pairing(registration, unix_ms()?)?;
            // This short-lived approval token is sensitive; print only to the
            // operator's terminal, never to application logs.
            println!("pending approval token: {token}");
        }
        Command::Approve { token } => {
            let authority = connect_authority(&config)?;
            let pair_id = authority.approve_pairing(&token, unix_ms()?)?;
            println!("approved pair: {pair_id}");
        }
        Command::ListPairs => {
            let authority = connect_authority(&config)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&authority.list_redacted()?)?
            );
        }
        Command::Revoke { pair_id } => {
            let authority = connect_authority(&config)?;
            if !authority.revoke(&pair_id)? {
                return Err("pair was not found".into());
            }
            println!("revoked pair lineage: {pair_id}");
        }
        Command::Serve => {
            let authority = Arc::new(connect_authority(&config)?);
            let anchor = Arc::new(PostgresContinuityAnchor::connect(&config)?);
            let replay = Arc::new(connect_replay(&config, anchor)?);
            replay.reconcile()?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(serve_gateway(config, authority, replay))?;
        }
    }
    Ok(())
}

async fn serve_gateway(
    config: GatewayConfig,
    authority: Arc<PostgresPairAuthority>,
    replay: Arc<GovernedRedisNonceStore>,
) -> BpcResult<()> {
    let verifier = BpcVerifier::new(
        BpcVerifierConfig::new(&config.audience, config.mode.pair_mode())?
            .with_signature_window_ms(config.signature_window_ms)?,
    );
    let mut middleware_state = BpcAxumState::new(verifier, authority, Arc::clone(&replay))
        .with_body_collection_limit(config.max_body_in_flight)
        .map_err(|error| BpcError::PairRegistry(error.into()))?
        .with_body_collection_timeout(Duration::from_secs(5))
        .map_err(|error| BpcError::PairRegistry(error.into()))?
        .with_verification_limit(config.max_verifications, Duration::from_secs(5))
        .map_err(|error| BpcError::PairRegistry(error.into()))?;
    middleware_state.max_body_bytes = config.max_body_bytes;
    let protected = Router::new()
        .route("/v1/echo", get(echo).post(echo))
        .route_layer(middleware::from_fn_with_state(
            middleware_state,
            bpc_axum_middleware::<PostgresPairAuthority, GovernedRedisNonceStore>,
        ));
    let readiness = ReadinessState {
        store: Arc::clone(&replay),
        permits: Arc::new(Semaphore::new(2)),
    };
    let app = Router::new()
        .route("/healthz", get(live))
        .route("/readyz", get(move || ready(readiness.clone())))
        .merge(protected);
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .map_err(|_| BpcError::PairRegistry("could not bind gateway listener".into()))?;
    eprintln!("BPC gateway listening on {}", config.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| BpcError::PairRegistry("gateway server failed".into()))
}
