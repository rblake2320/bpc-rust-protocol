//! PostgreSQL-backed BPC pair authority.
//!
//! Every state-changing operation uses a `SERIALIZABLE` transaction. Pair
//! approval, rotation, lifecycle transitions, and final successful-use claims
//! are atomic and version-fenced. Run migrations using a dedicated migration
//! role; the runtime role should retain only the DML permissions it needs.
//! Production constructors require TLS, certificate validation, and hostname
//! validation. Plaintext constructors are available only with the explicit
//! `postgres-insecure-tests` feature for isolated local testing.

use std::{fmt::Write as _, sync::Mutex};

use native_tls::{Certificate, Protocol, TlsConnector};
use postgres::{
    Client, Row, Transaction,
    config::{Host, SslMode},
};
use postgres_native_tls::MakeTlsConnector;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::authority::pair_matches_registration;
use crate::{
    AuditAction, AuditEntry, AuditEvent, AuditHead, AuditLog, AuditSeverity, AuditVerification,
    BpcError, CanaryClass, PairAuthority, PairKind, PairMode, PairRecord, PairRegistration,
    PairRegistry, PairStatus, ProvisionPairOutcome, PublicJwk, RedactedPair, Result, Scope,
    SuccessClaim, is_valid_pair_id,
};

/// Fresh-install schema for the Rust production authority. It uses strict
/// constraints at the database boundary; Rust additionally validates P-256
/// points and canonical base64url values before writing or returning records.
pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS bpc_pairs (
    id                    VARCHAR(64) PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,64}$'),
    name                  VARCHAR(128) NOT NULL CHECK (length(name) > 0),
    scope                 TEXT NOT NULL CHECK (scope IN ('read','read-write','admin')),
    mode                  TEXT NOT NULL CHECK (mode IN ('development','production')),
    request_hmac_key      CHAR(43) NOT NULL CHECK (request_hmac_key ~ '^[A-Za-z0-9_-]{43}$'),
    public_jwk            JSONB NOT NULL CHECK (
        public_jwk->>'kty' = 'EC' AND public_jwk->>'crv' = 'P-256'
        AND public_jwk ? 'x' AND public_jwk ? 'y'
    ),
    status                TEXT NOT NULL CHECK (status IN ('active','locked','expired','rotated','revoked')),
    created_at_ms         BIGINT NOT NULL CHECK (created_at_ms >= 0 AND created_at_ms <= 9007199254740991),
    expires_at_ms         BIGINT CHECK (expires_at_ms >= 0 AND expires_at_ms <= 9007199254740991),
    max_requests          BIGINT CHECK (max_requests IS NULL OR max_requests >= 0),
    requests              BIGINT NOT NULL DEFAULT 0 CHECK (requests >= 0),
    failed_signatures     INTEGER NOT NULL DEFAULT 0 CHECK (failed_signatures >= 0),
    authorization_version BIGINT NOT NULL DEFAULT 1 CHECK (authorization_version >= 1),
    kind                  TEXT NOT NULL DEFAULT 'legitimate' CHECK (kind IN ('legitimate','ghost')),
    canary_class          TEXT CHECK (canary_class IN ('env_file','docs','registry_exfil')),
    replaced_by           VARCHAR(64),
    CHECK ((kind = 'ghost' AND canary_class IS NOT NULL) OR (kind = 'legitimate' AND canary_class IS NULL))
);
CREATE INDEX IF NOT EXISTS bpc_pairs_active_idx ON bpc_pairs (status) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS bpc_pending (
    token_hash       CHAR(64) PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    registration     JSONB NOT NULL,
    requested_at_ms  BIGINT NOT NULL CHECK (requested_at_ms >= 0 AND requested_at_ms <= 9007199254740991),
    expires_at_ms    BIGINT NOT NULL CHECK (expires_at_ms >= requested_at_ms AND expires_at_ms <= 9007199254740991)
);
CREATE INDEX IF NOT EXISTS bpc_pending_expiry_idx ON bpc_pending (expires_at_ms);

CREATE TABLE IF NOT EXISTS bpc_audit_head (
    singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    sequence    BIGINT NOT NULL CHECK (sequence >= 0),
    chain_hash  CHAR(64) NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
    count       BIGINT NOT NULL CHECK (count >= 0)
);
INSERT INTO bpc_audit_head (singleton, sequence, chain_hash, count)
VALUES (TRUE, 0, repeat('0', 64), 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS bpc_audit (
    id            VARCHAR(64) PRIMARY KEY,
    sequence      BIGINT NOT NULL UNIQUE CHECK (sequence > 0),
    timestamp_ms  BIGINT NOT NULL CHECK (timestamp_ms >= 0 AND timestamp_ms <= 9007199254740991),
    action        TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('info','warn','critical')),
    pair_id       VARCHAR(64),
    error_code    VARCHAR(128),
    source_ip     VARCHAR(128),
    method        VARCHAR(16),
    path          VARCHAR(2048),
    request_id    VARCHAR(256),
    detail        VARCHAR(4096),
    previous_hash CHAR(64) NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    chain_hash    CHAR(64) NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS bpc_audit_pair_idx ON bpc_audit (pair_id, sequence DESC);
CREATE INDEX IF NOT EXISTS bpc_audit_time_idx ON bpc_audit (timestamp_ms DESC);
"#;

/// TLS trust configuration for the PostgreSQL production constructors.
///
/// The connector uses the platform trust store by default and always retains
/// native TLS certificate and hostname verification. A privileged deployment
/// can require an exclusive private CA by disabling platform roots before
/// adding the private CA certificate used by its database deployment to
/// [`additional_root_certificates_pem`](Self::additional_root_certificates_pem).
/// Each vector must contain one PEM-encoded X.509 CA certificate.
#[derive(Clone, Debug)]
pub struct PostgresTlsConfig {
    /// Whether operating-system trust roots are accepted in addition to explicit
    /// private roots. Defaults to `true` for library compatibility.
    pub use_system_roots: bool,
    /// Private CA certificates in PEM format, in addition to platform roots.
    pub additional_root_certificates_pem: Vec<Vec<u8>>,
}

impl Default for PostgresTlsConfig {
    fn default() -> Self {
        Self {
            use_system_roots: true,
            additional_root_certificates_pem: Vec::new(),
        }
    }
}

impl PostgresTlsConfig {
    /// Select whether operating-system trust roots are accepted. Disabling
    /// them requires at least one valid private CA root before connection.
    pub fn with_system_roots(mut self, enabled: bool) -> Self {
        self.use_system_roots = enabled;
        self
    }

    /// Adds one PEM-encoded private CA certificate to the trusted roots.
    pub fn with_additional_root_certificate_pem(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.additional_root_certificates_pem
            .push(certificate.into());
        self
    }

    fn build_connector(&self) -> Result<MakeTlsConnector> {
        if !self.use_system_roots && self.additional_root_certificates_pem.is_empty() {
            return Err(BpcError::PairRegistry(
                "exclusive PostgreSQL TLS trust requires a private root certificate".into(),
            ));
        }
        let mut builder = TlsConnector::builder();
        // Keep the TLS 1.3 floor explicit rather than inheriting a dependency
        // default that could change in a future release.
        builder.min_protocol_version(Some(Protocol::Tlsv13));
        builder.danger_accept_invalid_certs(false);
        builder.danger_accept_invalid_hostnames(false);
        builder.disable_built_in_roots(!self.use_system_roots);
        for certificate in &self.additional_root_certificates_pem {
            let certificate = Certificate::from_pem(certificate).map_err(|error| {
                BpcError::PairRegistry(format!("invalid PostgreSQL TLS root certificate: {error}"))
            })?;
            builder.add_root_certificate(certificate);
        }
        let connector = builder.build().map_err(|error| {
            BpcError::PairRegistry(format!("invalid PostgreSQL TLS configuration: {error}"))
        })?;
        Ok(MakeTlsConnector::new(connector))
    }
}

/// PostgreSQL authority configuration.
#[derive(Clone, Debug)]
pub struct PostgresAuthorityConfig {
    pub max_active_pairs: u64,
    /// Pending approvals expire rather than leaving unbounded authorization material.
    pub approval_ttl_ms: u64,
    pub schema: String,
}

impl Default for PostgresAuthorityConfig {
    fn default() -> Self {
        Self {
            max_active_pairs: 2_000,
            approval_ttl_ms: 15 * 60 * 1_000,
            schema: "public".into(),
        }
    }
}

impl PostgresAuthorityConfig {
    fn validate(&self) -> Result<()> {
        if self.max_active_pairs == 0 || self.approval_ttl_ms == 0 || !is_schema_name(&self.schema)
        {
            return Err(BpcError::PairRegistry(
                "invalid PostgreSQL authority configuration".into(),
            ));
        }
        Ok(())
    }
}

/// Durable pair authority. Its `Mutex<Client>` serializes use of the synchronous
/// PostgreSQL client; deploy multiple process instances for connection-level scale.
pub struct PostgresPairAuthority {
    client: Mutex<Client>,
    config: PostgresAuthorityConfig,
}

impl PostgresPairAuthority {
    /// Connects with TLS required plus certificate and hostname verification.
    ///
    /// The URL must name one or more TCP hosts. `sslmode=disable` and Unix
    /// socket targets are rejected; TLS is required even if `sslmode=prefer`
    /// is omitted or supplied in the URL.
    pub fn connect_tls(
        url: &str,
        config: PostgresAuthorityConfig,
        tls_config: PostgresTlsConfig,
    ) -> Result<Self> {
        config.validate()?;
        let client = connect_tls_client(url, &tls_config)?;
        Self::from_client(client, config)
    }

    /// Connects without TLS for an isolated local test database.
    ///
    /// This API is intentionally unavailable unless the
    /// `postgres-insecure-tests` feature is enabled. It must never be used in
    /// a production build.
    #[cfg(feature = "postgres-insecure-tests")]
    pub fn connect_insecure_for_tests(url: &str, config: PostgresAuthorityConfig) -> Result<Self> {
        config.validate()?;
        let client = Client::connect(url, postgres::NoTls).map_err(pg_error)?;
        Self::from_client(client, config)
    }

    fn from_client(mut client: Client, config: PostgresAuthorityConfig) -> Result<Self> {
        set_schema(&mut client, &config.schema)?;
        Ok(Self {
            client: Mutex::new(client),
            config,
        })
    }

    /// Performs fresh/idempotent schema provisioning. Use a migration role, then
    /// restrict this method from the runtime application's database credential.
    pub fn migrate(&self) -> Result<()> {
        let mut client = self.lock_client()?;
        ensure_schema(&mut client, &self.config.schema)?;
        client.batch_execute(POSTGRES_SCHEMA).map_err(pg_error)
    }

    fn lock_client(&self) -> Result<std::sync::MutexGuard<'_, Client>> {
        self.client
            .lock()
            .map_err(|_| BpcError::PairRegistry("PostgreSQL client lock poisoned".into()))
    }

    fn begin<'a>(&self, client: &'a mut Client) -> Result<Transaction<'a>> {
        let mut tx = client.transaction().map_err(pg_error)?;
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET LOCAL statement_timeout = '5s'; SET LOCAL lock_timeout = '2s';")
            .map_err(pg_error)?;
        Ok(tx)
    }
}

impl PairRegistry for PostgresPairAuthority {
    fn get(&self, pair_id: &str) -> Result<Option<PairRecord>> {
        let mut client = self.lock_client()?;
        let row = client
            .query_opt("SELECT * FROM bpc_pairs WHERE id = $1", &[&pair_id])
            .map_err(pg_error)?;
        row.map(row_to_pair).transpose()
    }

    fn record_failure(&self, pair_id: &str, lockout_after: u32) -> Result<()> {
        if lockout_after == 0 {
            return Ok(());
        }
        let mut client = self.lock_client()?;
        let threshold = i32::try_from(lockout_after).map_err(|_| {
            BpcError::PairRegistry("lockout threshold exceeds PostgreSQL range".into())
        })?;
        client
            .execute(
                "UPDATE bpc_pairs
                 SET failed_signatures = failed_signatures + 1,
                     status = CASE WHEN status = 'active' AND failed_signatures + 1 >= $2 THEN 'locked' ELSE status END,
                     authorization_version = CASE WHEN status = 'active' AND failed_signatures + 1 >= $2 THEN authorization_version + 1 ELSE authorization_version END
                 WHERE id = $1",
                &[&pair_id, &threshold],
            )
            .map_err(pg_error)?;
        Ok(())
    }

    fn claim_success(&self, expected: &PairRecord, now_ms: u64) -> Result<SuccessClaim> {
        let mut client = self.lock_client()?;
        let mut tx = self.begin(&mut client)?;
        let row = tx
            .query_opt(
                "SELECT * FROM bpc_pairs WHERE id = $1 FOR UPDATE",
                &[&expected.id],
            )
            .map_err(pg_error)?;
        let Some(row) = row else {
            tx.commit().map_err(pg_error)?;
            return Ok(SuccessClaim::StateChanged);
        };
        let current = row_to_pair(row)?;
        if !same_authorization_policy(&current, expected) {
            tx.commit().map_err(pg_error)?;
            return Ok(SuccessClaim::StateChanged);
        }
        if current.status != PairStatus::Active {
            tx.commit().map_err(pg_error)?;
            return Ok(SuccessClaim::StateChanged);
        }
        if current
            .expires_at_ms
            .is_some_and(|expires| now_ms > expires)
        {
            tx.execute(
                "UPDATE bpc_pairs SET status='expired', authorization_version=authorization_version+1 WHERE id=$1 AND authorization_version=$2",
                &[&current.id, &to_i64(current.authorization_version)?],
            ).map_err(pg_error)?;
            tx.commit().map_err(pg_error)?;
            return Ok(SuccessClaim::Expired);
        }
        if current
            .max_requests
            .is_some_and(|cap| cap > 0 && current.requests >= cap)
        {
            tx.execute(
                "UPDATE bpc_pairs SET status='expired', authorization_version=authorization_version+1 WHERE id=$1 AND authorization_version=$2",
                &[&current.id, &to_i64(current.authorization_version)?],
            ).map_err(pg_error)?;
            tx.commit().map_err(pg_error)?;
            return Ok(SuccessClaim::UsageExhausted);
        }
        let next_requests = current
            .requests
            .checked_add(1)
            .ok_or_else(|| BpcError::PairRegistry("request counter exhausted".into()))?;
        let expires_after_claim = current
            .max_requests
            .is_some_and(|cap| cap > 0 && next_requests >= cap);
        let rows = tx.execute(
            "UPDATE bpc_pairs
             SET requests=$3, failed_signatures=0,
                 status=CASE WHEN $4 THEN 'expired' ELSE status END,
                 authorization_version=CASE WHEN $4 THEN authorization_version+1 ELSE authorization_version END
             WHERE id=$1 AND authorization_version=$2 AND status='active'",
            &[&current.id, &to_i64(current.authorization_version)?, &to_i64(next_requests)?, &expires_after_claim],
        ).map_err(pg_error)?;
        if rows != 1 {
            return Err(BpcError::PairRegistry(
                "successful-use claim changed unexpectedly".into(),
            ));
        }
        tx.commit().map_err(pg_error)?;
        Ok(SuccessClaim::Claimed)
    }
}

impl PairAuthority for PostgresPairAuthority {
    fn request_pairing(&self, registration: PairRegistration, now_ms: u64) -> Result<String> {
        registration.validate()?;
        if now_ms > crate::MAX_JS_SAFE_INTEGER {
            return Err(BpcError::PairRegistry(
                "approval timestamp must be a JavaScript-safe integer".into(),
            ));
        }
        let expires = now_ms
            .checked_add(self.config.approval_ttl_ms)
            .ok_or_else(|| BpcError::PairRegistry("approval expiration overflow".into()))?;
        let token = format!("approval_{}", Uuid::new_v4().simple());
        let registration_json = serde_json::to_value(&registration)?;
        let mut client = self.lock_client()?;
        client.execute(
            "INSERT INTO bpc_pending(token_hash,registration,requested_at_ms,expires_at_ms) VALUES($1,$2,$3,$4)",
            &[&hash_token(&token), &registration_json, &to_i64(now_ms)?, &to_i64(expires)?],
        ).map_err(pg_error)?;
        Ok(token)
    }

    fn approve_pairing(&self, token: &str, now_ms: u64) -> Result<String> {
        if token.len() > 128 || token.is_empty() {
            return Err(BpcError::PairRegistry("approval token is invalid".into()));
        }
        let token_hash = hash_token(token);
        let mut client = self.lock_client()?;
        let mut tx = self.begin(&mut client)?;
        // Serialize capacity calculation while still retaining SERIALIZABLE isolation.
        tx.query_one("SELECT pg_advisory_xact_lock(842321904)", &[])
            .map_err(pg_error)?;
        let pending = tx.query_opt(
            "SELECT registration, expires_at_ms FROM bpc_pending WHERE token_hash=$1 FOR UPDATE",
            &[&token_hash],
        ).map_err(pg_error)?;
        let Some(pending) = pending else {
            tx.commit().map_err(pg_error)?;
            return Err(BpcError::PairRegistry(
                "approval token is unknown or already consumed".into(),
            ));
        };
        let expires: i64 = pending.get("expires_at_ms");
        if now_ms > from_i64(expires)? {
            tx.execute(
                "DELETE FROM bpc_pending WHERE token_hash=$1",
                &[&token_hash],
            )
            .map_err(pg_error)?;
            tx.commit().map_err(pg_error)?;
            return Err(BpcError::PairRegistry("approval token has expired".into()));
        }
        let registration_value: Value = pending.get("registration");
        let registration: PairRegistration = serde_json::from_value(registration_value)?;
        registration.validate()?;
        let active: i64 = tx
            .query_one("SELECT count(*) FROM bpc_pairs WHERE status='active'", &[])
            .map_err(pg_error)?
            .get(0);
        if u64::try_from(active)
            .map_err(|_| BpcError::PairRegistry("active pair count invalid".into()))?
            >= self.config.max_active_pairs
        {
            tx.commit().map_err(pg_error)?;
            return Err(BpcError::PairRegistry(
                "maximum active pair capacity reached".into(),
            ));
        }
        let id = format!("pair_{}", Uuid::new_v4().simple());
        let pair = PairRecord {
            id: id.clone(),
            name: registration.name,
            scope: registration.scope,
            mode: registration.mode,
            request_hmac_key: registration.request_hmac_key,
            public_jwk: registration.public_jwk,
            status: PairStatus::Active,
            created_at_ms: now_ms,
            expires_at_ms: registration.expires_at_ms,
            max_requests: registration.max_requests,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind: registration.kind,
            canary_class: registration.canary_class,
        };
        insert_pair(&mut tx, &pair)?;
        let deleted = tx
            .execute(
                "DELETE FROM bpc_pending WHERE token_hash=$1",
                &[&token_hash],
            )
            .map_err(pg_error)?;
        if deleted != 1 {
            return Err(BpcError::PairRegistry(
                "approval token changed during transaction".into(),
            ));
        }
        tx.commit().map_err(pg_error)?;
        Ok(id)
    }

    fn provision_pair(
        &self,
        pair_id: &str,
        registration: PairRegistration,
        now_ms: u64,
    ) -> Result<ProvisionPairOutcome> {
        registration.validate()?;
        if !is_valid_pair_id(pair_id) || now_ms > crate::MAX_JS_SAFE_INTEGER {
            return Err(BpcError::PairRegistry(
                "provisioning pair ID or timestamp is invalid".into(),
            ));
        }
        let mut client = self.lock_client()?;
        let mut tx = self.begin(&mut client)?;
        // Serialize the same external pair ID before inspecting or inserting it.
        // A hash collision merely serializes unrelated provisioning requests.
        tx.query_one("SELECT pg_advisory_xact_lock(hashtext($1))", &[&pair_id])
            .map_err(pg_error)?;
        if let Some(row) = tx
            .query_opt(
                "SELECT * FROM bpc_pairs WHERE id=$1 FOR UPDATE",
                &[&pair_id],
            )
            .map_err(pg_error)?
        {
            let existing = row_to_pair(row)?;
            tx.commit().map_err(pg_error)?;
            if existing.status == PairStatus::Active
                && pair_matches_registration(&existing, &registration)
            {
                return Ok(ProvisionPairOutcome::Existing);
            }
            return Err(BpcError::PairRegistry(
                "requested pair ID belongs to a different or inactive registration".into(),
            ));
        }
        tx.query_one("SELECT pg_advisory_xact_lock(842321904)", &[])
            .map_err(pg_error)?;
        let active: i64 = tx
            .query_one("SELECT count(*) FROM bpc_pairs WHERE status='active'", &[])
            .map_err(pg_error)?
            .get(0);
        if u64::try_from(active)
            .map_err(|_| BpcError::PairRegistry("active pair count invalid".into()))?
            >= self.config.max_active_pairs
        {
            return Err(BpcError::PairRegistry(
                "maximum active pair capacity reached".into(),
            ));
        }
        let pair = PairRecord {
            id: pair_id.to_owned(),
            name: registration.name,
            scope: registration.scope,
            mode: registration.mode,
            request_hmac_key: registration.request_hmac_key,
            public_jwk: registration.public_jwk,
            status: PairStatus::Active,
            created_at_ms: now_ms,
            expires_at_ms: registration.expires_at_ms,
            max_requests: registration.max_requests,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind: registration.kind,
            canary_class: registration.canary_class,
        };
        insert_pair(&mut tx, &pair)?;
        tx.commit().map_err(pg_error)?;
        Ok(ProvisionPairOutcome::Created)
    }

    fn revoke(&self, pair_id: &str) -> Result<bool> {
        let mut client = self.lock_client()?;
        let changed = client.execute(
            "UPDATE bpc_pairs SET status='revoked', authorization_version=authorization_version+1
             WHERE id=$1 AND status <> 'revoked'",
            &[&pair_id],
        ).map_err(pg_error)?;
        Ok(changed == 1)
    }

    fn rotate_pair(&self, expected_old: &PairRecord, replacement: PairRecord) -> Result<bool> {
        replacement.validate()?;
        if replacement.id == expected_old.id
            || replacement.status != PairStatus::Active
            || replacement.authorization_version != 1
        {
            return Err(BpcError::PairRegistry(
                "rotation replacement is invalid".into(),
            ));
        }
        let mut client = self.lock_client()?;
        let mut tx = self.begin(&mut client)?;
        let row = tx
            .query_opt(
                "SELECT * FROM bpc_pairs WHERE id=$1 FOR UPDATE",
                &[&expected_old.id],
            )
            .map_err(pg_error)?;
        let Some(row) = row else {
            tx.commit().map_err(pg_error)?;
            return Ok(false);
        };
        let current = row_to_pair(row)?;
        if current != *expected_old || current.status != PairStatus::Active {
            tx.commit().map_err(pg_error)?;
            return Ok(false);
        }
        let exists = tx
            .query_opt("SELECT 1 FROM bpc_pairs WHERE id=$1", &[&replacement.id])
            .map_err(pg_error)?;
        if exists.is_some() {
            tx.commit().map_err(pg_error)?;
            return Ok(false);
        }
        let updated = tx.execute(
            "UPDATE bpc_pairs SET status='rotated', replaced_by=$2, authorization_version=authorization_version+1
             WHERE id=$1 AND authorization_version=$3 AND status='active'",
            &[&current.id, &replacement.id, &to_i64(current.authorization_version)?],
        ).map_err(pg_error)?;
        if updated != 1 {
            return Err(BpcError::PairRegistry("rotation CAS failed".into()));
        }
        insert_pair(&mut tx, &replacement)?;
        tx.commit().map_err(pg_error)?;
        Ok(true)
    }

    fn list_redacted(&self) -> Result<Vec<RedactedPair>> {
        let mut client = self.lock_client()?;
        let rows = client.query(
            "SELECT id,name,scope,mode,status,created_at_ms,requests FROM bpc_pairs ORDER BY created_at_ms DESC",
            &[],
        ).map_err(pg_error)?;
        rows.into_iter()
            .map(|row| {
                Ok(RedactedPair {
                    id: row.get("id"),
                    name: row.get("name"),
                    scope: parse_scope(&row.get::<_, String>("scope"))?,
                    mode: parse_mode(&row.get::<_, String>("mode"))?,
                    status: parse_status(&row.get::<_, String>("status"))?,
                    created_at_ms: from_i64(row.get("created_at_ms"))?,
                    requests: from_i64(row.get("requests"))?,
                })
            })
            .collect()
    }
}

/// PostgreSQL implementation of the tamper-evident audit chain. It locks a
/// singleton head row so concurrent appenders receive deterministic sequences.
pub struct PostgresAuditLog {
    client: Mutex<Client>,
    schema: String,
}

impl PostgresAuditLog {
    /// Connects with TLS required plus certificate and hostname verification.
    ///
    /// The URL must name one or more TCP hosts. `sslmode=disable` and Unix
    /// socket targets are rejected; TLS is required even if `sslmode=prefer`
    /// is omitted or supplied in the URL.
    pub fn connect_tls(
        url: &str,
        schema: impl Into<String>,
        tls_config: PostgresTlsConfig,
    ) -> Result<Self> {
        let schema = schema.into();
        if !is_schema_name(&schema) {
            return Err(BpcError::PairRegistry("invalid audit schema name".into()));
        }
        let client = connect_tls_client(url, &tls_config)?;
        Self::from_client(client, schema)
    }

    /// Connects without TLS for an isolated local test database.
    ///
    /// This API is intentionally unavailable unless the
    /// `postgres-insecure-tests` feature is enabled. It must never be used in
    /// a production build.
    #[cfg(feature = "postgres-insecure-tests")]
    pub fn connect_insecure_for_tests(url: &str, schema: impl Into<String>) -> Result<Self> {
        let schema = schema.into();
        if !is_schema_name(&schema) {
            return Err(BpcError::PairRegistry("invalid audit schema name".into()));
        }
        let client = Client::connect(url, postgres::NoTls).map_err(pg_error)?;
        Self::from_client(client, schema)
    }

    fn from_client(mut client: Client, schema: String) -> Result<Self> {
        set_schema(&mut client, &schema)?;
        Ok(Self {
            client: Mutex::new(client),
            schema,
        })
    }

    pub fn migrate(&self) -> Result<()> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::PairRegistry("PostgreSQL audit client lock poisoned".into()))?;
        ensure_schema(&mut client, &self.schema)?;
        client.batch_execute(POSTGRES_SCHEMA).map_err(pg_error)
    }
}

impl AuditLog for PostgresAuditLog {
    fn append_at(&self, event: AuditEvent, timestamp_ms: u64) -> Result<AuditEntry> {
        event.validate()?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::PairRegistry("PostgreSQL audit client lock poisoned".into()))?;
        let mut tx = client.transaction().map_err(pg_error)?;
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET LOCAL statement_timeout = '5s'; SET LOCAL lock_timeout = '2s';").map_err(pg_error)?;
        let head = tx.query_one("SELECT sequence,chain_hash,count FROM bpc_audit_head WHERE singleton=TRUE FOR UPDATE", &[]).map_err(pg_error)?;
        let sequence = from_i64(head.get::<_, i64>("sequence"))?
            .checked_add(1)
            .ok_or_else(|| BpcError::PairRegistry("audit sequence exhausted".into()))?;
        let previous_hash: String = head.get("chain_hash");
        let mut entry = AuditEntry {
            id: format!("audit_{}", Uuid::new_v4().simple()),
            timestamp_ms,
            sequence,
            previous_hash,
            chain_hash: String::new(),
            event,
        };
        entry.chain_hash = crate::audit_hash(&entry)?;
        tx.execute(
            "INSERT INTO bpc_audit(id,sequence,timestamp_ms,action,severity,pair_id,error_code,source_ip,method,path,request_id,detail,previous_hash,chain_hash)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[&entry.id, &to_i64(entry.sequence)?, &to_i64(entry.timestamp_ms)?, &entry.event.action.as_str(), &entry.event.severity.as_str(),
              &entry.event.pair_id, &entry.event.error_code, &entry.event.source_ip, &entry.event.method, &entry.event.path,
              &entry.event.request_id, &entry.event.detail, &entry.previous_hash, &entry.chain_hash],
        ).map_err(pg_error)?;
        tx.execute(
            "UPDATE bpc_audit_head SET sequence=$1,chain_hash=$2,count=$1 WHERE singleton=TRUE",
            &[&to_i64(sequence)?, &entry.chain_hash],
        )
        .map_err(pg_error)?;
        tx.commit().map_err(pg_error)?;
        Ok(entry)
    }

    fn entries(&self) -> Result<Vec<AuditEntry>> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::PairRegistry("PostgreSQL audit client lock poisoned".into()))?;
        client
            .query("SELECT * FROM bpc_audit ORDER BY sequence ASC", &[])
            .map_err(pg_error)?
            .into_iter()
            .map(row_to_audit)
            .collect()
    }

    fn head(&self) -> Result<AuditHead> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::PairRegistry("PostgreSQL audit client lock poisoned".into()))?;
        let row = client
            .query_one(
                "SELECT sequence,chain_hash,count FROM bpc_audit_head WHERE singleton=TRUE",
                &[],
            )
            .map_err(pg_error)?;
        Ok(AuditHead {
            sequence: from_i64(row.get("sequence"))?,
            chain_hash: row.get("chain_hash"),
            count: from_i64(row.get("count"))?,
        })
    }

    fn verify(&self, expected_anchor: Option<&AuditHead>) -> Result<AuditVerification> {
        crate::verify_audit_entries(&self.entries()?, expected_anchor)
    }
}

fn insert_pair(tx: &mut Transaction<'_>, pair: &PairRecord) -> Result<()> {
    pair.validate()?;
    let jwk = serde_json::to_value(&pair.public_jwk)?;
    let rows = tx.execute(
        "INSERT INTO bpc_pairs(id,name,scope,mode,request_hmac_key,public_jwk,status,created_at_ms,expires_at_ms,max_requests,requests,failed_signatures,authorization_version,kind,canary_class)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        &[&pair.id, &pair.name, &scope_text(pair.scope), &mode_text(pair.mode), &pair.request_hmac_key, &jwk,
          &status_text(pair.status), &to_i64(pair.created_at_ms)?, &option_i64(pair.expires_at_ms)?, &option_i64(pair.max_requests)?,
          &to_i64(pair.requests)?, &i32::try_from(pair.failed_signatures).map_err(|_| BpcError::PairRegistry("failed signatures overflow".into()))?,
          &to_i64(pair.authorization_version)?, &kind_text(pair.kind), &pair.canary_class.map(canary_text)],
    ).map_err(pg_error)?;
    if rows != 1 {
        return Err(BpcError::PairRegistry(
            "pair insert did not affect one row".into(),
        ));
    }
    Ok(())
}

fn row_to_pair(row: Row) -> Result<PairRecord> {
    let jwk: Value = row.get("public_jwk");
    let public_jwk: PublicJwk = serde_json::from_value(jwk)?;
    let pair = PairRecord {
        id: row.get("id"),
        name: row.get("name"),
        scope: parse_scope(&row.get::<_, String>("scope"))?,
        mode: parse_mode(&row.get::<_, String>("mode"))?,
        request_hmac_key: row.get("request_hmac_key"),
        public_jwk,
        status: parse_status(&row.get::<_, String>("status"))?,
        created_at_ms: from_i64(row.get("created_at_ms"))?,
        expires_at_ms: option_from_i64(row.get("expires_at_ms"))?,
        max_requests: option_from_i64(row.get("max_requests"))?,
        requests: from_i64(row.get("requests"))?,
        failed_signatures: u32::try_from(row.get::<_, i32>("failed_signatures"))
            .map_err(|_| BpcError::PairRegistry("negative failed signature count".into()))?,
        authorization_version: from_i64(row.get("authorization_version"))?,
        kind: parse_kind(&row.get::<_, String>("kind"))?,
        canary_class: row
            .get::<_, Option<String>>("canary_class")
            .map(|value| parse_canary(&value))
            .transpose()?,
    };
    pair.validate()?;
    Ok(pair)
}

fn row_to_audit(row: Row) -> Result<AuditEntry> {
    let action = parse_audit_action(&row.get::<_, String>("action"))?;
    let severity = parse_severity(&row.get::<_, String>("severity"))?;
    Ok(AuditEntry {
        id: row.get("id"),
        timestamp_ms: from_i64(row.get("timestamp_ms"))?,
        sequence: from_i64(row.get("sequence"))?,
        previous_hash: row.get("previous_hash"),
        chain_hash: row.get("chain_hash"),
        event: AuditEvent {
            action,
            severity,
            pair_id: row.get("pair_id"),
            error_code: row.get("error_code"),
            source_ip: row.get("source_ip"),
            method: row.get("method"),
            path: row.get("path"),
            request_id: row.get("request_id"),
            detail: row.get("detail"),
        },
    })
}

fn same_authorization_policy(left: &PairRecord, right: &PairRecord) -> bool {
    left.authorization_version == right.authorization_version
        && left.status == right.status
        && left.scope == right.scope
        && left.mode == right.mode
        && left.request_hmac_key == right.request_hmac_key
        && left.public_jwk == right.public_jwk
        && left.expires_at_ms == right.expires_at_ms
        && left.max_requests == right.max_requests
        && left.kind == right.kind
        && left.canary_class == right.canary_class
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}
fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BpcError::PairRegistry("integer exceeds PostgreSQL BIGINT".into()))
}
fn from_i64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| BpcError::PairRegistry("negative PostgreSQL integer".into()))
}
fn option_i64(value: Option<u64>) -> Result<Option<i64>> {
    value.map(to_i64).transpose()
}
fn option_from_i64(value: Option<i64>) -> Result<Option<u64>> {
    value.map(from_i64).transpose()
}
fn pg_error(error: postgres::Error) -> BpcError {
    BpcError::PairRegistry(format!("PostgreSQL error: {error}"))
}

fn connect_tls_client(url: &str, tls_config: &PostgresTlsConfig) -> Result<Client> {
    let config = tls_connection_config(url)?;
    let connector = tls_config.build_connector()?;
    config.connect(connector).map_err(pg_error)
}

fn tls_connection_config(url: &str) -> Result<postgres::Config> {
    let mut config = url.parse::<postgres::Config>().map_err(pg_error)?;
    if config.get_ssl_mode() == SslMode::Disable {
        return Err(BpcError::PairRegistry(
            "PostgreSQL TLS connection rejects sslmode=disable".into(),
        ));
    }
    if config.get_hosts().is_empty() {
        return Err(BpcError::PairRegistry(
            "PostgreSQL TLS connection requires a TCP hostname for certificate verification".into(),
        ));
    }
    if config
        .get_hosts()
        .iter()
        .any(|host| !matches!(host, Host::Tcp(_)))
    {
        return Err(BpcError::PairRegistry(
            "PostgreSQL TLS connection rejects Unix socket targets because hostname verification is required"
                .into(),
        ));
    }
    // `postgres` defaults to `prefer`, which can fall back to plaintext. Force
    // TLS for every production constructor after rejecting explicit disable.
    config.ssl_mode(SslMode::Require);
    Ok(config)
}

fn parse_scope(value: &str) -> Result<Scope> {
    match value {
        "read" => Ok(Scope::Read),
        "read-write" => Ok(Scope::ReadWrite),
        "admin" => Ok(Scope::Admin),
        _ => Err(BpcError::PairRegistry("invalid stored scope".into())),
    }
}
fn parse_mode(value: &str) -> Result<PairMode> {
    match value {
        "development" => Ok(PairMode::Development),
        "production" => Ok(PairMode::Production),
        _ => Err(BpcError::PairRegistry("invalid stored mode".into())),
    }
}
fn parse_status(value: &str) -> Result<PairStatus> {
    match value {
        "active" => Ok(PairStatus::Active),
        "locked" => Ok(PairStatus::Locked),
        "expired" => Ok(PairStatus::Expired),
        "rotated" => Ok(PairStatus::Rotated),
        "revoked" => Ok(PairStatus::Revoked),
        _ => Err(BpcError::PairRegistry("invalid stored status".into())),
    }
}
fn parse_kind(value: &str) -> Result<PairKind> {
    match value {
        "legitimate" => Ok(PairKind::Legitimate),
        "ghost" => Ok(PairKind::Ghost),
        _ => Err(BpcError::PairRegistry("invalid stored pair kind".into())),
    }
}
fn parse_canary(value: &str) -> Result<CanaryClass> {
    match value {
        "env_file" => Ok(CanaryClass::EnvFile),
        "docs" => Ok(CanaryClass::Docs),
        "registry_exfil" => Ok(CanaryClass::RegistryExfil),
        _ => Err(BpcError::PairRegistry("invalid stored canary class".into())),
    }
}
fn parse_audit_action(value: &str) -> Result<AuditAction> {
    match value {
        "verify_pass" => Ok(AuditAction::VerifyPass),
        "verify_fail" => Ok(AuditAction::VerifyFail),
        "register" => Ok(AuditAction::Register),
        "approve" => Ok(AuditAction::Approve),
        "revoke" => Ok(AuditAction::Revoke),
        "rotate" => Ok(AuditAction::Rotate),
        "lockout" => Ok(AuditAction::Lockout),
        "unlock" => Ok(AuditAction::Unlock),
        "expire" => Ok(AuditAction::Expire),
        "usage_cap_exhausted" => Ok(AuditAction::UsageCapExhausted),
        _ => Err(BpcError::PairRegistry("invalid stored audit action".into())),
    }
}
fn parse_severity(value: &str) -> Result<AuditSeverity> {
    match value {
        "info" => Ok(AuditSeverity::Info),
        "warn" => Ok(AuditSeverity::Warn),
        "critical" => Ok(AuditSeverity::Critical),
        _ => Err(BpcError::PairRegistry(
            "invalid stored audit severity".into(),
        )),
    }
}
fn scope_text(value: Scope) -> &'static str {
    match value {
        Scope::Read => "read",
        Scope::ReadWrite => "read-write",
        Scope::Admin => "admin",
    }
}
fn mode_text(value: PairMode) -> &'static str {
    match value {
        PairMode::Development => "development",
        PairMode::Production => "production",
    }
}
fn status_text(value: PairStatus) -> &'static str {
    match value {
        PairStatus::Active => "active",
        PairStatus::Locked => "locked",
        PairStatus::Expired => "expired",
        PairStatus::Rotated => "rotated",
        PairStatus::Revoked => "revoked",
    }
}
fn kind_text(value: PairKind) -> &'static str {
    match value {
        PairKind::Legitimate => "legitimate",
        PairKind::Ghost => "ghost",
    }
}
fn canary_text(value: CanaryClass) -> &'static str {
    match value {
        CanaryClass::EnvFile => "env_file",
        CanaryClass::Docs => "docs",
        CanaryClass::RegistryExfil => "registry_exfil",
    }
}
fn is_schema_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with("pg_")
        && value.bytes().enumerate().all(|(i, b)| {
            (i == 0 && (b.is_ascii_alphabetic() || b == b'_'))
                || (i > 0 && (b.is_ascii_alphanumeric() || b == b'_'))
        })
}
fn set_schema(client: &mut Client, schema: &str) -> Result<()> {
    client
        .batch_execute(&format!(
            "SET search_path TO {}, pg_catalog",
            quote_schema(schema)
        ))
        .map_err(pg_error)
}

fn ensure_schema(client: &mut Client, schema: &str) -> Result<()> {
    client
        .batch_execute(&format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            quote_schema(schema)
        ))
        .map_err(pg_error)?;
    set_schema(client, schema)
}

fn quote_schema(schema: &str) -> String {
    // All callers validate with `is_schema_name`; the explicit double-quoting
    // preserves the configured case-free identifier as one SQL identifier.
    format!("\"{schema}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_url_rejects_plaintext_and_unverifiable_targets() {
        let plaintext = tls_connection_config("postgres://user@db.example/bpc?sslmode=disable")
            .expect_err("sslmode=disable must not reach a production connector");
        assert!(plaintext.to_string().contains("sslmode=disable"));

        let unix_socket = tls_connection_config("host=/var/run/postgresql dbname=bpc")
            .expect_err("Unix sockets cannot provide a TLS hostname");
        assert!(unix_socket.to_string().contains("Unix socket"));
    }

    #[test]
    fn tls_url_forces_require_and_rejects_bad_private_roots() {
        let config = tls_connection_config("postgres://user@db.example/bpc?sslmode=prefer")
            .expect("a TCP hostname is usable once TLS is made mandatory");
        assert_eq!(config.get_ssl_mode(), SslMode::Require);

        match PostgresTlsConfig::default()
            .with_system_roots(false)
            .build_connector()
        {
            Ok(_) => panic!("an exclusive trust policy needs a configured private root"),
            Err(error) => assert!(error.to_string().contains("exclusive PostgreSQL TLS trust")),
        }

        let result = PostgresTlsConfig::default()
            .with_additional_root_certificate_pem(b"not a PEM certificate".to_vec())
            .build_connector();
        match result {
            Ok(_) => panic!("malformed private roots must fail before network use"),
            Err(error) => assert!(error.to_string().contains("TLS root certificate")),
        }
    }

    #[test]
    fn authority_config_rejects_zero_limits_and_invalid_schema() {
        let zero_limit = PostgresAuthorityConfig {
            max_active_pairs: 0,
            ..PostgresAuthorityConfig::default()
        };
        assert!(zero_limit.validate().is_err());

        let invalid_schema = PostgresAuthorityConfig {
            schema: "public; DROP SCHEMA public".into(),
            ..PostgresAuthorityConfig::default()
        };
        assert!(invalid_schema.validate().is_err());

        let reserved_schema = PostgresAuthorityConfig {
            schema: "pg_catalog".into(),
            ..PostgresAuthorityConfig::default()
        };
        assert!(reserved_schema.validate().is_err());
    }
}
