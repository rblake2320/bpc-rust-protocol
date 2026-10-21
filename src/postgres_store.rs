//! PostgreSQL-backed BPC pair authority.
//!
//! Every state-changing operation uses a `SERIALIZABLE` transaction. Pair
//! approval, rotation, lifecycle transitions, and final successful-use claims
//! are atomic and version-fenced. Run migrations using a dedicated migration
//! role; the runtime role should retain only the DML permissions it needs.

use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use postgres::{Client, NoTls, Row, Transaction};
use postgres_rustls::{MakeTlsConnector, set_postgresql_alpn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    AuditAction, AuditEntry, AuditEvent, AuditHead, AuditLog, AuditSeverity, AuditVerification,
    BpcError, CanaryClass, PairAuthority, PairKind, PairMode, PairRecord, PairRegistration,
    PairRegistry, PairRequestProtocol, PairStatus, PublicJwk, RedactedPair, Result, Scope,
    SecretRequestHmacKey, SuccessClaim, b64url_decode, b64url_encode,
};

/// Encrypts BPC verifier material before it enters a durable PostgreSQL row.
///
/// Construct this value from a data-encryption key obtained from a secret
/// manager or KMS-backed envelope service, not from application source or a
/// database connection string. The `key_id` is deliberately carried in each
/// ciphertext envelope so a controlled re-encryption migration can distinguish
/// key generations without storing key material in PostgreSQL.
pub struct PostgresSecretProtector {
    key_id: String,
    data_key: [u8; 32],
}

impl PostgresSecretProtector {
    /// Creates a protector from exactly 32 bytes of AES-256 key material.
    pub fn new(key_id: impl Into<String>, data_key: [u8; 32]) -> Result<Self> {
        let key_id = key_id.into();
        if !is_key_id(&key_id) {
            return Err(BpcError::PairRegistry(
                "PostgreSQL secret-protector key id is invalid".into(),
            ));
        }
        Ok(Self { key_id, data_key })
    }

    /// Decodes an unpadded base64url AES-256 key supplied by a deployment
    /// secret manager. The plaintext key must never be committed or logged.
    pub fn from_base64url(key_id: impl Into<String>, encoded_data_key: &str) -> Result<Self> {
        let bytes = b64url_decode(encoded_data_key)?;
        let data_key: [u8; 32] = bytes.try_into().map_err(|_| {
            BpcError::PairRegistry("PostgreSQL data-encryption key must be 32 bytes".into())
        })?;
        Self::new(key_id, data_key)
    }

    /// Returns the non-secret key-generation label included in ciphertexts.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn seal(&self, context: &str, plaintext: &[u8]) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.data_key).map_err(|_| {
            BpcError::PairRegistry("could not initialize PostgreSQL secret protector".into())
        })?;
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| {
                BpcError::PairRegistry("could not encrypt PostgreSQL verifier secret".into())
            })?;
        let mut envelope = Vec::with_capacity(nonce.len() + ciphertext.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(format!("v1.{}.{}", self.key_id, b64url_encode(envelope)))
    }

    fn open(&self, context: &str, envelope: &str) -> Result<Vec<u8>> {
        let mut pieces = envelope.split('.');
        let (Some(version), Some(key_id), Some(encoded), None) =
            (pieces.next(), pieces.next(), pieces.next(), pieces.next())
        else {
            return Err(BpcError::PairRegistry(
                "stored PostgreSQL secret envelope is malformed".into(),
            ));
        };
        if version != "v1" || key_id != self.key_id {
            return Err(BpcError::PairRegistry(
                "stored PostgreSQL secret envelope uses an unavailable key".into(),
            ));
        }
        let bytes = b64url_decode(encoded)?;
        if bytes.len() < 12 + 16 {
            return Err(BpcError::PairRegistry(
                "stored PostgreSQL secret envelope is too short".into(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.data_key).map_err(|_| {
            BpcError::PairRegistry("could not initialize PostgreSQL secret protector".into())
        })?;
        let nonce: [u8; 12] = bytes[..12].try_into().map_err(|_| {
            BpcError::PairRegistry("stored PostgreSQL secret envelope nonce is invalid".into())
        })?;
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &bytes[12..],
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| {
                BpcError::PairRegistry("stored PostgreSQL verifier secret cannot be opened".into())
            })
    }
}

impl Clone for PostgresSecretProtector {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id.clone(),
            data_key: self.data_key,
        }
    }
}

impl std::fmt::Debug for PostgresSecretProtector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresSecretProtector")
            .field("key_id", &self.key_id)
            .field("data_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PostgresSecretProtector {
    fn drop(&mut self) {
        self.data_key.zeroize();
    }
}

/// Fresh-install schema for the Rust production authority. It uses strict
/// constraints at the database boundary; Rust additionally validates P-256
/// points and canonical base64url values before writing or returning records.
pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS bpc_pairs (
    id                    VARCHAR(64) PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,64}$'),
    name                  VARCHAR(128) NOT NULL CHECK (length(name) > 0),
    scope                 TEXT NOT NULL CHECK (scope IN ('read','read-write','admin')),
    mode                  TEXT NOT NULL CHECK (mode IN ('development','production')),
    audience              VARCHAR(256) NOT NULL CHECK (audience ~ '^[A-Za-z0-9:./_-]+$'),
    request_protocol      TEXT NOT NULL CHECK (request_protocol IN ('v1-compatibility','v2')),
    request_hmac_ciphertext TEXT NOT NULL CHECK (length(request_hmac_ciphertext) <= 512),
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
    registration_ciphertext TEXT NOT NULL CHECK (length(registration_ciphertext) <= 4096),
    request_hmac_ciphertext TEXT NOT NULL CHECK (length(request_hmac_ciphertext) <= 512),
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

// Existing active rows become explicit v1 compatibility records, which the
// secure-default verifier rejects. Old pending rows cannot prove explicit v2
// enrollment intent, so they are discarded rather than silently downgraded.
const POSTGRES_V2_MIGRATION: &str = r#"
ALTER TABLE bpc_pairs ADD COLUMN IF NOT EXISTS request_protocol TEXT;
UPDATE bpc_pairs SET request_protocol = 'v1-compatibility' WHERE request_protocol IS NULL;
ALTER TABLE bpc_pairs ALTER COLUMN request_protocol SET NOT NULL;
ALTER TABLE bpc_pairs DROP CONSTRAINT IF EXISTS bpc_pairs_request_protocol_check;
ALTER TABLE bpc_pairs ADD CONSTRAINT bpc_pairs_request_protocol_check CHECK (request_protocol IN ('v1-compatibility','v2'));
ALTER TABLE bpc_pending ADD COLUMN IF NOT EXISTS request_hmac_ciphertext TEXT;
DELETE FROM bpc_pending WHERE request_hmac_ciphertext IS NULL;
ALTER TABLE bpc_pending ALTER COLUMN request_hmac_ciphertext SET NOT NULL;
"#;

/// PostgreSQL authority configuration.
#[derive(Clone, Debug)]
pub struct PostgresAuthorityConfig {
    pub max_active_pairs: u64,
    /// Global bound for pending enrollment material. Expired rows are purged
    /// transactionally before every insert.
    pub max_pending_pairs: u64,
    /// Pending approvals expire rather than leaving unbounded authorization material.
    pub approval_ttl_ms: u64,
    pub schema: String,
    /// Mandatory envelope protector for HMAC verifier material and pending
    /// registrations. Supply a unique deployment key from a KMS/secret manager.
    pub secret_protector: PostgresSecretProtector,
    /// Requires PostgreSQL to have a configured synchronous standby and waits
    /// for `remote_apply` before acknowledging a security-state mutation.
    /// Set `false` only for isolated single-node development/tests.
    pub require_synchronous_replication: bool,
}

impl PostgresAuthorityConfig {
    /// Builds a production configuration with explicit verifier-secret
    /// protection. There is intentionally no `Default`: silently choosing a
    /// process-local or hard-coded encryption key would make durable records
    /// unreadable or falsely appear protected.
    pub fn new(secret_protector: PostgresSecretProtector) -> Self {
        Self {
            max_active_pairs: 2_000,
            max_pending_pairs: 2_000,
            approval_ttl_ms: 15 * 60 * 1_000,
            schema: "public".into(),
            secret_protector,
            require_synchronous_replication: true,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_active_pairs == 0
            || self.max_pending_pairs == 0
            || self.approval_ttl_ms == 0
            || !is_schema_name(&self.schema)
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

/// Private, non-secret pending enrollment metadata. The verifier key is sealed
/// separately with distinct authenticated data, so JSON buffers never contain
/// it and public domain objects need no Serde implementation.
#[derive(Serialize, Deserialize)]
struct PendingRegistrationMetadata {
    name: String,
    scope: Scope,
    mode: PairMode,
    audience: String,
    request_protocol: PairRequestProtocol,
    public_jwk: PublicJwk,
    expires_at_ms: Option<u64>,
    max_requests: Option<u64>,
    kind: PairKind,
    canary_class: Option<CanaryClass>,
}

impl From<&PairRegistration> for PendingRegistrationMetadata {
    fn from(registration: &PairRegistration) -> Self {
        Self {
            name: registration.name.clone(),
            scope: registration.scope,
            mode: registration.mode,
            audience: registration.audience.clone(),
            request_protocol: registration.request_protocol,
            public_jwk: registration.public_jwk.clone(),
            expires_at_ms: registration.expires_at_ms,
            max_requests: registration.max_requests,
            kind: registration.kind,
            canary_class: registration.canary_class,
        }
    }
}

impl PendingRegistrationMetadata {
    fn into_registration(self, request_hmac_key: SecretRequestHmacKey) -> PairRegistration {
        PairRegistration {
            name: self.name,
            scope: self.scope,
            mode: self.mode,
            audience: self.audience,
            request_hmac_key,
            request_protocol: self.request_protocol,
            public_jwk: self.public_jwk,
            expires_at_ms: self.expires_at_ms,
            max_requests: self.max_requests,
            kind: self.kind,
            canary_class: self.canary_class,
        }
    }
}

impl PostgresPairAuthority {
    /// Connects only to an explicitly loopback PostgreSQL endpoint without TLS.
    /// Production callers must use [`Self::connect_tls`].
    pub fn connect(url: &str, config: PostgresAuthorityConfig) -> Result<Self> {
        config.validate()?;
        require_loopback_database(url)?;
        let mut client = Client::connect(url, NoTls).map_err(pg_error)?;
        set_schema(&mut client, &config.schema)?;
        Ok(Self {
            client: Mutex::new(client),
            config,
        })
    }

    /// Connects using TLS 1.2+ and the system trust store. The URL must use
    /// `sslmode=verify-full` so certificate chain and server hostname validation
    /// are both mandatory.
    pub fn connect_tls(url: &str, config: PostgresAuthorityConfig) -> Result<Self> {
        config.validate()?;
        require_verified_postgres_tls(url)?;
        let mut client = connect_postgres_tls(url)?;
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
        set_schema(&mut client, &self.config.schema)?;
        client.batch_execute(POSTGRES_SCHEMA).map_err(pg_error)?;
        client
            .batch_execute(POSTGRES_V2_MIGRATION)
            .map_err(pg_error)
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
        if self.config.require_synchronous_replication {
            let configured: String = tx
                .query_one("SHOW synchronous_standby_names", &[])
                .map_err(pg_error)?
                .get(0);
            if configured.trim().is_empty() {
                return Err(BpcError::PairRegistry(
                    "PostgreSQL synchronous replication is required for security-state durability"
                        .into(),
                ));
            }
            tx.batch_execute("SET LOCAL synchronous_commit = 'remote_apply';")
                .map_err(pg_error)?;
        }
        Ok(tx)
    }
}

impl PairRegistry for PostgresPairAuthority {
    fn get(&self, pair_id: &str) -> Result<Option<PairRecord>> {
        let mut client = self.lock_client()?;
        let row = client
            .query_opt("SELECT * FROM bpc_pairs WHERE id = $1", &[&pair_id])
            .map_err(pg_error)?;
        row.map(|row| row_to_pair(row, &self.config.secret_protector))
            .transpose()
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
        let current = row_to_pair(row, &self.config.secret_protector)?;
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
        let token_hash = hash_token(&token);
        let mut registration_json =
            serde_json::to_vec(&PendingRegistrationMetadata::from(&registration))?;
        let registration_ciphertext = self
            .config
            .secret_protector
            .seal(&pending_metadata_context(&token_hash), &registration_json)?;
        registration_json.zeroize();
        let request_hmac_ciphertext = self.config.secret_protector.seal(
            &pending_hmac_context(&token_hash),
            registration.request_hmac_key.encoded().as_bytes(),
        )?;
        let mut client = self.lock_client()?;
        let mut tx = self.begin(&mut client)?;
        tx.execute(
            "DELETE FROM bpc_pending WHERE expires_at_ms < $1",
            &[&to_i64(now_ms)?],
        )
        .map_err(pg_error)?;
        let pending_count: i64 = tx
            .query_one("SELECT count(*) FROM bpc_pending", &[])
            .map_err(pg_error)?
            .get(0);
        if u64::try_from(pending_count)
            .map_err(|_| BpcError::PairRegistry("pending pair count is invalid".into()))?
            >= self.config.max_pending_pairs
        {
            tx.commit().map_err(pg_error)?;
            return Err(BpcError::PairRegistry(
                "maximum pending pairing capacity reached".into(),
            ));
        }
        tx.execute(
            "INSERT INTO bpc_pending(token_hash,registration_ciphertext,request_hmac_ciphertext,requested_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5)",
            &[&token_hash, &registration_ciphertext, &request_hmac_ciphertext, &to_i64(now_ms)?, &to_i64(expires)?],
        )
        .map_err(pg_error)?;
        tx.commit().map_err(pg_error)?;
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
            "SELECT registration_ciphertext, request_hmac_ciphertext, expires_at_ms FROM bpc_pending WHERE token_hash=$1 FOR UPDATE",
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
        let registration_ciphertext: String = pending.get("registration_ciphertext");
        let registration_json = self.config.secret_protector.open(
            &pending_metadata_context(&token_hash),
            &registration_ciphertext,
        )?;
        let metadata: PendingRegistrationMetadata = serde_json::from_slice(&registration_json)?;
        let request_hmac_ciphertext: String = pending.get("request_hmac_ciphertext");
        let request_hmac_key = SecretRequestHmacKey::from_base64url(
            String::from_utf8(
                self.config
                    .secret_protector
                    .open(&pending_hmac_context(&token_hash), &request_hmac_ciphertext)?,
            )
            .map_err(|_| {
                BpcError::PairRegistry("stored pending verifier key is not UTF-8".into())
            })?,
        )?;
        let registration = metadata.into_registration(request_hmac_key);
        registration.validate()?;
        if registration
            .expires_at_ms
            .is_some_and(|expires_at| now_ms > expires_at)
        {
            tx.execute(
                "DELETE FROM bpc_pending WHERE token_hash=$1",
                &[&token_hash],
            )
            .map_err(pg_error)?;
            tx.commit().map_err(pg_error)?;
            return Err(BpcError::PairRegistry(
                "pair registration has already expired".into(),
            ));
        }
        tx.execute(
            "UPDATE bpc_pairs
             SET status='expired', authorization_version=authorization_version+1
             WHERE status='active' AND expires_at_ms IS NOT NULL AND expires_at_ms < $1",
            &[&to_i64(now_ms)?],
        )
        .map_err(pg_error)?;
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
            audience: registration.audience,
            request_hmac_key: registration.request_hmac_key,
            request_protocol: registration.request_protocol,
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
            replaced_by: None,
        };
        insert_pair(&mut tx, &pair, &self.config.secret_protector)?;
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

    fn revoke(&self, pair_id: &str) -> Result<bool> {
        let mut client = self.lock_client()?;
        let mut tx = self.begin(&mut client)?;
        // Taking the root row lock before resolving descendants makes a racing
        // rotation serialize or fail, never report a successful partial revoke.
        let exists = tx
            .query_opt(
                "SELECT id FROM bpc_pairs WHERE id=$1 FOR UPDATE",
                &[&pair_id],
            )
            .map_err(pg_error)?;
        if exists.is_none() {
            tx.commit().map_err(pg_error)?;
            return Ok(false);
        }
        let changed = tx
            .execute(
                "WITH RECURSIVE lineage(id) AS (
                    SELECT id FROM bpc_pairs WHERE id=$1
                    UNION
                    SELECT predecessor.replaced_by
                    FROM bpc_pairs predecessor JOIN lineage parent ON predecessor.id=parent.id
                    WHERE predecessor.replaced_by IS NOT NULL
                 )
                 UPDATE bpc_pairs SET status='revoked', authorization_version=authorization_version+1
                 WHERE id IN (SELECT id FROM lineage) AND status <> 'revoked'",
                &[&pair_id],
            )
            .map_err(pg_error)?;
        tx.commit().map_err(pg_error)?;
        Ok(changed > 0)
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
        let current = row_to_pair(row, &self.config.secret_protector)?;
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
        insert_pair(&mut tx, &replacement, &self.config.secret_protector)?;
        tx.commit().map_err(pg_error)?;
        Ok(true)
    }

    fn list_redacted(&self) -> Result<Vec<RedactedPair>> {
        let mut client = self.lock_client()?;
        let rows = client.query(
            "SELECT id,name,scope,mode,audience,status,created_at_ms,requests FROM bpc_pairs ORDER BY created_at_ms DESC",
            &[],
        ).map_err(pg_error)?;
        rows.into_iter()
            .map(|row| {
                Ok(RedactedPair {
                    id: row.get("id"),
                    name: row.get("name"),
                    scope: parse_scope(&row.get::<_, String>("scope"))?,
                    mode: parse_mode(&row.get::<_, String>("mode"))?,
                    audience: row.get("audience"),
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
    /// Connects only to a loopback audit endpoint without TLS for isolated tests.
    /// Production callers must use [`Self::connect_tls`].
    pub fn connect(url: &str, schema: impl Into<String>) -> Result<Self> {
        let schema = schema.into();
        if !is_schema_name(&schema) {
            return Err(BpcError::PairRegistry("invalid audit schema name".into()));
        }
        require_loopback_database(url)?;
        let mut client = Client::connect(url, NoTls).map_err(pg_error)?;
        set_schema(&mut client, &schema)?;
        Ok(Self {
            client: Mutex::new(client),
            schema,
        })
    }

    /// Connects an audit chain through verified PostgreSQL TLS.
    pub fn connect_tls(url: &str, schema: impl Into<String>) -> Result<Self> {
        let schema = schema.into();
        if !is_schema_name(&schema) {
            return Err(BpcError::PairRegistry("invalid audit schema name".into()));
        }
        require_verified_postgres_tls(url)?;
        let mut client = connect_postgres_tls(url)?;
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
        set_schema(&mut client, &self.schema)?;
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
        let mut client = self
            .client
            .lock()
            .map_err(|_| BpcError::PairRegistry("PostgreSQL audit client lock poisoned".into()))?;
        let mut tx = client.transaction().map_err(pg_error)?;
        tx.batch_execute(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = '5s';",
        )
        .map_err(pg_error)?;
        let stored_head = tx
            .query_one(
                "SELECT sequence,chain_hash,count FROM bpc_audit_head WHERE singleton=TRUE",
                &[],
            )
            .map_err(pg_error)?;
        let rows = tx
            .query(
                "SELECT * FROM bpc_audit ORDER BY sequence ASC LIMIT $1",
                &[
                    &i64::try_from(crate::DEFAULT_AUDIT_VERIFY_MAX_ENTRIES + 1).map_err(|_| {
                        BpcError::PairRegistry("audit verification limit invalid".into())
                    })?,
                ],
            )
            .map_err(pg_error)?;
        tx.commit().map_err(pg_error)?;
        if rows.len() > crate::DEFAULT_AUDIT_VERIFY_MAX_ENTRIES {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: None,
                reason: Some("verification_work_limit_exceeded"),
            });
        }
        let entries = rows
            .into_iter()
            .map(row_to_audit)
            .collect::<Result<Vec<_>>>()?;
        let mut verification = crate::verify_audit_entries(&entries, expected_anchor)?;
        let stored_head = AuditHead {
            sequence: from_i64(stored_head.get("sequence"))?,
            chain_hash: stored_head.get("chain_hash"),
            count: from_i64(stored_head.get("count"))?,
        };
        let computed_head = match entries.last() {
            Some(entry) => AuditHead {
                sequence: entry.sequence,
                chain_hash: entry.chain_hash.clone(),
                count: u64::try_from(entries.len())
                    .map_err(|_| BpcError::PairRegistry("audit entry count invalid".into()))?,
            },
            None => AuditHead {
                sequence: 0,
                chain_hash: crate::GENESIS_HASH.into(),
                count: 0,
            },
        };
        if stored_head != computed_head {
            verification.valid = false;
            verification.broken_at_sequence = Some(stored_head.sequence);
            verification.reason = Some("persisted_head_mismatch");
        }
        Ok(verification)
    }
}

fn insert_pair(
    tx: &mut Transaction<'_>,
    pair: &PairRecord,
    secret_protector: &PostgresSecretProtector,
) -> Result<()> {
    pair.validate()?;
    let jwk = serde_json::to_value(&pair.public_jwk)?;
    let request_hmac_ciphertext = secret_protector.seal(
        &pair_secret_context(&pair.id),
        pair.request_hmac_key.encoded().as_bytes(),
    )?;
    let rows = tx.execute(
        "INSERT INTO bpc_pairs(id,name,scope,mode,audience,request_protocol,request_hmac_ciphertext,public_jwk,status,created_at_ms,expires_at_ms,max_requests,requests,failed_signatures,authorization_version,kind,canary_class,replaced_by)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        &[&pair.id, &pair.name, &scope_text(pair.scope), &mode_text(pair.mode), &pair.audience, &protocol_text(pair.request_protocol), &request_hmac_ciphertext, &jwk,
          &status_text(pair.status), &to_i64(pair.created_at_ms)?, &option_i64(pair.expires_at_ms)?, &option_i64(pair.max_requests)?,
          &to_i64(pair.requests)?, &i32::try_from(pair.failed_signatures).map_err(|_| BpcError::PairRegistry("failed signatures overflow".into()))?,
          &to_i64(pair.authorization_version)?, &kind_text(pair.kind), &pair.canary_class.map(canary_text), &pair.replaced_by],
    ).map_err(pg_error)?;
    if rows != 1 {
        return Err(BpcError::PairRegistry(
            "pair insert did not affect one row".into(),
        ));
    }
    Ok(())
}

fn row_to_pair(row: Row, secret_protector: &PostgresSecretProtector) -> Result<PairRecord> {
    let jwk: Value = row.get("public_jwk");
    let public_jwk: PublicJwk = serde_json::from_value(jwk)?;
    let id: String = row.get("id");
    let request_hmac_ciphertext: String = row.get("request_hmac_ciphertext");
    let request_hmac_key = SecretRequestHmacKey::from_base64url(
        String::from_utf8(
            secret_protector.open(&pair_secret_context(&id), &request_hmac_ciphertext)?,
        )
        .map_err(|_| {
            BpcError::PairRegistry("stored PostgreSQL verifier key is not UTF-8".into())
        })?,
    )?;
    let pair = PairRecord {
        id,
        name: row.get("name"),
        scope: parse_scope(&row.get::<_, String>("scope"))?,
        mode: parse_mode(&row.get::<_, String>("mode"))?,
        audience: row.get("audience"),
        request_hmac_key,
        request_protocol: parse_protocol(&row.get::<_, String>("request_protocol"))?,
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
        replaced_by: row.get("replaced_by"),
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
        && left.audience == right.audience
        && left.request_hmac_key == right.request_hmac_key
        && left.request_protocol == right.request_protocol
        && left.public_jwk == right.public_jwk
        && left.expires_at_ms == right.expires_at_ms
        && left.max_requests == right.max_requests
        && left.kind == right.kind
        && left.canary_class == right.canary_class
}

fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
fn pair_secret_context(pair_id: &str) -> String {
    format!("bpc-postgres-pair-hmac-v1:{pair_id}")
}
fn pending_metadata_context(token_hash: &str) -> String {
    format!("bpc-postgres-pending-metadata-v2:{token_hash}")
}
fn pending_hmac_context(token_hash: &str) -> String {
    format!("bpc-postgres-pending-hmac-v2:{token_hash}")
}
fn is_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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

fn require_loopback_database(connection_url: &str) -> Result<()> {
    let parsed = url::Url::parse(connection_url)
        .map_err(|_| BpcError::PairRegistry("PostgreSQL connection URL is invalid".into()))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") || !is_loopback_host(parsed.host_str())
    {
        return Err(BpcError::PairRegistry(
            "plaintext PostgreSQL is restricted to an explicit loopback endpoint; use connect_tls with sslmode=verify-full".into(),
        ));
    }
    Ok(())
}

fn require_verified_postgres_tls(connection_url: &str) -> Result<()> {
    let parsed = url::Url::parse(connection_url)
        .map_err(|_| BpcError::PairRegistry("PostgreSQL connection URL is invalid".into()))?;
    let verify_full = parsed
        .query_pairs()
        .any(|(key, value)| key == "sslmode" && value.eq_ignore_ascii_case("verify-full"));
    if !matches!(parsed.scheme(), "postgres" | "postgresql") || !verify_full {
        return Err(BpcError::PairRegistry(
            "PostgreSQL TLS URL must use sslmode=verify-full".into(),
        ));
    }
    Ok(())
}

fn connect_postgres_tls(connection_url: &str) -> Result<Client> {
    // Reqwest and PostgreSQL TLS can enable different Rustls providers in an
    // all-feature build. Explicitly select AWS-LC before constructing any TLS
    // config so Rustls never panics while resolving a process-global default.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() {
        return Err(BpcError::PairRegistry(
            "could not load complete PostgreSQL TLS trust store".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in loaded.certs {
        roots.add(certificate).map_err(|_| {
            BpcError::PairRegistry("could not add PostgreSQL TLS trust anchor".into())
        })?;
    }
    if roots.is_empty() {
        return Err(BpcError::PairRegistry(
            "PostgreSQL TLS trust store contains no certificates".into(),
        ));
    }
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    set_postgresql_alpn(&mut tls_config);
    // tokio-postgres exposes only disable/prefer/require, not libpq's
    // `verify-full`. We already enforced verify-full at our public boundary and
    // make Rustls verify the chain and hostname, so translate only for its URL
    // parser without weakening the actual TLS verifier.
    let driver_url = postgres_driver_tls_url(connection_url)?;
    Client::connect(
        &driver_url,
        MakeTlsConnector::new(TlsConnector::from(std::sync::Arc::new(tls_config))),
    )
    .map_err(pg_error)
}

fn postgres_driver_tls_url(connection_url: &str) -> Result<String> {
    let mut parsed = url::Url::parse(connection_url)
        .map_err(|_| BpcError::PairRegistry("PostgreSQL connection URL is invalid".into()))?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    {
        let mut query = parsed.query_pairs_mut();
        query.clear();
        for (key, value) in pairs {
            query.append_pair(&key, if key == "sslmode" { "require" } else { &value });
        }
    }
    Ok(parsed.into())
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost") | Some("127.0.0.1") | Some("::1"))
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
fn parse_protocol(value: &str) -> Result<PairRequestProtocol> {
    match value {
        "v1-compatibility" => Ok(PairRequestProtocol::V1Compatibility),
        "v2" => Ok(PairRequestProtocol::V2),
        _ => Err(BpcError::PairRegistry(
            "invalid stored request protocol".into(),
        )),
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
fn protocol_text(value: PairRequestProtocol) -> &'static str {
    match value {
        PairRequestProtocol::V1Compatibility => "v1-compatibility",
        PairRequestProtocol::V2 => "v2",
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
        && value.bytes().enumerate().all(|(i, b)| {
            (i == 0 && (b.is_ascii_alphabetic() || b == b'_'))
                || (i > 0 && (b.is_ascii_alphanumeric() || b == b'_'))
        })
}
fn set_schema(client: &mut Client, schema: &str) -> Result<()> {
    client
        .batch_execute(&format!("SET search_path TO {schema}, pg_catalog"))
        .map_err(pg_error)
}

fn ensure_schema(client: &mut Client, schema: &str) -> Result<()> {
    // Schema names are accepted only after `is_schema_name` validation in each
    // constructor/configuration path, so this identifier interpolation is safe.
    client
        .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
        .map_err(pg_error)
}

#[cfg(test)]
mod tests {
    use super::{
        PostgresSecretProtector, pair_secret_context, require_loopback_database,
        require_verified_postgres_tls,
    };

    #[test]
    fn verifier_secret_envelope_is_context_bound_and_tamper_evident() {
        let protector = PostgresSecretProtector::new("unit-key-v1", [42; 32]).unwrap();
        let context = pair_secret_context("pair_one");
        let envelope = protector.seal(&context, b"verifier-secret").unwrap();
        assert!(envelope.starts_with("v1.unit-key-v1."));
        assert_eq!(
            protector.open(&context, &envelope).unwrap(),
            b"verifier-secret"
        );
        assert!(
            protector
                .open(&pair_secret_context("pair_two"), &envelope)
                .is_err()
        );
        let mut tampered = envelope;
        tampered.push('A');
        assert!(protector.open(&context, &tampered).is_err());
    }

    #[test]
    fn plaintext_postgres_is_loopback_only_and_tls_requires_full_verification() {
        assert!(require_loopback_database("postgres://user:pass@127.0.0.1/db").is_ok());
        assert!(require_loopback_database("postgres://user:pass@db.example.test/db").is_err());
        assert!(
            require_verified_postgres_tls(
                "postgres://user:pass@db.example.test/db?sslmode=verify-full"
            )
            .is_ok()
        );
        assert!(
            require_verified_postgres_tls(
                "postgres://user:pass@db.example.test/db?sslmode=require"
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod hash_vectors {
    use super::hash_token;

    #[test]
    fn approval_token_hash_fixed_vector_is_stable() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
