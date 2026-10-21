//! Governed Redis replay protection for multi-process BPC deployments.
//!
//! The backend uses one Lua transaction to check continuity metadata, enforce a
//! fixed retention configuration, honor quarantine, and execute `SET NX PX`.
//! Plain `SET NX` is not exposed as a production acceptance path because it
//! cannot detect a restored/evicted Redis nonce keyspace.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use redis::{Client, Connection};

use crate::{BpcError, MAX_SIGNATURE_WINDOW_MS, NonceStore, Result};

const DEFAULT_SAFETY_BUFFER_MS: u64 = 10_000;
const DEFAULT_CONTINUITY_ALLOWANCE_MS: u64 = 30_000;

const CONSUME_SCRIPT: &str = r#"
local marker = redis.call('GET', KEYS[2])
local configured = redis.call('GET', KEYS[4])
if configured and configured ~= ARGV[4] then
  return 'CONFIG_MISMATCH'
end
if not configured then
  redis.call('SET', KEYS[4], ARGV[4], 'NX')
end
if not marker then
  redis.call('SET', KEYS[3], 'missing-marker', 'PX', ARGV[3])
  redis.call('SET', KEYS[2], ARGV[1], 'NX')
  return 'QUARANTINED'
end
if marker ~= ARGV[1] then
  redis.call('SET', KEYS[3], 'epoch-changed', 'PX', ARGV[3])
  return 'EPOCH_MISMATCH'
end
if redis.call('GET', KEYS[3]) then
  return 'QUARANTINED'
end
local current_time = redis.call('TIME')
local now_ms = tonumber(current_time[1]) * 1000 + math.floor(tonumber(current_time[2]) / 1000)
local signed_timestamp_ms = tonumber(ARGV[5])
local window_ms = tonumber(ARGV[6])
if math.abs(now_ms - signed_timestamp_ms) > window_ms then
  return 'STALE'
end
local accepted = redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[2])
if accepted then
  return 'FRESH'
end
return 'REPLAY'
"#;

const PROVISION_SCRIPT: &str = r#"
local marker = redis.call('GET', KEYS[1])
local configured = redis.call('GET', KEYS[3])
if configured and configured ~= ARGV[2] then
  return 'CONFIG_MISMATCH'
end
if not configured then
  redis.call('SET', KEYS[3], ARGV[2], 'NX')
end
if not marker then
  redis.call('SET', KEYS[1], ARGV[1], 'NX')
  redis.call('SET', KEYS[2], 'new-epoch', 'PX', ARGV[3])
  return 'QUARANTINED'
end
if marker ~= ARGV[1] then
  redis.call('SET', KEYS[2], 'epoch-mismatch', 'PX', ARGV[3])
  return 'EPOCH_MISMATCH'
end
if redis.call('GET', KEYS[2]) then
  return 'QUARANTINED'
end
return 'READY'
"#;

/// Production Redis nonce configuration.
#[derive(Clone, Debug)]
pub struct GovernedRedisNonceConfig {
    /// Isolates Redis hash-tagged keys by environment. 1–64 ASCII safe characters.
    pub namespace: String,
    /// Expected continuity epoch controlled by deployment configuration.
    pub epoch: String,
    /// BPC signature acceptance window, normally 60,000 ms.
    pub signature_window_ms: u64,
    /// Extra nonce retention after twice the signing window.
    pub safety_buffer_ms: u64,
    /// Extra quarantine beyond nonce retention after a continuity anomaly.
    pub continuity_allowance_ms: u64,
    /// Maximum duration of each blocking Redis command.
    pub command_timeout: Duration,
    /// Minimum replicas that must acknowledge a fresh nonce write before the
    /// verifier may authorize it. One is the secure production default; zero
    /// is permitted only with explicit insecure-loopback development mode.
    pub min_replica_acks: usize,
    /// Allows `redis://` only for a literal loopback host in isolated tests or
    /// local development. Production defaults to verified `rediss://`.
    pub allow_insecure_loopback: bool,
}

impl GovernedRedisNonceConfig {
    pub fn new(
        namespace: impl Into<String>,
        epoch: impl Into<String>,
        signature_window_ms: u64,
    ) -> Result<Self> {
        let config = Self {
            namespace: namespace.into(),
            epoch: epoch.into(),
            signature_window_ms,
            safety_buffer_ms: DEFAULT_SAFETY_BUFFER_MS,
            continuity_allowance_ms: DEFAULT_CONTINUITY_ALLOWANCE_MS,
            command_timeout: Duration::from_secs(2),
            min_replica_acks: 1,
            allow_insecure_loopback: false,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn retention_ms(&self) -> Result<u64> {
        self.signature_window_ms
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.safety_buffer_ms))
            .filter(|value| *value > 0)
            .ok_or_else(|| BpcError::NonceStore("nonce retention overflows or is zero".into()))
    }

    pub fn quarantine_ms(&self) -> Result<u64> {
        self.retention_ms().and_then(|value| {
            value
                .checked_add(self.continuity_allowance_ms)
                .ok_or_else(|| BpcError::NonceStore("quarantine duration overflows".into()))
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !is_namespace(&self.namespace) {
            return Err(BpcError::NonceStore(
                "Redis namespace must be 1–64 ASCII [A-Za-z0-9][A-Za-z0-9._-]*".into(),
            ));
        }
        if self.epoch.is_empty() || self.epoch.len() > 128 || !self.epoch.bytes().all(is_epoch_byte)
        {
            return Err(BpcError::NonceStore(
                "Redis continuity epoch is invalid".into(),
            ));
        }
        if self.signature_window_ms == 0
            || self.signature_window_ms > MAX_SIGNATURE_WINDOW_MS
            || self.command_timeout.is_zero()
        {
            return Err(BpcError::NonceStore(
                "Redis nonce durations must be positive".into(),
            ));
        }
        if self.min_replica_acks > 16
            || (self.min_replica_acks == 0 && !self.allow_insecure_loopback)
        {
            return Err(BpcError::NonceStore(
                "Redis replica acknowledgement policy is invalid".into(),
            ));
        }
        self.retention_ms()?;
        self.quarantine_ms()?;
        Ok(())
    }
}

/// Redis-backed BPC nonce store with a local ambiguity gate.
///
/// When an EVAL times out or fails, the local gate remains closed until an
/// explicit successful [`Self::reconcile`] after the Redis quarantine elapsed.
pub struct GovernedRedisNonceStore {
    connection: Mutex<Connection>,
    config: GovernedRedisNonceConfig,
    locally_quarantined: AtomicBool,
}

impl GovernedRedisNonceStore {
    /// Connects and proves the Redis server uses `maxmemory-policy noeviction`.
    pub fn connect(url: &str, config: GovernedRedisNonceConfig) -> Result<Self> {
        config.validate()?;
        require_secure_redis_transport(url, &config)?;
        let client = Client::open(url).map_err(redis_error)?;
        let mut connection = client.get_connection().map_err(redis_error)?;
        let timeout = config.command_timeout;
        connection
            .set_read_timeout(Some(timeout))
            .map_err(redis_error)?;
        connection
            .set_write_timeout(Some(timeout))
            .map_err(redis_error)?;
        assert_noeviction(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            config,
            locally_quarantined: AtomicBool::new(true),
        })
    }

    /// Installs/verifies the configured epoch. Fresh or changed namespaces are
    /// deliberately quarantined for a full retention horizon before serving.
    pub fn provision_epoch(&self) -> Result<()> {
        let mut connection = self.lock_connection()?;
        assert_noeviction(&mut connection)?;
        let reply = eval_provision(&mut connection, &self.config)?;
        match reply.as_str() {
            "READY" => {
                self.locally_quarantined.store(false, Ordering::Release);
                Ok(())
            }
            "QUARANTINED" | "EPOCH_MISMATCH" => {
                self.locally_quarantined.store(true, Ordering::Release);
                Err(BpcError::NonceStore(format!(
                    "Redis continuity namespace is quarantined ({reply})"
                )))
            }
            _ => {
                self.locally_quarantined.store(true, Ordering::Release);
                Err(BpcError::NonceStore(
                    "unexpected Redis provisioning reply".into(),
                ))
            }
        }
    }

    /// Re-opens the local gate only when Redis reports the configured marker,
    /// fixed horizon, safe eviction policy, and no active quarantine.
    pub fn reconcile(&self) -> Result<()> {
        let mut connection = self.lock_connection()?;
        assert_noeviction(&mut connection)?;
        let keys = continuity_keys(&self.config.namespace);
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&[&keys.marker, &keys.quarantine, &keys.config])
            .query(&mut *connection)
            .map_err(redis_error)?;
        if values.len() != 3
            || values[0].as_deref() != Some(&self.config.epoch)
            || values[1].is_some()
            || values[2].as_deref() != Some(&expected_config(&self.config)?)
        {
            self.locally_quarantined.store(true, Ordering::Release);
            return Err(BpcError::NonceStore(
                "Redis continuity state is absent, changed, or quarantined".into(),
            ));
        }
        self.locally_quarantined.store(false, Ordering::Release);
        Ok(())
    }

    pub fn is_locally_quarantined(&self) -> bool {
        self.locally_quarantined.load(Ordering::Acquire)
    }

    pub fn retention_ms(&self) -> Result<u64> {
        self.config.retention_ms()
    }

    fn lock_connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| BpcError::NonceStore("Redis connection lock poisoned".into()))
    }
}

impl NonceStore for GovernedRedisNonceStore {
    fn check_and_consume(
        &self,
        pair_id: &str,
        nonce: &str,
        signed_timestamp_ms: u64,
        _now_ms: u64,
        ttl_ms: u64,
    ) -> Result<bool> {
        if self.locally_quarantined.load(Ordering::Acquire) {
            return Err(BpcError::NonceStore(
                "Redis nonce gate is locally quarantined".into(),
            ));
        }
        if ttl_ms != self.config.retention_ms()? {
            self.locally_quarantined.store(true, Ordering::Release);
            return Err(BpcError::NonceStore(
                "verifier nonce TTL does not match governed Redis horizon".into(),
            ));
        }
        let result = (|| {
            let mut connection = self.lock_connection()?;
            let keys = continuity_keys(&self.config.namespace);
            let nonce_key = format!("{}{}:{nonce}", keys.nonce_prefix, pair_id);
            let reply: String = redis::cmd("EVAL")
                .arg(CONSUME_SCRIPT)
                .arg(4)
                .arg(nonce_key)
                .arg(&keys.marker)
                .arg(&keys.quarantine)
                .arg(&keys.config)
                .arg(&self.config.epoch)
                .arg(self.config.retention_ms()?)
                .arg(self.config.quarantine_ms()?)
                .arg(expected_config(&self.config)?)
                .arg(signed_timestamp_ms)
                .arg(self.config.signature_window_ms)
                .query(&mut *connection)
                .map_err(redis_error)?;
            Ok(reply)
        })();
        match result {
            Ok(reply) if reply == "FRESH" => {
                if let Err(error) = self.require_replica_acks() {
                    self.locally_quarantined.store(true, Ordering::Release);
                    return Err(error);
                }
                Ok(false)
            }
            Ok(reply) if reply == "REPLAY" => Ok(true),
            Ok(reply) => {
                self.locally_quarantined.store(true, Ordering::Release);
                Err(BpcError::NonceStore(format!(
                    "Redis continuity rejected nonce consumption ({reply})"
                )))
            }
            Err(error) => {
                // A timeout could have consumed the nonce after the caller gave up.
                // Fail closed locally rather than retrying this ambiguous operation.
                self.locally_quarantined.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
}

impl GovernedRedisNonceStore {
    fn require_replica_acks(&self) -> Result<()> {
        if self.config.min_replica_acks == 0 {
            return Ok(());
        }
        let mut connection = self.lock_connection()?;
        let acknowledged: i64 = redis::cmd("WAIT")
            .arg(self.config.min_replica_acks)
            .arg(self.config.command_timeout.as_millis())
            .query(&mut *connection)
            .map_err(redis_error)?;
        let required = i64::try_from(self.config.min_replica_acks)
            .map_err(|_| BpcError::NonceStore("Redis replica count is invalid".into()))?;
        if acknowledged < required {
            return Err(BpcError::NonceStore(
                "Redis nonce write did not reach the required replica acknowledgement quorum"
                    .into(),
            ));
        }
        Ok(())
    }
}

struct RedisKeys {
    nonce_prefix: String,
    marker: String,
    quarantine: String,
    config: String,
}

fn continuity_keys(namespace: &str) -> RedisKeys {
    let tag = format!("{{{namespace}}}");
    RedisKeys {
        nonce_prefix: format!("bpc:{tag}:nonce:"),
        marker: format!("bpc:{tag}:continuity:v1"),
        quarantine: format!("bpc:{tag}:continuity-quarantine:v1"),
        config: format!("bpc:{tag}:continuity-config:v1"),
    }
}

fn eval_provision(
    connection: &mut Connection,
    config: &GovernedRedisNonceConfig,
) -> Result<String> {
    let keys = continuity_keys(&config.namespace);
    redis::cmd("EVAL")
        .arg(PROVISION_SCRIPT)
        .arg(3)
        .arg(&keys.marker)
        .arg(&keys.quarantine)
        .arg(&keys.config)
        .arg(&config.epoch)
        .arg(expected_config(config)?)
        .arg(config.quarantine_ms()?)
        .query(connection)
        .map_err(redis_error)
}

fn expected_config(config: &GovernedRedisNonceConfig) -> Result<String> {
    Ok(format!(
        "{}:{}",
        config.retention_ms()?,
        config.quarantine_ms()?
    ))
}

fn assert_noeviction(connection: &mut Connection) -> Result<()> {
    let values: Vec<String> = redis::cmd("CONFIG")
        .arg("GET")
        .arg("maxmemory-policy")
        .query(connection)
        .map_err(redis_error)?;
    if values.len() != 2
        || values[0] != "maxmemory-policy"
        || !values[1].eq_ignore_ascii_case("noeviction")
    {
        return Err(BpcError::NonceStore(
            "Redis maxmemory-policy must be noeviction for replay safety".into(),
        ));
    }
    Ok(())
}

fn require_secure_redis_transport(url: &str, config: &GovernedRedisNonceConfig) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|_| BpcError::NonceStore("Redis connection URL is invalid".into()))?;
    if parsed.scheme() == "rediss" {
        return Ok(());
    }
    let loopback = matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1")
    );
    if parsed.scheme() == "redis" && config.allow_insecure_loopback && loopback {
        return Ok(());
    }
    Err(BpcError::NonceStore(
        "Redis must use rediss://; redis:// is available only for explicit literal-loopback development".into(),
    ))
}

fn redis_error(error: redis::RedisError) -> BpcError {
    BpcError::NonceStore(format!("Redis unavailable: {error}"))
}

fn is_namespace(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

fn is_epoch_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
}

#[cfg(test)]
mod tests {
    use super::{GovernedRedisNonceConfig, require_secure_redis_transport};

    #[test]
    fn redis_transport_requires_tls_except_explicit_literal_loopback() {
        let config = GovernedRedisNonceConfig::new("bpc-test", "epoch-1", 60_000).unwrap();
        assert!(
            require_secure_redis_transport("rediss://cache.example.test:6380/", &config).is_ok()
        );
        assert!(
            require_secure_redis_transport("redis://cache.example.test:6379/", &config).is_err()
        );
        assert!(require_secure_redis_transport("redis://127.0.0.1:6379/", &config).is_err());

        let mut local = config;
        local.allow_insecure_loopback = true;
        assert!(require_secure_redis_transport("redis://127.0.0.1:6379/", &local).is_ok());
        assert!(
            require_secure_redis_transport("redis://cache.example.test:6379/", &local).is_err()
        );
    }
}
