//! Governed Redis replay protection for multi-process BPC deployments.
//!
//! Redis alone cannot prove that every accepted nonce remains in its keyspace.
//! This store therefore requires an independently durable monotonic continuity
//! generation. Recovery controllers fence/drain verifiers, advance that anchor,
//! then provision a full replay-horizon quarantine before traffic resumes.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use redis::{Client, Connection};

use crate::{BpcError, MAX_SIGNATURE_WINDOW_MS, NonceStore, Result};

const DEFAULT_SAFETY_BUFFER_MS: u64 = 10_000;
const DEFAULT_CONTINUITY_ALLOWANCE_MS: u64 = 30_000;

const CONSUME_SCRIPT: &str = r#"
local marker = redis.call('GET', KEYS[2])
local configured = redis.call('GET', KEYS[4])
if configured and configured ~= ARGV[4] then return 'CONFIG_MISMATCH' end
if not configured then redis.call('SET', KEYS[4], ARGV[4], 'NX') end
if not marker then
  redis.call('SET', KEYS[3], 'missing-marker', 'PX', ARGV[3])
  return 'CONTINUITY_MISMATCH'
end
if marker ~= ARGV[1] then
  redis.call('SET', KEYS[3], 'generation-mismatch', 'PX', ARGV[3])
  return 'CONTINUITY_MISMATCH'
end
if redis.call('GET', KEYS[3]) then return 'QUARANTINED' end
local current_time = redis.call('TIME')
local now_ms = tonumber(current_time[1]) * 1000 + math.floor(tonumber(current_time[2]) / 1000)
if math.abs(now_ms - tonumber(ARGV[5])) > tonumber(ARGV[6]) then return 'STALE' end
if redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[2]) then return 'FRESH' end
return 'REPLAY'
"#;

const PROVISION_SCRIPT: &str = r#"
local marker = redis.call('GET', KEYS[1])
local configured = redis.call('GET', KEYS[3])
if configured and configured ~= ARGV[2] then return 'CONFIG_MISMATCH' end
if not configured then redis.call('SET', KEYS[3], ARGV[2], 'NX') end
if not marker or marker ~= ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[1])
  redis.call('SET', KEYS[2], 'generation-change', 'PX', ARGV[3])
  return 'QUARANTINED'
end
if redis.call('GET', KEYS[2]) then return 'QUARANTINED' end
return 'READY'
"#;

/// Nonzero value from durable storage that never regresses or repeats for a
/// namespace. It must not share a backup/restore domain with Redis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContinuityGeneration(u64);

impl ContinuityGeneration {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(BpcError::NonceStore(
                "continuity generation must be nonzero".into(),
            ));
        }
        Ok(Self(value))
    }
    fn marker(self) -> String {
        format!("v2:{}", self.0)
    }
}

/// Independent, linearizable generation source. The runtime role normally gets
/// only `current_generation`; `advance_after_fencing` belongs to a tightly
/// controlled recovery controller after all verifiers have been drained.
pub trait RedisContinuityAnchor: Send + Sync {
    fn current_generation(&self, namespace: &str) -> Result<ContinuityGeneration>;
    fn advance_after_fencing(&self, namespace: &str) -> Result<ContinuityGeneration>;
}

/// Development/test-only in-process anchor. It is not durable and must never
/// be used to protect a production Redis deployment.
#[derive(Debug)]
pub struct InMemoryContinuityAnchor {
    generation: AtomicU64,
}
impl InMemoryContinuityAnchor {
    pub fn new(initial: ContinuityGeneration) -> Self {
        Self {
            generation: AtomicU64::new(initial.0),
        }
    }
}
impl RedisContinuityAnchor for InMemoryContinuityAnchor {
    fn current_generation(&self, _namespace: &str) -> Result<ContinuityGeneration> {
        ContinuityGeneration::new(self.generation.load(Ordering::Acquire))
    }
    fn advance_after_fencing(&self, _namespace: &str) -> Result<ContinuityGeneration> {
        let mut current = self.generation.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(1)
                .ok_or_else(|| BpcError::NonceStore("continuity generation exhausted".into()))?;
            match self.generation.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return ContinuityGeneration::new(next),
                Err(observed) => current = observed,
            }
        }
    }
}

/// Production Redis nonce configuration. It deliberately contains no static
/// epoch: a static deployment value cannot attest to nonce-history continuity.
#[derive(Clone, Debug)]
pub struct GovernedRedisNonceConfig {
    pub namespace: String,
    pub signature_window_ms: u64,
    pub safety_buffer_ms: u64,
    pub continuity_allowance_ms: u64,
    pub command_timeout: Duration,
    pub min_replica_acks: usize,
    pub allow_insecure_loopback: bool,
}

impl GovernedRedisNonceConfig {
    pub fn new(namespace: impl Into<String>, signature_window_ms: u64) -> Result<Self> {
        let config = Self {
            namespace: namespace.into(),
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
            .and_then(|v| v.checked_add(self.safety_buffer_ms))
            .filter(|v| *v > 0)
            .ok_or_else(|| BpcError::NonceStore("nonce retention overflows or is zero".into()))
    }
    pub fn quarantine_ms(&self) -> Result<u64> {
        self.retention_ms()?
            .checked_add(self.continuity_allowance_ms)
            .ok_or_else(|| BpcError::NonceStore("quarantine duration overflows".into()))
    }
    pub fn validate(&self) -> Result<()> {
        if !is_namespace(&self.namespace) {
            return Err(BpcError::NonceStore(
                "Redis namespace must be 1–64 ASCII [A-Za-z0-9][A-Za-z0-9._-]*".into(),
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

/// Redis-backed nonce store with an ambiguity gate and independent continuity anchor.
pub struct GovernedRedisNonceStore {
    connection: Mutex<Connection>,
    config: GovernedRedisNonceConfig,
    anchor: Arc<dyn RedisContinuityAnchor>,
    locally_quarantined: AtomicBool,
}

impl GovernedRedisNonceStore {
    /// Connects closed. Call `provision_current_generation` after a fenced
    /// recovery event; ordinary joining workers call `reconcile` only.
    pub fn connect(
        url: &str,
        config: GovernedRedisNonceConfig,
        anchor: Arc<dyn RedisContinuityAnchor>,
    ) -> Result<Self> {
        config.validate()?;
        require_secure_redis_transport(url, &config)?;
        let client = Client::open(url).map_err(redis_error)?;
        let mut connection = client.get_connection().map_err(redis_error)?;
        connection
            .set_read_timeout(Some(config.command_timeout))
            .map_err(redis_error)?;
        connection
            .set_write_timeout(Some(config.command_timeout))
            .map_err(redis_error)?;
        assert_noeviction(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            config,
            anchor,
            locally_quarantined: AtomicBool::new(true),
        })
    }

    /// Provisions the externally anchored generation and deliberately holds a
    /// full replay-horizon quarantine if Redis had missing/different state.
    pub fn provision_current_generation(&self) -> Result<()> {
        let generation = self.current_generation_or_close()?;
        let mut connection = self.lock_connection()?;
        assert_noeviction(&mut connection)?;
        let reply = eval_provision(&mut connection, &self.config, generation)?;
        if reply == "READY" {
            self.locally_quarantined.store(false, Ordering::Release);
            Ok(())
        } else {
            self.locally_quarantined.store(true, Ordering::Release);
            Err(BpcError::NonceStore(format!(
                "Redis continuity namespace is quarantined ({reply})"
            )))
        }
    }

    /// Opens only if current anchor, Redis marker/config, noeviction and absent
    /// quarantine agree. Anchor failures always close the local gate.
    pub fn reconcile(&self) -> Result<()> {
        let generation = self.current_generation_or_close()?;
        let mut connection = self.lock_connection()?;
        assert_noeviction(&mut connection)?;
        let keys = continuity_keys(&self.config.namespace);
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&[&keys.marker, &keys.quarantine, &keys.config])
            .query(&mut *connection)
            .map_err(redis_error)?;
        if values.len() != 3
            || values[0].as_deref() != Some(&generation.marker())
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
    fn current_generation_or_close(&self) -> Result<ContinuityGeneration> {
        match self.anchor.current_generation(&self.config.namespace) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.locally_quarantined.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
    fn lock_connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| BpcError::NonceStore("Redis connection lock poisoned".into()))
    }
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
        if acknowledged
            < i64::try_from(self.config.min_replica_acks)
                .map_err(|_| BpcError::NonceStore("Redis replica count is invalid".into()))?
        {
            return Err(BpcError::NonceStore(
                "Redis nonce write did not reach the required replica acknowledgement quorum"
                    .into(),
            ));
        }
        Ok(())
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
            let generation = self.current_generation_or_close()?;
            let mut connection = self.lock_connection()?;
            let keys = continuity_keys(&self.config.namespace);
            let nonce_key = format!("{}{}:{nonce}", keys.nonce_prefix, pair_id);
            redis::cmd("EVAL")
                .arg(CONSUME_SCRIPT)
                .arg(4)
                .arg(nonce_key)
                .arg(&keys.marker)
                .arg(&keys.quarantine)
                .arg(&keys.config)
                .arg(generation.marker())
                .arg(self.config.retention_ms()?)
                .arg(self.config.quarantine_ms()?)
                .arg(expected_config(&self.config)?)
                .arg(signed_timestamp_ms)
                .arg(self.config.signature_window_ms)
                .query::<String>(&mut *connection)
                .map_err(redis_error)
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
                self.locally_quarantined.store(true, Ordering::Release);
                Err(error)
            }
        }
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
        marker: format!("bpc:{tag}:continuity:v2"),
        quarantine: format!("bpc:{tag}:continuity-quarantine:v2"),
        config: format!("bpc:{tag}:continuity-config:v2"),
    }
}
fn eval_provision(
    connection: &mut Connection,
    config: &GovernedRedisNonceConfig,
    generation: ContinuityGeneration,
) -> Result<String> {
    let keys = continuity_keys(&config.namespace);
    redis::cmd("EVAL")
        .arg(PROVISION_SCRIPT)
        .arg(3)
        .arg(&keys.marker)
        .arg(&keys.quarantine)
        .arg(&keys.config)
        .arg(generation.marker())
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
    Err(BpcError::NonceStore("Redis must use rediss://; redis:// is available only for explicit literal-loopback development".into()))
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
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{GovernedRedisNonceConfig, require_secure_redis_transport};
    #[test]
    fn redis_transport_requires_tls_except_explicit_literal_loopback() {
        let config = GovernedRedisNonceConfig::new("bpc-test", 60_000).unwrap();
        assert!(
            require_secure_redis_transport("rediss://cache.example.test:6380/", &config).is_ok()
        );
        assert!(
            require_secure_redis_transport("redis://cache.example.test:6379/", &config).is_err()
        );
        let mut local = config;
        local.allow_insecure_loopback = true;
        assert!(require_secure_redis_transport("redis://127.0.0.1:6379/", &local).is_ok());
    }
}
