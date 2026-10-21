//! Governed Redis replay protection for multi-process BPC deployments.
//!
//! The backend uses one Lua transaction to check continuity metadata, enforce a
//! fixed retention configuration, honor quarantine, and execute `SET NX PX`.
//! Plain `SET NX` is not exposed as a production acceptance path because it
//! cannot detect a restored/evicted Redis nonce keyspace.

use std::fmt;
#[cfg(feature = "redis-insecure-tests")]
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use redis::{Client, ClientTlsConfig, Connection, ConnectionAddr, TlsCertificates};
use rustls::RootCertStore;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer,
    pem::{PemObject, SectionKind},
};

use crate::{BpcError, NonceStore, Result};

const DEFAULT_SAFETY_BUFFER_MS: u64 = 10_000;
const DEFAULT_CONTINUITY_ALLOWANCE_MS: u64 = 30_000;

/// Maximum number of non-platform Redis trust anchors accepted in one configuration.
pub const MAX_REDIS_TLS_ADDITIONAL_ROOT_CERTIFICATES: usize = 16;
/// Maximum encoded size of one caller-supplied Redis CA certificate.
pub const MAX_REDIS_TLS_ROOT_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Maximum aggregate encoded size of caller-supplied Redis CA certificates.
pub const MAX_REDIS_TLS_TOTAL_ROOT_CERTIFICATE_BYTES: usize = 512 * 1024;
/// Maximum encoded size of a caller-supplied Redis mTLS certificate chain.
pub const MAX_REDIS_TLS_CLIENT_CERTIFICATE_CHAIN_BYTES: usize = 256 * 1024;
/// Maximum encoded size of a caller-supplied Redis mTLS private key.
pub const MAX_REDIS_TLS_CLIENT_PRIVATE_KEY_BYTES: usize = 64 * 1024;

const MAX_REDIS_TLS_CLIENT_CERTIFICATES: usize = 8;

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
        if self.signature_window_ms == 0 || self.command_timeout.is_zero() {
            return Err(BpcError::NonceStore(
                "Redis nonce durations must be positive".into(),
            ));
        }
        self.retention_ms()?;
        self.quarantine_ms()?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum RedisTlsEncoding {
    Pem,
    Der,
}

#[derive(Clone)]
struct RedisTlsMaterial {
    encoding: RedisTlsEncoding,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct RedisClientAuth {
    certificate_chain: RedisTlsMaterial,
    private_key: RedisTlsMaterial,
}

/// Verified TLS material for a production Redis connection.
///
/// [`Self::default`] uses platform trust roots. Private CA roots are additive
/// by default; call [`Self::with_system_roots`] with `false` only when the
/// supplied private roots are the complete intended trust set. PEM root inputs
/// must contain exactly one `CERTIFICATE` block. PEM client certificate inputs
/// may contain a chain of up to eight `CERTIFICATE` blocks. PEM private keys
/// must contain exactly one unencrypted PKCS#1, PKCS#8, or SEC1 key.
///
/// This type deliberately provides no custom verifier, SNI override, or
/// hostname-verification bypass. It is converted only into Redis's verified
/// Rustls configuration.
#[derive(Clone)]
pub struct RedisTlsConfig {
    use_system_roots: bool,
    additional_roots: Vec<RedisTlsMaterial>,
    client_auth: Option<RedisClientAuth>,
}

impl Default for RedisTlsConfig {
    fn default() -> Self {
        Self {
            use_system_roots: true,
            additional_roots: Vec::new(),
            client_auth: None,
        }
    }
}

impl fmt::Debug for RedisTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not expose certificate or private-key bytes through diagnostics.
        formatter
            .debug_struct("RedisTlsConfig")
            .field("use_system_roots", &self.use_system_roots)
            .field("additional_root_certificates", &self.additional_roots.len())
            .field("client_auth_configured", &self.client_auth.is_some())
            .finish()
    }
}

impl RedisTlsConfig {
    /// Selects whether platform trust roots are included with private roots.
    ///
    /// Defaults to `true`. Disabling it without adding at least one valid
    /// private root is rejected before any Redis network connection is made.
    pub fn with_system_roots(mut self, enabled: bool) -> Self {
        self.use_system_roots = enabled;
        self
    }

    /// Adds exactly one PEM-encoded private CA certificate.
    pub fn with_additional_root_certificate_pem(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.additional_roots.push(RedisTlsMaterial {
            encoding: RedisTlsEncoding::Pem,
            bytes: certificate.into(),
        });
        self
    }

    /// Adds exactly one DER-encoded private CA certificate.
    pub fn with_additional_root_certificate_der(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.additional_roots.push(RedisTlsMaterial {
            encoding: RedisTlsEncoding::Der,
            bytes: certificate.into(),
        });
        self
    }

    /// Configures mutually authenticated TLS with a PEM certificate chain and
    /// its matching unencrypted PEM private key.
    ///
    /// Certificate and key are accepted only as this pair; there is no API for
    /// configuring either one independently.
    pub fn with_client_auth_pem(
        mut self,
        certificate_chain: impl Into<Vec<u8>>,
        private_key: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_auth = Some(RedisClientAuth {
            certificate_chain: RedisTlsMaterial {
                encoding: RedisTlsEncoding::Pem,
                bytes: certificate_chain.into(),
            },
            private_key: RedisTlsMaterial {
                encoding: RedisTlsEncoding::Pem,
                bytes: private_key.into(),
            },
        });
        self
    }

    /// Configures mutually authenticated TLS with one DER client certificate
    /// and its matching unencrypted DER PKCS#1, PKCS#8, or SEC1 private key.
    ///
    /// Use [`Self::with_client_auth_pem`] when an intermediate client
    /// certificate chain is required.
    pub fn with_client_auth_der(
        mut self,
        certificate: impl Into<Vec<u8>>,
        private_key: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_auth = Some(RedisClientAuth {
            certificate_chain: RedisTlsMaterial {
                encoding: RedisTlsEncoding::Der,
                bytes: certificate.into(),
            },
            private_key: RedisTlsMaterial {
                encoding: RedisTlsEncoding::Der,
                bytes: private_key.into(),
            },
        });
        self
    }

    fn tls_certificates(&self) -> Result<TlsCertificates> {
        if self.additional_roots.len() > MAX_REDIS_TLS_ADDITIONAL_ROOT_CERTIFICATES {
            return Err(redis_tls_error(format!(
                "at most {MAX_REDIS_TLS_ADDITIONAL_ROOT_CERTIFICATES} private Redis TLS roots are allowed"
            )));
        }

        let total_private_root_bytes = self.additional_roots.iter().try_fold(0usize, |total, root| {
            if root.bytes.is_empty() || root.bytes.len() > MAX_REDIS_TLS_ROOT_CERTIFICATE_BYTES {
                return Err(redis_tls_error(format!(
                    "each private Redis TLS root must contain 1..={MAX_REDIS_TLS_ROOT_CERTIFICATE_BYTES} bytes"
                )));
            }
            total.checked_add(root.bytes.len()).ok_or_else(|| {
                redis_tls_error("private Redis TLS root size overflows platform usize".into())
            })
        })?;
        if total_private_root_bytes > MAX_REDIS_TLS_TOTAL_ROOT_CERTIFICATE_BYTES {
            return Err(redis_tls_error(format!(
                "private Redis TLS roots must total at most {MAX_REDIS_TLS_TOTAL_ROOT_CERTIFICATE_BYTES} bytes"
            )));
        }

        let mut root_store = RootCertStore::empty();
        let mut root_pem = Vec::new();
        if self.use_system_roots {
            let native = rustls_native_certs::load_native_certs();
            if let Some(error) = native.errors.into_iter().next() {
                return Err(redis_tls_error(format!(
                    "unable to load system Redis TLS trust roots: {error}"
                )));
            }
            for certificate in native.certs {
                add_trust_anchor(&mut root_store, certificate.clone(), "system")?;
                append_pem_block(&mut root_pem, "CERTIFICATE", certificate.as_ref());
            }
        }
        for root in &self.additional_roots {
            let certificate = parse_one_certificate(root, "private root")?;
            add_trust_anchor(&mut root_store, certificate.clone(), "private")?;
            append_pem_block(&mut root_pem, "CERTIFICATE", certificate.as_ref());
        }
        if root_pem.is_empty() {
            return Err(redis_tls_error(
                "Redis TLS requires system roots or at least one private root".into(),
            ));
        }

        let client_tls = if let Some(client_auth) = &self.client_auth {
            let certificates = parse_client_certificates(&client_auth.certificate_chain)?;
            let private_key = parse_private_key(&client_auth.private_key)?;
            // This uses Rustls's standard WebPKI verifier and checks the client
            // key is valid and matches the first certificate before networking.
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store.clone())
                .with_client_auth_cert(certificates.clone(), private_key.key)
                .map_err(|error| {
                    redis_tls_error(format!(
                        "invalid Redis TLS client certificate or private key: {error}"
                    ))
                })?;

            let mut certificate_pem = Vec::new();
            for certificate in certificates {
                append_pem_block(&mut certificate_pem, "CERTIFICATE", certificate.as_ref());
            }
            Some(ClientTlsConfig {
                client_cert: certificate_pem,
                client_key: private_key.pem,
            })
        } else {
            // Construct the verified path even without mTLS. This intentionally
            // never invokes Rustls's dangerous custom-verifier API.
            let _ = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            None
        };

        Ok(TlsCertificates {
            client_tls,
            // Redis's public custom-certificate constructor replaces its
            // default roots. Supplying the explicit combined set preserves the
            // selected system roots plus caller-supplied private roots.
            root_cert: Some(root_pem),
        })
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
    /// Connects over verified Rustls TLS and proves the Redis server uses
    /// `maxmemory-policy noeviction`.
    ///
    /// This production constructor accepts only a single `rediss://` TCP
    /// endpoint. It rejects plaintext, Unix sockets, alternate Redis schemes,
    /// multi-host targets, and every TLS verification bypass including
    /// `#insecure`.
    pub fn connect_tls(url: &str, config: GovernedRedisNonceConfig) -> Result<Self> {
        config.validate()?;
        let client = tls_client(url)?;
        Self::from_client(client, config)
    }

    /// Connects over verified Rustls TLS using explicit private-CA and optional
    /// mutually-authenticated TLS material.
    ///
    /// As with [`Self::connect_tls`], this accepts only one `rediss://` TCP
    /// endpoint and never permits certificate or hostname verification bypasses.
    /// The TLS configuration is validated before the Redis connection is opened.
    pub fn connect_tls_with_config(
        url: &str,
        config: GovernedRedisNonceConfig,
        tls_config: RedisTlsConfig,
    ) -> Result<Self> {
        config.validate()?;
        let client = tls_client_with_config(url, &tls_config)?;
        Self::from_client(client, config)
    }

    /// Connects without TLS only to a pinned loopback TCP address for an
    /// isolated local test Redis service.
    ///
    /// This API is intentionally unavailable unless the
    /// `redis-insecure-tests` feature is enabled. It accepts only `redis://`
    /// endpoints with `localhost`, `127.0.0.0/8`, or `::1`; `localhost` is
    /// rewritten to `127.0.0.1` before connecting so no DNS resolution occurs.
    /// It must never be used in a production build.
    #[cfg(feature = "redis-insecure-tests")]
    pub fn connect_loopback_for_tests(url: &str, config: GovernedRedisNonceConfig) -> Result<Self> {
        config.validate()?;
        let client = loopback_test_client(url)?;
        Self::from_client(client, config)
    }

    fn from_client(client: Client, config: GovernedRedisNonceConfig) -> Result<Self> {
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
    fn check_and_consume(&self, nonce: &str, _now_ms: u64, ttl_ms: u64) -> Result<bool> {
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
            let nonce_key = format!("{}{}", keys.nonce_prefix, nonce);
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
                .query(&mut *connection)
                .map_err(redis_error)?;
            Ok(reply)
        })();
        match result {
            Ok(reply) if reply == "FRESH" => Ok(false),
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

fn tls_client(url: &str) -> Result<Client> {
    validated_tls_url_client(url)
}

fn tls_client_with_config(url: &str, tls_config: &RedisTlsConfig) -> Result<Client> {
    // Validate the URL before processing material or constructing Redis's
    // TLS parameters, so a custom trust store cannot be used with another
    // scheme or an insecure URL fragment.
    let _ = validated_tls_url_client(url)?;
    let certificates = tls_config.tls_certificates()?;
    let client = Client::build_with_tls(url, certificates).map_err(redis_error)?;
    match &client.get_connection_info().addr {
        ConnectionAddr::TcpTls {
            host,
            insecure: false,
            tls_params: Some(_),
            ..
        } if is_single_tcp_host(host) => Ok(client),
        // The initial URL validation above should make every other branch
        // unreachable. Keep an explicit fail-closed check against future
        // redis-rs URL/constructor behavior.
        _ => Err(BpcError::NonceStore(
            "Redis TLS connection did not retain verified single-target TLS parameters".into(),
        )),
    }
}

fn validated_tls_url_client(url: &str) -> Result<Client> {
    let parsed = redis::parse_redis_url(url).ok_or_else(|| {
        BpcError::NonceStore("Redis TLS connection URL is invalid or unsupported".into())
    })?;
    if parsed.scheme() != "rediss" {
        return Err(BpcError::NonceStore(
            "Redis production connection requires a rediss:// URL".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(BpcError::NonceStore(
            "Redis TLS connection rejects URL fragments, including #insecure".into(),
        ));
    }

    let client = Client::open(url).map_err(redis_error)?;
    match &client.get_connection_info().addr {
        ConnectionAddr::TcpTls {
            host,
            insecure: false,
            tls_params: None,
            ..
        } if is_single_tcp_host(host) => Ok(client),
        ConnectionAddr::TcpTls { insecure: true, .. } => Err(BpcError::NonceStore(
            "Redis TLS connection rejects disabled certificate or hostname verification".into(),
        )),
        ConnectionAddr::TcpTls {
            tls_params: Some(_),
            ..
        } => Err(BpcError::NonceStore(
            "Redis TLS connection rejects caller-supplied TLS parameters".into(),
        )),
        ConnectionAddr::TcpTls { .. } => Err(BpcError::NonceStore(
            "Redis TLS connection requires one TCP hostname".into(),
        )),
        ConnectionAddr::Tcp(_, _) => Err(BpcError::NonceStore(
            "Redis production connection requires a rediss:// URL".into(),
        )),
        ConnectionAddr::Unix(_) => Err(BpcError::NonceStore(
            "Redis TLS connection rejects Unix socket targets".into(),
        )),
    }
}

fn redis_tls_error(message: String) -> BpcError {
    BpcError::NonceStore(format!("invalid Redis TLS configuration: {message}"))
}

fn add_trust_anchor(
    store: &mut RootCertStore,
    certificate: CertificateDer<'static>,
    source: &str,
) -> Result<()> {
    store.add(certificate).map_err(|error| {
        redis_tls_error(format!(
            "{source} Redis TLS certificate is not a valid X.509 trust anchor: {error}"
        ))
    })
}

fn parse_one_certificate(
    material: &RedisTlsMaterial,
    description: &str,
) -> Result<CertificateDer<'static>> {
    match material.encoding {
        RedisTlsEncoding::Pem => {
            let mut certificates = parse_pem_certificates(&material.bytes, description)?;
            if certificates.len() != 1 {
                return Err(redis_tls_error(format!(
                    "{description} Redis TLS PEM must contain exactly one CERTIFICATE block"
                )));
            }
            Ok(certificates.remove(0))
        }
        RedisTlsEncoding::Der => Ok(CertificateDer::from(material.bytes.clone())),
    }
}

fn parse_client_certificates(material: &RedisTlsMaterial) -> Result<Vec<CertificateDer<'static>>> {
    if material.bytes.is_empty()
        || material.bytes.len() > MAX_REDIS_TLS_CLIENT_CERTIFICATE_CHAIN_BYTES
    {
        return Err(redis_tls_error(format!(
            "Redis TLS client certificate chain must contain 1..={MAX_REDIS_TLS_CLIENT_CERTIFICATE_CHAIN_BYTES} bytes"
        )));
    }
    let certificates = match material.encoding {
        RedisTlsEncoding::Pem => parse_pem_certificates(&material.bytes, "client certificate")?,
        RedisTlsEncoding::Der => vec![CertificateDer::from(material.bytes.clone())],
    };
    if certificates.is_empty() || certificates.len() > MAX_REDIS_TLS_CLIENT_CERTIFICATES {
        return Err(redis_tls_error(format!(
            "Redis TLS client certificate chain must contain 1..={MAX_REDIS_TLS_CLIENT_CERTIFICATES} certificates"
        )));
    }
    Ok(certificates)
}

fn parse_pem_certificates(input: &[u8], description: &str) -> Result<Vec<CertificateDer<'static>>> {
    let input = trim_ascii_whitespace(input);
    let mut certificates = Vec::new();
    for item in <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(input) {
        let (kind, der) = item.map_err(|error| {
            redis_tls_error(format!("malformed {description} Redis TLS PEM: {error:?}"))
        })?;
        if kind != SectionKind::Certificate {
            return Err(redis_tls_error(format!(
                "{description} Redis TLS PEM contains a non-certificate block"
            )));
        }
        certificates.push(CertificateDer::from(der));
    }
    if certificates.is_empty() {
        return Err(redis_tls_error(format!(
            "{description} Redis TLS PEM contains no certificate"
        )));
    }
    Ok(certificates)
}

struct ParsedPrivateKey {
    key: PrivateKeyDer<'static>,
    pem: Vec<u8>,
}

fn parse_private_key(material: &RedisTlsMaterial) -> Result<ParsedPrivateKey> {
    if material.bytes.is_empty() || material.bytes.len() > MAX_REDIS_TLS_CLIENT_PRIVATE_KEY_BYTES {
        return Err(redis_tls_error(format!(
            "Redis TLS client private key must contain 1..={MAX_REDIS_TLS_CLIENT_PRIVATE_KEY_BYTES} bytes"
        )));
    }
    let (label, der) = match material.encoding {
        RedisTlsEncoding::Pem => parse_one_pem_private_key(&material.bytes)?,
        RedisTlsEncoding::Der => private_key_label_and_der(&material.bytes)?,
    };
    let key = PrivateKeyDer::try_from(der.clone()).map_err(|error| {
        redis_tls_error(format!("invalid Redis TLS client private key DER: {error}"))
    })?;
    let mut pem = Vec::new();
    append_pem_block(&mut pem, label, &der);
    Ok(ParsedPrivateKey { key, pem })
}

fn parse_one_pem_private_key(input: &[u8]) -> Result<(&'static str, Vec<u8>)> {
    let input = trim_ascii_whitespace(input);
    let mut items = <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(input);
    let (kind, der) = items
        .next()
        .ok_or_else(|| redis_tls_error("missing Redis TLS client private key PEM".into()))?
        .map_err(|error| {
            redis_tls_error(format!(
                "malformed Redis TLS client private key PEM: {error:?}"
            ))
        })?;
    if let Some(item) = items.next() {
        // Consume a possible parse failure as a configuration error as well as
        // rejecting multiple PEM sections. A client key file must be one key.
        item.map_err(|error| {
            redis_tls_error(format!(
                "malformed Redis TLS client private key PEM: {error:?}"
            ))
        })?;
        return Err(redis_tls_error(
            "Redis TLS client private key PEM must contain exactly one key block".into(),
        ));
    }
    match kind {
        SectionKind::RsaPrivateKey => Ok(("RSA PRIVATE KEY", der)),
        SectionKind::PrivateKey => Ok(("PRIVATE KEY", der)),
        SectionKind::EcPrivateKey => Ok(("EC PRIVATE KEY", der)),
        _ => Err(redis_tls_error(
            "Redis TLS client private key PEM contains a non-key block".into(),
        )),
    }
}

fn private_key_label_and_der(input: &[u8]) -> Result<(&'static str, Vec<u8>)> {
    let key = PrivateKeyDer::try_from(input).map_err(|error| {
        redis_tls_error(format!("invalid Redis TLS client private key DER: {error}"))
    })?;
    match key {
        PrivateKeyDer::Pkcs1(key) => Ok(("RSA PRIVATE KEY", key.secret_pkcs1_der().to_vec())),
        PrivateKeyDer::Pkcs8(key) => Ok(("PRIVATE KEY", key.secret_pkcs8_der().to_vec())),
        PrivateKeyDer::Sec1(key) => Ok(("EC PRIVATE KEY", key.secret_sec1_der().to_vec())),
        _ => Err(redis_tls_error(
            "Redis TLS client private key has an unsupported DER encoding".into(),
        )),
    }
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn append_pem_block(output: &mut Vec<u8>, label: &str, der: &[u8]) {
    output.extend_from_slice(b"-----BEGIN ");
    output.extend_from_slice(label.as_bytes());
    output.extend_from_slice(b"-----\n");
    let encoded = STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END ");
    output.extend_from_slice(label.as_bytes());
    output.extend_from_slice(b"-----\n");
}

#[cfg(feature = "redis-insecure-tests")]
fn loopback_test_client(url: &str) -> Result<Client> {
    let parsed = redis::parse_redis_url(url).ok_or_else(|| {
        BpcError::NonceStore("Redis loopback test URL is invalid or unsupported".into())
    })?;
    if parsed.scheme() != "redis" {
        return Err(BpcError::NonceStore(
            "Redis loopback test connection requires a redis:// URL".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(BpcError::NonceStore(
            "Redis loopback test connection rejects URL fragments".into(),
        ));
    }

    let client = Client::open(url).map_err(redis_error)?;
    let mut connection_info = client.get_connection_info().clone();
    match &mut connection_info.addr {
        ConnectionAddr::Tcp(host, _) if host == "localhost" => {
            // Do not trust a resolver configuration for a test-only plaintext
            // connection. Pin the conventional hostname to a numeric loopback.
            *host = "127.0.0.1".into();
        }
        ConnectionAddr::Tcp(host, _) => {
            let address = host.parse::<IpAddr>().map_err(|_| {
                BpcError::NonceStore(
                    "Redis loopback test connection requires localhost or a literal loopback IP"
                        .into(),
                )
            })?;
            if !address.is_loopback() {
                return Err(BpcError::NonceStore(
                    "Redis loopback test connection rejects non-loopback targets".into(),
                ));
            }
        }
        ConnectionAddr::TcpTls { .. } => {
            return Err(BpcError::NonceStore(
                "Redis loopback test connection requires a plaintext redis:// URL".into(),
            ));
        }
        ConnectionAddr::Unix(_) => {
            return Err(BpcError::NonceStore(
                "Redis loopback test connection rejects Unix socket targets".into(),
            ));
        }
    }
    Client::open(connection_info).map_err(redis_error)
}

fn is_single_tcp_host(host: &str) -> bool {
    !host.is_empty() && !host.contains(',')
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
    use super::*;

    // Non-production self-signed P-256 CA/client pair. It exists solely to
    // exercise Rustls configuration construction; no socket is opened by these
    // tests and it is not a deployment credential.
    const TEST_CERTIFICATE_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBlTCCATugAwIBAgIUTPmkC4a8PpSI7aM/PrMFRsCQQmMwCgYIKoZIzj0EAwIw\nIDEeMBwGA1UEAwwVcmVkaXMtdGxzLWNvbmZpZy10ZXN0MB4XDTI2MTAyMTA4MDAz\nMFoXDTI2MTAyMzA4MDAzMFowIDEeMBwGA1UEAwwVcmVkaXMtdGxzLWNvbmZpZy10\nZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA1vT55sFNMtM9zwonfYRJPqA\nuJ9aTzPIfuCKlA4NBY2qbUsaluztrvdYDHJZYvazFmSIzdHdUKbhb9xdAsT69aNT\nMFEwHQYDVR0OBBYEFP7g5YghiQzSP0mG1YlsAn/fT53RMB8GA1UdIwQYMBaAFP7g\n5YghiQzSP0mG1YlsAn/fT53RMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID\nSAAwRQIgW2yYWjAESrptKm/aDl+LuIde6FIxQjeNYknFSPsQjNICIQCxgEXiwvmt\no6Il9dV0SQgpJq/AhqCb00mHqaVq4m4NRQ==\n-----END CERTIFICATE-----\n";
    const TEST_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbGqlusuQioBMfZ/t\nG5xQf+lBHGw2LD+TqAtMorydY02hRANCAAQDW9PnmwU0y0z3PCid9hEk+oC4n1pP\nM8h+4IqUDg0FjaptSxqW7O2u91gMclli9rMWZIjN0d1QpuFv3F0CxPr1\n-----END PRIVATE KEY-----\n";

    fn test_certificate_der() -> Vec<u8> {
        parse_one_certificate(
            &RedisTlsMaterial {
                encoding: RedisTlsEncoding::Pem,
                bytes: TEST_CERTIFICATE_PEM.to_vec(),
            },
            "test certificate",
        )
        .expect("embedded test certificate is valid")
        .as_ref()
        .to_vec()
    }

    fn test_private_key_der() -> Vec<u8> {
        parse_one_pem_private_key(TEST_PRIVATE_KEY_PEM)
            .expect("embedded test key is valid")
            .1
    }

    #[test]
    fn tls_config_builds_verified_private_ca_and_paired_pem_mtls_parameters() {
        let tls_config = RedisTlsConfig::default()
            .with_system_roots(false)
            .with_additional_root_certificate_der(test_certificate_der())
            .with_client_auth_pem(TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM);
        let client = tls_client_with_config("rediss://redis.example:6380/0", &tls_config)
            .expect("private CA and matching mTLS material construct verified Redis parameters");
        assert!(matches!(
            client.get_connection_info().addr,
            ConnectionAddr::TcpTls {
                insecure: false,
                tls_params: Some(_),
                ..
            }
        ));
        let debug = format!("{tls_config:?}");
        assert!(debug.contains("client_auth_configured: true"));
        assert!(!debug.contains("PRIVATE KEY"));
    }

    #[test]
    fn tls_config_builds_verified_private_ca_and_paired_der_mtls_parameters() {
        let tls_config = RedisTlsConfig::default()
            .with_system_roots(false)
            .with_additional_root_certificate_pem(TEST_CERTIFICATE_PEM)
            .with_client_auth_der(test_certificate_der(), test_private_key_der());
        let client = tls_client_with_config("rediss://redis.example:6380/0", &tls_config)
            .expect("DER mTLS material constructs verified Redis parameters");
        assert!(matches!(
            client.get_connection_info().addr,
            ConnectionAddr::TcpTls {
                insecure: false,
                tls_params: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn tls_config_fails_closed_for_missing_malformed_or_oversized_material() {
        assert!(
            RedisTlsConfig::default()
                .with_system_roots(false)
                .tls_certificates()
                .is_err()
        );
        assert!(
            RedisTlsConfig::default()
                .with_system_roots(false)
                .with_additional_root_certificate_der(b"not a certificate")
                .tls_certificates()
                .is_err()
        );
        assert!(
            RedisTlsConfig::default()
                .with_system_roots(false)
                .with_additional_root_certificate_pem(
                    [TEST_CERTIFICATE_PEM, TEST_CERTIFICATE_PEM].concat()
                )
                .tls_certificates()
                .is_err()
        );
        assert!(
            RedisTlsConfig::default()
                .with_system_roots(false)
                .with_additional_root_certificate_pem(TEST_CERTIFICATE_PEM)
                .with_client_auth_pem(TEST_CERTIFICATE_PEM, b"not a private key")
                .tls_certificates()
                .is_err()
        );
        assert!(
            RedisTlsConfig::default()
                .with_system_roots(false)
                .with_additional_root_certificate_pem(TEST_CERTIFICATE_PEM)
                .with_client_auth_der(test_certificate_der(), Vec::new())
                .tls_certificates()
                .is_err()
        );

        let mut tls_config = RedisTlsConfig::default().with_system_roots(false);
        for _ in 0..=MAX_REDIS_TLS_ADDITIONAL_ROOT_CERTIFICATES {
            tls_config = tls_config.with_additional_root_certificate_der(vec![0x30]);
        }
        assert!(tls_config.tls_certificates().is_err());
    }

    #[test]
    fn custom_tls_config_keeps_secure_url_rules_before_constructing_parameters() {
        let tls_config = RedisTlsConfig::default()
            .with_system_roots(false)
            .with_additional_root_certificate_pem(TEST_CERTIFICATE_PEM);
        for url in [
            "redis://127.0.0.1:6379/0",
            "valkeys://redis.example:6380/0",
            "unix:///tmp/redis.sock",
            "rediss://redis-a.example,redis-b.example:6379/0",
            "rediss://redis.example:6380/0#insecure",
        ] {
            assert!(
                tls_client_with_config(url, &tls_config).is_err(),
                "custom production TLS configuration must reject {url}"
            );
        }
    }

    #[test]
    fn tls_url_accepts_a_single_verified_rediss_tcp_target() {
        let client = tls_client("rediss://user:password@redis.example:6380/3?protocol=resp3")
            .expect("a single rediss TCP URL with standard verification is valid");
        assert!(matches!(
            client.get_connection_info().addr,
            ConnectionAddr::TcpTls {
                insecure: false,
                tls_params: None,
                ..
            }
        ));
    }

    #[test]
    fn tls_url_rejects_plaintext_unix_invalid_multi_host_and_verification_bypass() {
        for url in [
            "redis://127.0.0.1:6379/0",
            "valkeys://redis.example:6380/0",
            "unix:///tmp/redis.sock",
            "rediss://",
            "rediss://redis-a.example,redis-b.example:6379/0",
            "rediss://redis.example:6380/0#insecure",
        ] {
            assert!(
                tls_client(url).is_err(),
                "production TLS URL must reject {url}"
            );
        }
    }

    #[cfg(feature = "redis-insecure-tests")]
    #[test]
    fn loopback_test_url_pins_localhost_and_rejects_remote_or_dns_targets() {
        let localhost = loopback_test_client("redis://localhost:6379/0")
            .expect("localhost is rewritten to a numeric loopback");
        assert!(matches!(
            localhost.get_connection_info().addr,
            ConnectionAddr::Tcp(ref host, 6379) if host == "127.0.0.1"
        ));
        assert!(loopback_test_client("redis://127.0.0.42:6379/0").is_ok());
        assert!(loopback_test_client("redis://[::1]:6379/0").is_ok());

        for url in [
            "redis://redis.example:6379/0",
            "redis://192.0.2.10:6379/0",
            "rediss://127.0.0.1:6379/0",
            "unix:///tmp/redis.sock",
            "redis://127.0.0.1,127.0.0.2:6379/0",
        ] {
            assert!(
                loopback_test_client(url).is_err(),
                "loopback-only test URL must reject {url}"
            );
        }
    }
}
