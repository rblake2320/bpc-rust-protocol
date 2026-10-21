#![cfg(feature = "live-integration")]

use bpc_protocol::{
    PairRegistry, PostgresAuthorityConfig, PostgresPairAuthority, PostgresSecretProtector,
};

/// Runs only when `BPC_TEST_POSTGRES_TLS_URL` is provided. Set `SSL_CERT_FILE`
/// to the test CA PEM (or use a system-trusted CA) before launching Cargo.
#[test]
fn postgres_tls_connection_uses_verified_chain_and_hostname() -> bpc_protocol::Result<()> {
    let Ok(url) = std::env::var("BPC_TEST_POSTGRES_TLS_URL") else {
        eprintln!("skipping PostgreSQL TLS probe: BPC_TEST_POSTGRES_TLS_URL is unset");
        return Ok(());
    };
    let schema = format!("bpctls{}", uuid::Uuid::new_v4().simple());
    let authority = PostgresPairAuthority::connect_tls(
        &url,
        PostgresAuthorityConfig {
            max_active_pairs: 1,
            max_pending_pairs: 1,
            approval_ttl_ms: 60_000,
            schema,
            secret_protector: PostgresSecretProtector::new("tls-test-key-v1", [3; 32])?,
            require_synchronous_replication: false,
        },
    )?;
    authority.migrate()?;
    assert!(authority.get("no_such_pair")?.is_none());
    Ok(())
}
