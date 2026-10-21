#![cfg(feature = "live-integration")]

use bpc_protocol::{
    AuditAction, AuditEvent, AuditLog, AuditSeverity, PairRegistry, PostgresAuditLog,
    PostgresAuthorityConfig, PostgresPairAuthority, PostgresSecretProtector,
};

fn required_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required: TLS integration must not silently skip"))
}

/// Requires a CA-signed `localhost` certificate and a bad-host URL whose IP has
/// no SAN. This proves a real TLS handshake plus chain and hostname validation.
#[test]
fn postgres_tls_connection_uses_verified_chain_and_hostname() -> bpc_protocol::Result<()> {
    let url = required_env("BPC_TEST_POSTGRES_TLS_URL");
    let bad_host_url = required_env("BPC_TEST_POSTGRES_TLS_BAD_HOST_URL");
    let schema = format!("bpctls{}", uuid::Uuid::new_v4().simple());
    let config = PostgresAuthorityConfig {
        max_active_pairs: 1,
        max_pending_pairs: 1,
        approval_ttl_ms: 60_000,
        schema: schema.clone(),
        secret_protector: PostgresSecretProtector::new("tls-test-key-v1", [3; 32])?,
        require_synchronous_replication: false,
    };
    assert!(PostgresPairAuthority::connect_tls(&bad_host_url, config.clone()).is_err());
    let authority = PostgresPairAuthority::connect_tls(&url, config)?;
    authority.migrate()?;
    assert!(authority.get("no_such_pair")?.is_none());

    let audit = PostgresAuditLog::connect_tls(&url, &schema)?;
    audit.migrate()?;
    audit.append_at(
        AuditEvent {
            action: AuditAction::VerifyPass,
            severity: AuditSeverity::Info,
            pair_id: None,
            error_code: None,
            source_ip: None,
            method: Some("POST".into()),
            path: Some("/tls-test".into()),
            request_id: Some("tls-integration".into()),
            detail: None,
        },
        1_740_000_000_000,
    )?;
    assert!(audit.verify(Some(&audit.head()?))?.valid);
    Ok(())
}
