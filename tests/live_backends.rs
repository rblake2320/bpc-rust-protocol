#![cfg(feature = "live-integration")]

use std::env;
use std::thread;
use std::time::Duration;

use bpc_protocol::{
    AuditAction, AuditEvent, AuditLog, AuditSeverity, BpcKeyPair, GovernedRedisNonceConfig,
    GovernedRedisNonceStore, NonceStore, PairAuthority, PairKind, PairMode, PairRegistration,
    PairRegistry, PostgresAuditLog, PostgresAuthorityConfig, PostgresPairAuthority, Scope,
    SuccessClaim, derive_request_hmac_key, sign_rotation_at, verify_and_rotate_at,
};
use postgres::{Client, NoTls};
use uuid::Uuid;

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is required: live backend tests deliberately do not silently skip service integration"
        )
    })
}

#[test]
fn governed_redis_fails_closed_then_detects_real_replay() {
    let url = required_env("BPC_TEST_REDIS_URL");
    let namespace = format!("bpcitest{}", Uuid::new_v4().simple());
    let mut config = GovernedRedisNonceConfig::new(namespace, "epoch-v1", 25).unwrap();
    config.safety_buffer_ms = 5;
    config.continuity_allowance_ms = 5;
    config.command_timeout = Duration::from_secs(2);
    let store = GovernedRedisNonceStore::connect(&url, config.clone()).unwrap();

    // A fresh namespace is deliberately unusable until the full replay horizon
    // has elapsed. This proves startup does not accept a potentially restored keyspace.
    assert!(store.provision_epoch().is_err());
    thread::sleep(Duration::from_millis(config.quarantine_ms().unwrap() + 20));
    store.reconcile().unwrap();
    let ttl = store.retention_ms().unwrap();
    assert!(
        !store
            .check_and_consume("nonce-live-redis-1", 1_740_000_000_000, ttl)
            .unwrap()
    );
    assert!(
        store
            .check_and_consume("nonce-live-redis-1", 1_740_000_000_000, ttl)
            .unwrap()
    );
}

#[test]
fn postgres_authority_and_audit_are_real_transactional_backends() {
    let url = required_env("BPC_TEST_POSTGRES_URL");
    let schema = format!("bpcit_{}", Uuid::new_v4().simple());
    let mut admin = Client::connect(&url, NoTls).unwrap();
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .unwrap();

    let result = (|| -> bpc_protocol::Result<()> {
        let authority = PostgresPairAuthority::connect(
            &url,
            PostgresAuthorityConfig {
                max_active_pairs: 10,
                approval_ttl_ms: 60_000,
                schema: schema.clone(),
            },
        )?;
        authority.migrate()?;
        let old_key = BpcKeyPair::generate()?;
        let registration = PairRegistration {
            name: "live-postgres".into(),
            scope: Scope::Admin,
            mode: PairMode::Production,
            request_hmac_key: derive_request_hmac_key("LivePostgresSecret9!@")?,
            public_jwk: old_key.public_jwk().clone(),
            expires_at_ms: None,
            max_requests: Some(1),
            kind: PairKind::Legitimate,
            canary_class: None,
        };
        let now = bpc_protocol::unix_ms()?;
        let token = authority.request_pairing(registration, now)?;
        let pair_id = authority.approve_pairing(&token, now)?;
        let initial = authority.get(&pair_id)?.expect("approved pair exists");
        assert_eq!(
            authority.claim_success(&initial, now)?,
            SuccessClaim::Claimed
        );
        let exhausted = authority.get(&pair_id)?.expect("pair retained after cap");
        assert_eq!(exhausted.status, bpc_protocol::PairStatus::Expired);

        // Rotation is tested separately on an unlimited successor registration.
        let rotate_key = BpcKeyPair::generate()?;
        let rotate_registration = PairRegistration {
            name: "rotation-live".into(),
            scope: Scope::ReadWrite,
            mode: PairMode::Production,
            request_hmac_key: derive_request_hmac_key("LiveRotationSecret9!@")?,
            public_jwk: rotate_key.public_jwk().clone(),
            expires_at_ms: None,
            max_requests: None,
            kind: PairKind::Legitimate,
            canary_class: None,
        };
        let token = authority.request_pairing(rotate_registration, now)?;
        let old_id = authority.approve_pairing(&token, now)?;
        let replacement_key = BpcKeyPair::generate()?;
        let rotation = sign_rotation_at(
            rotate_key.signing_key(),
            &old_id,
            replacement_key.public_jwk(),
            now,
        )?;
        let replacement_id = verify_and_rotate_at(&authority, &rotation, now, 60_000)?;
        assert_eq!(
            authority.get(&old_id)?.unwrap().status,
            bpc_protocol::PairStatus::Rotated
        );
        assert_eq!(
            authority.get(&replacement_id)?.unwrap().public_jwk,
            *replacement_key.public_jwk()
        );

        let audit = PostgresAuditLog::connect(&url, &schema)?;
        audit.migrate()?;
        audit.append_at(
            AuditEvent {
                action: AuditAction::Rotate,
                severity: AuditSeverity::Info,
                pair_id: Some(replacement_id),
                error_code: None,
                source_ip: None,
                method: None,
                path: None,
                request_id: Some("live-postgres".into()),
                detail: Some("integration test only".into()),
            },
            now,
        )?;
        assert!(audit.verify(Some(&audit.head()?))?.valid);
        Ok(())
    })();

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
    result.unwrap();
}
