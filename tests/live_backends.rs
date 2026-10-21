#![cfg(feature = "live-integration")]

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bpc_protocol::{
    AuditAction, AuditEvent, AuditLog, AuditSeverity, BpcKeyPair, ContinuityGeneration,
    GovernedRedisNonceConfig, GovernedRedisNonceStore, InMemoryContinuityAnchor, NonceStore,
    PairAuthority, PairKind, PairMode, PairRegistration, PairRegistry, PairRequestProtocol,
    PostgresAuditLog, PostgresAuthorityConfig, PostgresPairAuthority, PostgresSecretProtector,
    RedisContinuityAnchor, Scope, SuccessClaim, derive_request_hmac_key, sign_rotation_at,
    verify_and_rotate_at,
};
use postgres::{Client, NoTls};
use uuid::Uuid;

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required: live backend tests deliberately do not silently skip service integration"))
}

fn wait_until_reconciled(store: &GovernedRedisNonceStore) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match store.reconcile() {
            Ok(()) => return,
            Err(error) if Instant::now() >= deadline => {
                panic!("Redis continuity quarantine did not expire: {error}");
            }
            Err(_) => {}
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn governed_redis_fails_closed_and_detects_marker_preserved_nonce_rollback() {
    let url = required_env("BPC_TEST_REDIS_URL");
    let namespace = format!("bpcitest{}", Uuid::new_v4().simple());
    let mut config = GovernedRedisNonceConfig::new(namespace.clone(), 1_000).unwrap();
    config.allow_insecure_loopback = true;
    config.min_replica_acks = 0;
    config.safety_buffer_ms = 100;
    config.continuity_allowance_ms = 100;
    config.command_timeout = Duration::from_secs(2);
    let anchor = Arc::new(InMemoryContinuityAnchor::new(
        ContinuityGeneration::new(1).unwrap(),
    ));
    let store = GovernedRedisNonceStore::connect(&url, config.clone(), anchor.clone()).unwrap();

    assert!(store.provision_current_generation().is_err());
    wait_until_reconciled(&store);
    let ttl = store.retention_ms().unwrap();
    let now = bpc_protocol::unix_ms().unwrap();
    assert!(
        !store
            .check_and_consume("pair_live_redis", "nonce-live-redis-1", now, now, ttl)
            .unwrap()
    );
    assert!(
        store
            .check_and_consume("pair_live_redis", "nonce-live-redis-1", now, now, ttl)
            .unwrap()
    );

    // Simulate nonce-history rollback while marker/config remain. A recovery controller
    // advances the independently anchored generation before it permits traffic again.
    let tag = format!("{{{namespace}}}");
    let key = format!("bpc:{tag}:nonce:pair_live_redis:nonce-live-redis-1");
    let raw = redis::Client::open(url.as_str()).unwrap();
    let mut raw = raw.get_connection().unwrap();
    redis::cmd("DEL").arg(&key).query::<i64>(&mut raw).unwrap();
    anchor.advance_after_fencing(&namespace).unwrap();
    assert!(
        store
            .check_and_consume("pair_live_redis", "nonce-live-redis-1", now, now, ttl)
            .is_err()
    );
    assert!(store.is_locally_quarantined());
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
                max_pending_pairs: 1,
                approval_ttl_ms: 60_000,
                schema: schema.clone(),
                secret_protector: PostgresSecretProtector::new("test-key-v1", [7; 32])?,
                require_synchronous_replication: false,
            },
        )?;
        authority.migrate()?;
        let old_key = BpcKeyPair::generate()?;
        let registration = PairRegistration {
            name: "live-postgres".into(),
            scope: Scope::Admin,
            mode: PairMode::Production,
            audience: "bpc://live-postgres/production".into(),
            request_hmac_key: derive_request_hmac_key("LivePostgresSecret9!@")?,
            request_protocol: PairRequestProtocol::V2,
            public_jwk: old_key.public_jwk().clone(),
            expires_at_ms: None,
            max_requests: Some(1),
            kind: PairKind::Legitimate,
            canary_class: None,
        };
        let now = bpc_protocol::unix_ms()?;
        let token = authority.request_pairing(registration.clone(), now)?;
        assert!(authority.request_pairing(registration, now).is_err());
        let pair_id = authority.approve_pairing(&token, now)?;
        let initial = authority.get(&pair_id)?.expect("approved pair exists");
        let stored_ciphertext: String = admin
            .query_one(
                &format!("SELECT request_hmac_ciphertext FROM {schema}.bpc_pairs WHERE id = $1"),
                &[&pair_id],
            )
            .unwrap()
            .get(0);
        assert!(stored_ciphertext.starts_with("v1.test-key-v1."));
        assert!(!stored_ciphertext.contains("LivePostgresSecret9!@"));
        assert_eq!(
            authority.claim_success(&initial, now)?,
            SuccessClaim::Claimed
        );
        assert_eq!(
            authority
                .get(&pair_id)?
                .expect("pair retained after cap")
                .status,
            bpc_protocol::PairStatus::Expired
        );

        let rotate_key = BpcKeyPair::generate()?;
        let rotate_registration = PairRegistration {
            name: "rotation-live".into(),
            scope: Scope::ReadWrite,
            mode: PairMode::Production,
            audience: "bpc://live-postgres/production".into(),
            request_hmac_key: derive_request_hmac_key("LiveRotationSecret9!@")?,
            request_protocol: PairRequestProtocol::V2,
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
            "LiveRotationSecret9!@",
            &old_id,
            replacement_key.public_jwk(),
            Uuid::new_v4(),
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
