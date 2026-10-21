use std::sync::Arc;
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bpc_protocol::{
    AuditAction, AuditEvent, AuditHead, AuditLog, AuditSeverity, BpcError, BpcKeyPair, BpcRequest,
    BpcVerifier, BpcVerifierConfig, CanaryClass, MemoryAuditLog, MemoryNonceStore,
    MemoryPairAuthority, MemoryPairRegistry, PairAuthority, PairKind, PairMode, PairRecord,
    PairRegistration, PairRegistry, PairStatus, Scope, VerificationError, derive_request_hmac_key,
    generate_registration_secret, sign_request_at, sign_rotation_at, validate_secret,
    verify_and_rotate_at,
};
use serde::Deserialize;
use uuid::Uuid;

const NOW: u64 = 1_740_000_000_000;
const SECRET: &str = "ExampleSecret9!@";
const PAIR_ID: &str = "pair_protocol";

fn setup(kind: PairKind) -> (Arc<MemoryPairRegistry>, BpcKeyPair, MemoryNonceStore) {
    let registry = Arc::new(MemoryPairRegistry::default());
    let keypair = BpcKeyPair::generate().unwrap();
    registry
        .insert(PairRecord {
            id: PAIR_ID.into(),
            name: "protocol-test".into(),
            scope: Scope::Admin,
            mode: PairMode::Development,
            audience: "bpc://localhost/development".into(),
            request_hmac_key: derive_request_hmac_key(SECRET).unwrap(),
            public_jwk: keypair.public_jwk().clone(),
            status: PairStatus::Active,
            created_at_ms: NOW,
            expires_at_ms: None,
            max_requests: None,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind,
            canary_class: matches!(kind, PairKind::Ghost).then_some(CanaryClass::Docs),
            replaced_by: None,
        })
        .unwrap();
    (registry, keypair, MemoryNonceStore::default())
}

fn signed_request(keypair: &BpcKeyPair) -> (Vec<u8>, bpc_protocol::SignedHeaders) {
    let body = br#"{"widget":"bpc"}"#.to_vec();
    let (_, headers) = sign_request_at(
        keypair.signing_key(),
        PAIR_ID,
        SECRET,
        "POST",
        "/v1/widgets?from=test",
        &body,
        Uuid::parse_str("a8098c1a-f86e-4aef-9f0f-80e4b6c6c6c6").unwrap(),
        NOW,
    )
    .unwrap();
    (body, headers)
}

#[test]
fn signs_and_verifies_exact_body_and_path() {
    let (registry, keypair, nonces) = setup(PairKind::Legitimate);
    let (body, headers) = signed_request(&keypair);
    let result = BpcVerifier::default().verify_at(
        BpcRequest {
            pair_id: &headers.pair_id,
            signature: &headers.signature,
            signed_data: &headers.signed_data,
            version: &headers.version,
            method: "POST",
            path: "/v1/widgets?from=test",
            body: &body,
        },
        registry.as_ref(),
        &nonces,
        NOW,
    );
    assert!(result.ok, "{result:?}");
    assert_eq!(result.snapshot.unwrap().scope, Scope::Admin);
}

#[test]
fn verifier_rejects_untrusted_audience_and_out_of_policy_freshness_windows() {
    let (registry, keypair, nonces) = setup(PairKind::Legitimate);
    let (body, headers) = signed_request(&keypair);
    let production = BpcVerifier::new(
        BpcVerifierConfig::new("bpc://api.example.test/production", PairMode::Production).unwrap(),
    );
    let denied = production.verify_at(
        BpcRequest {
            pair_id: &headers.pair_id,
            signature: &headers.signature,
            signed_data: &headers.signed_data,
            version: &headers.version,
            method: "POST",
            path: "/v1/widgets?from=test",
            body: &body,
        },
        registry.as_ref(),
        &nonces,
        NOW,
    );
    assert_eq!(denied.error, Some(VerificationError::AudienceMismatch));
    assert!(
        BpcVerifierConfig::new("bpc://localhost/development", PairMode::Development)
            .unwrap()
            .with_signature_window_ms(bpc_protocol::MAX_SIGNATURE_WINDOW_MS + 1)
            .is_err()
    );
    assert!(
        BpcVerifierConfig::new("bpc://localhost/development", PairMode::Development)
            .unwrap()
            .with_signature_window_ms(0)
            .is_err()
    );
}

#[test]
fn nonce_identity_is_scoped_to_pair_but_still_rejects_each_pairs_replay() {
    let (registry, first_key, nonces) = setup(PairKind::Legitimate);
    let second_key = BpcKeyPair::generate().unwrap();
    registry
        .insert(PairRecord {
            id: "pair_second".into(),
            name: "second".into(),
            scope: Scope::Admin,
            mode: PairMode::Development,
            audience: "bpc://localhost/development".into(),
            request_hmac_key: derive_request_hmac_key("SecondProtocolSecret9!@#").unwrap(),
            public_jwk: second_key.public_jwk().clone(),
            status: PairStatus::Active,
            created_at_ms: NOW,
            expires_at_ms: None,
            max_requests: None,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind: PairKind::Legitimate,
            canary_class: None,
            replaced_by: None,
        })
        .unwrap();
    let nonce = Uuid::parse_str("a8098c1a-f86e-4aef-9f0f-80e4b6c6c6c6").unwrap();
    let body = br#"{"widget":"bpc"}"#;
    let (_, first) = sign_request_at(
        first_key.signing_key(),
        PAIR_ID,
        SECRET,
        "POST",
        "/v1/widgets?from=test",
        body,
        nonce,
        NOW,
    )
    .unwrap();
    let (_, second) = sign_request_at(
        second_key.signing_key(),
        "pair_second",
        "SecondProtocolSecret9!@#",
        "POST",
        "/v1/widgets?from=test",
        body,
        nonce,
        NOW,
    )
    .unwrap();
    let verifier = BpcVerifier::default();
    for headers in [&first, &second] {
        assert!(
            verifier
                .verify_at(
                    BpcRequest {
                        pair_id: &headers.pair_id,
                        signature: &headers.signature,
                        signed_data: &headers.signed_data,
                        version: &headers.version,
                        method: "POST",
                        path: "/v1/widgets?from=test",
                        body,
                    },
                    registry.as_ref(),
                    &nonces,
                    NOW,
                )
                .ok
        );
    }
    for headers in [&first, &second] {
        assert_eq!(
            verifier
                .verify_at(
                    BpcRequest {
                        pair_id: &headers.pair_id,
                        signature: &headers.signature,
                        signed_data: &headers.signed_data,
                        version: &headers.version,
                        method: "POST",
                        path: "/v1/widgets?from=test",
                        body,
                    },
                    registry.as_ref(),
                    &nonces,
                    NOW,
                )
                .error,
            Some(VerificationError::ReplayDetected)
        );
    }
}

#[test]
fn rust_signer_rejects_weak_registration_secret() {
    let keypair = BpcKeyPair::generate().unwrap();
    assert!(matches!(
        derive_request_hmac_key("weak"),
        Err(BpcError::SecretPolicy(_))
    ));
    let result = sign_request_at(
        keypair.signing_key(),
        PAIR_ID,
        "weak",
        "POST",
        "/v1/widgets",
        b"{}",
        Uuid::new_v4(),
        NOW,
    );
    assert!(matches!(result, Err(BpcError::SecretPolicy(_))));
}

#[test]
fn generated_registration_secrets_meet_policy_and_do_not_repeat() {
    let first = generate_registration_secret().unwrap();
    let second = generate_registration_secret().unwrap();
    assert_eq!(first.len(), 48);
    assert_eq!(second.len(), 48);
    assert!(first.starts_with("Aa0!!"));
    assert!(second.starts_with("Aa0!!"));
    validate_secret(&first).unwrap();
    validate_secret(&second).unwrap();
    assert_ne!(first, second);
}

#[test]
fn a_forged_signature_does_not_burn_the_nonce() {
    let (registry, keypair, nonces) = setup(PairKind::Legitimate);
    let (body, headers) = signed_request(&keypair);
    let mut forged = headers.clone();
    forged.signature.replace_range(0..1, "A");
    let verifier = BpcVerifier::default();
    let first = verifier.verify_at(
        BpcRequest {
            pair_id: &forged.pair_id,
            signature: &forged.signature,
            signed_data: &forged.signed_data,
            version: &forged.version,
            method: "POST",
            path: "/v1/widgets?from=test",
            body: &body,
        },
        registry.as_ref(),
        &nonces,
        NOW,
    );
    assert_eq!(first.error, Some(VerificationError::InvalidSignature));
    let valid = verifier.verify_at(
        BpcRequest {
            pair_id: &headers.pair_id,
            signature: &headers.signature,
            signed_data: &headers.signed_data,
            version: &headers.version,
            method: "POST",
            path: "/v1/widgets?from=test",
            body: &body,
        },
        registry.as_ref(),
        &nonces,
        NOW,
    );
    assert!(valid.ok, "{valid:?}");
}

#[test]
fn pair_id_only_junk_cannot_lock_a_credential() {
    let (registry, _keypair, nonces) = setup(PairKind::Legitimate);
    let verifier = BpcVerifier::default();
    for _ in 0..20 {
        let denied = verifier.verify_at(
            BpcRequest {
                pair_id: PAIR_ID,
                signature: "not-a-signature",
                signed_data: "not-base64url-json",
                version: bpc_protocol::BPC_PROTOCOL_VERSION,
                method: "POST",
                path: "/v1/widgets?from=test",
                body: b"{}",
            },
            registry.as_ref(),
            &nonces,
            NOW,
        );
        assert_eq!(denied.error, Some(VerificationError::InvalidSignedData));
    }
    let pair = registry.get(PAIR_ID).unwrap().unwrap();
    assert_eq!(pair.status, PairStatus::Active);
    assert_eq!(pair.failed_signatures, 0);
}

#[test]
fn replayed_valid_hmac_with_invalid_signatures_cannot_lock_a_credential() {
    let (registry, keypair, nonces) = setup(PairKind::Legitimate);
    let (body, headers) = signed_request(&keypair);
    let verifier = BpcVerifier::default();
    let mut forged = headers.clone();
    forged.signature.push('A');
    for _ in 0..2 {
        let denied = verifier.verify_at(
            BpcRequest {
                pair_id: &forged.pair_id,
                signature: &forged.signature,
                signed_data: &forged.signed_data,
                version: &forged.version,
                method: "POST",
                path: "/v1/widgets?from=test",
                body: &body,
            },
            registry.as_ref(),
            &nonces,
            NOW,
        );
        assert_eq!(denied.error, Some(VerificationError::InvalidSignature));
    }
    let pair = registry.get(PAIR_ID).unwrap().unwrap();
    assert_eq!(pair.status, PairStatus::Active);
    assert_eq!(pair.failed_signatures, 0);
}

#[test]
fn all_invalid_signatures_leave_credential_state_unchanged() {
    let (registry, keypair, nonces) = setup(PairKind::Legitimate);
    let (body, headers) = signed_request(&keypair);
    let verifier = BpcVerifier::default();
    let mut forged = headers.clone();
    forged.signature.push('A');
    for _ in 0..3 {
        assert_eq!(
            verifier
                .verify_at(
                    BpcRequest {
                        pair_id: &forged.pair_id,
                        signature: &forged.signature,
                        signed_data: &forged.signed_data,
                        version: &forged.version,
                        method: "POST",
                        path: "/v1/widgets?from=test",
                        body: &body,
                    },
                    registry.as_ref(),
                    &nonces,
                    NOW,
                )
                .error,
            Some(VerificationError::InvalidSignature)
        );
    }
    let pair = registry.get(PAIR_ID).unwrap().unwrap();
    assert_eq!(pair.status, PairStatus::Active);
    assert_eq!(pair.failed_signatures, 0);
}

#[test]
fn exactly_one_of_many_concurrent_replays_is_authorized() {
    let (registry, keypair, nonces) = setup(PairKind::Legitimate);
    let registry = Arc::clone(&registry);
    let nonces = Arc::new(nonces);
    let (body, headers) = signed_request(&keypair);
    let handles: Vec<_> = (0..64)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let nonces = Arc::clone(&nonces);
            let headers = headers.clone();
            let body = body.clone();
            thread::spawn(move || {
                BpcVerifier::default().verify_at(
                    BpcRequest {
                        pair_id: &headers.pair_id,
                        signature: &headers.signature,
                        signed_data: &headers.signed_data,
                        version: &headers.version,
                        method: "POST",
                        path: "/v1/widgets?from=test",
                        body: &body,
                    },
                    registry.as_ref(),
                    nonces.as_ref(),
                    NOW,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.ok).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.error == Some(VerificationError::ReplayDetected))
            .count(),
        63
    );
}

#[test]
fn verified_ghost_pair_is_never_authorized_and_its_nonce_is_spent() {
    let (registry, keypair, nonces) = setup(PairKind::Ghost);
    let (body, headers) = signed_request(&keypair);
    let verifier = BpcVerifier::default();
    let first = verifier.verify_at(
        BpcRequest {
            pair_id: &headers.pair_id,
            signature: &headers.signature,
            signed_data: &headers.signed_data,
            version: &headers.version,
            method: "POST",
            path: "/v1/widgets?from=test",
            body: &body,
        },
        registry.as_ref(),
        &nonces,
        NOW,
    );
    assert_eq!(first.error, Some(VerificationError::GhostPairDenied));
    let replay = verifier.verify_at(
        BpcRequest {
            pair_id: &headers.pair_id,
            signature: &headers.signature,
            signed_data: &headers.signed_data,
            version: &headers.version,
            method: "POST",
            path: "/v1/widgets?from=test",
            body: &body,
        },
        registry.as_ref(),
        &nonces,
        NOW,
    );
    assert_eq!(replay.error, Some(VerificationError::ReplayDetected));
}

#[test]
fn rotation_is_signed_bound_and_atomic() {
    let (registry, old_key, _) = setup(PairKind::Legitimate);
    let authority = MemoryPairAuthority::new(Arc::clone(&registry), 10).unwrap();
    let new_key = BpcKeyPair::generate().unwrap();
    let request = sign_rotation_at(
        old_key.signing_key(),
        SECRET,
        PAIR_ID,
        new_key.public_jwk(),
        Uuid::parse_str("03d8cf96-ab7c-4727-b4e1-6a9309efb312").unwrap(),
        NOW,
    )
    .unwrap();
    let mut signature_only = request.clone();
    signature_only.secret_hmac.replace_range(0..1, "A");
    assert!(verify_and_rotate_at(&authority, &signature_only, NOW, 60_000).is_err());
    assert_eq!(
        registry.get(PAIR_ID).unwrap().unwrap().status,
        PairStatus::Active
    );
    let replacement_id = verify_and_rotate_at(&authority, &request, NOW, 60_000).unwrap();
    assert_eq!(
        registry.get(PAIR_ID).unwrap().unwrap().status,
        PairStatus::Rotated
    );
    let replacement = registry.get(&replacement_id).unwrap().unwrap();
    assert_eq!(replacement.status, PairStatus::Active);
    assert_eq!(replacement.public_jwk, *new_key.public_jwk());
    assert!(verify_and_rotate_at(&authority, &request, NOW, 60_000).is_err());
    assert!(authority.revoke(PAIR_ID).unwrap());
    assert_eq!(
        registry.get(&replacement_id).unwrap().unwrap().status,
        PairStatus::Revoked
    );
}

#[test]
fn audit_chain_detects_tampering_and_bad_anchor() {
    let log = MemoryAuditLog::new();
    log.append_at(
        AuditEvent {
            action: AuditAction::Register,
            severity: AuditSeverity::Info,
            pair_id: Some(PAIR_ID.into()),
            error_code: None,
            source_ip: None,
            method: None,
            path: None,
            request_id: None,
            detail: None,
        },
        NOW,
    )
    .unwrap();
    log.append_at(
        AuditEvent {
            action: AuditAction::VerifyPass,
            severity: AuditSeverity::Info,
            pair_id: Some(PAIR_ID.into()),
            error_code: None,
            source_ip: None,
            method: Some("GET".into()),
            path: Some("/v1/widgets".into()),
            request_id: None,
            detail: None,
        },
        NOW + 1,
    )
    .unwrap();
    let head = log.head().unwrap();
    assert!(log.verify(Some(&head)).unwrap().valid);
    let mut entries = log.entries().unwrap();
    entries[1].event.path = Some("/tampered".into());
    assert!(
        !bpc_protocol::verify_audit_entries(&entries, Some(&head))
            .unwrap()
            .valid
    );
    let wrong = AuditHead {
        sequence: 3,
        chain_hash: head.chain_hash,
        count: 3,
    };
    assert!(!log.verify(Some(&wrong)).unwrap().valid);
}

#[derive(Deserialize)]
struct NodeFixture {
    registration_secret: String,
    request_hmac_key: String,
    public_jwk: bpc_protocol::PublicJwk,
    body_base64url: String,
    headers: bpc_protocol::SignedHeaders,
}

#[test]
fn accepts_node_webcrypto_p1363_request_fixture() {
    let fixture: NodeFixture =
        serde_json::from_str(include_str!("fixtures/node-webcrypto-v1.json")).unwrap();
    assert_eq!(
        derive_request_hmac_key(&fixture.registration_secret).unwrap(),
        fixture.request_hmac_key
    );
    let body = URL_SAFE_NO_PAD.decode(fixture.body_base64url).unwrap();
    let registry = MemoryPairRegistry::default();
    registry
        .insert(PairRecord {
            id: fixture.headers.pair_id.clone(),
            name: "node-webcrypto".into(),
            scope: Scope::ReadWrite,
            mode: PairMode::Production,
            audience: "bpc://api.example.test/production".into(),
            request_hmac_key: fixture.request_hmac_key,
            public_jwk: fixture.public_jwk,
            status: PairStatus::Active,
            created_at_ms: NOW,
            expires_at_ms: None,
            max_requests: None,
            requests: 0,
            failed_signatures: 0,
            authorization_version: 1,
            kind: PairKind::Legitimate,
            canary_class: None,
            replaced_by: None,
        })
        .unwrap();
    let verifier = BpcVerifier::new(
        BpcVerifierConfig::new("bpc://api.example.test/production", PairMode::Production).unwrap(),
    );
    let result = verifier.verify_at(
        BpcRequest {
            pair_id: &fixture.headers.pair_id,
            signature: &fixture.headers.signature,
            signed_data: &fixture.headers.signed_data,
            version: &fixture.headers.version,
            method: "POST",
            path: "/v1/widgets?source=node",
            body: &body,
        },
        &registry,
        &MemoryNonceStore::default(),
        NOW,
    );
    assert!(result.ok, "{result:?}");
}

#[test]
fn expired_pairs_are_transitioned_before_memory_capacity_is_checked() {
    let registry = Arc::new(MemoryPairRegistry::default());
    let authority = MemoryPairAuthority::new(Arc::clone(&registry), 1).unwrap();
    let first_key = BpcKeyPair::generate().unwrap();
    let first = PairRegistration {
        name: "first".into(),
        scope: Scope::Read,
        mode: PairMode::Development,
        audience: "bpc://localhost/development".into(),
        request_hmac_key: derive_request_hmac_key(SECRET).unwrap(),
        public_jwk: first_key.public_jwk().clone(),
        expires_at_ms: Some(NOW),
        max_requests: None,
        kind: PairKind::Legitimate,
        canary_class: None,
    };
    let first_token = authority.request_pairing(first, NOW).unwrap();
    let first_id = authority.approve_pairing(&first_token, NOW).unwrap();
    let second_key = BpcKeyPair::generate().unwrap();
    let second = PairRegistration {
        name: "second".into(),
        scope: Scope::Read,
        mode: PairMode::Development,
        audience: "bpc://localhost/development".into(),
        request_hmac_key: derive_request_hmac_key("SecondCapacitySecret9!@#").unwrap(),
        public_jwk: second_key.public_jwk().clone(),
        expires_at_ms: None,
        max_requests: None,
        kind: PairKind::Legitimate,
        canary_class: None,
    };
    let second_token = authority.request_pairing(second, NOW + 1).unwrap();
    let second_id = authority.approve_pairing(&second_token, NOW + 1).unwrap();
    assert_eq!(
        registry.get(&first_id).unwrap().unwrap().status,
        PairStatus::Expired
    );
    assert_eq!(
        registry.get(&second_id).unwrap().unwrap().status,
        PairStatus::Active
    );
}
