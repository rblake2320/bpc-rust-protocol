#![cfg(feature = "axum")]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request};
use axum::http::{Method, StatusCode};
use axum::middleware;
use axum::routing::post;
use bpc_protocol::{
    AuthSnapshot, BpcAxumState, BpcKeyPair, BpcSigningContext, BpcVerifier, MemoryNonceStore,
    MemoryPairRegistry, PairKind, PairMode, PairRecord, PairRequestProtocol, PairStatus, Scope,
    derive_request_hmac_key, sign_request_at,
};
use tower::ServiceExt;
use uuid::Uuid;

async fn protected(Extension(snapshot): Extension<AuthSnapshot>, body: String) -> String {
    format!(
        "{}:{}:{}",
        snapshot.pair_id,
        snapshot.scope.allows("POST"),
        body
    )
}

#[tokio::test]
async fn axum_layer_verifies_raw_bytes_and_restores_the_body() {
    let now = bpc_protocol::unix_ms().unwrap();
    let keypair = BpcKeyPair::generate().unwrap();
    let secret = "AxumProtocolSecret9!@#";
    let registry = Arc::new(MemoryPairRegistry::default());
    registry
        .insert(PairRecord {
            id: "pair_axum".into(),
            name: "axum".into(),
            scope: Scope::ReadWrite,
            mode: PairMode::Development,
            audience: "bpc://localhost/development".into(),
            request_hmac_key: derive_request_hmac_key(secret).unwrap(),
            request_protocol: PairRequestProtocol::V2,
            public_jwk: keypair.public_jwk().clone(),
            status: PairStatus::Active,
            created_at_ms: now,
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
    let nonce_store = Arc::new(MemoryNonceStore::default());
    let state = BpcAxumState::new(BpcVerifier::default(), registry, nonce_store);
    let app =
        Router::new()
            .route("/v1/widgets", post(protected))
            .layer(middleware::from_fn_with_state(
                state,
                bpc_protocol::bpc_axum_middleware,
            ));
    let body = br#"{"preserved":true}"#;
    let (_, headers) = sign_request_at(
        keypair.signing_key(),
        "pair_axum",
        secret,
        &BpcSigningContext::new("bpc://localhost/development", PairMode::Development).unwrap(),
        "POST",
        "/v1/widgets?via=axum",
        body,
        Uuid::parse_str("7f0e4b5a-7621-4ee6-93a5-c76a159f9001").unwrap(),
        now,
    )
    .unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/widgets?via=axum")
        .header("X-BPC-HMAC", headers.hmac)
        .header("X-BPC-Pair-ID", headers.pair_id)
        .header("X-BPC-Signature", headers.signature)
        .header("X-BPC-Signed-Data", headers.signed_data)
        .header("X-BPC-Version", headers.version)
        .body(Body::from(body.as_slice()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"pair_axum:true:{\"preserved\":true}");
}

#[tokio::test]
async fn axum_hides_verifier_failure_details_by_default() {
    let now = bpc_protocol::unix_ms().unwrap();
    let keypair = BpcKeyPair::generate().unwrap();
    let secret = "AxumProtocolSecret9!@#";
    let registry = Arc::new(MemoryPairRegistry::default());
    registry
        .insert(PairRecord {
            id: "pair_axum_errors".into(),
            name: "axum-errors".into(),
            scope: Scope::ReadWrite,
            mode: PairMode::Development,
            audience: "bpc://localhost/development".into(),
            request_hmac_key: derive_request_hmac_key(secret).unwrap(),
            request_protocol: PairRequestProtocol::V2,
            public_jwk: keypair.public_jwk().clone(),
            status: PairStatus::Active,
            created_at_ms: now,
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
    let state = BpcAxumState::new(
        BpcVerifier::default(),
        registry,
        Arc::new(MemoryNonceStore::default()),
    );
    let app =
        Router::new()
            .route("/v1/widgets", post(protected))
            .layer(middleware::from_fn_with_state(
                state,
                bpc_protocol::bpc_axum_middleware,
            ));
    let body = br#"{"preserved":true}"#;
    let (_, headers) = sign_request_at(
        keypair.signing_key(),
        "pair_axum_errors",
        secret,
        &BpcSigningContext::new("bpc://localhost/development", PairMode::Development).unwrap(),
        "POST",
        "/v1/widgets",
        body,
        Uuid::parse_str("7f0e4b5a-7621-4ee6-93a5-c76a159f9002").unwrap(),
        now,
    )
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/widgets")
                .header("X-BPC-HMAC", headers.hmac)
                .header("X-BPC-Pair-ID", headers.pair_id)
                .header("X-BPC-Signature", format!("{}x", headers.signature))
                .header("X-BPC-Signed-Data", headers.signed_data)
                .header("X-BPC-Version", headers.version)
                .body(Body::from(body.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&response_body[..], br#"{"error":{"code":"unauthorized"}}"#);
}

#[tokio::test]
async fn axum_rejects_declared_oversized_body_before_buffering() {
    let registry = Arc::new(MemoryPairRegistry::default());
    let mut state = BpcAxumState::new(
        BpcVerifier::default(),
        registry,
        Arc::new(MemoryNonceStore::default()),
    );
    state.max_body_bytes = 2;
    let app =
        Router::new()
            .route("/v1/widgets", post(protected))
            .layer(middleware::from_fn_with_state(
                state,
                bpc_protocol::bpc_axum_middleware,
            ));
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/widgets")
                .header("X-BPC-HMAC", "x")
                .header("X-BPC-Pair-ID", "pair_oversize")
                .header("X-BPC-Signature", "x")
                .header("X-BPC-Signed-Data", "x")
                .header("X-BPC-Version", "bpc-v1")
                .header("Content-Length", "3")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn axum_times_out_a_stalled_pre_auth_body_and_releases_its_permit() {
    let state = BpcAxumState::new(
        BpcVerifier::default(),
        Arc::new(MemoryPairRegistry::default()),
        Arc::new(MemoryNonceStore::default()),
    )
    .with_body_collection_limit(1)
    .unwrap()
    .with_body_collection_timeout(Duration::from_millis(10))
    .unwrap();
    let app =
        Router::new()
            .route("/v1/widgets", post(protected))
            .layer(middleware::from_fn_with_state(
                state,
                bpc_protocol::bpc_axum_middleware,
            ));
    let stalled = Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/widgets")
                .header("X-BPC-HMAC", "x")
                .header("X-BPC-Pair-ID", "pair_stalled")
                .header("X-BPC-Signature", "x")
                .header("X-BPC-Signed-Data", "x")
                .header("X-BPC-Version", "1.0")
                .body(stalled)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(response.headers().get("connection").unwrap(), "close");
}
