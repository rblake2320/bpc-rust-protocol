#![cfg(feature = "axum")]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request};
use axum::http::{Method, StatusCode};
use axum::middleware;
use axum::routing::post;
use bpc_protocol::{
    AuthSnapshot, BpcAxumState, BpcKeyPair, BpcVerifier, MemoryNonceStore, MemoryPairRegistry,
    PairKind, PairMode, PairRecord, PairStatus, Scope, derive_request_hmac_key, sign_request_at,
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
    let secret = "AxumSecret9!@";
    let registry = Arc::new(MemoryPairRegistry::default());
    registry
        .insert(PairRecord {
            id: "pair_axum".into(),
            name: "axum".into(),
            scope: Scope::ReadWrite,
            mode: PairMode::Development,
            request_hmac_key: derive_request_hmac_key(secret).unwrap(),
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
