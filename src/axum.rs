//! Axum integration for the BPC verifier.
//!
//! It reads the exact raw body once, verifies its digest, restores those exact
//! bytes for the inner service, and stores only the immutable authorization
//! snapshot in request extensions on success. The signed path is
//! `path_and_query()`; do not normalize routes/proxy paths on only one side.

use std::sync::Arc;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header::HeaderName};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::{AuthSnapshot, BpcRequest, BpcVerifier, NonceStore, PairRegistry, VerificationError};

/// State passed to [`bpc_axum_middleware`].
pub struct BpcAxumState<R, N> {
    pub verifier: BpcVerifier,
    pub registry: Arc<R>,
    pub nonce_store: Arc<N>,
    /// Hard cap before body buffering. Streaming uploads need an application
    /// supplied digest strategy; BPC v1 signs an exact precomputed body digest.
    pub max_body_bytes: usize,
}

impl<R, N> Clone for BpcAxumState<R, N> {
    fn clone(&self) -> Self {
        Self {
            verifier: self.verifier.clone(),
            registry: Arc::clone(&self.registry),
            nonce_store: Arc::clone(&self.nonce_store),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

impl<R, N> BpcAxumState<R, N> {
    pub fn new(verifier: BpcVerifier, registry: Arc<R>, nonce_store: Arc<N>) -> Self {
        Self {
            verifier,
            registry,
            nonce_store,
            max_body_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Axum middleware function intended for `middleware::from_fn_with_state`.
pub async fn bpc_axum_middleware<R, N>(
    State(state): State<BpcAxumState<R, N>>,
    request: Request,
    next: Next,
) -> Response
where
    R: PairRegistry + 'static,
    N: NonceStore + 'static,
{
    let (parts, body) = request.into_parts();
    let pair_id = match unique_header(&parts.headers, "x-bpc-pair-id") {
        Ok(value) => value,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
    let signature = match unique_header(&parts.headers, "x-bpc-signature") {
        Ok(value) => value,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
    let signed_data = match unique_header(&parts.headers, "x-bpc-signed-data") {
        Ok(value) => value,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
    let version = match unique_header(&parts.headers, "x-bpc-version") {
        Ok(value) => value,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
    let body = match to_bytes(body, state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
    };
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let result = state.verifier.verify(
        BpcRequest {
            pair_id: &pair_id,
            signature: &signature,
            signed_data: &signed_data,
            version: &version,
            method: parts.method.as_str(),
            path,
            body: &body,
        },
        state.registry.as_ref(),
        state.nonce_store.as_ref(),
    );
    if !result.ok {
        let error = result.error.expect("denial contains an error");
        return error_response(status_for(error), public_code(error));
    }
    let snapshot = result.snapshot.expect("success contains an auth snapshot");
    let mut restored = Request::from_parts(parts, Body::from(body));
    restored.extensions_mut().insert(snapshot);
    next.run(restored).await
}

fn unique_header(
    headers: &HeaderMap,
    name: &'static str,
) -> std::result::Result<String, &'static str> {
    let header = HeaderName::from_static(name);
    let mut values = headers.get_all(header).iter();
    let Some(value) = values.next() else {
        return Err("missing_headers");
    };
    if values.next().is_some() {
        return Err("duplicate_bpc_header");
    }
    value
        .to_str()
        .map(ToOwned::to_owned)
        .map_err(|_| "invalid_bpc_header")
}

fn status_for(error: VerificationError) -> StatusCode {
    match error {
        VerificationError::MissingHeaders
        | VerificationError::InvalidMethod
        | VerificationError::InvalidSignedData
        | VerificationError::VersionMismatch
        | VerificationError::MissingBodyHash => StatusCode::BAD_REQUEST,
        VerificationError::ScopeViolation => StatusCode::FORBIDDEN,
        VerificationError::ReplayStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNAUTHORIZED,
    }
}

fn public_code(error: VerificationError) -> &'static str {
    // A canary is an internal detection mechanism, not attacker-facing state.
    if error == VerificationError::GhostPairDenied {
        "unauthorized"
    } else {
        error.code()
    }
}

fn error_response(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": { "code": code } }))).into_response()
}

/// Retrieves the verified BPC authorization snapshot from a protected handler.
pub fn auth_snapshot(request: &Request) -> Option<&AuthSnapshot> {
    request.extensions().get::<AuthSnapshot>()
}
