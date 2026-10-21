//! Axum integration for the BPC verifier.
//!
//! It reads the exact raw body once, verifies its digest, restores those exact
//! bytes for the inner service, and stores only the immutable authorization
//! snapshot in request extensions on success. The signed path is
//! `path_and_query()`; do not normalize routes/proxy paths on only one side.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{
    HeaderMap, StatusCode,
    header::{CONNECTION, HeaderName, HeaderValue},
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::{AuthSnapshot, BpcRequest, BpcVerifier, NonceStore, PairRegistry, VerificationError};

/// Controls the error-code detail disclosed to an untrusted HTTP caller.
///
/// [`Self::Generic`] is the production-safe default. The verifier still returns
/// its precise error to trusted in-process telemetry, but the public response
/// never reveals pair lifecycle, replay, signature, or canary state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BpcPublicErrorDisclosure {
    #[default]
    Generic,
    DetailedForDevelopment,
}

/// State passed to [`bpc_axum_middleware`].
pub struct BpcAxumState<R, N> {
    pub verifier: BpcVerifier,
    pub registry: Arc<R>,
    pub nonce_store: Arc<N>,
    /// Hard cap before body buffering. Streaming uploads need an application
    /// supplied digest strategy; BPC v1 signs an exact precomputed body digest.
    pub max_body_bytes: usize,
    /// Bounds requests that can buffer a body before authentication. Keep a
    /// proxy/server read timeout in front of this adapter as well.
    body_collection_permits: Arc<Semaphore>,
    /// Hard deadline for unauthenticated body collection. The adapter returns a
    /// connection-closing timeout response when a streaming body stalls.
    body_collection_timeout: Duration,
    /// Bounds synchronous registry/nonce-store verification jobs placed on the
    /// Tokio blocking executor so they cannot stall async worker threads.
    verification_permits: Arc<Semaphore>,
    verification_timeout: Duration,
    /// Public error behavior. Keep the default in every internet-facing
    /// deployment; detailed codes exist only for isolated development.
    pub error_disclosure: BpcPublicErrorDisclosure,
}

impl<R, N> Clone for BpcAxumState<R, N> {
    fn clone(&self) -> Self {
        Self {
            verifier: self.verifier.clone(),
            registry: Arc::clone(&self.registry),
            nonce_store: Arc::clone(&self.nonce_store),
            max_body_bytes: self.max_body_bytes,
            body_collection_permits: Arc::clone(&self.body_collection_permits),
            body_collection_timeout: self.body_collection_timeout,
            verification_permits: Arc::clone(&self.verification_permits),
            verification_timeout: self.verification_timeout,
            error_disclosure: self.error_disclosure,
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
            body_collection_permits: Arc::new(Semaphore::new(64)),
            body_collection_timeout: Duration::from_secs(5),
            verification_permits: Arc::new(Semaphore::new(64)),
            verification_timeout: Duration::from_secs(5),
            error_disclosure: BpcPublicErrorDisclosure::Generic,
        }
    }

    /// Sets the maximum number of requests that may buffer a body before BPC
    /// verification. Zero is rejected because it would permanently deny traffic.
    pub fn with_body_collection_limit(
        mut self,
        max_in_flight: usize,
    ) -> std::result::Result<Self, &'static str> {
        if max_in_flight == 0 {
            return Err("body collection limit must be greater than zero");
        }
        self.body_collection_permits = Arc::new(Semaphore::new(max_in_flight));
        Ok(self)
    }

    /// Sets the maximum duration of one pre-authentication body read.
    pub fn with_body_collection_timeout(
        mut self,
        timeout: Duration,
    ) -> std::result::Result<Self, &'static str> {
        if timeout.is_zero() {
            return Err("body collection timeout must be greater than zero");
        }
        self.body_collection_timeout = timeout;
        Ok(self)
    }

    /// Sets a bounded timeout and concurrency level for synchronous verifier
    /// backends run on Tokio's dedicated blocking executor.
    pub fn with_verification_limit(
        mut self,
        max_in_flight: usize,
        timeout: Duration,
    ) -> std::result::Result<Self, &'static str> {
        if max_in_flight == 0 || timeout.is_zero() {
            return Err("verification limit and timeout must be greater than zero");
        }
        self.verification_permits = Arc::new(Semaphore::new(max_in_flight));
        self.verification_timeout = timeout;
        Ok(self)
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
    let hmac = match unique_header(&parts.headers, "x-bpc-hmac") {
        Ok(value) => value,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
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
    if declared_body_is_too_large(&parts.headers, state.max_body_bytes) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let _permit = match Arc::clone(&state.body_collection_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "authentication_busy"),
    };
    let body = match tokio::time::timeout(
        state.body_collection_timeout,
        to_bytes(body, state.max_body_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
        Err(_) => return timeout_response(),
    };
    drop(_permit);
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |value| value.as_str().to_owned());
    let method = parts.method.as_str().to_owned();
    let verification_permit = match Arc::clone(&state.verification_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "authentication_busy"),
    };
    let verifier = state.verifier.clone();
    let registry = Arc::clone(&state.registry);
    let nonce_store = Arc::clone(&state.nonce_store);
    let verify_body = body.clone();
    let result = match tokio::time::timeout(
        state.verification_timeout,
        tokio::task::spawn_blocking(move || {
            // A timed-out JoinHandle cannot cancel running blocking I/O. Keep
            // the permit with that task until it truly finishes so at most the
            // configured number of stalled backend calls can exist.
            let _permit = verification_permit;
            verifier.verify(
                BpcRequest {
                    hmac: &hmac,
                    pair_id: &pair_id,
                    signature: &signature,
                    signed_data: &signed_data,
                    version: &version,
                    method: &method,
                    path: &path,
                    body: &verify_body,
                },
                registry.as_ref(),
                nonce_store.as_ref(),
            )
        }),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_temporarily_unavailable",
            );
        }
    };
    if !result.ok {
        let error = result.error.expect("denial contains an error");
        return error_response(
            status_for(error, state.error_disclosure),
            public_code(error, state.error_disclosure),
        );
    }
    let Some(snapshot) = result.snapshot else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_temporarily_unavailable",
        );
    };
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

fn declared_body_is_too_large(headers: &HeaderMap, max_body_bytes: usize) -> bool {
    let mut values = headers.get_all("content-length").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|declared| declared > max_body_bytes)
}

fn status_for(error: VerificationError, disclosure: BpcPublicErrorDisclosure) -> StatusCode {
    if disclosure == BpcPublicErrorDisclosure::Generic {
        return match error {
            VerificationError::MissingHeaders
            | VerificationError::InvalidMethod
            | VerificationError::InvalidSignedData
            | VerificationError::VersionMismatch
            | VerificationError::MissingBodyHash => StatusCode::BAD_REQUEST,
            VerificationError::ReplayStoreUnavailable
            | VerificationError::PairFinalizationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        };
    }
    match error {
        VerificationError::MissingHeaders
        | VerificationError::InvalidMethod
        | VerificationError::InvalidSignedData
        | VerificationError::VersionMismatch
        | VerificationError::MissingBodyHash => StatusCode::BAD_REQUEST,
        VerificationError::ScopeViolation => StatusCode::FORBIDDEN,
        VerificationError::ReplayStoreUnavailable
        | VerificationError::PairFinalizationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNAUTHORIZED,
    }
}

fn public_code(error: VerificationError, disclosure: BpcPublicErrorDisclosure) -> &'static str {
    if disclosure == BpcPublicErrorDisclosure::Generic {
        return match error {
            VerificationError::MissingHeaders
            | VerificationError::InvalidMethod
            | VerificationError::InvalidSignedData
            | VerificationError::VersionMismatch
            | VerificationError::MissingBodyHash => "invalid_request",
            VerificationError::ReplayStoreUnavailable
            | VerificationError::PairFinalizationUnavailable => {
                "authentication_temporarily_unavailable"
            }
            _ => "unauthorized",
        };
    }
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

fn timeout_response() -> Response {
    let mut response = error_response(StatusCode::REQUEST_TIMEOUT, "authentication_timeout");
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Retrieves the verified BPC authorization snapshot from a protected handler.
pub fn auth_snapshot(request: &Request) -> Option<&AuthSnapshot> {
    request.extensions().get::<AuthSnapshot>()
}
