//! Reqwest transport for BPC-signed HTTPS requests.

use p256::ecdsa::SigningKey;
use reqwest::{Client, Method, Response, Url};

use crate::{BpcError, Result, SignedHeaders, sign_request};

/// A BPC client whose caller owns the signing-key lifecycle.
///
/// The transport accepts byte bodies rather than structured JSON to ensure the
/// exact bytes hashed, signed, and transmitted are identical.
pub struct BpcHttpClient {
    client: Client,
    base_url: Url,
    pair_id: String,
    registration_secret: String,
    signing_key: SigningKey,
}

impl BpcHttpClient {
    pub fn new(
        client: Client,
        base_url: Url,
        pair_id: impl Into<String>,
        registration_secret: impl Into<String>,
        signing_key: SigningKey,
    ) -> Result<Self> {
        if base_url.scheme() != "https"
            && !matches!(
                base_url.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1")
            )
        {
            return Err(BpcError::InvalidPayload(
                "BPC HTTP client requires HTTPS except for localhost development".into(),
            ));
        }
        let pair_id = pair_id.into();
        if !crate::is_valid_pair_id(&pair_id) {
            return Err(BpcError::InvalidPayload("invalid BPC pair ID".into()));
        }
        let registration_secret = registration_secret.into();
        if registration_secret.is_empty() {
            return Err(BpcError::EmptySecret);
        }
        Ok(Self {
            client,
            base_url,
            pair_id,
            registration_secret,
            signing_key,
        })
    }

    /// Creates headers for the exact `method`, signed request target, and body.
    pub fn signed_headers(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<SignedHeaders> {
        let (_, headers) = sign_request(
            &self.signing_key,
            &self.pair_id,
            &self.registration_secret,
            method,
            path_and_query,
            body,
        )?;
        Ok(headers)
    }

    /// Signs and sends exact body bytes. `path_and_query` must match the target
    /// format configured in the server's Axum adapter (this crate uses it verbatim).
    pub async fn request(
        &self,
        method: Method,
        path_and_query: &str,
        body: impl Into<Vec<u8>>,
    ) -> Result<Response> {
        if !path_and_query.starts_with('/') {
            return Err(BpcError::InvalidPayload(
                "signed path must begin with '/' and include any query string".into(),
            ));
        }
        let body = body.into();
        let headers = self.signed_headers(method.as_str(), path_and_query, &body)?;
        let url = self
            .base_url
            .join(path_and_query)
            .map_err(|error| BpcError::InvalidPayload(format!("invalid request path: {error}")))?;
        self.client
            .request(method, url)
            .header("X-BPC-Pair-ID", headers.pair_id)
            .header("X-BPC-Signature", headers.signature)
            .header("X-BPC-Signed-Data", headers.signed_data)
            .header("X-BPC-Version", headers.version)
            .body(body)
            .send()
            .await
            .map_err(|error| BpcError::PairRegistry(format!("HTTP transport failed: {error}")))
    }
}
