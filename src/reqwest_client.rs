//! Reqwest transport for BPC-signed HTTPS requests.

use p256::ecdsa::SigningKey;
use reqwest::redirect::Policy;
use reqwest::{Client, Method, Response, Url};

use crate::{BpcError, Result, SignedHeaders, sign_request};

/// A BPC client whose caller owns the signing-key lifecycle.
///
/// The transport accepts byte bodies rather than structured JSON to ensure the
/// exact bytes hashed, signed, and transmitted are identical. It pins requests
/// to one origin and disables redirects because BPC v1 headers are request
/// credentials, not ordinary metadata safe to forward.
pub struct BpcHttpClient {
    client: Client,
    base_url: Url,
    pair_id: String,
    registration_secret: String,
    signing_key: SigningKey,
}

impl BpcHttpClient {
    /// Creates a transport pinned to one HTTPS origin.
    ///
    /// A localhost origin is accepted only to support isolated development and
    /// integration testing. The internally constructed transport never follows
    /// redirects, preventing signed headers from being sent to a different
    /// authority or a request target different from the signed target.
    pub fn new(
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
        if base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
        {
            return Err(BpcError::InvalidPayload(
                "BPC HTTP client base URL must be an origin without credentials, path, query, or fragment".into(),
            ));
        }
        let pair_id = pair_id.into();
        if !crate::is_valid_pair_id(&pair_id) {
            return Err(BpcError::InvalidPayload("invalid BPC pair ID".into()));
        }
        let registration_secret = registration_secret.into();
        crate::validate_secret(&registration_secret)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                BpcError::PairRegistry(format!("HTTP client setup failed: {error}"))
            })?;
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
        self.resolve_target(path_and_query)?;
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

    /// Signs and sends exact body bytes. The returned response may be a redirect
    /// response; this transport deliberately does not follow it.
    pub async fn request(
        &self,
        method: Method,
        path_and_query: &str,
        body: impl Into<Vec<u8>>,
    ) -> Result<Response> {
        let url = self.resolve_target(path_and_query)?;
        let body = body.into();
        let headers = self.signed_headers(method.as_str(), path_and_query, &body)?;
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

    fn resolve_target(&self, path_and_query: &str) -> Result<Url> {
        if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
            return Err(BpcError::InvalidPayload(
                "signed path must begin with one '/' and include any query string".into(),
            ));
        }
        if path_and_query.contains(['\\', '#']) || contains_dot_segment(path_and_query) {
            return Err(BpcError::InvalidPayload(
                "signed path contains an unsafe normalization form".into(),
            ));
        }
        let url = self
            .base_url
            .join(path_and_query)
            .map_err(|error| BpcError::InvalidPayload(format!("invalid request path: {error}")))?;
        if !same_origin(&self.base_url, &url) || exact_path_and_query(&url) != path_and_query {
            return Err(BpcError::InvalidPayload(
                "signed path would not be transmitted exactly to the configured origin".into(),
            ));
        }
        Ok(url)
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn exact_path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

fn contains_dot_segment(path_and_query: &str) -> bool {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    path.split('/').any(|segment| {
        let segment = segment.to_ascii_lowercase();
        segment == "." || segment == ".." || segment.contains("%2e")
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use reqwest::Url;

    use super::BpcHttpClient;
    use crate::BpcError;

    fn client() -> BpcHttpClient {
        BpcHttpClient::new(
            Url::parse("https://api.example.test/").unwrap(),
            "pair_client",
            "ClientProtocolSecret9!@#",
            SigningKey::random(&mut rand_core::OsRng),
        )
        .unwrap()
    }

    #[test]
    fn rejects_authority_and_normalization_confusion_before_signing() {
        let client = client();
        for target in [
            "//attacker.example/collect",
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/widgets#fragment",
            "/v1\\widgets",
            "/v1/a path",
        ] {
            assert!(
                client.signed_headers("POST", target, b"{}").is_err(),
                "{target}"
            );
        }
        assert!(
            client
                .signed_headers("POST", "/v1/widgets?encoded=%2F", b"{}")
                .is_ok()
        );
    }

    #[test]
    fn rejects_weak_registration_secret_before_any_request_can_be_signed() {
        let result = BpcHttpClient::new(
            Url::parse("https://api.example.test/").unwrap(),
            "pair_client",
            "weak",
            SigningKey::random(&mut rand_core::OsRng),
        );
        assert!(matches!(result, Err(BpcError::SecretPolicy(_))));
    }
}
