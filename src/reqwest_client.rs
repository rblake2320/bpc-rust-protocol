//! Reqwest transport for BPC-signed HTTPS requests.
//!
//! The client deliberately owns its `reqwest::Client` so BPC authentication
//! headers can never follow a redirect to a different authority.

use p256::ecdsa::SigningKey;
use reqwest::{Client, Method, Response, Url, redirect::Policy};

use crate::{BpcError, Result, SignedHeaders, sign_request};

/// A BPC client whose caller owns the signing-key lifecycle.
///
/// The transport accepts byte bodies rather than structured JSON to ensure the
/// exact bytes hashed, signed, and transmitted are identical. It rejects
/// scheme-relative, absolute, fragment-bearing, and origin-changing targets;
/// redirects are disabled so authenticated headers cannot be replayed to a
/// different authority.
pub struct BpcHttpClient {
    client: Client,
    base_url: Url,
    pair_id: String,
    registration_secret: String,
    signing_key: SigningKey,
}

impl BpcHttpClient {
    /// Builds a BPC transport with redirects disabled.
    ///
    /// The constructor intentionally does not accept a caller-provided
    /// `reqwest::Client`: its redirect policy is part of the credential-bound
    /// transport security boundary.
    pub fn new(
        base_url: Url,
        pair_id: impl Into<String>,
        registration_secret: impl Into<String>,
        signing_key: SigningKey,
    ) -> Result<Self> {
        validate_base_url(&base_url)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                BpcError::PairRegistry(format!("BPC HTTP client setup failed: {error}"))
            })?;
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

    /// Signs and sends exact body bytes to the configured authority.
    ///
    /// `path_and_query` must be a rooted origin-relative target beginning with
    /// one slash, must not contain a fragment or backslash, and must round-trip
    /// exactly through URL parsing. This avoids signing one target and sending
    /// another.
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
        if !is_rooted_origin_relative_target(path_and_query) {
            return Err(BpcError::InvalidPayload(
                "signed target must be one rooted origin-relative path and query".into(),
            ));
        }
        let url = self.base_url.join(path_and_query).map_err(|error| {
            BpcError::InvalidPayload(format!("invalid BPC request target: {error}"))
        })?;
        if !same_origin(&self.base_url, &url) {
            return Err(BpcError::InvalidPayload(
                "BPC request target changes the configured authority".into(),
            ));
        }
        let actual = path_and_query_from_url(&url);
        if actual != path_and_query {
            return Err(BpcError::InvalidPayload(
                "BPC request target changes during URL parsing".into(),
            ));
        }
        Ok(url)
    }
}

fn validate_base_url(base_url: &Url) -> Result<()> {
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
        || base_url.fragment().is_some()
    {
        return Err(BpcError::InvalidPayload(
            "BPC base URL must be an origin without credentials or fragments".into(),
        ));
    }
    Ok(())
}

fn is_rooted_origin_relative_target(target: &str) -> bool {
    target.starts_with('/')
        && !target.starts_with("//")
        && !target.contains(['\\', '#', '\r', '\n'])
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn path_and_query_from_url(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use super::*;
    use crate::BpcKeyPair;

    fn client(base_url: Url) -> BpcHttpClient {
        let key_pair = BpcKeyPair::generate().unwrap();
        BpcHttpClient::new(
            base_url,
            "pair_test",
            "ExampleSecret9!@",
            key_pair.signing_key().clone(),
        )
        .unwrap()
    }

    #[test]
    fn rejects_authority_changing_scheme_relative_target() {
        let client = client(Url::parse("https://api.trusted.example/v1/").unwrap());
        assert!(client.resolve_target("//attacker.invalid/exfil").is_err());
        assert!(client.resolve_target("/\\attacker.invalid/exfil").is_err());
        assert!(client.resolve_target("/safe#fragment").is_err());
        assert!(client.resolve_target("/safe?value=%0a").is_ok());
    }

    #[tokio::test]
    async fn never_follows_a_redirect_with_bpc_headers() {
        let attack_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        attack_listener.set_nonblocking(true).unwrap();
        let attack_port = attack_listener.local_addr().unwrap().port();
        let (attack_seen_tx, attack_seen_rx) = mpsc::channel();
        let attack_thread = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(400);
            while std::time::Instant::now() < deadline {
                match attack_listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0_u8; 4096];
                        let _ = stream.read(&mut buffer);
                        let _ = attack_seen_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });

        let origin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_thread = thread::spawn(move || {
            let (mut stream, _) = origin_listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{attack_port}/exfil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });

        let client = client(Url::parse(&format!("http://127.0.0.1:{origin_port}/")).unwrap());
        let response = client
            .request(Method::POST, "/protected", b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        drop(response);
        origin_thread.join().unwrap();
        attack_thread.join().unwrap();
        assert!(attack_seen_rx.try_recv().is_err());
    }
}
