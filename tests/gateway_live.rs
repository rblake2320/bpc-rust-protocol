#![cfg(feature = "gateway")]

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use bpc_protocol::{
    BpcKeyPair, BpcSigningContext, PairAuthority, PairKind, PairMode, PairRegistration,
    PairRequestProtocol, PostgresAuthorityConfig, PostgresPairAuthority, PostgresSecretProtector,
    Scope, derive_request_hmac_key, generate_registration_secret, sign_request, unix_ms,
};

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the live gateway test"))
}

#[test]
fn durable_pair_authorizes_a_signed_request_through_live_gateway() {
    if env::var("BPC_GATEWAY_SMOKE").as_deref() != Ok("1") {
        eprintln!("skipping live gateway process test; set BPC_GATEWAY_SMOKE=1");
        return;
    }
    let data_key = required("BPC_GATEWAY_DATA_KEY_B64");
    let mut config = PostgresAuthorityConfig::new(
        PostgresSecretProtector::from_base64url(required("BPC_GATEWAY_DATA_KEY_ID"), &data_key)
            .expect("valid gateway data key"),
    );
    config.schema = required("BPC_GATEWAY_POSTGRES_SCHEMA");
    config.require_synchronous_replication = false;
    let authority = PostgresPairAuthority::connect(&required("BPC_GATEWAY_POSTGRES_URL"), config)
        .expect("gateway authority connects");
    let audience = required("BPC_GATEWAY_AUDIENCE");
    let key_pair = BpcKeyPair::generate().expect("key generation");
    let secret = generate_registration_secret().expect("secret generation");
    let registration = PairRegistration {
        name: format!("gateway-live-{}", unix_ms().unwrap()),
        scope: Scope::ReadWrite,
        mode: PairMode::Development,
        audience: audience.clone(),
        request_hmac_key: derive_request_hmac_key(&secret).expect("derivation"),
        request_protocol: PairRequestProtocol::V2,
        public_jwk: key_pair.public_jwk().clone(),
        expires_at_ms: None,
        max_requests: Some(2),
        kind: PairKind::Legitimate,
        canary_class: None,
    };
    let token = authority
        .request_pairing(registration, unix_ms().unwrap())
        .expect("enrollment");
    let pair_id = authority
        .approve_pairing(&token, unix_ms().unwrap())
        .expect("approval");
    let body = br#"{"test":"gateway-live"}"#;
    let (_, headers) = sign_request(
        key_pair.signing_key(),
        &pair_id,
        &secret,
        &BpcSigningContext::new(audience, PairMode::Development).expect("context"),
        "POST",
        "/v1/echo",
        body,
    )
    .expect("BPC v2 request signing");

    let mut stream = TcpStream::connect("127.0.0.1:8181").expect("gateway listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "POST /v1/echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-BPC-HMAC: {}\r\nX-BPC-Pair-ID: {}\r\nX-BPC-Signature: {}\r\nX-BPC-Signed-Data: {}\r\nX-BPC-Version: {}\r\n\r\n{}",
        body.len(),
        headers.hmac,
        headers.pair_id,
        headers.signature,
        headers.signed_data,
        headers.version,
        std::str::from_utf8(body).unwrap(),
    );
    stream.write_all(request.as_bytes()).expect("request write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("response read");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "gateway response: {response}"
    );
    assert!(
        response.contains("\"authenticated\":true"),
        "gateway response: {response}"
    );
    assert!(response.contains(&pair_id), "gateway response: {response}");
    assert!(authority.revoke(&pair_id).expect("revoke after test"));
}
