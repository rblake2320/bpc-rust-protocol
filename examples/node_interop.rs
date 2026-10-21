use bpc_protocol::{BpcKeyPair, BpcSigningContext, PairMode, sign_request_at};
use serde_json::json;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = BpcKeyPair::generate()?;
    let secret = "RustInteropSecret9!@";
    let body = br#"{"origin":"rust","verified":"node"}"#;
    let (payload, headers) = sign_request_at(
        keypair.signing_key(),
        "pair_rustinterop",
        secret,
        &BpcSigningContext::new("bpc://api.example.test/production", PairMode::Production)?,
        "PUT",
        "/v1/interop?peer=node",
        body,
        Uuid::parse_str("9f1c62dc-6c58-4c88-a5a2-f47f9b5c7001")?,
        1_740_000_000_001,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "secret": secret,
            "public_jwk": keypair.public_jwk(),
            "payload": payload,
            "headers": headers,
            "body_base64url": bpc_protocol::b64url_encode(body),
        }))?
    );
    Ok(())
}
