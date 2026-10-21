#![no_main]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bpc_protocol::{PublicJwk, parse_canonical_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // BPC receives base64url text in the signed-data header. Limit the fuzzer's
    // constructed header to BPC's own parser admission size.
    let encoded = URL_SAFE_NO_PAD.encode(&data[..data.len().min(4096)]);
    let _ = parse_canonical_payload(&encoded);

    // The public JWK originates at enrollment/rotation boundaries. Arbitrary
    // JSON must be rejected or accepted without panic, invalid point use, or
    // unbounded parsing behavior.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<PublicJwk>(text).map(|jwk| jwk.to_verifying_key());
    }
});
