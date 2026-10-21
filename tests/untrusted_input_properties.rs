use std::panic::{AssertUnwindSafe, catch_unwind};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bpc_protocol::{PublicJwk, parse_canonical_payload};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// Signed-data headers are attacker-controlled. Their parser must return a
    /// typed error rather than panic, including for arbitrary non-UTF-8 input.
    #[test]
    fn canonical_payload_parser_never_panics_on_bounded_adversarial_input(
        bytes in proptest::collection::vec(any::<u8>(), 0..5000)
    ) {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let outcome = catch_unwind(AssertUnwindSafe(|| parse_canonical_payload(&encoded)));
        prop_assert!(outcome.is_ok());
    }

    /// Enrollment and rotation accept JWK JSON from an external boundary. Both
    /// serde decoding and elliptic-curve point import must stay fail-closed.
    #[test]
    fn public_jwk_import_never_panics_on_adversarial_json(
        input in proptest::collection::vec(any::<u8>(), 0..5000)
    ) {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(text) = std::str::from_utf8(&input) {
                let _ = serde_json::from_str::<PublicJwk>(text).map(|jwk| jwk.to_verifying_key());
            }
        }));
        prop_assert!(outcome.is_ok());
    }
}
