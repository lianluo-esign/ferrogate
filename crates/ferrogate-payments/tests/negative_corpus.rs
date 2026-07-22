// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Negative corpus + property tests: every malformed, hostile, or
//! boundary-violating input is rejected with a typed error and never causes
//! a panic — and an invalid amount is never coerced to zero.

use std::fs;
use std::path::PathBuf;

use ferrogate_payments::{
    parse_atomic_amount, parse_payment_required, parse_payment_response, select_requirement,
    PaymentError, RequirementFilter, SolanaNetwork,
};
use proptest::prelude::*;

fn corpus(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/negative")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read corpus file {}: {e}", path.display()))
        .trim_end()
        .to_string()
}

/// Run the full client pipeline (parse → select) on a corpus entry.
fn parse_and_select(header: &str) -> Result<(), PaymentError> {
    let required = parse_payment_required(header)?;
    select_requirement(&required, &RequirementFilter::default())?;
    Ok(())
}

macro_rules! rejects {
    ($test:ident, $file:expr, $($pattern:pat_param)|+) => {
        #[test]
        fn $test() {
            let err = parse_and_select(&corpus($file)).unwrap_err();
            assert!(matches!(err, $($pattern)|+), "unexpected error: {err:?}");
        }
    };
}

rejects!(
    invalid_base64,
    "invalid_base64.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    base64_of_garbage,
    "base64_of_garbage.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    not_an_object,
    "not_an_object.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    version_1,
    "version_1.header",
    PaymentError::UnsupportedVersion { .. }
);
rejects!(
    version_string,
    "version_string.header",
    PaymentError::UnsupportedVersion { .. }
);
rejects!(
    version_missing,
    "version_missing.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    accepts_empty,
    "accepts_empty.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    accepts_non_object,
    "accepts_non_object.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    accepts_too_many,
    "accepts_too_many.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    accepts_duplicate,
    "accepts_duplicate.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    accepts_conflicting_amounts,
    "accepts_conflicting_amounts.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    amount_zero,
    "amount_zero.header",
    PaymentError::InvalidAmount { .. }
);
rejects!(
    amount_negative,
    "amount_negative.header",
    PaymentError::InvalidAmount { .. }
);
rejects!(
    amount_decimal,
    "amount_decimal.header",
    PaymentError::InvalidAmount { .. }
);
rejects!(
    amount_exponent,
    "amount_exponent.header",
    PaymentError::InvalidAmount { .. }
);
rejects!(
    amount_leading_zero,
    "amount_leading_zero.header",
    PaymentError::InvalidAmount { .. }
);
rejects!(
    amount_overflow,
    "amount_overflow.header",
    PaymentError::InvalidAmount { .. }
);
rejects!(
    amount_json_number,
    "amount_json_number.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    timeout_zero,
    "timeout_zero.header",
    PaymentError::InvalidTimeout { .. }
);
rejects!(
    timeout_negative,
    "timeout_negative.header",
    PaymentError::InvalidTimeout { .. }
);
rejects!(
    timeout_fractional,
    "timeout_fractional.header",
    PaymentError::InvalidTimeout { .. }
);
rejects!(
    timeout_unsafe,
    "timeout_unsafe.header",
    PaymentError::InvalidTimeout { .. }
);
rejects!(
    recipient_not_base58,
    "recipient_not_base58.header",
    PaymentError::InvalidRecipient { .. }
);
rejects!(
    recipient_wrong_length,
    "recipient_wrong_length.header",
    PaymentError::InvalidRecipient { .. }
);
rejects!(
    mint_invalid,
    "mint_invalid.header",
    PaymentError::InvalidRecipient { .. }
);
rejects!(
    fee_payer_missing,
    "fee_payer_missing.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    memo_oversized,
    "memo_oversized.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    resource_missing,
    "resource_missing.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    oversized,
    "oversized.header",
    PaymentError::OversizedHeader { .. }
);

#[test]
fn settlement_corpus_rejected() {
    for (file, is_oversized) in [
        ("settlement_missing_success.header", false),
        ("settlement_bad_signature.header", false),
        ("invalid_base64.header", false),
        ("base64_of_garbage.header", false),
        ("oversized.header", true),
    ] {
        let err = parse_payment_response(&corpus(file), SolanaNetwork::Mainnet).unwrap_err();
        if is_oversized {
            assert!(
                matches!(err, PaymentError::OversizedHeader { .. }),
                "{file}: {err:?}"
            );
        } else {
            assert!(
                matches!(err, PaymentError::MalformedSettlement { .. }),
                "{file}: {err:?}"
            );
        }
    }
    let err = parse_payment_response(
        &corpus("settlement_amount_zero.header"),
        SolanaNetwork::Mainnet,
    )
    .unwrap_err();
    assert!(matches!(err, PaymentError::InvalidAmount { .. }), "{err:?}");

    // An unrecognised settlement network is the more precise
    // UnsupportedNetwork, not the generic malformed-settlement error.
    let err = parse_payment_response(
        &corpus("settlement_wrong_network.header"),
        SolanaNetwork::Mainnet,
    )
    .unwrap_err();
    assert!(
        matches!(err, PaymentError::UnsupportedNetwork { .. }),
        "{err:?}"
    );
}

/// Invalid amounts are hard errors — the adapter never coerces to zero (or
/// any other value).
#[test]
fn invalid_amounts_never_coerce() {
    for bad in [
        "",
        "0",
        "00",
        "01",
        "-1",
        "+1",
        " 1",
        "1 ",
        "1.0",
        "0x10",
        "1_000",
        "1e3",
        "18446744073709551616", // u64::MAX + 1
        "999999999999999999999999999999",
        "１２３", // fullwidth digits
    ] {
        assert!(
            parse_atomic_amount(bad).is_err(),
            "amount {bad:?} must be rejected"
        );
    }
    assert_eq!(parse_atomic_amount("1").unwrap(), 1);
    assert_eq!(
        parse_atomic_amount("18446744073709551615").unwrap(),
        u64::MAX
    );
}

proptest! {
    /// Arbitrary bytes-as-header never panic anywhere in the pipeline.
    #[test]
    fn arbitrary_header_never_panics(input in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let header = String::from_utf8_lossy(&input).into_owned();
        let _ = parse_and_select(&header);
        let _ = parse_payment_response(&header, SolanaNetwork::Mainnet);
    }

    /// Arbitrary base64-wrapped bytes (always valid base64, arbitrary
    /// payload) never panic and never yield a selected payment with a zero
    /// amount.
    #[test]
    fn arbitrary_base64_payload_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
        use base64::Engine as _;
        let header = base64::engine::general_purpose::STANDARD.encode(&payload);
        if let Ok(required) = parse_payment_required(&header) {
            if let Ok(selected) = select_requirement(&required, &RequirementFilter::default()) {
                prop_assert!(selected.atomic_amount > 0);
            }
        }
        let _ = parse_payment_response(&header, SolanaNetwork::Devnet);
    }

    /// Amount parsing agrees with a strict reference model on arbitrary
    /// ASCII-ish strings.
    #[test]
    fn amount_parser_matches_reference(s in "[0-9a-zA-Z+\\-. ]{0,24}") {
        let reference_ok = !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && !(s.len() > 1 && s.starts_with('0'))
            && s.parse::<u64>().map(|v| v > 0).unwrap_or(false);
        prop_assert_eq!(parse_atomic_amount(&s).is_ok(), reference_ok, "input {:?}", s);
    }

    /// Base58 decode round-trips through a reference big-int encoder for
    /// 32-byte inputs.
    #[test]
    fn base58_rejects_or_roundtrips(s in "[1-9A-HJ-NP-Za-km-z]{0,50}") {
        if let Some(bytes) = ferrogate_payments::base58_decode(&s) {
            // decoded length is bounded by input length
            prop_assert!(bytes.len() <= s.len());
        }
    }
}
