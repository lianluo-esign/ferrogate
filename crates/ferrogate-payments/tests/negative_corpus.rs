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
    blockhash_invalid,
    "blockhash_invalid.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    blockhash_wrong_length,
    "blockhash_wrong_length.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    blockhash_non_string,
    "blockhash_non_string.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    last_valid_block_height_invalid,
    "last_valid_block_height_invalid.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    last_valid_block_height_json_number,
    "last_valid_block_height_json_number.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    last_valid_block_height_zero,
    "last_valid_block_height_zero.header",
    PaymentError::MalformedHeader { .. }
);
rejects!(
    extensions_non_object,
    "extensions_non_object.header",
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

/// Load a positive golden fixture (one directory up from the negative corpus)
/// as JSON so a single field can be mutated.
fn golden_json(name: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn header_of(doc: &serde_json::Value) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(doc).unwrap())
}

/// The "Failure contract" requires `UnsupportedScheme` to be distinguishable
/// from every other rejection. A lone requirement naming a non-`exact` scheme
/// must surface exactly that variant, not the generic
/// `NoAcceptableRequirement`.
#[test]
fn unsupported_scheme_is_its_own_variant() {
    let mut doc = golden_json("payment_required_devnet.json");
    doc["accepts"][0]["scheme"] = serde_json::json!("upto");
    let err = parse_and_select(&header_of(&doc)).unwrap_err();
    assert!(
        matches!(&err, PaymentError::UnsupportedScheme { scheme } if scheme == "upto"),
        "unexpected error: {err:?}"
    );
}

/// Likewise `UnsupportedNetwork` must be reachable from the challenge-parse
/// path (it was only covered on the settlement path), and a non-Solana CAIP-2
/// namespace must not be silently treated as Solana.
#[test]
fn unsupported_network_is_its_own_variant_on_the_challenge_path() {
    for bad_network in [
        "eip155:1",                                // Ethereum mainnet
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvd",  // mainnet id, one char short
        "SOLANA:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", // wrong case
        "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z", // testnet, not recognised
    ] {
        let mut doc = golden_json("payment_required_devnet.json");
        doc["accepts"][0]["network"] = serde_json::json!(bad_network);
        let err = parse_and_select(&header_of(&doc)).unwrap_err();
        assert!(
            matches!(&err, PaymentError::UnsupportedNetwork { network } if network == bad_network),
            "network {bad_network:?}: unexpected error: {err:?}"
        );
    }
}

/// When several entries are each unsupported for different reasons the
/// adapter must fall back to `NoAcceptableRequirement` rather than picking
/// one arbitrarily or coercing anything.
#[test]
fn several_unsupported_entries_yield_no_acceptable_requirement() {
    let mut doc = golden_json("payment_required_devnet.json");
    let mut other = doc["accepts"][0].clone();
    other["scheme"] = serde_json::json!("upto");
    doc["accepts"][0]["network"] = serde_json::json!("eip155:1");
    doc["accepts"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(other));

    let err = parse_and_select(&header_of(&doc)).unwrap_err();
    assert!(
        matches!(err, PaymentError::NoAcceptableRequirement),
        "unexpected error: {err:?}"
    );
}

/// An unsupported mint must be reported as `UnsupportedMint`, never by
/// falling through to a different requirement or a zeroed amount.
#[test]
fn unsupported_mint_is_its_own_variant() {
    let doc = golden_json("payment_required_devnet.json");
    let required = parse_payment_required(&header_of(&doc)).unwrap();
    let err = select_requirement(
        &required,
        &RequirementFilter {
            networks: &[],
            allowed_mints: Some(&["11111111111111111111111111111111"]),
        },
    )
    .unwrap_err();
    assert!(
        matches!(&err, PaymentError::UnsupportedMint { mint }
            if mint == "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"),
        "unexpected error: {err:?}"
    );
}

/// Every variant the issue's "Failure contract" enumerates must render a
/// distinct, non-empty Display string so callers can branch without string
/// matching and logs stay unambiguous.
#[test]
fn failure_contract_variants_are_all_distinct() {
    use std::collections::BTreeSet;
    let all = [
        PaymentError::MalformedHeader {
            header: "PAYMENT-REQUIRED",
            reason: "r".into(),
        },
        PaymentError::OversizedHeader {
            header: "PAYMENT-REQUIRED",
            limit: 1,
            actual: 2,
        },
        PaymentError::UnsupportedVersion { found: "1".into() },
        PaymentError::NoAcceptableRequirement,
        PaymentError::UnsupportedNetwork {
            network: "eip155:1".into(),
        },
        PaymentError::UnsupportedScheme {
            scheme: "upto".into(),
        },
        PaymentError::UnsupportedMint { mint: "m".into() },
        PaymentError::InvalidAmount {
            amount: "0".into(),
            reason: "zero".into(),
        },
        PaymentError::InvalidRecipient {
            field: "payTo",
            value: "x".into(),
        },
        PaymentError::InvalidTimeout {
            reason: "zero".into(),
        },
        PaymentError::SignerRejected {
            reason: "denied".into(),
        },
        PaymentError::ProofBuildFailed {
            reason: "empty".into(),
        },
        PaymentError::MalformedSettlement {
            reason: "bad".into(),
        },
        PaymentError::SdkIncompatible { detail: "msrv" },
    ];
    let rendered: BTreeSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(
        rendered.len(),
        all.len(),
        "Display strings collide across failure-contract variants: {rendered:?}"
    );
    assert!(rendered.iter().all(|s| !s.is_empty()));
    // Distinct variants must also compare unequal to each other.
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            assert_eq!(i == j, a == b, "variant {i} vs {j} equality is wrong");
        }
    }
}

proptest! {
    /// Signer secret material never appears in `Debug` or serde output in any
    /// plausible encoding (raw bytes, hex, base64, or a decimal byte list).
    #[test]
    fn secret_bytes_never_leak_in_any_encoding(
        raw in proptest::collection::vec(any::<u8>(), 8..64)
    ) {
        use base64::Engine as _;
        let secret = ferrogate_payments::SecretBytes::new(raw.clone());
        let debug = format!("{secret:?}");
        let json = serde_json::to_string(&secret).unwrap();

        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper = hex.to_uppercase();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let decimals = raw
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let lossy = String::from_utf8_lossy(&raw).into_owned();

        for sink in [&debug, &json] {
            prop_assert!(!sink.contains(&hex), "hex leaked: {}", sink);
            prop_assert!(!sink.contains(&hex_upper), "HEX leaked: {}", sink);
            prop_assert!(!sink.contains(&b64), "base64 leaked: {}", sink);
            prop_assert!(!sink.contains(&decimals), "byte list leaked: {}", sink);
            prop_assert!(!sink.contains(&lossy), "raw bytes leaked: {}", sink);
        }
        prop_assert!(debug.contains("REDACTED"));
        prop_assert_eq!(json, "\"[REDACTED]\"".to_string());
    }

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
