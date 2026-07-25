// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Golden-fixture tests freezing the x402 V2 / SVM `exact` wire contract
//! (issue #350). All fixtures are checked in under `fixtures/`; nothing here
//! touches the network.

use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ferrogate_payments::{
    build_payment_signature, parse_payment_required, parse_payment_response, select_requirement,
    PaymentError, RequirementFilter, SolanaNetwork, SvmTransferIntent, SvmTransferSigner,
    CAIP2_SOLANA_DEVNET, CAIP2_SOLANA_MAINNET,
};

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
        .trim_end()
        .to_string()
}

const USDC_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const PAY_TO: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";

/// Each `.header` golden is exactly the base64 of its `.json` twin, so the
/// human-readable and wire forms cannot drift apart.
#[test]
fn header_fixtures_encode_their_json_twins() {
    for name in [
        "payment_required_mainnet",
        "payment_required_devnet",
        "payment_required_sponsored",
        "payment_signature_svm",
        "payment_signature_sponsored",
        "payment_response_success",
        "payment_response_failure",
    ] {
        let json_bytes = fixture(&format!("{name}.json"));
        let decoded = B64
            .decode(fixture(&format!("{name}.header")))
            .unwrap_or_else(|e| panic!("{name}.header is not valid base64: {e}"));
        assert_eq!(
            decoded,
            format!("{json_bytes}\n").into_bytes(),
            "{name}.header does not encode {name}.json"
        );
    }
}

#[test]
fn caip2_network_recognition_is_local_and_exact() {
    assert_eq!(
        SolanaNetwork::from_caip2(CAIP2_SOLANA_MAINNET),
        Some(SolanaNetwork::Mainnet)
    );
    assert_eq!(
        SolanaNetwork::from_caip2(CAIP2_SOLANA_DEVNET),
        Some(SolanaNetwork::Devnet)
    );
    assert_eq!(
        CAIP2_SOLANA_MAINNET,
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    );
    assert_eq!(
        CAIP2_SOLANA_DEVNET,
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    );
    // Near-misses must not be recognised.
    for bogus in [
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp ",
        "solana:mainnet",
        "solana:",
        "eip155:84532",
        "SOLANA:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ] {
        assert_eq!(SolanaNetwork::from_caip2(bogus), None, "{bogus:?}");
    }
}

#[test]
fn golden_payment_required_mainnet_selects_svm_entry() {
    let required = parse_payment_required(&fixture("payment_required_mainnet.header")).unwrap();
    assert_eq!(
        required.resource_url,
        "https://pay.example.com/premium-data"
    );
    assert_eq!(required.accepts.len(), 2, "eip155 + solana entries");

    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();
    assert_eq!(selected.network, SolanaNetwork::Mainnet);
    assert_eq!(selected.mint, USDC_MAINNET);
    assert_eq!(selected.atomic_amount, 1000);
    assert_eq!(selected.recipient, PAY_TO);
    assert_eq!(selected.fee_payer, FEE_PAYER);
    assert_eq!(selected.memo.as_deref(), Some("pi_3abc123def456"));
    assert_eq!(selected.max_timeout_seconds, 60);
    assert_eq!(
        selected.resource_url,
        "https://pay.example.com/premium-data"
    );
}

#[test]
fn golden_payment_required_devnet_selects_devnet_entry() {
    let required = parse_payment_required(&fixture("payment_required_devnet.header")).unwrap();
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();
    assert_eq!(selected.network, SolanaNetwork::Devnet);
    assert_eq!(selected.mint, USDC_DEVNET);
    assert_eq!(selected.atomic_amount, 2500);
    assert_eq!(selected.memo, None);
    assert_eq!(selected.max_timeout_seconds, 120);
}

#[test]
fn challenge_hash_is_deterministic_and_input_sensitive() {
    let required = parse_payment_required(&fixture("payment_required_mainnet.header")).unwrap();
    let a = select_requirement(&required, &RequirementFilter::default()).unwrap();
    let b = select_requirement(&required, &RequirementFilter::default()).unwrap();
    assert_eq!(a.challenge_hash, b.challenge_hash);
    assert_eq!(a.challenge_hash_hex().len(), 64);

    let devnet = parse_payment_required(&fixture("payment_required_devnet.header")).unwrap();
    let c = select_requirement(&devnet, &RequirementFilter::default()).unwrap();
    assert_ne!(a.challenge_hash, c.challenge_hash);
}

/// The challenge hash is persisted by #352 and bound into #353's spend
/// authorization, so its value is part of the frozen contract. Changing the
/// hashed tuple MUST bump `CHALLENGE_HASH_DOMAIN` and this golden.
///
/// The pinned digest below was cross-checked against an independent
/// implementation of the documented rule — SHA-256 over
/// `domain, "exact", caip2, mint, payTo, feePayer, amount, timeout, url`
/// each followed by `0x00`, then `0x01 || memo` (or `0x00` when absent),
/// then a final `0x00` — so it verifies the rule, not just the code.
#[test]
fn challenge_hash_golden_is_pinned() {
    assert_eq!(
        ferrogate_payments::CHALLENGE_HASH_DOMAIN,
        "ferrogate-x402-challenge-v1"
    );
    let required = parse_payment_required(&fixture("payment_required_mainnet.header")).unwrap();
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();
    assert_eq!(
        selected.challenge_hash_hex(),
        "68dfeb509749893767994aa9bb578fa1b8a74eb7882d0507c04fb3e0ec87f777",
        "challenge hash changed; bump CHALLENGE_HASH_DOMAIN if intentional"
    );
}

/// Two challenges that differ only in `extra.memo` (the seller's invoice
/// reference) or `extra.feePayer` (the sponsor that co-signs) are DIFFERENT
/// payments and must not share an idempotency key.
#[test]
fn challenge_hash_separates_memo_and_fee_payer() {
    let base: serde_json::Value = serde_json::from_slice(
        &B64.decode(fixture("payment_required_devnet.header"))
            .unwrap(),
    )
    .unwrap();

    let hash_of = |doc: &serde_json::Value| {
        let header = B64.encode(serde_json::to_vec(doc).unwrap());
        let required = parse_payment_required(&header).unwrap();
        select_requirement(&required, &RequirementFilter::default())
            .unwrap()
            .challenge_hash
    };

    let no_memo = hash_of(&base);

    let mut empty_memo = base.clone();
    empty_memo["accepts"][0]["extra"]["memo"] = serde_json::json!("");
    let mut invoice_a = base.clone();
    invoice_a["accepts"][0]["extra"]["memo"] = serde_json::json!("inv_a");
    let mut invoice_b = base.clone();
    invoice_b["accepts"][0]["extra"]["memo"] = serde_json::json!("inv_b");
    let mut other_sponsor = base.clone();
    other_sponsor["accepts"][0]["extra"]["feePayer"] = serde_json::json!(USDC_MAINNET);

    // An absent memo and an empty memo are distinguishable.
    assert_ne!(no_memo, hash_of(&empty_memo));
    assert_ne!(hash_of(&invoice_a), hash_of(&invoice_b));
    assert_ne!(no_memo, hash_of(&other_sponsor));
}

/// A blockhash refresh between retries of the same logical challenge must NOT
/// change the idempotency key, or #352 would open a second attempt per retry.
#[test]
fn challenge_hash_ignores_transient_blockhash_hints() {
    let base: serde_json::Value = serde_json::from_slice(
        &B64.decode(fixture("payment_required_sponsored.header"))
            .unwrap(),
    )
    .unwrap();

    let hash_of = |doc: &serde_json::Value| {
        let header = B64.encode(serde_json::to_vec(doc).unwrap());
        let required = parse_payment_required(&header).unwrap();
        select_requirement(&required, &RequirementFilter::default())
            .unwrap()
            .challenge_hash
    };

    let mut refreshed = base.clone();
    refreshed["accepts"][0]["extra"]["recentBlockhash"] = serde_json::json!(USDC_MAINNET);
    refreshed["accepts"][0]["extra"]["lastValidBlockHeight"] = serde_json::json!("291470999");
    assert_eq!(hash_of(&base), hash_of(&refreshed));

    let mut no_hints = base.clone();
    let extra = no_hints["accepts"][0]["extra"].as_object_mut().unwrap();
    extra.remove("recentBlockhash");
    extra.remove("lastValidBlockHeight");
    assert_eq!(hash_of(&base), hash_of(&no_hints));
}

/// `extra.recentBlockhash` / `extra.lastValidBlockHeight` are signer input
/// under the SVM `exact` scheme and must reach `SvmTransferIntent` without the
/// signer re-parsing the raw requirement.
#[test]
fn sponsored_challenge_carries_blockhash_hints_into_the_intent() {
    let required = parse_payment_required(&fixture("payment_required_sponsored.header")).unwrap();
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();

    assert_eq!(selected.network, SolanaNetwork::Devnet);
    assert_eq!(selected.atomic_amount, 750);
    assert_eq!(selected.memo.as_deref(), Some("inv_2026_07_0001"));
    assert_eq!(
        selected.recent_blockhash.as_deref(),
        Some("EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k")
    );
    assert_eq!(selected.last_valid_block_height, Some(291_470_237));

    let intent = SvmTransferIntent::from_selected(&selected);
    assert_eq!(intent.recent_blockhash, selected.recent_blockhash);
    assert_eq!(
        intent.last_valid_block_height,
        selected.last_valid_block_height
    );

    // Absent hints stay absent: the signer must then fetch its own blockhash.
    let plain = parse_payment_required(&fixture("payment_required_devnet.header")).unwrap();
    let plain = select_requirement(&plain, &RequirementFilter::default()).unwrap();
    assert_eq!(plain.recent_blockhash, None);
    assert_eq!(plain.last_valid_block_height, None);
}

/// Spec: `lastValidBlockHeight` is "ignored when `recentBlockhash` is absent",
/// so an orphaned (even malformed) height must not fail the payment.
#[test]
fn orphan_last_valid_block_height_is_ignored() {
    let mut doc: serde_json::Value = serde_json::from_slice(
        &B64.decode(fixture("payment_required_sponsored.header"))
            .unwrap(),
    )
    .unwrap();
    let extra = doc["accepts"][0]["extra"].as_object_mut().unwrap();
    extra.remove("recentBlockhash");
    extra.insert(
        "lastValidBlockHeight".to_string(),
        serde_json::json!("not-a-number"),
    );

    let header = B64.encode(serde_json::to_vec(&doc).unwrap());
    let required = parse_payment_required(&header).unwrap();
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();
    assert_eq!(selected.recent_blockhash, None);
    assert_eq!(selected.last_valid_block_height, None);
}

/// x402 V2 §5.1.2: servers advertise `extensions` and clients "must include at
/// least the info received" when echoing them in the `PaymentPayload`.
#[test]
fn server_extensions_are_echoed_into_the_payment_payload() {
    let required = parse_payment_required(&fixture("payment_required_sponsored.header")).unwrap();
    assert!(required.extensions.is_some(), "challenge advertises bazaar");
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();

    let header = build_payment_signature(&selected, &SponsoredSigner).unwrap();
    let built: serde_json::Value = serde_json::from_slice(&B64.decode(header).unwrap()).unwrap();
    let golden: serde_json::Value = serde_json::from_slice(
        &B64.decode(fixture("payment_signature_sponsored.header"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(built, golden);
    assert_eq!(built["extensions"], required.extensions.unwrap());

    // A challenge without extensions must not invent an empty object.
    let plain = parse_payment_required(&fixture("payment_required_devnet.header")).unwrap();
    assert_eq!(plain.extensions, None);
    let plain = select_requirement(&plain, &RequirementFilter::default()).unwrap();
    let plain_header = build_payment_signature(&plain, &SponsoredSigner).unwrap();
    let plain_built: serde_json::Value =
        serde_json::from_slice(&B64.decode(plain_header).unwrap()).unwrap();
    assert!(plain_built.get("extensions").is_none());
}

#[test]
fn selection_honours_network_and_mint_filters() {
    let required = parse_payment_required(&fixture("payment_required_mainnet.header")).unwrap();

    let devnet_only = RequirementFilter {
        networks: &[SolanaNetwork::Devnet],
        allowed_mints: None,
    };
    assert!(matches!(
        select_requirement(&required, &devnet_only),
        Err(PaymentError::NoAcceptableRequirement)
    ));

    let wrong_mint = RequirementFilter {
        networks: &[],
        allowed_mints: Some(&[USDC_DEVNET]),
    };
    assert!(matches!(
        select_requirement(&required, &wrong_mint),
        Err(PaymentError::UnsupportedMint { .. })
    ));

    let exact_match = RequirementFilter {
        networks: &[SolanaNetwork::Mainnet],
        allowed_mints: Some(&[USDC_MAINNET]),
    };
    assert!(select_requirement(&required, &exact_match).is_ok());
}

struct FakeSigner {
    tx: Vec<u8>,
}

impl SvmTransferSigner for FakeSigner {
    fn payer_address(&self) -> String {
        PAY_TO.to_string()
    }
    fn sign_transfer(&self, intent: &SvmTransferIntent) -> Result<Vec<u8>, String> {
        assert_eq!(intent.fee_payer, FEE_PAYER);
        assert_eq!(intent.atomic_amount, 1000);
        Ok(self.tx.clone())
    }
}

/// Signer for the sponsored golden: emits the fixed 128-byte transaction the
/// `payment_signature_sponsored` fixture encodes.
struct SponsoredSigner;

impl SvmTransferSigner for SponsoredSigner {
    fn payer_address(&self) -> String {
        PAY_TO.to_string()
    }
    fn sign_transfer(&self, _intent: &SvmTransferIntent) -> Result<Vec<u8>, String> {
        Ok(vec![9u8; 128])
    }
}

struct RefusingSigner;

impl SvmTransferSigner for RefusingSigner {
    fn payer_address(&self) -> String {
        PAY_TO.to_string()
    }
    fn sign_transfer(&self, _intent: &SvmTransferIntent) -> Result<Vec<u8>, String> {
        Err("user denied payment".to_string())
    }
}

/// Building the proof through the injected signer yields a
/// `PAYMENT-SIGNATURE` header matching the golden `PaymentPayload` shape.
#[test]
fn proof_build_matches_golden_payment_signature_shape() {
    let required = parse_payment_required(&fixture("payment_required_mainnet.header")).unwrap();
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();
    let header = build_payment_signature(&selected, &FakeSigner { tx: vec![7u8; 96] }).unwrap();

    let built: serde_json::Value = serde_json::from_slice(&B64.decode(header).unwrap()).unwrap();
    let golden: serde_json::Value =
        serde_json::from_slice(&B64.decode(fixture("payment_signature_svm.header")).unwrap())
            .unwrap();
    assert_eq!(
        built, golden,
        "built PaymentPayload must equal the golden fixture"
    );
}

#[test]
fn signer_refusal_and_bad_output_map_to_typed_errors() {
    let required = parse_payment_required(&fixture("payment_required_mainnet.header")).unwrap();
    let selected = select_requirement(&required, &RequirementFilter::default()).unwrap();

    assert!(matches!(
        build_payment_signature(&selected, &RefusingSigner),
        Err(PaymentError::SignerRejected { reason }) if reason == "user denied payment"
    ));
    assert!(matches!(
        build_payment_signature(&selected, &FakeSigner { tx: vec![] }),
        Err(PaymentError::ProofBuildFailed { .. })
    ));
    assert!(matches!(
        build_payment_signature(
            &selected,
            &FakeSigner {
                tx: vec![0u8; 2000]
            }
        ),
        Err(PaymentError::ProofBuildFailed { .. })
    ));
}

#[test]
fn golden_settlement_success_decodes() {
    let evidence = parse_payment_response(
        &fixture("payment_response_success.header"),
        SolanaNetwork::Mainnet,
    )
    .unwrap();
    assert!(evidence.success);
    assert_eq!(evidence.network, SolanaNetwork::Mainnet);
    assert_eq!(evidence.settled_amount, Some(1000));
    assert_eq!(evidence.payer.as_deref(), Some(FEE_PAYER));
    let sig = evidence.transaction_signature.expect("signature present");
    assert_eq!(
        ferrogate_payments::base58_decode(&sig).unwrap().len(),
        64,
        "settlement signature decodes to 64 bytes"
    );
}

#[test]
fn golden_settlement_failure_decodes() {
    let evidence = parse_payment_response(
        &fixture("payment_response_failure.header"),
        SolanaNetwork::Mainnet,
    )
    .unwrap();
    assert!(!evidence.success);
    assert_eq!(evidence.transaction_signature, None);
    assert_eq!(evidence.error_reason.as_deref(), Some("insufficient_funds"));
}

#[test]
fn settlement_network_must_match_expected() {
    let err = parse_payment_response(
        &fixture("payment_response_success.header"),
        SolanaNetwork::Devnet,
    )
    .unwrap_err();
    assert!(matches!(err, PaymentError::MalformedSettlement { .. }));
}

/// Signer secret material never leaks through Debug or serde output.
#[test]
fn secret_bytes_redacted_in_debug_and_serde() {
    let secret = ferrogate_payments::SecretBytes::new(vec![0xAB; 32]);
    let debug = format!("{secret:?}");
    assert!(debug.contains("REDACTED"), "debug output: {debug}");
    assert!(
        !debug.to_lowercase().contains("ab, ab"),
        "debug output: {debug}"
    );
    assert!(!debug.contains("171"), "debug output: {debug}");

    let json = serde_json::to_string(&secret).unwrap();
    assert_eq!(json, "\"[REDACTED]\"");
    assert_eq!(secret.len(), 32);
    assert!(!secret.is_empty());
    assert_eq!(secret.expose(), &[0xAB; 32][..]);
}

#[test]
fn base58_decoder_matches_known_vectors() {
    // Leading '1's map to leading zero bytes.
    assert_eq!(
        ferrogate_payments::base58_decode("11111111111111111111111111111111").unwrap(),
        vec![0u8; 32]
    );
    let usdc = ferrogate_payments::base58_decode(USDC_MAINNET).unwrap();
    assert_eq!(usdc.len(), 32);
    // Bitcoin-alphabet excluded characters are rejected outright.
    for bad in ["0", "O", "I", "l", "", "with space"] {
        assert!(ferrogate_payments::base58_decode(bad).is_none(), "{bad:?}");
    }
}

#[cfg(feature = "sdk-solana-pay-kit")]
#[test]
fn sdk_qualification_record_is_frozen() {
    use ferrogate_payments::sdk;
    assert_eq!(sdk::SDK_NAME, "solana-pay-kit");
    assert_eq!(sdk::SDK_VERSION, "0.2.0");
    assert_eq!(sdk::SDK_VERDICT, sdk::SdkVerdict::NotUsableYet);
    assert!(sdk::SDK_EVIDENCE.contains("rustc >= 1.89"));
    assert!(matches!(
        sdk::sdk_unavailable(),
        PaymentError::SdkIncompatible { .. }
    ));
}
