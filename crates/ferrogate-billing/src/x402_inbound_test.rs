// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit + property tests for the inbound fixed-price x402
// monetization model (issue #356): 402-challenge construction round-tripping the
// frozen #350 wire parser, settlement->revenue coupling at the fixed price, and
// fail-closed behavior on any mismatch. Sibling test file per AGENTS.md testing
// architecture (no inline `mod tests {}`).

use super::*;
use ferrogate_core::TenantContext;
use ferrogate_payments::{
    parse_payment_required, select_requirement, RequirementFilter, SettlementEvidence,
    SolanaNetwork, CAIP2_SOLANA_DEVNET, CAIP2_SOLANA_MAINNET,
};
use proptest::prelude::*;

// Canonical, wire-validated base58 addresses (shared with the #350/#351 suites).
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER: &str = "So11111111111111111111111111111111111111112";
const PAYER: &str = "GDDMwNyyx8uB6zrqwBFHjLLG3TBYk2F8Az4yrQC5RzMp";
// Any non-empty string; the wire parser already validated the signature shape
// upstream, so the billing layer only records what it is handed.
const TX_SIG: &str =
    "5wHu1qwD4kBv2u2Q6yYyQ2v4hZ8fW9r1sT3cX7kP2mN8jL4dR6gH9bK1aE3sV5oU7yT9wQ2xN4mP6rB8cD1fG3";

const RESOURCE_URL: &str = "https://api.ferrogate.example/paid/report";
const FIXED_PRICE: u64 = 10_000; // 0.01 USDC at 6 decimals.

fn endpoint() -> InboundX402Endpoint {
    InboundX402Endpoint {
        resource_url: RESOURCE_URL.to_string(),
        resource_description: Some("Fixed-price report".to_string()),
        resource_mime_type: Some("application/json".to_string()),
        network_caip2: CAIP2_SOLANA_DEVNET.to_string(),
        mint: USDC_DEVNET.to_string(),
        recipient: RECIPIENT.to_string(),
        fee_payer: FEE_PAYER.to_string(),
        price_atomic_amount: FIXED_PRICE,
        max_timeout_seconds: 120,
        memo: Some("ferrogate-paid-report".to_string()),
        challenge_error: Some("payment required".to_string()),
        allowed_methods: Vec::new(),
    }
}

fn validated() -> ValidatedInboundX402Endpoint {
    endpoint().validate().expect("endpoint must validate")
}

fn call_ctx() -> InboundX402CallContext {
    InboundX402CallContext {
        request_id: "req-1".to_string(),
        sidecar_request_id: "sidecar-1".to_string(),
        trace_id: Some("trace-1".to_string()),
        method: "GET".to_string(),
        tenant: TenantContext {
            organization_id: Some("org-merchant".to_string()),
            api_key_id: Some("key-public".to_string()),
            ..TenantContext::default()
        },
        occurred_at_unix: Some(1_900_000_000),
    }
}

fn settled_evidence(network: SolanaNetwork, settled_amount: Option<u64>) -> SettlementEvidence {
    SettlementEvidence {
        success: true,
        transaction_signature: Some(TX_SIG.to_string()),
        network,
        payer: Some(PAYER.to_string()),
        error_reason: None,
        settled_amount,
    }
}

// ---------------------------------------------------------------------------
// 402 challenge construction (unpaid call)
// ---------------------------------------------------------------------------

#[test]
fn unpaid_call_challenge_carries_status_402_and_the_payment_required_header() {
    let challenge = validated().challenge();
    assert_eq!(challenge.http_status, PAYMENT_REQUIRED_STATUS);
    assert_eq!(challenge.http_status, 402);
    assert_eq!(challenge.header_name, "PAYMENT-REQUIRED");
    assert!(!challenge.header_value.is_empty());
}

#[test]
fn constructed_challenge_round_trips_through_the_wire_parser_to_the_fixed_price() {
    let ep = validated();
    let header = ep.build_payment_required();

    // The merchant-built challenge must parse and select on the exact #350 path
    // an x402 client uses.
    let required = parse_payment_required(&header).expect("challenge must parse");
    assert_eq!(required.resource_url, RESOURCE_URL);
    let filter = RequirementFilter {
        networks: &[SolanaNetwork::Devnet],
        allowed_mints: None,
    };
    let selected = select_requirement(&required, &filter).expect("requirement must select");

    assert_eq!(selected.network, SolanaNetwork::Devnet);
    assert_eq!(selected.mint, USDC_DEVNET);
    assert_eq!(selected.recipient, RECIPIENT);
    assert_eq!(selected.fee_payer, FEE_PAYER);
    assert_eq!(selected.memo.as_deref(), Some("ferrogate-paid-report"));
    assert_eq!(selected.resource_url, RESOURCE_URL);
    assert_eq!(selected.max_timeout_seconds, 120);
    // The core fixed-price invariant on the challenge side.
    assert_eq!(selected.atomic_amount, FIXED_PRICE);

    // expected_payment() is the same canonical view.
    let expected = ep.expected_payment().expect("expected payment");
    assert_eq!(expected.atomic_amount, FIXED_PRICE);
    assert_eq!(expected.challenge_hash, selected.challenge_hash);
}

// ---------------------------------------------------------------------------
// Paid call -> settlement/revenue coupling
// ---------------------------------------------------------------------------

#[test]
fn a_paid_call_couples_to_a_revenue_record_at_the_fixed_price() {
    let ep = validated();
    let evidence = settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE));
    let record = settle_inbound_payment(&ep, &call_ctx(), &evidence).expect("must settle");

    assert_eq!(record.revenue_source, RevenueSource::X402Inbound);
    assert_eq!(record.revenue_source.as_str(), "x402_inbound");
    assert_eq!(record.atomic_amount, FIXED_PRICE);
    assert_eq!(record.resource_url, RESOURCE_URL);
    assert_eq!(record.network_caip2, CAIP2_SOLANA_DEVNET);
    assert_eq!(record.mint, USDC_DEVNET);
    assert_eq!(record.recipient, RECIPIENT);
    assert_eq!(record.transaction_signature, TX_SIG);
    assert_eq!(record.payer.as_deref(), Some(PAYER));
    assert_eq!(record.request_id, "req-1");
    assert_eq!(
        record.tenant.organization_id.as_deref(),
        Some("org-merchant")
    );

    // The record couples to the challenge that was quoted.
    let expected = ep.expected_payment().unwrap();
    assert_eq!(record.challenge_hash_hex, expected.challenge_hash_hex());
    assert_eq!(
        record.id,
        format!("x402-inbound:{}:{TX_SIG}", expected.challenge_hash_hex())
    );
}

#[test]
fn payer_wallet_is_recorded_as_evidence_but_never_as_the_tenant() {
    let record = settle_inbound_payment(
        &validated(),
        &call_ctx(),
        &settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE)),
    )
    .unwrap();
    // Payer identity must not leak into the FerroGate tenant identity.
    assert_eq!(record.payer.as_deref(), Some(PAYER));
    assert_ne!(record.tenant.organization_id.as_deref(), Some(PAYER));
    assert_ne!(record.tenant.api_key_id.as_deref(), Some(PAYER));
}

// ---------------------------------------------------------------------------
// Fail-closed on mismatch
// ---------------------------------------------------------------------------

#[test]
fn underpayment_fails_closed_with_amount_mismatch() {
    let evidence = settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE - 1));
    let err = settle_inbound_payment(&validated(), &call_ctx(), &evidence).unwrap_err();
    assert_eq!(
        err,
        InboundX402SettlementError::AmountMismatch {
            expected: FIXED_PRICE,
            actual: FIXED_PRICE - 1,
        }
    );
}

#[test]
fn overpayment_also_fails_closed_with_amount_mismatch() {
    let evidence = settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE + 1));
    let err = settle_inbound_payment(&validated(), &call_ctx(), &evidence).unwrap_err();
    assert!(matches!(
        err,
        InboundX402SettlementError::AmountMismatch { .. }
    ));
}

#[test]
fn wrong_network_fails_closed() {
    let evidence = settled_evidence(SolanaNetwork::Mainnet, Some(FIXED_PRICE));
    let err = settle_inbound_payment(&validated(), &call_ctx(), &evidence).unwrap_err();
    assert_eq!(
        err,
        InboundX402SettlementError::NetworkMismatch {
            expected: CAIP2_SOLANA_DEVNET.to_string(),
            actual: CAIP2_SOLANA_MAINNET.to_string(),
        }
    );
}

#[test]
fn unsuccessful_settlement_fails_closed() {
    let mut evidence = settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE));
    evidence.success = false;
    evidence.error_reason = Some("insufficient funds".to_string());
    evidence.transaction_signature = None;
    let err = settle_inbound_payment(&validated(), &call_ctx(), &evidence).unwrap_err();
    assert_eq!(
        err,
        InboundX402SettlementError::SettlementFailed {
            reason: Some("insufficient funds".to_string()),
        }
    );
}

#[test]
fn missing_transaction_signature_fails_closed() {
    let mut evidence = settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE));
    evidence.transaction_signature = None;
    let err = settle_inbound_payment(&validated(), &call_ctx(), &evidence).unwrap_err();
    assert_eq!(err, InboundX402SettlementError::MissingTransactionSignature);
}

#[test]
fn missing_settled_amount_fails_closed() {
    let evidence = settled_evidence(SolanaNetwork::Devnet, None);
    let err = settle_inbound_payment(&validated(), &call_ctx(), &evidence).unwrap_err();
    assert_eq!(err, InboundX402SettlementError::MissingSettledAmount);
}

// ---------------------------------------------------------------------------
// Config validation (fail closed before any challenge/settlement)
// ---------------------------------------------------------------------------

#[test]
fn zero_price_is_rejected() {
    let mut ep = endpoint();
    ep.price_atomic_amount = 0;
    assert_eq!(
        ep.validate().unwrap_err(),
        InboundX402ConfigError::ZeroPrice
    );
}

#[test]
fn a_token_symbol_mint_is_rejected() {
    let mut ep = endpoint();
    ep.mint = "USDC".to_string();
    assert!(matches!(
        ep.validate().unwrap_err(),
        InboundX402ConfigError::InvalidAddress { field: "mint", .. }
    ));
}

#[test]
fn an_unrecognised_network_is_rejected() {
    let mut ep = endpoint();
    ep.network_caip2 = "solana:not-a-real-network".to_string();
    assert!(matches!(
        ep.validate().unwrap_err(),
        InboundX402ConfigError::UnsupportedNetwork { .. }
    ));
}

#[test]
fn an_unsafe_timeout_is_rejected() {
    let mut ep = endpoint();
    ep.max_timeout_seconds = 0;
    assert!(matches!(
        ep.validate().unwrap_err(),
        InboundX402ConfigError::InvalidTimeout { .. }
    ));
    let mut ep = endpoint();
    ep.max_timeout_seconds = u64::MAX;
    assert!(matches!(
        ep.validate().unwrap_err(),
        InboundX402ConfigError::InvalidTimeout { .. }
    ));
}

#[test]
fn an_oversized_memo_is_rejected() {
    let mut ep = endpoint();
    ep.memo = Some("m".repeat(257));
    assert!(matches!(
        ep.validate().unwrap_err(),
        InboundX402ConfigError::MemoTooLong { len: 257 }
    ));
}

// ---------------------------------------------------------------------------
// Revenue sink: idempotency + separation from the token-usage ledger
// ---------------------------------------------------------------------------

#[test]
fn duplicate_forward_of_the_same_paid_call_is_idempotent() {
    let ep = validated();
    let record = settle_inbound_payment(
        &ep,
        &call_ctx(),
        &settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE)),
    )
    .unwrap();

    let sink = InMemoryRevenueSink::default();
    assert!(sink.record(&record).unwrap()); // newly recorded
    assert!(!sink.record(&record).unwrap()); // idempotent replay, no double-count

    assert_eq!(sink.len(), 1);
    assert_eq!(sink.recorded_total(), 1);
    let totals = sink.totals();
    assert_eq!(totals.records, 1);
    assert_eq!(totals.total_atomic_amount, u128::from(FIXED_PRICE));
    assert_eq!(sink.get(&record.id).unwrap(), Some(record));
}

#[test]
fn a_conflicting_replay_under_the_same_id_fails_closed() {
    let ep = validated();
    let record = settle_inbound_payment(
        &ep,
        &call_ctx(),
        &settled_evidence(SolanaNetwork::Devnet, Some(FIXED_PRICE)),
    )
    .unwrap();

    let sink = InMemoryRevenueSink::default();
    assert!(sink.record(&record).unwrap());

    // Same idempotency id, tampered settlement data.
    let mut tampered = record.clone();
    tampered.payer = Some("attacker-wallet".to_string());
    let err = sink.record(&tampered).unwrap_err();
    assert_eq!(err.code, "billing_revenue_idempotency_conflict");
    assert_eq!(sink.len(), 1);
}

// ---------------------------------------------------------------------------
// Property tests: invariants over generated inputs
// ---------------------------------------------------------------------------

fn endpoint_with_price(price: u64) -> ValidatedInboundX402Endpoint {
    let mut ep = endpoint();
    ep.price_atomic_amount = price;
    ep.validate().expect("valid endpoint")
}

proptest! {
    /// The 402 challenge always round-trips to the exact fixed price, for any
    /// non-zero price across the whole u64 range.
    #[test]
    fn challenge_round_trips_to_the_fixed_price(price in 1u64..=u64::MAX) {
        let ep = endpoint_with_price(price);
        let selected = ep.expected_payment().expect("must select");
        prop_assert_eq!(selected.atomic_amount, price);
    }

    /// A settlement at the fixed price ALWAYS produces a record whose recorded
    /// atomic amount equals that fixed price -- the charged amount is never the
    /// caller-asserted number, always the endpoint's price.
    #[test]
    fn charged_amount_always_equals_the_fixed_price(price in 1u64..=u64::MAX) {
        let ep = endpoint_with_price(price);
        let evidence = settled_evidence(SolanaNetwork::Devnet, Some(price));
        let record = settle_inbound_payment(&ep, &call_ctx(), &evidence)
            .expect("settles at fixed price");
        prop_assert_eq!(record.atomic_amount, price);
    }

    /// Any settled amount other than the fixed price fails closed, never
    /// producing a revenue record.
    #[test]
    fn any_amount_other_than_the_fixed_price_fails_closed(
        price in 1u64..=1_000_000_000u64,
        settled in 0u64..=2_000_000_000u64,
    ) {
        prop_assume!(settled != price);
        let ep = endpoint_with_price(price);
        let evidence = settled_evidence(SolanaNetwork::Devnet, Some(settled));
        let result = settle_inbound_payment(&ep, &call_ctx(), &evidence);
        let is_amount_mismatch =
            matches!(result, Err(InboundX402SettlementError::AmountMismatch { .. }));
        prop_assert!(is_amount_mismatch);
    }
}
