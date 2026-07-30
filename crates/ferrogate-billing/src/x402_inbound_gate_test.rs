// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Unit tests for the composed inbound x402 gate (issue #356): the
// 402 challenge path, forward-once, duplicate retry, replay refusal, the durable
// revenue backstop, and the "never reaches the handler" refusal classes.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use ferrogate_core::TenantContext;
use ferrogate_payments::{CAIP2_SOLANA_DEVNET, CAIP2_SOLANA_MAINNET, HEADER_PAYMENT_RESPONSE};
use serde_json::json;

use super::*;
use crate::x402_inbound::{InMemoryRevenueSink, InboundX402Endpoint, InboundX402SettlementError};
use crate::x402_inbound_admission::{
    SidecarCredential, SidecarTransport, HEADER_SIDECAR_CREDENTIAL, HEADER_SIDECAR_REQUEST_ID,
};
use crate::x402_inbound_forward::InMemoryForwardClaimGuard;

const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER: &str = "So11111111111111111111111111111111111111112";
const PAYER: &str = "GDDMwNyyx8uB6zrqwBFHjLLG3TBYk2F8Az4yrQC5RzMp";
/// Base58 of exactly 64 bytes — `parse_payment_response` rejects anything else
/// on a successful settlement.
const TX_SIG: &str =
    "GAdFhyy8n88RPBg4ogkWqGgUwSz7SxukBbvF4S7aXnQ8s2nSTViag8WmaNrk3cBkCEdHH37ESD4YspnofHFM2Eq";
const CREDENTIAL: &str = "inbound-sidecar-secret-0123456789abcdef";
const FIXED_PRICE: u64 = 10_000;
const TTL: u64 = 600;

fn endpoint() -> ValidatedInboundX402Endpoint {
    InboundX402Endpoint {
        resource_url: "https://api.ferrogate.example/paid/report".to_string(),
        resource_description: Some("Fixed-price report".to_string()),
        resource_mime_type: Some("application/json".to_string()),
        network_caip2: CAIP2_SOLANA_DEVNET.to_string(),
        mint: USDC_DEVNET.to_string(),
        recipient: RECIPIENT.to_string(),
        fee_payer: FEE_PAYER.to_string(),
        price_atomic_amount: FIXED_PRICE,
        max_timeout_seconds: 120,
        memo: None,
        challenge_error: Some("payment required".to_string()),
    }
    .validate()
    .expect("endpoint validates")
}

fn tenant() -> TenantContext {
    TenantContext {
        organization_id: Some("tenant-monetized".to_string()),
        ..TenantContext::default()
    }
}

fn policy() -> SidecarAdmissionPolicy {
    SidecarAdmissionPolicy::new(
        SidecarCredential::new(CREDENTIAL, None).expect("credential is long enough"),
        false,
        Vec::new(),
        tenant(),
    )
    .expect("policy is consistent")
}

struct Harness {
    gate: InboundX402Gate,
    revenue: Arc<InMemoryRevenueSink>,
}

fn harness() -> Harness {
    let revenue = Arc::new(InMemoryRevenueSink::default());
    let claims = Arc::new(InMemoryForwardClaimGuard::new(TTL, 64).expect("valid bounds"));
    let gate = InboundX402Gate::new(
        endpoint(),
        policy(),
        claims,
        Arc::clone(&revenue) as Arc<dyn RevenueSink>,
    );
    Harness { gate, revenue }
}

/// Build a base64 `PAYMENT-RESPONSE` header the frozen wire parser accepts.
fn settlement_header(network: &str, amount: Option<u64>, success: bool) -> String {
    let mut root = json!({
        "success": success,
        "network": network,
        "transaction": TX_SIG,
        "payer": PAYER,
    });
    if let Some(amount) = amount {
        root["amount"] = json!(amount.to_string());
    }
    BASE64_STD.encode(root.to_string().as_bytes())
}

fn paid_header() -> String {
    settlement_header(CAIP2_SOLANA_DEVNET, Some(FIXED_PRICE), true)
}

fn call(request_id: &str) -> InboundCallIdentity {
    InboundCallIdentity {
        request_id: request_id.to_string(),
        trace_id: Some("trace-1".to_string()),
    }
}

fn request<'a>(headers: &'a [(&'a str, &'a str)]) -> ForwardedRequest<'a> {
    ForwardedRequest {
        transport: SidecarTransport::PrivateNetwork,
        method: "POST",
        path: "/v1/priced/report",
        headers,
    }
}

fn paid_headers(sidecar_request_id: &str, settlement: &str) -> Vec<(&'static str, String)> {
    vec![
        (HEADER_SIDECAR_CREDENTIAL, CREDENTIAL.to_string()),
        (HEADER_SIDECAR_REQUEST_ID, sidecar_request_id.to_string()),
        (HEADER_PAYMENT_RESPONSE, settlement.to_string()),
    ]
}

fn borrow<'a>(owned: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    owned
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

// -------------------------------------------------------------------------
// Unpaid call
// -------------------------------------------------------------------------

#[test]
fn an_admitted_call_without_a_payment_proof_gets_the_402_challenge() {
    let harness = harness();
    let owned = vec![
        (HEADER_SIDECAR_CREDENTIAL, CREDENTIAL.to_string()),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-1".to_string()),
    ];
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    match decision {
        InboundX402Decision::PaymentRequired(challenge) => {
            assert_eq!(challenge.http_status, 402);
            assert_eq!(challenge.header_name, "PAYMENT-REQUIRED");
        }
        other => panic!("expected a 402 challenge, got {other:?}"),
    }
    assert!(harness.revenue.is_empty(), "no revenue on an unpaid call");
}

// -------------------------------------------------------------------------
// Bypass and spoofing never reach the handler
// -------------------------------------------------------------------------

#[test]
fn a_direct_upstream_hit_is_refused_before_the_payment_proof_is_read() {
    let harness = harness();
    let owned = paid_headers("sidecar-1", &paid_header());
    let headers = borrow(&owned);
    let decision = harness.gate.evaluate(
        &ForwardedRequest {
            transport: SidecarTransport::Untrusted,
            method: "POST",
            path: "/v1/priced/report",
            headers: &headers,
        },
        &call("req-1"),
        1_000,
    );
    assert!(!decision.forwards());
    assert_eq!(decision.http_status(), Some(403));
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::Admission(
            InboundX402AdmissionError::UntrustedTransport
        ))
    ));
    assert!(harness.revenue.is_empty());
}

#[test]
fn a_spoofed_attribution_header_is_refused_even_on_a_genuinely_paid_call() {
    let harness = harness();
    let mut owned = paid_headers("sidecar-1", &paid_header());
    owned.push(("x-ferrogate-tenant", "victim-tenant".to_string()));
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(!decision.forwards());
    assert!(harness.revenue.is_empty());
}

#[test]
fn a_duplicated_settlement_header_is_ambiguous_rather_than_first_one_wins() {
    let harness = harness();
    let mut owned = paid_headers("sidecar-1", &paid_header());
    owned.push((
        HEADER_PAYMENT_RESPONSE,
        settlement_header(CAIP2_SOLANA_DEVNET, Some(1), true),
    ));
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::Admission(
            InboundX402AdmissionError::AmbiguousHeader { .. }
        ))
    ));
}

// -------------------------------------------------------------------------
// Settlement verification
// -------------------------------------------------------------------------

#[test]
fn a_paid_call_forwards_once_and_records_revenue_at_the_fixed_price() {
    let harness = harness();
    let owned = paid_headers("sidecar-1", &paid_header());
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    let InboundX402Decision::Forward(authorization) = decision else {
        panic!("a correctly settled call must forward");
    };
    assert_eq!(authorization.record.atomic_amount, FIXED_PRICE);
    assert_eq!(authorization.record.request_id, "req-1");
    assert_eq!(authorization.record.payer.as_deref(), Some(PAYER));
    assert_eq!(authorization.admitted.tenant, tenant());
    assert_eq!(harness.revenue.len(), 1);

    // Evidence correlates the paid call without reproducing the proof.
    let evidence = authorization.evidence_fields();
    let names: Vec<&str> = evidence.iter().map(|(name, _)| *name).collect();
    assert!(names.contains(&"request_id"));
    assert!(names.contains(&"trace_id"));
    assert!(names.contains(&"x402_transaction"));
    assert!(names.contains(&"x402_payer"));
    assert!(names.contains(&"sidecar_request_id"));
    for (name, value) in &evidence {
        assert_ne!(value, CREDENTIAL, "credential leaked through {name}");
    }
    assert!(authorization
        .headers_to_strip
        .contains(&HEADER_SIDECAR_CREDENTIAL));
}

#[test]
fn a_wrong_amount_never_records_revenue() {
    let harness = harness();
    let owned = paid_headers(
        "sidecar-1",
        &settlement_header(CAIP2_SOLANA_DEVNET, Some(FIXED_PRICE - 1), true),
    );
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::Settlement(
            InboundX402SettlementError::AmountMismatch { .. }
        ))
    ));
    assert_eq!(decision_status(&decision), 402);
    assert!(harness.revenue.is_empty());
}

#[test]
fn a_wrong_network_is_refused_by_the_wire_parser() {
    let harness = harness();
    let owned = paid_headers(
        "sidecar-1",
        &settlement_header(CAIP2_SOLANA_MAINNET, Some(FIXED_PRICE), true),
    );
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::MalformedSettlement { .. })
    ));
    assert!(harness.revenue.is_empty());
}

#[test]
fn an_unsuccessful_settlement_is_refused() {
    let harness = harness();
    let owned = paid_headers(
        "sidecar-1",
        &settlement_header(CAIP2_SOLANA_DEVNET, Some(FIXED_PRICE), false),
    );
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::Settlement(
            InboundX402SettlementError::SettlementFailed { .. }
        ))
    ));
    assert!(harness.revenue.is_empty());
}

#[test]
fn an_unparseable_settlement_header_is_refused() {
    let harness = harness();
    let owned = paid_headers("sidecar-1", "not-base64-@@@");
    let headers = borrow(&owned);
    let decision = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::MalformedSettlement { .. })
    ));
}

// -------------------------------------------------------------------------
// Forward-once
// -------------------------------------------------------------------------

#[test]
fn the_same_sidecar_request_retrying_is_idempotent_and_does_not_double_record() {
    let harness = harness();
    let owned = paid_headers("sidecar-1", &paid_header());
    let headers = borrow(&owned);
    assert!(harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_000)
        .forwards());
    let retry = harness
        .gate
        .evaluate(&request(&headers), &call("req-1"), 1_030);
    assert!(!retry.forwards());
    assert_eq!(retry.http_status(), Some(409));
    assert!(matches!(
        retry,
        InboundX402Decision::AlreadyForwarded { .. }
    ));
    assert_eq!(harness.revenue.len(), 1, "revenue must be counted once");
}

#[test]
fn a_different_request_replaying_the_proof_is_refused_with_402_not_409() {
    let harness = harness();
    let first = paid_headers("sidecar-1", &paid_header());
    let first_headers = borrow(&first);
    assert!(harness
        .gate
        .evaluate(&request(&first_headers), &call("req-1"), 1_000)
        .forwards());

    let stolen = paid_headers("sidecar-thief", &paid_header());
    let stolen_headers = borrow(&stolen);
    let decision = harness
        .gate
        .evaluate(&request(&stolen_headers), &call("req-2"), 1_001);
    assert!(!decision.forwards());
    assert_eq!(
        decision.http_status(),
        Some(402),
        "a replay is re-challengeable, not permanently forbidden"
    );
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::ProofReplay { .. })
    ));
    assert_eq!(harness.revenue.len(), 1);
}

#[test]
fn the_durable_revenue_record_blocks_a_replay_after_the_claim_is_gone() {
    // A claim guard with a TTL short enough that the claim is gone on the second
    // call — the restart/expiry shape. The revenue record is what still refuses.
    let revenue = Arc::new(InMemoryRevenueSink::default());
    let claims = Arc::new(InMemoryForwardClaimGuard::new(10, 64).expect("valid bounds"));
    let gate = InboundX402Gate::new(
        endpoint(),
        policy(),
        claims,
        Arc::clone(&revenue) as Arc<dyn RevenueSink>,
    );

    let first = paid_headers("sidecar-1", &paid_header());
    let first_headers = borrow(&first);
    assert!(gate
        .evaluate(&request(&first_headers), &call("req-1"), 1_000)
        .forwards());

    let stolen = paid_headers("sidecar-thief", &paid_header());
    let stolen_headers = borrow(&stolen);
    let decision = gate.evaluate(&request(&stolen_headers), &call("req-2"), 5_000);
    assert!(
        !decision.forwards(),
        "an expired claim must not turn a replay into a fresh forward"
    );
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::ProofReplay { .. })
    ));
    assert_eq!(revenue.len(), 1);
}

#[test]
fn the_durable_record_reports_the_original_call_as_already_forwarded() {
    let revenue = Arc::new(InMemoryRevenueSink::default());
    let claims = Arc::new(InMemoryForwardClaimGuard::new(10, 64).expect("valid bounds"));
    let gate = InboundX402Gate::new(
        endpoint(),
        policy(),
        claims,
        Arc::clone(&revenue) as Arc<dyn RevenueSink>,
    );
    let owned = paid_headers("sidecar-1", &paid_header());
    let headers = borrow(&owned);
    assert!(gate
        .evaluate(&request(&headers), &call("req-1"), 1_000)
        .forwards());
    // Same FerroGate request id: the sidecar's own retry, after the claim expired.
    let decision = gate.evaluate(&request(&headers), &call("req-1"), 5_000);
    assert!(matches!(
        decision,
        InboundX402Decision::AlreadyForwarded { .. }
    ));
    assert_eq!(revenue.len(), 1);
}

#[test]
fn a_full_claim_guard_fails_closed_with_503_and_records_nothing() {
    let revenue = Arc::new(InMemoryRevenueSink::default());
    let claims = Arc::new(InMemoryForwardClaimGuard::new(TTL, 1).expect("valid bounds"));
    claims
        .claim("some-other-payment", "sidecar-x", 1_000)
        .expect("fills the single slot");
    let gate = InboundX402Gate::new(
        endpoint(),
        policy(),
        claims,
        Arc::clone(&revenue) as Arc<dyn RevenueSink>,
    );
    let owned = paid_headers("sidecar-1", &paid_header());
    let headers = borrow(&owned);
    let decision = gate.evaluate(&request(&headers), &call("req-1"), 1_000);
    assert!(!decision.forwards());
    assert_eq!(decision.http_status(), Some(503));
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::Unavailable { .. })
    ));
    assert!(revenue.is_empty());
}

#[test]
fn releasing_a_claim_lets_the_payer_retry_with_a_fresh_request_id() {
    let harness = harness();
    let owned = paid_headers("sidecar-1", &paid_header());
    let headers = borrow(&owned);
    let InboundX402Decision::Forward(authorization) =
        harness
            .gate
            .evaluate(&request(&headers), &call("req-1"), 1_000)
    else {
        panic!("first call forwards");
    };
    assert!(harness
        .gate
        .release_claim(&authorization)
        .expect("the holder may release"));

    // The claim is free, but the durable revenue record still refuses the same
    // payment — the stated limitation of releasing after a recorded settlement.
    let retry = paid_headers("sidecar-2", &paid_header());
    let retry_headers = borrow(&retry);
    let decision = harness
        .gate
        .evaluate(&request(&retry_headers), &call("req-2"), 1_005);
    assert!(matches!(
        decision,
        InboundX402Decision::Refused(InboundX402Refusal::ProofReplay { .. })
    ));
}

fn decision_status(decision: &InboundX402Decision) -> u16 {
    decision.http_status().expect("refusals carry a status")
}
