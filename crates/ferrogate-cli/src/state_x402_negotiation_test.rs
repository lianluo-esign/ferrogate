// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Focused async tests for the x402 402-negotiation + single paid
// replay (issue #381). Proves the full path with a fake upstream and a fake
// signer (no live network): 402 -> policy Allow -> settle -> ONE paid replay
// records the attempt + settlement; 402 -> policy Deny -> no payment, no signer,
// typed failure; a second 402 after paying is a typed failure that never loops
// and parks outcome_unknown (hold retained); a 2xx paid replay with ambiguous
// settlement evidence parks outcome_unknown; insufficient funds never reaches
// the signer; signer refusal releases the pre-submission hold.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use ferrogate_payments::{SvmTransferIntent, CAIP2_SOLANA_DEVNET};
use ferrogate_policy::{
    ApprovalPolicy, ConversionRule, PolicyNetwork, ResourceRule, Rounding, SpendSnapshot,
    ValidatedX402SpendPolicy, X402SpendCaps, X402SpendPolicy,
};
use ferrogate_storage::{
    StoredWallet, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN, PAYMENT_ATTEMPT_RELEASED,
    PAYMENT_ATTEMPT_SETTLED, WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_RELEASED,
    WALLET_RESERVATION_SETTLED,
};
use serde_json::json;

use super::super::AppState;
use super::*;
use crate::config::Config;

const TENANT: &str = "tenant-x402-neg";
const RESOURCE_URL: &str = "https://api.example.com/paid";

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

// --------------------------------------------------------------------------
// base58 encoder (test-local): builds valid 32-byte addresses and 64-byte
// signatures the frozen wire contract will accept, with no external dep.
// --------------------------------------------------------------------------

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(BASE58_ALPHABET[d as usize] as char);
    }
    if out.is_empty() {
        out.push('1');
    }
    out
}

/// A distinct valid 32-byte base58 address seeded by `seed` (never all-zero).
fn addr(seed: u8) -> String {
    let mut bytes = [0u8; 32];
    bytes[0] = seed.max(1);
    bytes[31] = seed.wrapping_add(1).max(1);
    base58_encode(&bytes)
}

/// A valid 64-byte base58 transaction signature.
fn signature() -> String {
    base58_encode(&[7u8; 64])
}

fn mint() -> String {
    addr(11)
}
fn recipient() -> String {
    addr(22)
}
fn fee_payer() -> String {
    addr(33)
}

// --------------------------------------------------------------------------
// x402 wire artifacts
// --------------------------------------------------------------------------

fn payment_required_header() -> String {
    let object = json!({
        "x402Version": 2,
        "resource": { "url": RESOURCE_URL },
        "accepts": [{
            "scheme": "exact",
            "network": CAIP2_SOLANA_DEVNET,
            "asset": mint(),
            "amount": "1000",
            "payTo": recipient(),
            "maxTimeoutSeconds": 600,
            "extra": { "feePayer": fee_payer() }
        }]
    });
    BASE64_STD.encode(serde_json::to_vec(&object).expect("serialize challenge"))
}

fn settled_payment_response() -> String {
    let object = json!({
        "success": true,
        "network": CAIP2_SOLANA_DEVNET,
        "transaction": signature(),
        "amount": "1000",
    });
    BASE64_STD.encode(serde_json::to_vec(&object).expect("serialize settlement"))
}

fn payment_required_response() -> EgressResponse {
    EgressResponse {
        status: 402,
        payment_required: Some(payment_required_header()),
        payment_response: None,
    }
}

fn success_response(payment_response: Option<String>) -> EgressResponse {
    EgressResponse {
        status: 200,
        payment_required: None,
        payment_response,
    }
}

// --------------------------------------------------------------------------
// Fakes: transport (upstream) + signer
// --------------------------------------------------------------------------

struct FakeTransport {
    responses: Mutex<VecDeque<EgressResponse>>,
    signed_calls: Mutex<Vec<bool>>,
}

impl FakeTransport {
    fn new(responses: Vec<EgressResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            signed_calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<bool> {
        self.signed_calls.lock().unwrap().clone()
    }
}

impl PaidEgressTransport for FakeTransport {
    async fn dispatch(
        &self,
        payment_signature: Option<&str>,
    ) -> Result<EgressResponse, X402TransportError> {
        self.signed_calls
            .lock()
            .unwrap()
            .push(payment_signature.is_some());
        match self.responses.lock().unwrap().pop_front() {
            Some(response) => Ok(response),
            None => Err(X402TransportError::new("fake transport exhausted")),
        }
    }
}

struct FakeSigner {
    calls: AtomicUsize,
    reject: bool,
}

impl FakeSigner {
    fn allowing() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reject: false,
        }
    }

    fn rejecting() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reject: true,
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SvmTransferSigner for FakeSigner {
    fn payer_address(&self) -> String {
        addr(99)
    }

    fn sign_transfer(&self, _intent: &SvmTransferIntent) -> Result<Vec<u8>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject {
            Err("signer locked".to_string())
        } else {
            Ok(vec![7u8; 128])
        }
    }
}

// --------------------------------------------------------------------------
// Policy + state fixtures
// --------------------------------------------------------------------------

fn allowing_policy() -> ValidatedX402SpendPolicy {
    X402SpendPolicy {
        enabled: true,
        revision: 7,
        allowed_networks: vec![PolicyNetwork::DEVNET],
        allowed_assets: vec![ferrogate_policy::AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: mint(),
        }],
        allowed_recipients: vec![recipient()],
        allowed_resources: vec![ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/".to_string(),
        }],
        caps: X402SpendCaps::default(),
        conversion: ConversionRule {
            numerator: 1,
            denominator: 1,
            rounding: Rounding::Up,
            version: "conv-v1".to_string(),
        },
        approval: ApprovalPolicy::default(),
        allow_insecure_local_resources: false,
    }
    .validate()
    .expect("valid policy")
}

fn approval_policy() -> ValidatedX402SpendPolicy {
    X402SpendPolicy {
        enabled: true,
        revision: 8,
        allowed_networks: vec![PolicyNetwork::DEVNET],
        allowed_assets: vec![ferrogate_policy::AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: mint(),
        }],
        allowed_recipients: vec![recipient()],
        allowed_resources: vec![ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/".to_string(),
        }],
        caps: X402SpendCaps::default(),
        conversion: ConversionRule {
            numerator: 1,
            denominator: 1,
            rounding: Rounding::Up,
            version: "conv-v1".to_string(),
        },
        approval: ApprovalPolicy {
            threshold_credits: Some(10),
        },
        allow_insecure_local_resources: false,
    }
    .validate()
    .expect("valid approval policy")
}

fn seed_state(balance_credits: i64) -> AppState {
    let state = AppState::new(Config::default());
    block_on(state.upsert_wallet(StoredWallet {
        id: TENANT.into(),
        tenant_id: TENANT.into(),
        balance_credits,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .expect("seed wallet");
    state
}

fn context() -> X402NegotiationContext<'static> {
    X402NegotiationContext {
        tenant_id: TENANT,
        project_id: Some("project-1"),
        workspace_id: None,
        run_id: Some("run-1"),
        worker_id: Some("worker-1"),
        key_id: None,
        request_id: Some("req-1"),
        trace_id: Some("trace-1"),
        method: "POST",
        authorized_resource_url: RESOURCE_URL,
        request_body_hash: Some("body-hash-1"),
        hold_ttl_secs: 3_600,
        idempotency_key: "req-1",
    }
}

async fn reservation_status(state: &AppState, attempt_id: &str) -> Option<String> {
    state
        .repositories_arc()
        .list_wallet_reservations(TENANT)
        .await
        .expect("list reservations")
        .into_iter()
        .find(|r| r.id == attempt_id)
        .map(|r| r.status)
}

async fn attempt(state: &AppState, attempt_id: &str) -> ferrogate_storage::StoredPaymentAttempt {
    state
        .repositories_arc()
        .get_payment_attempt(attempt_id)
        .await
        .expect("get attempt")
        .expect("attempt exists")
}

async fn wallet_balance(state: &AppState) -> i64 {
    state
        .get_wallet(TENANT)
        .await
        .expect("get wallet")
        .expect("wallet exists")
        .balance_credits
}

// --------------------------------------------------------------------------
// 1. Happy path: 402 -> Allow -> single paid replay -> settled + recorded
// --------------------------------------------------------------------------

#[test]
fn allow_settle_single_replay_records_attempt_and_settlement() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![
        payment_required_response(),
        success_response(Some(settled_payment_response())),
    ]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let outcome = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect("negotiation succeeds");

    let (response, attempt_id, authorization, settlement) = match outcome {
        X402Negotiation::Paid {
            response,
            attempt_id,
            authorization,
            settlement,
        } => (response, attempt_id, authorization, settlement),
        other => panic!("expected Paid, got {other:?}"),
    };
    assert_eq!(response.status, 200);
    assert!(authorization.is_allowed());
    assert_eq!(authorization.reason_code, "x402_allowed");
    assert!(
        matches!(settlement, EdgeOutcome::Settled { .. }),
        "{settlement:?}"
    );

    // Exactly two dispatches: one unpaid, then ONE paid replay.
    assert_eq!(transport.calls(), vec![false, true]);
    // Signer invoked exactly once.
    assert_eq!(signer.call_count(), 1);

    // The attempt is durably settled with attribution + evidence preserved.
    let attempt = block_on(attempt(&state, &attempt_id));
    assert_eq!(attempt.state, PAYMENT_ATTEMPT_SETTLED);
    assert_eq!(attempt.trace_id.as_deref(), Some("trace-1"));
    assert_eq!(attempt.request_id.as_deref(), Some("req-1"));
    assert_eq!(attempt.run_id.as_deref(), Some("run-1"));
    assert_eq!(attempt.resource_url, RESOURCE_URL);
    assert_eq!(attempt.credits_amount, Some(1_000));
    assert_eq!(
        attempt.transaction_signature.as_deref(),
        Some(signature().as_str())
    );

    // The wallet was captured exactly once and the reservation settled.
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 9_000);
}

// --------------------------------------------------------------------------
// 2. Policy Deny: no payment, no signer, typed failure
// --------------------------------------------------------------------------

#[test]
fn policy_deny_makes_no_payment_and_never_signs() {
    let state = seed_state(10_000);
    let policy = X402SpendPolicy::disabled().validate().expect("disabled");
    let transport = FakeTransport::new(vec![payment_required_response()]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("policy deny is a typed failure");

    match error {
        X402NegotiationError::PolicyRejected { authorization } => {
            assert!(matches!(authorization.decision, PaymentDecision::Deny));
        }
        other => panic!("expected PolicyRejected, got {other:?}"),
    }
    // Only the initial unpaid dispatch happened; the signer was never invoked.
    assert_eq!(transport.calls(), vec![false]);
    assert_eq!(signer.call_count(), 0);
    // No attempt and no reservation were created.
    let attempt_id = "req-1";
    assert!(block_on(reservation_status(&state, attempt_id)).is_none());
}

// --------------------------------------------------------------------------
// 2b. ApprovalRequired short-circuits without paying.
// --------------------------------------------------------------------------

#[test]
fn approval_required_short_circuits_without_signing() {
    let state = seed_state(10_000);
    let policy = approval_policy();
    let transport = FakeTransport::new(vec![payment_required_response()]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("approval required is a typed failure");

    match error {
        X402NegotiationError::PolicyRejected { authorization } => {
            assert!(matches!(
                authorization.decision,
                PaymentDecision::ApprovalRequired { .. }
            ));
        }
        other => panic!("expected PolicyRejected/ApprovalRequired, got {other:?}"),
    }
    assert_eq!(transport.calls(), vec![false]);
    assert_eq!(signer.call_count(), 0);
}

// --------------------------------------------------------------------------
// 3. Second 402 after paying: typed failure, never loops, parks unknown.
// --------------------------------------------------------------------------

#[test]
fn second_402_after_paying_is_typed_failure_and_never_loops() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![
        payment_required_response(),
        // The paid replay is met with a SECOND 402.
        payment_required_response(),
    ]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("second 402 is a typed failure");

    let (attempt_id, settlement) = match error {
        X402NegotiationError::SecondPaymentRequired {
            attempt_id,
            authorization,
            settlement,
        } => {
            assert!(authorization.is_allowed());
            (attempt_id, settlement)
        }
        other => panic!("expected SecondPaymentRequired, got {other:?}"),
    };
    // Never a third dispatch: exactly the unpaid + one paid replay.
    assert_eq!(transport.calls(), vec![false, true]);
    assert_eq!(signer.call_count(), 1);

    // The proof was already submitted, so the attempt parks outcome_unknown with
    // the hold RETAINED -- never a false release that could spend for free.
    assert!(
        matches!(settlement, EdgeOutcome::OutcomeUnknown { parked: true, .. }),
        "{settlement:?}"
    );
    assert_eq!(
        block_on(attempt(&state, &attempt_id)).state,
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// 4. Outcome-unknown handling: 2xx paid replay with ambiguous settlement.
// --------------------------------------------------------------------------

#[test]
fn paid_replay_without_settlement_evidence_parks_outcome_unknown() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![
        payment_required_response(),
        // 2xx but NO PAYMENT-RESPONSE header: the resource was served but we have
        // no durable on-chain proof, so settlement must park unknown.
        success_response(None),
    ]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let outcome = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect("negotiation succeeds with ambiguous settlement");

    let (attempt_id, settlement) = match outcome {
        X402Negotiation::Paid {
            attempt_id,
            settlement,
            ..
        } => (attempt_id, settlement),
        other => panic!("expected Paid, got {other:?}"),
    };
    assert!(
        matches!(settlement, EdgeOutcome::OutcomeUnknown { parked: true, .. }),
        "{settlement:?}"
    );
    // Hold RETAINED, wallet untouched, attempt parked for the reconciler.
    assert_eq!(
        block_on(attempt(&state, &attempt_id)).state,
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// 4b. Paid replay fails for a non-payment reason: parks unknown, never releases.
// --------------------------------------------------------------------------

#[test]
fn paid_replay_non_2xx_failure_parks_outcome_unknown() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![
        payment_required_response(),
        EgressResponse {
            status: 500,
            payment_required: None,
            payment_response: None,
        },
    ]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("non-2xx paid replay is a typed failure");

    let (status, attempt_id, settlement) = match error {
        X402NegotiationError::ReplayFailed {
            status,
            attempt_id,
            authorization,
            settlement,
        } => {
            assert!(authorization.is_allowed());
            (status, attempt_id, settlement)
        }
        other => panic!("expected ReplayFailed, got {other:?}"),
    };
    assert_eq!(status, 500);
    assert_eq!(transport.calls(), vec![false, true]);
    // Proof already submitted -> park unknown, retain the hold (never a release).
    assert!(
        matches!(settlement, EdgeOutcome::OutcomeUnknown { parked: true, .. }),
        "{settlement:?}"
    );
    assert_eq!(
        block_on(attempt(&state, &attempt_id)).state,
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// 4c. Transport failure on the paid replay (after submit) parks unknown.
// --------------------------------------------------------------------------

#[test]
fn transport_failure_after_submit_parks_outcome_unknown() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    // Only the initial 402 is queued; the paid replay finds the transport
    // exhausted and returns a transport error.
    let transport = FakeTransport::new(vec![payment_required_response()]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("transport failure after submit is a typed failure");

    let (attempt_id, settlement) = match error {
        X402NegotiationError::Transport {
            source,
            attempt_id,
            settlement,
        } => {
            assert!(source.to_string().contains("transport"));
            (attempt_id, settlement)
        }
        other => panic!("expected Transport, got {other:?}"),
    };
    // The proof was submitted before the replay dispatch failed, so the attempt
    // is parked unknown with the hold retained for the reconciler.
    let attempt_id = attempt_id.expect("attempt id present after submit");
    assert!(
        matches!(
            settlement,
            Some(EdgeOutcome::OutcomeUnknown { parked: true, .. })
        ),
        "{settlement:?}"
    );
    assert_eq!(
        block_on(attempt(&state, &attempt_id)).state,
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// 5. Insufficient funds never reaches the signer.
// --------------------------------------------------------------------------

#[test]
fn insufficient_funds_never_invokes_signer() {
    // Wallet cannot cover the 1000-credit hold.
    let state = seed_state(100);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![payment_required_response()]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("insufficient funds is a typed failure");

    match error {
        X402NegotiationError::Unfundable {
            rejection:
                FundingRejection::Insufficient {
                    requested_credits, ..
                },
            authorization,
        } => {
            assert_eq!(requested_credits, 1_000);
            assert!(authorization.is_allowed());
        }
        other => panic!("expected Unfundable/Insufficient, got {other:?}"),
    }
    // The signer is never invoked and no paid replay is attempted.
    assert_eq!(signer.call_count(), 0);
    assert_eq!(transport.calls(), vec![false]);
}

// --------------------------------------------------------------------------
// 6. Signer refusal releases the pre-submission hold.
// --------------------------------------------------------------------------

#[test]
fn signer_rejection_releases_hold_and_makes_no_paid_replay() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![payment_required_response()]);
    let signer = FakeSigner::rejecting();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect_err("signer rejection is a typed failure");

    let attempt_id = match error {
        X402NegotiationError::SignerRejected {
            attempt_id,
            reason,
            authorization,
        } => {
            assert!(reason.contains("signer locked"));
            assert!(authorization.is_allowed());
            attempt_id
        }
        other => panic!("expected SignerRejected, got {other:?}"),
    };
    // Signer was consulted; no paid replay happened (only the unpaid dispatch).
    assert_eq!(signer.call_count(), 1);
    assert_eq!(transport.calls(), vec![false]);

    // The pre-submission hold was released and the balance restored.
    assert_eq!(
        block_on(attempt(&state, &attempt_id)).state,
        PAYMENT_ATTEMPT_RELEASED
    );
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// 7. No 402: original response passes through untouched.
// --------------------------------------------------------------------------

#[test]
fn no_payment_required_passes_response_through() {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![success_response(None)]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let outcome = block_on(negotiate_paid_egress(
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect("negotiation succeeds");

    match outcome {
        X402Negotiation::NotRequired { response } => assert_eq!(response.status, 200),
        other => panic!("expected NotRequired, got {other:?}"),
    }
    // No payment machinery ran: one dispatch, no signing.
    assert_eq!(transport.calls(), vec![false]);
    assert_eq!(signer.call_count(), 0);
}
