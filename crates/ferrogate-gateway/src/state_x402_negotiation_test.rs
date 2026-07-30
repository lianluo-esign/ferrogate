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
// the signer; signer refusal releases the pre-submission hold. Also pins the
// #476 money-safety rule that the hold is only ever captured once the
// merchant-REPORTED settled amount is proven to COVER the owed amount on parsed
// integers -- underpayment, an omitted amount, and an unparseable amount all
// park instead of capturing, while a spec-valid overpayment settles and still
// captures only the owed hold. Finally pins #497: every park leaves a DURABLE
// audit row (amount anomalies under the reconciler's own
// `x402.settlement.amount_mismatch`, other causes under
// `x402.settlement.outcome_unknown`), and a clean settle leaves neither.

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
use ferrogate_config::Config;

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

/// A 402 challenge demanding exactly `owed_atomic_amount` (canonical decimal).
fn payment_required_header_for(owed_atomic_amount: &str) -> String {
    let object = json!({
        "x402Version": 2,
        "resource": { "url": RESOURCE_URL },
        "accepts": [{
            "scheme": "exact",
            "network": CAIP2_SOLANA_DEVNET,
            "asset": mint(),
            "amount": owed_atomic_amount,
            "payTo": recipient(),
            "maxTimeoutSeconds": 600,
            "extra": { "feePayer": fee_payer() }
        }]
    });
    BASE64_STD.encode(serde_json::to_vec(&object).expect("serialize challenge"))
}

fn payment_required_header() -> String {
    payment_required_header_for("1000")
}

/// A merchant `PAYMENT-RESPONSE` claiming success with a valid on-chain
/// signature, reporting `amount` verbatim (a JSON value so a test can supply a
/// non-canonical / non-string / omitted amount).
fn settled_payment_response_with_amount(amount: Option<serde_json::Value>) -> String {
    let mut object = json!({
        "success": true,
        "network": CAIP2_SOLANA_DEVNET,
        "transaction": signature(),
    });
    if let Some(amount) = amount {
        object["amount"] = amount;
    }
    BASE64_STD.encode(serde_json::to_vec(&object).expect("serialize settlement"))
}

/// A merchant success report for exactly `settled_atomic_amount`.
fn settled_payment_response_for(settled_atomic_amount: &str) -> String {
    settled_payment_response_with_amount(Some(json!(settled_atomic_amount)))
}

fn settled_payment_response() -> String {
    settled_payment_response_for("1000")
}

/// A merchant `PAYMENT-RESPONSE` that reports the settlement FAILED. Not
/// on-chain proof in either direction, so it parks rather than releasing.
fn failed_payment_response() -> String {
    let object = json!({
        "success": false,
        "network": CAIP2_SOLANA_DEVNET,
        "transaction": signature(),
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

fn payment_required_response_for(owed_atomic_amount: &str) -> EgressResponse {
    EgressResponse {
        status: 402,
        payment_required: Some(payment_required_header_for(owed_atomic_amount)),
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
            expires_at_unix: None,
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
            expires_at_unix: None,
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

/// SHA-256 of the fixture's POST body, lowercase hex.
const BODY_SHA256_HEX: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

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
        // A real lowercase-hex SHA-256: the #351 payment intent binds the
        // request body, so a placeholder string is no longer a usable stand-in.
        request_body_hash: Some(BODY_SHA256_HEX),
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
        &state,
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
    assert_eq!(authorization.reason_code(), "x402_allowed");
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
    // Exact payment: the OBSERVED amount is persisted and equals what was owed
    // (#476 changed nothing for this case).
    assert_eq!(attempt.settled_atomic_amount.as_deref(), Some("1000"));
    assert_eq!(attempt.atomic_amount, "1000");

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
        &state,
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
            assert!(matches!(authorization.decision(), PaymentDecision::Deny));
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
        &state,
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
                authorization.decision(),
                PaymentDecision::ApprovalRequired { .. }
            ));
        }
        other => panic!("expected PolicyRejected/ApprovalRequired, got {other:?}"),
    }
    assert_eq!(transport.calls(), vec![false]);
    assert_eq!(signer.call_count(), 0);
}

// --------------------------------------------------------------------------
// 2c. The conversion-freshness clock is the negotiation's own `now_unix`.
// --------------------------------------------------------------------------

/// An expiring rate, with a policy that would otherwise allow.
fn expiring_policy(expires_at_unix: i64) -> ValidatedX402SpendPolicy {
    let mut policy = allowing_policy().policy().clone();
    policy.conversion.expires_at_unix = Some(expires_at_unix);
    policy.validate().expect("valid policy")
}

/// The caller's ledger snapshot claims the rate is fresh (`now_unix` well
/// before the deadline) while the negotiation is running AFTER it. The clock
/// that stamps the hold and the attempt is the clock the rate is judged by, so
/// this must deny rather than pay at a rate nobody can vouch for.
#[test]
fn a_stale_ledger_clock_cannot_vouch_for_an_expired_conversion_rate() {
    let state = seed_state(10_000);
    let policy = expiring_policy(200);
    let transport = FakeTransport::new(vec![payment_required_response()]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let error = block_on(negotiate_paid_egress(
        &state,
        &loop_,
        &policy,
        // The snapshot says "it is 100", which is inside the window.
        &SpendSnapshot {
            now_unix: Some(100),
            ..SpendSnapshot::default()
        },
        &context(),
        &transport,
        &signer,
        // The negotiation is happening at 300, which is past it.
        300,
    ))
    .expect_err("an expired conversion rate must deny");

    match error {
        X402NegotiationError::PolicyRejected { authorization } => {
            assert!(matches!(authorization.decision(), PaymentDecision::Deny));
            assert_eq!(authorization.reason_code(), "x402_conversion_expired");
        }
        other => panic!("expected PolicyRejected/conversion_expired, got {other:?}"),
    }
    // Nothing was paid and nothing was signed.
    assert_eq!(transport.calls(), vec![false]);
    assert_eq!(signer.call_count(), 0);
}

/// The mirror image: the caller supplied NO clock, which on its own denies
/// ("unprovable freshness must not authorize a spend"). The negotiation has an
/// authoritative one, so a rate that is genuinely still valid pays. Without the
/// plumbing, an expiry window would make the paid path permanently inert.
#[test]
fn the_negotiations_clock_proves_freshness_when_the_caller_supplied_none() {
    let state = seed_state(10_000);
    let policy = expiring_policy(1_000);
    let transport = FakeTransport::new(vec![
        payment_required_response(),
        success_response(Some(settled_payment_response())),
    ]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let outcome = block_on(negotiate_paid_egress(
        &state,
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect("a rate inside its validity window pays");

    match outcome {
        X402Negotiation::Paid { authorization, .. } => {
            assert!(authorization.is_allowed());
            assert_eq!(
                authorization.conversion().expires_at_unix,
                Some(1_000),
                "the decision records the freshness bound it was made under"
            );
        }
        other => panic!("expected Paid, got {other:?}"),
    }
    assert_eq!(signer.call_count(), 1);
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
        &state,
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
        &state,
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
        &state,
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
        &state,
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
        &state,
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
        &state,
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
        &state,
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

// --------------------------------------------------------------------------
// 8. #476: the merchant-reported settled amount is VERIFIED before the hold is
//    captured. This path and the offline reconciler (#469) make the SAME money
//    decision, so they apply the SAME discipline: `settled >= owed` on parsed
//    integers, fail-closed on anything else. Underpayment -- and a success claim
//    that omits the amount -- must never capture.
// --------------------------------------------------------------------------

/// Negotiate one paid egress where the challenge demands `owed` and the paid
/// replay returns 200 with `payment_response`. Returns the seeded state (wallet
/// 10_000), the attempt id, and the settlement edge finalize drove.
fn negotiate_with(owed: &str, payment_response: Option<String>) -> (AppState, String, EdgeOutcome) {
    let state = seed_state(10_000);
    let policy = allowing_policy();
    let transport = FakeTransport::new(vec![
        payment_required_response_for(owed),
        success_response(payment_response),
    ]);
    let signer = FakeSigner::allowing();
    let loop_ = state.x402_settlement_loop();

    let outcome = block_on(negotiate_paid_egress(
        &state,
        &loop_,
        &policy,
        &SpendSnapshot::default(),
        &context(),
        &transport,
        &signer,
        300,
    ))
    .expect("negotiation completes");

    match outcome {
        X402Negotiation::Paid {
            attempt_id,
            settlement,
            ..
        } => (state, attempt_id, settlement),
        other => panic!("expected Paid, got {other:?}"),
    }
}

/// The money-safety assertion: NOTHING was captured. The hold is still ACTIVE,
/// the wallet balance is untouched, the attempt is parked `outcome_unknown`
/// (never `settled`), and no settled amount was recorded.
fn assert_hold_not_captured(state: &AppState, attempt_id: &str, settlement: &EdgeOutcome) {
    assert!(
        matches!(settlement, EdgeOutcome::OutcomeUnknown { parked: true, .. }),
        "expected a park, got {settlement:?}"
    );
    let attempt = block_on(attempt(state, attempt_id));
    assert_eq!(attempt.state, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN);
    assert_ne!(attempt.state, PAYMENT_ATTEMPT_SETTLED);
    assert_eq!(attempt.settled_atomic_amount, None);
    assert_eq!(
        block_on(reservation_status(state, attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "the hold must still be reserved, never captured"
    );
    assert_eq!(block_on(wallet_balance(state)), 10_000);
}

#[test]
fn merchant_reported_underpayment_never_captures_the_hold() {
    // Owed 1000; the merchant claims success with a valid on-chain signature but
    // reports settling 999 -- one atomic unit short. Before #476 the amount was
    // never compared, so this captured the FULL 1000-credit hold: the tenant was
    // debited 1000 while 999 moved.
    let (state, attempt_id, settlement) =
        negotiate_with("1000", Some(settled_payment_response_for("999")));
    assert_hold_not_captured(&state, &attempt_id, &settlement);

    let attempt = block_on(attempt(&state, &attempt_id));
    // The signature is still persisted at the park CAS (#399) so the on-chain
    // reconciler -- which is authoritative -- can resolve the attempt from
    // storage alone.
    assert_eq!(
        attempt.transaction_signature.as_deref(),
        Some(signature().as_str())
    );
    // Evidence honesty: the merchant's report is durable VERBATIM, so what was
    // actually claimed (999) is inspectable rather than an assumed full payment.
    assert_eq!(
        attempt.settlement_response,
        Some(settled_payment_response_for("999"))
    );
}

#[test]
fn merchant_omitting_the_settled_amount_parks_instead_of_assuming_full_payment() {
    // THE DOCUMENTED #476 CHOICE. A success claim that reports no amount at all
    // used to fall back to "the owed amount was paid" and capture the hold. It
    // now parks `outcome_unknown` with the hold RETAINED, which composes with the
    // rest of the machine: the #354 reconciler picks up exactly these attempts
    // and verifies them against the chain. It is deliberately NOT a FAIL -- that
    // edge RELEASES the hold, and an amount-less claim is no more proof that the
    // money did not move than it is proof that it did.
    let (state, attempt_id, settlement) =
        negotiate_with("1000", Some(settled_payment_response_with_amount(None)));
    assert_hold_not_captured(&state, &attempt_id, &settlement);
    assert_eq!(
        block_on(attempt(&state, &attempt_id))
            .transaction_signature
            .as_deref(),
        Some(signature().as_str()),
        "the signature must still be persisted for the reconciler"
    );
}

#[test]
fn merchant_reported_overpayment_settles_and_captures_only_the_owed_hold() {
    // Overpayment stays spec-valid and settles, consistent with #469.
    let (state, attempt_id, settlement) =
        negotiate_with("1000", Some(settled_payment_response_for("1500")));
    assert!(
        matches!(settlement, EdgeOutcome::Settled { .. }),
        "{settlement:?}"
    );

    let attempt = block_on(attempt(&state, &attempt_id));
    assert_eq!(attempt.state, PAYMENT_ATTEMPT_SETTLED);
    // The OBSERVED amount is persisted, not the owed one, so overpaid and exact
    // settlements stay distinguishable in the durable row.
    assert_eq!(attempt.settled_atomic_amount.as_deref(), Some("1500"));
    assert_eq!(attempt.atomic_amount, "1000");
    // The capture takes exactly what the hold reserved (the owed 1000 credits):
    // `settle_wallet_reservation` takes no amount, so an overpayment can never
    // over-capture. The excess stayed with the payee on-chain.
    assert_eq!(
        block_on(reservation_status(&state, &attempt_id)).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 9_000);
}

#[test]
fn online_amount_comparison_is_integer_not_lexical_in_both_directions() {
    // THE LEXICAL TRAP. Owed 9, settled 10: a string comparison reads "10" < "9"
    // (it compares '1' against '9') and would refuse a spec-valid overpayment.
    let (state, attempt_id, settlement) =
        negotiate_with("9", Some(settled_payment_response_for("10")));
    assert!(
        matches!(settlement, EdgeOutcome::Settled { .. }),
        "owed 9, settled 10 must SETTLE -- a string compare would say \"10\" < \"9\": \
         {settlement:?}"
    );
    let attempt = block_on(attempt(&state, &attempt_id));
    assert_eq!(attempt.settled_atomic_amount.as_deref(), Some("10"));
    // Only the owed 9 credits were captured, never the reported 10.
    assert_eq!(block_on(wallet_balance(&state)), 9_991);

    // ...and the mirror, which is the money-losing direction on THIS path:
    // lexically "9" > "10", so a string comparison would CAPTURE a real
    // underpayment. Integer comparison refuses it.
    let (state, attempt_id, settlement) =
        negotiate_with("10", Some(settled_payment_response_for("9")));
    assert_hold_not_captured(&state, &attempt_id, &settlement);
}

#[test]
fn unparseable_reported_amount_fails_closed_and_never_captures() {
    // The frozen #350 wire parse rejects any non-canonical atomic amount, so a
    // garbage `amount` makes the whole PAYMENT-RESPONSE unparseable -- which is
    // ambiguous evidence and parks. Either way the hold is NEVER captured on an
    // amount that could not be proven to cover what is owed.
    for amount in [
        json!("1.5"),   // no decimal point on the atomic path
        json!("-1"),    // negative is not an atomic amount
        json!("1e3"),   // no float/exponent notation on the money path
        json!(" 1000"), // whitespace is not canonical
        json!("01000"), // non-canonical leading zero
        json!(""),      // empty
        json!(1000),    // a JSON number, not the wire's string amount
        json!(null),    // explicit null reads as "no amount reported"
        json!("99999999999999999999999999999999999999999"), // wider than u64
    ] {
        let (state, attempt_id, settlement) = negotiate_with(
            "1000",
            Some(settled_payment_response_with_amount(Some(amount.clone()))),
        );
        assert_hold_not_captured(&state, &attempt_id, &settlement);
        assert!(
            block_on(attempt(&state, &attempt_id))
                .settled_atomic_amount
                .is_none(),
            "amount {amount} must never be recorded as a settlement"
        );
    }
}

#[test]
fn reported_amount_decision_table() {
    fn covers(settled: &str, excess: Option<&str>) -> ReportedAmount {
        ReportedAmount::Covers {
            settled_atomic_amount: settled.to_string(),
            overpayment_atomic_amount: excess.map(str::to_string),
        }
    }
    fn short(observed: &str) -> ReportedAmount {
        ReportedAmount::Short {
            observed_atomic_amount: observed.to_string(),
        }
    }

    // Exact and overpaid both cover the owed amount; only the overpaid one
    // carries the excess, so the two never flatten together.
    assert_eq!(
        classify_reported_amount("1000", Some(1000)),
        covers("1000", None)
    );
    assert_eq!(
        classify_reported_amount("1000", Some(1500)),
        covers("1500", Some("500"))
    );
    // One atomic unit short still fails closed.
    assert_eq!(classify_reported_amount("1000", Some(999)), short("999"));
    // No amount reported at all: never assumed to be the owed amount.
    assert_eq!(
        classify_reported_amount("1000", None),
        ReportedAmount::Absent
    );
    // The lexical trap, both directions.
    assert_eq!(
        classify_reported_amount("9", Some(10)),
        covers("10", Some("1"))
    );
    assert_eq!(classify_reported_amount("10", Some(9)), short("9"));
    // The u64 boundary: the comparison and the excess are done in u128, so the
    // maximal overpayment neither overflows nor wraps.
    let max = u64::MAX.to_string();
    assert_eq!(
        classify_reported_amount(&max, Some(u64::MAX)),
        covers(&max, None)
    );
    assert_eq!(
        classify_reported_amount("1", Some(u64::MAX)),
        covers(&max, Some(&(u128::from(u64::MAX) - 1).to_string()))
    );
    // An owed amount that is not a canonical atomic value can never be PROVEN
    // covered, so it fails closed even against the largest possible report. The
    // #350 challenge parse makes this unreachable today; pinned so the shared
    // comparison's fail-closed default is a recorded property of this path too.
    assert_eq!(
        classify_reported_amount("not-a-number", Some(u64::MAX)),
        short(&max)
    );
    assert_eq!(classify_reported_amount("", Some(u64::MAX)), short(&max));
}

// --------------------------------------------------------------------------
// 9. #497: an online amount anomaly leaves a DURABLE audit row, not only a log
//    line. The park holds tenant credits that nothing reaps -- the TTL sweeper
//    deliberately never touches a post-submission hold -- so the anomaly has to
//    be queryable next to the attempt it belongs to. The offline reconciler
//    already emits `x402.settlement.amount_mismatch` for the same class of
//    anomaly; both paths must answer ONE query.
// --------------------------------------------------------------------------

const AMOUNT_MISMATCH: &str = "x402.settlement.amount_mismatch";
const EVIDENCE_UNPROVEN: &str = "x402.settlement.outcome_unknown";

/// Every audit event recorded for `attempt_id` under `action`.
fn audit_events_for(
    state: &AppState,
    attempt_id: &str,
    action: &str,
) -> Vec<ferrogate_storage::StoredAuditEvent> {
    state.flush_evidence_writer();
    block_on(state.repositories_arc().audit_events())
        .into_iter()
        .filter(|event| event.target == attempt_id && event.action == action)
        .collect()
}

/// The single amount-mismatch event for `attempt_id`, or a panic naming what the
/// audit trail actually holds.
fn amount_mismatch_event(
    state: &AppState,
    attempt_id: &str,
) -> ferrogate_storage::StoredAuditEvent {
    let mut events = audit_events_for(state, attempt_id, AMOUNT_MISMATCH);
    assert_eq!(
        events.len(),
        1,
        "expected exactly one {AMOUNT_MISMATCH} row for {attempt_id}, got {events:?}"
    );
    events.remove(0)
}

#[test]
fn merchant_reported_underpayment_records_a_durable_amount_mismatch_audit_row() {
    // The defect this pins: before #497 the online path emitted only a
    // `tracing::warn!`, so an operator querying the audit trail saw NOTHING for
    // a park that had locked the tenant's credits indefinitely.
    let (state, attempt_id, settlement) =
        negotiate_with("1000", Some(settled_payment_response_for("999")));
    assert_hold_not_captured(&state, &attempt_id, &settlement);

    let event = amount_mismatch_event(&state, &attempt_id);
    // The message must carry BOTH sides of the comparison: an operator has to be
    // able to see the shortfall from the audit row alone, without the process
    // log the row exists to replace.
    assert!(
        event.message.contains("1000") && event.message.contains("999"),
        "the audit message must name the owed and the reported amount: {}",
        event.message
    );
    // Attribution: the row joins the tenant, the run and the trace the payment
    // was authorized under, so it is queryable alongside the payment attempt.
    assert_eq!(event.tenant.organization_id.as_deref(), Some(TENANT));
    assert_eq!(event.tenant.project_id.as_deref(), Some("project-1"));
    assert_eq!(event.trace_id.as_deref(), Some("trace-1"));
    assert_eq!(event.agent_run_id.as_deref(), Some("run-1"));
    assert_eq!(event.request_id, "req-1");
}

#[test]
fn merchant_omitting_the_settled_amount_records_a_durable_amount_mismatch_audit_row() {
    // The absent-amount park is the other #476 anomaly class, and it strands the
    // hold identically -- so it is auditable identically, under the SAME action.
    let (state, attempt_id, settlement) =
        negotiate_with("1000", Some(settled_payment_response_with_amount(None)));
    assert_hold_not_captured(&state, &attempt_id, &settlement);

    let event = amount_mismatch_event(&state, &attempt_id);
    assert!(
        event.message.contains("1000"),
        "the audit message must name what was owed: {}",
        event.message
    );
    assert!(
        event.message.contains("NO settled amount"),
        "an absent amount must be distinguishable from an underpayment in the audit \
         trail, not flattened into it: {}",
        event.message
    );
}

#[test]
fn every_other_park_is_audited_too_and_is_not_called_an_amount_mismatch() {
    // The park classes that are NOT about the amount strand the hold exactly the
    // same way -- nothing reaps a post-submission hold -- so leaving them
    // log-only would reproduce this issue for four of the five park causes.
    // They are audited under a DISTINCT action: an unparseable header is not
    // evidence that the merchant shorted us, and an operator hunting merchants
    // that under-report must not have to filter these out by message text.
    //
    // Note the third class the issue names, "unparseable", lands HERE and not in
    // the amount branch: the frozen #350 parse rejects the entire
    // PAYMENT-RESPONSE when the amount is non-canonical, so by the time this
    // path sees it there is no amount to compare -- only an unusable header.
    let cases: Vec<(&str, Option<String>, &str)> = vec![
        ("no header at all", None, "no PAYMENT-RESPONSE header"),
        (
            "an unparseable amount makes the whole header unparseable",
            Some(settled_payment_response_with_amount(Some(json!("1.5")))),
            "did not parse",
        ),
        (
            "the merchant reported a failure",
            Some(failed_payment_response()),
            "FAILED settlement",
        ),
    ];

    for (case, payment_response, expected_reason) in cases {
        let (state, attempt_id, settlement) = negotiate_with("1000", payment_response);
        assert_hold_not_captured(&state, &attempt_id, &settlement);

        assert!(
            audit_events_for(&state, &attempt_id, AMOUNT_MISMATCH).is_empty(),
            "{case}: this is not an amount mismatch and must not be recorded as one"
        );
        let events = audit_events_for(&state, &attempt_id, EVIDENCE_UNPROVEN);
        assert_eq!(events.len(), 1, "{case}: expected exactly one park row");
        assert!(
            events[0].message.contains(expected_reason),
            "{case}: the row must name WHY the evidence was unusable, got: {}",
            events[0].message
        );
    }
}

#[test]
fn a_settling_negotiation_records_no_amount_mismatch_row() {
    // The negative pin: the row must mean "an anomaly happened", not "a
    // settlement was attempted". A covering report captures the hold and must
    // leave no mismatch row -- otherwise the query an operator runs to find
    // stranded holds returns every paid request.
    let (state, attempt_id, settlement) =
        negotiate_with("1000", Some(settled_payment_response_for("1000")));
    assert!(
        matches!(settlement, EdgeOutcome::Settled { .. }),
        "expected a settle, got {settlement:?}"
    );
    assert!(
        audit_events_for(&state, &attempt_id, AMOUNT_MISMATCH).is_empty(),
        "a clean settle must not be recorded as an amount mismatch"
    );
    assert!(
        audit_events_for(&state, &attempt_id, EVIDENCE_UNPROVEN).is_empty(),
        "a clean settle parked nothing, so it must leave no park row either"
    );
}
