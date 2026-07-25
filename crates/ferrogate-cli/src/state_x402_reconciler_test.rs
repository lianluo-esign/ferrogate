// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Focused async tests for the background on-chain x402 settlement
// reconciler (issue #354). Proves the money-safe trust order with an INJECTED
// fake on-chain RPC (no live network) and an injected `now_unix` (no timing
// sleeps): a confirmed on-chain transfer of the exact amount settles the attempt
// and captures the hold; a definitively-failed/absent-past-deadline transfer
// fails it and releases the hold; a still-pending transfer stays outcome_unknown
// with the hold retained and the backoff cursor advanced; on-chain RPC beats a
// conflicting merchant success header; a spec-valid OVERPAYMENT settles while
// capturing only the owed hold and stays distinguishable from an exact settle in
// the persisted evidence, whereas an UNDERPAYMENT is NEVER settled (fail-closed,
// hold retained) and the amount comparison is integer, not lexical (#469); the
// amount comparison is proven on u64 boundaries and unparseable amounts;
// one bad attempt in a batch never aborts the rest;
// a signatureless attempt is re-parked, never failed; disabled is a complete
// no-op; and concurrent reconciles (barrier, no sleeps) settle each attempt
// exactly once. Live on-chain RPC is not runnable here, so the fake stands in for
// the (deferred) SVM RPC transport binding.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use ferrogate_payments::CAIP2_SOLANA_MAINNET;
use ferrogate_storage::{
    StoredWallet, PAYMENT_ATTEMPT_FAILED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN, PAYMENT_ATTEMPT_SETTLED,
    WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_RELEASED, WALLET_RESERVATION_SETTLED,
};

use super::super::state_x402_settlement::{PaidEgressOpen, SettlementEvidence};
use super::super::AppState;
use super::*;
use crate::config::{Config, X402ReconcilerConfig};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

const TENANT: &str = "tenant-x402-reconcile";
const OPEN_AT: i64 = 100;
const SUBMIT_AT: i64 = 200;
const PARK_AT: i64 = 300;
/// The wallet hold must OUTLIVE the settlement/confirmation window: the wallet
/// primitive refuses to capture a hold past its `expires_at` (and auto-releases
/// it). A managed paid-egress deployment must therefore size `hold_ttl_secs` to
/// exceed `confirmation_deadline_secs` plus reconcile slack, so a submitted
/// attempt's hold survives long enough for the reconciler to capture it. The
/// test hold (opened at 100, expiring at 100 + 1_000_000) is still live at
/// `RECONCILE_NOW`, mirroring that operational contract.
const HOLD_TTL_SECS: i64 = 1_000_000;
const OWED_ATOMIC: &str = "1000000";
/// Past both the reconcile-check delay (updated_at=300 + 60) and the confirmation
/// deadline (submitted_at=200 + 900 = 1100), yet well within the hold TTL.
const RECONCILE_NOW: i64 = 100_000;

// --------------------------------------------------------------------------
// Fake on-chain RPC seam (no live network) + deterministic base58 signatures
// --------------------------------------------------------------------------

/// A deterministic on-chain RPC double keyed by transaction signature. An entry
/// maps to either an authoritative status or a transport error; an unmapped
/// signature answers `NotFound` (the chain has never seen it).
#[derive(Default)]
struct FakeOnChainRpc {
    by_signature: HashMap<String, Result<OnChainSettlementStatus, String>>,
}

impl FakeOnChainRpc {
    fn with(mut self, signature: &str, status: OnChainSettlementStatus) -> Self {
        self.by_signature.insert(signature.to_string(), Ok(status));
        self
    }
    fn with_error(mut self, signature: &str, message: &str) -> Self {
        self.by_signature
            .insert(signature.to_string(), Err(message.to_string()));
        self
    }
}

impl OnChainSettlementRpc for FakeOnChainRpc {
    async fn transfer_status(
        &self,
        query: &OnChainQuery<'_>,
    ) -> Result<OnChainSettlementStatus, OnChainRpcError> {
        // A real SVM RPC needs the network + destination + mint to locate the
        // right transfer instruction inside the transaction; the double at least
        // asserts the reconciler passed them (they flow straight from the durable
        // attempt), then keys its canned answer off the signature.
        assert!(
            !query.network_caip2.is_empty()
                && !query.recipient.is_empty()
                && !query.mint.is_empty(),
            "reconciler must pass the transfer's network/recipient/mint"
        );
        match self.by_signature.get(query.transaction_signature) {
            Some(Ok(status)) => Ok(status.clone()),
            Some(Err(message)) => Err(OnChainRpcError {
                message: message.clone(),
            }),
            None => Ok(OnChainSettlementStatus::NotFound),
        }
    }
}

/// Base58-encode (big-endian, Bitcoin alphabet -- the exact alphabet
/// `ferrogate_payments::base58_decode` inverts), so the merchant-header parser
/// accepts the round-tripped signature.
fn base58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// A valid, distinct 64-byte base58 transaction signature (seed in the leading
/// byte keeps the decoded length at exactly 64, which the parser requires).
fn signature(seed: u8) -> String {
    let mut bytes = [0u8; 64];
    bytes[0] = seed.max(1);
    base58_encode(&bytes)
}

/// A raw `PAYMENT-RESPONSE` merchant header claiming success for `signature`,
/// exactly what the negotiation stores in `settlement_response` when it parks an
/// attempt `outcome_unknown`. The reconciler recovers the signature from this
/// (untrusted) header, then verifies it against the (authoritative) RPC.
fn merchant_success_header(signature: &str, amount: &str) -> String {
    let json = serde_json::json!({
        "success": true,
        "network": CAIP2_SOLANA_MAINNET,
        "transaction": signature,
        "amount": amount,
    });
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&json).expect("encode"))
}

// --------------------------------------------------------------------------
// Seeding
// --------------------------------------------------------------------------

fn reconciler_config(
    enabled: bool,
    max_reconciles_per_tick: usize,
    reconcile_check_delay_secs: i64,
    confirmation_deadline_secs: i64,
) -> X402ReconcilerConfig {
    X402ReconcilerConfig {
        enabled,
        tick_interval_secs: 30,
        max_reconciles_per_tick,
        reconcile_check_delay_secs,
        confirmation_deadline_secs,
        // The wallet hold TTL must outlive the confirmation window (#400); this
        // fixture mirrors that operational contract with a hold that far exceeds
        // any deadline the reconcile tests exercise.
        hold_ttl_secs: HOLD_TTL_SECS,
    }
}

fn seed_state(balance_credits: i64, reconciler: X402ReconcilerConfig) -> AppState {
    let state = AppState::new(Config {
        x402_reconciler: reconciler,
        ..Config::default()
    });
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

fn open_request(attempt_id: &str, credits_amount: i64) -> PaidEgressOpen {
    PaidEgressOpen {
        attempt_id: attempt_id.into(),
        tenant_id: TENANT.into(),
        project_id: None,
        workspace_id: None,
        run_id: None,
        worker_id: None,
        request_id: Some(format!("req-{attempt_id}")),
        trace_id: Some(format!("trace-{attempt_id}")),
        method: "POST".into(),
        resource_url: "https://api.example.com/paid".into(),
        request_body_hash: None,
        challenge_hash: format!("challenge-{attempt_id}"),
        x402_version: 2,
        scheme: "exact".into(),
        network_caip2: CAIP2_SOLANA_MAINNET.into(),
        mint: "So11111111111111111111111111111111111111112".into(),
        atomic_amount: OWED_ATOMIC.into(),
        recipient: "RecipientPubkey1111111111111111111111111111".into(),
        credits_amount,
        conversion_version: Some("conv-v1".into()),
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_ttl_secs: HOLD_TTL_SECS,
    }
}

/// Opens, submits, then parks an attempt `outcome_unknown` carrying a merchant
/// success header for `signature` (the realistic durable source of the tx
/// signature the reconciler verifies on-chain). Hold is RETAINED (active).
fn seed_outcome_unknown(state: &AppState, attempt_id: &str, credits: i64, signature: &str) {
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request(attempt_id, credits), OPEN_AT)).expect("open");
    block_on(loop_.submit(attempt_id, None, SUBMIT_AT, SUBMIT_AT)).expect("submit");
    let header = merchant_success_header(signature, OWED_ATOMIC);
    block_on(loop_.finalize(
        attempt_id,
        &SettlementEvidence::Unknown {
            response: Some(&header),
            transaction_signature: None,
        },
        PARK_AT,
    ))
    .expect("park outcome_unknown");
}

/// Opens + submits an attempt but never parks it, so it is bare `submitted` with
/// no merchant header and thus no recoverable signature.
fn seed_submitted_no_header(state: &AppState, attempt_id: &str, credits: i64) {
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request(attempt_id, credits), OPEN_AT)).expect("open");
    block_on(loop_.submit(attempt_id, None, SUBMIT_AT, SUBMIT_AT)).expect("submit");
}

/// Opens + submits an attempt with the on-chain signature persisted into the
/// durable `transaction_signature` column AT SUBMIT (#399) and NO merchant
/// PAYMENT-RESPONSE header ever stored. The reconciler must recover the
/// signature from storage alone, proving the column -- not the merchant header --
/// is a sufficient source.
fn seed_submitted_with_column_signature(
    state: &AppState,
    attempt_id: &str,
    credits: i64,
    signature: &str,
) {
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request(attempt_id, credits), OPEN_AT)).expect("open");
    block_on(loop_.submit(attempt_id, Some(signature), SUBMIT_AT, SUBMIT_AT)).expect("submit");
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

async fn attempt_state(state: &AppState, attempt_id: &str) -> String {
    state
        .repositories_arc()
        .get_payment_attempt(attempt_id)
        .await
        .expect("get attempt")
        .expect("attempt exists")
        .state
}

async fn attempt_updated_at(state: &AppState, attempt_id: &str) -> i64 {
    state
        .repositories_arc()
        .get_payment_attempt(attempt_id)
        .await
        .expect("get attempt")
        .expect("attempt exists")
        .updated_at_unix
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
// Confirmed exact amount -> settled + hold captured
// --------------------------------------------------------------------------

#[test]
fn reconcile_confirmed_exact_amount_settles_and_captures_hold() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(1);
    seed_outcome_unknown(&state, "c1", 500, &sig);

    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: OWED_ATOMIC.into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.scanned, 1);
    assert_eq!(report.settled, 1, "confirmed exact amount settles");
    assert_eq!(report.failed, 0);
    assert_eq!(report.pending, 0);
    assert_eq!(report.errored, 0);

    assert_eq!(
        block_on(attempt_state(&state, "c1")),
        PAYMENT_ATTEMPT_SETTLED
    );
    assert_eq!(
        block_on(reservation_status(&state, "c1")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED),
        "the hold is CAPTURED on settle"
    );
    // Capture debits the held credits from the wallet balance.
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
}

// --------------------------------------------------------------------------
// Definitively failed / absent past deadline -> failed + hold released
// --------------------------------------------------------------------------

#[test]
fn reconcile_chain_rejected_fails_and_releases_hold() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(2);
    seed_outcome_unknown(&state, "f1", 500, &sig);

    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Failed {
            reason: "transaction dropped".into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.failed, 1, "a chain-rejected transfer fails");
    assert_eq!(report.settled, 0);

    assert_eq!(
        block_on(attempt_state(&state, "f1")),
        PAYMENT_ATTEMPT_FAILED
    );
    assert_eq!(
        block_on(reservation_status(&state, "f1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED),
        "the hold is RELEASED on a definite failure"
    );
    // Release restores available balance; no money moved.
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

#[test]
fn reconcile_absent_past_deadline_fails_but_absent_before_deadline_stays_unknown() {
    // Absent signature, but BEFORE the confirmation deadline (submitted_at=200 +
    // 900 = 1100): must stay outcome_unknown, never a premature fail.
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(3);
    seed_outcome_unknown(&state, "a1", 500, &sig);
    // Unmapped signature => the fake answers NotFound.
    let rpc = FakeOnChainRpc::default();

    let before = block_on(state.reconcile_x402_settlements_once(&rpc, 900));
    assert_eq!(
        before.pending, 1,
        "absent before the deadline is pending, not failed"
    );
    assert_eq!(before.failed, 0);
    assert_eq!(
        block_on(attempt_state(&state, "a1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, "a1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "hold retained while ambiguous"
    );

    // Same absence, now PAST the deadline: a definite fail.
    let after = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(after.failed, 1, "absent past the deadline fails");
    assert_eq!(
        block_on(attempt_state(&state, "a1")),
        PAYMENT_ATTEMPT_FAILED
    );
    assert_eq!(
        block_on(reservation_status(&state, "a1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// Still pending -> stays outcome_unknown, hold retained, backoff advanced
// --------------------------------------------------------------------------

#[test]
fn reconcile_pending_stays_outcome_unknown_and_advances_backoff() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(4);
    seed_outcome_unknown(&state, "p1", 500, &sig);
    let updated_before = block_on(attempt_updated_at(&state, "p1"));

    let rpc = FakeOnChainRpc::default().with(&sig, OnChainSettlementStatus::Pending);
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(
        report.pending, 1,
        "a pending transfer stays outcome_unknown"
    );
    assert_eq!(report.settled, 0);
    assert_eq!(report.failed, 0);

    assert_eq!(
        block_on(attempt_state(&state, "p1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, "p1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "hold RETAINED while pending -- its money may still confirm"
    );
    // Backoff advanced: the re-check cursor (updated_at) moved forward to `now`,
    // so a subsequent tick whose horizon predates it will NOT re-pick the attempt.
    let updated_after = block_on(attempt_updated_at(&state, "p1"));
    assert!(
        updated_after > updated_before,
        "backoff cursor advanced ({updated_before} -> {updated_after})"
    );
    assert_eq!(updated_after, RECONCILE_NOW);

    // Immediately re-running at the SAME now leaves it not-yet-due (updated_at ==
    // now, delay 60 => horizon now-60 < updated_at): the backoff defers it.
    let deferred = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(deferred.scanned, 0, "backoff defers the next re-check");
}

// --------------------------------------------------------------------------
// On-chain RPC beats a conflicting merchant success header
// --------------------------------------------------------------------------

#[test]
fn reconcile_onchain_rpc_beats_conflicting_merchant_success_header() {
    // The attempt carries a merchant header CLAIMING success, but the chain says
    // the transfer failed. On-chain evidence is authoritative: the attempt fails.
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(5);
    seed_outcome_unknown(&state, "m1", 500, &sig);

    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Failed {
            reason: "merchant lied; tx never confirmed".into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(
        report.failed, 1,
        "on-chain failure overrides the merchant success claim"
    );
    assert_eq!(
        report.settled, 0,
        "the merchant success header does NOT settle"
    );
    assert_eq!(
        block_on(attempt_state(&state, "m1")),
        PAYMENT_ATTEMPT_FAILED
    );
    assert_eq!(
        block_on(reservation_status(&state, "m1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// Amount mismatch -> NOT settled (fail-closed), hold retained
// --------------------------------------------------------------------------

#[test]
fn reconcile_amount_mismatch_is_never_settled_fail_closed() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(6);
    seed_outcome_unknown(&state, "x1", 500, &sig);

    // Chain confirms a transfer, but of the WRONG amount.
    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: "999999".into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(
        report.settled, 0,
        "a wrong-amount transfer is NEVER settled"
    );
    assert_eq!(report.failed, 0, "and NEVER released -- the money moved");
    assert_eq!(report.mismatch, 1, "flagged as a fail-closed mismatch");

    assert_eq!(
        block_on(attempt_state(&state, "x1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
        "held for operator review"
    );
    assert_eq!(
        block_on(reservation_status(&state, "x1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "hold RETAINED on an amount mismatch"
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// #469: a spec-valid OVERPAYMENT settles and captures only the owed hold
// --------------------------------------------------------------------------

/// The observed on-chain amount persisted on the attempt row (the durable
/// evidence that separates an overpaid settlement from an exact one).
async fn stored_settled_atomic_amount(state: &AppState, attempt_id: &str) -> Option<String> {
    state
        .repositories_arc()
        .get_payment_attempt(attempt_id)
        .await
        .expect("get attempt")
        .expect("attempt exists")
        .settled_atomic_amount
}

/// The message of the audit event recorded for `attempt_id` with `action`.
fn audit_message(state: &AppState, attempt_id: &str, action: &str) -> String {
    block_on(state.repositories_arc().audit_events())
        .into_iter()
        .find(|event| event.target == attempt_id && event.action == action)
        .unwrap_or_else(|| panic!("audit event {action} for {attempt_id}"))
        .message
}

#[test]
fn reconcile_confirmed_overpayment_settles_and_captures_only_the_owed_hold() {
    // The x402 SVM `exact` scheme calls a transfer that EXCEEDS the required
    // amount a MATCHING transfer. Before #469 the reconciler required an exact
    // match, so this confirmed-on-chain money was classified a mismatch and parked
    // in outcome_unknown forever: the merchant kept the funds, the hold was never
    // captured, and the tenant's credits stayed reserved. It must settle.
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(50);
    seed_outcome_unknown(&state, "over1", 500, &sig);

    // Owed 1_000_000 atomic; the payer transferred 1_500_000.
    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: "1500000".into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.scanned, 1);
    assert_eq!(report.settled, 1, "an overpayment is a spec-valid settle");
    assert_eq!(report.overpaid, 1, "and is broken out as an overpayment");
    assert_eq!(
        report.mismatch, 0,
        "an overpayment is NOT the fail-closed mismatch case"
    );
    assert_eq!(report.pending, 0);
    assert_eq!(report.errored, 0);

    assert_eq!(
        block_on(attempt_state(&state, "over1")),
        PAYMENT_ATTEMPT_SETTLED,
        "terminal, not stranded in outcome_unknown"
    );
    assert_eq!(
        block_on(reservation_status(&state, "over1")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED),
        "the hold is CAPTURED"
    );
    // The capture debits ONLY the credits the hold reserved for the owed amount --
    // the on-chain excess is the payer's and is never swept into the capture.
    assert_eq!(
        block_on(wallet_balance(&state)),
        9_500,
        "captured the owed hold (500 credits), never more"
    );

    // Evidence stays honest: the durable row records what the CHAIN transferred,
    // which differs from what was owed.
    assert_eq!(
        block_on(stored_settled_atomic_amount(&state, "over1")).as_deref(),
        Some("1500000"),
        "the observed on-chain amount is persisted verbatim"
    );
    let message = audit_message(&state, "over1", "x402.settlement.settled");
    assert!(
        message.contains("EXCEEDING") && message.contains("excess 500000"),
        "the audit event names the overpayment and its excess: {message}"
    );
}

#[test]
fn reconcile_overpaid_and_exact_settlements_are_not_flattened_together() {
    // Two attempts settle in the SAME batch -- one exact, one overpaid. Both reach
    // `settled`, but their persisted evidence must stay distinguishable.
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let exact_sig = signature(51);
    let over_sig = signature(52);
    seed_outcome_unknown(&state, "e1", 500, &exact_sig);
    seed_outcome_unknown(&state, "e2", 500, &over_sig);

    let rpc = FakeOnChainRpc::default()
        .with(
            &exact_sig,
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: OWED_ATOMIC.into(),
            },
        )
        .with(
            &over_sig,
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: "1000001".into(),
            },
        );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.settled, 2, "both settle");
    assert_eq!(report.overpaid, 1, "exactly one of them overpaid");

    assert_eq!(
        block_on(stored_settled_atomic_amount(&state, "e1")).as_deref(),
        Some(OWED_ATOMIC),
        "the exact settle records the owed amount"
    );
    assert_eq!(
        block_on(stored_settled_atomic_amount(&state, "e2")).as_deref(),
        Some("1000001"),
        "the overpaid settle records the larger observed amount"
    );
    let exact_message = audit_message(&state, "e1", "x402.settlement.settled");
    let over_message = audit_message(&state, "e2", "x402.settlement.settled");
    assert!(
        exact_message.contains("exact owed amount"),
        "exact audit message: {exact_message}"
    );
    assert!(
        over_message.contains("EXCEEDING") && over_message.contains("excess 1"),
        "overpaid audit message: {over_message}"
    );
    assert_ne!(
        exact_message, over_message,
        "an overpaid settlement is never flattened into an exact one"
    );
    // Each hold captured for its own owed amount only.
    assert_eq!(block_on(wallet_balance(&state)), 10_000 - 500 - 500);
}

#[test]
fn reconcile_underpayment_still_fails_closed_next_to_an_overpayment() {
    // #469 relaxes ONLY the upper side: a transfer SHORT of what is owed keeps the
    // money-protective fail-closed behaviour (never settled, never released).
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let under_sig = signature(53);
    seed_outcome_unknown(&state, "u1", 500, &under_sig);

    let rpc = FakeOnChainRpc::default().with(
        &under_sig,
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: "999999".into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.settled, 0, "an underpayment is NEVER settled");
    assert_eq!(report.overpaid, 0);
    assert_eq!(report.mismatch, 1, "it stays the fail-closed mismatch");
    assert_eq!(
        block_on(attempt_state(&state, "u1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, "u1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "hold retained, never captured on a short transfer"
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// Per-attempt error isolation: one bad attempt never aborts the batch
// --------------------------------------------------------------------------

#[test]
fn reconcile_batch_isolates_per_attempt_failure() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let bad_sig = signature(7);
    let good_sig = signature(8);
    // Parked oldest-first (same updated_at) then ordered by id: "g1" precedes
    // "g2" so the healthy one is proven to settle regardless of the other's error.
    seed_outcome_unknown(&state, "g1", 500, &bad_sig);
    seed_outcome_unknown(&state, "g2", 700, &good_sig);

    let rpc = FakeOnChainRpc::default()
        .with_error(&bad_sig, "rpc timeout")
        .with(
            &good_sig,
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: OWED_ATOMIC.into(),
            },
        );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.scanned, 2);
    assert_eq!(report.errored, 1, "the RPC failure is isolated");
    assert_eq!(report.settled, 1, "the healthy attempt still settles");

    // The errored attempt is untouched: outcome_unknown, hold retained.
    assert_eq!(
        block_on(attempt_state(&state, "g1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, "g1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "an RPC error never moves the hold"
    );
    // The healthy attempt settled despite the sibling error.
    assert_eq!(
        block_on(attempt_state(&state, "g2")),
        PAYMENT_ATTEMPT_SETTLED
    );
    assert_eq!(
        block_on(reservation_status(&state, "g2")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
}

// --------------------------------------------------------------------------
// No recoverable signature -> re-parked, never failed
// --------------------------------------------------------------------------

#[test]
fn reconcile_signatureless_attempt_is_reparked_not_failed() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    seed_submitted_no_header(&state, "s1", 500);
    // Even far past the confirmation deadline, with no signature there is nothing
    // to verify: it must be re-parked, NEVER failed.
    let rpc = FakeOnChainRpc::default();

    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.scanned, 1);
    assert_eq!(
        report.skipped, 1,
        "no signature to verify -> skipped (re-parked)"
    );
    assert_eq!(
        report.failed, 0,
        "absence of a signature is never a failure"
    );

    assert_eq!(
        block_on(attempt_state(&state, "s1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
        "a bare submitted attempt is re-parked to defer its next check"
    );
    assert_eq!(
        block_on(reservation_status(&state, "s1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "hold RETAINED"
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// #399: the reconciler resolves from the persisted column signature alone
// --------------------------------------------------------------------------

#[test]
fn reconcile_recovers_persisted_column_signature_without_merchant_header() {
    // A submitted attempt whose signature was persisted at submit (#399) but which
    // carries NO merchant PAYMENT-RESPONSE header. The reconciler must recover the
    // signature from the durable column (the header fallback has nothing to
    // parse), verify it on-chain, and settle -- exactly the production case the
    // issue targets, where the merchant header is absent but the attempt still
    // needs to reconcile.
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(40);
    seed_submitted_with_column_signature(&state, "col1", 500, &sig);

    // Prove the ONLY signature source is the column: no merchant header was stored.
    let stored = block_on(state.repositories_arc().get_payment_attempt("col1"))
        .expect("get attempt")
        .expect("attempt exists");
    assert_eq!(
        stored.transaction_signature.as_deref(),
        Some(sig.as_str()),
        "the signature is durable in the column"
    );
    assert_eq!(
        stored.settlement_response, None,
        "no merchant header -- the reconciler cannot fall back to parsing one"
    );

    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: OWED_ATOMIC.into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(
        report.settled, 1,
        "the reconciler recovered the column signature and settled"
    );
    assert_eq!(
        block_on(attempt_state(&state, "col1")),
        PAYMENT_ATTEMPT_SETTLED
    );
    assert_eq!(
        block_on(reservation_status(&state, "col1")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED),
        "the hold is captured on the reconciler-driven settle"
    );
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
}

#[test]
fn reconcile_pending_persists_recovered_signature_into_the_column() {
    // On a pending re-park the reconciler persists the signature it recovered from
    // the merchant header into the durable column (#399), so a later tick reads it
    // from storage directly rather than re-parsing the untrusted header. The hold
    // stays retained and the state stays outcome_unknown.
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig = signature(41);
    seed_outcome_unknown(&state, "col2", 500, &sig);
    // Seeded via a merchant header only; the column starts empty.
    assert_eq!(
        block_on(state.repositories_arc().get_payment_attempt("col2"))
            .expect("get")
            .expect("exists")
            .transaction_signature,
        None,
        "column empty until the reconciler persists it"
    );

    let rpc = FakeOnChainRpc::default().with(&sig, OnChainSettlementStatus::Pending);
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report.pending, 1);
    assert_eq!(
        block_on(state.repositories_arc().get_payment_attempt("col2"))
            .expect("get")
            .expect("exists")
            .transaction_signature
            .as_deref(),
        Some(sig.as_str()),
        "the recovered signature is now durable in the column"
    );
    assert_eq!(
        block_on(attempt_state(&state, "col2")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, "col2")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "hold retained while pending"
    );
}

// --------------------------------------------------------------------------
// Disabled reconciler is a complete no-op
// --------------------------------------------------------------------------

#[test]
fn reconcile_disabled_is_noop() {
    let state = seed_state(10_000, reconciler_config(false, 100, 60, 900));
    let sig = signature(9);
    seed_outcome_unknown(&state, "d1", 500, &sig);

    let rpc = FakeOnChainRpc::default().with(
        &sig,
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: OWED_ATOMIC.into(),
        },
    );
    let report = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(report, X402ReconcileReport::default(), "disabled = no-op");
    assert_eq!(
        block_on(attempt_state(&state, "d1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(reservation_status(&state, "d1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );

    // The always-spawned production tick also no-ops (enabled=false short-circuits
    // before it would look for an on-chain RPC client).
    let tick = block_on(state.reconcile_x402_settlements_tick(RECONCILE_NOW));
    assert_eq!(tick, X402ReconcileReport::default());
}

// --------------------------------------------------------------------------
// Bounded batch: the reconcile is paged by `max_reconciles_per_tick`
// --------------------------------------------------------------------------

#[test]
fn reconcile_batch_is_bounded_by_max_reconciles_per_tick() {
    let state = seed_state(100_000, reconciler_config(true, 2, 60, 900));
    let mut sigs = HashMap::new();
    for (i, id) in ["b1", "b2", "b3"].into_iter().enumerate() {
        let sig = signature(20 + i as u8);
        seed_outcome_unknown(&state, id, 500, &sig);
        sigs.insert(id, sig);
    }
    let mut rpc = FakeOnChainRpc::default();
    for sig in sigs.values() {
        rpc = rpc.with(
            sig,
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: OWED_ATOMIC.into(),
            },
        );
    }

    // First tick settles at most 2, leaving one still outcome_unknown.
    let first = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW));
    assert_eq!(first.scanned, 2, "batch capped at max_reconciles_per_tick");
    assert_eq!(first.settled, 2);
    let still_unknown = ["b1", "b2", "b3"]
        .into_iter()
        .filter(|id| block_on(attempt_state(&state, id)) == PAYMENT_ATTEMPT_OUTCOME_UNKNOWN)
        .count();
    assert_eq!(still_unknown, 1, "one attempt remains for the next page");

    // Second tick drains the remainder.
    let second = block_on(state.reconcile_x402_settlements_once(&rpc, RECONCILE_NOW + 1));
    assert_eq!(second.scanned, 1);
    assert_eq!(second.settled, 1);
    for id in ["b1", "b2", "b3"] {
        assert_eq!(block_on(attempt_state(&state, id)), PAYMENT_ATTEMPT_SETTLED);
    }
}

// --------------------------------------------------------------------------
// Concurrent reconciles settle each attempt exactly once (barrier, no sleeps)
// --------------------------------------------------------------------------

#[test]
fn concurrent_reconciles_settle_each_attempt_exactly_once() {
    let state = seed_state(10_000, reconciler_config(true, 100, 60, 900));
    let sig1 = signature(30);
    let sig2 = signature(31);
    seed_outcome_unknown(&state, "k1", 500, &sig1);
    seed_outcome_unknown(&state, "k2", 700, &sig2);
    let rpc = Arc::new(
        FakeOnChainRpc::default()
            .with(
                &sig1,
                OnChainSettlementStatus::Confirmed {
                    settled_atomic_amount: OWED_ATOMIC.into(),
                },
            )
            .with(
                &sig2,
                OnChainSettlementStatus::Confirmed {
                    settled_atomic_amount: OWED_ATOMIC.into(),
                },
            ),
    );

    block_on(async {
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let (state_a, state_b) = (state.clone(), state.clone());
        let (rpc_a, rpc_b) = (Arc::clone(&rpc), Arc::clone(&rpc));
        let (b_a, b_b) = (Arc::clone(&barrier), Arc::clone(&barrier));
        let task_a = async move {
            b_a.wait().await;
            state_a
                .reconcile_x402_settlements_once(rpc_a.as_ref(), RECONCILE_NOW)
                .await
        };
        let task_b = async move {
            b_b.wait().await;
            state_b
                .reconcile_x402_settlements_once(rpc_b.as_ref(), RECONCILE_NOW)
                .await
        };
        let (ra, rb) = tokio::join!(task_a, task_b);
        // The SETTLE edge is idempotent under the CAS generation token, so a
        // concurrent double-drive of the same batch never errors: a loser observes
        // the already-settled attempt and replays idempotently.
        assert_eq!(ra.errored, 0, "no per-attempt errors under concurrency");
        assert_eq!(rb.errored, 0, "no per-attempt errors under concurrency");
        assert!(
            ra.settled + rb.settled >= 2,
            "both attempts settled across the two concurrent reconciles"
        );
    });

    for id in ["k1", "k2"] {
        assert_eq!(block_on(attempt_state(&state, id)), PAYMENT_ATTEMPT_SETTLED);
        assert_eq!(
            block_on(reservation_status(&state, id)).as_deref(),
            Some(WALLET_RESERVATION_SETTLED)
        );
    }
    // Each hold captured exactly once: balance debited by 500 + 700 only.
    assert_eq!(block_on(wallet_balance(&state)), 10_000 - 500 - 700);
}

// --------------------------------------------------------------------------
// Trust-order decision table (pure), covering the deadline boundary + mismatch
// --------------------------------------------------------------------------

#[test]
fn trust_order_decision_table() {
    // Confirmed exact -> settle, and NOT flagged as an overpayment.
    assert_eq!(
        decide_reconcile(
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: "1000000".into()
            },
            "1000000",
            Some(200),
            100_000,
            900,
        ),
        ReconcileDecision::Settle {
            settled_atomic_amount: "1000000".into(),
            overpayment_atomic_amount: None,
        }
    );
    // Confirmed SHORT of the owed amount (even with a leading-zero form) -> never
    // settle: underpayment stays fail-closed.
    assert_eq!(
        decide_reconcile(
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: "999999".into()
            },
            "1000000",
            Some(200),
            100_000,
            900,
        ),
        ReconcileDecision::Mismatch {
            observed_atomic_amount: "999999".into()
        }
    );
    // Confirmed exact, canonical-decimal equality ignores leading zeros.
    assert_eq!(
        decide_reconcile(
            OnChainSettlementStatus::Confirmed {
                settled_atomic_amount: "01000000".into()
            },
            "1000000",
            Some(200),
            100_000,
            900,
        ),
        ReconcileDecision::Settle {
            settled_atomic_amount: "01000000".into(),
            overpayment_atomic_amount: None,
        }
    );
    // Chain-rejected -> fail regardless of the deadline.
    assert!(matches!(
        decide_reconcile(
            OnChainSettlementStatus::Failed { reason: "x".into() },
            "1000000",
            Some(200),
            300,
            900,
        ),
        ReconcileDecision::Fail { .. }
    ));
    // Absent BEFORE the deadline -> pending; AT/after -> fail.
    assert_eq!(
        decide_reconcile(
            OnChainSettlementStatus::NotFound,
            "1000000",
            Some(200),
            1_099,
            900,
        ),
        ReconcileDecision::Pending
    );
    assert!(matches!(
        decide_reconcile(
            OnChainSettlementStatus::NotFound,
            "1000000",
            Some(200),
            1_100,
            900,
        ),
        ReconcileDecision::Fail { .. }
    ));
    // Pending is ALWAYS pending, even past the deadline (its money may confirm).
    assert_eq!(
        decide_reconcile(
            OnChainSettlementStatus::Pending,
            "1000000",
            Some(200),
            100_000,
            900,
        ),
        ReconcileDecision::Pending
    );
    // Absent with no submission time is never past a deadline -> pending.
    assert_eq!(
        decide_reconcile(
            OnChainSettlementStatus::NotFound,
            "1000000",
            None,
            100_000,
            900,
        ),
        ReconcileDecision::Pending
    );
}

// --------------------------------------------------------------------------
// #469: the confirmed-amount comparison is INTEGER, not lexical
// --------------------------------------------------------------------------

/// `decide_reconcile` for a CONFIRMED transfer, with the deadline inputs pinned
/// (they are irrelevant to a confirmed status).
fn decide_confirmed(owed: &str, settled: &str) -> ReconcileDecision {
    decide_reconcile(
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount: settled.into(),
        },
        owed,
        Some(200),
        100_000,
        900,
    )
}

fn settle(settled: &str, overpayment: Option<&str>) -> ReconcileDecision {
    ReconcileDecision::Settle {
        settled_atomic_amount: settled.into(),
        overpayment_atomic_amount: overpayment.map(str::to_string),
    }
}

fn mismatch(observed: &str) -> ReconcileDecision {
    ReconcileDecision::Mismatch {
        observed_atomic_amount: observed.into(),
    }
}

#[test]
fn confirmed_amount_comparison_is_integer_not_lexical() {
    // Overpayment settles, carrying the excess (settled - owed) as evidence.
    assert_eq!(
        decide_confirmed("1000000", "1500000"),
        settle("1500000", Some("500000")),
        "a transfer exceeding the owed amount is spec-valid and settles"
    );
    // Exact settles with NO excess.
    assert_eq!(
        decide_confirmed("1000000", "1000000"),
        settle("1000000", None)
    );
    // Underpayment -- by a single atomic unit -- still fails closed.
    assert_eq!(decide_confirmed("1000000", "999999"), mismatch("999999"));

    // THE LEXICAL TRAP. A string comparison reads "10" < "9" (it compares '1'
    // against '9'), so a lexical implementation would call this overpayment an
    // underpayment and fail-close confirmed money...
    assert_eq!(
        decide_confirmed("9", "10"),
        settle("10", Some("1")),
        "owed 9, settled 10 must SETTLE -- a string compare would say \"10\" < \"9\""
    );
    // ...and its mirror: lexically "9" > "10", so a lexical implementation would
    // SETTLE a real underpayment. Integer comparison rejects it.
    assert_eq!(
        decide_confirmed("10", "9"),
        mismatch("9"),
        "owed 10, settled 9 must NOT settle -- a string compare would say \"9\" > \"10\""
    );

    // Leading zeros are canonicalised by the parse on both sides.
    assert_eq!(
        decide_confirmed("1000000", "01500000"),
        settle("01500000", Some("500000"))
    );
    assert_eq!(
        decide_confirmed("01000000", "1000000"),
        settle("1000000", None)
    );
}

#[test]
fn confirmed_amount_comparison_handles_u64_boundaries_without_overflow() {
    let max = u64::MAX.to_string();
    let max_minus_one = (u64::MAX - 1).to_string();

    // The largest representable on-chain amount, paid exactly.
    assert_eq!(decide_confirmed(&max, &max), settle(&max, None));
    // One atomic unit short of it is still an underpayment.
    assert_eq!(
        decide_confirmed(&max, &max_minus_one),
        mismatch(&max_minus_one)
    );
    // One atomic unit over the u64 domain: the comparison and the excess are done
    // in u128, so the maximal overpayment neither overflows nor wraps.
    assert_eq!(
        decide_confirmed("1", &max),
        settle(&max, Some(&(u64::MAX as u128 - 1).to_string()))
    );
    assert_eq!(
        decide_confirmed(&max_minus_one, &max),
        settle(&max, Some("1"))
    );
    // Zero owed: any confirmed transfer covers it.
    assert_eq!(decide_confirmed("0", "0"), settle("0", None));
    assert_eq!(decide_confirmed("0", "1"), settle("1", Some("1")));
}

#[test]
fn confirmed_amount_that_does_not_parse_stays_fail_closed() {
    // An amount that is not a canonical unsigned decimal is NEVER treated as
    // satisfying the owed threshold -- it is the pre-#469 conservative behaviour,
    // deliberately unchanged: mismatch, hold retained, operator review.
    for observed in [
        "",
        "abc",
        "1.5",                                       // no decimal point on the atomic path
        "-1",                                        // negative is not an atomic amount
        " 1000000",                                  // whitespace is not canonical
        "1e6",                                       // no float/exponent notation on the money path
        "1_000_000", // Rust literal separators are not a wire format
        "99999999999999999999999999999999999999999", // wider than u128
    ] {
        assert_eq!(
            decide_confirmed("1000000", observed),
            mismatch(observed),
            "unparseable observed amount {observed:?} must fail closed"
        );
    }
    // An unparseable OWED amount is equally fail-closed: with nothing to compare
    // against, a confirmed transfer can never be proven to cover it.
    assert_eq!(
        decide_confirmed("not-a-number", "1000000"),
        mismatch("1000000")
    );
    assert_eq!(decide_confirmed("", "1000000"), mismatch("1000000"));

    // Documented quirk of the parse path, INHERITED unchanged from the pre-#469
    // `atomic_amounts_match` (both use `str::parse`): Rust's integer parser
    // accepts an explicit leading `+`, so "+1000000" is the integer 1000000 and
    // settles as an exact transfer -- exactly as it did before this change. Pinned
    // here so the behaviour is a recorded decision rather than a surprise; the
    // value is still parsed as an INTEGER, never taken on trust as a string.
    assert_eq!(
        decide_confirmed("1000000", "+1000000"),
        settle("+1000000", None)
    );
    assert_eq!(
        decide_confirmed("1000000", "+999999"),
        mismatch("+999999"),
        "the leading `+` never bypasses the underpayment check"
    );
}
