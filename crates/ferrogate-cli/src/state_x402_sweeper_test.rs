// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Focused async tests for the background x402 TTL sweeper (issue
// #354). Proves the money-safe contract: a due, past-TTL pre-submission attempt
// is expired and its hold released; a not-yet-due attempt is untouched; a
// settled/terminal attempt is never touched; a submitted (ambiguous) attempt is
// never fetched and never released (hold retained -- that is outcome_unknown,
// the reconciler's job); one bad attempt in a batch never aborts the rest; the
// batch is bounded (paged) by `max_expiries_per_tick`; the `hold_ttl_grace_secs`
// knob delays expiry. Concurrency is exercised with a barrier, not timing
// sleeps, and every "clock" is the injected `now_unix`, never real time.

use std::sync::Arc;

use ferrogate_storage::{
    StoredPaymentAttempt, StoredWallet, PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_RELEASED,
    PAYMENT_ATTEMPT_SETTLED, PAYMENT_ATTEMPT_SUBMITTED, WALLET_RESERVATION_ACTIVE,
    WALLET_RESERVATION_RELEASED, WALLET_RESERVATION_SETTLED,
};

use super::super::state_x402_settlement::{PaidEgressOpen, SettlementEvidence};
use super::super::AppState;
use super::*;
use crate::config::{Config, X402SweeperConfig};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

const TENANT: &str = "tenant-x402-sweep";

/// TTL 3600 opened at now=100 => the hold expires at 3700.
const OPEN_AT: i64 = 100;
const HOLD_TTL_SECS: i64 = 3_600;

fn sweeper_config(enabled: bool, max_expiries_per_tick: usize, grace: i64) -> X402SweeperConfig {
    X402SweeperConfig {
        enabled,
        tick_interval_secs: 30,
        max_expiries_per_tick,
        hold_ttl_grace_secs: grace,
    }
}

fn seed_state(balance_credits: i64, sweeper: X402SweeperConfig) -> AppState {
    let state = AppState::new(Config {
        x402_sweeper: sweeper,
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
        network_caip2: "solana:mainnet".into(),
        mint: "So11111111111111111111111111111111111111112".into(),
        atomic_amount: "1000000".into(),
        recipient: "RecipientPubkey1111111111111111111111111111".into(),
        credits_amount,
        conversion_version: Some("conv-v1".into()),
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_ttl_secs: HOLD_TTL_SECS,
    }
}

/// Opens an authorized (pre-submission) attempt with a live hold expiring at
/// `OPEN_AT + HOLD_TTL_SECS` (3700).
fn open_authorized(state: &AppState, attempt_id: &str, credits: i64) {
    block_on(
        state
            .x402_settlement_loop()
            .open(&open_request(attempt_id, credits), OPEN_AT),
    )
    .expect("open");
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

async fn wallet_balance(state: &AppState) -> i64 {
    state
        .get_wallet(TENANT)
        .await
        .expect("get wallet")
        .expect("wallet exists")
        .balance_credits
}

// --------------------------------------------------------------------------
// Due, past-TTL pre-submission attempt -> expired + hold released
// --------------------------------------------------------------------------

#[test]
fn sweep_expires_due_attempt_and_releases_hold() {
    let state = seed_state(10_000, sweeper_config(true, 100, 0));
    open_authorized(&state, "d1", 500);

    // now=4000 > 3700: the hold is past TTL.
    let report = block_on(state.sweep_x402_expired_attempts_once(4_000));
    assert_eq!(report.scanned, 1, "one due candidate");
    assert_eq!(report.released, 1, "released the overdue hold");
    assert_eq!(report.skipped, 0);
    assert_eq!(report.outcome_unknown, 0);
    assert_eq!(report.failed, 0);

    assert_eq!(
        block_on(attempt_state(&state, "d1")),
        PAYMENT_ATTEMPT_RELEASED
    );
    assert_eq!(
        block_on(reservation_status(&state, "d1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
    // Release restores available balance; actual balance never moved.
    assert_eq!(block_on(wallet_balance(&state)), 10_000);

    // Idempotent: a second sweep finds nothing due (the hold is no longer active).
    let again = block_on(state.sweep_x402_expired_attempts_once(5_000));
    assert_eq!(again.scanned, 0);
    assert_eq!(again.released, 0);
}

// --------------------------------------------------------------------------
// Not-yet-due attempt -> untouched
// --------------------------------------------------------------------------

#[test]
fn sweep_leaves_not_yet_due_attempt_untouched() {
    let state = seed_state(10_000, sweeper_config(true, 100, 0));
    open_authorized(&state, "n1", 500);

    // now=3000 < 3700: not due yet.
    let report = block_on(state.sweep_x402_expired_attempts_once(3_000));
    assert_eq!(report.scanned, 0, "nothing is due");
    assert_eq!(report.released, 0);

    assert_eq!(
        block_on(attempt_state(&state, "n1")),
        PAYMENT_ATTEMPT_AUTHORIZED
    );
    assert_eq!(
        block_on(reservation_status(&state, "n1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
}

// --------------------------------------------------------------------------
// Settled / terminal attempt -> never touched
// --------------------------------------------------------------------------

#[test]
fn sweep_never_touches_settled_terminal_attempt() {
    let state = seed_state(10_000, sweeper_config(true, 100, 0));
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("t1", 500), OPEN_AT)).expect("open");
    block_on(loop_.submit("t1", None, 200, 200)).expect("submit");
    block_on(loop_.finalize(
        "t1",
        &SettlementEvidence::Settled {
            transaction_signature: "sig-1",
            settled_atomic_amount: "1000000",
            response: Some("{\"ok\":true}"),
        },
        300,
    ))
    .expect("finalize settled");
    assert_eq!(block_on(wallet_balance(&state)), 9_500);

    // Even far past any TTL, a settled attempt (hold captured, not active) is
    // never a sweep candidate and is never released.
    let report = block_on(state.sweep_x402_expired_attempts_once(9_999_999));
    assert_eq!(report.scanned, 0, "settled hold is not active, so not due");
    assert_eq!(report.released, 0);

    assert_eq!(
        block_on(attempt_state(&state, "t1")),
        PAYMENT_ATTEMPT_SETTLED
    );
    assert_eq!(
        block_on(reservation_status(&state, "t1")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
}

// --------------------------------------------------------------------------
// Submitted (ambiguous) attempt -> never fetched, never released, hold retained
// --------------------------------------------------------------------------

#[test]
fn sweep_never_releases_submitted_attempt_hold_retained() {
    let state = seed_state(10_000, sweeper_config(true, 100, 0));
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("s1", 500), OPEN_AT)).expect("open");
    // Proof went on-chain: after submission, a timed-out attempt is ambiguous
    // and its stablecoin may have moved. It must NEVER be released by the sweeper.
    block_on(loop_.submit("s1", None, 200, 200)).expect("submit");

    // Money-safety at the read layer: a submitted attempt is excluded from the
    // due-query even though its hold is active and past TTL.
    let due = block_on(
        state
            .repositories_arc()
            .list_expirable_due_payment_attempts(9_999_999, 100),
    )
    .expect("list due");
    assert!(
        due.iter().all(|a| a.id != "s1"),
        "a submitted attempt must never be a sweep candidate: {due:?}"
    );

    // And the full sweep leaves it submitted with the hold retained (active).
    let report = block_on(state.sweep_x402_expired_attempts_once(9_999_999));
    assert_eq!(report.scanned, 0);
    assert_eq!(report.released, 0);
    assert_eq!(report.outcome_unknown, 0);

    assert_eq!(
        block_on(attempt_state(&state, "s1")),
        PAYMENT_ATTEMPT_SUBMITTED
    );
    assert_eq!(
        block_on(reservation_status(&state, "s1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE),
        "the submitted attempt's hold is RETAINED, never released"
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// Per-attempt error isolation: one bad attempt never aborts the batch
// --------------------------------------------------------------------------

#[test]
fn sweep_batch_isolates_per_attempt_failure() {
    let state = seed_state(10_000, sweeper_config(true, 100, 0));
    open_authorized(&state, "g1", 500);

    // Real due candidate for g1, plus a poisoned entry whose id has no row: its
    // `expire_if_due` fails closed (NotFound). Ordered poison-FIRST so we prove a
    // failure does not abort the rest of the batch.
    let due = block_on(
        state
            .repositories_arc()
            .list_expirable_due_payment_attempts(4_000, 100),
    )
    .expect("list due");
    assert_eq!(due.len(), 1);
    let mut ghost: StoredPaymentAttempt = due[0].clone();
    ghost.id = "ghost-no-such-row".into();
    let batch = vec![ghost, due[0].clone()];

    let report = block_on(state.expire_x402_attempt_batch(&batch, 4_000));
    assert_eq!(report.scanned, 2);
    assert_eq!(
        report.failed, 1,
        "the poisoned attempt is isolated as a failure"
    );
    assert_eq!(report.released, 1, "the healthy attempt is still released");

    // g1 was released despite the earlier failure in the same batch.
    assert_eq!(
        block_on(attempt_state(&state, "g1")),
        PAYMENT_ATTEMPT_RELEASED
    );
    assert_eq!(
        block_on(reservation_status(&state, "g1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
}

// --------------------------------------------------------------------------
// Bounded batch: the sweep is paged by `max_expiries_per_tick`
// --------------------------------------------------------------------------

#[test]
fn sweep_batch_is_bounded_by_max_expiries_per_tick() {
    let state = seed_state(100_000, sweeper_config(true, 2, 0));
    for id in ["b1", "b2", "b3"] {
        open_authorized(&state, id, 500);
    }

    // First tick expires at most 2, leaving one still-authorized.
    let first = block_on(state.sweep_x402_expired_attempts_once(4_000));
    assert_eq!(first.scanned, 2, "batch is capped at max_expiries_per_tick");
    assert_eq!(first.released, 2);

    let still_authorized = ["b1", "b2", "b3"]
        .into_iter()
        .filter(|id| block_on(attempt_state(&state, id)) == PAYMENT_ATTEMPT_AUTHORIZED)
        .count();
    assert_eq!(still_authorized, 1, "one attempt remains for the next page");

    // Second tick drains the remainder.
    let second = block_on(state.sweep_x402_expired_attempts_once(4_100));
    assert_eq!(second.scanned, 1);
    assert_eq!(second.released, 1);
    for id in ["b1", "b2", "b3"] {
        assert_eq!(
            block_on(attempt_state(&state, id)),
            PAYMENT_ATTEMPT_RELEASED
        );
    }
    assert_eq!(block_on(wallet_balance(&state)), 100_000);
}

// --------------------------------------------------------------------------
// The `hold_ttl_grace_secs` knob delays expiry
// --------------------------------------------------------------------------

#[test]
fn sweep_respects_hold_ttl_grace_window() {
    // grace 1000: an attempt is due only once `expires_at + 1000 <= now`.
    let state = seed_state(10_000, sweeper_config(true, 100, 1_000));
    open_authorized(&state, "w1", 500);

    // now=4000: expires_at (3700) elapsed, but within the 1000s grace
    // (due_before = 4000 - 1000 = 3000 < 3700). Not yet swept.
    let within_grace = block_on(state.sweep_x402_expired_attempts_once(4_000));
    assert_eq!(within_grace.scanned, 0, "grace window defers the sweep");
    assert_eq!(
        block_on(attempt_state(&state, "w1")),
        PAYMENT_ATTEMPT_AUTHORIZED
    );

    // now=5000: due_before = 4000 >= 3700. Now past the grace -> swept.
    let past_grace = block_on(state.sweep_x402_expired_attempts_once(5_000));
    assert_eq!(past_grace.scanned, 1);
    assert_eq!(past_grace.released, 1);
    assert_eq!(
        block_on(attempt_state(&state, "w1")),
        PAYMENT_ATTEMPT_RELEASED
    );
}

// --------------------------------------------------------------------------
// Disabled sweeper is a complete no-op
// --------------------------------------------------------------------------

#[test]
fn sweep_disabled_is_noop() {
    let state = seed_state(10_000, sweeper_config(false, 100, 0));
    open_authorized(&state, "x1", 500);

    let report = block_on(state.sweep_x402_expired_attempts_once(9_999_999));
    assert_eq!(report, X402SweepReport::default(), "disabled = no-op");
    assert_eq!(
        block_on(attempt_state(&state, "x1")),
        PAYMENT_ATTEMPT_AUTHORIZED
    );
    assert_eq!(
        block_on(reservation_status(&state, "x1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
}

// --------------------------------------------------------------------------
// Concurrent sweeps release each hold exactly once (barrier, no timing sleeps)
// --------------------------------------------------------------------------

#[test]
fn concurrent_sweeps_release_each_hold_exactly_once() {
    let state = seed_state(10_000, sweeper_config(true, 100, 0));
    open_authorized(&state, "c1", 500);
    open_authorized(&state, "c2", 700);

    block_on(async {
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let state_a = state.clone();
        let state_b = state.clone();
        let b_a = Arc::clone(&barrier);
        let b_b = Arc::clone(&barrier);
        let task_a = async move {
            b_a.wait().await;
            state_a.sweep_x402_expired_attempts_once(4_000).await
        };
        let task_b = async move {
            b_b.wait().await;
            state_b.sweep_x402_expired_attempts_once(4_000).await
        };
        let (ra, rb) = tokio::join!(task_a, task_b);
        // The release edge is idempotent, so a concurrent double-drive of the
        // same due batch never errors (a loser observes the already-released
        // hold and either skips or replays idempotently). The durable
        // exactly-once guarantee is asserted below on the reservation state.
        assert_eq!(ra.failed, 0, "no per-attempt failures under concurrency");
        assert_eq!(rb.failed, 0, "no per-attempt failures under concurrency");
        assert!(
            ra.released + rb.released >= 2,
            "both holds were released across the two concurrent sweeps"
        );
    });

    for id in ["c1", "c2"] {
        assert_eq!(
            block_on(attempt_state(&state, id)),
            PAYMENT_ATTEMPT_RELEASED
        );
        assert_eq!(
            block_on(reservation_status(&state, id)).as_deref(),
            Some(WALLET_RESERVATION_RELEASED)
        );
    }
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}
