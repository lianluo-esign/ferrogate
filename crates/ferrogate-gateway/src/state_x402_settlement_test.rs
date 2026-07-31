// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Focused async tests for the x402 managed paid-egress
// settle/release loop (issue #354). Proves each edge is TWO idempotent
// primitives, that a simulated async-timeout between the two primitives yields
// `outcome_unknown` with the hold retained (never a false failure/release), and
// a proptest invariant that total captured credits never exceed the authorized
// holds. Concurrency is exercised with a barrier, not timing sleeps.

use std::sync::Arc;

use ferrogate_storage::{
    StoredWallet, PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_FAILED,
    PAYMENT_ATTEMPT_OUTCOME_UNKNOWN, PAYMENT_ATTEMPT_RELEASED, PAYMENT_ATTEMPT_SETTLED,
    PAYMENT_ATTEMPT_SUBMITTED, WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_RELEASED,
    WALLET_RESERVATION_SETTLED,
};
use proptest::prelude::*;

use super::*;
use ferrogate_config::{x402_hold_ttl_floor_secs, Config, X402ReconcilerConfig};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

const TENANT: &str = "tenant-x402";

fn seed_state(balance_credits: i64) -> AppState {
    seed_state_with_config(Config::default(), balance_credits)
}

fn seed_state_with_config(config: Config, balance_credits: i64) -> AppState {
    let state = AppState::new(config);
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
        hold_ttl_secs: 3_600,
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

async fn reservation_expires_at(state: &AppState, attempt_id: &str) -> Option<i64> {
    state
        .repositories_arc()
        .list_wallet_reservations(TENANT)
        .await
        .expect("list reservations")
        .into_iter()
        .find(|r| r.id == attempt_id)
        .map(|r| r.expires_at_unix)
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
// OPEN
// --------------------------------------------------------------------------

#[test]
fn open_reserves_hold_and_creates_authorized_attempt() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    let outcome = block_on(loop_.open(&open_request("a1", 500), 100)).expect("open");
    match outcome {
        OpenOutcome::Opened { attempt, claimed } => {
            assert_eq!(attempt.state, PAYMENT_ATTEMPT_AUTHORIZED);
            assert_eq!(attempt.hold_id.as_deref(), Some("a1"));
            assert_eq!(attempt.credits_amount, Some(500));
            // The FIRST open on an id is the claim winner; only this caller may
            // go on to sign.
            assert!(claimed, "first open on an attempt id must claim it");
        }
        other => panic!("expected Opened, got {other:?}"),
    }
    assert_eq!(
        block_on(reservation_status(&state, "a1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
}

#[test]
fn open_is_idempotent_on_replay() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("a2", 500), 100)).expect("first open");
    block_on(loop_.open(&open_request("a2", 500), 100)).expect("replay open");
    // Exactly one reservation and one attempt for the idempotency key.
    let reservations = block_on(state.repositories_arc().list_wallet_reservations(TENANT))
        .expect("list reservations");
    assert_eq!(reservations.iter().filter(|r| r.id == "a2").count(), 1);
    // Balance untouched: a hold reduces available, not actual balance.
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

#[test]
fn open_insufficient_funds_places_no_hold_no_attempt() {
    let state = seed_state(100);
    let loop_ = state.x402_settlement_loop();
    let outcome = block_on(loop_.open(&open_request("a3", 500), 100)).expect("open");
    assert!(
        matches!(outcome, OpenOutcome::Insufficient { requested_credits, .. } if requested_credits == 500),
        "expected Insufficient, got {outcome:?}"
    );
    assert_eq!(block_on(reservation_status(&state, "a3")), None);
    assert!(block_on(state.repositories_arc().get_payment_attempt("a3"))
        .expect("get attempt")
        .is_none());
}

// --------------------------------------------------------------------------
// SETTLE edge
// --------------------------------------------------------------------------

fn settled_evidence() -> SettlementEvidence<'static> {
    SettlementEvidence::Settled {
        transaction_signature: "sig-1",
        settled_atomic_amount: "1000000",
        response: Some("{\"ok\":true}"),
    }
}

#[test]
fn settle_edge_captures_hold_and_settles_attempt() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("s1", 500), 100)).expect("open");
    block_on(loop_.submit("s1", None, 200, 200)).expect("submit");
    let outcome = block_on(loop_.finalize("s1", &settled_evidence(), 300)).expect("finalize");
    assert!(
        matches!(outcome, EdgeOutcome::Settled { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        block_on(attempt_state(&state, "s1")),
        PAYMENT_ATTEMPT_SETTLED
    );
    assert_eq!(
        block_on(reservation_status(&state, "s1")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
    // Capture debited the wallet exactly once.
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
}

#[test]
fn settle_edge_is_idempotent_on_reentry() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("s2", 500), 100)).expect("open");
    block_on(loop_.submit("s2", None, 200, 200)).expect("submit");
    block_on(loop_.finalize("s2", &settled_evidence(), 300)).expect("first finalize");
    let second = block_on(loop_.finalize("s2", &settled_evidence(), 400)).expect("replay finalize");
    assert!(matches!(second, EdgeOutcome::Settled { .. }), "{second:?}");
    // No double debit on idempotent re-entry.
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
    assert_eq!(
        block_on(attempt_state(&state, "s2")),
        PAYMENT_ATTEMPT_SETTLED
    );
}

// --------------------------------------------------------------------------
// FAIL edge (definite failure evidence: release + fail)
// --------------------------------------------------------------------------

#[test]
fn fail_edge_releases_hold_and_fails_attempt() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("f1", 500), 100)).expect("open");
    block_on(loop_.submit("f1", None, 200, 200)).expect("submit");
    let outcome = block_on(loop_.finalize(
        "f1",
        &SettlementEvidence::Failed {
            failure_code: "x402_not_submitted",
            response: Some("reverted"),
        },
        300,
    ))
    .expect("finalize failed");
    assert!(matches!(outcome, EdgeOutcome::Failed { .. }), "{outcome:?}");
    assert_eq!(
        block_on(attempt_state(&state, "f1")),
        PAYMENT_ATTEMPT_FAILED
    );
    // Definite failure releases the hold and restores available balance.
    assert_eq!(
        block_on(reservation_status(&state, "f1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
    // Idempotent replay stays failed.
    let replay = block_on(loop_.finalize(
        "f1",
        &SettlementEvidence::Failed {
            failure_code: "x402_not_submitted",
            response: Some("reverted"),
        },
        400,
    ))
    .expect("finalize failed replay");
    assert!(matches!(replay, EdgeOutcome::Failed { .. }), "{replay:?}");
}

// --------------------------------------------------------------------------
// RELEASE edge (pre-submission cancel / TTL)
// --------------------------------------------------------------------------

#[test]
fn release_edge_releases_hold_and_attempt() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("r1", 500), 100)).expect("open");
    let outcome = block_on(loop_.cancel("r1", "x402_cancelled", 150)).expect("cancel");
    assert!(
        matches!(outcome, EdgeOutcome::Released { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        block_on(attempt_state(&state, "r1")),
        PAYMENT_ATTEMPT_RELEASED
    );
    assert_eq!(
        block_on(reservation_status(&state, "r1")).as_deref(),
        Some(WALLET_RESERVATION_RELEASED)
    );
    // Release restores available balance; actual balance never moved.
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
    // Idempotent replay.
    let replay = block_on(loop_.cancel("r1", "x402_cancelled", 160)).expect("cancel replay");
    assert!(matches!(replay, EdgeOutcome::Released { .. }), "{replay:?}");
}

#[test]
fn expire_if_due_releases_expired_pre_submission_hold() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    // TTL 3600 from now=100 -> expires at 3700.
    block_on(loop_.open(&open_request("e1", 500), 100)).expect("open");
    // Before expiry: nothing due.
    assert!(block_on(loop_.expire_if_due("e1", 3_000))
        .expect("not due")
        .is_none());
    // After expiry: released.
    let outcome = block_on(loop_.expire_if_due("e1", 4_000))
        .expect("due")
        .expect("some outcome");
    assert!(
        matches!(outcome, EdgeOutcome::Released { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        block_on(attempt_state(&state, "e1")),
        PAYMENT_ATTEMPT_RELEASED
    );
}

// --------------------------------------------------------------------------
// UNKNOWN evidence
// --------------------------------------------------------------------------

#[test]
fn finalize_unknown_evidence_parks_outcome_unknown_and_retains_hold() {
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("u1", 500), 100)).expect("open");
    block_on(loop_.submit("u1", None, 200, 200)).expect("submit");
    let outcome = block_on(loop_.finalize(
        "u1",
        &SettlementEvidence::Unknown {
            response: Some("timeout"),
            transaction_signature: None,
        },
        300,
    ))
    .expect("finalize unknown");
    assert!(
        matches!(outcome, EdgeOutcome::OutcomeUnknown { parked: true, .. }),
        "{outcome:?}"
    );
    assert_eq!(
        block_on(attempt_state(&state, "u1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    // The hold is RETAINED (still active, never released).
    assert_eq!(
        block_on(reservation_status(&state, "u1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);
}

// --------------------------------------------------------------------------
// #399: the reconciler-facing signature is durable at submit and park time
// --------------------------------------------------------------------------

async fn attempt_signature(state: &AppState, attempt_id: &str) -> Option<String> {
    state
        .repositories_arc()
        .get_payment_attempt(attempt_id)
        .await
        .expect("get attempt")
        .expect("attempt exists")
        .transaction_signature
}

#[test]
fn submit_persists_signature_and_park_retains_it_for_the_reconciler() {
    // #399: persist the on-chain signature the reconciler needs the moment it is
    // known -- at submit, coupled to the authorized->submitted CAS -- and keep it
    // when parking outcome_unknown, without changing any state transition.
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    let sig = "5".repeat(88);
    block_on(loop_.open(&open_request("g1", 500), 100)).expect("open");

    block_on(loop_.submit("g1", Some(&sig), 200, 200)).expect("submit");
    assert_eq!(
        block_on(attempt_state(&state, "g1")),
        PAYMENT_ATTEMPT_SUBMITTED,
        "submit still lands in `submitted` -- state semantics unchanged"
    );
    assert_eq!(
        block_on(attempt_signature(&state, "g1")).as_deref(),
        Some(sig.as_str()),
        "the submitted attempt carries the signature the reconciler queries"
    );

    // Park outcome_unknown WITHOUT re-supplying a signature: it is retained.
    let outcome = block_on(loop_.finalize(
        "g1",
        &SettlementEvidence::Unknown {
            response: Some("timeout"),
            transaction_signature: None,
        },
        300,
    ))
    .expect("park");
    assert!(matches!(
        outcome,
        EdgeOutcome::OutcomeUnknown { parked: true, .. }
    ));
    assert_eq!(
        block_on(attempt_signature(&state, "g1")).as_deref(),
        Some(sig.as_str()),
        "a parked outcome_unknown attempt retains the signature"
    );
    assert_eq!(
        block_on(reservation_status(&state, "g1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
}

#[test]
fn park_persists_a_later_known_signature_when_submit_had_none() {
    // First-park persistence: the signature is unknown at submit (the SVM
    // facilitator flow) and only supplied when the loop parks outcome_unknown.
    let state = seed_state(10_000);
    let loop_ = state.x402_settlement_loop();
    block_on(loop_.open(&open_request("g2", 500), 100)).expect("open");
    block_on(loop_.submit("g2", None, 200, 200)).expect("submit");
    assert_eq!(block_on(attempt_signature(&state, "g2")), None);

    let sig = "7".repeat(88);
    block_on(loop_.finalize(
        "g2",
        &SettlementEvidence::Unknown {
            response: None,
            transaction_signature: Some(&sig),
        },
        300,
    ))
    .expect("park with signature");
    assert_eq!(
        block_on(attempt_state(&state, "g2")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    assert_eq!(
        block_on(attempt_signature(&state, "g2")).as_deref(),
        Some(sig.as_str()),
        "the park CAS persisted the later-known signature"
    );
    // Hold RETAINED: persisting a signature never touches the money edges.
    assert_eq!(
        block_on(reservation_status(&state, "g2")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
}

// --------------------------------------------------------------------------
// Async-timeout truth table between the two primitives of the SETTLE edge
// --------------------------------------------------------------------------

/// A commit observer that fires exactly once, for the given primitive label,
/// with the given fault, then is inert. Deterministic and sleep-free.
fn one_shot_fault(label: &'static str, fault: CommitFault) -> CommitObserver {
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    Arc::new(move |seen: &'static str| {
        if seen == label
            && fired
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_ok()
        {
            Some(fault)
        } else {
            None
        }
    })
}

#[test]
fn async_timeout_before_capture_yields_outcome_unknown_and_retains_hold() {
    let state = seed_state(10_000);
    let repositories = state.repositories_arc();
    block_on(
        state
            .x402_settlement_loop()
            .open(&open_request("t1", 500), 100),
    )
    .expect("open");
    block_on(state.x402_settlement_loop().submit("t1", None, 200, 200)).expect("submit");

    // The wallet-capture primitive's commit outcome becomes unknown BEFORE it
    // ran. The loop must retain the hold and park outcome_unknown -- never a
    // false failure/release that would spend stablecoin for free.
    let faulted = X402SettlementLoop::with_observer(
        Arc::clone(&repositories),
        // Disabled reconciler = no floor; the clamp has its own tests below.
        &X402ReconcilerConfig::default(),
        one_shot_fault("settle_wallet_reservation", CommitFault::UnknownPreCommit),
    );
    let outcome = block_on(faulted.finalize("t1", &settled_evidence(), 300)).expect("finalize");
    assert!(
        matches!(outcome, EdgeOutcome::OutcomeUnknown { parked: true, .. }),
        "{outcome:?}"
    );
    assert_eq!(
        block_on(attempt_state(&state, "t1")),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    );
    // Hold RETAINED (still active), wallet untouched.
    assert_eq!(
        block_on(reservation_status(&state, "t1")).as_deref(),
        Some(WALLET_RESERVATION_ACTIVE)
    );
    assert_eq!(block_on(wallet_balance(&state)), 10_000);

    // Bounded re-entry (no fault) converges: outcome_unknown -> settled, and the
    // hold is now captured exactly once.
    let healthy = state.x402_settlement_loop();
    let reentry = block_on(healthy.finalize("t1", &settled_evidence(), 400)).expect("re-entry");
    assert!(
        matches!(reentry, EdgeOutcome::Settled { .. }),
        "{reentry:?}"
    );
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

#[test]
fn async_timeout_after_attempt_transition_never_releases_and_converges() {
    let state = seed_state(10_000);
    let repositories = state.repositories_arc();
    block_on(
        state
            .x402_settlement_loop()
            .open(&open_request("t2", 500), 100),
    )
    .expect("open");
    block_on(state.x402_settlement_loop().submit("t2", None, 200, 200)).expect("submit");

    // Capture succeeds; the attempt-transition primitive commits but its outcome
    // is reported unknown. The loop must NOT release; re-entry converges.
    let faulted = X402SettlementLoop::with_observer(
        Arc::clone(&repositories),
        // Disabled reconciler = no floor; the clamp has its own tests below.
        &X402ReconcilerConfig::default(),
        one_shot_fault("settle_payment_attempt", CommitFault::UnknownPostCommit),
    );
    let outcome = block_on(faulted.finalize("t2", &settled_evidence(), 300)).expect("finalize");
    assert!(
        matches!(outcome, EdgeOutcome::OutcomeUnknown { parked: false, .. }),
        "{outcome:?}"
    );
    // The hold was captured (retained, never released) and the attempt actually
    // committed to settled.
    assert_eq!(
        block_on(reservation_status(&state, "t2")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
    assert_eq!(
        block_on(attempt_state(&state, "t2")),
        PAYMENT_ATTEMPT_SETTLED
    );

    // Re-entry is idempotent.
    let reentry = block_on(
        state
            .x402_settlement_loop()
            .finalize("t2", &settled_evidence(), 400),
    )
    .expect("re-entry");
    assert!(
        matches!(reentry, EdgeOutcome::Settled { .. }),
        "{reentry:?}"
    );
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
}

// --------------------------------------------------------------------------
// Concurrent re-entry (barrier-coordinated, no timing sleeps)
// --------------------------------------------------------------------------

#[test]
fn concurrent_finalize_captures_hold_exactly_once() {
    let state = seed_state(10_000);
    block_on(
        state
            .x402_settlement_loop()
            .open(&open_request("c1", 500), 100),
    )
    .expect("open");
    block_on(state.x402_settlement_loop().submit("c1", None, 200, 200)).expect("submit");

    block_on(async {
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let loop_a = state.x402_settlement_loop();
        let loop_b = state.x402_settlement_loop();
        let b_a = Arc::clone(&barrier);
        let b_b = Arc::clone(&barrier);
        let task_a = async move {
            b_a.wait().await;
            loop_a.finalize("c1", &settled_evidence(), 300).await
        };
        let task_b = async move {
            b_b.wait().await;
            loop_b.finalize("c1", &settled_evidence(), 300).await
        };
        let (ra, rb) = tokio::join!(task_a, task_b);
        ra.expect("task a");
        rb.expect("task b");
    });

    // Exactly one capture despite two concurrent finalizes.
    assert_eq!(
        block_on(reservation_status(&state, "c1")).as_deref(),
        Some(WALLET_RESERVATION_SETTLED)
    );
    assert_eq!(
        block_on(attempt_state(&state, "c1")),
        PAYMENT_ATTEMPT_SETTLED
    );
    assert_eq!(block_on(wallet_balance(&state)), 9_500);
}

// --------------------------------------------------------------------------
// Property: total captured credits never exceed the authorized holds
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Action {
    Settle,
    Release,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn total_settled_never_exceeds_authorized(
        specs in proptest::collection::vec(
            (1i64..=100, prop::bool::ANY, 1u8..=3),
            1..=8,
        )
    ) {
        // Fund the wallet well above the maximum possible authorized total so
        // every reserve succeeds and the invariant is about the loop, not the
        // funding gate.
        let state = seed_state(1_000_000);
        let loop_ = state.x402_settlement_loop();

        let mut authorized_total = 0i64;
        let mut expected_captured = 0i64;

        block_on(async {
            for (index, (credits, settle, dup)) in specs.iter().enumerate() {
                let id = format!("p{index}");
                let action = if *settle { Action::Settle } else { Action::Release };
                let outcome = loop_.open(&open_request(&id, *credits), 100).await.expect("open");
                prop_assert!(
                    matches!(outcome, OpenOutcome::Opened { .. }),
                    "open must succeed"
                );
                authorized_total += *credits;

                match action {
                    Action::Settle => {
                        loop_.submit(&id, None, 200, 200).await.expect("submit");
                        // A distinct on-chain signature per attempt: one transfer
                        // may back at most ONE attempt (migration 59's partial
                        // UNIQUE index), so reusing a single literal here would
                        // exercise the double-capture-from-one-transfer path this
                        // property is not about -- and would now fail closed.
                        // Duplicate finalizes of the SAME attempt with the SAME
                        // signature still must not double-capture.
                        let signature = format!("sig-{id}");
                        let evidence = SettlementEvidence::Settled {
                            transaction_signature: signature.as_str(),
                            settled_atomic_amount: "1000000",
                            response: Some("{\"ok\":true}"),
                        };
                        for _ in 0..*dup {
                            loop_
                                .finalize(&id, &evidence, 300)
                                .await
                                .expect("finalize");
                        }
                        expected_captured += *credits;
                    }
                    Action::Release => {
                        for _ in 0..*dup {
                            loop_.cancel(&id, "x402_cancelled", 150).await.expect("cancel");
                        }
                    }
                }
            }
            Ok(())
        })?;

        // Sum captured credits across all reservations that reached `settled`.
        let reservations = block_on(state.repositories_arc().list_wallet_reservations(TENANT))
            .expect("list reservations");
        let captured_total: i64 = reservations
            .iter()
            .filter(|r| r.status == WALLET_RESERVATION_SETTLED)
            .map(|r| r.amount_credits)
            .sum();

        // The invariant: captured never exceeds authorized, and equals exactly
        // the settle-actioned holds (each captured once, releases never captured).
        prop_assert!(captured_total <= authorized_total);
        prop_assert_eq!(captured_total, expected_captured);

        // No reservation is simultaneously settled and released; totals reconcile.
        let released_total: i64 = reservations
            .iter()
            .filter(|r| r.status == WALLET_RESERVATION_RELEASED)
            .map(|r| r.amount_credits)
            .sum();
        prop_assert_eq!(captured_total + released_total, authorized_total);
    }
}

// --------------------------------------------------------------------------
// #401: the PER-REQUEST hold TTL cannot bypass #400's validated floor
//
// `x402_reconciler.hold_ttl_secs` is validated at config load but the real
// wallet hold TTL arrives as a per-request parameter, so without a clamp the
// validation is false assurance: a short runtime hold auto-releases before the
// reconciler can capture a payment that IS confirmed on-chain (stablecoin
// delivered, wallet never charged). `X402SettlementLoop::open` -- the one place
// a TTL becomes a wallet-hold `expires_at` -- clamps every request UP to the
// shared floor.
// --------------------------------------------------------------------------

/// A deliberately NON-default reconciler config: every component differs from
/// the shipped defaults (900/60/30 -> 600/45/17), so a clamp test can never pass
/// by accidentally agreeing with a default. Floor = 600 + 45 + 17 + 1 = 663.
fn clamp_reconciler_config() -> X402ReconcilerConfig {
    X402ReconcilerConfig {
        enabled: true,
        tick_interval_secs: 17,
        max_reconciles_per_tick: 100,
        reconcile_check_delay_secs: 45,
        confirmation_deadline_secs: 600,
        hold_ttl_secs: 7_200,
    }
}

fn clamp_config(reconciler: X402ReconcilerConfig) -> Config {
    Config {
        x402_reconciler: reconciler,
        ..Config::default()
    }
}

#[test]
fn open_clamps_a_below_floor_request_ttl_up_to_the_validated_floor() {
    let reconciler = clamp_reconciler_config();
    let floor = x402_hold_ttl_floor_secs(&reconciler);
    let state = seed_state_with_config(clamp_config(reconciler), 10_000);
    let loop_ = state.x402_settlement_loop();

    // The bypass a caller could otherwise attempt: a 1-second hold.
    let mut request = open_request("clamp-low", 500);
    request.hold_ttl_secs = 1;
    block_on(loop_.open(&request, 100)).expect("open");

    assert_eq!(
        block_on(reservation_expires_at(&state, "clamp-low")),
        Some(100 + floor),
        "a below-floor request TTL must be clamped up to the validated floor"
    );
}

#[test]
fn open_keeps_a_request_ttl_longer_than_the_validated_floor() {
    let reconciler = clamp_reconciler_config();
    let floor = x402_hold_ttl_floor_secs(&reconciler);
    let state = seed_state_with_config(clamp_config(reconciler), 10_000);
    let loop_ = state.x402_settlement_loop();

    // The clamp is a FLOOR, not an override: a longer request is honoured.
    let mut request = open_request("clamp-high", 500);
    request.hold_ttl_secs = floor + 5_000;
    block_on(loop_.open(&request, 100)).expect("open");

    assert_eq!(
        block_on(reservation_expires_at(&state, "clamp-high")),
        Some(100 + floor + 5_000),
        "a request may always ask for a LONGER hold than the floor"
    );
}

#[test]
fn clamp_floor_is_exactly_the_config_validation_boundary() {
    // Anti-drift: the runtime clamp and the #400 config-load check must be the
    // same number for the SAME config. If someone retunes one predicate without
    // the other, this fails.
    let reconciler = clamp_reconciler_config();
    let floor = x402_hold_ttl_floor_secs(&reconciler);

    clamp_config(X402ReconcilerConfig {
        hold_ttl_secs: floor,
        ..reconciler.clone()
    })
    .validate()
    .expect("a hold TTL exactly at the shared floor must pass config validation");

    let error = format!(
        "{:#}",
        clamp_config(X402ReconcilerConfig {
            hold_ttl_secs: floor - 1,
            ..reconciler.clone()
        })
        .validate()
        .expect_err("one second below the shared floor must fail config validation")
    );
    assert!(
        error.contains("field x402_reconciler.hold_ttl_secs"),
        "validation must reject exactly at floor - 1: {error}"
    );

    // ... and the clamp the runtime actually applies is that same floor.
    let state = seed_state_with_config(clamp_config(reconciler), 10_000);
    let mut request = open_request("clamp-boundary", 500);
    request.hold_ttl_secs = 1;
    block_on(state.x402_settlement_loop().open(&request, 0)).expect("open");
    assert_eq!(
        block_on(reservation_expires_at(&state, "clamp-boundary")),
        Some(floor),
        "the runtime clamp must use the same floor the config validation enforces"
    );
}

#[test]
fn a_clamped_hold_outlives_the_confirmation_deadline_check_delay_and_one_tick() {
    // The #400 invariant, asserted end-to-end at this seam: even for a request
    // that asked for an absurdly short hold, the hold that lands in the wallet
    // expires no earlier than `confirmation_deadline + check_delay + one tick`
    // after it was opened -- so the reconciler always still has a live hold to
    // capture when it resolves a payment confirmed on-chain.
    let reconciler = clamp_reconciler_config();
    let state = seed_state_with_config(clamp_config(reconciler.clone()), 10_000);
    let opened_at = 1_000;

    let mut request = open_request("clamp-invariant", 500);
    request.hold_ttl_secs = 30; // shorter than even the reconcile check delay
    block_on(state.x402_settlement_loop().open(&request, opened_at)).expect("open");

    let expires_at =
        block_on(reservation_expires_at(&state, "clamp-invariant")).expect("hold exists");
    // Recomputed straight from the config fields (NOT via the shared helper) so
    // this assertion still means what #400 says even if the helper changes.
    let earliest_safe_capture = opened_at
        + reconciler.confirmation_deadline_secs
        + reconciler.reconcile_check_delay_secs
        + reconciler.tick_interval_secs as i64;
    assert!(
        expires_at > earliest_safe_capture,
        "clamped hold expires at {expires_at}, which does not strictly outlive the \
         confirmation window ending at {earliest_safe_capture}"
    );
}

#[test]
fn a_disabled_reconciler_leaves_the_request_ttl_untouched() {
    // The clamp mirrors the #400 validation's own `enabled` gate exactly: while
    // the reconciler is disabled nothing captures a submitted attempt on this
    // path (so the money-loss window does not exist) AND its timing fields are
    // never validated (so clamping to a floor derived from them would enforce an
    // unvalidated number).
    let reconciler = X402ReconcilerConfig {
        enabled: false,
        ..clamp_reconciler_config()
    };
    let state = seed_state_with_config(clamp_config(reconciler), 10_000);

    let mut request = open_request("clamp-disabled", 500);
    request.hold_ttl_secs = 30;
    block_on(state.x402_settlement_loop().open(&request, 100)).expect("open");

    assert_eq!(
        block_on(reservation_expires_at(&state, "clamp-disabled")),
        Some(130),
        "a disabled reconciler must not impose an unvalidated floor"
    );
}

/// The classifier screens the amount DOMAIN, not just the arithmetic.
///
/// `u128::from_str` is looser than the column it feeds: it accepts a leading `+`
/// and any number of digits, so `"+250000"` and a 21-digit value passed this
/// guard, reached the CAS, and were then refused by migration 59's CHECK on
/// Postgres while the memory twin stored them (#352 review §2). Screening with
/// the SAME `is_canonical_atomic_amount` the storage layer and the CHECK use
/// keeps the money verdict at the money seam and the backends in agreement.
///
/// Fail-closed direction, always: a non-canonical amount is `Short`, which
/// refuses the capture, RETAINS the hold and leaves the attempt non-terminal for
/// the reconciler. It is never read as covering the owed amount.
///
/// Delete the `is_canonical_atomic_amount` screen in `classify_settled_amount`
/// and the `"+250000"` case goes red.
#[test]
fn a_non_canonical_amount_is_never_read_as_covering_the_owed_amount() {
    for bad in [
        "+250000",               // sign u128::from_str accepts, the column does not
        "184467440737095516150", // 21 digits: wider than u64::MAX
        "",
        "-250000",
        "2.5e5",
        " 250000",
    ] {
        assert_eq!(
            classify_settled_amount("250000", bad),
            AmountCoverage::Short,
            "settled {bad:?} must fail closed"
        );
        // And in the mirror direction: a non-canonical OWED amount cannot be
        // satisfied either, however large the settled side is.
        assert_eq!(
            classify_settled_amount(bad, "999999999"),
            AmountCoverage::Short,
            "owed {bad:?} must fail closed"
        );
    }

    // The screen is narrow: canonical amounts classify exactly as before, so an
    // exact transfer and the spec-valid overpayment both still settle.
    assert_eq!(
        classify_settled_amount("250000", "250000"),
        AmountCoverage::Covers {
            overpayment_atomic_amount: None
        }
    );
    assert_eq!(
        classify_settled_amount("250000", "250001"),
        AmountCoverage::Covers {
            overpayment_atomic_amount: Some("1".to_string())
        }
    );
    // Leading zeros are still canonical and still compare numerically.
    assert_eq!(
        classify_settled_amount("250000", "0250000"),
        AmountCoverage::Covers {
            overpayment_atomic_amount: None
        }
    );
    assert_eq!(
        classify_settled_amount("250000", "249999"),
        AmountCoverage::Short
    );
}
