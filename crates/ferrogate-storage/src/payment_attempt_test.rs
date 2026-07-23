// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Backend coverage for durable x402 payment attempts (#352):
// round-trip persistence, the wallet-hold coupling, idempotent replay and
// fail-closed conflict on the create + settle edges, the outcome_unknown
// hold-retention rule, a barrier-based concurrency proof that two conflicting
// state transitions cannot both win the CAS (no timing sleeps, per AGENTS.md),
// and a proptest invariant that no reachable transition sequence lets total
// settled credits exceed the authorized hold.

use std::sync::{Arc, Barrier};

use proptest::prelude::*;

use crate::schema_routing_test_support::block_on;
use crate::{
    payment_attempt_state_is_terminal, PaymentAttemptCreation, PaymentAttemptEvidenceArgs,
    PaymentAttemptTransition, RuntimeStorageRepositories, StorageError, StorageProviderKind,
    StoredPaymentAttempt, StoredWallet, WalletReservationResult, PAYMENT_ATTEMPT_AUTHORIZED,
    PAYMENT_ATTEMPT_CHALLENGED, PAYMENT_ATTEMPT_DENIED, PAYMENT_ATTEMPT_FAILED,
    PAYMENT_ATTEMPT_OUTCOME_UNKNOWN, PAYMENT_ATTEMPT_RELEASED, PAYMENT_ATTEMPT_SETTLED,
    PAYMENT_ATTEMPT_SUBMITTED, WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_SETTLED,
};

fn memory_repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16)
}

fn repositories_with_wallet(tenant: &str, balance: i64) -> RuntimeStorageRepositories {
    let repositories = memory_repositories();
    block_on(repositories.upsert_wallet(StoredWallet {
        id: tenant.into(),
        tenant_id: tenant.into(),
        balance_credits: balance,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    repositories
}

/// A fully-populated attempt in the given initial state, exercising every
/// column of the audit tuple so the round-trip test proves nothing is dropped.
fn sample_attempt(
    id: &str,
    tenant: &str,
    state: &str,
    hold_id: Option<&str>,
) -> StoredPaymentAttempt {
    StoredPaymentAttempt {
        id: id.into(),
        tenant_id: tenant.into(),
        project_id: Some("proj-1".into()),
        workspace_id: Some("ws-1".into()),
        run_id: Some("run-1".into()),
        worker_id: Some("worker-1".into()),
        request_id: Some("req-1".into()),
        trace_id: Some("trace-1".into()),
        method: "POST".into(),
        resource_url: "https://api.example.com/v1/tool".into(),
        request_body_hash: Some("a".repeat(64)),
        challenge_hash: "b".repeat(64),
        x402_version: 2,
        scheme: "exact".into(),
        network_caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".into(),
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
        atomic_amount: "18446744073709551615".into(), // u64::MAX survives TEXT storage
        recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM".into(),
        credits_amount: Some(250),
        conversion_version: Some("rate-2026-07".into()),
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_id: hold_id.map(Into::into),
        state: state.into(),
        generation: 0,
        submitted_at_unix: None,
        transaction_signature: None,
        settled_atomic_amount: None,
        settlement_response: None,
        failure_code: None,
        created_at_unix: 100,
        updated_at_unix: 100,
    }
}

fn no_evidence() -> PaymentAttemptEvidenceArgs<'static> {
    PaymentAttemptEvidenceArgs::default()
}

#[test]
fn create_round_trips_the_full_audit_tuple() {
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    let attempt = sample_attempt(
        "att-1",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-1"),
    );

    let created = block_on(repositories.create_payment_attempt(attempt.clone())).unwrap();
    assert_eq!(created, PaymentAttemptCreation::Created(attempt.clone()));

    let fetched = block_on(repositories.get_payment_attempt("att-1"))
        .unwrap()
        .expect("attempt persisted");
    assert_eq!(fetched, attempt, "every column must survive the round trip");

    let listed = block_on(repositories.list_payment_attempts("tenant-a")).unwrap();
    assert_eq!(listed, vec![attempt]);
    // Tenant scoping: another tenant sees nothing.
    assert!(block_on(repositories.list_payment_attempts("tenant-other"))
        .unwrap()
        .is_empty());
}

#[test]
fn create_is_idempotent_and_conflicting_challenge_fails_closed() {
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    let attempt = sample_attempt(
        "att-1",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-1"),
    );
    block_on(repositories.create_payment_attempt(attempt.clone())).unwrap();

    // Replaying the identical create returns the existing row.
    assert_eq!(
        block_on(repositories.create_payment_attempt(attempt.clone())).unwrap(),
        PaymentAttemptCreation::Existing(attempt.clone()),
    );

    // A conflicting challenge under the same idempotency id fails closed.
    let mut conflicting = attempt.clone();
    conflicting.challenge_hash = "c".repeat(64);
    assert!(matches!(
        block_on(repositories.create_payment_attempt(conflicting)),
        Err(StorageError::Conflict(_))
    ));

    // An illegal initial state is rejected.
    let bad = sample_attempt("att-2", "tenant-a", PAYMENT_ATTEMPT_SETTLED, None);
    assert!(matches!(
        block_on(repositories.create_payment_attempt(bad)),
        Err(StorageError::Conflict(_))
    ));
}

#[test]
fn full_lifecycle_couples_hold_capture_to_settlement() {
    // The happy path #354 will drive: reserve -> create(authorized) ->
    // submit -> settle, with the hold captured into a real wallet debit.
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    let reserved =
        block_on(repositories.reserve_wallet_credits("hold-1", "tenant-a", 250, 10_000, 1))
            .unwrap();
    assert!(matches!(reserved, WalletReservationResult::Reserved(_)));

    let attempt = sample_attempt(
        "att-1",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-1"),
    );
    block_on(repositories.create_payment_attempt(attempt)).unwrap();

    // authorized -> submitted records submission time.
    let submitted = block_on(repositories.submit_payment_attempt(
        "att-1",
        PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(200),
            ..Default::default()
        },
        200,
    ))
    .unwrap();
    let PaymentAttemptTransition::Applied(row) = submitted else {
        panic!("expected applied submit");
    };
    assert_eq!(row.state, PAYMENT_ATTEMPT_SUBMITTED);
    assert_eq!(row.submitted_at_unix, Some(200));
    assert_eq!(row.generation, 1, "one applied transition bumps generation");

    // submitted -> settled records the on-chain signature; #354 captures the
    // coupled hold in the same runtime step (a second short primitive).
    let settled = block_on(repositories.settle_payment_attempt(
        "att-1",
        PaymentAttemptEvidenceArgs {
            transaction_signature: Some("5".repeat(88).as_str()),
            settled_atomic_amount: Some("18446744073709551615"),
            ..Default::default()
        },
        300,
    ))
    .unwrap();
    assert!(matches!(settled, PaymentAttemptTransition::Applied(_)));
    let capture = block_on(repositories.settle_wallet_reservation("hold-1", 300)).unwrap();
    assert!(capture.newly_applied);

    // The admin evidence join stitches attempt -> hold -> settlement.
    let links = block_on(repositories.get_payment_attempt_links("att-1", "tenant-a"))
        .unwrap()
        .expect("links present");
    assert_eq!(links.attempt.state, PAYMENT_ATTEMPT_SETTLED);
    assert_eq!(
        links.reservation.as_ref().map(|r| r.status.as_str()),
        Some(WALLET_RESERVATION_SETTLED)
    );
    assert_eq!(
        links.settlement.as_ref().map(|s| s.delta_credits),
        Some(-250),
        "the captured wallet debit equals the authorized hold"
    );
    // Real balance dropped by exactly the held amount, once.
    assert_eq!(
        block_on(repositories.get_wallet("tenant-a"))
            .unwrap()
            .unwrap()
            .balance_credits,
        750
    );
    // Cross-tenant reads are denied (indistinguishable from missing).
    assert!(
        block_on(repositories.get_payment_attempt_links("att-1", "tenant-x"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn settle_replay_is_idempotent_but_conflicting_signature_fails_closed() {
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    block_on(repositories.create_payment_attempt(sample_attempt(
        "att-1",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-1"),
    )))
    .unwrap();
    block_on(repositories.submit_payment_attempt(
        "att-1",
        PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(200),
            ..Default::default()
        },
        200,
    ))
    .unwrap();
    let sig = "5".repeat(88);
    let settle = |signature: &str| {
        block_on(repositories.settle_payment_attempt(
            "att-1",
            PaymentAttemptEvidenceArgs {
                transaction_signature: Some(signature),
                ..Default::default()
            },
            300,
        ))
    };
    assert!(matches!(
        settle(&sig).unwrap(),
        PaymentAttemptTransition::Applied(_)
    ));
    // Same signature replays idempotently (captures once).
    assert!(matches!(
        settle(&sig).unwrap(),
        PaymentAttemptTransition::Idempotent(_)
    ));
    // A different signature for the already-settled attempt fails closed.
    assert!(matches!(
        settle(&"6".repeat(88)),
        Err(StorageError::Conflict(_))
    ));
}

#[test]
fn timeout_after_submission_is_outcome_unknown_and_retains_the_hold() {
    // #352 truth table: after submission a timeout/RPC ambiguity is
    // outcome_unknown; the hold MUST stay active, never released.
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    block_on(repositories.reserve_wallet_credits("hold-1", "tenant-a", 250, 10_000, 1)).unwrap();
    block_on(repositories.create_payment_attempt(sample_attempt(
        "att-1",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-1"),
    )))
    .unwrap();
    block_on(repositories.submit_payment_attempt(
        "att-1",
        PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(200),
            ..Default::default()
        },
        200,
    ))
    .unwrap();

    let unknown =
        block_on(repositories.mark_payment_attempt_outcome_unknown("att-1", no_evidence(), 300))
            .unwrap();
    let PaymentAttemptTransition::Applied(row) = unknown else {
        panic!("expected applied");
    };
    assert_eq!(row.state, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN);
    assert!(!payment_attempt_state_is_terminal(&row.state));

    // The hold is still active -- releasing it now would spend stablecoin
    // without charging the wallet.
    let links = block_on(repositories.get_payment_attempt_links("att-1", "tenant-a"))
        .unwrap()
        .unwrap();
    assert_eq!(
        links.reservation.as_ref().map(|r| r.status.as_str()),
        Some(WALLET_RESERVATION_ACTIVE),
        "outcome_unknown must retain the hold"
    );

    // Later durable evidence can still settle it from outcome_unknown.
    assert!(matches!(
        block_on(repositories.settle_payment_attempt(
            "att-1",
            PaymentAttemptEvidenceArgs {
                transaction_signature: Some("7".repeat(88).as_str()),
                ..Default::default()
            },
            400,
        ))
        .unwrap(),
        PaymentAttemptTransition::Applied(_)
    ));
}

#[test]
fn pre_submission_release_is_valid_but_post_submission_release_is_rejected() {
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    // Pre-submission: authorized -> released is allowed.
    block_on(repositories.create_payment_attempt(sample_attempt(
        "att-1",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-1"),
    )))
    .unwrap();
    assert!(matches!(
        block_on(repositories.release_payment_attempt(
            "att-1",
            PaymentAttemptEvidenceArgs {
                failure_code: Some("cancelled"),
                ..Default::default()
            },
            200,
        ))
        .unwrap(),
        PaymentAttemptTransition::Applied(_)
    ));

    // Post-submission: a submitted attempt can never be released.
    block_on(repositories.create_payment_attempt(sample_attempt(
        "att-2",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("hold-2"),
    )))
    .unwrap();
    block_on(repositories.submit_payment_attempt(
        "att-2",
        PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(200),
            ..Default::default()
        },
        200,
    ))
    .unwrap();
    assert!(matches!(
        block_on(repositories.release_payment_attempt("att-2", no_evidence(), 300)),
        Err(StorageError::Conflict(_))
    ));
    // A transition on an unknown attempt is NotFound, never a silent success.
    assert!(matches!(
        block_on(repositories.submit_payment_attempt("nope", no_evidence(), 1)),
        Err(StorageError::NotFound(_))
    ));
}

#[test]
fn list_expirable_due_returns_only_due_pre_submission_active_holds() {
    // #354 TTL sweep read: only pre-submission (authorized/challenged) attempts
    // whose live (`active`) hold expired at or before the cutoff, oldest-due
    // first, bounded by the limit. A submitted attempt (money may have moved),
    // a settled attempt (hold captured, not active), and a not-yet-due hold are
    // all excluded -- the money-safety filter at the read layer.
    let repositories = repositories_with_wallet("tenant-a", 100_000);
    for (hold, expires_at) in [
        ("h-due", 1_000),
        ("h-ch", 500),
        ("h-notdue", 5_000),
        ("h-sub", 800),
        ("h-settled", 900),
    ] {
        block_on(repositories.reserve_wallet_credits(hold, "tenant-a", 250, expires_at, 1))
            .unwrap();
    }

    // authorized + past-due  -> due
    block_on(repositories.create_payment_attempt(sample_attempt(
        "due",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("h-due"),
    )))
    .unwrap();
    // challenged + past-due  -> due (expirable includes challenged)
    block_on(repositories.create_payment_attempt(sample_attempt(
        "ch",
        "tenant-a",
        PAYMENT_ATTEMPT_CHALLENGED,
        Some("h-ch"),
    )))
    .unwrap();
    // authorized but hold not yet due -> excluded
    block_on(repositories.create_payment_attempt(sample_attempt(
        "notdue",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("h-notdue"),
    )))
    .unwrap();
    // submitted (hold still active + past due) -> excluded by the state filter:
    // its stablecoin may have moved on-chain, so its hold must never be swept.
    block_on(repositories.create_payment_attempt(sample_attempt(
        "sub",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("h-sub"),
    )))
    .unwrap();
    block_on(repositories.submit_payment_attempt("sub", no_evidence(), 2)).unwrap();
    // settled -> reservation captured (not active) -> excluded
    block_on(repositories.create_payment_attempt(sample_attempt(
        "settled",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        Some("h-settled"),
    )))
    .unwrap();
    block_on(repositories.submit_payment_attempt("settled", no_evidence(), 2)).unwrap();
    block_on(repositories.settle_wallet_reservation("h-settled", 3)).unwrap();
    block_on(repositories.settle_payment_attempt("settled", no_evidence(), 3)).unwrap();

    // Cutoff 2000: h-ch(500), h-sub(800), h-settled(900), h-due(1000) elapsed;
    // h-notdue(5000) has not. Only the pre-submission, active-hold rows survive,
    // ordered oldest-due first.
    let due = block_on(repositories.list_expirable_due_payment_attempts(2_000, 100)).unwrap();
    let ids: Vec<&str> = due.iter().map(|attempt| attempt.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["ch", "due"],
        "only due pre-submission active holds"
    );

    // Bounded: a limit of 1 yields only the single oldest-due candidate, so the
    // sweeper pages instead of scanning the whole table.
    let one = block_on(repositories.list_expirable_due_payment_attempts(2_000, 1)).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].id, "ch");
}

#[test]
fn conflicting_transitions_cannot_both_win_the_cas() {
    // Core CAS property (#352): two conflicting transitions from the same
    // source state race under maximum contention; exactly one applies and the
    // other observes the advanced state and is rejected. Barrier-synchronised,
    // no timing sleeps (AGENTS.md).
    for _ in 0..64 {
        let repositories = Arc::new(repositories_with_wallet("tenant-race", 1_000));
        block_on(repositories.create_payment_attempt(sample_attempt(
            "att-race",
            "tenant-race",
            PAYMENT_ATTEMPT_AUTHORIZED,
            Some("hold-race"),
        )))
        .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let submit_repos = Arc::clone(&repositories);
        let submit_barrier = Arc::clone(&barrier);
        let submit = std::thread::spawn(move || {
            submit_barrier.wait();
            block_on(submit_repos.submit_payment_attempt(
                "att-race",
                PaymentAttemptEvidenceArgs {
                    submitted_at_unix: Some(200),
                    ..Default::default()
                },
                200,
            ))
        });
        let release_repos = Arc::clone(&repositories);
        let release_barrier = Arc::clone(&barrier);
        let release = std::thread::spawn(move || {
            release_barrier.wait();
            block_on(release_repos.release_payment_attempt("att-race", no_evidence(), 200))
        });

        let outcomes = [submit.join().unwrap(), release.join().unwrap()];
        let applied = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(PaymentAttemptTransition::Applied(_))))
            .count();
        let conflicts = outcomes
            .iter()
            .filter(|o| matches!(o, Err(StorageError::Conflict(_))))
            .count();
        assert_eq!(applied, 1, "exactly one conflicting transition may win");
        assert_eq!(
            conflicts, 1,
            "the loser must be rejected, not silently lost"
        );

        // The durable state is terminal-consistent with the single winner and
        // the generation advanced exactly once.
        let final_state = block_on(repositories.get_payment_attempt("att-race"))
            .unwrap()
            .unwrap();
        assert!(
            final_state.state == PAYMENT_ATTEMPT_SUBMITTED
                || final_state.state == PAYMENT_ATTEMPT_RELEASED
        );
        assert_eq!(final_state.generation, 1);
    }
}

// A minimal transition alphabet the proptest drives against the real backend.
#[derive(Debug, Clone, Copy)]
enum Step {
    Submit,
    OutcomeUnknown,
    Settle,
    Release,
    Fail,
    Deny,
}

fn step_strategy() -> impl Strategy<Value = Step> {
    prop_oneof![
        Just(Step::Submit),
        Just(Step::OutcomeUnknown),
        Just(Step::Settle),
        Just(Step::Release),
        Just(Step::Fail),
        Just(Step::Deny),
    ]
}

proptest! {
    /// Invariant: no matter what (even invalid) transition sequence is thrown at
    /// one authorized attempt, total captured settlement credits never exceed
    /// the single authorized hold. `settled` is terminal and captures the hold
    /// exactly once, so the coupled wallet debit can never oversell.
    #[test]
    fn settled_capture_never_exceeds_authorized_hold(steps in prop::collection::vec(step_strategy(), 0..24)) {
        let repositories = repositories_with_wallet("tenant-p", 1_000);
        let hold_amount = 250i64;
        block_on(repositories.reserve_wallet_credits("hold-p", "tenant-p", hold_amount, 10_000, 1))
            .unwrap();
        block_on(repositories.create_payment_attempt(sample_attempt(
            "att-p",
            "tenant-p",
            PAYMENT_ATTEMPT_AUTHORIZED,
            Some("hold-p"),
        )))
        .unwrap();

        let mut now = 10i64;
        for step in steps {
            now += 1;
            let sig = "8".repeat(88);
            let _ = match step {
                Step::Submit => block_on(repositories.submit_payment_attempt(
                    "att-p",
                    PaymentAttemptEvidenceArgs { submitted_at_unix: Some(now), ..Default::default() },
                    now,
                )),
                Step::OutcomeUnknown => {
                    block_on(repositories.mark_payment_attempt_outcome_unknown("att-p", no_evidence(), now))
                }
                Step::Settle => {
                    let out = block_on(repositories.settle_payment_attempt(
                        "att-p",
                        PaymentAttemptEvidenceArgs {
                            transaction_signature: Some(sig.as_str()),
                            ..Default::default()
                        },
                        now,
                    ));
                    // On a successful attempt-settle, #354 captures the hold.
                    if matches!(out, Ok(PaymentAttemptTransition::Applied(_))) {
                        let _ = block_on(repositories.settle_wallet_reservation("hold-p", now));
                    }
                    out
                }
                Step::Release => {
                    let out = block_on(repositories.release_payment_attempt("att-p", no_evidence(), now));
                    if matches!(out, Ok(PaymentAttemptTransition::Applied(_))) {
                        let _ = block_on(repositories.release_wallet_reservation("hold-p", now));
                    }
                    out
                }
                Step::Fail => {
                    let out = block_on(repositories.fail_payment_attempt(
                        "att-p",
                        PaymentAttemptEvidenceArgs { failure_code: Some("rpc_error"), ..Default::default() },
                        now,
                    ));
                    if matches!(out, Ok(PaymentAttemptTransition::Applied(_))) {
                        let _ = block_on(repositories.release_wallet_reservation("hold-p", now));
                    }
                    out
                }
                Step::Deny => block_on(repositories.deny_payment_attempt(
                    "att-p",
                    PaymentAttemptEvidenceArgs { failure_code: Some("denied"), ..Default::default() },
                    now,
                )),
            };
        }

        // The captured (negative) delta can never exceed the authorized hold,
        // and the real balance never drops below balance - hold.
        let links = block_on(repositories.get_payment_attempt_links("att-p", "tenant-p"))
            .unwrap()
            .unwrap();
        if let Some(settlement) = links.settlement.as_ref() {
            prop_assert_eq!(settlement.delta_credits, -hold_amount);
        }
        let balance = block_on(repositories.get_wallet("tenant-p")).unwrap().unwrap().balance_credits;
        prop_assert!(balance >= 1_000 - hold_amount, "wallet can never oversell the hold");
        // A settled attempt is terminal; a released/failed/denied one too.
        if links.attempt.state == PAYMENT_ATTEMPT_SETTLED {
            prop_assert_eq!(balance, 1_000 - hold_amount);
        }
        if matches!(
            links.attempt.state.as_str(),
            PAYMENT_ATTEMPT_RELEASED | PAYMENT_ATTEMPT_FAILED | PAYMENT_ATTEMPT_DENIED
        ) {
            prop_assert_ne!(
                links.reservation.as_ref().map(|r| r.status.as_str()),
                Some(WALLET_RESERVATION_SETTLED)
            );
        }
    }
}
