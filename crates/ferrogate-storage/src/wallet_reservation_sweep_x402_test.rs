// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Money-safety coverage for `sweep_expired_wallet_reservations`
// (#396, narrowed by the #352 review §3 when the sweep was finally SCHEDULED).
// The blunt #281 sweeper released ANY active hold past its TTL, ignoring the
// owning x402 payment attempt -- so once scheduled it could release a
// `submitted`/`outcome_unknown` attempt's hold whose stablecoin transfer may
// already be on-chain (double-charging or losing the hold), and it could also
// release a PRE-submission attempt's hold behind that attempt's back, which is
// just as bad in a subtler way: `list_expirable_due_payment_attempts` joins on
// `wr.status = 'active'`, so an attempt whose hold this sweep released becomes
// permanently invisible to the loop that owns its state and is stranded in
// `authorized` forever. These tests pin the narrowed guard: a hold that ANY
// payment attempt owns is never swept here, and what IS swept is the orphan --
// a reserve that committed while its `create_payment_attempt` did not, plus
// genuinely non-x402 reservations. Expiry is driven by an injected `now_unix`,
// never a timing sleep; the in-memory backend is the mirror of the Postgres
// `NOT EXISTS` guard.

use crate::schema_routing_test_support::block_on;
use crate::{
    PaymentAttemptEvidenceArgs, RuntimeStorageRepositories, StorageProviderKind,
    StoredPaymentAttempt, StoredWallet, PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_CHALLENGED,
    WALLET_RESERVATION_ACTIVE,
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

/// An attempt bound to `hold_id` in the given INITIAL state (create only accepts
/// `challenged`/`authorized`/`denied`). Only the columns the sweep guard reads
/// (`hold_id`, `state`) are load-bearing; the rest are plausible filler.
fn attempt_bound_to(id: &str, tenant: &str, state: &str, hold_id: &str) -> StoredPaymentAttempt {
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
        atomic_amount: "250".into(),
        recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM".into(),
        credits_amount: Some(250),
        conversion_version: Some("rate-2026-07".into()),
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_id: Some(hold_id.into()),
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

/// A hold bound to a `submitted` x402 attempt (proof already on-chain) is the
/// exact money-safety hazard #396 fixes: even though the hold is `active` and
/// past its TTL, the sweep must NOT release it -- the transfer may have landed,
/// so the hold stays retained for the #354 reconciler.
#[test]
fn sweep_does_not_release_hold_bound_to_submitted_x402_attempt() {
    let repositories = repositories_with_wallet("tenant-a", 1_000);
    // reserve -> create(authorized) -> submit: the hold is still `active`
    // (submitted retains the hold), and its TTL (10) is well past `now = 100`.
    block_on(repositories.reserve_wallet_credits("hold-sub", "tenant-a", 250, 10, 1)).unwrap();
    block_on(repositories.create_payment_attempt(attempt_bound_to(
        "att-sub",
        "tenant-a",
        PAYMENT_ATTEMPT_AUTHORIZED,
        "hold-sub",
    )))
    .unwrap();
    block_on(repositories.submit_payment_attempt(
        "att-sub",
        PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(50),
            transaction_signature: Some("5".repeat(88).as_str()),
            ..Default::default()
        },
        50,
    ))
    .unwrap();

    let swept = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
    assert!(
        swept.is_empty(),
        "a hold bound to a submitted x402 attempt must never be swept: {swept:?}"
    );

    // The hold is still live and reservable-blocking: settling it later still
    // works, proving the money was retained, not lost.
    let reservation = block_on(repositories.list_wallet_reservations("tenant-a"))
        .unwrap()
        .into_iter()
        .find(|r| r.id == "hold-sub")
        .expect("hold present");
    assert_eq!(
        reservation.status, WALLET_RESERVATION_ACTIVE,
        "the submitted attempt's hold stays active"
    );
}

/// A hold bound to a PRE-submission (`authorized`/`challenged`) attempt is NOT
/// swept here either (#352 review §3). It is owned by the attempt-driven TTL
/// pass, which releases the hold and moves the attempt to `released` in one
/// re-driveable edge. Releasing it from this sweep would strand the attempt: the
/// attempt-side due query joins on `wr.status = 'active'`, so the loop that owns
/// its state would never see it again.
///
/// Delete the `NOT EXISTS` guard (Postgres) or the `protected` set (memory) and
/// this test goes red on the first iteration.
#[test]
fn sweep_does_not_release_hold_owned_by_a_pre_submission_attempt() {
    for pre_submission in [PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_CHALLENGED] {
        let repositories = repositories_with_wallet("tenant-b", 1_000);
        block_on(repositories.reserve_wallet_credits("hold-pre", "tenant-b", 250, 10, 1)).unwrap();
        block_on(repositories.create_payment_attempt(attempt_bound_to(
            "att-pre",
            "tenant-b",
            pre_submission,
            "hold-pre",
        )))
        .unwrap();

        let swept = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
        assert!(
            swept.is_empty(),
            "a hold owned by a {pre_submission} attempt belongs to the attempt-driven pass, \
             not to this sweep: {swept:?}"
        );
        // And it is still `active`, i.e. still visible to the attempt-driven
        // due query that joins on `wr.status = 'active'`.
        let reservation = block_on(repositories.list_wallet_reservations("tenant-b"))
            .unwrap()
            .into_iter()
            .find(|r| r.id == "hold-pre")
            .expect("hold present");
        assert_eq!(reservation.status, WALLET_RESERVATION_ACTIVE);
    }
}

/// The ORPHAN this sweep exists for (#352 review §3): `reserve_wallet_credits`
/// committed and `create_payment_attempt` never did, because the process died in
/// the window between the two transactions. Nothing else re-drives that row --
/// the attempt-driven pass is an INNER JOIN from the attempt side, so a hold with
/// no attempt is structurally invisible to it -- and available balance
/// self-heals, so the wallet is not oversold but every consumer reading `status`
/// reports a phantom live hold forever.
///
/// This is the same shape as a genuinely non-x402 reservation, which keeps the
/// original #281 behavior.
#[test]
fn sweep_releases_an_expired_hold_no_attempt_owns() {
    let repositories = repositories_with_wallet("tenant-c", 1_000);
    // The crash window: the reserve committed, the attempt create did not.
    block_on(repositories.reserve_wallet_credits("hold-plain", "tenant-c", 250, 10, 1)).unwrap();

    let swept = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
    assert_eq!(
        swept,
        vec!["hold-plain".to_string()],
        "an expired hold that no payment attempt owns must be reclaimed"
    );
    let reservation = block_on(repositories.list_wallet_reservations("tenant-c"))
        .unwrap()
        .into_iter()
        .find(|r| r.id == "hold-plain")
        .expect("hold present");
    assert_eq!(
        reservation.status,
        crate::WALLET_RESERVATION_RELEASED,
        "the orphan stops reporting itself as a live hold"
    );

    // Idempotent: a second pass finds nothing left to release.
    let again = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
    assert!(
        again.is_empty(),
        "the orphan sweep must be idempotent: {again:?}"
    );
}

/// A hold no attempt owns but that has NOT yet expired is left alone: this sweep
/// reclaims overdue orphans, it does not cancel live ones.
#[test]
fn sweep_leaves_an_unexpired_orphan_hold_alone() {
    let repositories = repositories_with_wallet("tenant-e", 1_000);
    block_on(repositories.reserve_wallet_credits("hold-live", "tenant-e", 250, 500, 1)).unwrap();

    let swept = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
    assert!(
        swept.is_empty(),
        "a hold whose TTL has not elapsed must not be released: {swept:?}"
    );
}

/// A hold bound to an `outcome_unknown` x402 attempt (parked by the reconciler,
/// hold deliberately retained) must also survive the sweep -- it is disjoint
/// from the pre-submission expirable set, same as `submitted`.
#[test]
fn sweep_does_not_release_hold_bound_to_outcome_unknown_x402_attempt() {
    let repositories = repositories_with_wallet("tenant-d", 1_000);
    block_on(repositories.reserve_wallet_credits("hold-unk", "tenant-d", 250, 10, 1)).unwrap();
    block_on(repositories.create_payment_attempt(attempt_bound_to(
        "att-unk",
        "tenant-d",
        PAYMENT_ATTEMPT_AUTHORIZED,
        "hold-unk",
    )))
    .unwrap();
    // authorized -> submitted -> outcome_unknown (parked, hold retained).
    block_on(repositories.submit_payment_attempt(
        "att-unk",
        PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(50),
            transaction_signature: Some("5".repeat(88).as_str()),
            ..Default::default()
        },
        50,
    ))
    .unwrap();
    block_on(repositories.mark_payment_attempt_outcome_unknown(
        "att-unk",
        PaymentAttemptEvidenceArgs::default(),
        60,
    ))
    .unwrap();

    let swept = block_on(repositories.sweep_expired_wallet_reservations(100)).unwrap();
    assert!(
        swept.is_empty(),
        "a hold bound to an outcome_unknown x402 attempt must never be swept: {swept:?}"
    );
}
