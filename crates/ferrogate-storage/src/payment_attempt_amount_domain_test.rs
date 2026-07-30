// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Coverage for the payment-attempt money-column domain (issue #352
// review §4). `atomic_amount` is TEXT because an on-chain u64 exceeds BIGINT's
// i64 range -- that choice is right, but it left the column with NO domain:
// "", "-5" and "1e9" were all storable into a durable audit record that
// `evidence_conflict` compares as opaque strings and the reconciler parses
// downstream. Migration 59 adds the Postgres CHECKs; these tests pin the
// application mirror so the memory backend refuses exactly the same set (the
// #188 conformance obligation), rather than accepting what the database rejects.

use crate::schema_routing_test_support::block_on;
use crate::{
    is_canonical_atomic_amount, RuntimeStorageRepositories, StorageError, StorageProviderKind,
    StoredPaymentAttempt, StoredWallet, AMOUNT_CORPUS, PAYMENT_ATTEMPT_AUTHORIZED,
};

fn amount_domain_repositories() -> RuntimeStorageRepositories {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    block_on(repositories.upsert_wallet(StoredWallet {
        id: "tenant-a".into(),
        tenant_id: "tenant-a".into(),
        balance_credits: 1_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    repositories
}

fn attempt(id: &str) -> StoredPaymentAttempt {
    StoredPaymentAttempt {
        id: id.into(),
        tenant_id: "tenant-a".into(),
        project_id: None,
        workspace_id: None,
        run_id: None,
        worker_id: None,
        request_id: None,
        trace_id: None,
        method: "GET".into(),
        resource_url: "https://api.example.com/v1/weather".into(),
        request_body_hash: None,
        challenge_hash: "b".repeat(64),
        x402_version: 2,
        scheme: "exact".into(),
        network_caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".into(),
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
        atomic_amount: "250000".into(),
        recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM".into(),
        credits_amount: Some(250),
        conversion_version: None,
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_id: None,
        state: PAYMENT_ATTEMPT_AUTHORIZED.into(),
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

/// Every value in the shared corpus that the domain refuses must be refused by
/// the create path too. Delete `validate_payment_attempt_amounts(&attempt)?`
/// from either create body and this test goes red on the first case.
///
/// The bad set is DERIVED from `is_canonical_atomic_amount` rather than
/// hand-listed (#352 review round 4), so a value added to [`AMOUNT_CORPUS`] for
/// the SQL conformance proof is automatically exercised here as well. The two
/// halves of the money domain now read one list and split it by one rule; they
/// cannot drift apart while both keep passing.
#[test]
fn a_non_canonical_atomic_amount_is_refused_at_create() {
    let bad_values: Vec<&str> = AMOUNT_CORPUS
        .into_iter()
        .filter(|value| !is_canonical_atomic_amount(value))
        .collect();
    // Anti-vacuity: an empty (or trivially small) bad set would make the loop
    // below assert nothing while still reporting success.
    assert!(
        bad_values.len() >= 4,
        "the corpus must carry values the domain refuses, got {bad_values:?}"
    );
    for bad in bad_values {
        let repositories = amount_domain_repositories();
        let mut candidate = attempt("att-bad");
        candidate.atomic_amount = bad.into();
        let error = block_on(repositories.create_payment_attempt(candidate))
            .expect_err(&format!("atomic_amount {bad:?} must be refused"));
        assert!(
            matches!(error, StorageError::Conflict(ref message) if message.contains("atomic_amount")),
            "{bad:?} produced the wrong error: {error:?}"
        );
        // Nothing was persisted.
        assert!(block_on(repositories.get_payment_attempt("att-bad"))
            .unwrap()
            .is_none());
    }
}

/// The canonical shapes must still pass, including the full `u64` range that is
/// the whole reason the column is TEXT.
///
/// Derived from the same corpus and the same rule as the refusal test above, so
/// the two directions cannot be given different lists.
#[test]
fn the_canonical_u64_range_is_accepted() {
    let good_values: Vec<&str> = AMOUNT_CORPUS
        .into_iter()
        .filter(|value| is_canonical_atomic_amount(value))
        .collect();
    assert!(
        good_values.len() >= 4,
        "the corpus must carry values the domain accepts, got {good_values:?}"
    );
    assert!(
        good_values.contains(&"18446744073709551615"),
        "the u64::MAX width is the whole reason this column is TEXT: {good_values:?}"
    );
    for good in good_values {
        let repositories = amount_domain_repositories();
        let mut candidate = attempt("att-good");
        candidate.atomic_amount = good.into();
        let created = block_on(repositories.create_payment_attempt(candidate));
        assert!(created.is_ok(), "atomic_amount {good:?} must be accepted");
    }
}

#[test]
fn a_non_canonical_settled_amount_is_refused_at_create() {
    let repositories = amount_domain_repositories();
    let mut candidate = attempt("att-settled");
    candidate.settled_atomic_amount = Some("-1".into());
    let error = block_on(repositories.create_payment_attempt(candidate))
        .expect_err("a negative settled_atomic_amount must be refused");
    assert!(
        matches!(error, StorageError::Conflict(ref message) if message.contains("settled_atomic_amount")),
        "wrong error: {error:?}"
    );

    // `None` remains legal -- an unsettled attempt has no settled amount.
    let repositories = amount_domain_repositories();
    let mut candidate = attempt("att-unsettled");
    candidate.settled_atomic_amount = None;
    assert!(block_on(repositories.create_payment_attempt(candidate)).is_ok());
}

#[test]
fn a_negative_credits_amount_is_refused_at_create() {
    let repositories = amount_domain_repositories();
    let mut candidate = attempt("att-credits");
    candidate.credits_amount = Some(-1_000_000);
    let error = block_on(repositories.create_payment_attempt(candidate))
        .expect_err("a negative credits_amount must be refused");
    assert!(
        matches!(error, StorageError::Conflict(ref message) if message.contains("credits_amount")),
        "wrong error: {error:?}"
    );

    // Zero is a legal hold size (a free/zero-amount authorization).
    let repositories = amount_domain_repositories();
    let mut candidate = attempt("att-zero");
    candidate.credits_amount = Some(0);
    assert!(block_on(repositories.create_payment_attempt(candidate)).is_ok());
}

/// The domain is enforced on the path that actually writes it in production.
///
/// `settled_atomic_amount` is written by the **transition**, not by a create --
/// so validating only the create bodies left the two backends disagreeing about
/// a money column on the one path production uses (#352 review §2). Migration
/// 59's `payment_attempts_settled_amount_canonical` CHECK applies to `UPDATE`
/// too: Postgres would raise 23514 (which the caller could not tell from a
/// transient outage, so the reconciler re-drove it forever with the hold
/// retained) while the memory twin stored the value.
///
/// The values here are the ones `u128::from_str` accepts and the column does
/// not, which is exactly how they got past `classify_settled_amount` -- a
/// leading `+`, and a 21-digit amount wider than `u64::MAX`. They are
/// attacker-influenced: they arrive verbatim from the facilitator/RPC
/// observation.
///
/// Delete `validate_transition_evidence_amounts(id, evidence)?` from either
/// transition body and this test goes red.
#[test]
fn a_non_canonical_settled_amount_is_refused_at_transition() {
    for bad in [
        "+250000",
        "184467440737095516150",
        "",
        "-1",
        "2.5e5",
        "0x10",
    ] {
        let repositories = amount_domain_repositories();
        block_on(repositories.reserve_wallet_credits("hold-t", "tenant-a", 250, 10_000, 100))
            .unwrap();
        let mut candidate = attempt("att-t");
        candidate.hold_id = Some("hold-t".into());
        block_on(repositories.create_payment_attempt(candidate)).unwrap();
        block_on(repositories.submit_payment_attempt(
            "att-t",
            crate::PaymentAttemptEvidenceArgs {
                submitted_at_unix: Some(200),
                ..Default::default()
            },
            200,
        ))
        .unwrap();

        let error = block_on(repositories.settle_payment_attempt(
            "att-t",
            crate::PaymentAttemptEvidenceArgs {
                transaction_signature: Some(&"5".repeat(88)),
                settled_atomic_amount: Some(bad),
                ..Default::default()
            },
            300,
        ))
        .expect_err(&format!("settled_atomic_amount {bad:?} must be refused"));
        assert!(
            matches!(error, StorageError::Conflict(ref message) if message.contains("settled_atomic_amount")),
            "{bad:?} produced the wrong error: {error:?}"
        );

        // Fail-closed means the row is untouched: still submitted, no evidence
        // recorded, so the hold is RETAINED and the attempt stays inspectable
        // for the reconciler rather than being half-settled.
        let stored = block_on(repositories.get_payment_attempt("att-t"))
            .unwrap()
            .expect("the attempt still exists");
        assert_eq!(stored.state, crate::PAYMENT_ATTEMPT_SUBMITTED);
        assert_eq!(stored.settled_atomic_amount, None);
        assert_eq!(stored.transaction_signature, None);
    }
}

/// The mirror direction: canonical settled amounts still settle, including the
/// full `u64` range and a spec-valid overpayment. A domain check that refused
/// these would break settlement entirely, so the refusal above has to be proven
/// narrow.
#[test]
fn a_canonical_settled_amount_still_settles() {
    for good in ["250000", "250001", "0", "18446744073709551615"] {
        let repositories = amount_domain_repositories();
        block_on(repositories.reserve_wallet_credits("hold-t", "tenant-a", 250, 10_000, 100))
            .unwrap();
        let mut candidate = attempt("att-t");
        candidate.hold_id = Some("hold-t".into());
        block_on(repositories.create_payment_attempt(candidate)).unwrap();
        block_on(repositories.submit_payment_attempt(
            "att-t",
            crate::PaymentAttemptEvidenceArgs {
                submitted_at_unix: Some(200),
                ..Default::default()
            },
            200,
        ))
        .unwrap();
        let settled = block_on(repositories.settle_payment_attempt(
            "att-t",
            crate::PaymentAttemptEvidenceArgs {
                transaction_signature: Some(&"5".repeat(88)),
                settled_atomic_amount: Some(good),
                ..Default::default()
            },
            300,
        ));
        assert!(
            settled.is_ok(),
            "settled_atomic_amount {good:?} must be accepted: {settled:?}"
        );
    }
}
