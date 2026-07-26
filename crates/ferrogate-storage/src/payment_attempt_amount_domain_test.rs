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
    RuntimeStorageRepositories, StorageError, StorageProviderKind, StoredPaymentAttempt,
    StoredWallet, PAYMENT_ATTEMPT_AUTHORIZED,
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

/// The exact values the review named, plus the shapes a naive "is it numeric"
/// check would let through. Delete `validate_payment_attempt_amounts(&attempt)?`
/// from either create body and this test goes red on the first case.
#[test]
fn a_non_canonical_atomic_amount_is_refused_at_create() {
    for bad in [
        "",                      // empty
        "-5",                    // signed
        "1e9",                   // exponent
        " 250",                  // leading space
        "250 ",                  // trailing space
        "0x10",                  // hex
        "25.0",                  // fractional
        "+250",                  // explicit sign
        "184467440737095516150", // 21 digits: wider than u64::MAX
    ] {
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
#[test]
fn the_canonical_u64_range_is_accepted() {
    for good in ["0", "1", "250000", "18446744073709551615"] {
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
