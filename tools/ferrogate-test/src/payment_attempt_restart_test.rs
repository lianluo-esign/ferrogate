// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the durable x402 payment-attempt restart
// fixture (issue #352). These assert the EXPECTATION the live restart scenario
// compares against, so a fixture that would silently accept a wrong durable row
// fails here first -- without needing a database.

use super::*;
use ferrogate_storage::{
    payment_attempt_state_is_terminal, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN, PAYMENT_ATTEMPT_SETTLED,
};

const RESOURCE_ID: &str = "ferrogate-postgres-test-1783641600";

fn fixture() -> DurablePaymentAttemptFixture {
    DurablePaymentAttemptFixture::new(RESOURCE_ID)
}

/// Every id is scoped to the scenario's per-run resource id, so two scenarios
/// (or a rerun against a retained database) can never collide on a primary key
/// and read each other's rows back as "durable".
#[test]
fn every_fixture_id_is_scoped_to_the_run() {
    let fixture = fixture();
    let settled = fixture.expected_settled();
    let unknown = fixture.expected_outcome_unknown();
    for id in [
        fixture.tenant_id.as_str(),
        settled.id.as_str(),
        unknown.id.as_str(),
        settled.hold_id.as_deref().expect("settled hold"),
        unknown.hold_id.as_deref().expect("unknown hold"),
    ] {
        assert!(id.starts_with(RESOURCE_ID), "unscoped fixture id {id}");
    }
    assert_ne!(settled.id, unknown.id);
    assert_ne!(settled.hold_id, unknown.hold_id);
    // Two distinct payments may never share one challenge: the challenge hash is
    // part of the immutable identity tuple a create replay fails closed on.
    assert_ne!(settled.challenge_hash, unknown.challenge_hash);
}

/// The settled leg is terminal, carries its transaction signature and the exact
/// settled amount, and reached that state through exactly three applied
/// transitions (`generation` is the operation token the scheduler preserves).
#[test]
fn settled_expectation_is_terminal_with_full_evidence() {
    let settled = fixture().expected_settled();
    assert_eq!(settled.state, PAYMENT_ATTEMPT_SETTLED);
    assert!(payment_attempt_state_is_terminal(&settled.state));
    assert_eq!(settled.generation, 3);
    assert_eq!(
        settled.transaction_signature.as_deref(),
        Some(SETTLED_SIGNATURE)
    );
    assert_eq!(
        settled.settled_atomic_amount.as_deref(),
        Some(SETTLED_ATOMIC_AMOUNT)
    );
    // Exact-amount settlement: what settled equals what was owed.
    assert_eq!(settled.settled_atomic_amount, Some(settled.atomic_amount));
    assert_eq!(settled.submitted_at_unix, Some(SUBMIT_UNIX));
    assert_eq!(settled.failure_code, None);
}

/// The money-critical one: post-submission ambiguity is NOT terminal, is not a
/// failure, and keeps its evidence. (That its hold stays `active` is asserted
/// against the live row by `expect_durable_after_restart`.)
#[test]
fn outcome_unknown_expectation_is_non_terminal_and_never_a_failure() {
    let unknown = fixture().expected_outcome_unknown();
    assert_eq!(unknown.state, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN);
    assert!(!payment_attempt_state_is_terminal(&unknown.state));
    assert_eq!(unknown.failure_code, None);
    assert_eq!(unknown.settled_atomic_amount, None);
    assert_eq!(
        unknown.transaction_signature.as_deref(),
        Some(UNKNOWN_SIGNATURE)
    );
    assert_eq!(unknown.submitted_at_unix, Some(SUBMIT_UNIX));
    assert!(unknown.hold_id.is_some(), "the hold must stay linked");
    assert_eq!(unknown.generation, 3);
}

/// The transitions may only touch the mutable state/evidence tail. If a future
/// edit moved an immutable audit field into an expectation, the live scenario
/// would "pass" while silently accepting a rewritten challenge tuple.
#[test]
fn transitions_never_rewrite_the_immutable_audit_tuple() {
    let fixture = fixture();
    for (seed, expected) in [
        (
            fixture.seed_record(AttemptLeg::Settled),
            fixture.expected_settled(),
        ),
        (
            fixture.seed_record(AttemptLeg::OutcomeUnknown),
            fixture.expected_outcome_unknown(),
        ),
    ] {
        assert_eq!(seed.id, expected.id);
        assert_eq!(seed.tenant_id, expected.tenant_id);
        assert_eq!(seed.challenge_hash, expected.challenge_hash);
        assert_eq!(seed.x402_version, expected.x402_version);
        assert_eq!(seed.network_caip2, expected.network_caip2);
        assert_eq!(seed.mint, expected.mint);
        assert_eq!(seed.atomic_amount, expected.atomic_amount);
        assert_eq!(seed.recipient, expected.recipient);
        assert_eq!(seed.resource_url, expected.resource_url);
        assert_eq!(seed.request_body_hash, expected.request_body_hash);
        assert_eq!(seed.policy_revision, expected.policy_revision);
        assert_eq!(seed.decision, expected.decision);
        assert_eq!(seed.credits_amount, expected.credits_amount);
        assert_eq!(seed.hold_id, expected.hold_id);
        assert_eq!(seed.created_at_unix, expected.created_at_unix);
        // ... and the seed itself is a legal create state with no evidence yet.
        assert_eq!(seed.state, PAYMENT_ATTEMPT_CHALLENGED);
        assert_eq!(seed.generation, 0);
        assert_eq!(seed.transaction_signature, None);
        assert_eq!(seed.submitted_at_unix, None);
    }
}

/// The durable body hash is the real SHA-256 of the fixture body, not a
/// hand-copied literal that could drift from what a runtime would compute.
#[test]
fn request_body_hash_is_the_sha256_of_the_fixture_body() {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_BODY.as_bytes());
    let expected = format!("{:x}", hasher.finalize());
    assert_eq!(request_body_hash(), expected);
    assert_eq!(expected.len(), 64);
    assert_eq!(
        fixture().expected_settled().request_body_hash,
        Some(expected)
    );
}

/// A drifted durable row must name the column that drifted, and an identical
/// row must pass.
#[test]
fn expect_attempt_eq_reports_the_drifted_column() {
    let fixture = fixture();
    let expected = fixture.expected_settled();
    expect_attempt_eq(&expected, &expected, "same").expect("identical rows compare equal");

    let mut released = expected.clone();
    released.state = "released".into();
    let error = expect_attempt_eq(&released, &expected, "restart")
        .expect_err("a state drift must fail")
        .to_string();
    assert!(error.contains("state"), "{error}");
    assert!(error.contains("restart"), "{error}");

    let mut rewritten = expected.clone();
    rewritten.transaction_signature = Some(CONFLICTING_SIGNATURE.into());
    let error = expect_attempt_eq(&rewritten, &expected, "restart")
        .expect_err("a signature rewrite must fail")
        .to_string();
    assert!(error.contains("transaction_signature"), "{error}");
}

/// A missing or wrong-status hold is a durability failure, not a pass. The
/// `outcome_unknown` leg in particular must reject a hold that came back
/// `released`.
#[test]
fn expect_reservation_rejects_a_lost_or_released_hold() {
    let fixture = fixture();
    let attempt = fixture.expected_outcome_unknown();
    let hold_id = attempt.hold_id.clone().expect("hold");

    let missing = PaymentAttemptLinks {
        attempt: attempt.clone(),
        reservation: None,
        settlement: None,
    };
    assert!(expect_reservation(
        &missing,
        &hold_id,
        UNKNOWN_CREDITS,
        WALLET_RESERVATION_ACTIVE,
        "restart"
    )
    .is_err());

    let released = PaymentAttemptLinks {
        attempt,
        reservation: Some(ferrogate_storage::StoredWalletReservation {
            id: hold_id.clone(),
            tenant_id: fixture.tenant_id.clone(),
            amount_credits: UNKNOWN_CREDITS,
            status: ferrogate_storage::WALLET_RESERVATION_RELEASED.into(),
            expires_at_unix: SEED_UNIX + HOLD_TTL_SECONDS,
            settlement_id: None,
            created_at_unix: SEED_UNIX,
            updated_at_unix: SEED_UNIX,
        }),
        settlement: None,
    };
    let error = expect_reservation(
        &released,
        &hold_id,
        UNKNOWN_CREDITS,
        WALLET_RESERVATION_ACTIVE,
        "restart",
    )
    .expect_err("a released hold under outcome_unknown must fail")
    .to_string();
    assert!(error.contains("status active"), "{error}");
}
