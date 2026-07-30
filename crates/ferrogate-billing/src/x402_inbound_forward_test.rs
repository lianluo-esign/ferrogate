// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Unit and property tests for the inbound x402 forward-once claim
// state machine (issue #356): admitted/duplicate-retry/proof-replay separation,
// TTL expiry, capacity fail-closed, and release ownership.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use proptest::prelude::*;

use super::*;

const TTL: u64 = 600;
const KEY: &str = "x402-inbound:deadbeef:sig-1";

fn guard() -> InMemoryForwardClaimGuard {
    InMemoryForwardClaimGuard::new(TTL, 64).expect("ttl and capacity are non-zero")
}

// -------------------------------------------------------------------------
// The three outcomes
// -------------------------------------------------------------------------

#[test]
fn the_first_claimant_is_admitted() {
    let guard = guard();
    let outcome = guard
        .claim(KEY, "sidecar-1", 1_000)
        .expect("guard has room");
    assert_eq!(outcome, ClaimOutcome::Admitted);
    assert!(outcome.forwards());
    assert_eq!(outcome.as_str(), "admitted");
    assert_eq!(guard.live_claims().expect("readable"), 1);
}

#[test]
fn the_same_sidecar_request_arriving_again_is_an_idempotent_retry() {
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 1_000).expect("first claim");
    let outcome = guard.claim(KEY, "sidecar-1", 1_030).expect("second claim");
    assert_eq!(
        outcome,
        ClaimOutcome::DuplicateRetry {
            first_request_id: "sidecar-1".to_string(),
            claimed_at_unix: 1_000,
        }
    );
    assert!(
        !outcome.forwards(),
        "an idempotent retry must not invoke the handler a second time"
    );
}

#[test]
fn a_different_request_presenting_the_same_payment_is_a_replay() {
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 1_000).expect("first claim");
    let outcome = guard.claim(KEY, "sidecar-2", 1_005).expect("second claim");
    assert_eq!(
        outcome,
        ClaimOutcome::ProofReplay {
            first_request_id: "sidecar-1".to_string(),
            claimed_at_unix: 1_000,
        }
    );
    assert!(!outcome.forwards());
    assert_eq!(outcome.as_str(), "proof_replay");
}

#[test]
fn replay_and_retry_are_distinguished_only_by_the_request_id() {
    // This is the discriminator the code review named: collapse it and a stolen
    // proof becomes a benign-looking retry.
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 1_000).expect("first claim");
    let retry = guard.claim(KEY, "sidecar-1", 1_001).expect("retry");
    let replay = guard.claim(KEY, "sidecar-2", 1_001).expect("replay");
    assert_ne!(retry, replay);
    assert!(matches!(retry, ClaimOutcome::DuplicateRetry { .. }));
    assert!(matches!(replay, ClaimOutcome::ProofReplay { .. }));
}

#[test]
fn distinct_payments_each_get_their_own_claim() {
    let guard = guard();
    assert_eq!(
        guard.claim("key-a", "sidecar-1", 1_000).expect("claim a"),
        ClaimOutcome::Admitted
    );
    assert_eq!(
        guard.claim("key-b", "sidecar-2", 1_000).expect("claim b"),
        ClaimOutcome::Admitted
    );
    assert_eq!(guard.live_claims().expect("readable"), 2);
}

// -------------------------------------------------------------------------
// TTL
// -------------------------------------------------------------------------

#[test]
fn a_claim_still_blocks_one_second_before_the_ttl_expires() {
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 1_000).expect("first claim");
    let outcome = guard
        .claim(KEY, "sidecar-2", 1_000 + TTL - 1)
        .expect("still inside the window");
    assert!(matches!(outcome, ClaimOutcome::ProofReplay { .. }));
}

#[test]
fn a_claim_is_released_exactly_at_the_ttl_boundary() {
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 1_000).expect("first claim");
    let outcome = guard
        .claim(KEY, "sidecar-2", 1_000 + TTL)
        .expect("the window has closed");
    assert_eq!(outcome, ClaimOutcome::Admitted);
}

#[test]
fn a_backwards_clock_does_not_expire_live_claims() {
    // NTP steps and stale callers move `now_unix` backwards. Expiring on that
    // would release live claims, so the safe direction is to keep them.
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 10_000).expect("first claim");
    let outcome = guard
        .claim(KEY, "sidecar-2", 9_000)
        .expect("clock moved backwards");
    assert!(matches!(outcome, ClaimOutcome::ProofReplay { .. }));
}

#[test]
fn expired_claims_are_pruned_rather_than_accumulated() {
    let guard = guard();
    for index in 0..10 {
        guard
            .claim(&format!("key-{index}"), "sidecar-1", 1_000)
            .expect("room for ten");
    }
    assert_eq!(guard.live_claims().expect("readable"), 10);
    guard
        .claim("key-fresh", "sidecar-2", 1_000 + TTL)
        .expect("all ten are expired by now");
    assert_eq!(
        guard.live_claims().expect("readable"),
        1,
        "pruning must run on the claim path, not only on a background sweep"
    );
}

// -------------------------------------------------------------------------
// Capacity: fail closed, never evict
// -------------------------------------------------------------------------

#[test]
fn a_full_guard_refuses_rather_than_evicting_a_live_claim() {
    let guard = InMemoryForwardClaimGuard::new(TTL, 2).expect("valid bounds");
    guard.claim("key-a", "sidecar-1", 1_000).expect("first");
    guard.claim("key-b", "sidecar-2", 1_000).expect("second");
    let error = guard
        .claim("key-c", "sidecar-3", 1_000)
        .expect_err("the guard is full and must fail closed");
    assert_eq!(error.code, "billing_x402_inbound_claim_capacity");
    // The live claims survived — evicting one is how a replay gets admitted.
    assert!(matches!(
        guard
            .claim("key-a", "sidecar-9", 1_000)
            .expect("still held"),
        ClaimOutcome::ProofReplay { .. }
    ));
}

#[test]
fn a_full_guard_still_answers_for_keys_it_already_holds() {
    let guard = InMemoryForwardClaimGuard::new(TTL, 1).expect("valid bounds");
    guard.claim("key-a", "sidecar-1", 1_000).expect("first");
    assert!(matches!(
        guard
            .claim("key-a", "sidecar-1", 1_010)
            .expect("retry path"),
        ClaimOutcome::DuplicateRetry { .. }
    ));
}

#[test]
fn zero_ttl_and_zero_capacity_are_rejected_at_construction() {
    assert_eq!(
        InMemoryForwardClaimGuard::new(0, 10).expect_err("zero ttl"),
        ForwardClaimGuardError::ZeroTtl
    );
    assert_eq!(
        InMemoryForwardClaimGuard::new(10, 0).expect_err("zero capacity"),
        ForwardClaimGuardError::ZeroCapacity
    );
}

// -------------------------------------------------------------------------
// Release ownership
// -------------------------------------------------------------------------

#[test]
fn only_the_claim_holder_may_release_it() {
    let guard = guard();
    guard.claim(KEY, "sidecar-1", 1_000).expect("first claim");
    assert!(
        !guard.release(KEY, "sidecar-2").expect("readable"),
        "a non-holder releasing would be a free replay primitive"
    );
    assert!(matches!(
        guard.claim(KEY, "sidecar-2", 1_001).expect("still held"),
        ClaimOutcome::ProofReplay { .. }
    ));
    assert!(guard.release(KEY, "sidecar-1").expect("holder releases"));
    assert_eq!(
        guard.claim(KEY, "sidecar-2", 1_002).expect("now free"),
        ClaimOutcome::Admitted
    );
}

#[test]
fn releasing_an_unknown_key_is_a_no_op() {
    let guard = guard();
    assert!(!guard
        .release("nothing-here", "sidecar-1")
        .expect("readable"));
}

// -------------------------------------------------------------------------
// Concurrency: exactly one winner
// -------------------------------------------------------------------------

#[test]
fn racing_requests_for_one_payment_produce_exactly_one_admission() {
    let guard = Arc::new(guard());
    let mut handles = Vec::new();
    for index in 0..16 {
        let guard = Arc::clone(&guard);
        handles.push(thread::spawn(move || {
            guard
                .claim(KEY, &format!("sidecar-{index}"), 1_000)
                .expect("guard has room for one key")
        }));
    }
    let admitted = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker did not panic"))
        .filter(ClaimOutcome::forwards)
        .count();
    assert_eq!(admitted, 1, "forward-once must hold under a race");
}

// -------------------------------------------------------------------------
// Property: the invariants across generated sequences
// -------------------------------------------------------------------------

proptest! {
    /// Across any interleaving of (payment_key, request_id, now_unix):
    ///
    /// 1. at most one `Admitted` per key within a TTL window, and
    /// 2. `DuplicateRetry` iff the arriving request id equals the first
    ///    claimant's — the discriminator that separates a payer's retry from a
    ///    stolen proof.
    ///
    /// The clock is generated non-decreasing because a real request stream is;
    /// the backwards-clock case is pinned by its own unit test above.
    #[test]
    fn claims_are_forward_once_and_retry_is_exactly_the_matching_request_id(
        ops in prop::collection::vec(
            (0usize..4, 0usize..4, 0u64..40),
            1..60,
        ),
    ) {
        // A capacity above the key space, so nothing fails closed here; the
        // capacity path has its own unit test.
        let guard = InMemoryForwardClaimGuard::new(TTL, 32).expect("valid bounds");

        // Mirror of what the guard should believe, maintained independently.
        let mut expected: HashMap<String, (String, u64)> = HashMap::new();
        let mut now: u64 = 1_000;

        for (key_index, request_index, advance) in ops {
            now += advance;
            let key = format!("key-{key_index}");
            let request_id = format!("sidecar-{request_index}");

            // Expire the mirror the same way the guard does.
            expected.retain(|_, (_, claimed_at)| now.saturating_sub(*claimed_at) < TTL);

            let outcome = guard
                .claim(&key, &request_id, now)
                .expect("capacity exceeds the key space");

            match expected.get(&key).cloned() {
                None => {
                    prop_assert_eq!(&outcome, &ClaimOutcome::Admitted);
                    expected.insert(key, (request_id, now));
                }
                Some((first_request_id, claimed_at)) => {
                    if first_request_id == request_id {
                        prop_assert_eq!(
                            &outcome,
                            &ClaimOutcome::DuplicateRetry {
                                first_request_id,
                                claimed_at_unix: claimed_at,
                            }
                        );
                    } else {
                        prop_assert_eq!(
                            &outcome,
                            &ClaimOutcome::ProofReplay {
                                first_request_id,
                                claimed_at_unix: claimed_at,
                            }
                        );
                    }
                    prop_assert!(!outcome.forwards());
                }
            }
        }
    }

    /// A released claim is re-claimable by anyone; an unreleased one is not.
    /// Ownership is the whole guard here: release by a non-holder must not open
    /// the window.
    #[test]
    fn release_only_opens_the_window_for_the_holder(
        holder in 0usize..3,
        releaser in 0usize..3,
    ) {
        let guard = InMemoryForwardClaimGuard::new(TTL, 8).expect("valid bounds");
        let holder_id = format!("sidecar-{holder}");
        let releaser_id = format!("sidecar-{releaser}");
        prop_assert_eq!(
            guard.claim(KEY, &holder_id, 1_000).expect("first claim"),
            ClaimOutcome::Admitted
        );
        let released = guard.release(KEY, &releaser_id).expect("readable");
        prop_assert_eq!(released, holder == releaser);

        let next = guard.claim(KEY, "sidecar-outsider", 1_001).expect("readable");
        if holder == releaser {
            prop_assert_eq!(next, ClaimOutcome::Admitted);
        } else {
            prop_assert!(!next.forwards());
        }
    }
}
