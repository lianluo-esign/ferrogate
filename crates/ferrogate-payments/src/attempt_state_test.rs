// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the x402 payment-attempt state alphabet
// (issue #352 `ferrogate-payments` scope bullet). Pins the durable spellings,
// the round trip, and the money-critical classification: the TTL-sweepable set
// and the reconcilable set must stay DISJOINT, and `outcome_unknown` must stay
// non-terminal and out of the sweepable set.

use super::PaymentAttemptState;

#[test]
fn every_state_round_trips_through_its_durable_spelling() {
    for state in PaymentAttemptState::ALL {
        assert_eq!(
            PaymentAttemptState::parse(state.as_str()),
            Some(*state),
            "{state:?} did not round-trip"
        );
    }
    assert_eq!(PaymentAttemptState::ALL.len(), 8);
    // A variant added without an `ALL` entry would make this set smaller than
    // the arm count in `as_str`, which is exhaustive by the compiler.
    let spellings: std::collections::BTreeSet<&str> = PaymentAttemptState::ALL
        .iter()
        .map(|state| state.as_str())
        .collect();
    assert_eq!(spellings.len(), 8, "duplicate durable spelling");
}

#[test]
fn unknown_spelling_is_refused_rather_than_defaulted() {
    assert_eq!(PaymentAttemptState::parse(""), None);
    assert_eq!(PaymentAttemptState::parse("Settled"), None);
    assert_eq!(PaymentAttemptState::parse("unknown"), None);
}

#[test]
fn outcome_unknown_is_non_terminal_and_retains_its_hold() {
    let unknown = PaymentAttemptState::OutcomeUnknown;
    assert!(
        !unknown.is_terminal(),
        "outcome_unknown must be non-terminal"
    );
    assert!(
        unknown.retains_hold_when_unresolved(),
        "post-submission ambiguity must RETAIN the hold"
    );
    // The money-critical exclusion: never sweepable.
    assert!(!unknown.is_pre_submission());
    assert!(unknown.is_reconcilable());
    // It is the ONLY state that retains a hold while unresolved.
    for state in PaymentAttemptState::ALL {
        assert_eq!(
            state.retains_hold_when_unresolved(),
            *state == PaymentAttemptState::OutcomeUnknown,
            "{state:?} disagrees about hold retention"
        );
    }
}

#[test]
fn sweepable_and_reconcilable_sets_are_disjoint_and_non_terminal() {
    for state in PaymentAttemptState::ALL {
        assert!(
            !(state.is_pre_submission() && state.is_reconcilable()),
            "{state:?} is in BOTH background loops' sets"
        );
        if state.is_pre_submission() || state.is_reconcilable() {
            assert!(!state.is_terminal(), "{state:?} is terminal yet actionable");
        }
    }
    assert!(PaymentAttemptState::Submitted.is_reconcilable());
    assert!(!PaymentAttemptState::Submitted.is_pre_submission());
    assert!(PaymentAttemptState::Authorized.is_pre_submission());
    assert!(PaymentAttemptState::Challenged.is_pre_submission());
}

#[test]
fn terminal_and_initial_sets_match_the_documented_truth_table() {
    let terminal: Vec<&str> = PaymentAttemptState::ALL
        .iter()
        .filter(|state| state.is_terminal())
        .map(|state| state.as_str())
        .collect();
    assert_eq!(terminal, vec!["settled", "denied", "released", "failed"]);

    let initial: Vec<&str> = PaymentAttemptState::ALL
        .iter()
        .filter(|state| state.is_initial())
        .map(|state| state.as_str())
        .collect();
    assert_eq!(initial, vec!["challenged", "authorized", "denied"]);
}
