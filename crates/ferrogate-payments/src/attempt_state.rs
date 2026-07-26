// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: The x402 payment-attempt state alphabet and its transition
// classification (issue #352, `## Scope and ownership`: "ferrogate-payments:
// state/transition types only; no SQL"). Pure types -- no storage, no SQL, no
// I/O -- so both the durable repository and any future consumer name the same
// states from one definition.

//! Payment-attempt state alphabet (issue #352).
//!
//! The issue's binding scope says `ferrogate-payments` owns "state/transition
//! types only; no SQL". This module is that ownership: the eight states, their
//! terminal/pre-submission/post-submission classification, and the string
//! spellings the durable record and the `state` CHECK constraint use.
//!
//! # Why this crate, and why the earlier rationale was wrong
//!
//! The state alphabet originally lived as `&str` consts inside
//! `ferrogate-storage`, justified as "policy already depends on storage, so a
//! back-dependency would cycle". That is true of `ferrogate-policy` — it depends
//! on both — but it was never true of THIS crate: `ferrogate-payments` declares
//! no FerroGate dependency at all (only `base64`, `serde`, `serde_json`,
//! `sha2`), so `ferrogate-storage -> ferrogate-payments` is acyclic. The states
//! therefore live here, and `ferrogate-storage` re-exports its existing `&str`
//! consts from them so no caller's API changed.
//!
//! # The one semantic that may not change
//!
//! [`PaymentAttemptState::OutcomeUnknown`] is NON-TERMINAL and RETAINS the
//! wallet hold. After proof submission, a timeout or RPC ambiguity is not proof
//! the money did not move — releasing the hold there could spend stablecoin
//! without ever charging the internal wallet. Everything in
//! [`PaymentAttemptState::is_pre_submission`] and
//! [`PaymentAttemptState::is_reconcilable`] exists to keep the TTL sweeper and
//! the settlement reconciler on disjoint sides of that line.

/// One state of the durable x402 payment attempt.
///
/// ```text
/// challenged --authorize--> authorized --submit--> submitted --settle--> settled (terminal)
///     |                          |                     |
///     |                          |                     +--> outcome_unknown (HOLD RETAINED)
///     |                          +--release--> released (terminal, pre-submission)
///     |                          +--fail-----> failed   (terminal)
///     +--deny-----> denied   (terminal, pre-authorization policy refusal)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PaymentAttemptState {
    /// The attempt exists but has not yet been authorized by policy.
    Challenged,
    /// Policy allowed the payment and credits are held.
    Authorized,
    /// The signed proof was submitted; from here a timeout is `OutcomeUnknown`.
    Submitted,
    /// Durable on-chain evidence captured the hold. Terminal.
    Settled,
    /// Policy refused the payment before authorization. Terminal.
    Denied,
    /// A pre-submission cancel/expiry released the hold. Terminal.
    Released,
    /// Durable evidence proved the payment did not settle. Terminal.
    Failed,
    /// Post-submission ambiguity. NON-TERMINAL, and the hold is RETAINED.
    OutcomeUnknown,
}

impl PaymentAttemptState {
    /// Every state, in the order the durable `state` CHECK constraint lists
    /// them. Exhaustive by construction: adding a variant without adding it here
    /// fails [`parse`](Self::parse)'s round-trip test.
    pub const ALL: &'static [Self] = &[
        Self::Challenged,
        Self::Authorized,
        Self::Submitted,
        Self::Settled,
        Self::Denied,
        Self::Released,
        Self::Failed,
        Self::OutcomeUnknown,
    ];

    /// The durable spelling. `const` so the storage crate can define its public
    /// `&str` consts directly from these variants rather than re-typing them.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Challenged => "challenged",
            Self::Authorized => "authorized",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Denied => "denied",
            Self::Released => "released",
            Self::Failed => "failed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    /// Parses a durable spelling. `None` for anything outside the alphabet — an
    /// unknown state is never coerced to a default, because guessing here would
    /// mean guessing whether a hold is live.
    ///
    /// Deliberately NOT `std::str::FromStr`: that trait's `Err` would have to be
    /// a type, and every caller here wants the plain "is this one of the eight"
    /// answer without an error type to discard.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|state| state.as_str() == value)
    }

    /// True for the four states no transition may leave.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Denied | Self::Released | Self::Failed
        )
    }

    /// True for the states a TTL sweep may expire by RELEASING the hold: the
    /// payment proof has not gone on-chain, so no stablecoin can have moved.
    /// `Submitted` is deliberately excluded, and so is `OutcomeUnknown`.
    pub const fn is_pre_submission(self) -> bool {
        matches!(self, Self::Authorized | Self::Challenged)
    }

    /// True for the non-terminal post-submission states the on-chain settlement
    /// reconciler drives to a definite terminal. Deliberately DISJOINT from
    /// [`is_pre_submission`](Self::is_pre_submission), so the TTL sweeper and the
    /// reconciler can never both act on one attempt.
    pub const fn is_reconcilable(self) -> bool {
        matches!(self, Self::Submitted | Self::OutcomeUnknown)
    }

    /// True for the states an attempt may be CREATED in — the entry points of
    /// the machine.
    pub const fn is_initial(self) -> bool {
        matches!(self, Self::Challenged | Self::Authorized | Self::Denied)
    }

    /// True iff this state RETAINS its wallet hold while non-terminal. Exactly
    /// `OutcomeUnknown`: post-submission ambiguity is not proof the money did
    /// not move.
    pub const fn retains_hold_when_unresolved(self) -> bool {
        matches!(self, Self::OutcomeUnknown)
    }
}

#[cfg(test)]
#[path = "attempt_state_test.rs"]
mod attempt_state_test;
