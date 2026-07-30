// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Exactly-once forwarding claim for the inbound x402 monetized route
// (issue #356). One settled payment forwards to the protected handler once; a
// sidecar retry is idempotent and a replayed proof is refused.

//! Forward-once claim state machine for the inbound x402 route (issue #356).
//!
//! A settled x402 payment buys exactly one call to the protected handler. Two
//! very different things can arrive carrying the same settled payment, and
//! collapsing them would be a security bug:
//!
//! - the **same sidecar request retried** after a timeout — the payer's own
//!   call, which must be idempotent and must not be charged or served twice;
//! - a **different request presenting the same proof** — a replay, whether from
//!   a stolen `PAYMENT-RESPONSE` header or a sidecar that forwards twice.
//!
//! [`ForwardClaimGuard::claim`] separates them on one discriminator: whether the
//! arriving request id equals the id of the *first* claimant of that payment
//! key. Equal is [`ClaimOutcome::DuplicateRetry`] (idempotent, 409); different is
//! [`ClaimOutcome::ProofReplay`] (refused, re-challenged with a fresh 402). Erase
//! that comparison and a stolen call becomes a benign-looking retry — which is
//! exactly the mutation the property test in the sibling test module kills.
//!
//! ## Fail-closed, not best-effort
//!
//! The in-memory guard is bounded. When it is full and pruning frees nothing, a
//! claim returns `Err` and the forward is refused
//! ([`InMemoryForwardClaimGuard::claim`]) — it never evicts a live claim to make
//! room, because evicting a live claim is precisely how a replay gets admitted.
//!
//! ## The clock is a parameter
//!
//! `now_unix` is passed in, never read. That keeps the guard usable from the
//! Pingora hot path (no syscall, no global state) and makes TTL expiry directly
//! testable rather than something a test has to sleep through.
//!
//! ## Durability boundary (explicitly not closed here)
//!
//! [`InMemoryForwardClaimGuard`] is process-local: claims do not survive a
//! restart, and a multi-replica deployment has one guard per replica. Durable,
//! cross-replica claim state and the Admin query surface over it are tracked in
//! issue #601 and are **not** part of this slice; the gate compensates for a
//! *pruned or lost* claim by consulting the durable revenue record before it
//! forwards (see [`crate::x402_inbound_gate`]), which closes replay across a
//! restart only as far as the configured [`RevenueSink`](crate::x402_inbound::RevenueSink)
//! is itself durable.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::BillingError;

/// Default number of live claims an in-memory guard holds before it fails
/// closed. Sized so a busy fixed-price route keeps a full TTL window in memory.
pub const DEFAULT_CLAIM_CAPACITY: usize = 16_384;

/// What happened when a request tried to claim the right to forward a settled
/// payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// First claimant of this payment key. Forward to the protected handler.
    Admitted,
    /// The first claimant's own request id arriving again: the sidecar retried.
    /// Idempotent — do not invoke the handler a second time.
    DuplicateRetry {
        /// The request id that holds the claim (equal to the arriving one).
        first_request_id: String,
        /// When the original claim was taken.
        claimed_at_unix: u64,
    },
    /// A *different* request presenting a payment that is already claimed: a
    /// replayed proof. Refuse and re-challenge.
    ProofReplay {
        /// The request id that legitimately holds the claim.
        first_request_id: String,
        /// When the original claim was taken.
        claimed_at_unix: u64,
    },
}

impl ClaimOutcome {
    /// Whether this outcome authorizes invoking the protected handler. True for
    /// exactly one outcome — this is the forward-once rule in one place.
    pub fn forwards(&self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// Stable tag for logs and audit evidence.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::DuplicateRetry { .. } => "duplicate_retry",
            Self::ProofReplay { .. } => "proof_replay",
        }
    }
}

/// The claim ledger for forward-once. Implementations must be safe to call
/// concurrently: two racing requests carrying the same payment key must produce
/// exactly one [`ClaimOutcome::Admitted`].
pub trait ForwardClaimGuard: Send + Sync {
    /// Take, or observe, the claim on `payment_key` for `request_id`.
    ///
    /// `Err` means the guard could not decide (it is full, or its state is
    /// unusable) and the caller MUST refuse the forward rather than assume the
    /// claim is free.
    fn claim(
        &self,
        payment_key: &str,
        request_id: &str,
        now_unix: u64,
    ) -> Result<ClaimOutcome, BillingError>;

    /// Give the claim back so the payer can retry with a fresh request id, used
    /// when the protected handler was never actually served (connect failure or
    /// upstream 5xx before any response).
    ///
    /// Only the holder may release: `request_id` must equal the first
    /// claimant's, otherwise this is a no-op returning `false`. Without that
    /// ownership rule, releasing would be a free replay primitive — anyone who
    /// observed the proof could clear the claim and re-present it.
    fn release(&self, payment_key: &str, request_id: &str) -> Result<bool, BillingError>;

    /// Number of live claims currently held. Diagnostics only.
    fn live_claims(&self) -> Result<usize, BillingError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimRecord {
    first_request_id: String,
    claimed_at_unix: u64,
}

#[derive(Debug, Default)]
struct ClaimState {
    claims: HashMap<String, ClaimRecord>,
}

/// Process-local, bounded, TTL-expiring [`ForwardClaimGuard`].
#[derive(Debug, Clone)]
pub struct InMemoryForwardClaimGuard {
    inner: Arc<Mutex<ClaimState>>,
    ttl_secs: u64,
    capacity: usize,
}

/// Why an [`InMemoryForwardClaimGuard`] could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardClaimGuardError {
    /// A zero TTL would expire every claim immediately, making every replay an
    /// `Admitted` — the opposite of the guard's purpose.
    ZeroTtl,
    /// A zero capacity would fail closed on every request.
    ZeroCapacity,
}

impl fmt::Display for ForwardClaimGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTtl => write!(f, "forward-claim TTL must be non-zero"),
            Self::ZeroCapacity => write!(f, "forward-claim capacity must be non-zero"),
        }
    }
}

impl std::error::Error for ForwardClaimGuardError {}

fn claim_poisoned() -> BillingError {
    BillingError::new(
        "billing_x402_inbound_claim_poisoned",
        "inbound x402 forward-claim lock poisoned",
    )
}

impl InMemoryForwardClaimGuard {
    /// Build a guard holding claims for `ttl_secs` with room for `capacity`
    /// live claims.
    pub fn new(ttl_secs: u64, capacity: usize) -> Result<Self, ForwardClaimGuardError> {
        if ttl_secs == 0 {
            return Err(ForwardClaimGuardError::ZeroTtl);
        }
        if capacity == 0 {
            return Err(ForwardClaimGuardError::ZeroCapacity);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(ClaimState::default())),
            ttl_secs,
            capacity,
        })
    }

    /// Build a guard with [`DEFAULT_CLAIM_CAPACITY`].
    pub fn with_ttl(ttl_secs: u64) -> Result<Self, ForwardClaimGuardError> {
        Self::new(ttl_secs, DEFAULT_CLAIM_CAPACITY)
    }

    /// The configured claim lifetime in seconds.
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// The configured live-claim ceiling.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drop claims older than the TTL relative to `now_unix`.
    ///
    /// `saturating_sub` on the age means a `now_unix` that moves backwards (NTP
    /// step, or a caller passing a stale clock) yields age 0 and expires
    /// nothing. Expiring on a backwards clock would release live claims, so the
    /// safe direction is to keep them.
    fn prune(&self, state: &mut ClaimState, now_unix: u64) {
        let ttl = self.ttl_secs;
        state
            .claims
            .retain(|_, record| now_unix.saturating_sub(record.claimed_at_unix) < ttl);
    }
}

impl ForwardClaimGuard for InMemoryForwardClaimGuard {
    fn claim(
        &self,
        payment_key: &str,
        request_id: &str,
        now_unix: u64,
    ) -> Result<ClaimOutcome, BillingError> {
        let mut state = self.inner.lock().map_err(|_| claim_poisoned())?;
        self.prune(&mut state, now_unix);

        if let Some(record) = state.claims.get(payment_key) {
            let outcome = if record.first_request_id == request_id {
                ClaimOutcome::DuplicateRetry {
                    first_request_id: record.first_request_id.clone(),
                    claimed_at_unix: record.claimed_at_unix,
                }
            } else {
                ClaimOutcome::ProofReplay {
                    first_request_id: record.first_request_id.clone(),
                    claimed_at_unix: record.claimed_at_unix,
                }
            };
            return Ok(outcome);
        }

        // Fail closed rather than evict: evicting a live claim to admit a new
        // one is exactly how a replay would be let through under load.
        if state.claims.len() >= self.capacity {
            return Err(BillingError::new(
                "billing_x402_inbound_claim_capacity",
                format!(
                    "inbound x402 forward-claim guard is at capacity ({}); refusing the forward",
                    self.capacity
                ),
            ));
        }

        state.claims.insert(
            payment_key.to_string(),
            ClaimRecord {
                first_request_id: request_id.to_string(),
                claimed_at_unix: now_unix,
            },
        );
        Ok(ClaimOutcome::Admitted)
    }

    fn release(&self, payment_key: &str, request_id: &str) -> Result<bool, BillingError> {
        let mut state = self.inner.lock().map_err(|_| claim_poisoned())?;
        let owned = state
            .claims
            .get(payment_key)
            .is_some_and(|record| record.first_request_id == request_id);
        if owned {
            state.claims.remove(payment_key);
        }
        Ok(owned)
    }

    fn live_claims(&self) -> Result<usize, BillingError> {
        let state = self.inner.lock().map_err(|_| claim_poisoned())?;
        Ok(state.claims.len())
    }
}

#[cfg(test)]
#[path = "x402_inbound_forward_test.rs"]
mod x402_inbound_forward_test;
