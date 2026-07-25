// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Runtime orchestration for the x402 managed paid-egress
// settle/release loop (issue #354). Composes the #281 wallet hold/reservation
// primitives with the #352 payment-attempt state machine so a governed paid
// egress attempt survives streaming, cancellation, duplicate retries, and
// ambiguous on-chain settlement without ever spending stablecoin for free.
//
// This file is ONLY the runtime coordinator. The durable CAS primitives live in
// `ferrogate-storage` (`payment_attempt.rs`, `wallet.rs`); the pure spend policy
// lives in `ferrogate-policy` (`x402_spend.rs`). Per AGENTS.md the database layer
// stays minimal CRUD/CAS and every coordination mutation is one short
// conditional statement; ALL orchestration, retry, backoff, and the
// CommitInFlight/OutcomeUnknown truth table are owned here in Rust async.
//
// -------------------------------------------------------------------------
// Edge truth table (each real state change is TWO short idempotent primitives)
// -------------------------------------------------------------------------
//
//   OPEN     : reserve wallet hold (#281)  ->  create attempt `authorized` (#352)
//   SUBMIT   : attempt `authorized -> submitted` (proof went on-chain)
//   SETTLE   : capture hold (#281)          ->  attempt `-> settled`   (Settled evidence)
//   FAIL     : release hold (#281)          ->  attempt `-> failed`    (definite Failed evidence)
//   RELEASE  : release hold (#281)          ->  attempt `-> released`  (pre-submission cancel/TTL)
//   UNKNOWN  : (no wallet mutation)         ->  attempt `-> outcome_unknown`, HOLD RETAINED
//
// Order matters. On the SETTLE edge the hold is captured BEFORE the attempt is
// marked settled, so a crash/timeout between the two primitives can never leave
// an attempt claiming `settled` without a matching wallet capture (the money is
// always captured first). On the FAIL/RELEASE edges the hold is released BEFORE
// the attempt is marked terminal, so a gap never strands funds in a hold behind
// an already-terminal attempt.
//
// Async-timeout safety (the money-safety invariant). If any primitive's COMMIT
// outcome becomes unknown across the async statement boundary
// (`OperationCommitOutcomeUnknown`, or a deadline whose commit had already
// started), the loop NEVER treats it as a definitive failure:
//   * SETTLE edge, capture uncertain  -> mark the attempt `outcome_unknown` and
//     RETAIN the hold. A stale reread that still shows `submitted` is not proof
//     the money did not move; releasing here could spend stablecoin without
//     charging the wallet.
//   * any edge, second primitive uncertain -> report `OutcomeUnknown` and let
//     bounded re-entry converge; both primitives are idempotent on their shared
//     operation token (the reservation/attempt id + the attempt `generation`),
//     so re-driving the same edge finishes the transition instead of doubling
//     it.
// Only a definitive pre-commit abort (`OperationCancelled`, or a deadline whose
// commit had not started) is safe to re-drive from scratch; it is handled the
// same conservative way (retain hold, reconcile) because it can never be told
// apart from an unknown after the fact without rereading, and a reread is never
// proof of failure.
//
// This module is the runtime loop's foundation: it is fully exercised by the
// sibling `*_test.rs` now, and its production entry point
// (`AppState::x402_settlement_loop`) is wired into the external-action paid-egress
// handler by the follow-up 402-negotiation/replay slice of #354 (the first
// unpaid dispatch + paid replay inside the same execution context, which is
// deferred here). Until that consumer lands, the non-test build has no caller,
// so allow dead_code off the test path -- mirroring `approval.rs` (#306) and
// `state_asset_lifecycle.rs`.
#![cfg_attr(not(test), allow(dead_code))]

use std::future::Future;
use std::sync::Arc;

use ferrogate_storage::{
    PaymentAttemptCreation, PaymentAttemptEvidenceArgs, PaymentAttemptTransition,
    RuntimeStorageRepositories, StorageError, StoredPaymentAttempt, WalletReservationResult,
    PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_CHALLENGED,
};

use super::AppState;
use crate::config::{x402_hold_ttl_floor_secs, X402ReconcilerConfig};

/// A durable success/failure classification produced by the injected settlement
/// verifier/reconciler BEFORE any database mutation (no external work runs
/// inside a transaction, per AGENTS.md). The trust order between on-chain RPC
/// evidence and a merchant header is the verifier's job; by the time evidence
/// reaches this loop it is already reduced to one of these three cases.
#[derive(Debug, Clone)]
pub(crate) enum SettlementEvidence<'a> {
    /// Durable proof the on-chain payment settled. Drives the SETTLE edge.
    Settled {
        transaction_signature: &'a str,
        settled_atomic_amount: &'a str,
        response: Option<&'a str>,
    },
    /// Durable proof the payment did not and cannot settle (e.g. on-chain proof
    /// the transaction was never accepted). Drives the FAIL edge.
    Failed {
        failure_code: &'a str,
        response: Option<&'a str>,
    },
    /// Ambiguous: post-submit timeout, cancellation, malformed/missing
    /// settlement evidence, or a contradictory merchant response. Retains the
    /// hold and parks the attempt in `outcome_unknown` for bounded
    /// reconciliation. NEVER releases and NEVER claims success.
    ///
    /// `transaction_signature`, when present, is persisted to the attempt row at
    /// the park CAS (#399): the earliest edge a signature is known that is NOT a
    /// settle. A merchant header carrying a signature, or a signature the
    /// reconciler already recovered on a prior tick, is captured into the durable
    /// column so subsequent reconcile passes can query the chain from storage
    /// alone. `None` leaves the column untouched (`COALESCE`).
    Unknown {
        response: Option<&'a str>,
        transaction_signature: Option<&'a str>,
    },
}

/// Immutable inputs for opening a paid-egress attempt: the frozen #350 wire
/// contract tuple plus the #351 policy decision output that already resolved to
/// `Allow`. The loop turns these into a wallet hold (#281) and a durable payment
/// attempt (#352). `attempt_id` is the idempotency key and is reused as the
/// reservation id so the attempt, its hold, and the ledger charge all reference
/// each other.
#[derive(Debug, Clone)]
pub(crate) struct PaidEgressOpen {
    pub attempt_id: String,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub workspace_id: Option<String>,
    pub run_id: Option<String>,
    pub worker_id: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub method: String,
    pub resource_url: String,
    pub request_body_hash: Option<String>,
    pub challenge_hash: String,
    pub x402_version: i64,
    pub scheme: String,
    pub network_caip2: String,
    pub mint: String,
    pub atomic_amount: String,
    pub recipient: String,
    /// Internal wallet credits to hold for this payment (the #281 hold size).
    pub credits_amount: i64,
    pub conversion_version: Option<String>,
    pub policy_revision: i64,
    pub decision: String,
    pub reason_code: String,
    /// REQUESTED seconds the hold stays live before it is TTL-eligible for
    /// release. This is a per-request runtime parameter and is NEVER the
    /// effective TTL on its own: [`X402SettlementLoop::open`] clamps it UP to
    /// the config-validated money-safety floor (issues #400/#401), so a
    /// short-lived request can never produce a hold that auto-releases before
    /// the reconciler could capture a payment confirmed on-chain. A request may
    /// always ask for a LONGER hold.
    pub hold_ttl_secs: i64,
}

/// Result of [`X402SettlementLoop::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpenOutcome {
    /// The hold was placed and the attempt exists in `authorized`. Boxed: the
    /// attempt record dwarfs the other variants (`clippy::large_enum_variant`).
    Opened(Box<StoredPaymentAttempt>),
    /// The wallet exists but its available balance cannot cover the hold. No
    /// hold is placed and no attempt is created: the signer/paid replay is never
    /// reached (acceptance: "insufficient funds never invokes signer").
    Insufficient {
        available_credits: i64,
        requested_credits: i64,
    },
    /// No wallet governs this tenant. Paid egress needs a funding source, so the
    /// caller must not proceed; nothing is reserved.
    NoWallet,
}

/// Result of driving one settle/fail/release edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EdgeOutcome {
    /// The attempt reached `settled`; the hold was captured exactly once.
    Settled { generation: i64 },
    /// The attempt reached `failed`; the hold was released.
    Failed { generation: i64 },
    /// The attempt reached `released`; the hold was released.
    Released { generation: i64 },
    /// The edge could not be proven complete across an async boundary. The hold
    /// is RETAINED (never released, never falsely captured-then-abandoned) and
    /// the attempt is left where bounded re-entry / reconciliation can finish
    /// it. This is never a false failure.
    OutcomeUnknown {
        generation: i64,
        /// True when the attempt was durably parked in `outcome_unknown`; false
        /// when it was left in its prior state for re-entry.
        parked: bool,
    },
}

/// Test-only seam: models an async statement boundary where a primitive's
/// commit outcome becomes unknown. Production installs the identity observer
/// ([`X402SettlementLoop::new`]) so no branch is taken. Keyed by the storage
/// operation label so a test can target exactly one primitive of an edge
/// without timing sleeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitFault {
    /// The boundary was crossed before the DML ran: the mutation never
    /// happened, yet the caller cannot know that and must not assume failure.
    UnknownPreCommit,
    /// The boundary was crossed after the DML ran: the mutation committed but
    /// the caller lost certainty. Re-entry must converge idempotently.
    UnknownPostCommit,
}

type CommitObserver = Arc<dyn Fn(&'static str) -> Option<CommitFault> + Send + Sync>;

/// The runtime coordinator that composes the wallet-hold and payment-attempt
/// primitives into the managed paid-egress loop. Cheap to construct per request;
/// holds only an `Arc` to the shared repositories, the money-safety hold-TTL
/// floor, and the (production no-op) commit observer.
#[derive(Clone)]
pub(crate) struct X402SettlementLoop {
    repositories: Arc<RuntimeStorageRepositories>,
    /// Money-safety floor (seconds) every wallet hold TTL is clamped UP to at
    /// [`X402SettlementLoop::open`] (issue #401).
    ///
    /// PRIVATE and derivable only by [`Self::hold_ttl_floor_secs`] from an
    /// `X402ReconcilerConfig`, never accepted as a raw number: every constructor
    /// takes the reconciler CONFIG, so no caller (present or future) can hand
    /// the loop a floor of its own choosing or forget one entirely.
    hold_ttl_floor_secs: i64,
    observer: CommitObserver,
}

impl X402SettlementLoop {
    pub(crate) fn new(
        repositories: Arc<RuntimeStorageRepositories>,
        reconciler: &X402ReconcilerConfig,
    ) -> Self {
        Self {
            repositories,
            hold_ttl_floor_secs: Self::hold_ttl_floor_secs(reconciler),
            observer: Arc::new(|_| None),
        }
    }

    /// Test constructor that installs a commit-outcome fault observer so the
    /// async-timeout truth table can be exercised with a deterministic,
    /// sleep-free injection point.
    #[cfg(test)]
    pub(crate) fn with_observer(
        repositories: Arc<RuntimeStorageRepositories>,
        reconciler: &X402ReconcilerConfig,
        observer: CommitObserver,
    ) -> Self {
        Self {
            repositories,
            hold_ttl_floor_secs: Self::hold_ttl_floor_secs(reconciler),
            observer,
        }
    }

    /// Resolves the #401 clamp floor from the reconciler config, via the SAME
    /// [`x402_hold_ttl_floor_secs`] the #400 config-load validation uses -- one
    /// definition, two callers, so the load-time check and the runtime clamp can
    /// never drift.
    ///
    /// Gated on `enabled` for exactly the reason the #400 validation is: only
    /// the reconciler captures a `submitted` attempt on this path, so only an
    /// enabled reconciler opens the money-loss window the floor protects -- and
    /// while disabled its timing fields are never validated, so a floor derived
    /// from them would enforce an unvalidated number. Disabled therefore yields
    /// a `0` floor, which `max(requested, 0)` leaves untouched (hold TTLs are
    /// always positive).
    fn hold_ttl_floor_secs(reconciler: &X402ReconcilerConfig) -> i64 {
        if !reconciler.enabled {
            return 0;
        }
        x402_hold_ttl_floor_secs(reconciler)
    }

    /// The money-safety clamp (issue #401). `x402_reconciler.hold_ttl_secs` is
    /// validated at config load to strictly outlive the settlement confirmation
    /// window, but the wallet hold's real TTL arrives here as a PER-REQUEST
    /// parameter -- so without this clamp the validated invariant could be
    /// bypassed at runtime by a short request TTL, and a payment confirmed
    /// on-chain could find its hold already auto-released (stablecoin delivered,
    /// wallet never charged).
    ///
    /// `effective = max(requested, floor)`: a request may always ask for a
    /// LONGER hold, never a shorter one than the validated floor.
    ///
    /// CLAMP, not reject: the floor is a safety minimum, and holding a tenant's
    /// own credits slightly longer is strictly recoverable (the #354 sweeper and
    /// the reconciler both release/settle it), whereas rejecting the egress
    /// request would turn an operator's TTL misconfiguration into user-visible
    /// request failures. This also matches the loop's standing conservative
    /// posture -- when in doubt, RETAIN the hold, never take the money-losing
    /// branch. The clamp is logged at `warn!` so the misconfiguration is
    /// diagnosable rather than silent.
    fn effective_hold_ttl_secs(&self, requested_secs: i64, attempt_id: &str) -> i64 {
        if requested_secs >= self.hold_ttl_floor_secs {
            return requested_secs;
        }
        tracing::warn!(
            attempt_id = %attempt_id,
            requested_hold_ttl_secs = requested_secs,
            effective_hold_ttl_secs = self.hold_ttl_floor_secs,
            "x402 open: per-request wallet hold TTL is below the validated \
             x402_reconciler money-safety floor (confirmation_deadline_secs + \
             reconcile_check_delay_secs + one tick); clamping up so a payment \
             confirmed on-chain cannot find its hold already auto-released"
        );
        self.hold_ttl_floor_secs
    }

    /// Runs one storage primitive through the commit-outcome fault seam. In
    /// production `observer` always returns `None` and this is a plain await.
    async fn primitive<T, F>(&self, label: &'static str, future: F) -> Result<T, StorageError>
    where
        F: Future<Output = Result<T, StorageError>>,
    {
        match (self.observer)(label) {
            Some(CommitFault::UnknownPreCommit) => {
                Err(StorageError::OperationCommitOutcomeUnknown {
                    operation: label,
                    stage: "injected pre-commit async boundary",
                })
            }
            Some(CommitFault::UnknownPostCommit) => {
                let result = future.await;
                match result {
                    Ok(_) => Err(StorageError::OperationCommitOutcomeUnknown {
                        operation: label,
                        stage: "injected post-commit async boundary",
                    }),
                    Err(error) => Err(error),
                }
            }
            None => future.await,
        }
    }

    // -- OPEN ------------------------------------------------------------

    /// Sequences `reserve (wallet hold) -> create (payment attempt)`. Idempotent
    /// on `attempt_id`: a replay returns the existing attempt without a second
    /// hold or a second row.
    ///
    /// This is the ONE place a hold TTL becomes a wallet-hold `expires_at` for
    /// paid egress, so the #401 money-safety clamp lives here rather than at any
    /// call site: `open.hold_ttl_secs` is a REQUEST, never the effective TTL.
    pub(crate) async fn open(
        &self,
        open: &PaidEgressOpen,
        now_unix: i64,
    ) -> Result<OpenOutcome, StorageError> {
        let hold_ttl_secs = self.effective_hold_ttl_secs(open.hold_ttl_secs, &open.attempt_id);
        let expires_at = now_unix.saturating_add(hold_ttl_secs);
        let reservation = self
            .repositories
            .reserve_wallet_credits(
                &open.attempt_id,
                &open.tenant_id,
                open.credits_amount,
                expires_at,
                now_unix,
            )
            .await?;
        match reservation {
            WalletReservationResult::Reserved(_) => {}
            WalletReservationResult::Insufficient {
                available_credits,
                requested_credits,
            } => {
                return Ok(OpenOutcome::Insufficient {
                    available_credits,
                    requested_credits,
                });
            }
            WalletReservationResult::NoWallet => return Ok(OpenOutcome::NoWallet),
        }

        let attempt = StoredPaymentAttempt {
            id: open.attempt_id.clone(),
            tenant_id: open.tenant_id.clone(),
            project_id: open.project_id.clone(),
            workspace_id: open.workspace_id.clone(),
            run_id: open.run_id.clone(),
            worker_id: open.worker_id.clone(),
            request_id: open.request_id.clone(),
            trace_id: open.trace_id.clone(),
            method: open.method.clone(),
            resource_url: open.resource_url.clone(),
            request_body_hash: open.request_body_hash.clone(),
            challenge_hash: open.challenge_hash.clone(),
            x402_version: open.x402_version,
            scheme: open.scheme.clone(),
            network_caip2: open.network_caip2.clone(),
            mint: open.mint.clone(),
            atomic_amount: open.atomic_amount.clone(),
            recipient: open.recipient.clone(),
            credits_amount: Some(open.credits_amount),
            conversion_version: open.conversion_version.clone(),
            policy_revision: open.policy_revision,
            decision: open.decision.clone(),
            reason_code: open.reason_code.clone(),
            hold_id: Some(open.attempt_id.clone()),
            state: PAYMENT_ATTEMPT_AUTHORIZED.to_string(),
            generation: 0,
            submitted_at_unix: None,
            transaction_signature: None,
            settled_atomic_amount: None,
            settlement_response: None,
            failure_code: None,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
        };
        let created = self.repositories.create_payment_attempt(attempt).await?;
        let attempt = match created {
            PaymentAttemptCreation::Created(attempt) => attempt,
            PaymentAttemptCreation::Existing(attempt) => attempt,
        };
        Ok(OpenOutcome::Opened(Box::new(attempt)))
    }

    // -- SUBMIT ----------------------------------------------------------

    /// `authorized -> submitted`: the signed proof went on-chain. After this a
    /// timeout is `outcome_unknown`, never a release. `transaction_signature` is
    /// persisted into the attempt row coupled to this same CAS when it is already
    /// known at submit time (#399), so a `submitted`/`outcome_unknown` attempt the
    /// reconciler (#354) later picks up already carries a recoverable signature
    /// instead of depending on a merchant settlement header that may never arrive.
    /// `None` leaves the column untouched (`COALESCE`), for the common flow where
    /// the on-chain signature is only reported later by the facilitator.
    pub(crate) async fn submit(
        &self,
        attempt_id: &str,
        transaction_signature: Option<&str>,
        submitted_at_unix: i64,
        now_unix: i64,
    ) -> Result<StoredPaymentAttempt, StorageError> {
        let evidence = PaymentAttemptEvidenceArgs {
            submitted_at_unix: Some(submitted_at_unix),
            transaction_signature,
            ..Default::default()
        };
        let transition = self
            .repositories
            .submit_payment_attempt(attempt_id, evidence, now_unix)
            .await?;
        Ok(transition_attempt(transition))
    }

    // -- FINALIZE (settle / fail / outcome_unknown) ----------------------

    /// Ingests settlement evidence for a submitted (or already `outcome_unknown`)
    /// attempt and drives the matching edge. This is the heart of the loop.
    pub(crate) async fn finalize(
        &self,
        attempt_id: &str,
        evidence: &SettlementEvidence<'_>,
        now_unix: i64,
    ) -> Result<EdgeOutcome, StorageError> {
        let attempt = self
            .repositories
            .get_payment_attempt(attempt_id)
            .await?
            .ok_or_else(|| {
                StorageError::NotFound(format!("payment attempt {attempt_id} does not exist"))
            })?;
        let Some(hold_id) = attempt.hold_id.clone() else {
            return Err(StorageError::Conflict(format!(
                "payment attempt {attempt_id} has no wallet hold to finalize"
            )));
        };

        match evidence {
            SettlementEvidence::Settled {
                transaction_signature,
                settled_atomic_amount,
                response,
            } => {
                self.settle_edge(
                    attempt_id,
                    &hold_id,
                    transaction_signature,
                    settled_atomic_amount,
                    *response,
                    now_unix,
                )
                .await
            }
            SettlementEvidence::Failed {
                failure_code,
                response,
            } => {
                self.fail_edge(attempt_id, &hold_id, failure_code, *response, now_unix)
                    .await
            }
            SettlementEvidence::Unknown {
                response,
                transaction_signature,
            } => {
                self.mark_unknown(attempt_id, *response, *transaction_signature, now_unix)
                    .await
            }
        }
    }

    /// SETTLE edge: capture hold, THEN mark attempt settled. Capturing first
    /// guarantees an attempt is never `settled` without the money captured.
    async fn settle_edge(
        &self,
        attempt_id: &str,
        hold_id: &str,
        transaction_signature: &str,
        settled_atomic_amount: &str,
        response: Option<&str>,
        now_unix: i64,
    ) -> Result<EdgeOutcome, StorageError> {
        // Primitive 1: capture the wallet hold.
        match self
            .primitive(
                "settle_wallet_reservation",
                self.repositories
                    .settle_wallet_reservation(hold_id, now_unix),
            )
            .await
        {
            Ok(_) => {}
            Err(error) if is_unresolved(&error) => {
                // The capture's commit outcome is unknown (or a definitive
                // pre-commit abort that is indistinguishable without a reread).
                // Retain the hold and park the attempt in `outcome_unknown`;
                // this is the money-safety invariant -- releasing here could
                // spend stablecoin without charging the wallet.
                tracing::warn!(
                    attempt_id,
                    hold_id,
                    error = %error,
                    "x402 settle capture unresolved; retaining hold, parking outcome_unknown"
                );
                // The on-chain signature was known here (the settle carried it);
                // persist it at the park CAS so the reconciler can query the chain
                // from storage even though the capture is deferred (#399).
                return self
                    .mark_unknown(attempt_id, response, Some(transaction_signature), now_unix)
                    .await;
            }
            Err(error) => return Err(error),
        }

        // Primitive 2: mark the attempt settled, recording the on-chain evidence.
        let evidence = PaymentAttemptEvidenceArgs {
            transaction_signature: Some(transaction_signature),
            settled_atomic_amount: Some(settled_atomic_amount),
            settlement_response: response,
            ..Default::default()
        };
        match self
            .primitive(
                "settle_payment_attempt",
                self.repositories
                    .settle_payment_attempt(attempt_id, evidence, now_unix),
            )
            .await
        {
            Ok(transition) => Ok(EdgeOutcome::Settled {
                generation: transition_attempt(transition).generation,
            }),
            Err(error) if is_unresolved(&error) => {
                // The hold is already captured; only the attempt transition is
                // unresolved. Re-entry re-drives both idempotently and finishes
                // on `submitted -> settled`. The hold stays captured (retained).
                tracing::warn!(
                    attempt_id,
                    hold_id,
                    error = %error,
                    "x402 settle attempt-transition unresolved; hold captured, awaiting re-entry"
                );
                let generation = self.current_generation(attempt_id).await?;
                Ok(EdgeOutcome::OutcomeUnknown {
                    generation,
                    parked: false,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// FAIL edge (definite failure evidence): release hold, THEN mark failed.
    async fn fail_edge(
        &self,
        attempt_id: &str,
        hold_id: &str,
        failure_code: &str,
        response: Option<&str>,
        now_unix: i64,
    ) -> Result<EdgeOutcome, StorageError> {
        // Primitive 1: release the hold. Safe only because the evidence is a
        // DEFINITE failure -- releasing under ambiguity is forbidden and routed
        // to `mark_unknown` instead.
        match self
            .primitive(
                "release_wallet_reservation",
                self.repositories
                    .release_wallet_reservation(hold_id, now_unix),
            )
            .await
        {
            Ok(_) => {}
            Err(error) if is_unresolved(&error) => {
                // Do not mark the attempt terminal while the release is
                // unresolved; leave it for idempotent re-entry.
                let generation = self.current_generation(attempt_id).await?;
                return Ok(EdgeOutcome::OutcomeUnknown {
                    generation,
                    parked: false,
                });
            }
            Err(error) => return Err(error),
        }

        // Primitive 2: mark the attempt failed.
        let evidence = PaymentAttemptEvidenceArgs {
            failure_code: Some(failure_code),
            settlement_response: response,
            ..Default::default()
        };
        match self
            .primitive(
                "fail_payment_attempt",
                self.repositories
                    .fail_payment_attempt(attempt_id, evidence, now_unix),
            )
            .await
        {
            Ok(transition) => Ok(EdgeOutcome::Failed {
                generation: transition_attempt(transition).generation,
            }),
            Err(error) if is_unresolved(&error) => {
                let generation = self.current_generation(attempt_id).await?;
                Ok(EdgeOutcome::OutcomeUnknown {
                    generation,
                    parked: false,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// UNKNOWN edge: `submitted -> outcome_unknown`, HOLD RETAINED. Idempotent
    /// when the attempt is already `outcome_unknown`. `transaction_signature`, when
    /// present, is persisted coupled to this park CAS (#399) so a parked attempt
    /// durably carries the signature the reconciler needs; `None` leaves the
    /// column untouched (`COALESCE`, write-once).
    async fn mark_unknown(
        &self,
        attempt_id: &str,
        response: Option<&str>,
        transaction_signature: Option<&str>,
        now_unix: i64,
    ) -> Result<EdgeOutcome, StorageError> {
        let evidence = PaymentAttemptEvidenceArgs {
            settlement_response: response,
            transaction_signature,
            ..Default::default()
        };
        let transition = self
            .repositories
            .mark_payment_attempt_outcome_unknown(attempt_id, evidence, now_unix)
            .await?;
        Ok(EdgeOutcome::OutcomeUnknown {
            generation: transition_attempt(transition).generation,
            parked: true,
        })
    }

    // -- RELEASE (pre-submission cancel / TTL expiry) --------------------

    /// RELEASE edge: release hold, THEN mark attempt released. Valid only on a
    /// pre-submission attempt (`challenged | authorized`). Idempotent on replay.
    pub(crate) async fn cancel(
        &self,
        attempt_id: &str,
        failure_code: &str,
        now_unix: i64,
    ) -> Result<EdgeOutcome, StorageError> {
        let attempt = self
            .repositories
            .get_payment_attempt(attempt_id)
            .await?
            .ok_or_else(|| {
                StorageError::NotFound(format!("payment attempt {attempt_id} does not exist"))
            })?;
        let Some(hold_id) = attempt.hold_id.clone() else {
            return Err(StorageError::Conflict(format!(
                "payment attempt {attempt_id} has no wallet hold to release"
            )));
        };

        // Primitive 1: release the hold.
        match self
            .primitive(
                "release_wallet_reservation",
                self.repositories
                    .release_wallet_reservation(&hold_id, now_unix),
            )
            .await
        {
            Ok(_) => {}
            Err(error) if is_unresolved(&error) => {
                let generation = self.current_generation(attempt_id).await?;
                return Ok(EdgeOutcome::OutcomeUnknown {
                    generation,
                    parked: false,
                });
            }
            Err(error) => return Err(error),
        }

        // Primitive 2: mark the attempt released.
        let evidence = PaymentAttemptEvidenceArgs {
            failure_code: Some(failure_code),
            ..Default::default()
        };
        match self
            .primitive(
                "release_payment_attempt",
                self.repositories
                    .release_payment_attempt(attempt_id, evidence, now_unix),
            )
            .await
        {
            Ok(transition) => Ok(EdgeOutcome::Released {
                generation: transition_attempt(transition).generation,
            }),
            Err(error) if is_unresolved(&error) => {
                let generation = self.current_generation(attempt_id).await?;
                Ok(EdgeOutcome::OutcomeUnknown {
                    generation,
                    parked: false,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Drives TTL/expiry for one attempt: if its hold is past its TTL and the
    /// attempt is still pre-submission, release it. A post-submission attempt is
    /// never released by TTL -- its money may already have moved on-chain.
    pub(crate) async fn expire_if_due(
        &self,
        attempt_id: &str,
        now_unix: i64,
    ) -> Result<Option<EdgeOutcome>, StorageError> {
        let Some(links) = self
            .repositories
            .get_payment_attempt_links(attempt_id, &self.tenant_of(attempt_id).await?)
            .await?
        else {
            return Ok(None);
        };
        let pre_submission = matches!(
            links.attempt.state.as_str(),
            PAYMENT_ATTEMPT_AUTHORIZED | PAYMENT_ATTEMPT_CHALLENGED
        );
        let expired = links
            .reservation
            .as_ref()
            .map(|reservation| now_unix >= reservation.expires_at_unix)
            .unwrap_or(false);
        if pre_submission && expired {
            let outcome = self
                .cancel(attempt_id, "x402_hold_ttl_expired", now_unix)
                .await?;
            return Ok(Some(outcome));
        }
        Ok(None)
    }

    async fn tenant_of(&self, attempt_id: &str) -> Result<String, StorageError> {
        self.repositories
            .get_payment_attempt(attempt_id)
            .await?
            .map(|attempt| attempt.tenant_id)
            .ok_or_else(|| {
                StorageError::NotFound(format!("payment attempt {attempt_id} does not exist"))
            })
    }

    /// Rereads the attempt's current `generation` (the operation token surfaced
    /// on an unresolved edge). A reread is never proof of failure -- it only
    /// carries the token forward so a caller/reconciler can detect staleness.
    async fn current_generation(&self, attempt_id: &str) -> Result<i64, StorageError> {
        Ok(self
            .repositories
            .get_payment_attempt(attempt_id)
            .await?
            .map(|attempt| attempt.generation)
            .unwrap_or_default())
    }
}

/// True when a storage error means the mutation's outcome is not definitively
/// known to have failed: either an explicit unknown commit outcome, or a
/// deadline whose commit had already started. Per AGENTS.md a stale reread while
/// such a mutation is unresolved never proves failure, so these are handled
/// conservatively (retain hold, reconcile) rather than as a failure. A
/// definitive pre-commit abort (`OperationCancelled`, deadline before commit)
/// is folded in here too: it is only ever encountered after the fact, where it
/// is indistinguishable from an unknown without a reread, and the safe action is
/// identical.
fn is_unresolved(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::OperationCommitOutcomeUnknown { .. }
            | StorageError::OperationDeadlineExceeded { .. }
            | StorageError::OperationCancelled { .. }
    )
}

fn transition_attempt(transition: PaymentAttemptTransition) -> StoredPaymentAttempt {
    match transition {
        PaymentAttemptTransition::Applied(attempt) => attempt,
        PaymentAttemptTransition::Idempotent(attempt) => attempt,
    }
}

impl AppState {
    /// Production accessor: the paid-egress settle/release loop bound to this
    /// node's shared repositories AND to this node's current money-safety
    /// hold-TTL floor. Cheap; construct one per request -- and because the floor
    /// is re-read from `self.config` here, a `/admin/v1/config/reload` that
    /// retunes the reconciler applies to the very next opened hold with no
    /// restart, exactly like the sweeper/reconciler tick loops.
    pub(crate) fn x402_settlement_loop(&self) -> X402SettlementLoop {
        X402SettlementLoop::new(Arc::clone(&self.repositories), &self.config.x402_reconciler)
    }

    /// Test accessor for the shared repositories handle, so a test can build a
    /// loop with an injected commit-outcome observer.
    #[cfg(test)]
    pub(crate) fn repositories_arc(&self) -> Arc<RuntimeStorageRepositories> {
        Arc::clone(&self.repositories)
    }
}

#[cfg(test)]
#[path = "state_x402_settlement_test.rs"]
mod state_x402_settlement_test;
