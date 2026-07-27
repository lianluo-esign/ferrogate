// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Background on-chain settlement reconciler for x402 payment
// attempts (issue #354). The settle/release loop (`state_x402_settlement.rs`)
// exposes money-safe SETTLE / FAIL / UNKNOWN edges, and the TTL sweeper
// (`state_x402_sweeper.rs`) reclaims overdue PRE-submission holds -- but the
// sweeper deliberately never touches a `submitted` or `outcome_unknown` attempt,
// because after proof submission the stablecoin may already have moved on-chain,
// so releasing its hold could spend without charging the wallet. This module is
// the control-plane loop that resolves exactly those left-behind attempts.
//
// One bounded tick fetches a page of post-submission attempts due for a re-check
// (short indexed storage read, oldest-checked-first, LIMIT -- never a full-table
// scan), then for each attempt queries an INJECTED on-chain-RPC seam
// (`OnChainSettlementRpc`, mockable, no live network) for the transaction
// signature's status/amount and applies an EXPLICIT trust order:
//
//   * a confirmed on-chain transfer that COVERS the owed atomic amount (equal to
//     it, or -- per the x402 SVM `exact` scheme, where a matching transfer MAY
//     exceed the required amount and MUST NOT be less -- greater than it, #469)
//       -> SETTLE  (capture the hold, attempt -> settled);
//   * a transfer the chain definitively REJECTED, or one still ABSENT past the
//     confirmation deadline
//       -> FAIL    (release the hold, attempt -> failed);
//   * anything still PENDING / absent-before-deadline, or an UNDERPAYMENT
//       -> remain `outcome_unknown` (hold RETAINED), advancing the backoff
//          cursor. NEVER a guess, NEVER a false terminal.
//
// On-chain RPC evidence is AUTHORITATIVE over any merchant-reported settlement
// header: the transaction signature is taken from the (untrusted) merchant
// header, but the verdict comes from the chain. The reconciler reuses the loop's
// existing edges (it never reimplements a transition) and respects the CAS
// `generation` token, so it is money-safe to run on every gateway instance
// concurrently. It is off the Pingora hot path entirely.
//
// The generic `reconcile_x402_settlements_once` (the batch driver) is fully
// exercised by the sibling `*_test.rs` with an injected fake RPC and injected
// `now_unix`. Its production entry point (`reconcile_x402_settlements_tick`) is
// spawned unconditionally like the sweeper but no-ops until BOTH the reconciler
// is enabled AND a concrete on-chain RPC client is bound -- binding that client
// (the live SVM RPC transport) is the remaining #354 work, so today the
// production tick is a safe no-op. Mirrors the settlement loop's own precedent of
// landing a fully-tested mechanism ahead of its production transport.
//
// Until the live SVM RPC client is bound, the production tick only ever
// instantiates the driver with the inert `UnboundOnChainRpc`, so the on-chain
// status variants and trust-order branches are exercised solely by the sibling
// tests -- allow dead_code off the test path, exactly like
// `state_x402_settlement.rs` (#354) and `approval.rs` (#306).
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use ferrogate_payments::{parse_payment_response, SolanaNetwork};
use ferrogate_storage::StoredPaymentAttempt;

use super::state_x402_settlement::{
    classify_settled_amount, AmountCoverage, EdgeOutcome, SettlementEvidence,
};
use super::*;

// ---------------------------------------------------------------------------
// Injected on-chain RPC seam
// ---------------------------------------------------------------------------

/// The AUTHORITATIVE settlement status of one transaction signature, as reported
/// by an injected on-chain RPC. This outranks any merchant-reported
/// `PAYMENT-RESPONSE` header: the signature is merchant-sourced, the verdict is
/// the chain's. Deliberately coarse -- the reconciler only needs enough to apply
/// the trust order, not a full transaction decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnChainSettlementStatus {
    /// The transfer confirmed/finalized on-chain. `settled_atomic_amount` is the
    /// ACTUAL transferred atomic amount (canonical decimal string) the RPC
    /// observed; the reconciler compares it to the owed amount as an INTEGER and
    /// settles only when it COVERS what is owed (equal or greater, #469).
    Confirmed { settled_atomic_amount: String },
    /// The transaction landed on-chain but the chain REJECTED it (dropped,
    /// errored, insufficient funds, etc.). A definite failure regardless of the
    /// confirmation deadline.
    Failed { reason: String },
    /// The signature is not (yet) known to the chain. Absence ALONE is never
    /// proof of failure (it may still be propagating); only absence PAST the
    /// confirmation deadline is treated as a definite fail.
    NotFound,
    /// The signature is known but not yet confirmed/finalized. Always ambiguous;
    /// NEVER a failure -- its money may still confirm.
    Pending,
}

/// Immutable, borrowed inputs the reconciler hands the RPC seam to identify one
/// attempt's on-chain transfer: the signature to look up plus the
/// network/destination/mint that pin WHICH transfer instruction inside that
/// transaction is the settlement (a real SVM RPC parses the tx and extracts the
/// SPL transfer of `mint` to `recipient`). The OWED amount is deliberately NOT
/// passed -- the seam reports the ACTUAL observed amount and the reconciler
/// compares it, so the RPC can never be nudged into "confirming" a wrong amount.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OnChainQuery<'a> {
    /// Base58 transaction signature (merchant-sourced, chain-verified).
    pub transaction_signature: &'a str,
    /// CAIP-2 network the payment was proposed on.
    pub network_caip2: &'a str,
    /// Expected recipient (`payTo`, base58).
    pub recipient: &'a str,
    /// Expected SPL token mint (base58).
    pub mint: &'a str,
}

/// A failure querying the on-chain RPC (transport error, malformed response,
/// rate limit, ...). NEVER interpreted as a settlement verdict: an RPC error is
/// isolated per-attempt (the hold is retained, the attempt untouched) and the
/// attempt is retried on a later tick. Only an explicit
/// [`OnChainSettlementStatus`] ever drives an edge.
#[derive(Debug, Clone)]
pub(crate) struct OnChainRpcError {
    pub message: String,
}

impl fmt::Display for OnChainRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "on-chain settlement rpc error: {}", self.message)
    }
}

impl std::error::Error for OnChainRpcError {}

/// The injected on-chain settlement boundary. One implementation performs the
/// real (future) SVM JSON-RPC lookup; tests supply a deterministic fake. This is
/// the ONLY place the reconciler learns the on-chain truth, keeping the trust
/// order pure and unit-testable with no live network.
#[allow(async_fn_in_trait)]
pub(crate) trait OnChainSettlementRpc {
    /// Look up the settlement status of one transaction signature. An `Err` is an
    /// RPC/transport failure (never a settlement verdict); an `Ok` is the chain's
    /// authoritative status.
    async fn transfer_status(
        &self,
        query: &OnChainQuery<'_>,
    ) -> Result<OnChainSettlementStatus, OnChainRpcError>;
}

/// Production on-chain RPC placeholder: no live SVM RPC client is bound yet
/// (binding it is the remaining #354 transport work), so every lookup fails
/// EXPLICITLY. Because an `Err` is only ever isolated per-attempt (hold retained,
/// attempt untouched), this can NEVER drive a false SETTLE/FAIL -- an unbound
/// reconciler is inert, not dangerous. Swapped for the real client when the SVM
/// RPC transport lands.
struct UnboundOnChainRpc;

impl OnChainSettlementRpc for UnboundOnChainRpc {
    async fn transfer_status(
        &self,
        _query: &OnChainQuery<'_>,
    ) -> Result<OnChainSettlementStatus, OnChainRpcError> {
        Err(OnChainRpcError {
            message: "no on-chain settlement RPC client is bound (transport binding is \
                      remaining #354 work); reconciler is inert"
                .to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Trust order (pure decision)
// ---------------------------------------------------------------------------

/// The reconcile verdict for one attempt, derived purely from the on-chain
/// status + the owed amount + the confirmation deadline. Separated from all I/O
/// so the trust order is unit-testable in isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReconcileDecision {
    /// Confirmed on-chain transfer that COVERS the owed amount -> SETTLE.
    Settle {
        /// The amount actually observed on-chain, carried through verbatim so the
        /// durable evidence records what the chain saw (not what was owed).
        settled_atomic_amount: String,
        /// `Some(excess)` when the confirmed transfer EXCEEDED the owed amount
        /// (`settled - owed`, decimal); `None` on an exact transfer. Keeps an
        /// overpaid settlement distinguishable from an exact one instead of
        /// flattening the two (#469). The excess is the payer's -- it is never
        /// added to what the wallet hold captures.
        overpayment_atomic_amount: Option<String>,
    },
    /// Definitive failure (chain-rejected, or absent past the deadline) -> FAIL.
    Fail { failure_code: String },
    /// Still pending / absent-before-deadline -> remain `outcome_unknown`,
    /// advance backoff.
    Pending,
    /// Confirmed on-chain, but the transferred amount does NOT cover what is owed
    /// (an UNDERPAYMENT, or an amount that is not a parseable atomic value).
    /// Fail-closed: NEVER settle a short transfer, and NEVER release (the money
    /// moved) -- retain the hold in `outcome_unknown` and flag it loudly for an
    /// operator.
    Mismatch { observed_atomic_amount: String },
}

/// Classify a CONFIRMED on-chain transfer against what is owed, on PARSED INTEGER
/// atomic amounts.
///
/// The comparison itself lives in [`classify_settled_amount`] (`u128` parse,
/// `settled >= owed`, fail-closed on anything unparseable) because the ONLINE
/// finalize path makes the identical money decision and must not drift from this
/// one (#476); this function is only the reconciler's adapter from that shared
/// verdict to its own decision enum:
///
///   * `Covers` -> SETTLE. Exact and overpaid are both spec-valid; the overpaid
///     case additionally carries `settled - owed` so the evidence stays honest
///     about which one happened (#469).
///   * `Short`  -> MISMATCH, fail-closed. An underpayment (or an unparseable
///     amount) is never settled; that is the money-protective direction and is
///     unchanged.
fn decide_confirmed_amount(
    expected_atomic_amount: &str,
    settled_atomic_amount: String,
) -> ReconcileDecision {
    match classify_settled_amount(expected_atomic_amount, &settled_atomic_amount) {
        AmountCoverage::Covers {
            overpayment_atomic_amount,
        } => ReconcileDecision::Settle {
            overpayment_atomic_amount,
            settled_atomic_amount,
        },
        AmountCoverage::Short => ReconcileDecision::Mismatch {
            observed_atomic_amount: settled_atomic_amount,
        },
    }
}

/// True once a submitted attempt is past its confirmation deadline (absence may
/// now be treated as a definite fail). A missing `submitted_at_unix` is never
/// past the deadline -- without a submission time the attempt stays pending
/// rather than risk a premature fail.
fn past_confirmation_deadline(
    submitted_at_unix: Option<i64>,
    now_unix: i64,
    confirmation_deadline_secs: i64,
) -> bool {
    match submitted_at_unix {
        Some(submitted) => now_unix >= submitted.saturating_add(confirmation_deadline_secs.max(0)),
        None => false,
    }
}

/// Apply the trust order. On-chain status is authoritative; the confirmation
/// deadline only ever upgrades an ABSENT signature to a fail (never a pending
/// one, never overrides a confirmed one).
fn decide_reconcile(
    status: OnChainSettlementStatus,
    expected_atomic_amount: &str,
    submitted_at_unix: Option<i64>,
    now_unix: i64,
    confirmation_deadline_secs: i64,
) -> ReconcileDecision {
    match status {
        OnChainSettlementStatus::Confirmed {
            settled_atomic_amount,
        } => decide_confirmed_amount(expected_atomic_amount, settled_atomic_amount),
        OnChainSettlementStatus::Failed { .. } => ReconcileDecision::Fail {
            failure_code: "x402_onchain_settlement_rejected".to_string(),
        },
        OnChainSettlementStatus::NotFound => {
            if past_confirmation_deadline(submitted_at_unix, now_unix, confirmation_deadline_secs) {
                ReconcileDecision::Fail {
                    failure_code: "x402_onchain_absent_past_deadline".to_string(),
                }
            } else {
                ReconcileDecision::Pending
            }
        }
        OnChainSettlementStatus::Pending => ReconcileDecision::Pending,
    }
}

/// Recover the transaction signature to verify on-chain. Prefers the durable
/// `transaction_signature` column (set once a settle records it), falling back
/// to parsing the raw merchant `PAYMENT-RESPONSE` header stored in
/// `settlement_response`. `None` means there is nothing to verify yet -- the
/// attempt is safely re-parked (never failed) until a signature appears.
fn attempt_transaction_signature(attempt: &StoredPaymentAttempt) -> Option<String> {
    if let Some(signature) = attempt.transaction_signature.as_deref() {
        if !signature.is_empty() {
            return Some(signature.to_string());
        }
    }
    let network = SolanaNetwork::from_caip2(&attempt.network_caip2)?;
    let header = attempt.settlement_response.as_deref()?;
    parse_payment_response(header, network)
        .ok()?
        .transaction_signature
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// One reconcile pass's outcome, returned for tests and folded into an
/// inspectable structured log line (+ a per-terminal / per-anomaly audit event).
/// The per-attempt outcome counters are DISJOINT: every scanned attempt bumps
/// exactly one of `settled`/`failed`/`pending`/`mismatch`/`unresolved`/`skipped`/
/// `errored`, so `settled + failed + pending + mismatch + unresolved + skipped +
/// errored == scanned`. `overpaid` is the one deliberate exception: it is a
/// BREAKOUT of `settled`, not an outcome of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct X402ReconcileReport {
    /// Post-submission candidates fetched this tick (<= `max_reconciles_per_tick`).
    pub(crate) scanned: u64,
    /// Confirmed transfers COVERING the owed amount driven to `settled` (hold
    /// captured) -- exact transfers and spec-valid overpayments alike (#469).
    pub(crate) settled: u64,
    /// How many of `settled` were OVERPAYMENTS (`settled > owed`). NOT disjoint:
    /// every overpaid attempt is also counted in `settled`. Broken out so an
    /// overpayment is visible in the tick summary instead of hiding inside a plain
    /// settle -- the hold still captures only the owed amount.
    pub(crate) overpaid: u64,
    /// Definitive failures driven to `failed` (hold released).
    pub(crate) failed: u64,
    /// Still pending / absent-before-deadline: re-parked `outcome_unknown`, hold
    /// retained, backoff cursor advanced.
    pub(crate) pending: u64,
    /// Confirmed on-chain but SHORT of (or unparseable against) the owed amount:
    /// fail-closed, hold retained in `outcome_unknown`, flagged for an operator.
    /// Never settled, never released.
    pub(crate) mismatch: u64,
    /// The chosen edge could not be proven complete across an async boundary:
    /// hold retained, left for idempotent re-entry. Never a false terminal.
    pub(crate) unresolved: u64,
    /// No signature to verify yet, or the attempt raced to a terminal on the
    /// fresh re-read: nothing driven (a no-signature attempt is re-parked to
    /// defer its next check).
    pub(crate) skipped: u64,
    /// Per-attempt errors (RPC failures, storage errors), isolated so one failure
    /// never aborts the batch. Hold retained, attempt untouched.
    pub(crate) errored: u64,
}

/// The per-attempt reconcile outcome, folded into [`X402ReconcileReport`]. Errors
/// are an OUTCOME, not a `Result`, so a single attempt can never abort the batch.
enum ReconcileOutcome {
    /// Driven to `settled` (hold captured). `overpaid` records whether the
    /// confirmed transfer exceeded the owed amount, so the tick summary can break
    /// out overpayments without a second comparison (#469).
    Settled {
        overpaid: bool,
    },
    Failed,
    Pending,
    Mismatch,
    Unresolved,
    Skipped,
    Errored,
}

impl AppState {
    /// Production reconcile tick: resolves the (currently unbound) production
    /// on-chain RPC client and delegates to [`Self::reconcile_x402_settlements_once`].
    /// No-ops when the reconciler is disabled OR no RPC client is bound, so an
    /// operator can enable it via hot config-reload with no restart, and enabling
    /// it before the SVM RPC transport lands is a safe (loudly-logged) no-op.
    /// `now_unix` is injected by the spawning loop so the time source stays owned
    /// by the caller.
    pub(crate) async fn reconcile_x402_settlements_tick(
        &self,
        now_unix: i64,
    ) -> X402ReconcileReport {
        if !self.config.x402_reconciler.enabled {
            return X402ReconcileReport::default();
        }
        match self.production_onchain_settlement_rpc() {
            Some(rpc) => self.reconcile_x402_settlements_once(&rpc, now_unix).await,
            None => {
                tracing::warn!(
                    "x402 settlement reconcile: enabled but no on-chain RPC client is bound \
                     (transport binding is remaining #354 work); skipping tick"
                );
                X402ReconcileReport::default()
            }
        }
    }

    /// The production on-chain RPC client, or `None` while the live SVM RPC
    /// transport is unbound (the remaining #354 work). Returning `None` keeps the
    /// production reconciler inert; the generic driver below is what tests
    /// exercise with an injected fake. The `if let Some(_)` call site in
    /// `reconcile_x402_settlements_tick` still instantiates the driver for the
    /// non-test build (so it is never dead code) via [`UnboundOnChainRpc`].
    fn production_onchain_settlement_rpc(&self) -> Option<UnboundOnChainRpc> {
        None
    }

    /// One on-chain settlement reconcile pass. Re-reads `self.config.x402_reconciler`
    /// so a hot config reload (enable, tune interval/batch/delay/deadline) applies
    /// on the next tick; no-ops immediately when disabled. Fetches a bounded,
    /// oldest-checked-first page of post-submission attempts whose re-check cursor
    /// (`updated_at_unix`) is older than the reconcile-check delay, then drives
    /// each through the injected RPC + trust order with per-attempt error
    /// isolation.
    pub(crate) async fn reconcile_x402_settlements_once<R: OnChainSettlementRpc>(
        &self,
        rpc: &R,
        now_unix: i64,
    ) -> X402ReconcileReport {
        let config = self.config.x402_reconciler.clone();
        if !config.enabled || config.max_reconciles_per_tick == 0 {
            return X402ReconcileReport::default();
        }
        // Only re-check attempts untouched for at least `reconcile_check_delay_secs`:
        // gives a freshly-submitted proof time to propagate before the first
        // check, and spaces re-checks of a still-pending attempt (each re-park
        // bumps `updated_at_unix`, deferring the next check by this delay).
        let checked_before = now_unix.saturating_sub(config.reconcile_check_delay_secs.max(0));

        let candidates = match self
            .repositories
            .list_reconcilable_payment_attempts(checked_before, config.max_reconciles_per_tick)
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(error = %error, "x402 reconcile: failed to list reconcilable attempts");
                return X402ReconcileReport {
                    errored: 1,
                    ..X402ReconcileReport::default()
                };
            }
        };

        let report = self
            .reconcile_x402_attempt_batch(
                rpc,
                &candidates,
                now_unix,
                config.confirmation_deadline_secs,
            )
            .await;
        tracing::info!(
            scanned = report.scanned,
            settled = report.settled,
            overpaid = report.overpaid,
            failed = report.failed,
            pending = report.pending,
            mismatch = report.mismatch,
            unresolved = report.unresolved,
            skipped = report.skipped,
            errored = report.errored,
            "x402 settlement reconcile complete"
        );
        report
    }

    /// Drives the reconcile trust order for one already-fetched batch, with
    /// per-attempt error isolation. Split from the fetch so the isolation
    /// contract is testable directly with a hand-built batch (no timing sleeps).
    async fn reconcile_x402_attempt_batch<R: OnChainSettlementRpc>(
        &self,
        rpc: &R,
        candidates: &[StoredPaymentAttempt],
        now_unix: i64,
        confirmation_deadline_secs: i64,
    ) -> X402ReconcileReport {
        let mut report = X402ReconcileReport {
            scanned: candidates.len() as u64,
            ..X402ReconcileReport::default()
        };
        let loop_ = self.x402_settlement_loop();
        for attempt in candidates {
            let outcome = self
                .reconcile_one_attempt(rpc, &loop_, attempt, now_unix, confirmation_deadline_secs)
                .await;
            match outcome {
                ReconcileOutcome::Settled { overpaid } => {
                    report.settled = report.settled.saturating_add(1);
                    if overpaid {
                        report.overpaid = report.overpaid.saturating_add(1);
                    }
                }
                ReconcileOutcome::Failed => report.failed = report.failed.saturating_add(1),
                ReconcileOutcome::Pending => report.pending = report.pending.saturating_add(1),
                ReconcileOutcome::Mismatch => report.mismatch = report.mismatch.saturating_add(1),
                ReconcileOutcome::Unresolved => {
                    report.unresolved = report.unresolved.saturating_add(1)
                }
                ReconcileOutcome::Skipped => report.skipped = report.skipped.saturating_add(1),
                ReconcileOutcome::Errored => report.errored = report.errored.saturating_add(1),
            }
        }
        report
    }

    /// Reconcile ONE attempt: recover its signature, query the injected RPC, and
    /// drive the loop's SETTLE / FAIL / UNKNOWN edge per the trust order. Every
    /// failure path is an isolated [`ReconcileOutcome`], never a `?`-propagated
    /// abort of the batch. The hold is only ever CAPTURED on a confirmed transfer
    /// that COVERS the owed amount (and then only for the owed amount the hold
    /// reserved), only ever RELEASED on a definite failure, and otherwise
    /// RETAINED.
    async fn reconcile_one_attempt<R: OnChainSettlementRpc>(
        &self,
        rpc: &R,
        loop_: &super::state_x402_settlement::X402SettlementLoop,
        attempt: &StoredPaymentAttempt,
        now_unix: i64,
        confirmation_deadline_secs: i64,
    ) -> ReconcileOutcome {
        let Some(signature) = attempt_transaction_signature(attempt) else {
            // Nothing to verify yet. Re-park (advance the backoff cursor, retain
            // the hold) so a signatureless attempt does not churn every tick, and
            // never fail it -- absence of a signature is not proof of failure.
            return match loop_
                .finalize(
                    &attempt.id,
                    &SettlementEvidence::Unknown {
                        response: None,
                        transaction_signature: None,
                    },
                    now_unix,
                )
                .await
            {
                Ok(_) => {
                    tracing::debug!(
                        attempt_id = %attempt.id,
                        "x402 reconcile: no transaction signature to verify; re-parked outcome_unknown"
                    );
                    ReconcileOutcome::Skipped
                }
                Err(error) => {
                    tracing::warn!(attempt_id = %attempt.id, error = %error,
                        "x402 reconcile: re-park of signatureless attempt failed (isolated)");
                    ReconcileOutcome::Errored
                }
            };
        };

        let query = OnChainQuery {
            transaction_signature: &signature,
            network_caip2: &attempt.network_caip2,
            recipient: &attempt.recipient,
            mint: &attempt.mint,
        };
        let status = match rpc.transfer_status(&query).await {
            Ok(status) => status,
            Err(error) => {
                // An RPC failure is NEVER a settlement verdict: retain the hold,
                // leave the attempt untouched, retry next tick.
                tracing::warn!(attempt_id = %attempt.id, error = %error,
                    "x402 reconcile: on-chain rpc query failed (isolated); hold retained");
                return ReconcileOutcome::Errored;
            }
        };

        let decision = decide_reconcile(
            status,
            &attempt.atomic_amount,
            attempt.submitted_at_unix,
            now_unix,
            confirmation_deadline_secs,
        );

        match decision {
            ReconcileDecision::Settle {
                settled_atomic_amount,
                overpayment_atomic_amount,
            } => {
                let evidence = SettlementEvidence::Settled {
                    transaction_signature: &signature,
                    // The amount the CHAIN transferred, not the amount owed: an
                    // overpaid settlement therefore persists a
                    // `settled_atomic_amount` that differs from the attempt's
                    // `atomic_amount`, keeping the two cases distinguishable in the
                    // durable row (#469).
                    settled_atomic_amount: &settled_atomic_amount,
                    response: attempt.settlement_response.as_deref(),
                };
                // The wallet capture (`settle_wallet_reservation`) debits exactly
                // the amount the hold reserved -- the OWED amount -- and takes no
                // amount argument, so an overpayment can never over-capture. The
                // excess stayed with the payee on-chain; it is the payer's, and
                // FerroGate neither captures nor sweeps it. Only the audit trail
                // changes.
                let audit_message = match overpayment_atomic_amount.as_deref() {
                    Some(excess) => {
                        tracing::info!(
                            attempt_id = %attempt.id,
                            owed = %attempt.atomic_amount,
                            settled = %settled_atomic_amount,
                            excess = %excess,
                            // Logged at the DECISION (the audit event below is
                            // recorded only once the edge proves the terminal).
                            "x402 reconcile: confirmed on-chain OVERPAYMENT (spec-valid, \
                             settled > owed); driving SETTLE with the hold capturing the owed \
                             amount only"
                        );
                        format!(
                            "confirmed on-chain transfer EXCEEDING the owed amount (owed {}, \
                             settled {}, excess {}); captured the wallet hold reserved for the \
                             owed amount only -- the excess is the payer's and is NOT captured \
                             -- and settled the attempt",
                            attempt.atomic_amount, settled_atomic_amount, excess
                        )
                    }
                    None => format!(
                        "confirmed on-chain transfer of the exact owed amount ({}); captured the \
                         wallet hold and settled the attempt",
                        attempt.atomic_amount
                    ),
                };
                self.drive_terminal_edge(
                    loop_,
                    attempt,
                    &evidence,
                    now_unix,
                    ReconcileOutcome::Settled {
                        overpaid: overpayment_atomic_amount.is_some(),
                    },
                    &audit_message,
                )
                .await
            }
            ReconcileDecision::Fail { failure_code } => {
                let evidence = SettlementEvidence::Failed {
                    failure_code: &failure_code,
                    response: attempt.settlement_response.as_deref(),
                };
                self.drive_terminal_edge(
                    loop_,
                    attempt,
                    &evidence,
                    now_unix,
                    ReconcileOutcome::Failed,
                    "on-chain evidence proved the transfer did not settle; released the wallet \
                     hold and failed the attempt",
                )
                .await
            }
            ReconcileDecision::Pending => {
                // Retain the hold; re-park to advance the backoff cursor. `None`
                // response leaves the stored merchant header untouched. Persist the
                // recovered signature into the durable column (#399) so the next
                // tick reads it from storage rather than re-parsing the header.
                match loop_
                    .finalize(
                        &attempt.id,
                        &SettlementEvidence::Unknown {
                            response: None,
                            transaction_signature: Some(&signature),
                        },
                        now_unix,
                    )
                    .await
                {
                    Ok(_) => ReconcileOutcome::Pending,
                    Err(error) => {
                        tracing::warn!(attempt_id = %attempt.id, error = %error,
                            "x402 reconcile: re-park (pending) failed (isolated)");
                        ReconcileOutcome::Errored
                    }
                }
            }
            ReconcileDecision::Mismatch {
                observed_atomic_amount,
            } => {
                // Fail-closed money-safety anomaly: a confirmed transfer that does
                // NOT cover what is owed (short, or an unparseable amount). Never
                // settle, never release -- retain the hold in outcome_unknown and
                // leave a loud, inspectable audit trail.
                let outcome = match loop_
                    .finalize(
                        &attempt.id,
                        &SettlementEvidence::Unknown {
                            response: None,
                            transaction_signature: Some(&signature),
                        },
                        now_unix,
                    )
                    .await
                {
                    Ok(_) => ReconcileOutcome::Mismatch,
                    Err(error) => {
                        tracing::warn!(attempt_id = %attempt.id, error = %error,
                            "x402 reconcile: re-park (amount mismatch) failed (isolated)");
                        return ReconcileOutcome::Errored;
                    }
                };
                tracing::warn!(
                    attempt_id = %attempt.id,
                    expected = %attempt.atomic_amount,
                    observed = %observed_atomic_amount,
                    "x402 reconcile: on-chain amount does NOT cover what is owed; hold retained, \
                     NOT settled (fail-closed)"
                );
                self.record_x402_reconcile_audit(
                    attempt,
                    "x402.settlement.amount_mismatch",
                    &format!(
                        "on-chain transfer confirmed an amount that does not cover what is owed \
                         (expected at least {}, observed {}); hold retained, attempt left \
                         outcome_unknown pending operator review",
                        attempt.atomic_amount, observed_atomic_amount
                    ),
                );
                outcome
            }
        }
    }

    /// Drive a definite SETTLE/FAIL edge and classify its result: a proven
    /// terminal records the money-decision audit and returns `terminal`; an edge
    /// left unresolved across an async boundary retains the hold
    /// (`Unresolved`); any other (raced) result is a safe `Skipped`.
    ///
    /// `audit_message` is the caller's description of the money decision it drove
    /// (an exact settle, an overpaid settle, a release); the audit `action` still
    /// comes from the edge the loop actually PROVED, never from the caller's
    /// intent, so the recorded verb can never outrun the evidence.
    async fn drive_terminal_edge(
        &self,
        loop_: &super::state_x402_settlement::X402SettlementLoop,
        attempt: &StoredPaymentAttempt,
        evidence: &SettlementEvidence<'_>,
        now_unix: i64,
        terminal: ReconcileOutcome,
        audit_message: &str,
    ) -> ReconcileOutcome {
        match loop_.finalize(&attempt.id, evidence, now_unix).await {
            Ok(EdgeOutcome::Settled { .. }) => {
                self.record_x402_reconcile_audit(attempt, "x402.settlement.settled", audit_message);
                terminal
            }
            Ok(EdgeOutcome::Failed { .. }) => {
                self.record_x402_reconcile_audit(attempt, "x402.settlement.failed", audit_message);
                terminal
            }
            Ok(EdgeOutcome::OutcomeUnknown { .. }) => {
                tracing::warn!(attempt_id = %attempt.id,
                    "x402 reconcile: terminal edge unresolved across async boundary; hold retained");
                ReconcileOutcome::Unresolved
            }
            // Any other edge (e.g. the attempt raced to a different terminal on
            // the fresh re-read): nothing of ours moved, a safe skip.
            Ok(_) => ReconcileOutcome::Skipped,
            Err(error) => {
                tracing::warn!(attempt_id = %attempt.id, error = %error,
                    "x402 reconcile: terminal edge failed (isolated); hold retained");
                ReconcileOutcome::Errored
            }
        }
    }

    /// Emit the audit event for one reconcile money-decision (settle / fail /
    /// amount-mismatch): capturing or releasing a wallet hold is a money decision
    /// and must leave inspectable evidence (AGENTS.md "do not hide operational
    /// decisions"). Mirrors the TTL sweeper's audit precedent -- no live
    /// `AuthContext`, so the draft is built directly with `actor_api_key_id: None`.
    fn record_x402_reconcile_audit(
        &self,
        attempt: &StoredPaymentAttempt,
        action: &str,
        message: &str,
    ) {
        let tenant = ferrogate_core::TenantContext {
            organization_id: (!attempt.tenant_id.is_empty()).then(|| attempt.tenant_id.clone()),
            project_id: attempt.project_id.clone(),
            workspace_id: attempt.workspace_id.clone(),
            ..ferrogate_core::TenantContext::default()
        };
        self.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            action_identity: Default::default(),
            request_id: format!("x402-reconcile-{}", now_unix_seconds().unwrap_or(0)),
            trace_id: attempt.trace_id.clone(),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant,
            action: action.to_string(),
            target: attempt.id.clone(),
            outcome: "committed".to_string(),
            message: message.to_string(),
        });
    }
}

#[cfg(test)]
#[path = "state_x402_reconciler_test.rs"]
mod state_x402_reconciler_test;
