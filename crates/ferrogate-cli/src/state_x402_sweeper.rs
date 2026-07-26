// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Background TTL sweeper for overdue x402 payment attempts (issue
// #354). The settle/release loop (`state_x402_settlement.rs`) already exposes a
// money-safe per-attempt `expire_if_due` edge, but nothing drove it on a
// schedule: an attempt authorized/challenged but never finalized kept its wallet
// hold indefinitely. This module is the control-plane side of the gap-fill --
// one bounded tick fetches a page of due, pre-submission attempts (short indexed
// storage read, never a full-table scan) and re-drives the loop's idempotent
// RELEASE edge for each, with per-attempt error isolation. It is money-safe by
// construction: the due-query and `expire_if_due` BOTH restrict to
// pre-submission holds, so a `submitted` attempt whose stablecoin may already
// have moved on-chain is never released -- that case stays `outcome_unknown`
// (hold retained), the reconciler's job, not the sweeper's. Modeled on the
// billing outbox / scheduler / asset-lifecycle sweepers: always-spawned loop,
// re-reads `state.current()`, no-op when disabled, safe to run on every gateway
// instance concurrently (the release edge is idempotent).

use super::state_x402_settlement::EdgeOutcome;
use super::*;

/// One x402 TTL sweep pass's outcome, returned for tests and folded into an
/// inspectable structured log line + a per-release audit event. All counts are
/// over the single bounded batch this tick fetched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct X402SweepReport {
    /// Due, pre-submission candidates fetched this tick (<= `max_expiries_per_tick`).
    pub(crate) scanned: u64,
    /// Attempts whose overdue pre-submission hold was released (attempt -> released).
    pub(crate) released: u64,
    /// Candidates the fresh re-check found no longer expirable/due (e.g. raced
    /// into `submitted`, or already terminal): left untouched, no hold moved.
    pub(crate) skipped: u64,
    /// Candidates whose release edge could not be proven complete across an
    /// async boundary: hold RETAINED, left for idempotent re-entry. Never a
    /// false release.
    pub(crate) outcome_unknown: u64,
    /// Per-attempt errors, isolated so one failure never aborts the batch.
    pub(crate) failed: u64,
    /// Overdue wallet holds that NO payment attempt owns, released by the
    /// orphan sweep this tick (see [`AppState::sweep_orphaned_x402_holds`]).
    pub(crate) orphan_holds_released: u64,
}

impl AppState {
    /// One x402 TTL sweep pass. Re-reads `self.config.x402_sweeper` so a hot
    /// config reload (enable, tune interval/batch/grace) applies on the next
    /// tick; no-ops immediately when disabled, exactly like the billing outbox,
    /// scheduler, and asset-lifecycle sweepers.
    ///
    /// `now_unix` is injected (not read from the clock here) so the driving loop
    /// owns the time source and tests can drive expiry deterministically without
    /// timing sleeps.
    pub(crate) async fn sweep_x402_expired_attempts_once(&self, now_unix: i64) -> X402SweepReport {
        let config = self.config.x402_sweeper.clone();
        if !config.enabled || config.max_expiries_per_tick == 0 {
            return X402SweepReport::default();
        }
        // Only sweep holds whose TTL elapsed at least `hold_ttl_grace_secs` ago:
        // a defensive delay so the sweeper never races a hold that only just
        // expired while an in-flight finalize is still landing.
        let due_before = now_unix.saturating_sub(config.hold_ttl_grace_secs.max(0));

        let candidates = match self
            .repositories
            .list_expirable_due_payment_attempts(due_before, config.max_expiries_per_tick)
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(error = %error, "x402 ttl sweep: failed to list due attempts");
                return X402SweepReport {
                    failed: 1,
                    ..X402SweepReport::default()
                };
            }
        };

        let mut report = self.expire_x402_attempt_batch(&candidates, now_unix).await;
        // Second, disjoint pass: the holds no attempt owns. The attempt-driven
        // pass above cannot see them -- `list_expirable_due_payment_attempts` is
        // an INNER JOIN driven from the attempt side, so a hold whose attempt row
        // never committed is structurally invisible to it.
        self.sweep_orphaned_x402_holds(due_before, &mut report)
            .await;
        tracing::info!(
            scanned = report.scanned,
            released = report.released,
            skipped = report.skipped,
            outcome_unknown = report.outcome_unknown,
            failed = report.failed,
            orphan_holds_released = report.orphan_holds_released,
            "x402 ttl sweep complete"
        );
        report
    }

    /// Reclaims overdue wallet holds that NO payment attempt owns (#352 review
    /// §3), folding the count and per-hold audit evidence into `report`.
    ///
    /// The crash window this closes is real and documented: `open()` commits the
    /// wallet reserve and then, in a SECOND transaction, commits the attempt row.
    /// A process death between the two leaves a `status = 'active'` reservation
    /// with no attempt. Available balance self-heals (it sums only unexpired
    /// holds), so this is not an oversell -- but every consumer that reads
    /// `status` instead of recomputing expiry reports a phantom live hold against
    /// the customer's wallet, forever, because nothing re-drives that row.
    ///
    /// Money-safety is enforced in the storage predicate, not here:
    /// `sweep_expired_wallet_reservations` releases only holds with NO
    /// `payment_attempts` row, so a `submitted`/`outcome_unknown` attempt's hold
    /// (whose stablecoin may already have moved on-chain) and a pre-submission
    /// attempt's hold (owned by the attempt-driven pass above) are both excluded
    /// by construction. The release is idempotent -- an already-`released` row is
    /// not `active` and is not re-swept -- so this is safe on every gateway
    /// instance concurrently, like the rest of the tick.
    async fn sweep_orphaned_x402_holds(&self, due_before: i64, report: &mut X402SweepReport) {
        match self
            .repositories
            .sweep_expired_wallet_reservations(due_before)
            .await
        {
            Ok(released) => {
                report.orphan_holds_released = released.len() as u64;
                for hold_id in &released {
                    self.record_x402_orphan_hold_audit(hold_id);
                }
            }
            Err(error) => {
                report.failed = report.failed.saturating_add(1);
                tracing::warn!(
                    error = %error,
                    "x402 ttl sweep: failed to sweep orphaned wallet holds (isolated)"
                );
            }
        }
    }

    /// Drives the loop's release edge for one already-fetched batch, with
    /// per-attempt error isolation. Split from the fetch so the isolation
    /// contract is testable directly with a hand-built batch (no timing sleeps).
    async fn expire_x402_attempt_batch(
        &self,
        candidates: &[ferrogate_storage::StoredPaymentAttempt],
        now_unix: i64,
    ) -> X402SweepReport {
        let mut report = X402SweepReport {
            scanned: candidates.len() as u64,
            ..X402SweepReport::default()
        };
        let loop_ = self.x402_settlement_loop();
        for attempt in candidates {
            // `expire_if_due` re-reads and re-checks under a fresh transaction and
            // drives the loop's idempotent RELEASE edge ONLY for a still
            // pre-submission, still-expired hold. It never reimplements the state
            // machine here and never releases a submitted hold, so a candidate
            // that raced into `submitted` between the list read and this call is
            // safe. Per-attempt error isolation: one failure is logged + counted,
            // never aborting the rest of the batch.
            match loop_.expire_if_due(&attempt.id, now_unix).await {
                Ok(Some(EdgeOutcome::Released { .. })) => {
                    report.released = report.released.saturating_add(1);
                    self.record_x402_sweep_audit(attempt);
                }
                Ok(Some(EdgeOutcome::OutcomeUnknown { .. })) => {
                    report.outcome_unknown = report.outcome_unknown.saturating_add(1);
                    tracing::warn!(
                        attempt_id = %attempt.id,
                        "x402 ttl sweep: release edge unresolved across async boundary; \
                         hold retained for re-entry"
                    );
                }
                // `None` (no longer due/pre-submission on re-read) or any other
                // terminal edge that cannot arise from `expire_if_due`: nothing
                // was released, so it is a safe skip.
                Ok(_) => {
                    report.skipped = report.skipped.saturating_add(1);
                }
                Err(error) => {
                    report.failed = report.failed.saturating_add(1);
                    tracing::warn!(
                        attempt_id = %attempt.id,
                        error = %error,
                        "x402 ttl sweep: failed to expire attempt (isolated)"
                    );
                }
            }
        }
        report
    }

    /// Emit the audit event for one sweep-driven hold release: releasing a wallet
    /// hold is a money decision, so it must leave inspectable evidence (AGENTS.md
    /// "do not hide operational decisions"). Mirrors the wallet-ledger / asset
    /// lifecycle audit precedent -- no live `AuthContext`, so the draft is built
    /// directly with `actor_api_key_id: None`.
    fn record_x402_sweep_audit(&self, attempt: &ferrogate_storage::StoredPaymentAttempt) {
        let tenant = ferrogate_core::TenantContext {
            organization_id: (!attempt.tenant_id.is_empty()).then(|| attempt.tenant_id.clone()),
            project_id: attempt.project_id.clone(),
            workspace_id: attempt.workspace_id.clone(),
            ..ferrogate_core::TenantContext::default()
        };
        self.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            action_identity: Default::default(),
            request_id: format!("x402-ttl-sweep-{}", now_unix_seconds().unwrap_or(0)),
            trace_id: attempt.trace_id.clone(),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant,
            action: "x402.hold.ttl_expired".to_string(),
            target: attempt.id.clone(),
            outcome: "committed".to_string(),
            message: format!(
                "released overdue pre-submission x402 hold {} (attempt state {}) via TTL sweep",
                attempt.hold_id.as_deref().unwrap_or("-"),
                attempt.state,
            ),
        });
    }

    /// Emit the audit event for one orphan-hold release. The hold has no attempt
    /// row, so there is no tenant/project chain to attribute it to -- the
    /// evidence is deliberately the bare hold id plus the reason it was
    /// reclaimable, rather than a guessed tenancy.
    fn record_x402_orphan_hold_audit(&self, hold_id: &str) {
        self.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            action_identity: Default::default(),
            request_id: format!("x402-orphan-hold-sweep-{}", now_unix_seconds().unwrap_or(0)),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            action: "x402.hold.orphan_expired".to_string(),
            target: hold_id.to_string(),
            outcome: "committed".to_string(),
            message: format!(
                "released overdue wallet hold {hold_id}: past its TTL and owned by no payment \
                 attempt (reserve committed, attempt create did not)"
            ),
        });
    }
}

#[cfg(test)]
#[path = "state_x402_sweeper_test.rs"]
mod state_x402_sweeper_test;
