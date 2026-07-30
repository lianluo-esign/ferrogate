// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Periodic reclaim of `self_hosted_run_dispatches` rows a terminal
// run left behind (issue #545). #502 gave settlement four on-demand release
// points, but every one of them needs an actor to touch the run: a job a worker
// leased and then abandoned has none, so its unacked `cancel_run` and its
// superseded `start_run` persist until some caller happens to retry the cancel.
// The run is terminal, so the submit budget already released the slot and the
// per-tenant cap never trips -- the rows just accumulate. This sweeper is the
// only release that fires with no actor. Modeled on the billing outbox /
// scheduler / asset-lifecycle / x402 sweepers: always-spawned loop, re-reads
// `state.current()`, no-op when disabled, and idempotent (a delete of an
// already-deleted row is a no-op), so it is safe on every gateway instance
// concurrently.

use super::*;

/// One reclaim pass's outcome, returned for tests and folded into a structured
/// log line. Every count is over the single bounded batch this tick considered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SelfHostedDispatchSweepReport {
    /// Durable dispatch rows read this tick.
    pub(crate) scanned_rows: u64,
    /// Runs holding at least one row whose lease is still live (inside
    /// `lease_expires_at_unix + lease_grace_secs`): skipped WITHOUT a run-status
    /// read, so a worker that reports completion and then acks keeps its ack.
    pub(crate) deferred_live_lease_runs: u64,
    /// Runs whose rows are all lease-dead and whose canonical `agent_runs` row
    /// is NOT terminal -- a live run. Never reclaimed: #503's lease-ownership
    /// proof reads the `start_run` row for the whole life of the run.
    pub(crate) live_runs: u64,
    /// Terminal runs holding an UNDELIVERED `cancel_run` for an assigned
    /// `start_run`, held back because they have not been terminal for
    /// `pending_cancel_grace_secs` yet (or carry no `completed_at_unix` to prove
    /// it with). Deleting these on lease expiry alone is what would make a
    /// cancel the caller already saw succeed silently undeliverable.
    pub(crate) deferred_pending_cancel_runs: u64,
    /// Terminal runs this tick left for the next one because
    /// `max_runs_per_tick` was already spent. Non-zero means a backlog is
    /// draining, not that anything is stuck.
    pub(crate) deferred_over_budget_runs: u64,
    /// Runs whose rows were reclaimed this tick. Only counted when at least one
    /// of the run's rows was actually removed somewhere.
    pub(crate) reclaimed_runs: u64,
    /// Rows actually removed (locally, durably, or both).
    pub(crate) reclaimed_rows: u64,
    /// Rows a reclaim attempt did not remove anywhere -- already gone (a peer
    /// swept the same run concurrently) or the durable delete failed and was
    /// warned about. Retried on the next tick either way; never a false claim
    /// of reclamation.
    pub(crate) unchanged_rows: u64,
}

impl AppState {
    /// One reclaim pass over `self_hosted_run_dispatches`.
    ///
    /// The condition is TERMINAL RUN plus DEAD LEASE, per run, never age alone:
    ///
    /// * A run with no `agent_runs` terminal status is live, and #503's
    ///   ownership proof reads its `start_run` row for the run's whole life --
    ///   deleting that row would make every subsequent worker report fail the
    ///   ownership check.
    /// * A run whose rows include a still-live lease is left for the next tick
    ///   even when terminal. That is the #549 ack window: the worker that
    ///   reported completion is by construction the `start_run` lease holder and
    ///   may not have acked yet. Once the lease expires the ack is refused by
    ///   the queue anyway (`ack lease has expired`), so nothing is lost by
    ///   reclaiming afterwards.
    ///
    /// The gate is evaluated per RUN rather than per row, so a terminal run's
    /// never-leased `cancel_run` row -- the abandoned-worker leak this issue is
    /// about -- is not reclaimed while its sibling `start_run` lease is still
    /// live and could still deliver that cancel to the holder.
    ///
    /// One shape needs MORE than a dead lease. A `cancel_run` that is unacked
    /// while its run's `start_run` was assigned is the NOT-WITHDRAWABLE cancel
    /// (`agent_jobs.rs::cancel_agent_job_in_runtime`): the row is deliberately
    /// kept because collecting it is the ONLY thing that stops a worker already
    /// executing the run, and its delivery is bounded by that worker's next
    /// poll, not by the lease. Leases are 30-60s and never renewed, so on any
    /// job longer than a minute the lease is dead while the work is still
    /// running. Those groups are therefore additionally gated on how long the
    /// run has been TERMINAL (`pending_cancel_grace_secs`), which is the only
    /// clock that tracks "has the caller's cancel had a fair chance to land".
    ///
    /// `now_unix` is injected (not read from the clock here) so the driving loop
    /// owns the time source and tests can drive expiry deterministically without
    /// timing sleeps.
    pub(crate) fn sweep_self_hosted_dispatches_once(
        &self,
        now_unix: u64,
    ) -> SelfHostedDispatchSweepReport {
        let config = self.config.self_hosted_dispatch_sweeper.clone();
        if !config.enabled {
            return SelfHostedDispatchSweepReport::default();
        }
        if config.max_runs_per_tick == 0 {
            // Behaviourally identical to `enabled = false`, so say so instead of
            // letting a mis-set bound look like a healthy sweeper.
            tracing::warn!(
                "self-hosted dispatch reclaim sweeper is configured with \
                 max_runs_per_tick = 0 and can never reclaim anything; set it \
                 above zero or disable the sweeper explicitly"
            );
            return SelfHostedDispatchSweepReport::default();
        }
        let lease_grace_secs = clamp_grace_secs(config.lease_grace_secs, "lease_grace_secs");
        let pending_cancel_grace_secs = clamp_grace_secs(
            config.pending_cancel_grace_secs,
            "pending_cancel_grace_secs",
        );

        let mut rows = ferrogate_sync_bridge::block_on_sync_bridge(
            self.repositories.self_hosted_run_dispatches(),
        );
        // The store has no pushdown filter for this table yet, so the read is
        // still whole-table; this bounds the WORK done per tick (grouping, the
        // batched run-status read, the delete loop) and makes the size visible.
        if rows.len() > config.max_scanned_rows {
            tracing::warn!(
                table_rows = rows.len(),
                max_scanned_rows = config.max_scanned_rows,
                "self_hosted_run_dispatches exceeds the reclaim sweeper's scan \
                 bound; this tick considers only the first max_scanned_rows \
                 rows and the read itself is still a full-table load"
            );
            rows.truncate(config.max_scanned_rows);
        }
        let mut report = SelfHostedDispatchSweepReport {
            scanned_rows: rows.len() as u64,
            ..SelfHostedDispatchSweepReport::default()
        };
        if rows.is_empty() {
            self.record_self_hosted_dispatch_reclaim_metrics(&report);
            return report;
        }

        // Group by run, remembering the oldest queue time so the backlog drains
        // oldest-first and successive bounded ticks make guaranteed progress.
        let mut runs: HashMap<String, RunDispatchGroup> = HashMap::new();
        for row in rows {
            let group = runs.entry(row.run_id.clone()).or_default();
            group.lease_is_live |=
                lease_is_live(row.lease_expires_at_unix, lease_grace_secs, now_unix);
            group.has_unacked_cancel |=
                row.action == SELF_HOSTED_CANCEL_RUN_ACTION && row.acknowledged_status.is_none();
            group.start_was_assigned |=
                row.action == SELF_HOSTED_START_RUN_ACTION && row.assigned_worker_id.is_some();
            group.oldest_queued_at_unix = group
                .oldest_queued_at_unix
                .min(row.queued_at_unix.unwrap_or(0));
            if group.tenant_id.is_empty() {
                group.tenant_id = row.tenant_id;
            }
            group.dispatch_ids.push(row.dispatch_id);
        }

        let mut candidates: Vec<(String, RunDispatchGroup)> = Vec::new();
        for (run_id, group) in runs {
            if group.lease_is_live {
                report.deferred_live_lease_runs += 1;
                continue;
            }
            candidates.push((run_id, group));
        }
        if candidates.is_empty() {
            self.record_self_hosted_dispatch_reclaim_metrics(&report);
            return report;
        }
        // `(queued_at, run_id)` and not `queued_at` alone: rows seeded in the
        // same second must still order deterministically, or the bound below
        // could keep re-picking the same subset and starve the rest.
        candidates.sort_by(|left, right| {
            (left.1.oldest_queued_at_unix, &left.0).cmp(&(right.1.oldest_queued_at_unix, &right.0))
        });

        // ONE batched, durable run-status read for the whole tick, over EVERY
        // candidate rather than a pre-truncated prefix: the run row is the
        // cluster-wide record, so a job terminalized through a peer is
        // reclaimable here even though this node never served it -- and the
        // per-tick budget must be spent on runs that can actually be reclaimed.
        // Candidates that can never become terminal (a dispatch with no
        // `agent_runs` row, a worker that vanished without a cancel) accumulate
        // forever and sort oldest-first; truncating BEFORE this read would hand
        // them the whole budget and stop the sweeper permanently.
        let run_ids: Vec<String> = candidates
            .iter()
            .map(|(run_id, _)| run_id.clone())
            .collect();
        let settled_runs = self.settled_agent_run_completions(&run_ids);

        for (run_id, group) in candidates {
            if report.reclaimed_runs as usize >= config.max_runs_per_tick {
                report.deferred_over_budget_runs += 1;
                continue;
            }
            let Some(completed_at_unix) = settled_runs.get(&run_id) else {
                report.live_runs += 1;
                continue;
            };
            if group.has_unacked_cancel
                && group.start_was_assigned
                && !terminal_long_enough(*completed_at_unix, pending_cancel_grace_secs, now_unix)
            {
                report.deferred_pending_cancel_runs += 1;
                continue;
            }

            let mut reclaimed_here = 0_u64;
            for dispatch_id in &group.dispatch_ids {
                if self.discard_self_hosted_dispatch(dispatch_id) {
                    reclaimed_here += 1;
                } else {
                    report.unchanged_rows += 1;
                }
            }
            report.reclaimed_rows += reclaimed_here;
            // Only a run whose rows actually went anywhere is a reclaim. A run
            // whose every delete was a no-op (a peer swept it first, or the
            // durable delete errored) is retried next tick and must not spend
            // this tick's budget or be reported as collected.
            if reclaimed_here > 0 {
                report.reclaimed_runs += 1;
                self.record_self_hosted_dispatch_reclaim_audit(
                    &group.tenant_id,
                    &run_id,
                    reclaimed_here,
                );
            }
        }

        self.record_self_hosted_dispatch_reclaim_metrics(&report);
        if report.reclaimed_rows > 0 || report.unchanged_rows > 0 {
            tracing::info!(
                scanned_rows = report.scanned_rows,
                deferred_live_lease_runs = report.deferred_live_lease_runs,
                deferred_pending_cancel_runs = report.deferred_pending_cancel_runs,
                deferred_over_budget_runs = report.deferred_over_budget_runs,
                live_runs = report.live_runs,
                reclaimed_runs = report.reclaimed_runs,
                reclaimed_rows = report.reclaimed_rows,
                unchanged_rows = report.unchanged_rows,
                "self-hosted dispatch reclaim sweep complete"
            );
        } else {
            // `warn!`, not `debug!`: candidates were present and NOTHING was
            // reclaimed. Nothing else prunes this table, so at default log level
            // this is the only way an operator sees the sweeper has stalled.
            tracing::warn!(
                scanned_rows = report.scanned_rows,
                deferred_live_lease_runs = report.deferred_live_lease_runs,
                deferred_pending_cancel_runs = report.deferred_pending_cancel_runs,
                deferred_over_budget_runs = report.deferred_over_budget_runs,
                live_runs = report.live_runs,
                "self-hosted dispatch reclaim sweep found nothing to reclaim"
            );
        }
        report
    }

    /// Fold one sweep into the cumulative Prometheus counters
    /// (`ferrogate_self_hosted_dispatch_reclaim_{scanned,reclaimed,failed}_total`),
    /// mirroring `record_asset_lifecycle_metrics`.
    fn record_self_hosted_dispatch_reclaim_metrics(&self, report: &SelfHostedDispatchSweepReport) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_self_hosted_dispatch_reclaim_sweep(
                report.scanned_rows,
                report.reclaimed_rows,
                report.unchanged_rows,
            );
        }
    }

    /// Compliance evidence for one run's reclaim: this is a data-DELETING
    /// background task, and `docs/security-controls.md`'s Data Retention section
    /// requires the purge itself to be audited. Shaped like
    /// `record_asset_lifecycle_audit`; the tenant comes off the dispatch rows.
    fn record_self_hosted_dispatch_reclaim_audit(
        &self,
        tenant_id: &str,
        run_id: &str,
        reclaimed_rows: u64,
    ) {
        let tenant = ferrogate_core::TenantContext {
            organization_id: (!tenant_id.is_empty()).then(|| tenant_id.to_string()),
            ..ferrogate_core::TenantContext::default()
        };
        self.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            action_identity: Default::default(),
            request_id: format!(
                "self-hosted-dispatch-reclaim-{}",
                now_unix_seconds().unwrap_or(0)
            ),
            trace_id: None,
            agent_run_id: Some(run_id.to_string()),
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant,
            action: "self_hosted_dispatch.reclaim".to_string(),
            target: format!("agent_run:{run_id}"),
            outcome: "committed".to_string(),
            message: format!(
                "reclaimed {reclaimed_rows} self-hosted dispatch row(s) left behind by terminal \
                 run {run_id}"
            ),
        });
    }
}

/// `StoredSelfHostedRunDispatch::action` is a string column; these are the two
/// values the reclaim decision reads. Kept next to the fold that uses them
/// rather than re-deriving them through `SelfHostedRunAction` parsing, which
/// would silently treat an unknown action as neither.
const SELF_HOSTED_START_RUN_ACTION: &str = "start_run";
const SELF_HOSTED_CANCEL_RUN_ACTION: &str = "cancel_run";

/// The per-run fold the sweep builds before it decides anything.
#[derive(Debug)]
struct RunDispatchGroup {
    dispatch_ids: Vec<String>,
    lease_is_live: bool,
    /// A `cancel_run` row nobody has acked. On its own this is the abandoned
    /// cancel the reclaim exists for; combined with `start_was_assigned` it is
    /// instead a cancel that may still be undelivered to a working holder.
    has_unacked_cancel: bool,
    /// A `start_run` row that was handed to a worker. The worker may still be
    /// executing long after its (never-renewed) lease expired.
    start_was_assigned: bool,
    /// Tenant of the run's rows, for the reclaim audit event. Every row of one
    /// run carries the same tenant, so the first non-empty one is authoritative.
    tenant_id: String,
    oldest_queued_at_unix: u64,
}

impl Default for RunDispatchGroup {
    fn default() -> Self {
        Self {
            dispatch_ids: Vec::new(),
            lease_is_live: false,
            has_unacked_cancel: false,
            start_was_assigned: false,
            tenant_id: String::new(),
            // `min`-folded, so the identity element is the maximum.
            oldest_queued_at_unix: u64::MAX,
        }
    }
}

/// Whether a terminal run has been terminal for at least `grace_secs`.
///
/// A terminal run with NO `completed_at_unix` cannot prove it, so it is not
/// long enough -- absence of a timestamp never licenses a delete that could eat
/// an undelivered cancel. Every current settle path writes the timestamp
/// (`agent_jobs.rs` sets it on cancel, `state_agent_runtime.rs` on the worker
/// report), so this only holds back rows written before those paths did.
fn terminal_long_enough(completed_at_unix: Option<u64>, grace_secs: u64, now_unix: u64) -> bool {
    match completed_at_unix {
        Some(completed_at) => completed_at.saturating_add(grace_secs) <= now_unix,
        None => false,
    }
}

/// Clamp a configured grace window to
/// [`ferrogate_config::MAX_SELF_HOSTED_DISPATCH_SWEEPER_GRACE_SECS`].
///
/// An unbounded grace is not a conservative setting, it is a silent off switch:
/// `lease_is_live` would answer "live" forever and nothing would ever be
/// reclaimed, with no other signal that the sweeper had been disabled.
fn clamp_grace_secs(configured_secs: u64, field: &'static str) -> u64 {
    if configured_secs > ferrogate_config::MAX_SELF_HOSTED_DISPATCH_SWEEPER_GRACE_SECS {
        tracing::warn!(
            field,
            configured_secs,
            max_secs = ferrogate_config::MAX_SELF_HOSTED_DISPATCH_SWEEPER_GRACE_SECS,
            "self-hosted dispatch reclaim sweeper grace exceeds the supported \
             maximum and was clamped; an unclamped value would disable the \
             reclaim entirely"
        );
        return ferrogate_config::MAX_SELF_HOSTED_DISPATCH_SWEEPER_GRACE_SECS;
    }
    configured_secs
}

/// Whether a dispatch's lease is still live at `now_unix`.
///
/// A row that was never leased (`None`) has no lease to outlive and is NOT live
/// -- that is the abandoned `cancel_run` this reclaim exists for. `grace_secs`
/// is added to the persisted expiry because that expiry is derived from the
/// WORKER-supplied `now_unix` of the poll that took the lease, so a worker whose
/// clock runs slow would otherwise present a still-held lease as dead.
fn lease_is_live(lease_expires_at_unix: Option<u64>, grace_secs: u64, now_unix: u64) -> bool {
    match lease_expires_at_unix {
        Some(expires_at) => expires_at.saturating_add(grace_secs) > now_unix,
        None => false,
    }
}

#[cfg(test)]
#[path = "state_self_hosted_dispatch_sweeper_test.rs"]
mod state_self_hosted_dispatch_sweeper_test;
