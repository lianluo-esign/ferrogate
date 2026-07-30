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
    /// Runs whose rows were reclaimed this tick.
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
    /// `now_unix` is injected (not read from the clock here) so the driving loop
    /// owns the time source and tests can drive expiry deterministically without
    /// timing sleeps.
    pub(crate) fn sweep_self_hosted_dispatches_once(
        &self,
        now_unix: u64,
    ) -> SelfHostedDispatchSweepReport {
        let config = self.config.self_hosted_dispatch_sweeper.clone();
        if !config.enabled || config.max_runs_per_tick == 0 {
            return SelfHostedDispatchSweepReport::default();
        }

        let rows = ferrogate_sync_bridge::block_on_sync_bridge(
            self.repositories.self_hosted_run_dispatches(),
        );
        let mut report = SelfHostedDispatchSweepReport {
            scanned_rows: rows.len() as u64,
            ..SelfHostedDispatchSweepReport::default()
        };
        if rows.is_empty() {
            return report;
        }

        // Group by run, remembering the oldest queue time so the backlog drains
        // oldest-first and successive bounded ticks make guaranteed progress.
        let mut runs: HashMap<String, RunDispatchGroup> = HashMap::new();
        for row in rows {
            let group = runs.entry(row.run_id.clone()).or_default();
            group.lease_is_live |=
                lease_is_live(row.lease_expires_at_unix, config.lease_grace_secs, now_unix);
            group.oldest_queued_at_unix = group
                .oldest_queued_at_unix
                .min(row.queued_at_unix.unwrap_or(0));
            group.dispatch_ids.push(row.dispatch_id);
        }

        let mut candidates: Vec<(u64, String, Vec<String>)> = Vec::new();
        for (run_id, group) in runs {
            if group.lease_is_live {
                report.deferred_live_lease_runs += 1;
                continue;
            }
            candidates.push((group.oldest_queued_at_unix, run_id, group.dispatch_ids));
        }
        if candidates.is_empty() {
            return report;
        }
        // `(queued_at, run_id)` and not `queued_at` alone: rows seeded in the
        // same second must still order deterministically, or the bound below
        // could keep re-picking the same subset and starve the rest.
        candidates.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
        candidates.truncate(config.max_runs_per_tick);

        // ONE batched, durable run-status read for the whole tick: the run row
        // is the cluster-wide record, so a job terminalized through a peer is
        // reclaimable here even though this node never served it.
        let run_ids: Vec<String> = candidates
            .iter()
            .map(|(_, run_id, _)| run_id.clone())
            .collect();
        let terminal_run_ids = self.settled_agent_run_ids(&run_ids);

        for (_, run_id, dispatch_ids) in candidates {
            if !terminal_run_ids.contains(&run_id) {
                report.live_runs += 1;
                continue;
            }
            report.reclaimed_runs += 1;
            for dispatch_id in dispatch_ids {
                if self.discard_self_hosted_dispatch(&dispatch_id) {
                    report.reclaimed_rows += 1;
                } else {
                    report.unchanged_rows += 1;
                }
            }
        }

        if report.reclaimed_rows > 0 || report.unchanged_rows > 0 {
            tracing::info!(
                scanned_rows = report.scanned_rows,
                deferred_live_lease_runs = report.deferred_live_lease_runs,
                live_runs = report.live_runs,
                reclaimed_runs = report.reclaimed_runs,
                reclaimed_rows = report.reclaimed_rows,
                unchanged_rows = report.unchanged_rows,
                "self-hosted dispatch reclaim sweep complete"
            );
        } else {
            tracing::debug!(
                scanned_rows = report.scanned_rows,
                deferred_live_lease_runs = report.deferred_live_lease_runs,
                live_runs = report.live_runs,
                "self-hosted dispatch reclaim sweep found nothing to reclaim"
            );
        }
        report
    }
}

/// The per-run fold the sweep builds before it decides anything.
#[derive(Debug)]
struct RunDispatchGroup {
    dispatch_ids: Vec<String>,
    lease_is_live: bool,
    oldest_queued_at_unix: u64,
}

impl Default for RunDispatchGroup {
    fn default() -> Self {
        Self {
            dispatch_ids: Vec::new(),
            lease_is_live: false,
            // `min`-folded, so the identity element is the maximum.
            oldest_queued_at_unix: u64::MAX,
        }
    }
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
