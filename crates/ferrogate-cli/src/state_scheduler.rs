// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Scheduler tick loop for time-based agent schedule triggers
// (#246). A control-plane trigger layer: when a schedule is due it enqueues a
// dispatch into the EXISTING self-hosted lease queue (reusing the worker
// poll/ack task-state machine) and records an idempotent fire-history row. The
// `agent_schedule_fires` UNIQUE (schedule_id, scheduled_fire_at_unix) row plus
// a deterministic dispatch id make firing at-most-once per (schedule, slot)
// even with multiple gateway instances racing the same database.

use super::*;

/// Max due schedules processed per tick. Bounds one tick's work so a large
/// backlog is drained across ticks rather than in a single unbounded pass.
const SCHEDULER_DUE_BATCH: i64 = 200;

/// Hard cap on catch-up iterations when fast-forwarding `next_fire_at` past a
/// long outage, so advancing a short-interval schedule after extended downtime
/// can never spin unbounded (the remaining gap self-heals on later ticks).
const SCHEDULER_CATCHUP_ITER_CAP: u64 = 10_000;

/// Deterministic dispatch id for a (schedule, slot) fire so two gateway
/// instances that race the same due slot enqueue the SAME dispatch -- the lease
/// queue dedups on id, yielding exactly one dispatch per slot.
fn scheduled_dispatch_id(schedule_id: &str, slot: i64) -> String {
    format!("schedule-dispatch-{schedule_id}-{slot}")
}

impl AppState {
    /// One scheduler tick. Re-reads `self.config` so a hot config reload (enable
    /// the scheduler, change the tick interval) applies on the next tick, and
    /// no-ops immediately when `scheduler.enabled = false` -- exactly like the
    /// billing outbox sweeper, so the always-spawned loop costs one sleep-wake
    /// per tick when the feature is off.
    pub(crate) async fn sweep_agent_schedules_once(&self) {
        if !self.config.scheduler.enabled {
            return;
        }
        let now = now_unix_seconds().unwrap_or_default() as i64;
        if now == 0 {
            return;
        }
        let due = match self
            .repositories
            .list_due_agent_schedules(now, SCHEDULER_DUE_BATCH)
            .await
        {
            Ok(due) => due,
            Err(error) => {
                warn!(error = %error, "scheduler: failed to list due agent schedules");
                return;
            }
        };
        for schedule in due {
            self.fire_due_schedule(&schedule, now).await;
        }
    }

    async fn fire_due_schedule(&self, schedule: &StoredAgentSchedule, now: i64) {
        let Some(slot) = schedule.next_fire_at_unix else {
            return;
        };

        // Are newer slots already elapsed (we are catching up after downtime)
        // rather than firing on time? True when the slot immediately after the
        // due one is itself already in the past.
        let is_catchup = schedule
            .compute_next_fire_at(slot)
            .ok()
            .flatten()
            .is_some_and(|next| next <= now);

        // Catch-up policy `skip_missed` (n8n semantics, default): do NOT fire a
        // missed slot; fast-forward to the first future slot. `fire_once` falls
        // through and fires a single catch-up for this slot, then fast-forwards.
        if is_catchup && schedule.catchup_policy == CatchupPolicy::SkipMissed {
            self.advance_schedule_past_now(schedule, slot, now).await;
            return;
        }

        // Overlap policy `skip` (default): suppress this fire while the previous
        // fire's dispatch is still in flight (unacked), preventing pile-up.
        if schedule.overlap_policy == OverlapPolicy::Skip {
            if let Some(prev_slot) = schedule.last_fire_at_unix {
                let prev_dispatch_id = scheduled_dispatch_id(&schedule.schedule_id, prev_slot);
                if self.self_hosted_dispatch_unacked(&prev_dispatch_id) {
                    self.record_fire(
                        schedule,
                        slot,
                        now,
                        ScheduleFireOutcome::SkippedOverlap,
                        None,
                        Some("previous dispatch still in flight"),
                    )
                    .await;
                    self.advance_schedule_past_now(schedule, slot, now).await;
                    return;
                }
            }
        }

        match schedule.target_kind {
            ScheduleTargetKind::SelfHostedDispatch => {
                let dispatch = match build_self_hosted_dispatch(schedule, slot, now) {
                    Ok(dispatch) => dispatch,
                    Err(message) => {
                        self.record_fire(
                            schedule,
                            slot,
                            now,
                            ScheduleFireOutcome::Error,
                            None,
                            Some(&message),
                        )
                        .await;
                        self.advance_schedule_past_now(schedule, slot, now).await;
                        return;
                    }
                };
                let dispatch_id = dispatch.dispatch_id.clone();
                // Enqueue FIRST (idempotent on the deterministic id), then claim
                // the fire slot. If a peer instance already enqueued the same
                // dispatch it is deduped; if a peer already claimed the fire
                // row, our claim loses and we simply advance -- either way the
                // slot yields exactly one dispatch.
                if let Err(error) = self.enqueue_scheduled_self_hosted_dispatch(dispatch) {
                    warn!(
                        schedule_id = %schedule.schedule_id,
                        error = %error,
                        "scheduler: failed to enqueue self-hosted dispatch"
                    );
                    self.record_fire(
                        schedule,
                        slot,
                        now,
                        ScheduleFireOutcome::Error,
                        None,
                        Some(&error.to_string()),
                    )
                    .await;
                    self.advance_schedule_past_now(schedule, slot, now).await;
                    return;
                }
                self.record_fire(
                    schedule,
                    slot,
                    now,
                    ScheduleFireOutcome::Dispatched,
                    Some(dispatch_id),
                    None,
                )
                .await;
                self.advance_schedule_past_now(schedule, slot, now).await;
            }
            ScheduleTargetKind::AgentRun => {
                // TODO(#246): wire the managed/synchronous `handle_agent_run_create`
                // path. The self-hosted dispatch target is the fully-supported
                // trigger today; record the attempt so the gap is observable
                // rather than silently dropped.
                self.record_fire(
                    schedule,
                    slot,
                    now,
                    ScheduleFireOutcome::Error,
                    None,
                    Some("agent_run target kind is not yet wired (TODO #246)"),
                )
                .await;
                self.advance_schedule_past_now(schedule, slot, now).await;
            }
        }
    }

    /// Idempotently record a fire-history row for `(schedule, slot)`. The insert
    /// is the at-most-once gate: a peer that already recorded the slot makes
    /// this a no-op.
    async fn record_fire(
        &self,
        schedule: &StoredAgentSchedule,
        slot: i64,
        now: i64,
        outcome: ScheduleFireOutcome,
        dispatch_id: Option<String>,
        detail: Option<&str>,
    ) {
        let fire = StoredAgentScheduleFire {
            fire_id: agent_schedule_fire_id(&schedule.schedule_id, slot),
            schedule_id: schedule.schedule_id.clone(),
            scheduled_fire_at_unix: slot,
            fired_at_unix: now,
            node_id: Some(self.cluster_identity_node_id()),
            outcome,
            dispatch_id,
            run_id: None,
            detail: detail.map(str::to_string),
        };
        if let Err(error) = self.repositories.insert_agent_schedule_fire(fire).await {
            warn!(
                schedule_id = %schedule.schedule_id,
                error = %error,
                "scheduler: failed to record schedule fire"
            );
        }
    }

    /// Advance `next_fire_at` to the first slot strictly after `now`, stamping
    /// `last_fire_at = slot`. On-time firing loops zero times (the next slot is
    /// already in the future); catch-up fast-forwards past every elapsed slot,
    /// bounded by [`SCHEDULER_CATCHUP_ITER_CAP`].
    async fn advance_schedule_past_now(&self, schedule: &StoredAgentSchedule, slot: i64, now: i64) {
        let mut updated = schedule.clone();
        updated.last_fire_at_unix = Some(slot);
        updated.updated_at_unix = now;

        // Walk forward from the fired slot. On-time firing converges in a single
        // step (the next slot is already in the future). A short catch-up takes a
        // few steps. If a long outage exceeds [`SCHEDULER_CATCHUP_ITER_CAP`], stop
        // stepping and jump straight to the first slot strictly after `now`
        // (`compute_next_fire_at(now)`) so fast-forward is bounded regardless of
        // how far behind the schedule is -- iterating slot-by-slot from a
        // far-past anchor could otherwise need millions of steps for a
        // short-interval or every-minute cron schedule.
        let mut cursor = slot;
        let mut next_fire = None;
        let mut converged = false;
        for _ in 0..SCHEDULER_CATCHUP_ITER_CAP {
            match updated.compute_next_fire_at(cursor) {
                Ok(Some(candidate)) => {
                    if candidate > now {
                        next_fire = Some(candidate);
                        converged = true;
                        break;
                    }
                    cursor = candidate;
                }
                Ok(None) => {
                    // Invalid interval -> stop firing.
                    converged = true;
                    break;
                }
                Err(error) => {
                    warn!(
                        schedule_id = %schedule.schedule_id,
                        error = %error,
                        "scheduler: failed to compute next fire; leaving schedule unscheduled"
                    );
                    converged = true;
                    break;
                }
            }
        }
        if !converged {
            // The bounded walk did not reach a future slot; jump directly.
            match updated.compute_next_fire_at(now) {
                Ok(candidate) => next_fire = candidate,
                Err(error) => {
                    warn!(
                        schedule_id = %schedule.schedule_id,
                        error = %error,
                        "scheduler: failed to jump next fire past now; leaving schedule unscheduled"
                    );
                }
            }
        }
        updated.next_fire_at_unix = next_fire;

        if let Err(error) = self.repositories.upsert_agent_schedule(updated).await {
            warn!(
                schedule_id = %schedule.schedule_id,
                error = %error,
                "scheduler: failed to advance schedule next-fire"
            );
        }
    }

    fn cluster_identity_node_id(&self) -> String {
        self.cluster_status().node_id
    }

    /// Enqueue a schedule-originated dispatch into the self-hosted lease queue
    /// and write it through to durable storage, mirroring the poll/ack handlers.
    /// Idempotent on the dispatch id.
    pub(crate) fn enqueue_scheduled_self_hosted_dispatch(
        &self,
        dispatch: SelfHostedRunDispatch,
    ) -> Result<(), SelfHostedWorkerError> {
        let records = match self.self_hosted_dispatch.lock() {
            Ok(mut runtime) => {
                runtime.enqueue_scheduled_dispatch(dispatch)?;
                runtime.storage_records()
            }
            Err(poisoned) => {
                let mut runtime = poisoned.into_inner();
                runtime.enqueue_scheduled_dispatch(dispatch)?;
                runtime.storage_records()
            }
        };
        persist_self_hosted_dispatch_records(&self.repositories, records)
    }

    /// Whether `dispatch_id` is still queued and unacknowledged.
    pub(crate) fn self_hosted_dispatch_unacked(&self, dispatch_id: &str) -> bool {
        match self.self_hosted_dispatch.lock() {
            Ok(runtime) => runtime.dispatch_unacked(dispatch_id),
            Err(poisoned) => poisoned.into_inner().dispatch_unacked(dispatch_id),
        }
    }
}

/// Build a `StartRun` dispatch from a schedule's `target_json`. All fields have
/// sensible defaults so a minimal `{}` target still produces a valid dispatch
/// (validated by the lease queue). Recognized keys: `framework_adapter`,
/// `required_capabilities` (array), `workload_ref`, `session_id`.
fn build_self_hosted_dispatch(
    schedule: &StoredAgentSchedule,
    slot: i64,
    now: i64,
) -> Result<SelfHostedRunDispatch, String> {
    let target: serde_json::Value = serde_json::from_str(&schedule.target_json)
        .map_err(|error| format!("target_json is not valid JSON: {error}"))?;

    let framework_adapter = target
        .get("framework_adapter")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("native-harness")
        .to_string();

    let required_capabilities = target
        .get("required_capabilities")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|caps| !caps.is_empty())
        .unwrap_or_else(|| vec!["shell".to_string()]);

    let workload_ref = target
        .get("workload_ref")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("self-hosted-workload://{}", schedule.schedule_id));

    let session_id = target
        .get("session_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("schedule-session-{}", schedule.schedule_id));

    Ok(SelfHostedRunDispatch {
        dispatch_id: scheduled_dispatch_id(&schedule.schedule_id, slot),
        action: SelfHostedRunAction::StartRun,
        tenant_id: schedule.tenant_id.clone(),
        workspace_id: schedule.workspace_id.clone(),
        session_id,
        run_id: format!("schedule-run-{}-{slot}", schedule.schedule_id),
        framework_adapter,
        required_capabilities,
        workload_ref,
        // `now`, not `slot`: the queue rejects queued_at_unix == 0, and a
        // catch-up slot could in principle be 0 for a misconfigured schedule.
        queued_at_unix: now.max(1) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_storage::{ScheduleSpecKind, ScheduleTargetKind, StoredAgentSchedule};

    fn scheduler_enabled_config() -> Config {
        let mut config = Config::default();
        config.scheduler.enabled = true;
        config
    }

    fn interval_schedule(schedule_id: &str, next_fire_at_unix: i64) -> StoredAgentSchedule {
        StoredAgentSchedule {
            schedule_id: schedule_id.into(),
            tenant_id: "tenant-a".into(),
            workspace_id: "ws-a".into(),
            name: "nightly".into(),
            enabled: true,
            spec_kind: ScheduleSpecKind::Interval,
            cron_expr: None,
            timezone: "UTC".into(),
            interval_secs: Some(60),
            target_kind: ScheduleTargetKind::SelfHostedDispatch,
            target_json: "{\"required_capabilities\":[\"shell\"]}".into(),
            overlap_policy: OverlapPolicy::Skip,
            catchup_policy: CatchupPolicy::SkipMissed,
            jitter_secs: 0,
            next_fire_at_unix: Some(next_fire_at_unix),
            last_fire_at_unix: None,
            created_at_unix: 1,
            updated_at_unix: 1,
            revision: 1,
        }
    }

    #[test]
    fn disabled_scheduler_is_a_no_op() {
        let state = AppState::new(Config::default()); // scheduler.enabled = false
                                                      // A due schedule exists, but a disabled sweeper must not touch it.
        crate::gateway::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("s1", 1)),
        )
        .expect("seed schedule");
        crate::gateway::block_on_sync_bridge(state.sweep_agent_schedules_once());
        let fires = crate::gateway::block_on_sync_bridge(
            state.repositories.list_agent_schedule_fires("s1", 10),
        )
        .expect("list fires");
        assert!(fires.is_empty(), "disabled scheduler records no fires");
    }

    #[test]
    fn due_schedule_fires_a_dispatch_and_records_history() {
        let state = AppState::new(scheduler_enabled_config());
        // Seed a slot that is due right now (not a stale missed slot): the next
        // slot after it is still in the future, so skip_missed treats this as an
        // on-time fire rather than a catch-up.
        let now = now_unix_seconds().unwrap_or_default() as i64;
        crate::gateway::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("s1", now)),
        )
        .expect("seed schedule");

        crate::gateway::block_on_sync_bridge(state.sweep_agent_schedules_once());

        // Exactly one fire recorded, marked dispatched, with a linked dispatch.
        let fires = crate::gateway::block_on_sync_bridge(
            state.repositories.list_agent_schedule_fires("s1", 10),
        )
        .expect("list fires");
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].outcome, ScheduleFireOutcome::Dispatched);
        let dispatch_id = fires[0].dispatch_id.clone().expect("dispatch linked");
        assert_eq!(dispatch_id, format!("schedule-dispatch-s1-{now}"));
        // The dispatch is enqueued and unacked (in flight).
        assert!(state.self_hosted_dispatch_unacked(&dispatch_id));

        // next_fire advanced strictly past now; a second immediate tick does not
        // double-fire the same slot.
        crate::gateway::block_on_sync_bridge(state.sweep_agent_schedules_once());
        let fires = crate::gateway::block_on_sync_bridge(
            state.repositories.list_agent_schedule_fires("s1", 10),
        )
        .expect("list fires");
        let slot_fires = fires
            .iter()
            .filter(|fire| fire.scheduled_fire_at_unix == now)
            .count();
        assert_eq!(slot_fires, 1, "the due slot fires at most once");
    }

    #[test]
    fn advance_fast_forwards_past_now_on_catchup() {
        let state = AppState::new(scheduler_enabled_config());
        // A schedule whose next fire is far in the past (interval 60s) with the
        // default skip_missed policy must NOT fire the stale slot and must
        // fast-forward next_fire to a future slot.
        crate::gateway::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("stale", 1)),
        )
        .expect("seed schedule");

        crate::gateway::block_on_sync_bridge(state.sweep_agent_schedules_once());

        let fires = crate::gateway::block_on_sync_bridge(
            state.repositories.list_agent_schedule_fires("stale", 10),
        )
        .expect("list fires");
        assert!(
            fires.is_empty(),
            "skip_missed does not fire missed slots on catch-up"
        );
        let schedule =
            crate::gateway::block_on_sync_bridge(state.repositories.get_agent_schedule("stale"))
                .expect("get")
                .expect("schedule present");
        let now = now_unix_seconds().unwrap_or_default() as i64;
        assert!(
            schedule.next_fire_at_unix.is_some_and(|next| next > now),
            "next_fire fast-forwarded strictly past now",
        );
    }
}
