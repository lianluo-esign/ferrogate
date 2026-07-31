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
pub(crate) fn scheduled_dispatch_id(schedule_id: &str, slot: i64) -> String {
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
                        ScheduleFireResult::skipped_overlap("previous dispatch still in flight"),
                    )
                    .await;
                    self.advance_schedule_past_now(schedule, slot, now).await;
                    return;
                }
            }
        }

        // Execute the schedule's target action (enqueue a self-hosted dispatch
        // or create an agent run), then claim the fire slot idempotently and
        // advance regardless of the action's outcome so a failing target still
        // fast-forwards past the slot instead of re-firing it every tick.
        // A background tick has no dispatching request — no correlation
        // context is fabricated for it (#305).
        let result = self
            .dispatch_schedule_target(schedule, slot, now, None)
            .await;
        self.record_fire(schedule, slot, now, result).await;
        self.advance_schedule_past_now(schedule, slot, now).await;
    }

    /// Execute a schedule's target action for one `(schedule, slot)` fire and
    /// report what happened, WITHOUT recording the fire or advancing the
    /// schedule (the caller owns those). Shared by the tick loop
    /// ([`Self::fire_due_schedule`]) and the manual `run-now` admin trigger
    /// ([`Self::run_agent_schedule_now`]) so both target kinds behave
    /// identically on either path.
    async fn dispatch_schedule_target(
        &self,
        schedule: &StoredAgentSchedule,
        slot: i64,
        now: i64,
        correlation: Option<&ScheduleFireCorrelation<'_>>,
    ) -> ScheduleFireResult {
        if let Err(error) = self
            .repositories
            .require_usable_tenancy(
                ferrogate_storage::LifecycleSeam::Request,
                ferrogate_storage::TenancyRefs::new(
                    Some(&schedule.tenant_id),
                    None,
                    Some(&schedule.workspace_id),
                ),
            )
            .await
        {
            let code = error.code();
            let message = error.message();
            warn!(
                schedule_id = %schedule.schedule_id,
                lifecycle_code = code,
                lifecycle_message = %message,
                "scheduler: refused agent schedule fire because tenancy lifecycle is inactive"
            );
            return ScheduleFireResult::error(format!("{code}: {message}"));
        }

        // #428 run admission for the scheduled-dispatch path. A runaway cron is
        // precisely the workload a spend cap exists to bound, and it was the one
        // run-start path with no budget consultation at all -- an over-budget
        // tenant refused at `POST /v1/agent-runs` and `POST /v1/agent-jobs`
        // could still burn without limit through a schedule that fires every
        // minute.
        //
        // Placed after the tenancy-lifecycle gate and before EITHER target kind
        // is acted on, so it covers the self-hosted dispatch and the direct
        // agent-run record equally, on both the tick loop and the admin
        // `run-now` trigger (both reach the target through this one function).
        //
        // A refusal is a fire OUTCOME, not an error the caller retries: the slot
        // is still recorded and the schedule still advances, so a budget-blocked
        // schedule leaves an auditable fire-history row per slot and resumes on
        // its own cadence once the period rolls over or the ceiling is raised --
        // rather than silently skipping or backing up a catch-up queue.
        //
        // The schedule carries no api-key identity, so it names itself with
        // `UNATTRIBUTED_AGENT_KEY` in the refusal log and audit attribution.
        // That label does NOT decide the verdict: `admit_agent_run` evaluates
        // the ceiling against the tenant's TOTAL agent burn for the period (the
        // sum of every per-agent row), so a cron is bounded by the spend its
        // tenant's api-keyed agents settled, not only by burn recorded under
        // this one keyless label -- which was zero on every deployment that uses
        // api keys.
        let tenant = ferrogate_core::TenantContext {
            organization_id: Some(schedule.tenant_id.clone()),
            workspace_id: Some(schedule.workspace_id.clone()),
            ..Default::default()
        };
        let run_id = format!("schedule-run-{}-{slot}", schedule.schedule_id);
        match self
            .admit_agent_run(&tenant, UNATTRIBUTED_AGENT_KEY, &run_id)
            .await
        {
            AgentRunAdmission::Unbudgeted | AgentRunAdmission::Admitted { .. } => {}
            AgentRunAdmission::Refused { code, message, .. } => {
                warn!(
                    schedule_id = %schedule.schedule_id,
                    slot,
                    code,
                    message = %message,
                    "scheduler: refused agent schedule fire because the agent cost budget \
                     halts new dispatch"
                );
                return ScheduleFireResult::error(format!("{code}: {message}"));
            }
        }

        match schedule.target_kind {
            ScheduleTargetKind::SelfHostedDispatch => {
                let dispatch = match build_self_hosted_dispatch(schedule, slot, now, correlation) {
                    Ok(dispatch) => dispatch,
                    Err(message) => return ScheduleFireResult::error(message),
                };
                let dispatch_id = dispatch.dispatch_id.clone();
                // Enqueue FIRST (idempotent on the deterministic id), then the
                // caller claims the fire slot. If a peer instance already
                // enqueued the same dispatch it is deduped; if a peer already
                // claimed the fire row, that claim loses -- either way the slot
                // yields exactly one dispatch.
                if let Err(error) = self.enqueue_scheduled_self_hosted_dispatch(dispatch) {
                    warn!(
                        schedule_id = %schedule.schedule_id,
                        error = %error,
                        "scheduler: failed to enqueue self-hosted dispatch"
                    );
                    return ScheduleFireResult::error(error.to_string());
                }
                ScheduleFireResult::dispatched_run(None, Some(dispatch_id))
            }
            ScheduleTargetKind::AgentRun => {
                // Create an agent-run record through the same durable seam the
                // synchronous `POST /v1/agent-runs` create path uses
                // (`record_agent_run` -> `repositories.upsert_agent_run`). The
                // scheduler is a control-plane trigger, so it registers the run
                // (status `running`) and records the linked run id; the managed
                // runtime drives the run to completion out of band.
                let run = build_scheduled_agent_run(schedule, slot, now, &self.config, correlation);
                let run_id = run.id.clone();
                if let Err(error) = self.repositories.upsert_agent_run(run).await {
                    warn!(
                        schedule_id = %schedule.schedule_id,
                        error = %error,
                        "scheduler: failed to create scheduled agent run"
                    );
                    return ScheduleFireResult::error(error.to_string());
                }
                ScheduleFireResult::dispatched_run(Some(run_id), None)
            }
        }
    }

    /// Manual `run-now` trigger for the admin API (#251). Executes the
    /// schedule's target immediately -- regardless of `enabled`, next-fire, or
    /// catch-up/overlap policy -- and records a dedicated fire-history row so
    /// the manual trigger is observable. Does NOT advance `next_fire_at`: a
    /// manual run is an ad-hoc extra fire, not a replacement for the schedule's
    /// own cadence.
    pub(crate) async fn run_agent_schedule_now(
        &self,
        schedule: &StoredAgentSchedule,
        correlation: Option<&ScheduleFireCorrelation<'_>>,
    ) -> Result<StoredAgentScheduleFire, StorageError> {
        let now = now_unix_seconds().unwrap_or_default() as i64;
        let result = self
            .dispatch_schedule_target(schedule, now, now, correlation)
            .await;
        let fire = StoredAgentScheduleFire {
            // A `manual:` prefix keeps a run-now fire id distinct from the
            // scheduler's deterministic per-slot id for the same second.
            fire_id: format!(
                "manual:{}",
                agent_schedule_fire_id(&schedule.schedule_id, now)
            ),
            schedule_id: schedule.schedule_id.clone(),
            scheduled_fire_at_unix: now,
            fired_at_unix: now,
            node_id: Some(self.cluster_identity_node_id()),
            outcome: result.outcome,
            dispatch_id: result.dispatch_id,
            run_id: result.run_id,
            detail: Some(
                result
                    .detail
                    .unwrap_or_else(|| "manual run-now trigger".to_string()),
            ),
        };
        // Best-effort ledger write: a UNIQUE collision with a scheduled fire
        // for the same second is harmless (the target action already ran); the
        // caller still gets the fire record it should report.
        self.repositories
            .insert_agent_schedule_fire(fire.clone())
            .await?;
        Ok(fire)
    }

    /// Idempotently record a fire-history row for `(schedule, slot)`. The insert
    /// is the at-most-once gate: a peer that already recorded the slot makes
    /// this a no-op.
    async fn record_fire(
        &self,
        schedule: &StoredAgentSchedule,
        slot: i64,
        now: i64,
        result: ScheduleFireResult,
    ) {
        let fire = StoredAgentScheduleFire {
            fire_id: agent_schedule_fire_id(&schedule.schedule_id, slot),
            schedule_id: schedule.schedule_id.clone(),
            scheduled_fire_at_unix: slot,
            fired_at_unix: now,
            node_id: Some(self.cluster_identity_node_id()),
            outcome: result.outcome,
            dispatch_id: result.dispatch_id,
            run_id: result.run_id,
            detail: result.detail,
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

    // --- Admin API surface (#251). Thin async wrappers over the durable
    // agent-schedule repositories so the gateway handlers (which cannot reach
    // the private `repositories` field) drive CRUD + fire history without a
    // config reload -- schedules are pure control-plane storage, not config. ---

    pub(crate) async fn admin_list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.repositories
            .list_agent_schedules(tenant_id, workspace_id)
            .await
    }

    pub(crate) async fn admin_list_all_agent_schedules(
        &self,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.repositories.list_all_agent_schedules().await
    }

    pub(crate) async fn admin_get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        self.repositories.get_agent_schedule(schedule_id).await
    }

    pub(crate) async fn admin_upsert_agent_schedule(
        &self,
        schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        self.repositories.upsert_agent_schedule(schedule).await
    }

    pub(crate) async fn admin_delete_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<bool, StorageError> {
        self.repositories.delete_agent_schedule(schedule_id).await
    }

    pub(crate) async fn admin_list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        self.repositories
            .list_agent_schedule_fires(schedule_id, limit)
            .await
    }

    /// Enqueue a schedule-originated dispatch into the self-hosted lease queue
    /// and write it through to durable storage, mirroring the poll/ack handlers.
    /// Idempotent on the dispatch id.
    ///
    /// #474 (rework): only the dispatch this call created is written through,
    /// not the whole queue. `storage_records()` snapshots EVERY queued dispatch,
    /// so persisting it made each enqueue an O(queue) burst of synchronous
    /// upserts paid inside the request -- and `/v1/agent-jobs` is the first
    /// surface that lets an ordinary tenant API key drive that at will. Enqueue
    /// mutates exactly one record (it is an insert, idempotent on the dispatch
    /// id), so writing that one record through is the same durable state at
    /// O(1) cost per submit.
    pub(crate) fn enqueue_scheduled_self_hosted_dispatch(
        &self,
        dispatch: SelfHostedRunDispatch,
    ) -> Result<(), SelfHostedWorkerError> {
        let dispatch_id = dispatch.dispatch_id.clone();
        let records = match self.self_hosted_dispatch.lock() {
            Ok(mut runtime) => {
                runtime.enqueue_scheduled_dispatch(dispatch)?;
                runtime.storage_records_for(&dispatch_id)
            }
            Err(poisoned) => {
                let mut runtime = poisoned.into_inner();
                runtime.enqueue_scheduled_dispatch(dispatch)?;
                runtime.storage_records_for(&dispatch_id)
            }
        };
        persist_self_hosted_dispatch_records(&self.repositories, records)
    }

    /// Run ids of the tenant's unacknowledged submit-surface start dispatches,
    /// projected out under the queue lock rather than deep-cloning every record
    /// of every tenant on every submit (#502 rework: the read side of the cap
    /// was O(total dispatches) with a deep clone, on the request path, holding
    /// the lock every worker poll and ack shares).
    fn unacked_start_run_ids(&self, tenant_id: &str, dispatch_id_prefix: &str) -> Vec<String> {
        match self.self_hosted_dispatch.lock() {
            Ok(runtime) => runtime
                .queue
                .unacked_start_run_ids(tenant_id, dispatch_id_prefix),
            Err(poisoned) => poisoned
                .into_inner()
                .queue
                .unacked_start_run_ids(tenant_id, dispatch_id_prefix),
        }
    }

    /// Admit ONE caller-submitted start dispatch against the tenant's open-job
    /// budget and enqueue it in the SAME critical section.
    ///
    /// #474 (rework) introduced the budget so an ordinary tenant API key could
    /// not drive the shared dispatch queue without bound. A dispatch counts
    /// against it when ALL of these hold:
    ///
    /// * it belongs to `tenant_id` -- one tenant's backlog never throttles
    ///   another's submits;
    /// * it is UNACKNOWLEDGED -- a tenant whose runtime keeps settling its work
    ///   is never throttled;
    /// * its dispatch id starts with `dispatch_id_prefix`, i.e. the SUBMIT
    ///   surface minted it. Schedule fires (#426) and worker-registration seeds
    ///   enqueue `start_run` dispatches into the same queue, and background work
    ///   the caller never asked for must not silently eat the caller's budget;
    /// * its RUN HAS NOT SETTLED. This is the release condition, and #502 makes
    ///   it the run row rather than the dispatch: the production completion path
    ///   is worker telemetry ([`AppState::apply_worker_reported_run_state`]),
    ///   which terminalizes `agent_runs.status` and never writes
    ///   `acknowledged_status`, so keying the release on the ack locked a tenant
    ///   with a perfectly HEALTHY worker out of the surface after `max_open`
    ///   finished jobs. Cancel terminalizes the same row, so every remedy the
    ///   refusal names releases through one rule.
    ///
    /// The settled read is DURABLE and batched
    /// ([`AppState::settled_agent_run_ids`]), which is what makes the release
    /// cluster-wide: a job finished or cancelled through a PEER replica stops
    /// counting here even though this node still holds its start dispatch in
    /// memory. Only the opposite direction stays node-local -- this node cannot
    /// see a peer's still-OPEN dispatches -- so with N replicas the effective
    /// cap is at most N x the caller's cap. That over-permissive residue is a
    /// deliberately retained limitation (a cluster-wide OPEN count needs a
    /// durable aggregate the control-plane store does not expose); the refusal
    /// text promises only releases that always work.
    ///
    /// Gate and enqueue are ONE operation because #502's first cut left them
    /// check-then-act: the count took the queue lock, released it, and the
    /// enqueue took a fresh one ~50 lines later, so K concurrent submits at
    /// `max_open - 1` all read "below the cap" and all landed. Recounting under
    /// the guard that performs the insert makes the per-node cap an invariant
    /// instead of an observation.
    ///
    /// The durable settled-run read is deliberately taken BEFORE the guard: it
    /// is blocking I/O and the queue lock is shared with every worker poll and
    /// ack. A run that settles inside that window is simply counted as open,
    /// which can refuse one submit that would have been admitted -- conservative
    /// in the safe direction, never over-admitting.
    pub(crate) fn admit_and_enqueue_agent_job_dispatch(
        &self,
        tenant_id: &str,
        dispatch_id_prefix: &str,
        max_open: usize,
        dispatch: SelfHostedRunDispatch,
    ) -> AgentJobDispatchAdmission {
        let candidates = self.unacked_start_run_ids(tenant_id, dispatch_id_prefix);
        let settled = self.settled_agent_run_ids(&candidates);
        let dispatch_id = dispatch.dispatch_id.clone();
        let mut runtime = match self.self_hosted_dispatch.lock() {
            Ok(runtime) => runtime,
            Err(poisoned) => poisoned.into_inner(),
        };
        let open = runtime
            .queue
            .unacked_start_run_ids(tenant_id, dispatch_id_prefix)
            .into_iter()
            .filter(|run_id| !settled.contains(run_id.as_str()))
            .count();
        if open >= max_open {
            return AgentJobDispatchAdmission::OverBudget { open };
        }
        if let Err(error) = runtime.enqueue_scheduled_dispatch(dispatch) {
            return AgentJobDispatchAdmission::TransportRefused(error);
        }
        let records = runtime.storage_records_for(&dispatch_id);
        drop(runtime);
        match persist_self_hosted_dispatch_records(&self.repositories, records) {
            Ok(()) => AgentJobDispatchAdmission::Enqueued,
            Err(error) => AgentJobDispatchAdmission::TransportRefused(error),
        }
    }

    /// Whether `dispatch_id` is still queued and unacknowledged.
    pub(crate) fn self_hosted_dispatch_unacked(&self, dispatch_id: &str) -> bool {
        match self.self_hosted_dispatch.lock() {
            Ok(runtime) => runtime.dispatch_unacked(dispatch_id),
            Err(poisoned) => poisoned.into_inner().dispatch_unacked(dispatch_id),
        }
    }
}

/// The outcome of [`AppState::admit_and_enqueue_agent_job_dispatch`] (#502).
///
/// Three states, not a `Result<(), E>`: "refused by the budget" and "the
/// transport would not take it" are different answers to the caller (429 vs
/// 503) and must not collapse into one error string.
#[derive(Debug)]
pub(crate) enum AgentJobDispatchAdmission {
    /// Admitted: the dispatch is in the queue and its durable row is written.
    Enqueued,
    /// Refused by the per-tenant open-job budget, which held `open` jobs.
    OverBudget { open: usize },
    /// The lease queue or its durable store rejected the dispatch.
    TransportRefused(SelfHostedWorkerError),
}

/// The result of executing a schedule's target action for one fire, before it
/// is committed to the fire-history ledger. Exactly one of `dispatch_id` /
/// `run_id` is set on success (per target kind); `detail` carries the failure
/// reason on an error outcome.
struct ScheduleFireResult {
    outcome: ScheduleFireOutcome,
    dispatch_id: Option<String>,
    run_id: Option<String>,
    detail: Option<String>,
}

impl ScheduleFireResult {
    fn dispatched_run(run_id: Option<String>, dispatch_id: Option<String>) -> Self {
        Self {
            outcome: ScheduleFireOutcome::Dispatched,
            dispatch_id,
            run_id,
            detail: None,
        }
    }

    fn error(detail: impl Into<String>) -> Self {
        Self {
            outcome: ScheduleFireOutcome::Error,
            dispatch_id: None,
            run_id: None,
            detail: Some(detail.into()),
        }
    }

    fn skipped_overlap(detail: impl Into<String>) -> Self {
        Self {
            outcome: ScheduleFireOutcome::SkippedOverlap,
            dispatch_id: None,
            run_id: None,
            detail: Some(detail.into()),
        }
    }
}

/// The provider label recorded on a scheduled agent run, mirroring the
/// synchronous create path's `agent_provider_name` so scheduled and
/// interactively-created runs are attributed to the same provider.
fn scheduled_agent_run_provider(config: &Config) -> &'static str {
    match config.agent_runtime.provider {
        ferrogate_config::AgentRuntimeProvider::ManagedWorker => "ferrogate.agent-worker",
        ferrogate_config::AgentRuntimeProvider::External => "ferrogate.external",
    }
}

/// Build the `StoredAgentRun` a schedule creates when it fires an `agent_run`
/// target. The run id is deterministic per `(schedule, slot)` so a peer
/// instance racing the same slot upserts the SAME row rather than creating a
/// duplicate run.
/// #305: correlation context of the request that manually triggered a schedule
/// fire (the admin `run-now` endpoint). Background tick fires pass `None` — a
/// tick has no dispatching request, so nothing is fabricated for it.
pub(crate) struct ScheduleFireCorrelation<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) trace_id: Option<&'a str>,
}

fn build_scheduled_agent_run(
    schedule: &StoredAgentSchedule,
    slot: i64,
    now: i64,
    config: &Config,
    correlation: Option<&ScheduleFireCorrelation<'_>>,
) -> StoredAgentRun {
    let run_id = format!("schedule-run-{}-{slot}", schedule.schedule_id);
    StoredAgentRun {
        id: run_id.clone(),
        // #305: a manual run-now fire records the triggering admin request's
        // real ids; a tick fire keeps the deterministic `schedule:` request id
        // it always had (and no trace — none exists).
        request_id: correlation
            .map(|correlation| correlation.request_id.to_string())
            .unwrap_or_else(|| format!("schedule:{}:{slot}", schedule.schedule_id)),
        trace_id: correlation.and_then(|correlation| correlation.trace_id.map(str::to_string)),
        tenant: ferrogate_core::TenantContext {
            organization_id: Some(schedule.tenant_id.clone()),
            workspace_id: Some(schedule.workspace_id.clone()),
            ..Default::default()
        },
        status: "running".to_string(),
        provider: scheduled_agent_run_provider(config).to_string(),
        turns_executed: 0,
        output_recorded: false,
        started_at_unix: Some(now.max(0) as u64),
        completed_at_unix: None,
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
    correlation: Option<&ScheduleFireCorrelation<'_>>,
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

    let run_id = format!("schedule-run-{}-{slot}", schedule.schedule_id);
    Ok(SelfHostedRunDispatch {
        dispatch_id: scheduled_dispatch_id(&schedule.schedule_id, slot),
        action: SelfHostedRunAction::StartRun,
        tenant_id: schedule.tenant_id.clone(),
        workspace_id: schedule.workspace_id.clone(),
        session_id,
        run_id: run_id.clone(),
        framework_adapter,
        required_capabilities,
        workload_ref,
        // `now`, not `slot`: the queue rejects queued_at_unix == 0, and a
        // catch-up slot could in principle be 0 for a misconfigured schedule.
        queued_at_unix: now.max(1) as u64,
        // #305: a manual run-now fire carries the triggering admin request's
        // ids; a background tick fire carries None (nothing is fabricated).
        // The agent run this dispatch starts is its own run_id, recorded
        // explicitly so dispatch leases join run evidence uniformly.
        request_id: correlation.map(|correlation| correlation.request_id.to_string()),
        trace_id: correlation.and_then(|correlation| correlation.trace_id.map(str::to_string)),
        agent_run_id: Some(run_id),
        // #307: neither a schedule tick nor the admin run-now trigger is a
        // governed ACTION — there is no upstream action fingerprint to
        // inherit, so the parent stays an explicit None (never fabricated).
        // The field flows end-to-end (dispatch → durable row → worker lease)
        // for the day a governed seam enqueues dispatches.
        parent_action_fingerprint: None,
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
        ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("s1", 1)),
        )
        .expect("seed schedule");
        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());
        let fires = ferrogate_sync_bridge::block_on_sync_bridge(
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
        ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("s1", now)),
        )
        .expect("seed schedule");

        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());

        // Exactly one fire recorded, marked dispatched, with a linked dispatch.
        let fires = ferrogate_sync_bridge::block_on_sync_bridge(
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
        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());
        let fires = ferrogate_sync_bridge::block_on_sync_bridge(
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
    fn agent_run_target_creates_a_run_and_records_dispatched() {
        let state = AppState::new(scheduler_enabled_config());
        let now = now_unix_seconds().unwrap_or_default() as i64;
        let mut schedule = interval_schedule("run-sched", now);
        schedule.target_kind = ScheduleTargetKind::AgentRun;
        schedule.target_json = "{}".into();
        ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.upsert_agent_schedule(schedule),
        )
        .expect("seed schedule");

        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());

        // The fire is recorded as dispatched and linked to a created run id (not
        // a self-hosted dispatch id).
        let fires = ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .list_agent_schedule_fires("run-sched", 10),
        )
        .expect("list fires");
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].outcome, ScheduleFireOutcome::Dispatched);
        assert!(
            fires[0].dispatch_id.is_none(),
            "agent_run records no dispatch"
        );
        let run_id = fires[0].run_id.clone().expect("run id linked");
        assert_eq!(run_id, format!("schedule-run-run-sched-{now}"));

        // The agent run was created through the shared record_agent_run seam.
        let run = state.agent_run_record(&run_id).expect("run persisted");
        assert_eq!(run.status, "running");
        assert_eq!(run.tenant.organization_id.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn run_now_triggers_immediately_and_records_a_manual_fire() {
        let state = AppState::new(scheduler_enabled_config());
        // A far-future next_fire so the tick loop would never fire it; run-now
        // must trigger regardless.
        let schedule = interval_schedule("manual-sched", i64::MAX / 2);
        ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.upsert_agent_schedule(schedule.clone()),
        )
        .expect("seed schedule");

        let fire = ferrogate_sync_bridge::block_on_sync_bridge(state.run_agent_schedule_now(
            &schedule,
            Some(&ScheduleFireCorrelation {
                request_id: "fg-run-now-1",
                trace_id: Some("trace-run-now-1"),
            }),
        ))
        .expect("run-now succeeds");
        assert_eq!(fire.outcome, ScheduleFireOutcome::Dispatched);
        assert!(
            fire.fire_id.starts_with("manual:"),
            "run-now fire id is namespaced: {}",
            fire.fire_id
        );
        let dispatch_id = fire.dispatch_id.clone().expect("dispatch linked");
        assert!(state.self_hosted_dispatch_unacked(&dispatch_id));

        // #305: the durable dispatch row carries the manual trigger's
        // {request_id, trace_id} and the agent run it starts, so the lease
        // joins timeline/audit/approval evidence on the same triple.
        let dispatches = ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.self_hosted_run_dispatches(),
        );
        let dispatch = dispatches
            .iter()
            .find(|dispatch| dispatch.dispatch_id == dispatch_id)
            .expect("dispatch persisted durably");
        assert_eq!(dispatch.request_id.as_deref(), Some("fg-run-now-1"));
        assert_eq!(dispatch.trace_id.as_deref(), Some("trace-run-now-1"));
        assert_eq!(
            dispatch.agent_run_id.as_deref(),
            Some(dispatch.run_id.as_str()),
            "the dispatch's agent run correlation is the run it starts"
        );
        // #307: run-now is an admin trigger, not a governed action — the
        // parent stays an explicit NULL (never fabricated).
        assert_eq!(dispatch.parent_action_fingerprint, None);
    }

    /// #305: a background tick fire has no dispatching request — the dispatch
    /// row must carry None for request/trace (nothing fabricated) while still
    /// recording the agent run it starts.
    #[test]
    fn tick_fired_dispatch_carries_no_fabricated_request_context() {
        let state = AppState::new(scheduler_enabled_config());
        let now = now_unix_seconds().unwrap_or_default() as i64;
        ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("tick-corr", now - 1)),
        )
        .expect("seed schedule");

        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());

        let dispatches = ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.self_hosted_run_dispatches(),
        );
        let dispatch = dispatches
            .iter()
            .find(|dispatch| {
                dispatch
                    .dispatch_id
                    .starts_with("schedule-dispatch-tick-corr-")
            })
            .expect("tick fire enqueued a dispatch");
        assert_eq!(dispatch.request_id, None);
        assert_eq!(dispatch.trace_id, None);
        assert_eq!(
            dispatch.agent_run_id.as_deref(),
            Some(dispatch.run_id.as_str())
        );
        // #307: a tick fire has no governed-action parent either.
        assert_eq!(dispatch.parent_action_fingerprint, None);
    }

    /// #428: a runaway cron is exactly the workload a spend cap exists to
    /// bound, and the scheduled-dispatch path had no budget consultation at
    /// all. An over-budget tenant's schedule must enqueue NOTHING.
    #[test]
    fn an_over_budget_tenant_fires_no_scheduled_dispatch() {
        let state = AppState::new(scheduler_enabled_config());
        let now = now_unix_seconds().unwrap_or_default() as i64;
        // A 100 USD ceiling on the schedule's own tenant, already burnt past the
        // 0.8 warn threshold by prior spend recorded through the metering path.
        ferrogate_sync_bridge::block_on_sync_bridge(state.upsert_quota_policy(
            crate::state::StoredQuotaPolicy {
                id: "tenant:tenant-a".into(),
                scope_type: crate::state::QuotaScopeKind::Tenant,
                scope_id: "tenant-a".into(),
                model_allowlist: vec![],
                rpm_limit: None,
                tpm_limit: None,
                monthly_budget_usd: None,
                asset_storage_quota_bytes: None,
                asset_max_object_bytes: None,
                agent_cost_budget_usd: Some(100.0),
                alert_threshold_pcts: vec![],
                monthly_egress_bytes_budget: None,
                download_rpm_limit: None,
                enabled: true,
                created_at_unix: 1,
                updated_at_unix: 1,
            },
        ))
        .expect("seed tenant quota policy");
        ferrogate_sync_bridge::block_on_sync_bridge(state.repositories.add_agent_burn(
            "tenant-a",
            UNATTRIBUTED_AGENT_KEY,
            &state.current_period_month(),
            100.0,
        ))
        .expect("seed durable agent burn");
        ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("over-budget", now - 1)),
        )
        .expect("seed schedule");

        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());

        let dispatches = ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.self_hosted_run_dispatches(),
        );
        assert!(
            !dispatches.iter().any(|dispatch| dispatch
                .dispatch_id
                .starts_with("schedule-dispatch-over-budget-")),
            "an over-budget tenant's schedule must enqueue no dispatch, got {dispatches:?}",
        );
        // The refusal is a recorded fire OUTCOME, not a silent skip: the slot is
        // claimed and auditable, so an operator can see WHY the cron stopped
        // producing work rather than watching it vanish.
        let fires = ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .list_agent_schedule_fires("over-budget", 10),
        )
        .expect("list fires");
        assert!(
            fires.iter().any(|fire| fire
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("agent_budget_exceeded"))),
            "the budget refusal must be visible in the fire history, got {fires:?}",
        );
    }

    /// The same schedule, on a tenant with NO configured agent budget, must be
    /// byte-identical to the pre-#428 path: the gate resolves to `Unbudgeted`
    /// without a ledger read and the dispatch is enqueued as before.
    #[test]
    fn an_unbudgeted_tenants_schedule_fires_exactly_as_before() {
        let state = AppState::new(scheduler_enabled_config());
        let now = now_unix_seconds().unwrap_or_default() as i64;
        ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("unbudgeted", now - 1)),
        )
        .expect("seed schedule");

        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());

        let dispatches = ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.self_hosted_run_dispatches(),
        );
        assert!(
            dispatches.iter().any(|dispatch| dispatch
                .dispatch_id
                .starts_with("schedule-dispatch-unbudgeted-")),
            "an unbudgeted tenant's schedule must still enqueue its dispatch",
        );
    }

    #[test]
    fn advance_fast_forwards_past_now_on_catchup() {
        let state = AppState::new(scheduler_enabled_config());
        // A schedule whose next fire is far in the past (interval 60s) with the
        // default skip_missed policy must NOT fire the stale slot and must
        // fast-forward next_fire to a future slot.
        ferrogate_sync_bridge::block_on_sync_bridge(
            state
                .repositories
                .upsert_agent_schedule(interval_schedule("stale", 1)),
        )
        .expect("seed schedule");

        ferrogate_sync_bridge::block_on_sync_bridge(state.sweep_agent_schedules_once());

        let fires = ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.list_agent_schedule_fires("stale", 10),
        )
        .expect("list fires");
        assert!(
            fires.is_empty(),
            "skip_missed does not fire missed slots on catch-up"
        );
        let schedule = ferrogate_sync_bridge::block_on_sync_bridge(
            state.repositories.get_agent_schedule("stale"),
        )
        .expect("get")
        .expect("schedule present");
        let now = now_unix_seconds().unwrap_or_default() as i64;
        assert!(
            schedule.next_fire_at_unix.is_some_and(|next| next > now),
            "next_fire fast-forwarded strictly past now",
        );
    }
}

#[cfg(test)]
#[path = "state_scheduler_lifecycle_test.rs"]
mod state_scheduler_lifecycle_test;
