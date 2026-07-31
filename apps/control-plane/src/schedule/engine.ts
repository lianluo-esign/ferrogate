/**
 * The scheduler: the part that was entirely absent.
 *
 * `docs/rewrite/parity-audit-storage.md` §4.2 — "the agent-schedule engine is
 * entirely absent (no module at all) … a schedule an operator creates never
 * fires". The CRUD surface existed, `/fires` listed a collection nothing
 * appended to, and `run-now` set `{ run_now: true }` on the document and
 * dispatched nothing.
 *
 * This is the TS port of `crates/ferrogate-gateway/src/state_scheduler.rs`:
 * `sweep_agent_schedules_once` → {@link runScheduleTick},
 * `fire_due_schedule` → {@link fireDueSchedule},
 * `dispatch_schedule_target` → {@link dispatchScheduleTarget},
 * `run_agent_schedule_now` → {@link runScheduleNow},
 * `record_fire` → {@link recordFire},
 * `advance_schedule_past_now` → {@link advanceSchedule}.
 *
 * ## The at-most-once gate, and why it is real here
 *
 * Rust's gate is `agent_schedule_fires`' `UNIQUE (schedule_id,
 * scheduled_fire_at_unix)` plus `ON CONFLICT DO NOTHING`. The gate here is the
 * SAME shape one layer up: {@link agentScheduleFireId} makes two Workers racing
 * one slot mint the same primary key, and `D1ControlPlaneStore.create` is
 * `INSERT … ON CONFLICT (resource_kind, resource_id) DO NOTHING RETURNING`,
 * so the loser gets `StoreConflictError` and does not dispatch. There is no
 * lock anywhere else in this path, exactly as in Rust.
 *
 * The ORDER is load-bearing and is the reverse of the obvious one: the fire row
 * is claimed BEFORE the target action runs. Rust enqueues first because its
 * lease queue dedups on the deterministic dispatch id, so a double enqueue is
 * harmless there. Here the `agent_run` target has no such dedup — creating the
 * run twice would be two runs an operator pays for — so the claim comes first
 * and the outcome is written onto the claimed row afterwards. The trade is
 * explicit: a Worker that dies between claim and dispatch loses that slot
 * rather than double-firing it. For a paid agent run, losing one fire is the
 * cheaper failure, and the next slot fires normally.
 */

import { type ApiOperation, operationById } from "../contract.js";
import type {
  AuthContext,
  CallerScope,
  ControlPlaneStore,
  StoreRecord,
  TenancyLifecycleGatePort,
} from "../ports.js";
import { StoreConflictError } from "../ports.js";
import {
  type AgentScheduleSpec,
  type ScheduleFireOutcome,
  advanceNextFireAt,
  agentScheduleFireId,
  isCatchupFire,
  manualScheduleFireId,
  scheduleJitterOffset,
  scheduleSpecFromRecord,
  scheduledDispatchId,
} from "./model.js";

/** Store collections the engine reads and writes. */
export const SCHEDULE_COLLECTION = "agent-schedules";
export const SCHEDULE_FIRE_COLLECTION = "agent-schedule-fires";
export const SELF_HOSTED_DISPATCH_COLLECTION = "self-hosted-run-dispatches";
export const AGENT_RUN_COLLECTION = "agent-runs";

/**
 * Rust `SCHEDULER_DUE_BATCH`. Bounds one tick's work so a large backlog drains
 * across ticks instead of in one unbounded pass — which on Workers is not a
 * nicety but the CPU-time limit.
 */
export const SCHEDULER_DUE_BATCH = 200;

/**
 * A self-hosted dispatch is "still in flight" until it reaches one of these.
 * Rust asks the in-process lease queue (`self_hosted_dispatch_unacked`); the
 * durable equivalent is the dispatch row's own status, which is what the lease
 * queue writes through anyway.
 */
const TERMINAL_DISPATCH_STATUSES: ReadonlySet<string> = new Set([
  "acked",
  "completed",
  "succeeded",
  "failed",
  "cancelled",
  "canceled",
  "expired",
]);

/** Rust `ScheduleFireResult`. */
export interface ScheduleFireResult {
  readonly outcome: ScheduleFireOutcome;
  readonly dispatch_id: string | null;
  readonly run_id: string | null;
  readonly detail: string | null;
}

/** A durable fire-history row. Rust `StoredAgentScheduleFire`. */
export interface ScheduleFireRecord extends StoreRecord {
  readonly schedule_id: string;
  readonly scheduled_fire_at_unix: number;
  readonly fired_at_unix: number;
  readonly outcome: ScheduleFireOutcome;
}

/** Everything the engine needs, injected so a tick has no hidden globals. */
export interface ScheduleEngineDeps {
  readonly store: ControlPlaneStore;
  /**
   * Rust `require_usable_tenancy`: a suspended tenant's schedules must not
   * fire. Optional because a deployment can run the engine without the gate
   * (the unit suites do), and its ABSENCE must be visible rather than silently
   * meaning "admit everything" — see {@link admitTenancy}.
   */
  readonly lifecycle?: TenancyLifecycleGatePort;
  /** Identifies which Worker recorded a fire. Rust `cluster_identity_node_id`. */
  readonly nodeId?: string;
}

/** What one tick did. Returned rather than logged so a test can assert on it. */
export interface ScheduleTickSummary {
  readonly scanned: number;
  readonly fired: readonly string[];
  readonly skipped: readonly string[];
  readonly advanced: readonly string[];
  readonly errors: readonly string[];
}

/** The scope a background tick acts under: no caller, so platform-wide. */
const TICK_SCOPE: CallerScope = { kind: "platform_operator" };

/**
 * The contract operation a fire is judged as, for the lifecycle gate.
 *
 * The gate's only structural question is whether the operation is one of the
 * RECOVERY operations that a suspended tenant is still allowed to reach (so an
 * operator can un-suspend itself); firing a schedule is emphatically not one,
 * and taking the id from the contract rather than inventing a string means a
 * future recovery-list change classifies this path too. Resolved at module load
 * and thrown on if absent — the same fail-at-build shape `crudGroup` uses, so a
 * contract rename cannot silently turn the gate into a no-op.
 */
const FIRE_OPERATION: ApiOperation = (() => {
  const operation = operationById("runAdminAgentScheduleNow");
  if (operation === undefined) {
    throw new Error(
      "control-plane scheduler: contract operation runAdminAgentScheduleNow is missing; the lifecycle gate has nothing to classify a schedule fire as",
    );
  }
  return operation;
})();

function tenantIdOf(schedule: StoreRecord): string | null {
  const value = schedule.tenant_id;
  return typeof value === "string" && value !== "" ? value : null;
}

function workspaceIdOf(schedule: StoreRecord): string | null {
  const value = schedule.workspace_id;
  return typeof value === "string" && value !== "" ? value : null;
}

function nextFireAtOf(schedule: StoreRecord): number | null {
  const value = schedule.next_fire_at_unix;
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function lastFireAtOf(schedule: StoreRecord): number | null {
  const value = schedule.last_fire_at_unix;
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * How long after its slot this schedule actually becomes due.
 *
 * `jitter_secs` is the one field where this port does MORE than the Rust
 * original, and it is worth being explicit rather than quiet about it: Rust
 * carries `jitter_secs` on `StoredAgentSchedule`, validates it as non-negative
 * in `build_schedule_from_mutation`, persists it — and no code path ever reads
 * it back (`grep -rn jitter_secs crates/ferrogate-gateway/src` finds only the
 * struct, the validator and test fixtures). An operator who sets it today gets
 * nothing, which is the same "configured and inert" shape this port has been
 * closing everywhere else.
 *
 * Here it delays the fire WITHIN its slot: the schedule becomes due at
 * `slot + offset` while the slot key stays `slot`, so the at-most-once ledger
 * and the fire history are unchanged and only the moment of dispatch moves.
 * The offset is deterministic ({@link scheduleJitterOffset}) — several isolates
 * evaluating the same slot must agree, or "due" would mean something different
 * in each of them.
 */
function jitterDelayOf(schedule: StoreRecord, slot: number): number {
  const raw = schedule.jitter_secs;
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw <= 0) return 0;
  return scheduleJitterOffset(String(schedule.id), slot, raw);
}

// ---------------------------------------------------------------------------
// Tenancy admission
// ---------------------------------------------------------------------------

/**
 * Rust `dispatch_schedule_target`'s first act: refuse the fire when the
 * schedule's tenancy is not usable.
 *
 * A schedule outlives the tenant that owns it — suspending a tenant must stop
 * its scheduled spend, and a scheduler that keeps firing is a suspension
 * control that does not control anything (#514, reproduced in the port for the
 * request path and closed there; this is the same hole on the timer path).
 *
 * When no gate is injected this returns `admitted`, and that is why
 * `ScheduleEngineDeps.lifecycle` is threaded from the composition root rather
 * than defaulted here: the production wiring always supplies it, and the
 * mount-gate test asserts a suspended tenant's schedule does not fire through
 * the REAL Worker, so removing the wiring turns that test red.
 */
async function admitTenancy(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
): Promise<{ admitted: true } | { admitted: false; detail: string }> {
  const gate = deps.lifecycle;
  if (gate === undefined) return { admitted: true };
  const auth: AuthContext = {
    subject: typeof schedule.id === "string" ? schedule.id : null,
    tenancy: {
      tenantId: tenantIdOf(schedule),
      projectId: typeof schedule.project_id === "string" ? schedule.project_id : null,
      workspaceId: workspaceIdOf(schedule),
      userId: null,
    },
    scopes: ["admin.write"],
    platformOperator: false,
    source: "durable_native",
  };
  const decision = await gate.admit(auth, FIRE_OPERATION);
  if (decision.admitted) return { admitted: true };
  return { admitted: false, detail: `${decision.code}: ${decision.message}` };
}

// ---------------------------------------------------------------------------
// Target dispatch
// ---------------------------------------------------------------------------

/**
 * Rust `dispatch_schedule_target`: run the schedule's target action for one
 * slot, WITHOUT recording the fire or advancing the schedule (the caller owns
 * both). Shared by the tick loop and the manual `run-now` trigger so the two
 * paths cannot diverge on what a target kind means.
 */
export async function dispatchScheduleTarget(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  spec: AgentScheduleSpec,
  slot: number,
  now: number,
): Promise<ScheduleFireResult> {
  const admission = await admitTenancy(deps, schedule);
  if (!admission.admitted) {
    return {
      outcome: "error",
      dispatch_id: null,
      run_id: null,
      detail: admission.detail,
    };
  }

  const scheduleId = String(schedule.id);
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  const target = (schedule.target ?? {}) as Record<string, unknown>;

  if (spec.target_kind === "agent_run") {
    // Rust: the scheduler is a control-plane TRIGGER — it registers the run in
    // `running` and the managed runtime drives it to completion out of band.
    // The run id is deterministic for the same reason the dispatch id is: two
    // isolates that both got past the fire gate must not create two runs.
    const runId = `schedule-run-${scheduleId}-${slot}`;
    try {
      await deps.store.create(AGENT_RUN_COLLECTION, scope, {
        ...target,
        id: runId,
        tenant_id: tenantId,
        workspace_id: workspaceIdOf(schedule),
        status: "running",
        source: "agent_schedule",
        schedule_id: scheduleId,
        scheduled_fire_at_unix: slot,
        created_at: now,
      });
    } catch (error) {
      if (!(error instanceof StoreConflictError)) {
        return {
          outcome: "error",
          dispatch_id: null,
          run_id: null,
          detail: error instanceof Error ? error.message : String(error),
        };
      }
      // A peer created it. Idempotent, so the fire still counts as dispatched.
    }
    return { outcome: "dispatched", dispatch_id: null, run_id: runId, detail: null };
  }

  const dispatchId = scheduledDispatchId(scheduleId, slot);
  try {
    await deps.store.create(SELF_HOSTED_DISPATCH_COLLECTION, scope, {
      ...target,
      id: dispatchId,
      tenant_id: tenantId,
      workspace_id: workspaceIdOf(schedule),
      schedule_id: scheduleId,
      scheduled_fire_at_unix: slot,
      status: "queued",
      enqueued_at: now,
    });
  } catch (error) {
    if (!(error instanceof StoreConflictError)) {
      return {
        outcome: "error",
        dispatch_id: null,
        run_id: null,
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    // Rust: the lease queue dedups on the deterministic dispatch id, so an
    // existing row IS the success case, not a failure.
  }
  return { outcome: "dispatched", dispatch_id: dispatchId, run_id: null, detail: null };
}

// ---------------------------------------------------------------------------
// The fire ledger
// ---------------------------------------------------------------------------

/**
 * Claim `(schedule, slot)` in the fire ledger.
 *
 * Returns `null` when a peer already claimed it — that is not an error, it is
 * the at-most-once gate doing its job, and the caller must NOT dispatch.
 */
async function claimFireSlot(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  fireId: string,
  slot: number,
  now: number,
): Promise<ScheduleFireRecord | null> {
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  try {
    const stored = await deps.store.create(SCHEDULE_FIRE_COLLECTION, scope, {
      id: fireId,
      tenant_id: tenantId,
      schedule_id: String(schedule.id),
      scheduled_fire_at_unix: slot,
      fired_at_unix: now,
      node_id: deps.nodeId ?? null,
      outcome: "dispatched" satisfies ScheduleFireOutcome,
      dispatch_id: null,
      run_id: null,
      detail: null,
    });
    return stored as ScheduleFireRecord;
  } catch (error) {
    if (error instanceof StoreConflictError) return null;
    throw error;
  }
}

/** Write the target action's outcome onto the fire row this Worker claimed. */
async function recordFireOutcome(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  fireId: string,
  result: ScheduleFireResult,
): Promise<ScheduleFireRecord | null> {
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  const merged = await deps.store.merge(SCHEDULE_FIRE_COLLECTION, scope, fireId, {
    outcome: result.outcome,
    dispatch_id: result.dispatch_id,
    run_id: result.run_id,
    detail: result.detail,
  });
  return merged === null ? null : (merged as ScheduleFireRecord);
}

/**
 * Rust `record_fire` for the paths that do NOT dispatch (overlap/disabled
 * skips): claim the slot and stamp the terminal outcome in one write, because
 * there is no action to await in between.
 */
async function recordFire(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  slot: number,
  now: number,
  result: ScheduleFireResult,
): Promise<ScheduleFireRecord | null> {
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  try {
    const stored = await deps.store.create(SCHEDULE_FIRE_COLLECTION, scope, {
      id: agentScheduleFireId(String(schedule.id), slot),
      tenant_id: tenantId,
      schedule_id: String(schedule.id),
      scheduled_fire_at_unix: slot,
      fired_at_unix: now,
      node_id: deps.nodeId ?? null,
      outcome: result.outcome,
      dispatch_id: result.dispatch_id,
      run_id: result.run_id,
      detail: result.detail,
    });
    return stored as ScheduleFireRecord;
  } catch (error) {
    if (error instanceof StoreConflictError) return null;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Advancing
// ---------------------------------------------------------------------------

/**
 * Rust `advance_schedule_past_now`: stamp `last_fire_at = slot` and move
 * `next_fire_at` to the first slot strictly after `now`.
 *
 * Guarded on the slot it fired (`mergeIf`), so a peer that already advanced the
 * schedule wins and this one is a no-op. Without the guard two isolates racing
 * a tick could each write a next-fire computed from a different anchor, and the
 * later write would move the schedule BACKWARDS — re-firing a slot the ledger
 * has already recorded, which the fire gate would then silently swallow, so the
 * schedule would appear to stall.
 */
async function advanceSchedule(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  spec: AgentScheduleSpec,
  slot: number,
  now: number,
): Promise<boolean> {
  const nextFire = advanceNextFireAt(spec, slot, now);
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  const outcome = await deps.store.mergeIf(
    SCHEDULE_COLLECTION,
    scope,
    String(schedule.id),
    { last_fire_at_unix: slot, next_fire_at_unix: nextFire, updated_at_unix: now },
    (current) => nextFireAtOf(current) === slot,
  );
  return outcome.kind === "merged";
}

// ---------------------------------------------------------------------------
// One schedule
// ---------------------------------------------------------------------------

/** Rust `fire_due_schedule`. Returns what happened, for the tick summary. */
export async function fireDueSchedule(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  now: number,
): Promise<"fired" | "skipped" | "advanced" | "error" | "claimed_by_peer"> {
  const slot = nextFireAtOf(schedule);
  if (slot === null) return "skipped";
  const spec = scheduleSpecFromRecord(schedule);
  const scheduleId = String(schedule.id);

  // Catch-up policy `skip_missed` (n8n semantics, default): do NOT fire a
  // missed slot — fast-forward past it. `fire_once` falls through and fires a
  // single catch-up, then fast-forwards the same way.
  if (spec.catchup_policy === "skip_missed" && isCatchupFire(spec, slot, now)) {
    await advanceSchedule(deps, schedule, spec, slot, now);
    return "advanced";
  }

  // Overlap policy `skip` (default): suppress while the previous fire's
  // dispatch is still in flight, which is what stops a slow target from piling
  // up one run per slot until the tenant's wallet is empty.
  if (spec.overlap_policy === "skip") {
    const previousSlot = lastFireAtOf(schedule);
    if (previousSlot !== null && (await isDispatchUnacked(deps, schedule, previousSlot))) {
      await recordFire(deps, schedule, slot, now, {
        outcome: "skipped_overlap",
        dispatch_id: null,
        run_id: null,
        detail: "previous dispatch still in flight",
      });
      await advanceSchedule(deps, schedule, spec, slot, now);
      return "skipped";
    }
  }

  // Claim the slot BEFORE the target runs — see the module docblock on why this
  // is the reverse of Rust's order.
  const fireId = agentScheduleFireId(scheduleId, slot);
  const claim = await claimFireSlot(deps, schedule, fireId, slot, now);
  if (claim === null) {
    // A peer owns this slot. It will also advance the schedule, so this Worker
    // does nothing at all — advancing here would race that peer's write.
    return "claimed_by_peer";
  }

  const result = await dispatchScheduleTarget(deps, schedule, spec, slot, now);
  await recordFireOutcome(deps, schedule, fireId, result);
  // Advance regardless of the action's outcome, so a permanently failing target
  // fast-forwards past its slot instead of re-firing it on every tick.
  await advanceSchedule(deps, schedule, spec, slot, now);
  return result.outcome === "dispatched" ? "fired" : "error";
}

/** Rust `self_hosted_dispatch_unacked`, over the durable dispatch row. */
async function isDispatchUnacked(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  previousSlot: number,
): Promise<boolean> {
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  const dispatchId = scheduledDispatchId(String(schedule.id), previousSlot);
  const record = await deps.store.get(SELF_HOSTED_DISPATCH_COLLECTION, scope, dispatchId);
  if (record === null) return false;
  const status = typeof record.status === "string" ? record.status : "";
  return !TERMINAL_DISPATCH_STATUSES.has(status);
}

// ---------------------------------------------------------------------------
// The tick
// ---------------------------------------------------------------------------

/**
 * Rust `sweep_agent_schedules_once`. One pass over the due schedules.
 *
 * The due scan reads the collection and filters in the isolate rather than
 * pushing `next_fire_at_unix <= ?` into SQL. That is forced by the storage
 * shape, not chosen: every admin collection lives in the generic
 * `control_plane_resources` document table, so `next_fire_at_unix` is a JSON
 * field with no index — the same constraint `store/d1.ts`'s kept
 * `PORT-TODO(inventory-edge-control §9.3)` records for list filtering, and for
 * the same reason (pushing a predicate into SQL over `document_json` changes
 * its meaning). It is bounded by {@link SCHEDULER_DUE_BATCH}, and a backlog
 * drains over successive ticks.
 */
export async function runScheduleTick(
  deps: ScheduleEngineDeps,
  now: number,
  batchSize = SCHEDULER_DUE_BATCH,
): Promise<ScheduleTickSummary> {
  const fired: string[] = [];
  const skipped: string[] = [];
  const advanced: string[] = [];
  const errors: string[] = [];

  const page = await deps.store.list(SCHEDULE_COLLECTION, TICK_SCOPE, {
    offset: 0,
    limit: Number.MAX_SAFE_INTEGER,
    paginate: false,
    search: null,
    filters: {},
  });

  const due = page.items
    .filter((record) => {
      if (record.enabled === false) return false;
      const next = nextFireAtOf(record);
      if (next === null) return false;
      return next + jitterDelayOf(record, next) <= now;
    })
    // Cheapest first, matching the `idx_agent_schedules_due` ordering: a
    // backlog drains oldest-slot-first rather than in document order, so no
    // schedule can be starved by a noisier neighbour.
    .sort((left, right) => (nextFireAtOf(left) ?? 0) - (nextFireAtOf(right) ?? 0))
    .slice(0, batchSize);

  for (const schedule of due) {
    const id = String(schedule.id);
    try {
      switch (await fireDueSchedule(deps, schedule, now)) {
        case "fired":
          fired.push(id);
          break;
        case "skipped":
        case "claimed_by_peer":
          skipped.push(id);
          break;
        case "advanced":
          advanced.push(id);
          break;
        case "error":
          errors.push(id);
          break;
      }
    } catch (error) {
      // One poisoned schedule must not stop the tick: the remaining due
      // schedules belong to other tenants.
      errors.push(`${id}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return { scanned: page.items.length, fired, skipped, advanced, errors };
}

// ---------------------------------------------------------------------------
// The manual trigger
// ---------------------------------------------------------------------------

/**
 * Rust `run_agent_schedule_now` (#251): fire the target immediately, regardless
 * of `enabled`, `next_fire_at`, or the catch-up/overlap policies, and record a
 * dedicated fire row so the manual trigger is observable.
 *
 * Does NOT advance `next_fire_at`: a manual run is an ad-hoc EXTRA fire, not a
 * replacement for the schedule's own cadence. The `manual:` prefix on the fire
 * id keeps it from consuming the slot the tick loop is about to claim for the
 * same second.
 */
export async function runScheduleNow(
  deps: ScheduleEngineDeps,
  schedule: StoreRecord,
  now: number,
): Promise<ScheduleFireRecord> {
  const spec = scheduleSpecFromRecord(schedule);
  const result = await dispatchScheduleTarget(deps, schedule, spec, now, now);
  const tenantId = tenantIdOf(schedule);
  const scope: CallerScope = tenantId === null ? TICK_SCOPE : { kind: "tenant", tenantId };
  const fireId = manualScheduleFireId(String(schedule.id), now);
  const row = {
    id: fireId,
    tenant_id: tenantId,
    schedule_id: String(schedule.id),
    scheduled_fire_at_unix: now,
    fired_at_unix: now,
    node_id: deps.nodeId ?? null,
    outcome: result.outcome,
    dispatch_id: result.dispatch_id,
    run_id: result.run_id,
    detail: result.detail ?? "manual run-now trigger",
  } satisfies StoreRecord;
  try {
    return (await deps.store.create(SCHEDULE_FIRE_COLLECTION, scope, row)) as ScheduleFireRecord;
  } catch (error) {
    // Rust: a collision for the same second is harmless — the target action
    // already ran, and the caller still gets the record it should report.
    if (error instanceof StoreConflictError) return row as ScheduleFireRecord;
    throw error;
  }
}
