/**
 * The agent-schedule domain: spec kinds, the four policies, next-fire
 * computation, and the deterministic identifiers the at-most-once gate is
 * built on.
 *
 * Ported 1:1 from `crates/ferrogate-storage/src/agent_schedule.rs`
 * (`ScheduleSpecKind`, `ScheduleTargetKind`, `OverlapPolicy`, `CatchupPolicy`,
 * `ScheduleFireOutcome`, `StoredAgentSchedule::compute_next_fire_at`,
 * `agent_schedule_fire_id`) plus the mutation validation in
 * `crates/ferrogate-gateway/src/server/agent_schedules.rs`
 * (`build_schedule_from_mutation`) and the dispatch id from
 * `state_scheduler.rs` (`scheduled_dispatch_id`).
 *
 * ## Why the schedule stays a document
 *
 * `sql/d1-ts/tenant/0001_init_tenant.sql` carries a typed `agent_schedules`
 * table, and this app persists schedules through the generic
 * `control_plane_resources` document store instead. That is not a shortcut
 * around the typed schema — the typed table lives in the PER-TENANT database and
 * every one of the eight `/admin/v1/agent-schedules*` contract operations is a
 * control-plane operation served against the control database, the same as the
 * other ~60 admin collections. Splitting one collection onto a different
 * database would also split the tenant-scope enforcement that
 * `ControlPlaneStore` applies uniformly.
 *
 * What DOES come from the typed schema is the shape and the invariants, and
 * they are enforced here rather than by the DDL:
 *
 *  - the fire ledger's `UNIQUE (schedule_id, scheduled_fire_at_unix)` becomes
 *    the deterministic {@link agentScheduleFireId} plus `store.create`, whose
 *    D1 implementation is `INSERT … ON CONFLICT DO NOTHING RETURNING` — the
 *    same atomic insert-if-absent, so two Workers racing the same slot still
 *    yield exactly one fire;
 *  - the column CHECK constraints become {@link normalizeScheduleSpec}, which
 *    refuses at write time rather than at fire time.
 */

import {
  ScheduleError,
  assertValidTimezone,
  nextCronOccurrence,
  parseCronExpression,
} from "./cron.js";

export { ScheduleError } from "./cron.js";

/** Rust `ScheduleSpecKind`. */
export type ScheduleSpecKind = "cron" | "interval";
export const SCHEDULE_SPEC_KINDS: readonly ScheduleSpecKind[] = ["cron", "interval"];

/** Rust `ScheduleTargetKind`. */
export type ScheduleTargetKind = "self_hosted_dispatch" | "agent_run";
export const SCHEDULE_TARGET_KINDS: readonly ScheduleTargetKind[] = [
  "self_hosted_dispatch",
  "agent_run",
];

/** Rust `OverlapPolicy`. `skip` (default) suppresses a pile-up. */
export type OverlapPolicy = "skip" | "allow";
export const OVERLAP_POLICIES: readonly OverlapPolicy[] = ["skip", "allow"];

/** Rust `CatchupPolicy`. `skip_missed` (default) is n8n semantics. */
export type CatchupPolicy = "skip_missed" | "fire_once";
export const CATCHUP_POLICIES: readonly CatchupPolicy[] = ["skip_missed", "fire_once"];

/** Rust `ScheduleFireOutcome`. */
export type ScheduleFireOutcome = "dispatched" | "skipped_overlap" | "skipped_disabled" | "error";

/** The validated firing definition of one schedule. Rust `StoredAgentSchedule`. */
export interface AgentScheduleSpec {
  readonly spec_kind: ScheduleSpecKind;
  readonly cron_expr: string | null;
  readonly timezone: string;
  readonly interval_secs: number | null;
  readonly target_kind: ScheduleTargetKind;
  readonly overlap_policy: OverlapPolicy;
  readonly catchup_policy: CatchupPolicy;
  readonly jitter_secs: number;
  readonly enabled: boolean;
}

/** Fields a stored schedule document carries beyond its operator payload. */
export interface ScheduleFiringState {
  readonly next_fire_at_unix: number | null;
  readonly last_fire_at_unix: number | null;
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/**
 * Rust `agent_schedule_fire_id`. Deterministic so two Workers racing the same
 * slot mint the SAME primary key and collide, which is the whole at-most-once
 * gate.
 *
 * Length-prefixed for the reason Rust states: without it, schedule `a` at slot
 * `0:0` and schedule `a:0` at slot `0` would produce the same string, so a
 * crafted schedule id could suppress another schedule's fire.
 */
export function agentScheduleFireId(scheduleId: string, scheduledFireAtUnix: number): string {
  return `${scheduleId.length}:${scheduleId}:${scheduledFireAtUnix}`;
}

/**
 * Rust `scheduled_dispatch_id`. Two Workers that race the same due slot enqueue
 * the SAME dispatch id, so the lease queue dedups to exactly one dispatch even
 * if both get past the fire gate.
 */
export function scheduledDispatchId(scheduleId: string, slot: number): string {
  return `schedule-dispatch-${scheduleId}-${slot}`;
}

/**
 * Rust: a manual `run-now` fire id carries a `manual:` prefix so it can never
 * collide with the scheduler's per-slot id for the same second — an operator
 * pressing the button must not consume the slot the tick loop is about to fire.
 */
export function manualScheduleFireId(scheduleId: string, atUnix: number): string {
  return `manual:${agentScheduleFireId(scheduleId, atUnix)}`;
}

// ---------------------------------------------------------------------------
// Next-fire computation
// ---------------------------------------------------------------------------

/**
 * Rust `StoredAgentSchedule::compute_next_fire_at`: the next fire strictly
 * after `afterUnix`.
 *
 * `null` — never an error — for an interval schedule whose interval is
 * non-positive. Rust is explicit that this is "an invalid definition that must
 * never fire", and the distinction matters: `null` parks the schedule, an
 * exception would leave the previous `next_fire_at` in place and re-fire it
 * every tick.
 *
 * @throws {ScheduleError} for a cron schedule with a missing/invalid expression
 * or an unknown timezone.
 */
export function computeNextFireAt(spec: AgentScheduleSpec, afterUnix: number): number | null {
  if (spec.spec_kind === "cron") {
    const expr = spec.cron_expr?.trim();
    if (expr === undefined || expr === "") throw ScheduleError.missingCronExpr();
    return nextCronOccurrence(expr, spec.timezone, afterUnix);
  }
  const interval = spec.interval_secs ?? 0;
  if (interval <= 0) return null;
  // Rust `saturating_add`; JS has no wrap, but an overflowing sum must not
  // become a fire time in the past.
  const next = afterUnix + interval;
  return Number.isSafeInteger(next) ? next : null;
}

/**
 * Rust `SCHEDULER_CATCHUP_ITER_CAP`. Bounds the walk that fast-forwards
 * `next_fire_at` past a long outage; beyond it the search jumps straight to
 * `computeNextFireAt(now)` instead of stepping slot by slot.
 */
export const SCHEDULER_CATCHUP_ITER_CAP = 10_000;

/**
 * Rust `advance_schedule_past_now`: the first slot strictly after `now`,
 * walking forward from the slot that just fired.
 *
 * On-time firing converges in one step. A short catch-up takes a few. A long
 * outage would need millions of steps for an every-minute schedule, so the walk
 * is capped and then jumps directly — bounded fast-forward regardless of how
 * far behind the schedule is.
 *
 * Returns `null` when the schedule can no longer be scheduled (invalid
 * interval, or a cron expression that stopped computing), which parks it rather
 * than leaving a stale past slot that re-fires forever.
 */
export function advanceNextFireAt(
  spec: AgentScheduleSpec,
  firedSlot: number,
  now: number,
): number | null {
  let cursor = firedSlot;
  for (let step = 0; step < SCHEDULER_CATCHUP_ITER_CAP; step += 1) {
    let candidate: number | null;
    try {
      candidate = computeNextFireAt(spec, cursor);
    } catch {
      return null;
    }
    if (candidate === null) return null;
    if (candidate > now) return candidate;
    cursor = candidate;
  }
  try {
    return computeNextFireAt(spec, now);
  } catch {
    return null;
  }
}

/**
 * Rust `fire_due_schedule`'s `is_catchup`: are we firing a MISSED slot rather
 * than an on-time one? True when the slot immediately after the due one is
 * itself already in the past.
 */
export function isCatchupFire(spec: AgentScheduleSpec, slot: number, now: number): boolean {
  try {
    const next = computeNextFireAt(spec, slot);
    return next !== null && next <= now;
  } catch {
    return false;
  }
}

/**
 * Deterministic per-slot jitter in `[0, jitter_secs]`.
 *
 * Rust carries `jitter_secs` on the row and the tick loop leaves the spread to
 * the dispatcher. On Workers the equivalent has to be DETERMINISTIC rather than
 * randomized: several isolates evaluate the same slot concurrently, and a
 * random offset would make each of them compute a different effective fire time
 * for one slot — which is a thundering herd with extra steps, and it would make
 * the at-most-once gate's slot key ambiguous. Derived from (schedule, slot) so
 * every isolate agrees, and so a given schedule's offset within its window is
 * stable rather than jumping every fire.
 */
export function scheduleJitterOffset(scheduleId: string, slot: number, jitterSecs: number): number {
  if (!Number.isFinite(jitterSecs) || jitterSecs <= 0) return 0;
  const key = `${scheduleId}:${slot}`;
  // FNV-1a over the slot key. Cheap, no crypto, and stable across isolates and
  // across deploys — a hash that changed between builds would move every
  // schedule's fire time on every release.
  let hash = 0x811c9dc5;
  for (let index = 0; index < key.length; index += 1) {
    hash ^= key.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash % (Math.floor(jitterSecs) + 1);
}

// ---------------------------------------------------------------------------
// Write-path validation
// ---------------------------------------------------------------------------

/** A rejected mutation. The caller turns this into `400 invalid_request_body`. */
export class ScheduleSpecError extends Error {
  override readonly name = "ScheduleSpecError";
}

function pickEnum<T extends string>(
  raw: unknown,
  allowed: readonly T[],
  field: string,
  fallback: T | undefined,
): T {
  if (raw === undefined || raw === null) {
    if (fallback === undefined) throw new ScheduleSpecError(`${field} is required`);
    return fallback;
  }
  if (typeof raw !== "string" || !(allowed as readonly string[]).includes(raw)) {
    throw new ScheduleSpecError(
      `unknown ${field} '${String(raw)}' (expected ${allowed.map((value) => `'${value}'`).join(" or ")})`,
    );
  }
  return raw as T;
}

function optionalString(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  return trimmed === "" ? undefined : trimmed;
}

function optionalInteger(raw: unknown, field: string): number | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
    throw new ScheduleSpecError(`${field} must be an integer number of seconds`);
  }
  return raw;
}

function optionalBoolean(raw: unknown): boolean | undefined {
  return typeof raw === "boolean" ? raw : undefined;
}

/**
 * Validate a create/replace/merge body into an {@link AgentScheduleSpec} and
 * seed its first fire. Rust `build_schedule_from_mutation`.
 *
 * `existing` is the stored document for PATCH/PUT-over-an-existing-row, so an
 * omitted field keeps its previous value exactly as Rust's `.or_else(|| existing
 * …)` chain does. A create passes `null` and gets the documented defaults.
 *
 * ## The legacy `schedule` field
 *
 * Before this module the collection accepted a free-text `schedule` string and
 * stored it. That spelling stays a valid ALIAS for `cron_expr` — an operator's
 * existing `{"schedule": "0 3 * * *"}` still means the same thing, and now it is
 * checked. What changed is that an unparseable value is refused instead of
 * being stored as a schedule that can never fire.
 *
 * @throws {ScheduleSpecError} with an operator-readable reason.
 */
export function normalizeScheduleSpec(
  body: Readonly<Record<string, unknown>>,
  existing: Readonly<Record<string, unknown>> | null,
  now: number,
): { spec: AgentScheduleSpec; nextFireAt: number | null } {
  const prior = existing ?? {};

  const cronExpr =
    optionalString(body.cron_expr) ??
    optionalString(body.schedule) ??
    (Object.hasOwn(body, "cron_expr") || Object.hasOwn(body, "schedule")
      ? undefined
      : (optionalString(prior.cron_expr) ?? optionalString(prior.schedule)));

  const intervalSecs =
    optionalInteger(body.interval_secs, "interval_secs") ??
    (Object.hasOwn(body, "interval_secs")
      ? undefined
      : optionalInteger(prior.interval_secs, "interval_secs"));

  // Rust requires `spec_kind` explicitly. Here it is INFERRED when absent,
  // because the collection's pre-existing wire shape is a bare `schedule`
  // string and rejecting every one of those would be a breaking change to a
  // surface that is already deployed. The inference is unambiguous: an interval
  // was given, or an expression was.
  const declaredSpecKind = optionalString(body.spec_kind) ?? optionalString(prior.spec_kind);
  const inferredSpecKind: ScheduleSpecKind | undefined =
    declaredSpecKind === undefined
      ? cronExpr !== undefined
        ? "cron"
        : intervalSecs !== undefined
          ? "interval"
          : undefined
      : undefined;
  const specKind = pickEnum<ScheduleSpecKind>(
    declaredSpecKind,
    SCHEDULE_SPEC_KINDS,
    "spec_kind",
    inferredSpecKind,
  );

  const targetKind = pickEnum<ScheduleTargetKind>(
    optionalString(body.target_kind) ?? optionalString(prior.target_kind),
    SCHEDULE_TARGET_KINDS,
    "target_kind",
    "self_hosted_dispatch",
  );
  const overlapPolicy = pickEnum<OverlapPolicy>(
    optionalString(body.overlap_policy) ?? optionalString(prior.overlap_policy),
    OVERLAP_POLICIES,
    "overlap_policy",
    "skip",
  );
  const catchupPolicy = pickEnum<CatchupPolicy>(
    optionalString(body.catchup_policy) ?? optionalString(prior.catchup_policy),
    CATCHUP_POLICIES,
    "catchup_policy",
    "skip_missed",
  );

  const timezone = optionalString(body.timezone) ?? optionalString(prior.timezone) ?? "UTC";
  try {
    assertValidTimezone(timezone);
  } catch (error) {
    throw new ScheduleSpecError(
      error instanceof ScheduleError ? error.message : `invalid timezone '${timezone}'`,
    );
  }

  const jitterSecs =
    optionalInteger(body.jitter_secs, "jitter_secs") ??
    optionalInteger(prior.jitter_secs, "jitter_secs") ??
    0;
  if (jitterSecs < 0) throw new ScheduleSpecError("jitter_secs must not be negative");

  const enabled = optionalBoolean(body.enabled) ?? optionalBoolean(prior.enabled) ?? true;

  if (specKind === "interval") {
    if (intervalSecs === undefined || intervalSecs <= 0) {
      throw new ScheduleSpecError("interval schedule requires interval_secs > 0");
    }
  } else {
    if (cronExpr === undefined) {
      throw new ScheduleSpecError("cron schedule requires a non-empty cron_expr");
    }
    try {
      parseCronExpression(cronExpr);
    } catch (error) {
      throw new ScheduleSpecError(
        error instanceof ScheduleError ? error.message : `invalid cron expression '${cronExpr}'`,
      );
    }
  }

  const spec: AgentScheduleSpec = {
    spec_kind: specKind,
    cron_expr: cronExpr ?? null,
    timezone,
    interval_secs: intervalSecs ?? null,
    target_kind: targetKind,
    overlap_policy: overlapPolicy,
    catchup_policy: catchupPolicy,
    jitter_secs: jitterSecs,
    enabled,
  };

  let nextFireAt: number | null;
  try {
    nextFireAt = computeNextFireAt(spec, now);
  } catch (error) {
    throw new ScheduleSpecError(
      error instanceof ScheduleError ? error.message : "schedule has no computable next fire",
    );
  }
  return { spec, nextFireAt };
}

/**
 * Read a stored schedule document back into a spec.
 *
 * Deliberately TOLERANT where {@link normalizeScheduleSpec} is strict, and the
 * asymmetry is the same one the lifecycle gate uses: the write side refuses
 * anything it cannot fire, and the read side must still be able to describe a
 * row written by an older build. A row it cannot make sense of is returned with
 * an unfireable spec (`enabled: false` is NOT assumed — a legacy row with no
 * `spec_kind` and a valid `schedule` string is a real cron schedule).
 */
export function scheduleSpecFromRecord(
  record: Readonly<Record<string, unknown>>,
): AgentScheduleSpec {
  const cronExpr = optionalString(record.cron_expr) ?? optionalString(record.schedule) ?? null;
  const intervalRaw = record.interval_secs;
  const intervalSecs =
    typeof intervalRaw === "number" && Number.isInteger(intervalRaw) ? intervalRaw : null;
  const declared = optionalString(record.spec_kind);
  const specKind: ScheduleSpecKind =
    declared === "interval" || declared === "cron"
      ? declared
      : cronExpr !== null
        ? "cron"
        : "interval";
  const targetKind = optionalString(record.target_kind);
  const overlap = optionalString(record.overlap_policy);
  const catchup = optionalString(record.catchup_policy);
  const jitterRaw = record.jitter_secs;
  return {
    spec_kind: specKind,
    cron_expr: cronExpr,
    timezone: optionalString(record.timezone) ?? "UTC",
    interval_secs: intervalSecs,
    target_kind:
      targetKind === "agent_run" || targetKind === "self_hosted_dispatch"
        ? targetKind
        : "self_hosted_dispatch",
    overlap_policy: overlap === "allow" ? "allow" : "skip",
    catchup_policy: catchup === "fire_once" ? "fire_once" : "skip_missed",
    jitter_secs:
      typeof jitterRaw === "number" && Number.isInteger(jitterRaw) && jitterRaw > 0 ? jitterRaw : 0,
    enabled: record.enabled !== false,
  };
}
