/**
 * Time-based agent schedule triggers (#246) — the cron/interval engine, the
 * schedule + fire DTOs, and the pure tick decision.
 *
 * Clean-room re-implementation of `ferrogate-storage::agent_schedule` plus the
 * pure half of the Rust tick loop (`ferrogate-gateway::state_scheduler`). Before
 * this module the family was ABSENT, not partial: `sql/d1-ts/tenant/` created
 * `agent_schedules` and `agent_schedule_fires` with the at-most-once UNIQUE and
 * no code wrote either, so a schedule an operator created never fired.
 *
 * ## The correctness gate is one UNIQUE, and it is not here
 *
 * At-most-once firing is NOT enforced by anything in this file. It is the
 * `UNIQUE (schedule_id, scheduled_fire_at_unix)` row in `agent_schedule_fires`,
 * claimed with `INSERT ... ON CONFLICT DO NOTHING RETURNING` — see
 * {@link ./d1/agent-schedule-d1.js D1AgentScheduleStore.insertScheduleFire}.
 * Everything below decides WHICH slot to claim; the database decides WHO claims
 * it. Two Workers racing the same cron minute both compute the same slot (the
 * computation is deterministic — that is why {@link agentScheduleFireId} is a
 * pure function of `(schedule_id, slot)` and not a uuid), and exactly one wins
 * the insert. Without that gate the same paid agent run is dispatched twice.
 *
 * ## No cron library
 *
 * Rust uses `croner` + `chrono-tz`. Neither is imported here (and the clean-room
 * rule forbids reusing the Rust artifacts anyway), so the 5-field parser below
 * is written from the standard Vixie-cron grammar and the timezone arithmetic
 * runs on `Intl.DateTimeFormat`, which workerd ships with full ICU — no
 * dependency, no timezone database to keep in sync, and DST handled by the same
 * data the platform uses everywhere else.
 *
 * The grammar implemented is stated exactly in {@link parseCronExpression} and
 * pinned field-by-field by `test/agent-schedule.test.ts`, because "compatible
 * with croner" is not a testable claim from this side of the port — what IS
 * testable is that the documented grammar is what the code does.
 *
 * ## `jitterSecs` is stored and NOT applied — deliberately
 *
 * The Rust admin API validates `jitter_secs >= 0` and persists it, and the Rust
 * tick loop then never reads it: no fire time is offset by it anywhere in
 * `state_scheduler.rs`. This port does exactly the same rather than inventing a
 * delay Rust does not have. Recorded here so the next reader does not "fix" it
 * into a behavior change; pinned by a test asserting a non-zero `jitterSecs`
 * moves no computed fire time.
 */
import { StorageError } from "./errors.js";

// ---------------------------------------------------------------------------
// Vocabularies
// ---------------------------------------------------------------------------

/** How a schedule's firing cadence is expressed. */
export type ScheduleSpecKind = "cron" | "interval";

/** Parse the TEXT column; `undefined` for an unknown token (never a default). */
export function scheduleSpecKindFromString(raw: string): ScheduleSpecKind | undefined {
  return raw === "cron" || raw === "interval" ? raw : undefined;
}

/** What a due schedule triggers when it fires. */
export type ScheduleTargetKind = "self_hosted_dispatch" | "agent_run";

export function scheduleTargetKindFromString(raw: string): ScheduleTargetKind | undefined {
  return raw === "self_hosted_dispatch" || raw === "agent_run" ? raw : undefined;
}

/** Whether a new fire is suppressed while the previous one is still active. */
export type OverlapPolicy = "skip" | "allow";

export function overlapPolicyFromString(raw: string): OverlapPolicy | undefined {
  return raw === "skip" || raw === "allow" ? raw : undefined;
}

/** How slots missed during downtime are handled on catch-up. */
export type CatchupPolicy = "skip_missed" | "fire_once";

export function catchupPolicyFromString(raw: string): CatchupPolicy | undefined {
  return raw === "skip_missed" || raw === "fire_once" ? raw : undefined;
}

/** Terminal outcome recorded for one `(schedule, slot)` fire attempt. */
export type ScheduleFireOutcome = "dispatched" | "skipped_overlap" | "skipped_disabled" | "error";

export function scheduleFireOutcomeFromString(raw: string): ScheduleFireOutcome | undefined {
  switch (raw) {
    case "dispatched":
    case "skipped_overlap":
    case "skipped_disabled":
    case "error":
      return raw;
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/** A control-plane schedule definition (#246). */
export interface StoredAgentSchedule {
  scheduleId: string;
  tenantId: string;
  workspaceId: string;
  name: string;
  enabled: boolean;
  specKind: ScheduleSpecKind;
  cronExpr?: string;
  /** IANA zone name; cron slots are wall-clock in this zone, so DST is honored. */
  timezone: string;
  intervalSecs?: number;
  targetKind: ScheduleTargetKind;
  /** Free-form JSON string interpreted by the fire action. */
  targetJson: string;
  overlapPolicy: OverlapPolicy;
  catchupPolicy: CatchupPolicy;
  /** Stored and validated `>= 0`; applied by nothing — see the module docblock. */
  jitterSecs: number;
  nextFireAtUnix?: number;
  lastFireAtUnix?: number;
  createdAtUnix: number;
  updatedAtUnix: number;
  revision: number;
}

/** A durable fire-history record AND the per-slot idempotency token. */
export interface StoredAgentScheduleFire {
  fireId: string;
  scheduleId: string;
  scheduledFireAtUnix: number;
  firedAtUnix: number;
  nodeId?: string;
  outcome: ScheduleFireOutcome;
  dispatchId?: string;
  runId?: string;
  detail?: string;
}

/**
 * Deterministic fire id, so two isolates racing the same slot produce the SAME
 * primary key — which, with the `(schedule_id, scheduled_fire_at_unix)` UNIQUE,
 * is what makes the insert idempotent instead of merely conflicting.
 *
 * Length-prefixed: without the prefix a crafted `schedule_id` containing `:`
 * could alias another schedule's slot id and steal its at-most-once claim.
 */
export function agentScheduleFireId(scheduleId: string, scheduledFireAtUnix: number): string {
  return `${scheduleId.length}:${scheduleId}:${scheduledFireAtUnix}`;
}

/**
 * Deterministic dispatch id for a `(schedule, slot)` fire, so two isolates that
 * race the same due slot enqueue the SAME dispatch and the lease queue dedups
 * them — the second line of defense behind the fire-row UNIQUE.
 */
export function scheduledDispatchId(scheduleId: string, slot: number): string {
  return `schedule-dispatch-${scheduleId}-${slot}`;
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

/** Why a next-fire computation could not produce a time. */
export type ScheduleError =
  | { kind: "invalid_timezone"; timezone: string }
  | { kind: "invalid_cron"; message: string }
  | { kind: "invalid_timestamp"; timestamp: number }
  | { kind: "missing_cron_expr" };

/** The Rust `Display` text for a {@link ScheduleError}, verbatim. */
export function scheduleErrorMessage(error: ScheduleError): string {
  switch (error.kind) {
    case "invalid_timezone":
      return `invalid IANA timezone '${error.timezone}'`;
    case "invalid_cron":
      return `invalid cron expression: ${error.message}`;
    case "invalid_timestamp":
      return `unrepresentable unix timestamp ${error.timestamp}`;
    case "missing_cron_expr":
      return "cron schedule is missing its cron expression";
  }
}

/** A {@link ScheduleError} as the `StorageError` the Rust `From` impl produces. */
export function scheduleStorageError(error: ScheduleError): StorageError {
  return StorageError.runtime(scheduleErrorMessage(error));
}

/** One parsed cron field: the set of values it matches. */
interface CronField {
  values: Set<number>;
  /** `true` when the field was a bare `*` — load-bearing for the dom/dow rule. */
  wildcard: boolean;
}

/** A parsed 5-field cron expression. */
export interface CronExpression {
  minute: CronField;
  hour: CronField;
  dayOfMonth: CronField;
  month: CronField;
  dayOfWeek: CronField;
}

const MONTH_NAMES: Record<string, number> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};

const DAY_NAMES: Record<string, number> = {
  sun: 0,
  mon: 1,
  tue: 2,
  wed: 3,
  thu: 4,
  fri: 5,
  sat: 6,
};

function parseFieldValue(
  raw: string,
  min: number,
  max: number,
  names: Record<string, number>,
): number {
  const lower = raw.toLowerCase();
  if (lower in names) return names[lower] as number;
  if (!/^\d+$/.test(raw)) throw new Error(`unrecognized value '${raw}'`);
  const value = Number(raw);
  if (value < min || value > max) {
    throw new Error(`value ${value} is outside ${min}-${max}`);
  }
  return value;
}

/**
 * Parse one cron field into the set of values it matches.
 *
 * Grammar (standard Vixie cron, and this is the WHOLE grammar — anything else
 * is rejected rather than silently ignored, because a cron expression an
 * operator believes is restrictive but which silently matches everything is how
 * a schedule fires 1,440 times a day):
 *
 *   `*` · `n` · `a-b` · `a-b/s` · `*​/s` · `n/s` · any comma-separated list of
 *   those. Month names `JAN`–`DEC` and day names `SUN`–`SAT` (case-insensitive)
 *   are accepted wherever a number is.
 */
function parseCronField(
  raw: string,
  min: number,
  max: number,
  names: Record<string, number> = {},
): CronField {
  const trimmed = raw.trim();
  if (trimmed === "") throw new Error("empty field");
  const values = new Set<number>();
  const wildcard = trimmed === "*";
  for (const part of trimmed.split(",")) {
    const [rangePart, stepPart, ...rest] = part.split("/");
    if (rest.length > 0) throw new Error(`too many '/' in '${part}'`);
    let step = 1;
    if (stepPart !== undefined) {
      if (!/^\d+$/.test(stepPart) || Number(stepPart) === 0) {
        throw new Error(`invalid step '${stepPart}'`);
      }
      step = Number(stepPart);
    }
    let start: number;
    let end: number;
    const range = (rangePart ?? "").trim();
    if (range === "*") {
      start = min;
      end = max;
    } else if (range.includes("-")) {
      const [lo, hi, ...extra] = range.split("-");
      if (extra.length > 0) throw new Error(`invalid range '${range}'`);
      start = parseFieldValue(lo ?? "", min, max, names);
      end = parseFieldValue(hi ?? "", min, max, names);
      if (end < start) throw new Error(`descending range '${range}'`);
    } else {
      start = parseFieldValue(range, min, max, names);
      // `n/s` means "from n to the field maximum, every s" — the same reading
      // as `n-max/s`. A bare `n` with no step is just `n`.
      end = stepPart === undefined ? start : max;
    }
    for (let value = start; value <= end; value += step) values.add(value);
  }
  if (values.size === 0) throw new Error("field matches nothing");
  return { values, wildcard };
}

/**
 * Parse a standard 5-field cron expression: `minute hour day-of-month month
 * day-of-week`.
 *
 * Day-of-week accepts `0`–`7` with BOTH `0` and `7` meaning Sunday, which is the
 * conventional Vixie behavior and the one an operator copying a crontab line
 * expects.
 *
 * Fields are separated by runs of whitespace. Anything other than exactly five
 * fields is rejected — a 6-field (seconds) expression is NOT silently reinterpreted,
 * because reading `0 0 12 * * *` as a 5-field expression would shift every field
 * by one position and fire at a time the operator never asked for.
 */
export function parseCronExpression(expression: string): CronExpression {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(
      `expected 5 fields (minute hour day-of-month month day-of-week), got ${fields.length}`,
    );
  }
  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields as [
    string,
    string,
    string,
    string,
    string,
  ];
  const dow = parseCronField(dayOfWeek, 0, 7, DAY_NAMES);
  // Normalize 7 → 0 AFTER parsing so `5-7` still means Fri–Sun.
  if (dow.values.has(7)) {
    dow.values.delete(7);
    dow.values.add(0);
  }
  return {
    minute: parseCronField(minute, 0, 59),
    hour: parseCronField(hour, 0, 23),
    dayOfMonth: parseCronField(dayOfMonth, 1, 31),
    month: parseCronField(month, 1, 12, MONTH_NAMES),
    dayOfWeek: dow,
  };
}

/** Local wall-clock components of an instant, in one IANA zone. */
interface ZonedParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

const formatterCache = new Map<string, Intl.DateTimeFormat>();

function zoneFormatter(timezone: string): Intl.DateTimeFormat {
  const cached = formatterCache.get(timezone);
  if (cached !== undefined) return cached;
  // Throws `RangeError` for an unknown zone — that is the timezone validation.
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  formatterCache.set(timezone, formatter);
  return formatter;
}

/** The wall-clock components of `unixSeconds` in `timezone`. */
function zonedParts(timezone: string, unixSeconds: number): ZonedParts {
  const parts = zoneFormatter(timezone).formatToParts(new Date(unixSeconds * 1000));
  const read = (type: string): number => {
    const found = parts.find((part) => part.type === type);
    return found === undefined ? 0 : Number(found.value);
  };
  return {
    year: read("year"),
    month: read("month"),
    day: read("day"),
    hour: read("hour"),
    minute: read("minute"),
    second: read("second"),
  };
}

/** Wall-clock components read as if they were UTC, in seconds. */
function partsAsUtcSeconds(parts: ZonedParts): number {
  return (
    Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) / 1000
  );
}

/** The zone's UTC offset (seconds east) in effect at `unixSeconds`. */
function zoneOffsetSeconds(timezone: string, unixSeconds: number): number {
  return partsAsUtcSeconds(zonedParts(timezone, unixSeconds)) - unixSeconds;
}

/**
 * The instant at which the wall clock in `timezone` reads exactly these
 * components, or `undefined` when that wall-clock time DOES NOT EXIST.
 *
 * Two passes: guess with the offset in effect at the naive instant, then
 * re-resolve with the offset actually in effect at the guess. That converges for
 * every real zone because offsets change by whole minutes and never twice within
 * one offset's own span.
 *
 * The existence check is the reason for the final round-trip. During a
 * spring-forward gap, 02:30 simply never happens; any instant we compute for it
 * reads back as 03:30, and returning that would silently fire a `30 2 * * *`
 * schedule an hour late on exactly one day a year. Returning `undefined` lets
 * the caller skip the slot instead, which is the honest answer for a wall-clock
 * time the calendar does not contain.
 *
 * Fall-back (a wall-clock time that happens TWICE) resolves to the FIRST
 * occurrence, because the two-pass converges on the pre-transition offset. That
 * is the conventional choice: the schedule fires at the first 01:30, not both.
 */
function wallClockToUnix(timezone: string, parts: ZonedParts): number | undefined {
  const naive = partsAsUtcSeconds(parts);
  const firstOffset = zoneOffsetSeconds(timezone, naive);
  let instant = naive - firstOffset;
  const secondOffset = zoneOffsetSeconds(timezone, instant);
  if (secondOffset !== firstOffset) instant = naive - secondOffset;
  const roundTrip = zonedParts(timezone, instant);
  if (
    roundTrip.year !== parts.year ||
    roundTrip.month !== parts.month ||
    roundTrip.day !== parts.day ||
    roundTrip.hour !== parts.hour ||
    roundTrip.minute !== parts.minute
  ) {
    return undefined;
  }
  return instant;
}

/** Days in a Gregorian month. */
function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/** Day of week (0 = Sunday) for a proleptic Gregorian date. */
function dayOfWeekFor(year: number, month: number, day: number): number {
  return new Date(Date.UTC(year, month - 1, day)).getUTCDay();
}

/**
 * Whether a calendar day matches the expression's day fields.
 *
 * The Vixie rule, and it is genuinely surprising if you have not met it: when
 * BOTH `day-of-month` and `day-of-week` are restricted, the day matches if
 * EITHER matches (a union, not an intersection). When only one is restricted,
 * only that one is consulted. `0 0 1 * MON` therefore fires on the 1st AND on
 * every Monday — which is what a crontab does, and what an operator copying one
 * in expects.
 */
function dayMatches(cron: CronExpression, year: number, month: number, day: number): boolean {
  const domRestricted = !cron.dayOfMonth.wildcard;
  const dowRestricted = !cron.dayOfWeek.wildcard;
  const domHit = cron.dayOfMonth.values.has(day);
  const dowHit = cron.dayOfWeek.values.has(dayOfWeekFor(year, month, day));
  if (domRestricted && dowRestricted) return domHit || dowHit;
  if (domRestricted) return domHit;
  if (dowRestricted) return dowHit;
  return true;
}

/**
 * How many years forward {@link computeNextCronFireAt} will search before
 * giving up. Four covers every leap-year-only expression (`0 0 29 2 *`); an
 * expression matching nothing at all (`0 0 30 2 *` — February 30th) then fails
 * loudly instead of looping.
 */
const CRON_SEARCH_YEARS = 5;

/**
 * The next cron occurrence STRICTLY after `afterUnix`, evaluated as wall clock
 * in `timezone`.
 *
 * Timezone-aware rather than fixed-offset, so DST is honored: `0 2 * * *` in
 * `America/New_York` fires at 02:00 local on both sides of a transition, not at
 * a fixed UTC hour that drifts by one every spring.
 *
 * Throws a {@link ScheduleError}-carrying `StorageError` for an unknown zone, an
 * unparseable expression, an unrepresentable timestamp, or an expression that
 * matches no date within {@link CRON_SEARCH_YEARS}.
 */
export function computeNextCronFireAt(
  cronExpr: string,
  timezone: string,
  afterUnix: number,
): number {
  if (!Number.isFinite(afterUnix) || Math.abs(afterUnix) > 8.64e12) {
    throw scheduleStorageError({ kind: "invalid_timestamp", timestamp: afterUnix });
  }
  let cron: CronExpression;
  try {
    cron = parseCronExpression(cronExpr);
  } catch (error) {
    throw scheduleStorageError({
      kind: "invalid_cron",
      message: error instanceof Error ? error.message : String(error),
    });
  }
  let start: ZonedParts;
  try {
    start = zonedParts(timezone, afterUnix);
  } catch {
    throw scheduleStorageError({ kind: "invalid_timezone", timezone });
  }

  // Search from the minute AFTER the anchor: the contract is "strictly after",
  // so a schedule that just fired at its own slot must not re-select it.
  let { year, month, day, hour, minute } = start;
  minute += 1;
  if (minute > 59) {
    minute = 0;
    hour += 1;
  }
  if (hour > 23) {
    hour = 0;
    day += 1;
  }
  const endYear = start.year + CRON_SEARCH_YEARS;

  while (year <= endYear) {
    if (day > daysInMonth(year, month)) {
      day = 1;
      month += 1;
      hour = 0;
      minute = 0;
      if (month > 12) {
        month = 1;
        year += 1;
      }
      continue;
    }
    if (!cron.month.values.has(month)) {
      month += 1;
      day = 1;
      hour = 0;
      minute = 0;
      if (month > 12) {
        month = 1;
        year += 1;
      }
      continue;
    }
    if (!dayMatches(cron, year, month, day)) {
      day += 1;
      hour = 0;
      minute = 0;
      continue;
    }
    if (!cron.hour.values.has(hour)) {
      hour += 1;
      minute = 0;
      if (hour > 23) {
        hour = 0;
        day += 1;
      }
      continue;
    }
    if (!cron.minute.values.has(minute)) {
      minute += 1;
      if (minute > 59) {
        minute = 0;
        hour += 1;
        if (hour > 23) {
          hour = 0;
          day += 1;
        }
      }
      continue;
    }
    const instant = wallClockToUnix(timezone, { year, month, day, hour, minute, second: 0 });
    // `undefined` = this wall-clock minute does not exist (spring-forward gap).
    // Skip it rather than firing an hour late; see `wallClockToUnix`.
    if (instant !== undefined && instant > afterUnix) return instant;
    minute += 1;
    if (minute > 59) {
      minute = 0;
      hour += 1;
      if (hour > 23) {
        hour = 0;
        day += 1;
      }
    }
  }
  throw scheduleStorageError({
    kind: "invalid_cron",
    message: `no occurrence within ${CRON_SEARCH_YEARS} years of the anchor`,
  });
}

/**
 * The next fire time strictly after `afterUnix` for one schedule.
 *
 * `undefined` ONLY for an interval schedule with a non-positive interval — an
 * invalid definition that must never fire. It is not an error: a schedule with a
 * broken interval is left unscheduled (`next_fire_at_unix = NULL`), which the
 * due query then skips, rather than throwing on every tick forever.
 */
export function computeNextFireAt(
  schedule: Pick<StoredAgentSchedule, "specKind" | "cronExpr" | "timezone" | "intervalSecs">,
  afterUnix: number,
): number | undefined {
  if (schedule.specKind === "cron") {
    const expr = schedule.cronExpr;
    if (expr === undefined || expr.trim() === "") {
      throw scheduleStorageError({ kind: "missing_cron_expr" });
    }
    return computeNextCronFireAt(expr, schedule.timezone, afterUnix);
  }
  const interval = schedule.intervalSecs ?? 0;
  if (interval <= 0) return undefined;
  return afterUnix + interval;
}

// ---------------------------------------------------------------------------
// The tick decision
// ---------------------------------------------------------------------------

/**
 * Hard cap on catch-up iterations when fast-forwarding past a long outage, so
 * advancing an every-minute schedule after extended downtime cannot spin
 * unbounded. Beyond it the walk jumps straight to the first slot after `now`.
 */
export const SCHEDULER_CATCHUP_ITER_CAP = 10_000;

/** What one tick decided to do with one due schedule. */
export type ScheduleTickAction =
  /** `nextFireAtUnix` is unset or still in the future — nothing to do. */
  | { kind: "not_due" }
  /**
   * Claim `slot` and run the target. `advanceTo` is the schedule's new
   * `next_fire_at_unix` (`undefined` = leave it unscheduled).
   */
  | { kind: "fire"; slot: number; advanceTo: number | undefined }
  /**
   * Do NOT run the target; still record a fire row with `outcome` and advance.
   * `skipped_overlap` records evidence that a slot was deliberately dropped;
   * `skip_missed` catch-up records nothing (Rust does not either) and is
   * reported as {@link ScheduleTickAction} `advance_only`.
   */
  | {
      kind: "record_skip";
      slot: number;
      outcome: ScheduleFireOutcome;
      advanceTo: number | undefined;
    }
  /** Fast-forward past a missed slot without firing and without evidence. */
  | { kind: "advance_only"; slot: number; advanceTo: number | undefined };

/**
 * The pure tick decision for ONE due schedule (ports `fire_due_schedule` minus
 * its I/O), in the Rust order — which is observable, because it decides whether
 * a catch-up slot is even considered for the overlap check.
 *
 * `previousDispatchUnacked` answers "is the dispatch from `lastFireAtUnix` still
 * in flight". It is a parameter and not a lookup because the answer lives in the
 * lease queue, which is not this package's business; the caller supplies it.
 *
 * The two policies, and why each defaults the way it does:
 *
 *  - `catchupPolicy = skip_missed` (default): a slot is a CATCH-UP when the slot
 *    after it has ALSO already elapsed — i.e. we are behind, not merely on time.
 *    Missed slots are fast-forwarded without firing (n8n semantics). Firing them
 *    all would turn an hour of downtime into an hour of agent runs charged at
 *    once. `fire_once` fires a single catch-up for the most recent missed slot.
 *  - `overlapPolicy = skip` (default): suppress a fire while the previous
 *    dispatch is unacked, which is what stops a schedule slower than its own
 *    period from piling up. The suppression IS recorded as a
 *    `skipped_overlap` fire row, so the slot is still consumed and an operator
 *    can see why nothing ran.
 *
 * In every branch the schedule advances past `now`, including the failure ones.
 * A slot that is not advanced past is re-selected on the very next tick, so a
 * schedule whose target keeps failing would re-fire forever.
 */
export function planScheduleTick(
  schedule: StoredAgentSchedule,
  nowUnix: number,
  previousDispatchUnacked: (dispatchId: string) => boolean,
): ScheduleTickAction {
  const slot = schedule.nextFireAtUnix;
  if (slot === undefined || slot > nowUnix) return { kind: "not_due" };

  const advanceTo = advanceSchedulePastNow(schedule, slot, nowUnix);

  // Are we catching up? True when the slot AFTER the due one has itself already
  // elapsed — that is what distinguishes "behind" from "on time".
  let isCatchup = false;
  try {
    const following = computeNextFireAt(schedule, slot);
    isCatchup = following !== undefined && following <= nowUnix;
  } catch {
    // An unparseable definition is not a catch-up; it is handled by the advance
    // walk, which leaves the schedule unscheduled.
    isCatchup = false;
  }

  if (isCatchup && schedule.catchupPolicy === "skip_missed") {
    return { kind: "advance_only", slot, advanceTo };
  }

  if (schedule.overlapPolicy === "skip" && schedule.lastFireAtUnix !== undefined) {
    const previousDispatch = scheduledDispatchId(schedule.scheduleId, schedule.lastFireAtUnix);
    if (previousDispatchUnacked(previousDispatch)) {
      return { kind: "record_skip", slot, outcome: "skipped_overlap", advanceTo };
    }
  }

  return { kind: "fire", slot, advanceTo };
}

/**
 * The schedule's new `next_fire_at_unix` after firing `slot` (ports
 * `advance_schedule_past_now`).
 *
 * Walks forward slot by slot from the fired one. On-time firing converges in a
 * single step. A short catch-up takes a few. Past
 * {@link SCHEDULER_CATCHUP_ITER_CAP} the walk stops and jumps directly to the
 * first slot after `now`, because iterating from a far-past anchor on an
 * every-minute schedule would otherwise need millions of steps — and the whole
 * point of advancing is to stop being behind.
 *
 * `undefined` means "leave this schedule unscheduled": an invalid interval, or a
 * definition whose next fire cannot be computed at all. Unscheduled is the
 * fail-safe direction — the due query skips it, so a broken definition stops
 * firing rather than firing wrongly.
 */
export function advanceSchedulePastNow(
  schedule: StoredAgentSchedule,
  slot: number,
  nowUnix: number,
): number | undefined {
  let cursor = slot;
  for (let step = 0; step < SCHEDULER_CATCHUP_ITER_CAP; step += 1) {
    let candidate: number | undefined;
    try {
      candidate = computeNextFireAt(schedule, cursor);
    } catch {
      return undefined;
    }
    if (candidate === undefined) return undefined;
    if (candidate > nowUnix) return candidate;
    cursor = candidate;
  }
  try {
    return computeNextFireAt(schedule, nowUnix);
  } catch {
    return undefined;
  }
}

/**
 * Validate a schedule definition at write time (ports the Rust admin-API
 * guards). Returns the human message for the FIRST problem, or `undefined`.
 *
 * Rejecting at write time rather than at fire time is the point: a schedule that
 * only reveals its broken cron expression on the tick that should have fired it
 * fails silently in a background loop nobody is watching.
 */
export function validateAgentSchedule(schedule: StoredAgentSchedule): string | undefined {
  if (schedule.scheduleId.trim() === "") return "schedule_id must not be empty";
  if (schedule.name.trim() === "") return "name must not be empty";
  if (schedule.jitterSecs < 0) return "jitter_secs must not be negative";
  if (schedule.specKind === "cron") {
    const expr = schedule.cronExpr;
    if (expr === undefined || expr.trim() === "") {
      return scheduleErrorMessage({ kind: "missing_cron_expr" });
    }
    try {
      parseCronExpression(expr);
    } catch (error) {
      return scheduleErrorMessage({
        kind: "invalid_cron",
        message: error instanceof Error ? error.message : String(error),
      });
    }
    try {
      zoneFormatter(schedule.timezone);
    } catch {
      return scheduleErrorMessage({ kind: "invalid_timezone", timezone: schedule.timezone });
    }
  } else if ((schedule.intervalSecs ?? 0) <= 0) {
    return "interval_secs must be greater than zero for an interval schedule";
  }
  try {
    JSON.parse(schedule.targetJson);
  } catch (error) {
    return `agent schedule target_json is not valid JSON: ${
      error instanceof Error ? error.message : String(error)
    }`;
  }
  return undefined;
}
