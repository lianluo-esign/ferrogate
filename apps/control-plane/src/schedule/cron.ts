/**
 * Cron parsing and IANA-timezone-aware next-occurrence computation.
 *
 * The TS half of `crates/ferrogate-storage/src/agent_schedule.rs`'s
 * `compute_next_cron_fire_at`, which is `croner` + `chrono-tz`. Neither has a
 * Workers equivalent worth pulling in: `Intl.DateTimeFormat` in workerd carries
 * the full ICU timezone database, so the timezone half is native, and the cron
 * half is ~150 lines of set membership. Re-implemented clean-room from the
 * behaviour the Rust tests pin (see `test/schedule-cron.test.ts`, which carries
 * the same four cases with the same expected instants).
 *
 * ## What is accepted
 *
 * Standard **five**-field cron — `minute hour day-of-month month day-of-week` —
 * plus the Vixie nicknames (`@hourly`, `@daily`, …). Seconds are NOT a field:
 * `croner`'s default in Rust is seconds-off, and silently reinterpreting a
 * 5-field expression as 6 would shift every operator's schedule by a factor of
 * sixty in the wrong direction.
 *
 * Per field: `*`, `?` (= `*`), a literal, `a-b`, `a,b,c`, a step (`n` after a
 * slash, applied to `*` or to a range), and
 * three-letter month (`JAN`..`DEC`) / weekday (`SUN`..`SAT`) names. `7` is
 * Sunday as well as `0`, which is the POSIX rule.
 *
 * ## Day-of-month vs day-of-week
 *
 * When BOTH are restricted the day matches if **either** does (Vixie/POSIX
 * semantics; `croner`'s `dom_and_dow = false` default, which is what Rust runs).
 * `0 0 1 * MON` therefore fires on the 1st *and* on every Monday, not on the
 * intersection. This is the single most commonly inverted cron rule, so it is
 * stated here and pinned by a test.
 *
 * ## Why the search runs in wall-clock space
 *
 * A schedule's meaning is a LOCAL wall-clock time: `0 3 * * *` in
 * `America/New_York` means 03:00 as the operator's clock reads it, on both
 * sides of a DST transition, which is a different UTC instant each side. So the
 * search advances local civil fields and converts to an instant only once a
 * candidate matches. Converting first and testing after would pin the UTC
 * offset of whichever side the search started on.
 *
 * DST edge cases, both deliberate:
 *  - **Spring-forward gap** (02:30 does not exist): the slot is SKIPPED, and
 *    the search continues to the next matching wall clock. Firing it anyway
 *    would mean inventing an instant, and clamping it to 03:00 would silently
 *    merge two different schedules onto one instant.
 *  - **Fall-back overlap** (01:30 happens twice): the FIRST (pre-transition)
 *    instant is taken, so an hourly-or-coarser schedule fires once per wall
 *    clock rather than twice.
 */

/** Failure modes of next-fire computation. Mirrors Rust `ScheduleError`. */
export type ScheduleErrorKind =
  | "invalid_timezone"
  | "invalid_cron"
  | "invalid_timestamp"
  | "missing_cron_expr";

/** Rust `ScheduleError` — a typed refusal, never a silently-wrong fire time. */
export class ScheduleError extends Error {
  override readonly name = "ScheduleError";
  readonly kind: ScheduleErrorKind;

  constructor(kind: ScheduleErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }

  static invalidTimezone(timezone: string): ScheduleError {
    return new ScheduleError("invalid_timezone", `invalid IANA timezone '${timezone}'`);
  }

  static invalidCron(detail: string): ScheduleError {
    return new ScheduleError("invalid_cron", `invalid cron expression: ${detail}`);
  }

  static invalidTimestamp(value: number): ScheduleError {
    return new ScheduleError("invalid_timestamp", `unrepresentable unix timestamp ${value}`);
  }

  static missingCronExpr(): ScheduleError {
    return new ScheduleError("missing_cron_expr", "cron schedule is missing its cron expression");
  }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/** A parsed 5-field cron expression, as explicit sets of matching values. */
export interface CronPattern {
  readonly minutes: ReadonlySet<number>;
  readonly hours: ReadonlySet<number>;
  readonly daysOfMonth: ReadonlySet<number>;
  readonly months: ReadonlySet<number>;
  /** 0 = Sunday .. 6 = Saturday. `7` is normalized onto `0`. */
  readonly daysOfWeek: ReadonlySet<number>;
  /** `true` when the day-of-month field was NOT `*`/`?` (Vixie OR rule). */
  readonly domRestricted: boolean;
  /** `true` when the day-of-week field was NOT `*`/`?` (Vixie OR rule). */
  readonly dowRestricted: boolean;
}

const MONTH_NAMES: Readonly<Record<string, number>> = {
  JAN: 1,
  FEB: 2,
  MAR: 3,
  APR: 4,
  MAY: 5,
  JUN: 6,
  JUL: 7,
  AUG: 8,
  SEP: 9,
  OCT: 10,
  NOV: 11,
  DEC: 12,
};

const WEEKDAY_NAMES: Readonly<Record<string, number>> = {
  SUN: 0,
  MON: 1,
  TUE: 2,
  WED: 3,
  THU: 4,
  FRI: 5,
  SAT: 6,
};

/** Vixie nicknames, expanded to their canonical 5-field form. */
const NICKNAMES: Readonly<Record<string, string>> = {
  "@yearly": "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
  "@monthly": "0 0 1 * *",
  "@weekly": "0 0 * * 0",
  "@daily": "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@hourly": "0 * * * *",
};

interface FieldSpec {
  readonly name: string;
  readonly min: number;
  readonly max: number;
  readonly names?: Readonly<Record<string, number>>;
}

function parseFieldValue(token: string, field: FieldSpec): number {
  const upper = token.toUpperCase();
  const named = field.names?.[upper];
  if (named !== undefined) return named;
  if (!/^\d+$/.test(token)) {
    throw ScheduleError.invalidCron(`field '${field.name}' has invalid value '${token}'`);
  }
  const value = Number.parseInt(token, 10);
  // POSIX: 7 is Sunday as well as 0. Normalized before the range check so the
  // declared max stays 6 and `8` is still an error.
  const normalized = field.name === "day-of-week" && value === 7 ? 0 : value;
  if (normalized < field.min || normalized > field.max) {
    throw ScheduleError.invalidCron(
      `field '${field.name}' value ${value} is outside ${field.min}-${field.max}`,
    );
  }
  return normalized;
}

/** Parse one cron field into the explicit set of values it matches. */
function parseField(raw: string, field: FieldSpec): { values: Set<number>; restricted: boolean } {
  const values = new Set<number>();
  let restricted = false;

  for (const part of raw.split(",")) {
    const token = part.trim();
    if (token === "") {
      throw ScheduleError.invalidCron(`field '${field.name}' has an empty list element`);
    }

    const [rangePart, stepPart, ...extra] = token.split("/");
    if (extra.length > 0 || rangePart === undefined) {
      throw ScheduleError.invalidCron(`field '${field.name}' has a malformed step in '${token}'`);
    }

    let step = 1;
    if (stepPart !== undefined) {
      if (!/^\d+$/.test(stepPart)) {
        throw ScheduleError.invalidCron(`field '${field.name}' has invalid step '${stepPart}'`);
      }
      step = Number.parseInt(stepPart, 10);
      if (step === 0) {
        throw ScheduleError.invalidCron(`field '${field.name}' has a zero step`);
      }
    }

    let start: number;
    let end: number;
    if (rangePart === "*" || rangePart === "?") {
      start = field.min;
      end = field.max;
    } else if (rangePart.includes("-")) {
      const [lowRaw, highRaw, ...rest] = rangePart.split("-");
      if (rest.length > 0 || lowRaw === undefined || highRaw === undefined) {
        throw ScheduleError.invalidCron(`field '${field.name}' has a malformed range '${token}'`);
      }
      start = parseFieldValue(lowRaw, field);
      end = parseFieldValue(highRaw, field);
      if (end < start) {
        throw ScheduleError.invalidCron(
          `field '${field.name}' range '${rangePart}' ends before it starts`,
        );
      }
      restricted = true;
    } else {
      start = parseFieldValue(rangePart, field);
      // A bare literal with a step (`5/15`) means "from 5 to the field max",
      // which is what every cron implementation does.
      end = stepPart === undefined ? start : field.max;
      restricted = true;
    }

    for (let value = start; value <= end; value += step) values.add(value);
  }

  if (values.size === 0) {
    throw ScheduleError.invalidCron(`field '${field.name}' matches nothing`);
  }
  return { values, restricted };
}

const FIELDS: readonly FieldSpec[] = [
  { name: "minute", min: 0, max: 59 },
  { name: "hour", min: 0, max: 23 },
  { name: "day-of-month", min: 1, max: 31 },
  { name: "month", min: 1, max: 12, names: MONTH_NAMES },
  { name: "day-of-week", min: 0, max: 6, names: WEEKDAY_NAMES },
];

/**
 * Parse a 5-field cron expression (or a Vixie nickname).
 *
 * @throws {ScheduleError} `invalid_cron` for anything else. Refusing here is
 * the point: an unparseable expression accepted at write time becomes a
 * schedule that silently never fires, which is exactly the failure this whole
 * module exists to remove.
 */
export function parseCronExpression(expression: string): CronPattern {
  const trimmed = expression.trim();
  if (trimmed === "") throw ScheduleError.invalidCron("expression is empty");

  const expanded = NICKNAMES[trimmed.toLowerCase()] ?? trimmed;
  if (expanded.startsWith("@")) {
    throw ScheduleError.invalidCron(`unknown nickname '${trimmed}'`);
  }

  const fields = expanded.split(/\s+/);
  if (fields.length !== FIELDS.length) {
    throw ScheduleError.invalidCron(
      `expected ${FIELDS.length} fields (minute hour day-of-month month day-of-week), got ${fields.length}`,
    );
  }

  const parsed = fields.map((raw, index) => {
    const field = FIELDS[index];
    if (field === undefined) throw ScheduleError.invalidCron("field index out of range");
    return parseField(raw, field);
  });

  const [minute, hour, dom, month, dow] = parsed;
  if (
    minute === undefined ||
    hour === undefined ||
    dom === undefined ||
    month === undefined ||
    dow === undefined
  ) {
    throw ScheduleError.invalidCron("field parse produced no result");
  }

  return {
    minutes: minute.values,
    hours: hour.values,
    daysOfMonth: dom.values,
    months: month.values,
    daysOfWeek: dow.values,
    domRestricted: dom.restricted,
    dowRestricted: dow.restricted,
  };
}

// ---------------------------------------------------------------------------
// Timezone conversion
// ---------------------------------------------------------------------------

/** Civil (wall-clock) fields, with no timezone attached. */
interface CivilTime {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
}

const formatterCache = new Map<string, Intl.DateTimeFormat>();

/**
 * A formatter pinned to `timeZone`, cached per isolate.
 *
 * @throws {ScheduleError} `invalid_timezone` — `Intl` throws `RangeError` for an
 * unknown zone, and the ICU database in workerd is the same one the runtime
 * uses everywhere else, so this IS the validity check. There is no zone list to
 * hand-maintain and drift.
 */
function zonedFormatter(timeZone: string): Intl.DateTimeFormat {
  const cached = formatterCache.get(timeZone);
  if (cached !== undefined) return cached;
  let formatter: Intl.DateTimeFormat;
  try {
    formatter = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      era: "short",
    });
  } catch {
    throw ScheduleError.invalidTimezone(timeZone);
  }
  formatterCache.set(timeZone, formatter);
  return formatter;
}

/** Assert a timezone is a real IANA zone. Used by write-path validation. */
export function assertValidTimezone(timeZone: string): void {
  zonedFormatter(timeZone);
}

/** The wall-clock fields `unixSeconds` reads as in `timeZone`. */
function zonedCivilTime(unixSeconds: number, timeZone: string): CivilTime {
  const parts = zonedFormatter(timeZone).formatToParts(new Date(unixSeconds * 1000));
  const bag: Record<string, string> = {};
  for (const part of parts) bag[part.type] = part.value;

  const year = Number.parseInt(bag.year ?? "", 10);
  const month = Number.parseInt(bag.month ?? "", 10);
  const day = Number.parseInt(bag.day ?? "", 10);
  const hour = Number.parseInt(bag.hour ?? "", 10);
  const minute = Number.parseInt(bag.minute ?? "", 10);
  if (
    !Number.isFinite(year) ||
    !Number.isFinite(month) ||
    !Number.isFinite(day) ||
    !Number.isFinite(hour) ||
    !Number.isFinite(minute)
  ) {
    throw ScheduleError.invalidTimestamp(unixSeconds);
  }
  // `era: "short"` makes a BC instant render as "1 BC"; those cannot be a fire
  // time and would otherwise silently become year 1 AD.
  const signedYear = (bag.era ?? "AD").toUpperCase().startsWith("B") ? 1 - year : year;
  return { year: signedYear, month, day, hour, minute };
}

/** Civil fields as if they were UTC — the anchor both offset passes use. */
function civilAsUtcSeconds(civil: CivilTime): number {
  const ms = Date.UTC(civil.year, civil.month - 1, civil.day, civil.hour, civil.minute, 0, 0);
  // `Date.UTC` maps years 0-99 onto 1900-1999; schedules are never in that
  // range, but doing it silently would be a bug that only appears in a fixture.
  if (civil.year >= 0 && civil.year <= 99) {
    const corrected = new Date(ms);
    corrected.setUTCFullYear(civil.year);
    return Math.floor(corrected.getTime() / 1000);
  }
  return Math.floor(ms / 1000);
}

/** Seconds east of UTC that `timeZone` was at the instant `unixSeconds`. */
function zoneOffsetSeconds(unixSeconds: number, timeZone: string): number {
  return civilAsUtcSeconds(zonedCivilTime(unixSeconds, timeZone)) - unixSeconds;
}

/**
 * The UTC instant at which `timeZone`'s clock reads `civil`, or `null` when it
 * never does (the spring-forward gap).
 *
 * Two passes, which is the standard fixed-point for this: guess with the offset
 * at the naive instant, then re-derive the offset at the guess. A third pass
 * cannot change the answer for any real zone, and the round-trip check below is
 * what actually decides correctness rather than the pass count.
 */
function civilToInstant(civil: CivilTime, timeZone: string): number | null {
  const naive = civilAsUtcSeconds(civil);
  const firstGuess = naive - zoneOffsetSeconds(naive, timeZone);
  const candidate = naive - zoneOffsetSeconds(firstGuess, timeZone);

  // The gap check. Inside a spring-forward gap every candidate round-trips to a
  // DIFFERENT wall clock than the one asked for, because the requested one does
  // not exist. Returning it anyway would fire a schedule at a time the operator
  // never wrote.
  const roundTrip = zonedCivilTime(candidate, timeZone);
  if (
    roundTrip.year !== civil.year ||
    roundTrip.month !== civil.month ||
    roundTrip.day !== civil.day ||
    roundTrip.hour !== civil.hour ||
    roundTrip.minute !== civil.minute
  ) {
    return null;
  }

  // Fall-back overlap: the same wall clock exists twice. `firstGuess` is derived
  // from the PRE-transition offset, so prefer it when it also round-trips —
  // that makes an ambiguous slot fire once, at its first occurrence.
  if (firstGuess < candidate) {
    const alternate = zonedCivilTime(firstGuess, timeZone);
    if (
      alternate.year === civil.year &&
      alternate.month === civil.month &&
      alternate.day === civil.day &&
      alternate.hour === civil.hour &&
      alternate.minute === civil.minute
    ) {
      return firstGuess;
    }
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// Civil arithmetic
// ---------------------------------------------------------------------------

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function dayOfWeek(civil: CivilTime): number {
  return new Date(Date.UTC(civil.year, civil.month - 1, civil.day)).getUTCDay();
}

function addMinute(civil: CivilTime): void {
  civil.minute += 1;
  if (civil.minute < 60) return;
  civil.minute = 0;
  addHour(civil);
}

function addHour(civil: CivilTime): void {
  civil.hour += 1;
  if (civil.hour < 24) return;
  civil.hour = 0;
  addDay(civil);
}

function addDay(civil: CivilTime): void {
  civil.day += 1;
  if (civil.day <= daysInMonth(civil.year, civil.month)) return;
  civil.day = 1;
  addMonth(civil);
}

function addMonth(civil: CivilTime): void {
  civil.month += 1;
  if (civil.month <= 12) return;
  civil.month = 1;
  civil.year += 1;
}

/**
 * How far ahead the search will look before declaring an expression unfireable.
 *
 * Four years covers every leap-year-dependent expression (`0 0 29 2 *` fires at
 * least once in any four-year window). Beyond it the expression matches no real
 * date — `0 0 31 2 *` — and the honest answer is a refusal, not a hang.
 */
const MAX_SEARCH_YEARS = 4;

/**
 * The next instant strictly after `afterUnix` at which `cronExpr` fires, read
 * in `timeZone`. Rust `compute_next_cron_fire_at`.
 *
 * @throws {ScheduleError} for an invalid expression, an unknown zone, an
 * unrepresentable timestamp, or an expression with no occurrence inside
 * {@link MAX_SEARCH_YEARS}.
 */
export function nextCronOccurrence(cronExpr: string, timeZone: string, afterUnix: number): number {
  if (!Number.isFinite(afterUnix) || !Number.isSafeInteger(afterUnix)) {
    throw ScheduleError.invalidTimestamp(afterUnix);
  }
  const pattern = parseCronExpression(cronExpr);
  const cursor = zonedCivilTime(afterUnix, timeZone);
  const deadlineYear = cursor.year + MAX_SEARCH_YEARS;

  // Strictly after: truncate to the minute, then step one minute on. A caller
  // sitting exactly on a matching boundary therefore gets the NEXT slot, never
  // the one it is already standing on — re-firing the current slot forever is
  // the classic scheduler livelock.
  addMinute(cursor);

  // Bounded by construction: each iteration advances at least a minute, and
  // non-matching months/days/hours skip whole units, so the realistic count is
  // in the hundreds. The cap only has to make a pathological expression
  // terminate.
  for (let guard = 0; guard < 5_000_000; guard += 1) {
    if (cursor.year > deadlineYear) {
      throw ScheduleError.invalidCron(
        `expression '${cronExpr}' has no occurrence within ${MAX_SEARCH_YEARS} years`,
      );
    }
    if (!pattern.months.has(cursor.month)) {
      cursor.day = 1;
      cursor.hour = 0;
      cursor.minute = 0;
      addMonth(cursor);
      continue;
    }
    if (!dayMatches(pattern, cursor)) {
      cursor.hour = 0;
      cursor.minute = 0;
      addDay(cursor);
      continue;
    }
    if (!pattern.hours.has(cursor.hour)) {
      cursor.minute = 0;
      addHour(cursor);
      continue;
    }
    if (!pattern.minutes.has(cursor.minute)) {
      addMinute(cursor);
      continue;
    }

    const instant = civilToInstant(cursor, timeZone);
    // `null` = the spring-forward gap; `<= afterUnix` = a repeated wall clock
    // in the fall-back overlap whose first occurrence is already behind us.
    if (instant !== null && instant > afterUnix) return instant;
    addMinute(cursor);
  }
  throw ScheduleError.invalidCron(`expression '${cronExpr}' did not converge on a next occurrence`);
}

/**
 * Vixie/POSIX day matching: when both day fields are restricted the day matches
 * if EITHER does. See the module docblock.
 */
function dayMatches(pattern: CronPattern, civil: CivilTime): boolean {
  const domHit = pattern.daysOfMonth.has(civil.day);
  const dowHit = pattern.daysOfWeek.has(dayOfWeek(civil));
  if (pattern.domRestricted && pattern.dowRestricted) return domHit || dowHit;
  if (pattern.domRestricted) return domHit;
  if (pattern.dowRestricted) return dowHit;
  return true;
}
