/**
 * The cron + IANA-timezone engine (`src/schedule/cron.ts`, `src/schedule/model.ts`).
 *
 * The first four cases are the Rust tests from
 * `crates/ferrogate-storage/src/agent_schedule.rs` transcribed with the SAME
 * input timestamps and the SAME expected instants — a clean-room
 * re-implementation is only proven by agreeing with the original on the exact
 * numbers, not by being internally consistent. Everything after them covers
 * ground `croner` gave Rust for free and this port had to write.
 */
import { describe, expect, it } from "vitest";
import {
  ScheduleError,
  assertValidTimezone,
  nextCronOccurrence,
  parseCronExpression,
} from "../src/schedule/cron.js";
import {
  ScheduleSpecError,
  advanceNextFireAt,
  agentScheduleFireId,
  computeNextFireAt,
  isCatchupFire,
  manualScheduleFireId,
  normalizeScheduleSpec,
  scheduleJitterOffset,
  scheduledDispatchId,
} from "../src/schedule/model.js";
import type { AgentScheduleSpec } from "../src/schedule/model.js";

function cronSpec(cronExpr: string, timezone = "UTC"): AgentScheduleSpec {
  return {
    spec_kind: "cron",
    cron_expr: cronExpr,
    timezone,
    interval_secs: null,
    target_kind: "self_hosted_dispatch",
    overlap_policy: "skip",
    catchup_policy: "skip_missed",
    jitter_secs: 0,
    enabled: true,
  };
}

const iso = (unix: number) => new Date(unix * 1000).toISOString();

describe("Rust parity — the four pinned cases from agent_schedule.rs", () => {
  it("cron_every_minute_advances_to_next_minute_boundary", () => {
    // 2026-01-01T00:00:30Z -> next `*/1 * * * *` slot is 00:01:00Z.
    const next = nextCronOccurrence("*/1 * * * *", "UTC", 1_767_225_630);
    expect(next).toBe(1_767_225_660);
    expect(next % 60).toBe(0);
  });

  it("cron_daily_utc_fires_at_configured_hour", () => {
    const next = nextCronOccurrence("0 2 * * *", "UTC", 1_767_225_600);
    expect(iso(next)).toBe("2026-01-01T02:00:00.000Z");
  });

  it("cron_respects_iana_timezone_offset", () => {
    // Local midnight in America/New_York on 2026-01-16 is 05:00Z (EST, UTC-5).
    const next = nextCronOccurrence("0 0 * * *", "America/New_York", 1_768_460_400);
    expect(iso(next)).toBe("2026-01-16T05:00:00.000Z");
  });

  it("cron_dst_spring_forward_keeps_wall_clock_hour", () => {
    // The whole point of doing the search in wall-clock space: `0 3 * * *` in
    // America/New_York is 03:00 LOCAL on both sides of the 2026-03-08
    // transition, so the UTC instant moves by an hour and the hour on the
    // operator's clock does not.
    expect(iso(nextCronOccurrence("0 3 * * *", "America/New_York", 1_772_798_400))).toBe(
      "2026-03-07T08:00:00.000Z",
    );
    expect(iso(nextCronOccurrence("0 3 * * *", "America/New_York", 1_773_057_600))).toBe(
      "2026-03-10T07:00:00.000Z",
    );
  });

  it("invalid_timezone_and_cron_are_rejected", () => {
    expect(() => nextCronOccurrence("0 2 * * *", "Not/AZone", 0)).toThrow(ScheduleError);
    expect(() => nextCronOccurrence("0 2 * * *", "Not/AZone", 0)).toThrow(/invalid IANA timezone/);
    expect(() => nextCronOccurrence("not a cron", "UTC", 0)).toThrow(/invalid cron expression/);
  });

  it("fire_id_is_deterministic_and_slot_specific", () => {
    expect(agentScheduleFireId("sched-1", 1_767_225_660)).toBe(
      agentScheduleFireId("sched-1", 1_767_225_660),
    );
    expect(agentScheduleFireId("sched-1", 1_767_225_660)).not.toBe(
      agentScheduleFireId("sched-1", 1_767_225_720),
    );
    // The length prefix is what stops a crafted schedule id aliasing another
    // schedule's slot and silently suppressing its fire.
    expect(agentScheduleFireId("a", 0)).not.toBe(agentScheduleFireId("a:0", 0));
  });

  it("schedule_compute_next_fire_at dispatches by spec kind", () => {
    expect(computeNextFireAt(cronSpec("0 2 * * *"), 1_767_225_600)).toBe(1_767_232_800);
    expect(
      computeNextFireAt(
        { ...cronSpec("0 2 * * *"), spec_kind: "interval", interval_secs: 300 },
        1_000,
      ),
    ).toBe(1_300);
  });

  it("interval_non_positive_never_fires", () => {
    for (const interval of [0, -30]) {
      expect(
        computeNextFireAt(
          { ...cronSpec("0 2 * * *"), spec_kind: "interval", interval_secs: interval },
          1_000,
        ),
      ).toBeNull();
    }
  });
});

describe("cron field grammar", () => {
  it("expands the Vixie nicknames", () => {
    // 2026-01-01T00:30:00Z.
    const at = 1_767_227_400;
    expect(iso(nextCronOccurrence("@hourly", "UTC", at))).toBe("2026-01-01T01:00:00.000Z");
    expect(iso(nextCronOccurrence("@daily", "UTC", at))).toBe("2026-01-02T00:00:00.000Z");
    expect(iso(nextCronOccurrence("@monthly", "UTC", at))).toBe("2026-02-01T00:00:00.000Z");
    expect(iso(nextCronOccurrence("@yearly", "UTC", at))).toBe("2027-01-01T00:00:00.000Z");
  });

  it("rejects an unknown nickname rather than treating it as a field", () => {
    expect(() => parseCronExpression("@sometimes")).toThrow(/unknown nickname/);
  });

  it("accepts lists, ranges, steps and names", () => {
    const pattern = parseCronExpression("0,30 9-17/4 * JAN-MAR MON,WED");
    expect([...pattern.minutes].sort((a, b) => a - b)).toEqual([0, 30]);
    expect([...pattern.hours].sort((a, b) => a - b)).toEqual([9, 13, 17]);
    expect([...pattern.months].sort((a, b) => a - b)).toEqual([1, 2, 3]);
    expect([...pattern.daysOfWeek].sort((a, b) => a - b)).toEqual([1, 3]);
    expect(pattern.dowRestricted).toBe(true);
    expect(pattern.domRestricted).toBe(false);
  });

  it("normalizes 7 onto Sunday and still refuses 8", () => {
    expect([...parseCronExpression("0 0 * * 7").daysOfWeek]).toEqual([0]);
    expect(() => parseCronExpression("0 0 * * 8")).toThrow(/outside 0-6/);
  });

  it("refuses the wrong field count in both directions", () => {
    // 6 fields is the seconds-enabled dialect. Silently accepting it would
    // reinterpret every field by one position, so an operator's `0 0 3 * * *`
    // would fire hourly instead of daily.
    expect(() => parseCronExpression("0 0 3 * * *")).toThrow(/expected 5 fields/);
    expect(() => parseCronExpression("0 0 3 *")).toThrow(/expected 5 fields/);
  });

  it("refuses malformed pieces instead of silently matching everything", () => {
    expect(() => parseCronExpression("0 0 * * MONDAY")).toThrow(/invalid value/);
    expect(() => parseCronExpression("*/0 * * * *")).toThrow(/zero step/);
    expect(() => parseCronExpression("17-3 * * * *")).toThrow(/ends before it starts/);
    expect(() => parseCronExpression("60 * * * *")).toThrow(/outside 0-59/);
    expect(() => parseCronExpression("0 0 * * ")).toThrow(/expected 5 fields/);
  });

  it("treats ? as * (Quartz spelling operators paste in)", () => {
    expect(nextCronOccurrence("0 0 ? * ?", "UTC", 1_767_225_600)).toBe(
      nextCronOccurrence("0 0 * * *", "UTC", 1_767_225_600),
    );
  });
});

describe("day-of-month vs day-of-week is the Vixie OR, not the intersection", () => {
  it("fires on the 1st AND on every Monday when both fields are restricted", () => {
    // 2026-01-01 is a Thursday. `0 0 1 * MON` must hit Thu Jan 1 (dom) and then
    // Mon Jan 5 (dow). The intersection reading would skip Jan 1 entirely and
    // fire only on Mondays that fall on the 1st — roughly once a year.
    let cursor = 1_767_139_200; // 2025-12-31T00:00:00Z
    const hits: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      cursor = nextCronOccurrence("0 0 1 * MON", "UTC", cursor);
      hits.push(iso(cursor));
    }
    expect(hits).toEqual([
      "2026-01-01T00:00:00.000Z",
      "2026-01-05T00:00:00.000Z",
      "2026-01-12T00:00:00.000Z",
    ]);
  });

  it("uses only the restricted field when the other is *", () => {
    // 2026-01-01 is a Thursday, so the next Monday is the 5th.
    expect(iso(nextCronOccurrence("0 0 * * MON", "UTC", 1_767_225_600))).toBe(
      "2026-01-05T00:00:00.000Z",
    );
    expect(iso(nextCronOccurrence("0 0 15 * *", "UTC", 1_767_225_600))).toBe(
      "2026-01-15T00:00:00.000Z",
    );
  });
});

describe("DST edge cases", () => {
  it("SKIPS a wall-clock time that the spring-forward gap deletes", () => {
    // 2026-03-08, America/New_York jumps 02:00 -> 03:00. A `30 2 * * *`
    // schedule has no 02:30 that day at all, so the next fire is the following
    // day's 02:30 EDT (= 06:30Z). Inventing an instant for a time the clock
    // never shows would fire a schedule the operator never wrote.
    const from = Math.floor(Date.UTC(2026, 2, 8, 0, 0, 0) / 1000); // 2026-03-08T00:00:00Z
    const next = nextCronOccurrence("30 2 * * *", "America/New_York", from);
    expect(iso(next)).toBe("2026-03-09T06:30:00.000Z");
  });

  it("fires ONCE, at the first instant, for a wall clock the fall-back repeats", () => {
    // 2026-11-01, America/New_York repeats 01:00-02:00. `30 1 * * *` must fire
    // once, at the EDT (first) occurrence 05:30Z — not twice.
    const from = Math.floor(Date.UTC(2026, 10, 1, 0, 0, 0) / 1000);
    const first = nextCronOccurrence("30 1 * * *", "America/New_York", from);
    expect(iso(first)).toBe("2026-11-01T05:30:00.000Z");
    // The very next occurrence is the NEXT DAY, not the repeated 01:30 EST.
    const second = nextCronOccurrence("30 1 * * *", "America/New_York", first);
    expect(iso(second)).toBe("2026-11-02T06:30:00.000Z");
  });

  it("keeps a southern-hemisphere zone's transition straight too", () => {
    // Australia/Sydney runs DST the other way round; a zone-agnostic bug that
    // happened to work for the US would show up here.
    // Sydney enters AEDT on 2026-10-04. `0 12 * * *` is local noon on both
    // sides: 02:00Z under AEST (UTC+10), then 01:00Z under AEDT (UTC+11) — the
    // offset moves the OTHER way from the US case, so a hard-coded sign error
    // that passed the New York tests fails here.
    const from = Math.floor(Date.UTC(2026, 9, 3, 0, 0, 0) / 1000); // 2026-10-03T00:00Z
    const beforeTransition = nextCronOccurrence("0 12 * * *", "Australia/Sydney", from);
    expect(iso(beforeTransition)).toBe("2026-10-03T02:00:00.000Z");
    expect(iso(nextCronOccurrence("0 12 * * *", "Australia/Sydney", beforeTransition))).toBe(
      "2026-10-04T01:00:00.000Z",
    );
  });
});

describe("bounded search", () => {
  it("refuses an expression with no occurrence rather than spinning", () => {
    expect(() => nextCronOccurrence("0 0 30 2 *", "UTC", 1_767_225_600)).toThrow(
      /no occurrence within 4 years/,
    );
  });

  it("finds 29 February inside the search window", () => {
    expect(iso(nextCronOccurrence("0 0 29 2 *", "UTC", 1_767_225_600))).toBe(
      "2028-02-29T00:00:00.000Z",
    );
  });
});

describe("assertValidTimezone", () => {
  it("accepts real IANA zones and refuses invented ones", () => {
    expect(() => assertValidTimezone("Europe/Berlin")).not.toThrow();
    expect(() => assertValidTimezone("UTC")).not.toThrow();
    expect(() => assertValidTimezone("EST5EDT")).not.toThrow();
    expect(() => assertValidTimezone("Mars/Olympus")).toThrow(/invalid IANA timezone/);
    expect(() => assertValidTimezone("")).toThrow(/invalid IANA timezone/);
  });
});

describe("catch-up and advance (Rust advance_schedule_past_now)", () => {
  const everyMinute = { ...cronSpec("*/1 * * * *") };

  it("advances a single step when firing on time", () => {
    const slot = 1_767_225_660; // 00:01:00Z
    expect(advanceNextFireAt(everyMinute, slot, slot)).toBe(slot + 60);
  });

  it("fast-forwards past every elapsed slot after an outage", () => {
    const slot = 1_767_225_660;
    const now = slot + 3600; // an hour of missed minutes
    const next = advanceNextFireAt(everyMinute, slot, now);
    expect(next).toBeGreaterThan(now);
    expect(next).toBe(now + 60);
  });

  it("stays bounded when the outage exceeds the catch-up cap", () => {
    // 30 days of missed one-minute slots is 43 200 iterations, well past the
    // 10 000 cap; the walk must jump rather than crawl.
    const slot = 1_767_225_660;
    const now = slot + 30 * 24 * 3600;
    const started = Date.now();
    const next = advanceNextFireAt(everyMinute, slot, now);
    expect(next).toBe(now + 60);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("parks an interval schedule whose interval became invalid", () => {
    const spec: AgentScheduleSpec = {
      ...cronSpec("*/1 * * * *"),
      spec_kind: "interval",
      interval_secs: 0,
    };
    expect(advanceNextFireAt(spec, 1_000, 2_000)).toBeNull();
  });

  it("isCatchupFire is true only when the NEXT slot is also already past", () => {
    const slot = 1_767_225_660;
    expect(isCatchupFire(everyMinute, slot, slot)).toBe(false);
    expect(isCatchupFire(everyMinute, slot, slot + 59)).toBe(false);
    expect(isCatchupFire(everyMinute, slot, slot + 60)).toBe(true);
  });
});

describe("deterministic identifiers", () => {
  it("scheduledDispatchId is stable per (schedule, slot)", () => {
    expect(scheduledDispatchId("s", 5)).toBe("schedule-dispatch-s-5");
    expect(scheduledDispatchId("s", 5)).not.toBe(scheduledDispatchId("s", 6));
  });

  it("a manual fire id can never collide with the slot id for the same second", () => {
    expect(manualScheduleFireId("s", 5)).not.toBe(agentScheduleFireId("s", 5));
    expect(manualScheduleFireId("s", 5).startsWith("manual:")).toBe(true);
  });

  it("jitter is deterministic, in range, and actually spreads schedules out", () => {
    expect(scheduleJitterOffset("s", 100, 0)).toBe(0);
    expect(scheduleJitterOffset("s", 100, -5)).toBe(0);
    for (const id of ["a", "b", "c", "d", "e"]) {
      const offset = scheduleJitterOffset(id, 100, 60);
      expect(offset).toBeGreaterThanOrEqual(0);
      expect(offset).toBeLessThanOrEqual(60);
      // Same inputs, same answer: several isolates must agree on when a slot
      // is due, or "due" means something different in each of them.
      expect(scheduleJitterOffset(id, 100, 60)).toBe(offset);
    }
    const spread = new Set(
      ["a", "b", "c", "d", "e", "f", "g", "h"].map((id) => scheduleJitterOffset(id, 100, 600)),
    );
    expect(spread.size).toBeGreaterThan(1);
  });
});

describe("normalizeScheduleSpec — the write-path gate", () => {
  const NOW = 1_767_225_600; // 2026-01-01T00:00:00Z

  it("accepts the legacy bare `schedule` string as a cron expression", () => {
    const { spec, nextFireAt } = normalizeScheduleSpec({ schedule: "0 3 * * *" }, null, NOW);
    expect(spec.spec_kind).toBe("cron");
    expect(spec.cron_expr).toBe("0 3 * * *");
    expect(iso(nextFireAt ?? 0)).toBe("2026-01-01T03:00:00.000Z");
  });

  it("infers the interval kind and seeds the first fire", () => {
    const { spec, nextFireAt } = normalizeScheduleSpec({ interval_secs: 900 }, null, NOW);
    expect(spec.spec_kind).toBe("interval");
    expect(nextFireAt).toBe(NOW + 900);
  });

  it("applies the documented defaults", () => {
    const { spec } = normalizeScheduleSpec({ cron_expr: "@hourly" }, null, NOW);
    expect(spec).toMatchObject({
      timezone: "UTC",
      target_kind: "self_hosted_dispatch",
      overlap_policy: "skip",
      catchup_policy: "skip_missed",
      jitter_secs: 0,
      enabled: true,
    });
  });

  it("refuses every way a schedule could be stored unfireable", () => {
    const bad: [Record<string, unknown>, RegExp][] = [
      [{ cron_expr: "not a cron" }, /invalid cron expression/],
      [{ cron_expr: "0 3 * * *", timezone: "Mars/Olympus" }, /invalid IANA timezone/],
      [{ spec_kind: "interval", interval_secs: 0 }, /interval_secs > 0/],
      [{ spec_kind: "interval" }, /interval_secs > 0/],
      [{ spec_kind: "cron" }, /non-empty cron_expr/],
      [{ cron_expr: "0 3 * * *", jitter_secs: -1 }, /must not be negative/],
      [{ cron_expr: "0 3 * * *", target_kind: "carrier_pigeon" }, /unknown target_kind/],
      [{ cron_expr: "0 3 * * *", overlap_policy: "queue" }, /unknown overlap_policy/],
      [{ cron_expr: "0 3 * * *", catchup_policy: "fire_all" }, /unknown catchup_policy/],
      [{ spec_kind: "sundial", cron_expr: "0 3 * * *" }, /unknown spec_kind/],
      [{ name: "no spec at all" }, /spec_kind is required/],
    ];
    for (const [body, message] of bad) {
      expect(() => normalizeScheduleSpec(body, null, NOW), JSON.stringify(body)).toThrow(
        ScheduleSpecError,
      );
      expect(() => normalizeScheduleSpec(body, null, NOW), JSON.stringify(body)).toThrow(message);
    }
  });

  it("inherits omitted fields from the existing row (Rust's or_else chain)", () => {
    const existing = {
      spec_kind: "cron",
      cron_expr: "0 3 * * *",
      timezone: "America/New_York",
      target_kind: "agent_run",
      overlap_policy: "allow",
      catchup_policy: "fire_once",
      jitter_secs: 30,
      enabled: false,
    };
    const { spec } = normalizeScheduleSpec({ name: "renamed" }, existing, NOW);
    expect(spec).toMatchObject({
      spec_kind: "cron",
      cron_expr: "0 3 * * *",
      timezone: "America/New_York",
      target_kind: "agent_run",
      overlap_policy: "allow",
      catchup_policy: "fire_once",
      jitter_secs: 30,
      enabled: false,
    });
  });

  it("lets a PATCH switch an existing cron schedule to an interval one", () => {
    const existing = { spec_kind: "cron", cron_expr: "0 3 * * *", timezone: "UTC" };
    const { spec, nextFireAt } = normalizeScheduleSpec(
      { spec_kind: "interval", interval_secs: 60 },
      existing,
      NOW,
    );
    expect(spec.spec_kind).toBe("interval");
    expect(nextFireAt).toBe(NOW + 60);
  });
});
