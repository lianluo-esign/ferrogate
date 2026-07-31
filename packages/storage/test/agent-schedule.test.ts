/**
 * The agent-schedule engine (#246): the cron grammar, timezone-aware wall-clock
 * arithmetic including DST, the interval spec, and the pure tick decision.
 *
 * These are the assertions that make "compatible with a crontab" a claim
 * somebody can check. The grammar is re-implemented clean-room, so what is
 * pinned here is that the DOCUMENTED grammar is what the code does — field by
 * field, including the two rules people get wrong (the dom/dow union, and `7`
 * meaning Sunday).
 */
import { describe, expect, test } from "vitest";
import {
  type StoredAgentSchedule,
  advanceSchedulePastNow,
  agentScheduleFireId,
  computeNextCronFireAt,
  computeNextFireAt,
  parseCronExpression,
  planScheduleTick,
  scheduledDispatchId,
  validateAgentSchedule,
} from "../src/index.js";

/** 2026-07-15T00:00:00Z, a Wednesday. */
const NOW = 1_784_073_600;

function at(iso: string): number {
  return Math.floor(Date.parse(iso) / 1000);
}

function schedule(overrides: Partial<StoredAgentSchedule> = {}): StoredAgentSchedule {
  return {
    scheduleId: "sched_1",
    tenantId: "tenant_a",
    workspaceId: "ws_1",
    name: "nightly",
    enabled: true,
    specKind: "cron",
    cronExpr: "0 2 * * *",
    timezone: "UTC",
    intervalSecs: undefined,
    targetKind: "self_hosted_dispatch",
    targetJson: "{}",
    overlapPolicy: "skip",
    catchupPolicy: "skip_missed",
    jitterSecs: 0,
    nextFireAtUnix: undefined,
    lastFireAtUnix: undefined,
    createdAtUnix: NOW,
    updatedAtUnix: NOW,
    revision: 1,
    ...overrides,
  };
}

const neverUnacked = () => false;
const alwaysUnacked = () => true;

describe("cron grammar", () => {
  test("accepts exactly five fields and rejects any other count", () => {
    expect(() => parseCronExpression("* * * * *")).not.toThrow();
    // A 6-field (seconds) expression must NOT be silently reinterpreted: every
    // field would shift one position and the schedule would fire at a time
    // nobody asked for.
    expect(() => parseCronExpression("0 0 0 12 * *")).toThrow(/expected 5 fields/);
    expect(() => parseCronExpression("* * * *")).toThrow(/expected 5 fields/);
  });

  test("wildcards, literals, lists, ranges and steps", () => {
    expect([...parseCronExpression("*/15 * * * *").minute.values]).toEqual([0, 15, 30, 45]);
    expect([...parseCronExpression("1,2,3 * * * *").minute.values]).toEqual([1, 2, 3]);
    expect([...parseCronExpression("10-13 * * * *").minute.values]).toEqual([10, 11, 12, 13]);
    expect([...parseCronExpression("10-20/5 * * * *").minute.values]).toEqual([10, 15, 20]);
    // `n/s` reads as `n-max/s`, the conventional Vixie meaning.
    expect([...parseCronExpression("* 20/2 * * *").hour.values]).toEqual([20, 22]);
  });

  test("month and day names are accepted wherever a number is", () => {
    expect([...parseCronExpression("0 0 1 JAN *").month.values]).toEqual([1]);
    expect([...parseCronExpression("0 0 1 jan-mar *").month.values]).toEqual([1, 2, 3]);
    expect([...parseCronExpression("0 0 * * MON-FRI").dayOfWeek.values]).toEqual([1, 2, 3, 4, 5]);
  });

  test("day-of-week 7 is Sunday, and normalizes to 0 AFTER range expansion", () => {
    expect([...parseCronExpression("0 0 * * 7").dayOfWeek.values]).toEqual([0]);
    // `5-7` must still mean Fri/Sat/Sun — normalizing before expansion would
    // turn it into a descending range and reject a valid crontab line.
    expect([...parseCronExpression("0 0 * * 5-7").dayOfWeek.values].sort()).toEqual([0, 5, 6]);
  });

  test("rejects out-of-range values, descending ranges and zero steps", () => {
    expect(() => parseCronExpression("60 * * * *")).toThrow();
    expect(() => parseCronExpression("* 24 * * *")).toThrow();
    expect(() => parseCronExpression("0 0 0 * *")).toThrow(); // day-of-month starts at 1
    expect(() => parseCronExpression("10-5 * * * *")).toThrow(/descending/);
    expect(() => parseCronExpression("*/0 * * * *")).toThrow(/invalid step/);
  });

  test("rejects unrecognized syntax instead of silently matching everything", () => {
    // The failure mode this guards: an operator writes an expression they
    // believe is restrictive, it degrades to `*`, and the schedule fires 1,440
    // times a day.
    expect(() => parseCronExpression("L * * * *")).toThrow();
    expect(() => parseCronExpression("0 0 ? * *")).toThrow();
    expect(() => parseCronExpression("0 0 1#2 * *")).toThrow();
  });
});

describe("next fire — UTC", () => {
  test("is STRICTLY after the anchor, so a schedule cannot re-select its own slot", () => {
    const slot = at("2026-07-15T02:00:00Z");
    expect(computeNextCronFireAt("0 2 * * *", "UTC", slot)).toBe(at("2026-07-16T02:00:00Z"));
  });

  test("finds the next matching minute within the hour", () => {
    expect(computeNextCronFireAt("*/15 * * * *", "UTC", at("2026-07-15T10:07:00Z"))).toBe(
      at("2026-07-15T10:15:00Z"),
    );
  });

  test("rolls forward across month and year boundaries", () => {
    expect(computeNextCronFireAt("0 0 1 * *", "UTC", at("2026-12-15T00:00:00Z"))).toBe(
      at("2027-01-01T00:00:00Z"),
    );
  });

  test("handles a leap-year-only expression rather than looping", () => {
    expect(computeNextCronFireAt("0 0 29 2 *", "UTC", at("2026-03-01T00:00:00Z"))).toBe(
      at("2028-02-29T00:00:00Z"),
    );
  });

  test("an expression that can never match fails loudly", () => {
    // February 30th. Silently returning nothing would leave the schedule
    // permanently unscheduled with no explanation.
    expect(() => computeNextCronFireAt("0 0 30 2 *", "UTC", NOW)).toThrow(
      /invalid cron expression/,
    );
  });

  test("day-of-month and day-of-week are a UNION when both are restricted", () => {
    // `0 0 1 * MON` fires on the 1st AND on every Monday. Surprising, and it is
    // what a crontab does.
    const first = computeNextCronFireAt("0 0 1 * MON", "UTC", at("2026-07-15T12:00:00Z"));
    expect(first).toBe(at("2026-07-20T00:00:00Z")); // the next Monday
    const second = computeNextCronFireAt("0 0 1 * MON", "UTC", at("2026-07-28T00:00:00Z"));
    expect(second).toBe(at("2026-08-01T00:00:00Z")); // the 1st, a Saturday
  });

  test("only the restricted one is consulted when the other is a wildcard", () => {
    // `0 0 1 * *` must NOT also fire every day just because dow is `*`.
    expect(computeNextCronFireAt("0 0 1 * *", "UTC", at("2026-07-15T00:00:00Z"))).toBe(
      at("2026-08-01T00:00:00Z"),
    );
  });
});

describe("next fire — IANA timezones and DST", () => {
  test("a daily wall-clock slot stays at the same LOCAL hour across a DST boundary", () => {
    // 2026-11-01 is the US fall-back. A fixed-UTC-offset implementation would
    // drift by an hour here; a wall-clock one does not.
    const before = computeNextCronFireAt(
      "0 2 * * *",
      "America/New_York",
      at("2026-10-30T12:00:00Z"),
    );
    expect(before).toBe(at("2026-10-31T06:00:00Z")); // 02:00 EDT (UTC-4)
    const after = computeNextCronFireAt(
      "0 2 * * *",
      "America/New_York",
      at("2026-11-02T12:00:00Z"),
    );
    expect(after).toBe(at("2026-11-03T07:00:00Z")); // 02:00 EST (UTC-5)
  });

  test("a wall-clock time inside the spring-forward GAP is skipped, not fired late", () => {
    // 2026-03-08 02:30 America/New_York does not exist. Firing at 03:30 instead
    // would run a `30 2 * * *` schedule an hour late on exactly one day a year
    // and nowhere say so.
    const next = computeNextCronFireAt(
      "30 2 * * *",
      "America/New_York",
      at("2026-03-07T12:00:00Z"),
    );
    expect(next).toBe(at("2026-03-09T06:30:00Z")); // 02:30 EDT on the 9th
  });

  test("a zone with a non-hour offset is honored", () => {
    // Asia/Kolkata is UTC+05:30 — a half-hour offset catches an implementation
    // that assumed whole-hour offsets.
    expect(computeNextCronFireAt("0 9 * * *", "Asia/Kolkata", at("2026-07-15T00:00:00Z"))).toBe(
      at("2026-07-15T03:30:00Z"),
    );
  });

  test("an unknown zone is rejected by name", () => {
    expect(() => computeNextCronFireAt("0 2 * * *", "Mars/Olympus_Mons", NOW)).toThrow(
      /invalid IANA timezone 'Mars\/Olympus_Mons'/,
    );
  });
});

describe("interval schedules", () => {
  test("a positive interval steps forward from the anchor", () => {
    expect(computeNextFireAt(schedule({ specKind: "interval", intervalSecs: 900 }), NOW)).toBe(
      NOW + 900,
    );
  });

  test("a non-positive interval is UNSCHEDULED, not an error and not zero", () => {
    // `undefined` means "leave next_fire_at NULL", which the due query skips —
    // a broken definition stops firing rather than firing every tick forever.
    expect(
      computeNextFireAt(schedule({ specKind: "interval", intervalSecs: 0 }), NOW),
    ).toBeUndefined();
    expect(
      computeNextFireAt(schedule({ specKind: "interval", intervalSecs: -5 }), NOW),
    ).toBeUndefined();
    expect(computeNextFireAt(schedule({ specKind: "interval" }), NOW)).toBeUndefined();
  });

  test("a cron schedule with no expression is an error, not a silent skip", () => {
    expect(() => computeNextFireAt(schedule({ cronExpr: undefined }), NOW)).toThrow(
      /cron schedule is missing its cron expression/,
    );
    expect(() => computeNextFireAt(schedule({ cronExpr: "   " }), NOW)).toThrow(
      /cron schedule is missing its cron expression/,
    );
  });

  test("jitterSecs moves NO computed fire time — Rust does not apply it either", () => {
    const plain = computeNextFireAt(schedule({ specKind: "interval", intervalSecs: 60 }), NOW);
    const jittered = computeNextFireAt(
      schedule({ specKind: "interval", intervalSecs: 60, jitterSecs: 45 }),
      NOW,
    );
    expect(jittered).toBe(plain);
  });
});

describe("deterministic ids", () => {
  test("the fire id is a pure function of (schedule, slot)", () => {
    // Determinism is half the idempotency: two isolates racing one slot must
    // produce the SAME primary key for the UNIQUE to reject the loser.
    expect(agentScheduleFireId("sched_1", 100)).toBe(agentScheduleFireId("sched_1", 100));
    expect(agentScheduleFireId("sched_1", 100)).not.toBe(agentScheduleFireId("sched_1", 101));
  });

  test("the length prefix makes a crafted schedule id unable to alias another slot", () => {
    // Without the prefix, `("a:b", 1)` and `("a", "b:1")`-shaped inputs collide.
    expect(agentScheduleFireId("a:b", 1)).not.toBe(agentScheduleFireId("a", Number("b1") || 1));
    expect(agentScheduleFireId("ab", 1)).not.toBe(agentScheduleFireId("a", 1));
  });

  test("the dispatch id is deterministic per (schedule, slot) too", () => {
    expect(scheduledDispatchId("s", 7)).toBe("schedule-dispatch-s-7");
  });
});

describe("advanceSchedulePastNow", () => {
  test("on-time firing converges in one step", () => {
    const slot = at("2026-07-15T02:00:00Z");
    expect(advanceSchedulePastNow(schedule(), slot, slot + 1)).toBe(at("2026-07-16T02:00:00Z"));
  });

  test("a short outage fast-forwards past EVERY missed slot in one call", () => {
    const s = schedule({ specKind: "interval", intervalSecs: 60 });
    // Fired at NOW; the loop only wakes up 10 minutes later.
    expect(advanceSchedulePastNow(s, NOW, NOW + 600)).toBe(NOW + 660);
  });

  test("a very long outage is BOUNDED and still lands strictly after now", () => {
    // 60s cadence, one year behind: a slot-by-slot walk needs ~525,600 steps.
    // The cap makes it jump straight to the first future slot instead.
    const s = schedule({ specKind: "interval", intervalSecs: 60 });
    const now = NOW + 365 * 24 * 3600;
    const next = advanceSchedulePastNow(s, NOW, now);
    expect(next).toBeGreaterThan(now);
    expect(next).toBe(now + 60);
  });

  test("an uncomputable definition leaves the schedule UNSCHEDULED", () => {
    expect(
      advanceSchedulePastNow(schedule({ cronExpr: "not a cron" }), NOW, NOW + 1),
    ).toBeUndefined();
    expect(
      advanceSchedulePastNow(schedule({ specKind: "interval", intervalSecs: 0 }), NOW, NOW + 1),
    ).toBeUndefined();
  });
});

describe("planScheduleTick", () => {
  test("a schedule whose slot is still in the future is not due", () => {
    const s = schedule({ nextFireAtUnix: NOW + 60 });
    expect(planScheduleTick(s, NOW, neverUnacked)).toEqual({ kind: "not_due" });
  });

  test("a schedule with no cursor at all is not due", () => {
    expect(planScheduleTick(schedule(), NOW, neverUnacked)).toEqual({ kind: "not_due" });
  });

  test("an on-time slot FIRES and advances to the next one", () => {
    const slot = at("2026-07-15T02:00:00Z");
    const s = schedule({ nextFireAtUnix: slot });
    expect(planScheduleTick(s, slot, neverUnacked)).toEqual({
      kind: "fire",
      slot,
      advanceTo: at("2026-07-16T02:00:00Z"),
    });
  });

  test("skip_missed fast-forwards a BACKLOG without firing and without evidence", () => {
    // Being 3 hours behind on a per-minute schedule must not turn into 180
    // agent runs charged at once.
    const s = schedule({ specKind: "interval", intervalSecs: 60, nextFireAtUnix: NOW });
    const action = planScheduleTick(s, NOW + 3 * 3600, neverUnacked);
    expect(action.kind).toBe("advance_only");
    if (action.kind === "advance_only") {
      expect(action.slot).toBe(NOW);
      expect(action.advanceTo).toBeGreaterThan(NOW + 3 * 3600);
    }
  });

  test("fire_once fires exactly ONE catch-up for the backlog, then fast-forwards", () => {
    const s = schedule({
      specKind: "interval",
      intervalSecs: 60,
      catchupPolicy: "fire_once",
      nextFireAtUnix: NOW,
    });
    const action = planScheduleTick(s, NOW + 3 * 3600, neverUnacked);
    expect(action.kind).toBe("fire");
    if (action.kind === "fire") {
      expect(action.slot).toBe(NOW);
      // ...and the cursor still jumps past the whole backlog, so the NEXT tick
      // is on time rather than replaying the remaining 179 slots.
      expect(action.advanceTo).toBeGreaterThan(NOW + 3 * 3600);
    }
  });

  test("skip_missed does NOT suppress an on-time slot", () => {
    // The defect this guards: reading "skip missed slots" as "skip the due
    // slot" makes a skip_missed schedule never fire at all.
    const slot = at("2026-07-15T02:00:00Z");
    const s = schedule({ nextFireAtUnix: slot });
    expect(planScheduleTick(s, slot + 1, neverUnacked).kind).toBe("fire");
  });

  test("overlap=skip suppresses the fire but RECORDS the suppression", () => {
    const slot = at("2026-07-15T02:00:00Z");
    const s = schedule({ nextFireAtUnix: slot, lastFireAtUnix: slot - 86_400 });
    const action = planScheduleTick(s, slot, alwaysUnacked);
    expect(action).toEqual({
      kind: "record_skip",
      slot,
      outcome: "skipped_overlap",
      advanceTo: at("2026-07-16T02:00:00Z"),
    });
  });

  test("overlap=skip consults the PREVIOUS slot's dispatch id, not an arbitrary one", () => {
    const slot = at("2026-07-15T02:00:00Z");
    const previous = slot - 86_400;
    const s = schedule({ nextFireAtUnix: slot, lastFireAtUnix: previous });
    const seen: string[] = [];
    planScheduleTick(s, slot, (id) => {
      seen.push(id);
      return false;
    });
    expect(seen).toEqual([scheduledDispatchId("sched_1", previous)]);
  });

  test("overlap=allow fires even while the previous dispatch is in flight", () => {
    const slot = at("2026-07-15T02:00:00Z");
    const s = schedule({
      overlapPolicy: "allow",
      nextFireAtUnix: slot,
      lastFireAtUnix: slot - 86_400,
    });
    expect(planScheduleTick(s, slot, alwaysUnacked).kind).toBe("fire");
  });

  test("a first-ever fire is never suppressed by overlap (there is no previous)", () => {
    const slot = at("2026-07-15T02:00:00Z");
    const s = schedule({ nextFireAtUnix: slot, lastFireAtUnix: undefined });
    expect(planScheduleTick(s, slot, alwaysUnacked).kind).toBe("fire");
  });

  test("EVERY branch advances past now, so a failing target cannot re-fire forever", () => {
    const slot = at("2026-07-15T02:00:00Z");
    const cases: { now: number; action: ReturnType<typeof planScheduleTick> }[] = [
      // fire
      {
        now: slot,
        action: planScheduleTick(schedule({ nextFireAtUnix: slot }), slot, neverUnacked),
      },
      // record_skip (overlap)
      {
        now: slot,
        action: planScheduleTick(
          schedule({ nextFireAtUnix: slot, lastFireAtUnix: slot - 86_400 }),
          slot,
          alwaysUnacked,
        ),
      },
      // advance_only (skip_missed catch-up)
      {
        now: NOW + 3600,
        action: planScheduleTick(
          schedule({ specKind: "interval", intervalSecs: 60, nextFireAtUnix: NOW }),
          NOW + 3600,
          neverUnacked,
        ),
      },
    ];
    expect(cases.map((c) => c.action.kind)).toEqual(["fire", "record_skip", "advance_only"]);
    for (const { now, action } of cases) {
      if (action.kind !== "not_due") expect(action.advanceTo).toBeGreaterThan(now);
    }
  });
});

describe("validateAgentSchedule — reject at WRITE time, not at fire time", () => {
  test("accepts a well-formed definition", () => {
    expect(validateAgentSchedule(schedule())).toBeUndefined();
    expect(
      validateAgentSchedule(
        schedule({ specKind: "interval", intervalSecs: 60, cronExpr: undefined }),
      ),
    ).toBeUndefined();
  });

  test("rejects a broken cron expression BEFORE it lands in the database", () => {
    // Rejecting at fire time means failing silently inside a background loop
    // nobody is watching.
    expect(validateAgentSchedule(schedule({ cronExpr: "not a cron" }))).toMatch(
      /invalid cron expression/,
    );
    expect(validateAgentSchedule(schedule({ cronExpr: "" }))).toMatch(
      /missing its cron expression/,
    );
  });

  test("rejects an unknown timezone", () => {
    expect(validateAgentSchedule(schedule({ timezone: "Nowhere/Nothing" }))).toMatch(
      /invalid IANA timezone/,
    );
  });

  test("rejects a non-positive interval and a negative jitter", () => {
    expect(validateAgentSchedule(schedule({ specKind: "interval", intervalSecs: 0 }))).toMatch(
      /interval_secs must be greater than zero/,
    );
    expect(validateAgentSchedule(schedule({ jitterSecs: -1 }))).toBe(
      "jitter_secs must not be negative",
    );
  });

  test("rejects a target payload that is not JSON", () => {
    expect(validateAgentSchedule(schedule({ targetJson: "{oops" }))).toMatch(
      /target_json is not valid JSON/,
    );
  });

  test("rejects blank identity fields", () => {
    expect(validateAgentSchedule(schedule({ scheduleId: "  " }))).toBe(
      "schedule_id must not be empty",
    );
    expect(validateAgentSchedule(schedule({ name: "" }))).toBe("name must not be empty");
  });
});
