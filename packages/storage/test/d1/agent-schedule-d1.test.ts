/**
 * The agent-schedule durable store against REAL D1 (#246).
 *
 * One claim dominates this file: firing is AT MOST ONCE per (schedule, slot),
 * and the only thing enforcing it is the `UNIQUE (schedule_id,
 * scheduled_fire_at_unix)` row claimed with `ON CONFLICT DO NOTHING RETURNING`.
 * That is a property of SQLite, not of this package's code, so it cannot be
 * asserted against a fake — a fake's UNIQUE holds because the fake was written
 * to agree. Two Workers racing one cron minute is the scenario; a duplicate
 * paid agent run is the cost of getting it wrong.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1AgentScheduleStore,
  CLAIM_AND_ADVANCE_SCHEDULE_SQL,
  INSERT_SCHEDULE_FIRE_SQL,
  type StoredAgentSchedule,
  type StoredAgentScheduleFire,
  type TenantDatabaseHandle,
  agentScheduleFireId,
  planScheduleTick,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, resetTenantData, setupTenantRouter, tenantDb } from "./harness.js";

const NOW = 1_784_073_600;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;
let storeA: D1AgentScheduleStore;
let storeB: D1AgentScheduleStore;

beforeAll(async () => {
  const router = await setupTenantRouter();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
  storeA = new D1AgentScheduleStore(handleA);
  storeB = new D1AgentScheduleStore(handleB);
});

beforeEach(async () => {
  await resetTenantData(tenantDb(TENANT_A));
  await resetTenantData(tenantDb(TENANT_B));
});

function schedule(overrides: Partial<StoredAgentSchedule> = {}): StoredAgentSchedule {
  return {
    scheduleId: "sched_1",
    tenantId: TENANT_A,
    workspaceId: "ws_1",
    name: "nightly",
    enabled: true,
    specKind: "cron",
    cronExpr: "0 2 * * *",
    timezone: "UTC",
    intervalSecs: undefined,
    targetKind: "self_hosted_dispatch",
    targetJson: '{"agent":"summarizer"}',
    overlapPolicy: "skip",
    catchupPolicy: "skip_missed",
    jitterSecs: 0,
    nextFireAtUnix: NOW,
    lastFireAtUnix: undefined,
    createdAtUnix: NOW,
    updatedAtUnix: NOW,
    revision: 1,
    ...overrides,
  };
}

function fire(overrides: Partial<StoredAgentScheduleFire> = {}): StoredAgentScheduleFire {
  const scheduleId = overrides.scheduleId ?? "sched_1";
  const slot = overrides.scheduledFireAtUnix ?? NOW;
  return {
    fireId: agentScheduleFireId(scheduleId, slot),
    scheduleId,
    scheduledFireAtUnix: slot,
    firedAtUnix: NOW + 1,
    nodeId: "worker-1",
    outcome: "dispatched",
    dispatchId: "dispatch-1",
    runId: undefined,
    detail: undefined,
    ...overrides,
  };
}

describe("D1AgentScheduleStore — THE at-most-once fire gate", () => {
  test("the claim SQL is a conflict-suppressing INSERT that REPORTS the win", () => {
    // The two properties an outcome-only test would not distinguish from a
    // plain INSERT wrapped in try/catch — which cannot tell "I won" from "the
    // write failed for some other reason".
    expect(INSERT_SCHEDULE_FIRE_SQL).toContain(
      "ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING",
    );
    expect(INSERT_SCHEDULE_FIRE_SQL).toContain("RETURNING fire_id");
  });

  test("the first claim on a slot wins and the second loses", async () => {
    await storeA.upsertSchedule(schedule());
    expect(await storeA.insertScheduleFire(fire())).toBe(true);
    expect(await storeA.insertScheduleFire(fire())).toBe(false);
    expect(await storeA.listScheduleFires("sched_1", 10)).toHaveLength(1);
  });

  test("EXACTLY ONE of eight isolates racing one slot claims it", async () => {
    await storeA.upsertSchedule(schedule());
    const wins = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        // Every racer supplies its OWN node id and dispatch id, exactly as
        // eight different isolates would. Only the (schedule, slot) key is
        // shared — that is what the gate keys on.
        storeA.insertScheduleFire(
          fire({ nodeId: `worker-${index}`, dispatchId: `dispatch-${index}` }),
        ),
      ),
    );
    expect(wins.filter(Boolean)).toHaveLength(1);
    expect(await storeA.listScheduleFires("sched_1", 10)).toHaveLength(1);
  });

  test("a LOSER cannot overwrite the winner's evidence", async () => {
    await storeA.upsertSchedule(schedule());
    await storeA.insertScheduleFire(fire({ nodeId: "winner", outcome: "dispatched" }));
    await storeA.insertScheduleFire(fire({ nodeId: "loser", outcome: "error", detail: "boom" }));
    const [row] = await storeA.listScheduleFires("sched_1", 10);
    // `DO NOTHING`, not `DO UPDATE`: the second caller must not be able to
    // rewrite what the first recorded.
    expect(row?.nodeId).toBe("winner");
    expect(row?.outcome).toBe("dispatched");
    expect(row?.detail).toBeUndefined();
  });

  test("a DIFFERENT slot of the same schedule is a separate claim", async () => {
    await storeA.upsertSchedule(schedule());
    expect(await storeA.insertScheduleFire(fire({ scheduledFireAtUnix: NOW }))).toBe(true);
    expect(await storeA.insertScheduleFire(fire({ scheduledFireAtUnix: NOW + 86_400 }))).toBe(true);
    expect(await storeA.listScheduleFires("sched_1", 10)).toHaveLength(2);
  });

  test("the stored fire id is recomputed, so a caller cannot defeat the deterministic key", async () => {
    await storeA.upsertSchedule(schedule());
    // A caller that generated a random id must NOT get a second row for the
    // same slot — the id is derived from (scheduleId, slot) inside the store.
    expect(await storeA.insertScheduleFire(fire({ fireId: "random-1" }))).toBe(true);
    expect(await storeA.insertScheduleFire(fire({ fireId: "random-2" }))).toBe(false);
    const [row] = await storeA.listScheduleFires("sched_1", 10);
    expect(row?.fireId).toBe(agentScheduleFireId("sched_1", NOW));
  });

  test("claim and cursor advance commit together, and a duplicate does neither", async () => {
    await storeA.upsertSchedule(schedule());
    expect(CLAIM_AND_ADVANCE_SCHEDULE_SQL).toContain("RETURNING fire_id");

    const [first, second] = await Promise.all([
      storeA.claimAndAdvanceSchedule(fire({ outcome: "error" }), NOW + 86_400, NOW + 1),
      new D1AgentScheduleStore(handleA).claimAndAdvanceSchedule(
        fire({ outcome: "error" }),
        NOW + 86_400,
        NOW + 1,
      ),
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    expect(await storeA.listScheduleFires("sched_1", 10)).toHaveLength(1);
    expect(await storeA.getSchedule("sched_1")).toMatchObject({
      lastFireAtUnix: NOW,
      nextFireAtUnix: NOW + 86_400,
    });
  });
});

describe("D1AgentScheduleStore — the due scan", () => {
  test("returns arrived slots soonest-first and excludes future ones", async () => {
    await storeA.upsertSchedule(schedule({ scheduleId: "late", nextFireAtUnix: NOW - 100 }));
    await storeA.upsertSchedule(schedule({ scheduleId: "now", nextFireAtUnix: NOW }));
    await storeA.upsertSchedule(schedule({ scheduleId: "future", nextFireAtUnix: NOW + 100 }));
    expect((await storeA.listDueSchedules(NOW, 10)).map((s) => s.scheduleId)).toEqual([
      "late",
      "now",
    ]);
  });

  test("excludes disabled schedules and unscheduled (NULL cursor) ones", async () => {
    await storeA.upsertSchedule(schedule({ scheduleId: "off", enabled: false }));
    await storeA.upsertSchedule(schedule({ scheduleId: "unscheduled", nextFireAtUnix: undefined }));
    await storeA.upsertSchedule(schedule({ scheduleId: "on" }));
    expect((await storeA.listDueSchedules(NOW, 10)).map((s) => s.scheduleId)).toEqual(["on"]);
  });

  test("is bounded, so a backlog drains across ticks instead of blowing one budget", async () => {
    for (let i = 0; i < 7; i += 1) {
      await storeA.upsertSchedule(schedule({ scheduleId: `s${i}`, nextFireAtUnix: NOW - i }));
    }
    expect(await storeA.listDueSchedules(NOW, 3)).toHaveLength(3);
  });

  test("rejects a non-positive limit rather than silently scanning everything", async () => {
    await expect(storeA.listDueSchedules(NOW, 0)).rejects.toThrow(/positive integer limit/);
  });

  test("is per tenant database — one tenant's backlog is invisible to another", async () => {
    await storeA.upsertSchedule(schedule());
    expect(await storeB.listDueSchedules(NOW, 10)).toEqual([]);
  });
});

describe("D1AgentScheduleStore — schedules", () => {
  test("round-trips every field including the enums and the optionals", async () => {
    const s = schedule({
      specKind: "interval",
      cronExpr: undefined,
      intervalSecs: 900,
      targetKind: "agent_run",
      overlapPolicy: "allow",
      catchupPolicy: "fire_once",
      jitterSecs: 30,
      lastFireAtUnix: NOW - 900,
      revision: 4,
    });
    await storeA.upsertSchedule(s);
    expect(await storeA.getSchedule("sched_1")).toEqual(s);
  });

  test("a broken definition is REFUSED at write time, not stored to fail later", async () => {
    await expect(storeA.upsertSchedule(schedule({ cronExpr: "not a cron" }))).rejects.toThrow(
      /invalid agent schedule sched_1: invalid cron expression/,
    );
    await expect(storeA.upsertSchedule(schedule({ targetJson: "{oops" }))).rejects.toThrow(
      /target_json is not valid JSON/,
    );
    expect(await storeA.getSchedule("sched_1")).toBeUndefined();
  });

  test("an unknown enum token in the row FAILS CLOSED instead of defaulting", async () => {
    await storeA.upsertSchedule(schedule());
    await tenantDb(TENANT_A)
      .prepare("UPDATE agent_schedules SET catchup_policy = 'whatever' WHERE schedule_id = ?")
      .bind("sched_1")
      .run();
    // Defaulting an unrecognized catchup policy to `skip_missed` would silently
    // change WHEN this schedule fires.
    await expect(storeA.getSchedule("sched_1")).rejects.toThrow(
      /unknown agent_schedules.catchup_policy whatever/,
    );
  });

  test("advance writes the new cursor, and undefined leaves it UNSCHEDULED", async () => {
    await storeA.upsertSchedule(schedule());
    expect(await storeA.advanceSchedule("sched_1", NOW, NOW + 86_400, NOW + 1)).toBe(true);
    let read = await storeA.getSchedule("sched_1");
    expect(read?.lastFireAtUnix).toBe(NOW);
    expect(read?.nextFireAtUnix).toBe(NOW + 86_400);

    expect(await storeA.advanceSchedule("sched_1", NOW + 86_400, undefined, NOW + 2)).toBe(true);
    read = await storeA.getSchedule("sched_1");
    expect(read?.nextFireAtUnix).toBeUndefined();
    // ...and the due scan then skips it, which is the whole point of NULL.
    expect(await storeA.listDueSchedules(NOW + 10 * 86_400, 10)).toEqual([]);
  });

  test("advancing an unknown schedule reports false rather than inventing a row", async () => {
    expect(await storeA.advanceSchedule("nope", NOW, NOW + 1, NOW)).toBe(false);
  });

  test("list narrows by workspace and orders by name", async () => {
    await storeA.upsertSchedule(schedule({ scheduleId: "b", name: "beta" }));
    await storeA.upsertSchedule(schedule({ scheduleId: "a", name: "alpha" }));
    await storeA.upsertSchedule(schedule({ scheduleId: "c", name: "gamma", workspaceId: "ws_2" }));
    expect((await storeA.listSchedules(TENANT_A, "ws_1")).map((s) => s.name)).toEqual([
      "alpha",
      "beta",
    ]);
    expect(await storeA.listSchedules(TENANT_A)).toHaveLength(3);
  });
});

describe("D1AgentScheduleStore — delete CASCADES the fire ledger", () => {
  test("deleting a schedule removes its fire rows in the same breath", async () => {
    await storeA.upsertSchedule(schedule());
    await storeA.insertScheduleFire(fire());
    expect(await storeA.deleteSchedule("sched_1")).toBe(true);
    expect(await storeA.getSchedule("sched_1")).toBeUndefined();
    expect(await storeA.listScheduleFires("sched_1", 10)).toEqual([]);
  });

  test("a RE-CREATED same-id schedule can fire its old slots again", async () => {
    // The bug the cascade exists to prevent: an orphaned fire ledger makes the
    // at-most-once gate suppress the new schedule's first fires — silently,
    // forever, with no error anywhere.
    await storeA.upsertSchedule(schedule());
    expect(await storeA.insertScheduleFire(fire())).toBe(true);
    await storeA.deleteSchedule("sched_1");
    await storeA.upsertSchedule(schedule());
    expect(await storeA.insertScheduleFire(fire())).toBe(true);
  });

  test("deleting an unknown schedule is false, not a phantom success", async () => {
    expect(await storeA.deleteSchedule("nope")).toBe(false);
  });

  test("one schedule's delete does not touch another's fire ledger", async () => {
    await storeA.upsertSchedule(schedule({ scheduleId: "keep" }));
    await storeA.upsertSchedule(schedule({ scheduleId: "drop" }));
    await storeA.insertScheduleFire(fire({ scheduleId: "keep" }));
    await storeA.insertScheduleFire(fire({ scheduleId: "drop" }));
    await storeA.deleteSchedule("drop");
    expect(await storeA.listScheduleFires("keep", 10)).toHaveLength(1);
  });
});

describe("one full tick, end to end", () => {
  test("due → plan → claim → advance, and a second tick is a no-op", async () => {
    // This is the loop a `[triggers] crons` handler owes; running it here is
    // what proves the four pieces compose.
    const slot = 1_784_080_800; // 2026-07-15T02:00:00Z, the cron's own slot
    await storeA.upsertSchedule(schedule({ nextFireAtUnix: slot }));

    const due = await storeA.listDueSchedules(slot, 10);
    expect(due).toHaveLength(1);
    const action = planScheduleTick(due[0] as StoredAgentSchedule, slot, () => false);
    expect(action.kind).toBe("fire");
    if (action.kind !== "fire") throw new Error("unreachable");

    expect(await storeA.insertScheduleFire(fire({ scheduledFireAtUnix: action.slot }))).toBe(true);
    await storeA.advanceSchedule("sched_1", action.slot, action.advanceTo, slot);

    // The cursor moved a whole day, so the same tick time yields nothing.
    expect(await storeA.listDueSchedules(slot, 10)).toEqual([]);
    expect((await storeA.getSchedule("sched_1"))?.nextFireAtUnix).toBe(slot + 86_400);
    expect((await storeA.getSchedule("sched_1"))?.lastFireAtUnix).toBe(slot);
  });

  test("two Workers running the SAME tick dispatch the slot exactly once", async () => {
    const slot = 1_784_080_800;
    await storeA.upsertSchedule(schedule({ nextFireAtUnix: slot }));
    const due = await storeA.listDueSchedules(slot, 10);
    const s = due[0] as StoredAgentSchedule;

    // Both isolates read the same due row and both decide to fire — that is
    // expected and unavoidable. The gate is what makes it harmless.
    const [first, second] = await Promise.all([
      storeA.insertScheduleFire(fire({ scheduledFireAtUnix: slot, nodeId: "w1" })),
      new D1AgentScheduleStore(handleA).insertScheduleFire(
        fire({ scheduledFireAtUnix: slot, nodeId: "w2" }),
      ),
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    expect(planScheduleTick(s, slot, () => false).kind).toBe("fire");
    expect(await storeA.listScheduleFires("sched_1", 10)).toHaveLength(1);
  });
});
