/**
 * THE MOUNT GATE for the agent-schedule engine.
 *
 * `docs/rewrite/parity-audit-storage.md` §4.2: the engine did not exist, and
 * the CRUD surface that stood in for it stayed green the whole time — schedules
 * were stored as documents, `/fires` listed a collection nothing appended to,
 * and `run-now` merged `{ run_now: true }` and dispatched nothing. That is this
 * repo's dominant defect class: fully implemented, fully tested, never reached.
 *
 * So every assertion in the first two describes is written to FAIL when a
 * specific wiring line in `src/routes/admin_agent_schedule.ts` is removed, and
 * each one names the line it guards. All of them drive `SELF` — the object
 * `src/worker.ts` re-exports as the Worker's default handler — with
 * `CONTROL_PLANE_STORE` unset, i.e. the production D1 path. A test that built
 * its own Hono app and its own store would prove nothing about what ships.
 *
 * The third describe drives the tick loop directly against the same real D1
 * store, because the tick has no HTTP surface (see the note on
 * `src/schedule/engine.ts` and the wiring report: the `scheduled` handler lives
 * in `src/worker.ts`, which this slice may not edit).
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveLifecycle } from "../src/adapters.js";
import {
  SCHEDULE_COLLECTION,
  SCHEDULE_FIRE_COLLECTION,
  SELF_HOSTED_DISPATCH_COLLECTION,
  runScheduleTick,
} from "../src/schedule/engine.js";
import { agentScheduleFireId, scheduledDispatchId } from "../src/schedule/model.js";
import { runScheduledTick, scheduled } from "../src/schedule/scheduled.js";
import { D1ControlPlaneStore } from "../src/store/d1.js";
import { applySchema, db, rawDocument, resetD1, seedD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const KEY = operatorKey.secret;
const TENANT_A_KEY = "sched-tenant-a";
const TENANT_B_KEY = "sched-tenant-b";

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_A_KEY, "tenant_a"), tenantKey(TENANT_B_KEY, "tenant_b")],
  });
});

async function createSchedule(
  body: Record<string, unknown>,
  key = KEY,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const response = await SELF.fetch(
    `${BASE}/admin/v1/agent-schedules`,
    jsonRequest(key, "POST", body),
  );
  return { status: response.status, json: (await response.json()) as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// MOUNT 1 — the write path validates the firing spec and seeds next_fire_at
// ---------------------------------------------------------------------------

describe("MOUNT: create/replace/merge run normalizeScheduleSpec", () => {
  it("refuses an unparseable cron expression with 400", async () => {
    // Guards: `withFiringState` on `createSchedule`. Remove it and this stores
    // a schedule that can never fire, and answers 201 while doing so.
    const created = await createSchedule({ id: "s_bad", cron_expr: "every tuesday-ish" });
    expect(created.status).toBe(400);
    expect(JSON.stringify(created.json)).toMatch(/invalid cron expression/);
    expect(await rawDocument(SCHEDULE_COLLECTION, "s_bad")).toBeNull();
  });

  it("refuses an unknown IANA timezone with 400", async () => {
    const created = await createSchedule({
      id: "s_tz",
      cron_expr: "0 3 * * *",
      timezone: "Mars/Olympus",
    });
    expect(created.status).toBe(400);
    expect(JSON.stringify(created.json)).toMatch(/invalid IANA timezone/);
  });

  it("refuses a non-positive interval with 400", async () => {
    const created = await createSchedule({ id: "s_int", spec_kind: "interval", interval_secs: 0 });
    expect(created.status).toBe(400);
    expect(JSON.stringify(created.json)).toMatch(/interval_secs > 0/);
  });

  it("stamps next_fire_at_unix on the STORED document, not just the response", async () => {
    // Guards: the `next_fire_at_unix` line in `withFiringState`. It is the ONLY
    // field the due scan looks at, so a create that skipped it would store a
    // schedule the tick loop can never see — which is precisely §4.2.
    const now = Math.floor(Date.now() / 1000);
    const created = await createSchedule({
      id: "s_seed",
      spec_kind: "interval",
      interval_secs: 60,
    });
    expect(created.status).toBe(201);

    const stored = await rawDocument(SCHEDULE_COLLECTION, "s_seed");
    expect(stored).not.toBeNull();
    expect(typeof stored?.next_fire_at_unix).toBe("number");
    expect(stored?.next_fire_at_unix as number).toBeGreaterThanOrEqual(now + 60);
    expect(stored?.spec_kind).toBe("interval");
    expect(stored?.last_fire_at_unix).toBeNull();
  });

  it("recomputes next_fire_at_unix when a PATCH changes the cadence", async () => {
    await createSchedule({ id: "s_patch", spec_kind: "interval", interval_secs: 3600 });
    const before = (await rawDocument(SCHEDULE_COLLECTION, "s_patch"))?.next_fire_at_unix as number;

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/s_patch`,
      jsonRequest(KEY, "PATCH", { interval_secs: 60 }),
    );
    expect(patched.status).toBe(200);
    const after = (await rawDocument(SCHEDULE_COLLECTION, "s_patch"))?.next_fire_at_unix as number;
    // A cadence change that left the old slot in place would keep the schedule
    // firing on its previous cadence until the next fire — silently ignoring
    // the operator's edit for up to an hour.
    expect(after).toBeLessThan(before);
  });

  it("refuses an invalid cadence on PATCH too, leaving the stored row untouched", async () => {
    await createSchedule({ id: "s_keep", cron_expr: "0 3 * * *" });
    const before = await rawDocument(SCHEDULE_COLLECTION, "s_keep");
    const patched = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/s_keep`,
      jsonRequest(KEY, "PATCH", { cron_expr: "0 3 * *" }),
    );
    expect(patched.status).toBe(400);
    expect(await rawDocument(SCHEDULE_COLLECTION, "s_keep")).toEqual(before);
  });

  it("a PUT is a full replace and re-derives the spec from the body alone", async () => {
    await createSchedule({ id: "s_put", cron_expr: "0 3 * * *", timezone: "America/New_York" });
    const replaced = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/s_put`,
      jsonRequest(KEY, "PUT", { spec_kind: "interval", interval_secs: 120 }),
    );
    expect(replaced.status).toBe(200);
    const stored = await rawDocument(SCHEDULE_COLLECTION, "s_put");
    expect(stored?.spec_kind).toBe("interval");
    // The replaced cron expression must be GONE — a PUT that inherited it would
    // leave two contradictory cadences on one row.
    expect(stored?.cron_expr).toBeNull();
    expect(stored?.timezone).toBe("UTC");
  });
});

// ---------------------------------------------------------------------------
// MOUNT 2 — run-now, the fire ledger, and the delete cascade
// ---------------------------------------------------------------------------

describe("MOUNT: run-now dispatches through the engine", () => {
  it("answers 202 with the fire record and leaves a durable dispatch behind", async () => {
    // Guards: the `runScheduleNow(engineDeps(deps), …)` call in `runNow`.
    // Before this slice the handler merged `{ run_now: true }` onto the
    // document and returned 200 — successful-looking, and nothing happened.
    await createSchedule({ id: "s_run", cron_expr: "0 3 * * *" });
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_run/run-now`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(response.status).toBe(202);
    const body = (await response.json()) as {
      object: string;
      fire: { schedule_id: string; outcome: string; dispatch_id: string; id: string };
    };
    expect(body.object).toBe("agent_schedule_fire");
    expect(body.fire.schedule_id).toBe("s_run");
    expect(body.fire.outcome).toBe("dispatched");
    expect(body.fire.id.startsWith("manual:")).toBe(true);

    // The two durable consequences the old implementation had neither of.
    expect(await rawDocument(SCHEDULE_FIRE_COLLECTION, body.fire.id)).not.toBeNull();
    const dispatch = await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, body.fire.dispatch_id);
    expect(dispatch).not.toBeNull();
    expect(dispatch?.schedule_id).toBe("s_run");
    expect(dispatch?.status).toBe("queued");
  });

  it("creates an agent run when the target kind says so", async () => {
    await createSchedule({
      id: "s_agent",
      cron_expr: "0 3 * * *",
      target_kind: "agent_run",
      target: { agent: "researcher" },
    });
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_agent/run-now`, {
      method: "POST",
      headers: bearer(KEY),
    });
    const body = (await response.json()) as {
      fire: { run_id: string; dispatch_id: string | null };
    };
    expect(body.fire.dispatch_id).toBeNull();
    const run = await rawDocument("agent-runs", body.fire.run_id);
    expect(run).toMatchObject({
      status: "running",
      source: "agent_schedule",
      schedule_id: "s_agent",
      agent: "researcher",
    });
  });

  it("does NOT advance the schedule's own cadence", async () => {
    // Rust: a manual run is an ad-hoc EXTRA fire, not a replacement for the
    // schedule's cadence. Advancing here would let an operator pressing the
    // button repeatedly skip the schedule forward indefinitely.
    await createSchedule({ id: "s_noadv", spec_kind: "interval", interval_secs: 3600 });
    const before = await rawDocument(SCHEDULE_COLLECTION, "s_noadv");
    await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_noadv/run-now`, {
      method: "POST",
      headers: bearer(KEY),
    });
    const after = await rawDocument(SCHEDULE_COLLECTION, "s_noadv");
    expect(after?.next_fire_at_unix).toBe(before?.next_fire_at_unix);
    expect(after?.last_fire_at_unix).toBeNull();
  });

  it("serves the fire history newest slot first", async () => {
    // Guards: the sort in `listFires`. The question an operator asks a fire log
    // is "did the last one work"; document order answers it only by accident.
    await createSchedule({ id: "s_hist", cron_expr: "0 3 * * *" });
    await seedD1(SCHEDULE_FIRE_COLLECTION, [
      { id: "f_old", schedule_id: "s_hist", scheduled_fire_at_unix: 100, outcome: "dispatched" },
      { id: "f_new", schedule_id: "s_hist", scheduled_fire_at_unix: 900, outcome: "error" },
      { id: "f_mid", schedule_id: "s_hist", scheduled_fire_at_unix: 500, outcome: "dispatched" },
      { id: "f_other", schedule_id: "elsewhere", scheduled_fire_at_unix: 999, outcome: "error" },
    ]);
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_hist/fires`, {
      headers: bearer(KEY),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((row) => row.id)).toEqual(["f_new", "f_mid", "f_old"]);
  });

  it("a tenant-scoped caller cannot run another tenant's schedule", async () => {
    await createSchedule({ id: "s_theirs", cron_expr: "0 3 * * *" }, TENANT_A_KEY);
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_theirs/run-now`, {
      method: "POST",
      headers: bearer(TENANT_B_KEY),
    });
    // 404, never 403: a 403 would confirm the schedule exists across the
    // tenant boundary.
    expect(response.status).toBe(404);
    expect(
      await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, scheduledDispatchId("s_theirs", 0)),
    ).toBeNull();
  });
});

describe("MOUNT: delete cascades the fire ledger", () => {
  it("removes the schedule's fire rows so a recreated id is not pre-suppressed", async () => {
    // Guards: the cascade loop in `deleteSchedule`. `sql/d1-ts/tenant/…` says
    // out loud that the Postgres ON DELETE CASCADE is gone in this dialect and
    // the delete must cascade itself. Without it, recreating a schedule under
    // the same id inherits the old ledger and the at-most-once gate suppresses
    // the new schedule's fires.
    await createSchedule({ id: "s_del", cron_expr: "0 3 * * *" });
    await seedD1(SCHEDULE_FIRE_COLLECTION, [
      { id: agentScheduleFireId("s_del", 100), schedule_id: "s_del", scheduled_fire_at_unix: 100 },
      { id: agentScheduleFireId("s_del", 200), schedule_id: "s_del", scheduled_fire_at_unix: 200 },
      { id: agentScheduleFireId("other", 100), schedule_id: "other", scheduled_fire_at_unix: 100 },
    ]);

    const deleted = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_del`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);

    expect(
      await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("s_del", 100)),
    ).toBeNull();
    expect(
      await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("s_del", 200)),
    ).toBeNull();
    // Another schedule's ledger is untouched — a cascade that swept the whole
    // collection would be a much worse bug than the one it fixes.
    expect(
      await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("other", 100)),
    ).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// MOUNT 3 — the tenancy lifecycle gate is threaded into the engine
// ---------------------------------------------------------------------------

describe("MOUNT: a suspended tenancy stops its schedules firing", () => {
  /**
   * Guards: the `lifecycle: deps.lifecycle` line in `engineDeps`.
   *
   * A tenant-scoped caller cannot reach `run-now` at all once its tenant is
   * suspended — `contractAuth` stops it a layer earlier. The hole this closes
   * is the one auth cannot see: a PLATFORM OPERATOR (whose own tenancy is
   * empty, so the gate lets it through) firing a SUSPENDED tenant's schedule,
   * and — the reason it matters — the unattended tick, which has no caller and
   * therefore no auth at all. Suspension that does not stop scheduled spend is
   * #514's decorative status column on a timer.
   */
  beforeEach(async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts`,
      jsonRequest(KEY, "POST", { id: "tenant_susp", tenant_id: "tenant_susp", name: "S" }),
    );
  });

  async function suspend(): Promise<void> {
    const patched = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/tenant_susp`,
      jsonRequest(KEY, "PATCH", { status: "suspended" }),
    );
    expect(patched.status).toBe(200);
  }

  it("run-now records an error outcome and dispatches nothing", async () => {
    await createSchedule({ id: "s_susp", cron_expr: "0 3 * * *", tenant_id: "tenant_susp" });
    await suspend();

    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_susp/run-now`, {
      method: "POST",
      headers: bearer(KEY),
    });
    expect(response.status).toBe(202);
    const body = (await response.json()) as {
      fire: { outcome: string; detail: string; dispatch_id: string | null };
    };
    expect(body.fire.outcome).toBe("error");
    expect(body.fire.dispatch_id).toBeNull();
    // The refusal names the root cause rather than a bare failure.
    expect(body.fire.detail).toMatch(/suspend/i);

    // Nothing was queued. This is the assertion the response alone cannot make.
    const queued = await db()
      .prepare(
        "SELECT COUNT(*) AS n FROM control_plane_resources WHERE resource_kind = ? AND json_extract(document_json, '$.schedule_id') = ?",
      )
      .bind(SELF_HOSTED_DISPATCH_COLLECTION, "s_susp")
      .first<{ n: number }>();
    expect(queued?.n).toBe(0);
  });

  it("run-now still dispatches while the tenant is active", async () => {
    // The control for the assertion above: without it, "no dispatch" could be
    // any unrelated failure rather than the gate.
    await createSchedule({ id: "s_active", cron_expr: "0 3 * * *", tenant_id: "tenant_susp" });
    const response = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_active/run-now`, {
      method: "POST",
      headers: bearer(KEY),
    });
    const body = (await response.json()) as { fire: { outcome: string } };
    expect(body.fire.outcome).toBe("dispatched");
  });

  it("the unattended tick refuses a suspended tenant's due schedule", async () => {
    await createSchedule({
      id: "s_tick_susp",
      spec_kind: "interval",
      interval_secs: 60,
      tenant_id: "tenant_susp",
    });
    await suspend();

    // Exactly ON the slot, not an hour past it: a far-future `now` would make
    // this a CATCH-UP, which `skip_missed` fast-forwards before the gate is
    // ever consulted — the test would then pass without the gate existing.
    const slot = (await rawDocument(SCHEDULE_COLLECTION, "s_tick_susp"))
      ?.next_fire_at_unix as number;
    const now = slot;
    const store = new D1ControlPlaneStore(db(), { requestId: "tick-lifecycle" });
    const gate = resolveLifecycle(
      { CONTROL_PLANE_STORE: undefined, TENANCY_LIFECYCLE: "{}", DB: db() } as never,
      store,
    );
    const summary = await runScheduleTick({ store, lifecycle: gate }, now);
    expect(summary.errors).toEqual(["s_tick_susp"]);
    expect(summary.fired).toEqual([]);

    const queued = await db()
      .prepare(
        "SELECT COUNT(*) AS n FROM control_plane_resources WHERE resource_kind = ? AND json_extract(document_json, '$.schedule_id') = ?",
      )
      .bind(SELF_HOSTED_DISPATCH_COLLECTION, "s_tick_susp")
      .first<{ n: number }>();
    expect(queued?.n).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// The tick loop, against the same real D1 store
// ---------------------------------------------------------------------------

describe("runScheduleTick against the real control database", () => {
  const store = () => new D1ControlPlaneStore(db(), { requestId: "tick-test" });

  async function seedSchedule(record: Record<string, unknown>): Promise<void> {
    await seedD1(SCHEDULE_COLLECTION, [
      { tenant_id: "tenant_a", enabled: true, ...record } as never,
    ]);
  }

  it("fires a due schedule: ledger row, dispatch, and an advanced cadence", async () => {
    const now = 2_000_000;
    await seedSchedule({
      id: "t_due",
      spec_kind: "interval",
      interval_secs: 600,
      next_fire_at_unix: now - 5,
    });

    const summary = await runScheduleTick({ store: store() }, now);
    expect(summary.fired).toEqual(["t_due"]);

    const fire = await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("t_due", now - 5));
    expect(fire).toMatchObject({ schedule_id: "t_due", outcome: "dispatched" });
    expect(
      await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, scheduledDispatchId("t_due", now - 5)),
    ).not.toBeNull();

    const schedule = await rawDocument(SCHEDULE_COLLECTION, "t_due");
    expect(schedule?.last_fire_at_unix).toBe(now - 5);
    expect(schedule?.next_fire_at_unix).toBe(now + 595);
  });

  it("is at-most-once per slot: a second tick over the same slot does not re-fire", async () => {
    // THE gate. `agentScheduleFireId` makes two Workers racing one slot mint
    // the same primary key, and `store.create` is INSERT … ON CONFLICT DO
    // NOTHING RETURNING, so the loser never dispatches. Simulated here by
    // rewinding the schedule onto the slot it already fired.
    //
    // `overlap_policy: "allow"` is LOAD-BEARING in this fixture, not decoration.
    // With the default `skip`, the second tick short-circuits on the previous
    // dispatch still being unacked and returns `skipped` WITHOUT ever reaching
    // the claim — so the test passed with the gate mutated out, i.e. it proved
    // the overlap policy and nothing about at-most-once. Caught by mutation.
    const now = 3_000_000;
    await seedSchedule({
      id: "t_once",
      spec_kind: "interval",
      interval_secs: 600,
      overlap_policy: "allow",
      next_fire_at_unix: now,
    });
    expect((await runScheduleTick({ store: store() }, now)).fired).toEqual(["t_once"]);

    await db()
      .prepare(
        "UPDATE control_plane_resources SET document_json = json_set(document_json, '$.next_fire_at_unix', ?) WHERE resource_kind = ? AND resource_id = ?",
      )
      .bind(now, SCHEDULE_COLLECTION, "t_once")
      .run();

    const second = await runScheduleTick({ store: store() }, now);
    expect(second.fired).toEqual([]);
    expect(second.skipped).toEqual(["t_once"]);
    // And there is still exactly ONE fire row for the slot — the ledger is the
    // evidence, not the summary.
    const rows = await db()
      .prepare(
        "SELECT COUNT(*) AS n FROM control_plane_resources WHERE resource_kind = ? AND json_extract(document_json, '$.schedule_id') = ?",
      )
      .bind(SCHEDULE_FIRE_COLLECTION, "t_once")
      .first<{ n: number }>();
    expect(rows?.n).toBe(1);
  });

  it("skip_missed fast-forwards a backlog WITHOUT firing the missed slots", async () => {
    const now = 4_000_000;
    await seedSchedule({
      id: "t_catchup",
      spec_kind: "interval",
      interval_secs: 60,
      catchup_policy: "skip_missed",
      next_fire_at_unix: now - 3600, // an hour of missed one-minute slots
    });

    const summary = await runScheduleTick({ store: store() }, now);
    expect(summary.advanced).toEqual(["t_catchup"]);
    expect(summary.fired).toEqual([]);
    // No dispatch at all — the point of n8n semantics is that an hour of
    // downtime does not become sixty queued runs the tenant pays for.
    expect(
      await rawDocument(
        SELF_HOSTED_DISPATCH_COLLECTION,
        scheduledDispatchId("t_catchup", now - 3600),
      ),
    ).toBeNull();
    const schedule = await rawDocument(SCHEDULE_COLLECTION, "t_catchup");
    expect(schedule?.next_fire_at_unix as number).toBeGreaterThan(now);
  });

  it("fire_once fires exactly one catch-up for the backlog, then fast-forwards", async () => {
    const now = 5_000_000;
    await seedSchedule({
      id: "t_once_catchup",
      spec_kind: "interval",
      interval_secs: 60,
      catchup_policy: "fire_once",
      next_fire_at_unix: now - 3600,
    });

    const summary = await runScheduleTick({ store: store() }, now);
    expect(summary.fired).toEqual(["t_once_catchup"]);
    const schedule = await rawDocument(SCHEDULE_COLLECTION, "t_once_catchup");
    expect(schedule?.next_fire_at_unix as number).toBeGreaterThan(now);

    // And the very next tick must NOT fire again — one catch-up, not sixty.
    expect((await runScheduleTick({ store: store() }, now)).fired).toEqual([]);
  });

  it("overlap=skip suppresses a fire while the previous dispatch is unacked", async () => {
    const now = 6_000_000;
    const previousSlot = now - 600;
    await seedSchedule({
      id: "t_overlap",
      spec_kind: "interval",
      interval_secs: 600,
      overlap_policy: "skip",
      next_fire_at_unix: now,
      last_fire_at_unix: previousSlot,
    });
    await seedD1(SELF_HOSTED_DISPATCH_COLLECTION, [
      {
        id: scheduledDispatchId("t_overlap", previousSlot),
        tenant_id: "tenant_a",
        status: "queued",
      },
    ]);

    const summary = await runScheduleTick({ store: store() }, now);
    expect(summary.skipped).toEqual(["t_overlap"]);
    // The suppression is RECORDED, not silent: an operator asking why a slot
    // did nothing gets an answer.
    expect(
      await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("t_overlap", now)),
    ).toMatchObject({ outcome: "skipped_overlap" });
    expect(
      await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, scheduledDispatchId("t_overlap", now)),
    ).toBeNull();
  });

  it("overlap=skip does NOT suppress once the previous dispatch is terminal", async () => {
    const now = 6_100_000;
    const previousSlot = now - 600;
    await seedSchedule({
      id: "t_overlap_done",
      spec_kind: "interval",
      interval_secs: 600,
      overlap_policy: "skip",
      next_fire_at_unix: now,
      last_fire_at_unix: previousSlot,
    });
    await seedD1(SELF_HOSTED_DISPATCH_COLLECTION, [
      {
        id: scheduledDispatchId("t_overlap_done", previousSlot),
        tenant_id: "tenant_a",
        status: "completed",
      },
    ]);
    expect((await runScheduleTick({ store: store() }, now)).fired).toEqual(["t_overlap_done"]);
  });

  it("overlap=allow fires straight through an in-flight dispatch", async () => {
    const now = 6_200_000;
    const previousSlot = now - 600;
    await seedSchedule({
      id: "t_allow",
      spec_kind: "interval",
      interval_secs: 600,
      overlap_policy: "allow",
      next_fire_at_unix: now,
      last_fire_at_unix: previousSlot,
    });
    await seedD1(SELF_HOSTED_DISPATCH_COLLECTION, [
      { id: scheduledDispatchId("t_allow", previousSlot), tenant_id: "tenant_a", status: "queued" },
    ]);
    expect((await runScheduleTick({ store: store() }, now)).fired).toEqual(["t_allow"]);
  });

  it("never fires a disabled schedule", async () => {
    const now = 7_000_000;
    await seedSchedule({
      id: "t_off",
      enabled: false,
      spec_kind: "interval",
      interval_secs: 60,
      next_fire_at_unix: now - 1,
    });
    const summary = await runScheduleTick({ store: store() }, now);
    expect(summary.fired).toEqual([]);
    expect(summary.advanced).toEqual([]);
    expect(
      await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("t_off", now - 1)),
    ).toBeNull();
  });

  it("never fires a schedule whose slot has not arrived", async () => {
    const now = 7_100_000;
    await seedSchedule({
      id: "t_future",
      spec_kind: "interval",
      interval_secs: 60,
      next_fire_at_unix: now + 1,
    });
    expect((await runScheduleTick({ store: store() }, now)).fired).toEqual([]);
  });

  it("holds jitter back until the offset has elapsed, then fires the SAME slot", async () => {
    // `jitter_secs` is stored-and-inert in Rust; here it delays dispatch within
    // the slot without changing the slot key, so the ledger is unaffected.
    const now = 7_200_000;
    await seedSchedule({
      id: "t_jitter",
      spec_kind: "interval",
      interval_secs: 600,
      jitter_secs: 300,
      next_fire_at_unix: now,
    });
    // The offset is deterministic, so this asserts against the real value
    // rather than a guess: at `now` the schedule is either already due (offset
    // 0) or held back — and one full jitter window later it is due either way.
    const held = await runScheduleTick({ store: store() }, now);
    const later = await runScheduleTick({ store: store() }, now + 300);
    expect([...held.fired, ...later.fired]).toEqual(["t_jitter"]);
    // Whichever tick fired it, the slot recorded is the SLOT, not the jittered
    // moment — otherwise two isolates with different clocks would claim two
    // different keys for one slot.
    expect(
      await rawDocument(SCHEDULE_FIRE_COLLECTION, agentScheduleFireId("t_jitter", now)),
    ).not.toBeNull();
  });

  it("bounds one tick's work to the batch size", async () => {
    const now = 8_000_000;
    for (let index = 0; index < 5; index += 1) {
      await seedSchedule({
        id: `t_batch_${index}`,
        spec_kind: "interval",
        interval_secs: 600,
        next_fire_at_unix: now - (10 - index),
      });
    }
    const summary = await runScheduleTick({ store: store() }, now, 2);
    expect(summary.fired).toHaveLength(2);
    // Oldest slot first, so a backlog drains fairly instead of letting one
    // schedule starve behind whatever document order happens to be.
    expect(summary.fired).toEqual(["t_batch_0", "t_batch_1"]);
  });

  it("one poisoned schedule does not stop the tick for other tenants", async () => {
    const now = 9_000_000;
    await seedSchedule({
      id: "t_poison",
      spec_kind: "cron",
      cron_expr: "0 0 31 2 *", // parses, but never occurs
      next_fire_at_unix: now - 1,
    });
    await seedSchedule({
      id: "t_healthy",
      spec_kind: "interval",
      interval_secs: 60,
      next_fire_at_unix: now - 1,
    });
    const summary = await runScheduleTick({ store: store() }, now);
    expect(summary.fired).toContain("t_healthy");
  });
});

// ---------------------------------------------------------------------------
// The `scheduled` seam — proven here, MOUNTED by the integrate step
// ---------------------------------------------------------------------------

describe("the scheduled handler (src/schedule/scheduled.ts)", () => {
  /**
   * The tick's composition root is `src/worker.ts`, which this slice may not
   * edit, so there is no `SELF`-driven mount gate to write for it. What CAN be
   * proven — and is, here — is that the exported handler builds its deps from
   * the real bindings and drives a real fire end to end, so the integrate step
   * only has to add `export { scheduled } from "./schedule/scheduled.js";`
   * plus a `[triggers] crons` stanza. See that module's docblock for the exact
   * lines and for the plain statement that until they land, nothing fires on
   * its own.
   */
  it("fires a due schedule through the SAME deps resolveDeps builds for a request", async () => {
    const created = await createSchedule({
      id: "s_cron",
      spec_kind: "interval",
      interval_secs: 60,
    });
    expect(created.status).toBe(201);
    const slot = (await rawDocument(SCHEDULE_COLLECTION, "s_cron"))?.next_fire_at_unix as number;

    const report = await runScheduledTick(
      { ...(env as unknown as Record<string, unknown>), CONTROL_PLANE_STORE: undefined } as never,
      slot,
    );
    expect(report.at).toBe(slot);
    expect(report.fired).toEqual(["s_cron"]);
    expect(
      await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, scheduledDispatchId("s_cron", slot)),
    ).not.toBeNull();
  });

  it("exports a handler with the shape workerd requires of `scheduled`", async () => {
    // A `scheduled` export that is not callable with (controller, env, ctx)
    // fails the Worker at STARTUP, not at the first cron — so the shape is
    // worth an assertion rather than a deploy.
    expect(typeof scheduled).toBe("function");
    await createSchedule({ id: "s_cron2", spec_kind: "interval", interval_secs: 60 });
    const slot = (await rawDocument(SCHEDULE_COLLECTION, "s_cron2"))?.next_fire_at_unix as number;
    await scheduled(
      { scheduledTime: slot * 1000, cron: "* * * * *", noRetry: () => {} },
      { ...(env as unknown as Record<string, unknown>), CONTROL_PLANE_STORE: undefined } as never,
      { waitUntil: () => {}, passThroughOnException: () => {}, props: {} } as never,
    );
    expect(
      await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, scheduledDispatchId("s_cron2", slot)),
    ).not.toBeNull();
  });
});
