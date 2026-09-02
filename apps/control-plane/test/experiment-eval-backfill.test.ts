/**
 * `POST /admin/v1/experiment-eval-backfill` driven through the EXPORTED Worker
 * with the D1 store live (production default), so the sweep reads the REAL
 * control `experiment_shadow_legs` / `online_eval_scores` projection facades and
 * writes the REAL tenant objects — the boundary the deploy-ordering keystone
 * actually crosses.
 *
 * The load-bearing proofs:
 *
 *  - **verbatim column copy** — a row seeded DIRECTLY onto the control facade
 *    (never through the route, so it lands only on control, exactly as a leg
 *    produced before the gateway dual-write shipped would) reappears byte for
 *    byte in the owning tenant object, under the NATURAL primary key, with the
 *    control-only `projection_key` dropped;
 *  - **the gate** — with `CONTROL_EXPERIMENT_EVAL_BACKFILL` unset/`"off"` the
 *    route refuses `409` and writes nothing, so an un-armed deploy cannot begin
 *    the relocation;
 *  - **resumability** — a `projection_key` cursor is honoured (WHERE
 *    projection_key > ?) and threaded across calls with `page_size`, covering a
 *    table one page at a time without double-counting.
 *
 * The env-var override that arms the gate follows `siem-export.test.ts`: mutate
 * the shared `env` in `beforeEach`, restore the committed `"off"` in `afterEach`.
 * Per-file isolate isolation keeps the mutation out of `env-var-drift.test.ts`.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { registerObjectTenants, tenantObjectDb } from "./tenant-object.js";

const KEY = operatorKey.secret;
const TENANT_A_KEY = "tenant-a-secret";
const PATH = `${BASE}/admin/v1/experiment-eval-backfill`;
const ACK = "BACKFILL_EXPERIMENT_EVAL";
const FLAG = "CONTROL_EXPERIMENT_EVAL_BACKFILL";

type MutableEnv = Record<string, string | undefined>;

/**
 * Seed one `experiment_shadow_legs` row DIRECTLY onto the control facade — never
 * through any route — so it exists ONLY on control, the state of every leg
 * produced before the gateway dual-write shipped. `projection_key` is the
 * control PRIMARY KEY that orders the sweep and is dropped on copy; `latencyMs`
 * is a distinguishing nullable value that must survive the copy verbatim.
 */
async function seedControlShadowLeg(opts: {
  projectionKey: string;
  legId: string;
  tenant: string;
  latencyMs?: number | null;
}): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO experiment_shadow_legs
         (projection_key, leg_id, client_request_id, experiment_id, tenant,
          logical_model, provider, provider_model, latency_ms, observed_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      opts.projectionKey,
      opts.legId,
      `${opts.legId}~client`,
      "exp-1",
      opts.tenant,
      "gpt-4",
      "openai",
      "gpt-4-0613",
      opts.latencyMs ?? null,
      1_700_000_000,
    )
    .run();
}

/** Seed one control-only `online_eval_scores` row — see {@link seedControlShadowLeg}. */
async function seedControlEvalScore(opts: {
  projectionKey: string;
  requestId: string;
  criterionId: string;
  tenant: string;
  score?: number;
}): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO online_eval_scores
         (projection_key, request_id, criterion_id, tenant,
          sampling_key, sampling_unit, sample_rate, judge_model, score, scored_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      opts.projectionKey,
      opts.requestId,
      opts.criterionId,
      opts.tenant,
      "samp-1",
      "request",
      1,
      "judge-1",
      opts.score ?? 0.87,
      1_700_000_000,
    )
    .run();
}

/** The full copied leg row straight out of the owning object, or `null`. */
function objectShadowLeg(tenantId: string, legId: string): Promise<Record<string, unknown> | null> {
  return tenantObjectDb(tenantId)
    .prepare("SELECT * FROM experiment_shadow_legs WHERE leg_id = ?")
    .bind(legId)
    .first<Record<string, unknown>>();
}

/** The full copied score row straight out of the owning object, or `null`. */
function objectEvalScore(
  tenantId: string,
  requestId: string,
  criterionId: string,
): Promise<Record<string, unknown> | null> {
  return tenantObjectDb(tenantId)
    .prepare("SELECT * FROM online_eval_scores WHERE request_id = ? AND criterion_id = ?")
    .bind(requestId, criterionId)
    .first<Record<string, unknown>>();
}

/**
 * `resetD1` truncates neither projection family (control facade nor tenant
 * object), so a prior test's rows would make a later "empty first" precondition
 * lie or double the sweep's source count. Wipe both, control and both fixture
 * objects, exactly like the roster-driven cleanup does for the tables it owns.
 */
async function cleanProjectionTables(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM experiment_shadow_legs"),
    db().prepare("DELETE FROM online_eval_scores"),
  ]);
  for (const tenantId of ["tenant_a", "tenant_b"]) {
    const object = tenantObjectDb(tenantId);
    await object.batch([
      object.prepare("DELETE FROM experiment_shadow_legs"),
      object.prepare("DELETE FROM online_eval_scores"),
    ]);
  }
}

interface TableResult {
  source_rows: number;
  written: number;
  next_cursor: string | null;
  skipped: { unprovisioned: number; non_durable_object: number };
  residuals: number;
  errors: Record<string, string>;
}

interface BackfillReport {
  acknowledged: boolean;
  dry_run: boolean;
  page_size: number;
  // The route always emits BOTH families, so they are required here — direct
  // property access rather than an index that `noUncheckedIndexedAccess` widens.
  per_table: {
    experiment_shadow_legs: TableResult;
    online_eval_scores: TableResult;
  };
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_A_KEY, "tenant_a")],
  });
  await registerObjectTenants(["tenant_a", "tenant_b"]);
  await cleanProjectionTables();
  // Arm the gate for the copy suites; the gate-off test overrides this back.
  (env as unknown as MutableEnv)[FLAG] = "on";
});

afterEach(() => {
  // Restore the value `wrangler.toml` commits, so no test leaks an armed gate.
  (env as unknown as MutableEnv)[FLAG] = "off";
});

describe("experiment-eval-backfill fences", () => {
  it("fence 1: a missing key is 401", async () => {
    const res = await SELF.fetch(PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ acknowledge: ACK }),
    });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "missing_api_key" } });
  });

  it("fence 1: a tenant-scoped key is 403 platform_operator_required", async () => {
    const res = await SELF.fetch(PATH, jsonRequest(TENANT_A_KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({
      error: { code: "platform_operator_required" },
    });
  });

  it("fence 2: acknowledge must be the literal BACKFILL_EXPERIMENT_EVAL", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: "BACKFILL_QUOTA_POLICIES" }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "acknowledge_required" } });
  });

  it("a non-boolean dry_run is 400 before any write", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: ACK, dry_run: "yes" }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "invalid_request_body" } });
  });

  it("a non-integer page_size is 400", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: ACK, page_size: 0 }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "invalid_request_body" } });
  });

  it("a cursor for an unknown table is 400", async () => {
    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: ACK, cursor: { not_a_table: "x" } }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "invalid_request_body" } });
  });

  it("fence 3: an un-armed gate refuses 409 and writes nothing", async () => {
    // The gate-off state a deploy that did not opt in leaves — override the
    // armed value the beforeEach set.
    (env as unknown as MutableEnv)[FLAG] = "off";
    await seedControlShadowLeg({ projectionKey: "pk-a-1", legId: "leg-a-1", tenant: "tenant_a" });

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(409);
    await expect(res.json()).resolves.toMatchObject({ error: { code: "backfill_disabled" } });
    expect(await objectShadowLeg("tenant_a", "leg-a-1")).toBeNull();
  });
});

describe("experiment-eval-backfill copies control rows into tenant objects", () => {
  it("copies both families into the owning object VERBATIM, projection_key dropped", async () => {
    await seedControlShadowLeg({
      projectionKey: "pk-a-1",
      legId: "leg-a-1",
      tenant: "tenant_a",
      latencyMs: 123,
    });
    await seedControlEvalScore({
      projectionKey: "pk-e-1",
      requestId: "req-e-1",
      criterionId: "crit-1",
      tenant: "tenant_a",
      score: 0.87,
    });
    // Precondition: the object has NOTHING yet — what a reader cutover would meet
    // without the backfill.
    expect(await objectShadowLeg("tenant_a", "leg-a-1")).toBeNull();
    expect(await objectEvalScore("tenant_a", "req-e-1", "crit-1")).toBeNull();

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(200);
    const report = (await res.json()) as BackfillReport;
    expect(report.dry_run).toBe(false);
    expect(report.per_table.experiment_shadow_legs).toMatchObject({
      source_rows: 1,
      written: 1,
      next_cursor: null,
    });
    expect(report.per_table.online_eval_scores).toMatchObject({
      source_rows: 1,
      written: 1,
      next_cursor: null,
    });

    const leg = await objectShadowLeg("tenant_a", "leg-a-1");
    expect(leg).toMatchObject({
      leg_id: "leg-a-1",
      client_request_id: "leg-a-1~client",
      experiment_id: "exp-1",
      tenant: "tenant_a",
      provider: "openai",
      provider_model: "gpt-4-0613",
      latency_ms: 123,
    });
    expect(leg?.projection_key).toBeUndefined();

    const score = await objectEvalScore("tenant_a", "req-e-1", "crit-1");
    expect(score).toMatchObject({
      request_id: "req-e-1",
      criterion_id: "crit-1",
      tenant: "tenant_a",
      judge_model: "judge-1",
      score: 0.87,
    });
    expect(score?.projection_key).toBeUndefined();
  });

  it("is idempotent: a second run overwrites and reports the same, no errors", async () => {
    await seedControlShadowLeg({ projectionKey: "pk-a-1", legId: "leg-a-1", tenant: "tenant_a" });

    const first = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(first.status).toBe(200);

    const second = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(second.status).toBe(200);
    const report = (await second.json()) as BackfillReport;
    expect(report.per_table.experiment_shadow_legs.written).toBe(1);
    expect(report.per_table.experiment_shadow_legs.errors).toEqual({});
    expect(await objectShadowLeg("tenant_a", "leg-a-1")).not.toBeNull();
  });

  it("dry_run reports the plan without writing anything", async () => {
    await seedControlShadowLeg({ projectionKey: "pk-a-1", legId: "leg-a-1", tenant: "tenant_a" });

    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: ACK, dry_run: true }),
    );
    expect(res.status).toBe(200);
    const report = (await res.json()) as BackfillReport;
    expect(report.dry_run).toBe(true);
    expect(report.per_table.experiment_shadow_legs.written).toBe(1);
    // Nothing was actually written.
    expect(await objectShadowLeg("tenant_a", "leg-a-1")).toBeNull();
  });

  it("honours a cursor: WHERE projection_key > ? skips already-copied rows", async () => {
    await seedControlShadowLeg({ projectionKey: "pk-a-1", legId: "leg-a-1", tenant: "tenant_a" });
    await seedControlShadowLeg({ projectionKey: "pk-a-2", legId: "leg-a-2", tenant: "tenant_a" });
    await seedControlShadowLeg({ projectionKey: "pk-a-3", legId: "leg-a-3", tenant: "tenant_a" });

    const res = await SELF.fetch(
      PATH,
      jsonRequest(KEY, "POST", { acknowledge: ACK, cursor: { experiment_shadow_legs: "pk-a-2" } }),
    );
    expect(res.status).toBe(200);
    const report = (await res.json()) as BackfillReport;
    // Only the row after the cursor was read and written.
    expect(report.per_table.experiment_shadow_legs.source_rows).toBe(1);
    expect(report.per_table.experiment_shadow_legs.written).toBe(1);
    expect(await objectShadowLeg("tenant_a", "leg-a-1")).toBeNull();
    expect(await objectShadowLeg("tenant_a", "leg-a-2")).toBeNull();
    expect(await objectShadowLeg("tenant_a", "leg-a-3")).not.toBeNull();
  });

  it("pages with next_cursor across calls without double-counting", async () => {
    await seedControlShadowLeg({ projectionKey: "pk-a-1", legId: "leg-a-1", tenant: "tenant_a" });
    await seedControlShadowLeg({ projectionKey: "pk-a-2", legId: "leg-a-2", tenant: "tenant_a" });

    // Page 1: one row, cursor points past it.
    const first = (await (
      await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK, page_size: 1 }))
    ).json()) as BackfillReport;
    expect(first.per_table.experiment_shadow_legs.written).toBe(1);
    const cursor1 = first.per_table.experiment_shadow_legs.next_cursor;
    expect(cursor1).toBe("pk-a-1");

    // Page 2: the next row, cursor still full (page_size 1 === rows read).
    const second = (await (
      await SELF.fetch(
        PATH,
        jsonRequest(KEY, "POST", {
          acknowledge: ACK,
          page_size: 1,
          cursor: { experiment_shadow_legs: cursor1 },
        }),
      )
    ).json()) as BackfillReport;
    expect(second.per_table.experiment_shadow_legs.written).toBe(1);
    const cursor2 = second.per_table.experiment_shadow_legs.next_cursor;
    expect(cursor2).toBe("pk-a-2");

    // Page 3: exhausted — no rows, cursor null, termination signalled.
    const third = (await (
      await SELF.fetch(
        PATH,
        jsonRequest(KEY, "POST", {
          acknowledge: ACK,
          page_size: 1,
          cursor: { experiment_shadow_legs: cursor2 },
        }),
      )
    ).json()) as BackfillReport;
    expect(third.per_table.experiment_shadow_legs.source_rows).toBe(0);
    expect(third.per_table.experiment_shadow_legs.next_cursor).toBeNull();

    // Both legs landed exactly once.
    expect(await objectShadowLeg("tenant_a", "leg-a-1")).not.toBeNull();
    expect(await objectShadowLeg("tenant_a", "leg-a-2")).not.toBeNull();
  });

  it("skips a leg whose owning tenant has no provisioned object", async () => {
    // `tenant_zzz` is a real tenant value but was never registered in the roster.
    await seedControlShadowLeg({ projectionKey: "pk-z-1", legId: "leg-z-1", tenant: "tenant_zzz" });

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(200);
    const report = (await res.json()) as BackfillReport;
    expect(report.per_table.experiment_shadow_legs.written).toBe(0);
    expect(report.per_table.experiment_shadow_legs.skipped.unprovisioned).toBe(1);
  });

  it("reports a leg with an empty tenant as a residual, not a write", async () => {
    await seedControlShadowLeg({ projectionKey: "pk-r-1", legId: "leg-r-1", tenant: "" });

    const res = await SELF.fetch(PATH, jsonRequest(KEY, "POST", { acknowledge: ACK }));
    expect(res.status).toBe(200);
    const report = (await res.json()) as BackfillReport;
    expect(report.per_table.experiment_shadow_legs.written).toBe(0);
    expect(report.per_table.experiment_shadow_legs.residuals).toBe(1);
  });
});
