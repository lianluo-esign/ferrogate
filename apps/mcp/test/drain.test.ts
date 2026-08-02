/**
 * `apps/mcp`'s half of the operator drain (FC-1): the MOUNT, the probes, and
 * the fail-closed posture.
 *
 * `test/drain-fleet.test.ts` owns the FLEET property — one
 * `POST /admin/v1/drain`, both spend Workers shut. This file owns the three
 * things that are about THIS Worker and would otherwise have no gate:
 *
 *  1. **the probes.** What `/healthz` and `/readyz` answer while draining is a
 *     load-balancer contract, and getting it backwards is worse than having no
 *     drain: `/healthz` must stay 200 (liveness — a drained node is ALIVE, and
 *     flipping it makes an orchestrator RESTART the node, destroying the
 *     in-flight work the drain exists to let finish) while `/readyz` must
 *     answer 503 `operator_drain` (readiness — stop sending me new traffic).
 *  2. **fail-closed on a lookup error.** A control that admits when its backend
 *     is unavailable recreates the bypass in a new form. `src/drain.ts` refuses
 *     with a DISTINCT code rather than claiming `node_draining`, because
 *     telling an operator the node is draining while `GET /admin/v1/drain` says
 *     it is not is an incident-time lie.
 *  3. **the precedence rule**, tested directly, because `apps/mcp` declares no
 *     drain var and so cannot exercise the `GATEWAY_DRAIN` arm behaviourally.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  DRAIN_COLLECTION,
  DRAIN_ID,
  DRAIN_UNAVAILABLE_CODE,
  NOT_DRAINING,
  RESOURCE_TABLE,
  combineDrain,
  drainRefusal,
  drainVarSet,
  parseDrainDocument,
  readDurableDrain,
  resolveDrain,
} from "../src/drain.js";
import type { McpEnv } from "../src/ports.js";
import { readinessReport } from "../src/routes/index.js";
import { seedFixture } from "./fixtures.js";

interface Bindings {
  readonly DB: D1Database;
  /** Migrated with the TENANT schema, which has NO `control_plane_resources`. */
  readonly TENANT_DB_A: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

const bindings = (): Bindings => env as unknown as Bindings;
const control = (): D1Database => bindings().DB;

async function setDrain(draining: boolean, reason: string | null = null): Promise<void> {
  await control()
    .prepare(
      `INSERT INTO ${RESOURCE_TABLE}
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 1, 1, 1)
       ON CONFLICT (resource_kind, resource_id) DO UPDATE SET
         document_json = excluded.document_json`,
    )
    .bind(
      DRAIN_COLLECTION,
      DRAIN_ID,
      JSON.stringify({ id: DRAIN_ID, draining, reason, changed_at: 1, tenant_id: null }),
    )
    .run();
}

/** Write a raw document, for the shapes the writer would never produce. */
async function setRawDrainDocument(document: unknown): Promise<void> {
  await control()
    .prepare(
      `INSERT INTO ${RESOURCE_TABLE}
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 1, 1, 1)
       ON CONFLICT (resource_kind, resource_id) DO UPDATE SET
         document_json = excluded.document_json`,
    )
    .bind(
      DRAIN_COLLECTION,
      DRAIN_ID,
      typeof document === "string" ? document : JSON.stringify(document),
    )
    .run();
}

async function clearDrain(): Promise<void> {
  await control()
    .prepare(`DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`)
    .bind(DRAIN_COLLECTION, DRAIN_ID)
    .run();
}

beforeAll(async () => {
  const b = bindings();
  await applyD1Migrations(b.DB, b.TEST_CONTROL_D1_SCHEMA);
  await applyD1Migrations(b.TENANT_DB_A, b.TEST_TENANT_D1_SCHEMA);
});

beforeEach(async () => {
  await clearDrain();
  seedFixture();
});

// `.wrangler/state` persists across FILES, so a leftover drain row would refuse
// traffic in every other suite.
afterEach(clearDrain);

// ---------------------------------------------------------------------------

describe("what /healthz and /readyz answer while draining", () => {
  it("/healthz stays 200 — a drained node is ALIVE", async () => {
    await setDrain(true, "pre-migration");
    const response = await SELF.fetch("https://ferrogate.test/healthz");
    expect(response.status).toBe(200);
    expect(((await response.json()) as { status: string }).status).toBe("ok");
  });

  it("/readyz answers 503 not_ready with readiness_reason operator_drain", async () => {
    await setDrain(true, "pre-migration");
    const response = await SELF.fetch("https://ferrogate.test/readyz");
    expect(response.status).toBe(503);
    const body = (await response.json()) as {
      status: string;
      readiness_reason: string;
      draining: boolean;
      accepting_new_requests: boolean;
      dependencies: { ready: boolean };
    };
    expect(body.status).toBe("not_ready");
    expect(body.readiness_reason).toBe("operator_drain");
    expect(body.draining).toBe(true);
    expect(body.accepting_new_requests).toBe(false);
    // The dependencies are FINE — it is the operator who stopped the traffic.
    // Collapsing the two would tell an operator their ports are unbound.
    expect(body.dependencies.ready).toBe(true);
  });

  it("an UNEVALUABLE drain is drain_state_unavailable, NOT operator_drain", () => {
    // Found by the wave-22 INTEGRATE boot proof, not by this suite: a fresh
    // `wrangler dev --local` answered `503 not_ready` with
    // `readiness_reason: "operator_drain"` and `draining: true` on a deployment
    // NOBODY HAD DRAINED — because the local D1 had no schema, the durable
    // lookup failed, and `readinessReport` collapsed `unavailable` onto the
    // drain arm. Refusing is correct and non-negotiable; telling an operator
    // mid-incident that the fleet is draining while `GET /admin/v1/drain` says
    // it is not is the exact lie `drainRefusal` splits into two codes on the
    // data plane, and the probe now splits the same two.
    //
    // Driven through `readinessReport` rather than over `SELF` because this
    // harness MIGRATES the control database — which is precisely why the arm
    // was unreachable here for a whole wave. Reaching it behaviourally would
    // mean unbinding `DB`, and an unbound database is a THIRD fact
    // (`dependencies.ready: false`), not this one.
    const unavailable = {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "unavailable",
      detail: "no such table: control_plane_resources",
    } as const;
    const report = readinessReport(env as unknown as McpEnv, unavailable);
    expect(report.status).toBe(503);
    expect(report.body.status).toBe("not_ready");
    expect(report.body.readiness_reason).toBe(DRAIN_UNAVAILABLE_CODE);
    expect(report.body.readiness_reason).not.toBe("operator_drain");
    // NOT draining: the operator did not drain anything, and a dashboard that
    // reads this field must not show a drain that never happened.
    expect(report.body.draining).toBe(false);
    // Still refusing, though — `accepting_new_requests` is about whether work
    // should be sent here, and it must not be while the control is unreadable.
    expect(report.body.accepting_new_requests).toBe(false);
    // And the ordinary drain still reports itself, so the split is not a
    // blanket rename.
    const drained = readinessReport(env as unknown as McpEnv, {
      draining: true,
      accepting_new_requests: false,
      reason: "migration window",
      source: "durable",
    });
    expect(drained.body.readiness_reason).toBe("operator_drain");
    expect(drained.body.draining).toBe(true);
  });

  it("/readyz is 200 ready again once the drain is lifted", async () => {
    // The negative control: without it, `not_ready` above could be this
    // Worker's permanent answer for an unrelated reason.
    await setDrain(false);
    const response = await SELF.fetch("https://ferrogate.test/readyz");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { status: string; draining: boolean };
    expect(body.status).toBe("ready");
    expect(body.draining).toBe(false);
  });
});

describe("FAIL CLOSED — a drain lookup that cannot be answered refuses", () => {
  it("refuses with a DISTINCT code when the control table is unreachable", async () => {
    // `TENANT_DB_A` carries the TENANT schema: `control_plane_resources` does
    // not exist there, so the prepared statement throws exactly as a D1 outage
    // would. A resolver that swallowed the error and returned "not draining"
    // would admit every caller during an outage — the free-traffic hole
    // `src/admission/gate.ts` refuses for the same reason.
    const state = await readDurableDrain(bindings().TENANT_DB_A);
    expect(state.source).toBe("unavailable");
    expect(state.draining).toBe(true);
    expect(state.accepting_new_requests).toBe(false);

    const refusal = drainRefusal(state);
    expect(refusal?.status).toBe(503);
    expect(refusal?.code).toBe("drain_state_unavailable");
    // NOT `node_draining`: the node is not draining, the control is unreadable,
    // and `GET /admin/v1/drain` would say so. Two facts, two codes.
    expect(refusal?.code).not.toBe("node_draining");
  });

  it("refuses on a corrupt document rather than serving traffic", async () => {
    await setRawDrainDocument("{not json");
    const state = await resolveDrain({ DB: control() });
    expect(state.source).toBe("unavailable");
    expect(drainRefusal(state)?.code).toBe("drain_state_unavailable");
  });

  it("ADMITS when no control database is bound at all", async () => {
    // The complementary case, and it is NOT a hole: with no control database
    // this Worker has no control plane, `portsBound` is false, and every
    // authenticated surface already answers `503 mcp_auth_unavailable`. "No
    // document" is the honest answer, not a bypass.
    expect(await resolveDrain({})).toEqual(NOT_DRAINING);
  });
});

describe("the document parse is strict in both directions", () => {
  it("only the JSON boolean true drains", async () => {
    for (const value of ["true", 1, "yes", null, undefined]) {
      await setRawDrainDocument({ id: DRAIN_ID, draining: value, tenant_id: null });
      const state = await resolveDrain({ DB: control() });
      expect(state.draining, `draining: ${JSON.stringify(value)}`).toBe(false);
    }
    await setDrain(true);
    expect((await resolveDrain({ DB: control() })).draining).toBe(true);
  });

  it("IGNORES a tenant-attributed drain row", async () => {
    // The operator drain is DEPLOYMENT state that every Worker reads by primary
    // key. If a tenant-scoped admin could mint it under their own `tenant_id`,
    // one tenant would drain the whole fleet — a cross-tenant denial of
    // service. `apps/control-plane` refuses to write one (see
    // `test/drain.test.ts` there); this refuses to believe one.
    await setRawDrainDocument({
      id: DRAIN_ID,
      draining: true,
      reason: "hostile",
      tenant_id: "tenant-b",
    });
    const state = await resolveDrain({ DB: control() });
    expect(state.draining).toBe(false);
    expect(drainRefusal(state)).toBeNull();
  });

  it("carries the operator's reason through", async () => {
    await setDrain(true, "pre-migration");
    const state = await resolveDrain({ DB: control() });
    expect(state).toEqual({
      draining: true,
      accepting_new_requests: false,
      reason: "pre-migration",
      source: "durable",
    });
  });
});

describe("the precedence rule — durable OR deploy var, never latest-wins", () => {
  it("either source drains, and neither cancels the other", () => {
    const durableDraining = parseDrainDocument({ draining: true, tenant_id: null });
    expect(combineDrain(NOT_DRAINING, false)).toEqual(NOT_DRAINING);
    // The var alone drains a deployment whose document says otherwise…
    expect(combineDrain(NOT_DRAINING, true).draining).toBe(true);
    expect(combineDrain(NOT_DRAINING, true).source).toBe("deploy_var");
    // …and the document alone drains a deployment whose var is unset.
    expect(combineDrain(durableDraining, false).draining).toBe(true);
    expect(combineDrain(durableDraining, false).source).toBe("durable");
    // A `{"draining": false}` API call CANNOT re-admit traffic to a deployment
    // drained at deploy time for a migration. That direction is the whole point
    // of OR rather than "the newest write wins".
    expect(combineDrain(NOT_DRAINING, true).draining).toBe(true);
  });

  it("a lookup failure outranks BOTH sources", () => {
    const unavailable = {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "unavailable",
      detail: "boom",
    } as const;
    expect(combineDrain(unavailable, false)).toEqual(unavailable);
    expect(combineDrain(unavailable, true)).toEqual(unavailable);
    expect(drainRefusal(combineDrain(unavailable, true))?.code).toBe("drain_state_unavailable");
  });

  it("parses the var exactly as GATEWAY_DRAIN does — only `true` drains", () => {
    // A typo'd var must not take a deployment out of rotation, and must not
    // silently keep a drained one in it either.
    expect(drainVarSet("true")).toBe(true);
    expect(drainVarSet(" TRUE ")).toBe(true);
    for (const value of ["1", "yes", "on", "false", "", undefined]) {
      expect(drainVarSet(value), `var ${String(value)}`).toBe(false);
    }
  });
});
