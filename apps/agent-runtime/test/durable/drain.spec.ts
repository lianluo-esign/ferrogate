/**
 * THE OPERATOR DRAIN, against a REAL migrated control database (FC-1).
 *
 * `apps/mcp/test/drain-fleet.test.ts` proves the FLEET property — one
 * `POST /admin/v1/drain`, both spend Workers shut — and reaches this Worker
 * through its production resolver (`src/drain.ts`) rather than through its
 * router. That leaves exactly one thing unproven, and it is the thing this
 * repository keeps getting wrong: **that the deployed Worker actually MOUNTS
 * it**. A resolver module that exists and is not wired is a green suite over a
 * dead seam.
 *
 * So every request below goes through `SELF.fetch` into the real
 * `src/worker.ts`, with the harness's two bound, MIGRATED databases and the
 * `FG_DEV_*` bundle absent (`harness/wrangler.toml`) — the same posture the
 * other specs in this directory run in. The drain row is written directly into
 * `control_plane_resources`, which is what `apps/control-plane`'s
 * `setAdminDrain` writes, and nothing else about the request changes.
 *
 * ## What is asserted, and why each one is here
 *
 *  1. a guarded operation is ADMITTED with no drain document — the negative
 *     control, without which every refusal below could be caused by anything;
 *  2. the same operation is REFUSED `503 node_draining` with the document set;
 *  3. lifting the drain re-admits it INSIDE THE SAME ISOLATE, which is what a
 *     boot-cached flag cannot do;
 *  4. the reads and the worker-plane callbacks keep serving while draining —
 *     a drain that stranded in-flight jobs would destroy the work it exists to
 *     let finish;
 *  5. `/healthz` stays 200 and `/readyz` answers 503 `operator_drain`, which is
 *     the pair a load balancer needs: "do not restart me, stop sending me new
 *     traffic".
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  DRAIN_COLLECTION,
  DRAIN_ID,
  DRAIN_UNAVAILABLE_CODE,
  NODE_DRAINING_MESSAGE,
  RESOURCE_TABLE,
} from "../../src/drain.js";
import type { AgentRuntimeBindings } from "../../src/ports.js";
import { readinessReport } from "../../src/routes/health.js";
import {
  BASE,
  DURABLE_WORKER_A,
  KEY_LIVE,
  bearer,
  errorCode,
  get,
  heartbeat,
  post,
  setupDurablePorts,
} from "./setup.js";

beforeAll(setupDurablePorts);

/** `POST /admin/v1/drain` — the row `apps/control-plane` writes, verbatim. */
async function adminSetDrain(draining: boolean, reason: string | null = null): Promise<void> {
  const document = {
    id: DRAIN_ID,
    draining,
    reason,
    changed_at: 1_700_000_000,
    tenant_id: null,
  };
  await env.CONTROL_DB.prepare(
    `INSERT INTO ${RESOURCE_TABLE}
       (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
     VALUES (?, ?, ?, 1, 1, 1)
     ON CONFLICT (resource_kind, resource_id) DO UPDATE SET document_json = excluded.document_json`,
  )
    .bind(DRAIN_COLLECTION, DRAIN_ID, JSON.stringify(document))
    .run();
}

async function clearDrain(): Promise<void> {
  await env.CONTROL_DB.prepare(
    `DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`,
  )
    .bind(DRAIN_COLLECTION, DRAIN_ID)
    .run();
}

// `.wrangler/state` persists across FILES in this pool, so a leftover drain row
// would refuse traffic in every other spec of the suite.
afterEach(clearDrain);

/** `POST /v1/agent-jobs` — a guarded, spend-producing operation. */
async function submitJob(): Promise<Response> {
  return await post("/v1/agent-jobs", bearer(KEY_LIVE), {
    input: "write the patch",
    required_capabilities: ["coding"],
    idempotency_key: `drain-${Math.random().toString(36).slice(2)}`,
  });
}

describe("the deployed Worker honours the durable operator drain", () => {
  it("ADMITS a spend operation when no drain document exists", async () => {
    // The negative control. Without it, "refused while draining" could be
    // "refused always" — the vacuous shape this repository keeps catching.
    await clearDrain();
    const response = await submitJob();
    expect(response.status).toBe(202);
  });

  it("REFUSES the same operation with 503 node_draining once the drain is set", async () => {
    await adminSetDrain(true, "pre-migration");
    const response = await submitJob();
    expect(response.status).toBe(503);
    expect(await errorCode(response)).toBe("node_draining");
  });

  it("carries Rust's message byte for byte", async () => {
    await adminSetDrain(true);
    const response = await submitJob();
    const body = (await response.json()) as { error?: { message?: string } };
    expect(body.error?.message).toBe(NODE_DRAINING_MESSAGE);
  });

  it("re-reads the document PER REQUEST — lifting the drain re-admits", async () => {
    // The memoisation trap. A module-scoped `const draining = …` passes every
    // test that only ever drains, and pins the FIRST request's answer for the
    // life of the isolate — so a deployment drained after an isolate warmed
    // would keep serving from it. Both flips happen in ONE isolate here.
    await adminSetDrain(true);
    expect((await submitJob()).status).toBe(503);

    await adminSetDrain(false);
    expect((await submitJob()).status).toBe(202);

    await adminSetDrain(true);
    expect((await submitJob()).status).toBe(503);
  });

  it("REFUSES the A2A ingress too, not just the job verb", async () => {
    await adminSetDrain(true);
    const response = await post("/v1/agents/helper", bearer(KEY_LIVE), {
      message: { role: "user", parts: [{ kind: "text", text: "hi" }] },
    });
    expect(response.status).toBe(503);
    expect(await errorCode(response)).toBe("node_draining");
  });
});

describe("a drain lets outstanding work finish — the point of draining", () => {
  it("keeps the agent-job READ serving", async () => {
    // A client must be able to watch its outstanding work complete on a
    // draining node. `getAgentJob` is deliberately absent from
    // `DRAIN_GUARDED_OPERATION_IDS`; this is that decision, asserted.
    await adminSetDrain(true);
    const response = await get("/v1/agent-jobs/job-does-not-exist", bearer(KEY_LIVE));
    expect(response.status).not.toBe(503);
    expect(await errorCode(response)).not.toBe("node_draining");
  });

  it("keeps the worker-plane callbacks serving", async () => {
    // The six `auth.kind: "internal"` callbacks are IN-FLIGHT work reporting
    // back. Refusing a heartbeat, an artifact upload or a checkpoint during a
    // drain would strand every running job and lose its output. The gate lives
    // on the BEARER leg only, which is the structural reason this holds.
    await adminSetDrain(true);
    const response = await heartbeat(DURABLE_WORKER_A);
    expect(response.status).not.toBe(503);
    expect(await errorCode(response)).not.toBe("node_draining");
  });
});

describe("what /healthz and /readyz answer while draining", () => {
  it("/healthz stays 200 — a drained node is ALIVE", async () => {
    // Liveness, not readiness. Flipping `/healthz` would make an orchestrator
    // RESTART the node, destroying the in-flight work the drain exists to let
    // finish. This is the same answer `apps/gateway` gives.
    await adminSetDrain(true);
    const response = await SELF.fetch(`${BASE}/healthz`);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { status: string }).status).toBe("ok");
  });

  it("/readyz answers 503 not_ready with readiness_reason operator_drain", async () => {
    // Readiness: "stop sending me new traffic". `apps/gateway`'s decision table
    // puts DRAIN ahead of state in the reason, and this Worker reproduces the
    // vocabulary so one operator dashboard covers the fleet.
    await adminSetDrain(true, "pre-migration");
    const response = await SELF.fetch(`${BASE}/readyz`);
    expect(response.status).toBe(503);
    const body = (await response.json()) as {
      status: string;
      ready: boolean;
      readiness_reason: string;
      draining: boolean;
      accepting_new_requests: boolean;
    };
    expect(body.status).toBe("not_ready");
    expect(body.ready).toBe(false);
    expect(body.readiness_reason).toBe("operator_drain");
    expect(body.draining).toBe(true);
    expect(body.accepting_new_requests).toBe(false);
  });

  it("an UNEVALUABLE drain is drain_state_unavailable, NOT operator_drain", () => {
    // The mcp-side twin of `apps/mcp/test/drain.test.ts`'s case of the same
    // name, and the same finding: the wave-22 INTEGRATE boot proof observed a
    // Worker answering `503 not_ready` with `readiness_reason:
    // "operator_drain"` and `draining: true` on a deployment nobody had
    // drained, because the durable lookup had FAILED and the report collapsed
    // the two facts. Refusing is right; naming a drain that did not happen is
    // an incident-time lie, and it is exactly the split `drainRefusal` already
    // makes between `node_draining` and `drain_state_unavailable`.
    //
    // Driven through `readinessReport` rather than over `SELF` because this
    // harness binds a MIGRATED `CONTROL_DB` — which is why the arm was
    // unreachable from any suite for a whole wave.
    const report = readinessReport(env as unknown as AgentRuntimeBindings, {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "unavailable",
      detail: "no such table: control_plane_resources",
    });
    expect(report.status).toBe(503);
    expect(report.body.status).toBe("not_ready");
    expect(report.body.readiness_reason).toBe(DRAIN_UNAVAILABLE_CODE);
    expect(report.body.readiness_reason).not.toBe("operator_drain");
    expect(report.body.draining).toBe(false);
    // Still refusing: `accepting_new_requests` must agree with `status`, or one
    // document tells a load balancer and an operator opposite things.
    expect(report.body.accepting_new_requests).toBe(false);

    // The ordinary drain still reports itself — the split is not a rename.
    const drained = readinessReport(env as unknown as AgentRuntimeBindings, {
      draining: true,
      accepting_new_requests: false,
      reason: "migration window",
      source: "durable",
    });
    expect(drained.body.readiness_reason).toBe("operator_drain");
    expect(drained.body.draining).toBe(true);
  });

  it("/readyz is 200 ready again once the drain is lifted", async () => {
    // The negative control for the probe: without it, `not_ready` above could
    // be this harness's permanent answer for an unrelated reason.
    await adminSetDrain(false);
    const response = await SELF.fetch(`${BASE}/readyz`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { status: string; draining: boolean };
    expect(body.status).toBe("ready");
    expect(body.draining).toBe(false);
  });
});
