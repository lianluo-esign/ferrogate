/**
 * **ONE DRAIN, EVERY DOOR** — the fleet effect of `POST /admin/v1/drain`.
 * (FLEET-CONSISTENCY item **FC-1**.)
 *
 * ## The defect this holds closed
 *
 * `POST /admin/v1/drain {"draining": true}` answered
 * `200 {"object":"drain","draining":true}`, wrote the durable
 * `runtime-state/drain` document, and **nothing read it**:
 *
 * ```
 * $ grep -rn '"runtime-state"' apps/ --include=src/**.ts   # before this wave
 * apps/control-plane/src/routes/admin_config_ops.ts:33
 * ```
 *
 * One writer. Zero readers. `apps/gateway` did enforce a drain, but off a
 * DIFFERENT source — the deploy-time `GATEWAY_DRAIN` var
 * (`apps/gateway/src/routes/readiness.ts`) — and `apps/mcp` and
 * `apps/agent-runtime` had no drain gate on either source. Both halves of the
 * control were built and never joined, so an operator draining a deployment
 * ahead of a migration kept taking new billable traffic on every Worker while
 * the admin API told them the deployment was draining.
 *
 * That is `docs/rewrite/FLEET-CONSISTENCY.md`'s recorded class: **a control an
 * operator applies in one place that does not apply everywhere it is
 * enforced**, and it is invisible to per-Worker suites because each Worker was
 * individually correct. `apps/mcp/test/drain.test.ts` and
 * `apps/agent-runtime/test/durable/drain.spec.ts` each prove their own Worker
 * refuses; **neither can fail for the defect the operator actually cares
 * about**. So the assertions below are deliberately written as ONE path —
 * observe both doors OPEN, issue ONE admin write, observe both doors SHUT —
 * inside single `it()` blocks, exactly as
 * `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` is.
 *
 * ## How three Workers are reached from one test
 *
 * The five Workers are separately bundled and no app may import another's
 * module graph. This file is a TEST, not a bundle, and it reaches each side
 * differently on purpose:
 *
 *  - **`apps/mcp`** — behavioural and end to end: the real `SELF.fetch` into
 *    this Worker's deployed `src/worker.ts`, through the real router, the real
 *    `authenticateRequest`, the real admission ladder.
 *  - **`apps/agent-runtime`** — its REAL production resolver,
 *    `resolveDrain`/`drainRefusal` out of `apps/agent-runtime/src/drain.ts`,
 *    invoked against the SAME control database handle. Not a reproduction of
 *    its SQL and not a paraphrase: the functions
 *    `middleware/auth.ts::bearerAuth` calls on every bearer request. Its
 *    BEHAVIOURAL leg — that the deployed Worker actually mounts them — is
 *    `apps/agent-runtime/test/durable/drain.spec.ts`, driven over `SELF` with
 *    `CONTROL_DB` bound.
 *  - **`apps/control-plane`** — the document the admin route writes, built by
 *    the route's own {@link drainDocument} rather than by a literal here, so
 *    this test cannot drift from the writer.
 *  - **`apps/gateway`** — read as TEXT (`?raw`, the same inlining
 *    `test/env-var-drift.test.ts` uses) to compare its refusal constants with
 *    the other two. A client that fails over from a `503 node_draining` on one
 *    Worker to a `503 gateway_draining` on another is looking at two products.
 *
 * Those cross-app imports are only sound because both `drain.ts` modules are
 * LEAVES — they import nothing at all — so no other Worker's module graph is
 * pulled into this bundle. {@link "the cross-app drain modules stay leaves"}
 * asserts that off the files' own source text rather than trusting this
 * paragraph.
 */
import { SELF, type applyD1Migrations, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { controlNamespace } from "./support/control-namespace.js";

// --- apps/agent-runtime: the OTHER enforcer's real resolver ----------------
import {
  NODE_DRAINING_CODE as AR_CODE,
  DRAIN_GUARDED_OPERATION_IDS as AR_GUARDED,
  NODE_DRAINING_MESSAGE as AR_MESSAGE,
  drainRefusal as arDrainRefusal,
  resolveDrain as arResolveDrain,
} from "../../agent-runtime/src/drain.js";
import arDrainSource from "../../agent-runtime/src/drain.ts?raw";
// --- apps/control-plane: the WRITER's own document shape -------------------
import {
  DRAIN_COLLECTION as CP_COLLECTION,
  DRAIN_ID as CP_ID,
  RESOURCE_TABLE as CP_TABLE,
  drainDocument,
} from "../../control-plane/src/store/runtime_state.js";
import gatewayDrainSource from "../../gateway/src/routes/drain.ts?raw";
import gatewayReadinessSource from "../../gateway/src/routes/readiness.ts?raw";
// --- apps/mcp: this Worker ------------------------------------------------
import {
  DRAIN_GUARDED_RPC_METHODS,
  NODE_DRAINING_CODE,
  NODE_DRAINING_MESSAGE,
  drainRefusal,
  resolveDrain,
} from "../src/drain.js";
import mcpDrainSource from "../src/drain.ts?raw";
import { EXEC_KEY, rpcRequest, seedFixture } from "./fixtures.js";

interface Bindings {
  readonly DB: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

const bindings = (): Bindings => env as unknown as Bindings;
/** `apps/mcp` binds the CONTROL database as `DB` (`src/ports.ts`). */
const control = (): D1Database => bindings().DB;

interface JsonBody {
  readonly error?: { code: string; message: string };
  readonly result?: unknown;
}

// ---------------------------------------------------------------------------
// `apps/control-plane`'s write, by row content
// ---------------------------------------------------------------------------

/**
 * `POST /admin/v1/drain` — `D1ControlPlaneStore.merge`/`create` behind
 * `routes/admin_config_ops.ts::setAdminDrain`.
 *
 * The DOCUMENT comes from the route's own {@link drainDocument}; only the
 * INSERT is reproduced, exactly as
 * `agent-upstream-fleet-withdrawal.test.ts::storeUpstream` reproduces
 * `D1ControlPlaneStore.create`. A rename of the collection, the id, or a field
 * therefore breaks this test rather than silently making it write to a row
 * nobody reads — which is the FC-1 defect itself.
 */
async function adminSetDrain(draining: boolean, reason: string | null = null): Promise<void> {
  const document = drainDocument({ draining, reason, changedAt: 1_700_000_000 });
  await control()
    .prepare(
      `INSERT INTO ${CP_TABLE}
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 1, 1, 1)
       ON CONFLICT (resource_kind, resource_id) DO UPDATE SET
         document_json = excluded.document_json`,
    )
    .bind(CP_COLLECTION, CP_ID, JSON.stringify(document))
    .run();
}

/** Remove the singleton drain row entirely (the "never drained" state). */
async function clearDrain(): Promise<void> {
  await control()
    .prepare(`DELETE FROM ${CP_TABLE} WHERE resource_kind = ? AND resource_id = ?`)
    .bind(CP_COLLECTION, CP_ID)
    .run();
}

// ---------------------------------------------------------------------------
// Door 1 — `apps/mcp`, over `SELF`
// ---------------------------------------------------------------------------

async function post(body: Record<string, unknown>): Promise<{ status: number; body: JsonBody }> {
  const res = await SELF.fetch(rpcRequest(body, { key: EXEC_KEY }));
  return { status: res.status, body: (await res.json()) as JsonBody };
}

const toolsCall = (): Promise<{ status: number; body: JsonBody }> =>
  post({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "srv-echo", arguments: {} },
  });

const toolsList = (): Promise<{ status: number; body: JsonBody }> =>
  post({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });

async function executeMcpTool(): Promise<{ status: number; body: JsonBody }> {
  const res = await SELF.fetch(
    new Request("https://ferrogate.test/v1/mcp/tool/execute", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${EXEC_KEY}` },
      body: JSON.stringify({ name: "srv-echo", arguments: {} }),
    }),
  );
  return { status: res.status, body: (await res.json()) as JsonBody };
}

// ---------------------------------------------------------------------------
// Door 2 — `apps/agent-runtime`, through its own production resolver
// ---------------------------------------------------------------------------

/**
 * What `middleware/auth.ts::bearerAuth` computes for a guarded operation on the
 * other Worker, against THIS test's control database.
 *
 * `apps/agent-runtime` binds the control database as `CONTROL_DB`; `apps/mcp`
 * binds the same database as `DB`. Handing the one handle under the name that
 * Worker reads is what makes this the same durable row and not a second one.
 */
async function agentRuntimeRefusal(): Promise<{
  status: number;
  code: string;
  message: string;
} | null> {
  const state = await arResolveDrain({ CONTROL_DATA: controlNamespace() });
  return arDrainRefusal(state);
}

// ---------------------------------------------------------------------------

beforeAll(async () => {
  const b = bindings();
  // Zero-D1 S5 (#881): the ControlDataObject self-applies its schema on first
  // wake; there is no control D1 to migrate here.
});

beforeEach(async () => {
  // The pool does not roll D1 writes back and `.wrangler/state` persists across
  // FILES, so a leftover drain row would refuse traffic in every other suite.
  await clearDrain();
  seedFixture();
});

afterEach(clearDrain);

// ---------------------------------------------------------------------------

describe("FC-1 one POST /admin/v1/drain shuts every spend door in the fleet", () => {
  it("both doors are OPEN before the drain, and BOTH are shut after it", async () => {
    // --- before: no drain document exists at all --------------------------
    const mcpBefore = await toolsCall();
    expect(mcpBefore.status, "apps/mcp tools/call before the drain").toBe(200);
    expect(mcpBefore.body.error, "apps/mcp refused before any drain was applied").toBeUndefined();
    expect(await agentRuntimeRefusal(), "apps/agent-runtime before the drain").toBeNull();

    // --- ONE control-plane action ----------------------------------------
    await adminSetDrain(true, "pre-migration");

    // --- after: BOTH doors shut, with the SAME status and code ------------
    const mcpAfter = await toolsCall();
    expect(mcpAfter.status, "apps/mcp tools/call while draining").toBe(503);
    expect(mcpAfter.body.error?.code).toBe("node_draining");
    expect(mcpAfter.body.error?.message).toBe(NODE_DRAINING_MESSAGE);

    const arAfter = await agentRuntimeRefusal();
    expect(arAfter, "apps/agent-runtime while draining").not.toBeNull();
    expect(arAfter?.status).toBe(503);
    expect(arAfter?.code).toBe("node_draining");
    expect(arAfter?.message).toBe(NODE_DRAINING_MESSAGE);
  });

  it("the REST tool transport shuts on the same one write", async () => {
    const before = await executeMcpTool();
    expect(before.body.error?.code, "executeMcpTool before the drain").not.toBe("node_draining");

    await adminSetDrain(true);

    const after = await executeMcpTool();
    expect(after.status).toBe(503);
    expect(after.body.error?.code).toBe("node_draining");
  });

  it("lifting the drain re-opens both doors — the flag is re-read PER REQUEST", async () => {
    // The memoisation trap: a module-scoped `const draining = …` passes every
    // test that only ever drains, and pins the FIRST request's posture for the
    // life of the isolate. Both flips happen inside ONE isolate here.
    await adminSetDrain(true);
    expect((await toolsCall()).status).toBe(503);
    expect(await agentRuntimeRefusal()).not.toBeNull();

    await adminSetDrain(false);
    const reopened = await toolsCall();
    expect(reopened.status, "apps/mcp after the drain was lifted").toBe(200);
    expect(reopened.body.error).toBeUndefined();
    expect(await agentRuntimeRefusal(), "apps/agent-runtime after the drain was lifted").toBeNull();
  });

  it("keeps DISCOVERY serving while draining, on the spend Worker that has it", async () => {
    // A drain that swallowed every route would break a client's failover
    // discovery at the moment it needs it most — the reason
    // `apps/gateway/src/routes/drain.ts` leaves `listModels` unguarded.
    await adminSetDrain(true);
    const list = await toolsList();
    expect(list.status, "tools/list while draining").toBe(200);
    expect(list.body.error).toBeUndefined();
  });
});

describe("FC-1 the two enforcers refuse identically", () => {
  it("carries the same status, code and message on both Workers", () => {
    // The consistency IS the fix. Three green per-Worker suites that answer
    // three different documents for one operator action are three products.
    expect({ code: NODE_DRAINING_CODE, message: NODE_DRAINING_MESSAGE }).toEqual({
      code: AR_CODE,
      message: AR_MESSAGE,
    });
  });

  it("agrees with the gateway's already-shipped constants, read as TEXT", () => {
    // `apps/gateway/src/routes/drain.ts` is not a leaf, so it is read rather
    // than imported. If the gateway ever renames its code or edits its message,
    // the fleet answers two different things for one drain and this goes RED.
    expect(gatewayDrainSource).toContain(`"node_draining"`);
    expect(gatewayDrainSource).toContain(NODE_DRAINING_MESSAGE);
  });

  it("the THIRD enforcer reads the SAME document — the gateway's leg, as TEXT", () => {
    // FC-1's last leg, landed by the wave-22 INTEGRATE step. Until then
    // `apps/gateway/src/routes/readiness.ts::drainStatus` was
    // `env?.GATEWAY_DRAIN?.trim().toLowerCase() === "true"` and nothing else,
    // so the write this file issues shut two doors of three and
    // `/v1/chat/completions` kept spending. This asserts, off the gateway's own
    // source, that it now addresses the identical row this test wrote: same
    // table, same `resource_kind`, same `resource_id` — the three values
    // `apps/control-plane`'s writer uses, imported here from the WRITER so a
    // rename on either side is red rather than silently divergent.
    //
    // The gateway's BEHAVIOUR on that row is
    // `apps/gateway/test/fleet-control-matrix.test.ts` §5 (one write over
    // `SELF`, `/v1/chat/completions` answers `503 node_draining`), which this
    // bundle cannot drive because it is not that Worker.
    expect(gatewayReadinessSource, "gateway drain authority table").toContain(CP_TABLE);
    expect(gatewayReadinessSource, "gateway drain resource_kind").toContain(`"${CP_COLLECTION}"`);
    expect(gatewayReadinessSource, "gateway drain resource_id").toContain(`"${CP_ID}"`);
    // And the PRECEDENCE, which is what keeps the var an override rather than a
    // second truth: the gateway must state the same OR rule the other two do.
    expect(gatewayReadinessSource).toContain("export function combineDrain");
    // The gate must consume the resolver rather than re-deriving a second
    // answer. (That it does not ALSO read the var directly is asserted against
    // COMMENT-STRIPPED source in `apps/gateway/test/fleet-consistency.test.ts`;
    // this file reads raw text, where the var name appears in prose.)
    expect(gatewayDrainSource).toContain("resolveDrainState(");
  });

  it("resolves the SAME durable document, byte for byte, from both resolvers", async () => {
    await adminSetDrain(true, "shared reason");
    const mcpState = await resolveDrain({ CONTROL_DATA: controlNamespace() });
    const arState = await arResolveDrain({ CONTROL_DATA: controlNamespace() });
    expect(mcpState).toEqual(arState);
    expect(mcpState.source).toBe("durable");
    expect(mcpState.reason).toBe("shared reason");
    expect(drainRefusal(mcpState)).toEqual(arDrainRefusal(arState));
  });

  it("guards a NON-EMPTY, spend-only operation set on each Worker", () => {
    // Non-vacuity. An empty table would make every refusal assertion above
    // depend on a gate that guards nothing.
    expect(DRAIN_GUARDED_RPC_METHODS.length).toBeGreaterThan(0);
    expect(AR_GUARDED.length).toBeGreaterThan(0);
    // The reads a drain must NOT break, named so a future widening is a choice.
    expect(DRAIN_GUARDED_RPC_METHODS).not.toContain("tools/list");
    expect(AR_GUARDED).not.toContain("getAgentJob");
    expect(AR_GUARDED).not.toContain("cancelAgentJob");
    expect(AR_GUARDED).not.toContain("pollSelfHostedWorkerRun");
  });

  it("the cross-app drain modules import only the control seam", () => {
    // This file pulls two other Workers' modules into ONE test bundle. Since
    // Zero-D1 S5 (#881) the drain resolves control storage through the
    // `controlDatabaseFrom` seam (the `CONTROL_DB` D1 binding it used to read
    // directly is gone), so each module carries EXACTLY that one import and
    // nothing else — no other Worker's module graph is dragged in here.
    for (const [name, source] of [
      ["apps/mcp/src/drain.ts", mcpDrainSource],
      ["apps/agent-runtime/src/drain.ts", arDrainSource],
    ] as const) {
      const imports = source
        .split("\n")
        .filter((line) => /^\s*import\s/.test(line) && !/^\s*\*/.test(line));
      expect(imports, `${name} must import only the control seam`).toEqual([
        'import { controlDatabaseFrom } from "./control-data.js";',
      ]);
    }
  });
});
