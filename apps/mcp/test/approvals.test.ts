/**
 * The DURABLE approval gate (`src/approvals.ts`), driven through the REAL Worker.
 *
 * Before this suite the port was `AutoApproval`, which returns `undefined` for
 * every call — i.e. it APPROVED EVERYTHING. Every MCP tool that an operator
 * deliberately left OUT of `tools_to_auto_execute` ran with no human decision
 * at all, and the whole suite stayed green because nothing asserted that a
 * non-auto tool is stopped.
 *
 * So the first test here is the one that has to exist: a non-`auto_execute`
 * tool, called over `SELF.fetch` against the app the Worker exports, must be
 * REFUSED and must leave a pending row in the queue `apps/control-plane`
 * serves at `GET /admin/v1/tool-approvals`. Dropping `approvals:
 * durableApprovals(env)` from `resolvePorts` turns it red.
 *
 * Every state transition below is driven by writing the row the way the ADMIN
 * SURFACE writes it (raw SQL on `control_plane_resources`, never through the
 * code under test), because a fixture built with the reader cannot show that
 * the reader reads what is actually in the table.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  D1ToolApprovals,
  RESOURCE_TABLE,
  TOOL_APPROVAL_COLLECTION,
  type ToolApprovalDocument,
  approvalFingerprint,
  canonicalizeJson,
} from "../src/approvals.js";
import { JsonRpcErrorCode } from "../src/jsonrpc.js";
import type { AuthContext, DispatchContext, McpTool } from "../src/ports.js";
import { AGENT_RUN_ID_HEADER } from "../src/protocol.js";
import {
  EXEC_KEY,
  type Fixture,
  TENANT,
  rpcRequest,
  seedFixture,
  tenantAuth,
  upstreamConfig,
} from "./fixtures.js";

interface ApprovalBindings {
  readonly DB: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

const control = (): D1Database => (env as unknown as ApprovalBindings).DB;

async function tenantDb(tenantId: string): Promise<D1Database> {
  const namespace = (
    env as unknown as {
      TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
    }
  ).TENANT_DATA;
  if (namespace === undefined) throw new Error("approval test expects TENANT_DATA");
  return (await new DurableObjectTenantDatabaseRouter(namespace, control()).forTenant(tenantId)).db;
}

/** A key belonging to a DIFFERENT tenant, for the isolation test. */
const OTHER_TENANT_KEY = "fg_other_tenant_key";
const OTHER_TENANT = "tenant-other";

const RISKY = "gov-risky";
const ARGS = { path: "/etc/passwd" };

let fixture: Fixture;

beforeAll(async () => {
  const b = env as unknown as ApprovalBindings;
  await applyD1Migrations(b.DB, b.TEST_CONTROL_D1_SCHEMA);
});

beforeEach(async () => {
  await control()
    .prepare(`DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ?`)
    .bind(TOOL_APPROVAL_COLLECTION)
    .run();
  await Promise.all(
    [TENANT, OTHER_TENANT].map(async (tenantId) => {
      const db = await tenantDb(tenantId);
      await db
        .prepare(`DELETE FROM tenant_resources WHERE resource_kind = ?`)
        .bind(TOOL_APPROVAL_COLLECTION)
        .run();
    }),
  );

  fixture = seedFixture();
  // An upstream whose tool is allowlisted for EXECUTION but deliberately not
  // for AUTO execution — exactly the shape the approval gate exists for.
  fixture.ports.upstreams.register(
    upstreamConfig({ name: "gov", toolsToExecute: ["risky"], toolsToAutoExecute: [] }),
    [{ name: "risky", description: "needs a human", input_schema: { type: "object" } }],
    // eslint-disable-next-line @typescript-eslint/require-await
    async (tool, args, identity, context) => {
      fixture.calls.push({ tool, args, identity, context });
      return { content: { content: [{ type: "text", text: "ran" }] }, isError: false };
    },
  );
  fixture.ports.auth.register(
    OTHER_TENANT_KEY,
    tenantAuth({ organizationId: OTHER_TENANT, apiKeyId: "key-other" }),
  );
});

// ---------------------------------------------------------------------------

interface RestResult {
  readonly error?: { code: string; message: string };
  readonly content?: unknown;
}

/**
 * Drive the REST transport (`POST /v1/mcp/tool/execute`), because it renders
 * the governed chokepoint's refusal as a real HTTP STATUS. The JSON-RPC
 * transport answers `200` with a JSON-RPC error envelope — correct per the
 * spec, and pinned separately below — which would make a status assertion here
 * silently unable to fail.
 */
async function callRisky(
  init: { key?: string; args?: Record<string, unknown>; runId?: string } = {},
): Promise<{ status: number; body: RestResult }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    authorization: `Bearer ${init.key ?? EXEC_KEY}`,
  };
  if (init.runId !== undefined) headers[AGENT_RUN_ID_HEADER] = init.runId;
  const res = await SELF.fetch(
    new Request("https://ferrogate.test/v1/mcp/tool/execute", {
      method: "POST",
      headers,
      body: JSON.stringify({ name: RISKY, arguments: init.args ?? ARGS }),
    }),
  );
  return { status: res.status, body: (await res.json()) as RestResult };
}

async function storedApprovals(): Promise<ToolApprovalDocument[]> {
  const rows = await Promise.all(
    [TENANT, OTHER_TENANT].map(async (tenantId) =>
      (await tenantDb(tenantId))
        .prepare(`SELECT document_json FROM tenant_resources WHERE resource_kind = ?`)
        .bind(TOOL_APPROVAL_COLLECTION)
        .all<{ document_json: string }>(),
    ),
  );
  return rows.flatMap((result) =>
    result.results.map((row) => JSON.parse(row.document_json) as ToolApprovalDocument),
  );
}

/** Record a decision the way `routes/admin_tool.ts` records one. */
async function decide(fingerprint: string, patch: Partial<ToolApprovalDocument>): Promise<void> {
  const [existing] = (await storedApprovals()).filter((row) => row.fingerprint === fingerprint);
  expect(existing, "the pending row must exist before it can be decided").toBeDefined();
  const updated = { ...(existing as ToolApprovalDocument), ...patch };
  await (await tenantDb(existing?.tenant_id ?? TENANT))
    .prepare(
      `UPDATE tenant_resources SET document_json = ?, revision = revision + 1
         WHERE resource_kind = ? AND resource_id = ?`,
    )
    .bind(JSON.stringify(updated), TOOL_APPROVAL_COLLECTION, updated.id)
    .run();
}

function authFor(tenantId: string, apiKeyId: string): AuthContext {
  return tenantAuth({ organizationId: tenantId, apiKeyId });
}

const RISKY_TOOL: McpTool = {
  name: RISKY,
  serverName: "gov",
  remoteName: "risky",
  inputSchema: { type: "object" },
  autoExecute: false,
};

// ---------------------------------------------------------------------------

describe("the approval gate is MOUNTED on the app the Worker exports", () => {
  it("refuses a non-auto tool and RAISES a pending row a reviewer can see", async () => {
    // Control: nothing is queued before the call.
    expect(await storedApprovals()).toHaveLength(0);

    const res = await callRisky();
    expect(res.status).toBe(403);
    expect(res.body.error?.code).toBe("approval_pending");
    // The upstream was NOT reached — the whole point of the gate.
    expect(fixture.calls).toHaveLength(0);

    const queued = await storedApprovals();
    expect(queued).toHaveLength(1);
    expect(queued[0]).toMatchObject({
      object: "tool_approval",
      status: "pending",
      tool_name: RISKY,
      server_name: "gov",
      tenant_id: TENANT,
      actor_api_key_id: "key-1",
      risk_reason: "mcp tool is not marked auto_execute",
    });
    // The queue row lands in the collection `apps/control-plane` serves.
    expect(queued[0]?.expires_at).toBeGreaterThan(queued[0]?.requested_at ?? 0);
  });

  it("still executes an AUTO-execute tool without queueing anything", async () => {
    // The control that keeps the test above from being "MCP is simply broken".
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "srv-echo", arguments: {} },
        },
        { key: EXEC_KEY },
      ),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { error?: unknown }).error).toBeUndefined();
    expect(fixture.calls).toHaveLength(1);
    expect(await storedApprovals()).toHaveLength(0);
  });

  it("joins the raised approval into the caller's correlation chain (#522)", async () => {
    await callRisky({ runId: "run-approval-1" });
    expect((await storedApprovals())[0]?.agent_run_id).toBe("run-approval-1");
  });

  it("carries Rust's stored canonical decision reason for a pending record", async () => {
    await callRisky();
    expect((await storedApprovals())[0]?.decision_reason).toBe("approval_pending");
  });

  it("renders the refusal on the JSON-RPC transport too", async () => {
    // The other transport for the SAME chokepoint. `200` + a JSON-RPC error
    // envelope is the spec-correct shape, so it is asserted on its own terms.
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: RISKY, arguments: ARGS } },
        { key: EXEC_KEY },
      ),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(JsonRpcErrorCode.ApplicationError);
    expect(body.error?.message).toContain("requires an approval");
    expect(fixture.calls).toHaveLength(0);
    expect(await storedApprovals()).toHaveLength(1);
  });
});

describe("the decision recorded by the admin surface is what admits the call", () => {
  it("APPROVED admits the retry, and the upstream finally runs", async () => {
    const fingerprint = await approvalFingerprint(authFor(TENANT, "key-1"), RISKY_TOOL, ARGS);

    const refused = await callRisky();
    expect(refused.status).toBe(403);

    await decide(fingerprint, { status: "approved", decided_by: "operator@test" });

    const admitted = await callRisky();
    expect(admitted.status).toBe(200);
    expect(admitted.body.error).toBeUndefined();
    expect(fixture.calls).toHaveLength(1);
  });

  it("DENIED keeps refusing", async () => {
    const fingerprint = await approvalFingerprint(authFor(TENANT, "key-1"), RISKY_TOOL, ARGS);
    await callRisky();
    await decide(fingerprint, { status: "denied" });

    const res = await callRisky();
    expect(res.status).toBe(403);
    expect(res.body.error?.code).toBe("tool_denied");
    expect(fixture.calls).toHaveLength(0);
  });

  it("an APPROVED record past its review window is not an approval", async () => {
    const fingerprint = await approvalFingerprint(authFor(TENANT, "key-1"), RISKY_TOOL, ARGS);
    await callRisky();
    await decide(fingerprint, { status: "approved", expires_at: 1 });

    const res = await callRisky();
    expect(res.status).toBe(403);
    expect(res.body.error?.code).toBe("tool_denied");
    expect(fixture.calls).toHaveLength(0);
  });

  it("an UNRECOGNIZED status is never treated as an approval", async () => {
    const fingerprint = await approvalFingerprint(authFor(TENANT, "key-1"), RISKY_TOOL, ARGS);
    await callRisky();
    await decide(fingerprint, { status: "half_approved" as ToolApprovalDocument["status"] });

    const res = await callRisky();
    expect(res.status).toBe(403);
    expect(fixture.calls).toHaveLength(0);
  });
});

describe("the fingerprint is the idempotency key AND the binding", () => {
  it("a retry loop does not flood the reviewer's queue", async () => {
    await callRisky();
    await callRisky();
    await callRisky();
    expect(await storedApprovals()).toHaveLength(1);
  });

  it("an approval does NOT carry over to different arguments", async () => {
    const fingerprint = await approvalFingerprint(authFor(TENANT, "key-1"), RISKY_TOOL, ARGS);
    await callRisky();
    await decide(fingerprint, { status: "approved" });
    expect((await callRisky()).body.error).toBeUndefined();

    // One byte of argument difference is a different call.
    const other = await callRisky({ args: { path: "/etc/shadow" } });
    expect(other.status).toBe(403);
    expect(other.body.error?.code).toBe("approval_pending");
    expect(fixture.calls).toHaveLength(1);
  });

  it("ignores argument KEY ORDER, so a re-serialized retry keeps its approval", async () => {
    const ordered = { a: 1, b: { d: 4, c: 3 } };
    const reordered = { b: { c: 3, d: 4 }, a: 1 };
    expect(JSON.stringify(canonicalizeJson(ordered))).toBe(
      JSON.stringify(canonicalizeJson(reordered)),
    );
    expect(await approvalFingerprint(authFor(TENANT, "k"), RISKY_TOOL, ordered)).toBe(
      await approvalFingerprint(authFor(TENANT, "k"), RISKY_TOOL, reordered),
    );
  });

  it("one tenant's approval can NEVER redeem another tenant's identical call", async () => {
    const fingerprint = await approvalFingerprint(authFor(TENANT, "key-1"), RISKY_TOOL, ARGS);
    await callRisky();
    await decide(fingerprint, { status: "approved" });
    // Same tool, byte-identical arguments, different tenant.
    const other = await callRisky({ key: OTHER_TENANT_KEY });
    expect(other.status).toBe(403);
    expect(other.body.error?.code).toBe("approval_pending");
    expect(fixture.calls).toHaveLength(0);

    const queued = await storedApprovals();
    expect(queued).toHaveLength(2);
    expect(new Set(queued.map((row) => row.tenant_id))).toEqual(new Set([TENANT, OTHER_TENANT]));
  });
});

describe("an unreadable queue FAILS CLOSED", () => {
  function brokenDb(): D1Database {
    return {
      prepare() {
        const statement = {
          bind: () => statement,
          first: async () => {
            throw new Error("D1_ERROR: network");
          },
          run: async () => {
            throw new Error("D1_ERROR: network");
          },
        };
        return statement;
      },
    } as unknown as D1Database;
  }

  it("refuses rather than approving when the store cannot be read", async () => {
    // The previous implementation's answer to "no queue" was "approve
    // everything". This asserts the opposite.
    const gate = new D1ToolApprovals(brokenDb());
    const context: DispatchContext = { requestId: "r1", auth: authFor(TENANT, "key-1") };
    const outcome = await gate.require(context, RISKY_TOOL, ARGS);
    expect(outcome).toBeDefined();
    expect(outcome?.code).toBe("tool_denied");
  });
});
