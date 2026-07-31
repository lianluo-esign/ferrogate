/**
 * #522 — the declared `agent_run_id` MUST survive dispatch, end to end.
 *
 * This is the parity contract the Rust tree held with a dedicated test
 * (`mcp_rpc_test.rs::tools_call_threads_declared_agent_run_id_into_governed_tool_execution`
 * and `::mcp_ingress_audit_rows_join_the_declared_agent_run_id`). It is what
 * joins an MCP `tools/call` into the same correlation chain as the chat,
 * agent-run, and A2A surfaces — without it, an MCP action is unjoinable and an
 * investigator cannot reconstruct what an agent did.
 *
 * Every test drives the DEPLOYED Worker over HTTP — `SELF.fetch` against the
 * real `export default app` from `src/index.ts`, in real `workerd`. There is no
 * bespoke harness router anywhere in this file: the "unreachable in production,
 * green in test" failure mode that hit `apps/gateway` cannot hide this
 * invariant, and the guard below pins that (the two surfaces exercised here are
 * asserted to be the ones the production registry actually mounted).
 *
 * Each test asserts BOTH legs the id has to travel:
 *   1. the DISPATCH leg — the id reaches the upstream MCP call's context;
 *   2. the AUDIT leg     — the id is stamped on the rows the ingress and the
 *                          governed chokepoint record.
 *
 * Mutation checks — each was RUN against this suite and each turned it RED, so
 * none of the assertions below is vacuous:
 *   - drop `event.agent_run_id` from `auditEvent` (`src/tools.ts`)
 *     → 7 failed / 6 passed — every AUDIT-leg assertion;
 *   - drop `context.agentRunId` from `authenticateRequest` (`src/http.ts`)
 *     → 7 failed / 6 passed — the context is where the id enters, so both legs
 *       go dark at once;
 *   - strip `agentRunId` from the context handed to `ports.upstreams.callTool`
 *     (`src/tools.ts`) → 2 failed / 11 passed — isolates the DISPATCH leg,
 *     proving it is asserted independently of the audit rows;
 *   - make `declaredAgentRunId` fabricate an id when the header is absent
 *     (`src/protocol.ts`) → 1 failed / 12 passed — the "never a fabrication"
 *     block is the only thing standing between an unjoinable action and a
 *     plausible-looking but invented correlation id.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { mcpRouter } from "../src/index.js";
import { AGENT_RUN_ID_HEADER } from "../src/protocol.js";
import { EXEC_KEY, type Fixture, READ_KEY, TENANT, rpcRequest, seedFixture } from "./fixtures.js";

const RUN = "run-mcp-call-1";

let fixture: Fixture;

beforeEach(() => {
  fixture = seedFixture();
  fixture.ports.assets.seed(
    TENANT,
    {
      assetType: "cli_tool",
      name: "deploy",
      version: "1.0.0",
      contentType: "text/plain",
      sizeBytes: 10,
      sha256: "a".repeat(64),
      downloadable: true,
    },
    new TextEncoder().encode("echo hello"),
  );
});

function rowFor(action: string) {
  return fixture.ports.audit.events().find((event) => event.action === action);
}

describe("this suite exercises the DEPLOYED surfaces, not a harness", () => {
  it("drives the two operations the production registry mounted", () => {
    // `SELF.fetch` already guarantees the real Worker answers; this pins WHICH
    // contract operations the requests below land on, so the invariant cannot
    // survive by being re-tested against a route the Worker no longer exports.
    const registered = new Set(mcpRouter.registeredOperationIds());
    expect(registered.has("mcpJsonRpc")).toBe(true);
    expect(registered.has("executeMcpTool")).toBe(true);
  });
});

describe("tools/call threads the declared agent_run_id end to end", () => {
  it("reaches the upstream dispatch context AND the tool.execute audit row", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 9,
          method: "tools/call",
          params: { name: "srv-echo", arguments: { text: "hi" } },
        },
        { key: EXEC_KEY, headers: { [AGENT_RUN_ID_HEADER]: RUN } },
      ),
    );
    // Guard: the call actually executed, so the rows below are the success rows
    // this contract threads — not an error row on a divergent path.
    expect(res.status).toBe(200);
    expect(((await res.json()) as { result: { isError: boolean } }).result.isError).toBe(false);

    // Leg 1 — DISPATCH: the upstream MCP call carries the caller's run id.
    expect(fixture.calls).toHaveLength(1);
    expect(fixture.calls[0]?.context.agentRunId).toBe(RUN);

    // Leg 2 — AUDIT: the governed chokepoint stamps it on the execution row.
    const executed = rowFor("tool.execute");
    expect(executed).toBeDefined();
    expect(executed?.agent_run_id).toBe(RUN);
    expect(executed?.outcome).toBe("success");

    // The identity-resolution row the chokepoint records joins too.
    expect(rowFor("mcp.identity.use")?.agent_run_id).toBe(RUN);
  });

  it("stamps the id on a DENIED call's audit row as well", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "srv-danger" } },
        { key: EXEC_KEY, headers: { [AGENT_RUN_ID_HEADER]: RUN } },
      ),
    );
    // Guard: this is the deny arm (the tool is not allowlisted).
    expect(((await res.json()) as { error: { code: number } }).error.code).toBe(-32001);
    const executed = rowFor("tool.execute");
    expect(executed?.outcome).toBe("rejected");
    // A refused action is exactly the one an investigator must be able to join.
    expect(executed?.agent_run_id).toBe(RUN);
  });

  it("threads through the REST transport too", async () => {
    await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/tool/execute", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${EXEC_KEY}`,
          [AGENT_RUN_ID_HEADER]: RUN,
        },
        body: JSON.stringify({ name: "srv-echo", arguments: {} }),
      }),
    );
    expect(fixture.calls[0]?.context.agentRunId).toBe(RUN);
    expect(rowFor("tool.execute")?.agent_run_id).toBe(RUN);
  });
});

describe("every MCP ingress audit row joins the declared run id", () => {
  it.each([
    ["tools/list", "tool.list", READ_KEY, {}],
    ["resources/list", "resource.list", READ_KEY, {}],
    ["resources/read", "resource.read", READ_KEY, { uri: "asset://cli_tool/deploy/1.0.0" }],
  ])("%s → %s row", async (method, action, key, params) => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method, params },
        { key: key as string, headers: { [AGENT_RUN_ID_HEADER]: RUN } },
      ),
    );
    // Guard: the handler succeeded, so we assert on its success row.
    const body = (await res.json()) as { result?: unknown; error?: unknown };
    expect(body.error).toBeUndefined();
    expect(body.result).toBeDefined();

    const row = rowFor(action as string);
    expect(row, `a ${action} ingress audit row must be recorded`).toBeDefined();
    expect(
      row?.agent_run_id,
      `the ${action} ingress row must carry the declared correlation id (#522)`,
    ).toBe(RUN);
  });

  it("stamps the id on the protocol-negotiation row of a legacy initialize", async () => {
    await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } },
        { key: READ_KEY, headers: { [AGENT_RUN_ID_HEADER]: RUN } },
      ),
    );
    expect(rowFor("mcp.protocol_negotiated")?.agent_run_id).toBe(RUN);
  });
});

describe("an absent declaration is the unjoinable-action signal, never a fabrication", () => {
  it("leaves agent_run_id unset on every row and counts the unjoinable action", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    expect(res.status).toBe(200);

    expect(fixture.calls[0]?.context.agentRunId).toBeUndefined();
    for (const row of fixture.ports.audit.events()) {
      expect(row.agent_run_id, `${row.action} must not fabricate a run id`).toBeUndefined();
    }
    expect(fixture.ports.metrics.unjoinableActions).toContainEqual({
      tenantKey: TENANT,
      surface: "mcp",
    });
  });

  it("does not count an unjoinable action when an id WAS declared", async () => {
    await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { key: READ_KEY, headers: { [AGENT_RUN_ID_HEADER]: RUN } },
      ),
    );
    expect(fixture.ports.metrics.unjoinableActions).toHaveLength(0);
  });
});

describe("a malformed declaration is refused before anything executes", () => {
  it.each([
    ["has space", "out-of-charset"],
    ["a".repeat(129), "overlong"],
  ])("rejects %s (%s) with 400 invalid_agent_run_id_header", async (value) => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY, headers: { [AGENT_RUN_ID_HEADER]: value } },
      ),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_agent_run_id_header",
    );
    // Fail closed: a bad correlation id must not produce an unjoinable execution.
    expect(fixture.calls).toHaveLength(0);
    expect(fixture.ports.audit.events()).toHaveLength(0);
  });

  it("treats a whitespace-only declaration as absent rather than malformed", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { key: READ_KEY, headers: { [AGENT_RUN_ID_HEADER]: "   " } },
      ),
    );
    expect(res.status).toBe(200);
    expect(rowFor("tool.list")?.agent_run_id).toBeUndefined();
  });
});
