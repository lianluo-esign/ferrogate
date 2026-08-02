/**
 * The KEPT stdio PLATFORM LIMIT, pinned against the app the Worker exports.
 *
 * `src/transport.ts`, `src/ports.ts` and `src/protocol.ts` all carry the same
 * marker: workerd has no `fork`/`exec`, no pipes and no process table, so the
 * Rust `stdio_client.rs` upstream (a child process per MCP server) has no
 * Workers implementation and never will. The marker names the approximation
 * that IS implemented, and this file is the assertion that the approximation
 * cannot drift:
 *
 *  1. a stdio upstream stays FULLY CONFIGURABLE — it round-trips through the
 *     catalog and its allowlisted tools are still LISTED, so the operator sees
 *     the misconfiguration instead of a server that silently vanished; and
 *  2. it is REFUSED AT DISPATCH with `mcp_server_unavailable`, and the
 *     upstream handler is never reached — because the dangerous failure mode
 *     is the other one: treating a stdio upstream as HTTP would put a
 *     local-process server's traffic on the network.
 *
 * Why this file exists when `test/upstream-transport.test.ts` already covers
 * stdio: that suite constructs `HttpMcpUpstreams` directly, so it proves the
 * refusal in the class but says nothing about the app. The refusal in
 * `InMemoryUpstreams.callTool` (`src/ports.ts`) — the host the DEV/dispatch
 * posture actually mounts — had NO test at all, in either class or app form.
 * Deleting that `transport === "stdio"` branch left all 314 tests green while
 * the deployed Worker would have handed a stdio config to the HTTP handler.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { JsonRpcErrorCode } from "../src/jsonrpc.js";
import {
  EXEC_KEY,
  type Fixture,
  READ_KEY,
  rpcRequest,
  seedFixture,
  upstreamConfig,
} from "./fixtures.js";

let fixture: Fixture;

/** Register a stdio upstream whose one tool is allowlisted AND auto-execute. */
function seedStdioUpstream(): void {
  fixture.ports.upstreams.register(
    upstreamConfig({
      name: "local",
      transport: "stdio",
      // A stdio server has no endpoint by construction — that is the point.
      url: undefined,
      toolsToExecute: ["run"],
      // Auto-execute so the durable approval gate cannot be what refuses this;
      // the refusal under test must come from the transport branch itself.
      toolsToAutoExecute: ["run"],
    }),
    [{ name: "run", description: "runs locally", input_schema: { type: "object" } }],
    () => {
      throw new Error("the stdio upstream handler must never be reached");
    },
  );
}

async function rpc(body: Record<string, unknown>, key: string) {
  const res = await SELF.fetch(rpcRequest(body, { key }));
  return (await res.json()) as {
    error?: { code: number; message: string };
    result?: { tools?: Array<{ name: string }> };
  };
}

beforeEach(() => {
  fixture = seedFixture();
  seedStdioUpstream();
});

describe("PLATFORM LIMIT: stdio MCP upstreams cannot run in a Worker", () => {
  it("keeps the misconfigured upstream VISIBLE in tools/list", async () => {
    const listed = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, READ_KEY);
    const names = (listed.result?.tools ?? []).map((tool) => tool.name);
    // Silently dropping it from the catalog would hide an operator error that
    // only ever surfaces as "my tool does nothing".
    expect(names).toContain("local-run");
    // The control: the healthy HTTP upstream from the fixture is listed too, so
    // "contains local-run" is not passing against an empty-ish list.
    expect(names).toContain("srv-echo");
  });

  it("REFUSES the dispatch with mcp_server_unavailable instead of calling it over HTTP", async () => {
    const called = await rpc(
      {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "local-run", arguments: { cmd: "ls" } },
      },
      EXEC_KEY,
    );

    expect(called.result).toBeUndefined();
    expect(called.error?.code).toBe(JsonRpcErrorCode.McpServerUnavailable);
    // The message names the reason an operator has to act on, and the fix.
    expect(called.error?.message).toMatch(/stdio/);
    // The seeded handler throws if reached, so "the upstream never ran" is not
    // merely inferred from the error code.
    expect(fixture.calls).toHaveLength(0);
  });

  it("does not confuse the transport refusal with the allowlist refusal", async () => {
    // `srv-danger` exists upstream but is not allowlisted: `tool_denied`.
    const denied = await rpc(
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-danger" } },
      EXEC_KEY,
    );
    expect(denied.error?.code).toBe(JsonRpcErrorCode.ToolDenied);

    // The stdio tool IS allowlisted, so a different code has to come back — if
    // both answered `tool_denied` the transport branch would be unobservable.
    const unavailable = await rpc(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "local-run" } },
      EXEC_KEY,
    );
    expect(unavailable.error?.code).toBe(JsonRpcErrorCode.McpServerUnavailable);
    expect(unavailable.error?.code).not.toBe(denied.error?.code);
  });

  it("still serves the HTTP upstream — the control for all three above", async () => {
    const ok = await rpc(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "srv-echo", arguments: { text: "hi" } },
      },
      EXEC_KEY,
    );
    // Without this, "every dispatch is refused" would satisfy the assertions
    // above just as well as a correctly-scoped stdio refusal does.
    expect(ok.error).toBeUndefined();
    expect(fixture.calls).toHaveLength(1);
  });
});
