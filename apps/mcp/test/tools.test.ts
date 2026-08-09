/**
 * `SELF` integration tests for `tools/list` and `tools/call` over the real
 * Worker: routing, method→scope gating, the deny-by-default allowlist, the
 * governed chokepoint, and the Streamable-HTTP response shapes.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { MCP_METHOD_HEADER, MCP_NAME_HEADER } from "../src/protocol.js";
import { parseSseEvents } from "../src/transport.js";
import {
  EXEC_KEY,
  type Fixture,
  NO_SCOPE_KEY,
  READ_KEY,
  rpcRequest,
  seedFixture,
} from "./fixtures.js";

let fixture: Fixture;

beforeEach(() => {
  fixture = seedFixture();
});

describe("POST /v1/mcp — transport and auth", () => {
  it("requires POST", async () => {
    const res = await SELF.fetch("https://ferrogate.test/v1/mcp", { method: "GET" });
    expect(res.status).toBe(405);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "method_not_allowed",
    );
  });

  it("answers unparseable JSON with a -32700 body at HTTP 200", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${READ_KEY}` },
        body: "{not json",
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32700);
  });

  it("rejects an unauthenticated request", async () => {
    const res = await SELF.fetch(rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }));
    expect(res.status).toBe(401);
  });

  it("gates tools/list on the method's contract scope (tools.read)", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: NO_SCOPE_KEY }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "insufficient_scope",
    );
  });

  it("gates tools/call on tools.execute, which a read-only key lacks", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: READ_KEY },
      ),
    );
    expect(res.status).toBe(403);
  });

  it("acknowledges a Notification with 202 and no body", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", method: "notifications/initialized" }, { key: READ_KEY }),
    );
    expect(res.status).toBe(202);
    expect(await res.text()).toBe("");
  });
});

describe("tools/list", () => {
  it("lists only allowlisted, namespaced tools", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: READ_KEY }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((tool) => tool.name);
    expect(names).toContain("srv-echo");
    // Deny-by-default: `danger` exists upstream but is not in `toolsToExecute`.
    expect(names).not.toContain("srv-danger");
  });

  it("advertises builtin.fetch_asset only to keys holding assets.read", async () => {
    const withScope = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: READ_KEY }),
    );
    const withScopeNames = (
      (await withScope.json()) as { result: { tools: Array<{ name: string }> } }
    ).result.tools.map((tool) => tool.name);
    expect(withScopeNames).toContain("builtin.fetch_asset");

    fixture.ports.auth.register("fg_tools_only", {
      apiKeyId: "key-2",
      organizationId: "tenant-1",
      workspaceId: "ws-1",
      userId: "user-1",
      scopes: ["tools.read"],
      permissions: [],
      platformOperator: false,
    });
    const withoutScope = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: "fg_tools_only" }),
    );
    const withoutScopeNames = (
      (await withoutScope.json()) as { result: { tools: Array<{ name: string }> } }
    ).result.tools.map((tool) => tool.name);
    // A key that could never execute the tool must not be shown it.
    expect(withoutScopeNames).not.toContain("builtin.fetch_asset");
  });

  it("records a tool.list audit row", async () => {
    await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: READ_KEY }),
    );
    const row = fixture.ports.audit.events().find((event) => event.action === "tool.list");
    expect(row?.outcome).toBe("success");
  });
});

describe("tools/call", () => {
  it("executes an allowlisted tool through the governed chokepoint", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 7,
          method: "tools/call",
          params: { name: "srv-echo", arguments: { text: "hi" } },
        },
        { key: EXEC_KEY },
      ),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      id: number;
      result: { content: Array<{ text: string }>; isError: boolean };
    };
    expect(body.id).toBe(7);
    expect(body.result.isError).toBe(false);
    expect(JSON.parse(body.result.content[0]?.text ?? "null")).toEqual({ text: "hi" });

    expect(fixture.calls).toHaveLength(1);
    expect(fixture.calls[0]?.tool.remoteName).toBe("echo");
    expect(fixture.calls[0]?.args).toEqual({ text: "hi" });
  });

  it("denies an un-allowlisted tool at the chokepoint and audits the refusal", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-danger" } },
        { key: EXEC_KEY },
      ),
    );
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32001);
    expect(fixture.calls).toHaveLength(0);
    const row = fixture.ports.audit.events().find((event) => event.action === "tool.execute");
    expect(row?.outcome).toBe("rejected");
  });

  it("requires the serverName-toolName namespace", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo" } },
        { key: EXEC_KEY },
      ),
    );
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32001);
    expect(body.error.message).toMatch(/serverName-toolName namespace/);
  });

  it("requires params.name", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {} }, { key: EXEC_KEY }),
    );
    expect(((await res.json()) as { error: { code: number } }).error.code).toBe(-32602);
  });

  it("enforces the plan/RBAC entitlement gate before the chokepoint", async () => {
    fixture.ports.entitlements.deniedTenants.add("tenant-1");
    fixture.ports.auth.register("fg_no_plan", {
      apiKeyId: "key-3",
      organizationId: "tenant-1",
      workspaceId: "ws-1",
      userId: "user-1",
      scopes: ["tools.execute"],
      permissions: [],
      platformOperator: false,
    });
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: "fg_no_plan" },
      ),
    );
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toMatch(/mcp\.execute permission/);
    expect(fixture.calls).toHaveLength(0);
  });

  it("fails closed when a routing header disagrees with the body", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "srv-echo", arguments: {} },
        },
        {
          key: EXEC_KEY,
          // Metered as a cheap tool, body executes a different one.
          headers: { [MCP_METHOD_HEADER]: "tools/call", [MCP_NAME_HEADER]: "srv-cheap" },
        },
      ),
    );
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32600);
    expect(fixture.calls).toHaveLength(0);
  });
});

describe("Streamable HTTP response shapes", () => {
  it("answers with SSE when the caller prefers the event stream", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 3, method: "tools/list" },
        { key: READ_KEY, headers: { accept: "text/event-stream" } },
      ),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream; charset=utf-8");
    const events = parseSseEvents(await res.text());
    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("message");
    const payload = JSON.parse(events[0]?.data ?? "null") as {
      id: number;
      result: { tools: unknown[] };
    };
    expect(payload.id).toBe(3);
    expect(Array.isArray(payload.result.tools)).toBe(true);
  });

  it("answers with JSON by default", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 3, method: "tools/list" }, { key: READ_KEY }),
    );
    expect(res.headers.get("content-type")).toBe("application/json");
  });
});

describe("POST /v1/mcp/tool/execute", () => {
  it("runs the SAME governed chokepoint as tools/call", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/tool/execute", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${EXEC_KEY}` },
        body: JSON.stringify({ name: "srv-echo", arguments: { text: "rest" } }),
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { object: string; is_error: boolean };
    expect(body.object).toBe("tool_execution");
    expect(body.is_error).toBe(false);
    expect(fixture.calls).toHaveLength(1);
  });

  it("denies an un-allowlisted tool identically to the JSON-RPC transport", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/tool/execute", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${EXEC_KEY}` },
        body: JSON.stringify({ name: "srv-danger" }),
      }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("tool_denied");
  });

  it("rejects a malformed body", async () => {
    const res = await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/tool/execute", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${EXEC_KEY}` },
        body: "[]",
      }),
    );
    expect(res.status).toBe(400);
  });
});
