/**
 * The multiplex contract ON THE WIRE (#687), over the real Worker via `SELF`.
 *
 * `test/multiplex.test.ts` pins the resolution and attribution rules against
 * the fan-in host directly. This file pins the two legs that only exist at the
 * ingress and which that file cannot reach: the JSON-RPC selector
 * (`params._meta["ferrogate/server"]`, read by `toolsCall`) and its REST
 * spelling (a top-level `server` field on `POST /v1/mcp/tool/execute`). Both
 * transports resolve through the same chokepoint, so if they disagreed about
 * which upstream serves a name they would be two different gateways.
 *
 * The seeded catalogue collides on purpose:
 *   docs        : search-v2  -> "docs-search-v2"
 *   docs-search : v2         -> "docs-search-v2"
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { JsonRpcErrorCode } from "../src/jsonrpc.js";
import { MULTIPLEX_AMBIGUOUS_META, MULTIPLEX_SERVER_META } from "../src/multiplex.js";
import { inMemoryPorts, resetInMemoryPorts } from "../src/ports.js";
import { EXEC_KEY, READ_KEY, rpcRequest, tenantAuth, upstreamConfig } from "./fixtures.js";

/** Which upstream actually served each call, in order. */
let served: string[];

beforeEach(() => {
  resetInMemoryPorts();
  const ports = inMemoryPorts();
  served = [];
  ports.auth
    .register(READ_KEY, tenantAuth({ scopes: ["tools.read"] }))
    .register(EXEC_KEY, tenantAuth());

  const record =
    (serverName: string) =>
    // eslint-disable-next-line @typescript-eslint/require-await
    async () => {
      served.push(serverName);
      return { content: { content: [{ type: "text", text: serverName }] }, isError: false };
    };

  ports.upstreams
    .register(
      upstreamConfig({
        name: "docs",
        toolsToExecute: ["search-v2"],
        toolsToAutoExecute: ["search-v2"],
      }),
      [{ name: "search-v2", input_schema: { type: "object" } }],
      record("docs"),
    )
    .register(
      upstreamConfig({ name: "docs-search", toolsToExecute: ["v2"], toolsToAutoExecute: ["v2"] }),
      [{ name: "v2", input_schema: { type: "object" } }],
      record("docs-search"),
    );
});

function call(params: Record<string, unknown>): Request {
  return rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/call", params }, { key: EXEC_KEY });
}

describe("tools/list on the wire", () => {
  it("stamps the owning upstream on each tool and reports the collision", async () => {
    const res = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: READ_KEY }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: {
        tools: Array<{ name: string; _meta?: Record<string, unknown> }>;
        _meta?: Record<string, Array<{ name: string; servers: string[] }>>;
      };
    };
    const colliding = body.result.tools.filter((tool) => tool.name === "docs-search-v2");
    expect(colliding).toHaveLength(2);
    expect(colliding.map((tool) => tool._meta?.[MULTIPLEX_SERVER_META]).sort()).toEqual([
      "docs",
      "docs-search",
    ]);
    expect(body.result._meta?.[MULTIPLEX_AMBIGUOUS_META]).toEqual([
      { name: "docs-search-v2", servers: ["docs", "docs-search"] },
    ]);
  });
});

describe("tools/call on the wire", () => {
  it("refuses the bare colliding name with -32006 and dispatches to nobody", async () => {
    const res = await SELF.fetch(call({ name: "docs-search-v2", arguments: {} }));
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(JsonRpcErrorCode.McpToolAmbiguous);
    expect(body.error.message).toContain("docs-search");
    expect(served).toEqual([]);
  });

  it("honours _meta['ferrogate/server'] and reaches exactly that upstream", async () => {
    const res = await SELF.fetch(
      call({
        name: "docs-search-v2",
        arguments: {},
        _meta: { [MULTIPLEX_SERVER_META]: "docs" },
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { isError: boolean } };
    expect(body.result.isError).toBe(false);
    expect(served).toEqual(["docs"]);
  });

  it("does not fall back to another upstream when the selector names the wrong one", async () => {
    // `docs` DOES advertise a colliding flat name, but not this one. Falling
    // back to whichever upstream happens to own it is the exact substitution
    // the ambiguity refusal exists to prevent.
    const res = await SELF.fetch(
      call({ name: "docs-search-v2", arguments: {}, _meta: { [MULTIPLEX_SERVER_META]: "absent" } }),
    );
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(JsonRpcErrorCode.ToolDenied);
    expect(served).toEqual([]);
  });
});

describe("POST /v1/mcp/tool/execute agrees with the JSON-RPC transport", () => {
  async function execute(payload: Record<string, unknown>): Promise<Response> {
    return await SELF.fetch(
      new Request("https://ferrogate.test/v1/mcp/tool/execute", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${EXEC_KEY}` },
        body: JSON.stringify(payload),
      }),
    );
  }

  it("refuses the bare colliding name with HTTP 409", async () => {
    const res = await execute({ name: "docs-search-v2", arguments: {} });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "mcp_tool_ambiguous",
    );
    expect(served).toEqual([]);
  });

  it("honours the top-level server field", async () => {
    const res = await execute({ name: "docs-search-v2", arguments: {}, server: "docs-search" });
    expect(res.status).toBe(200);
    expect(served).toEqual(["docs-search"]);
  });
});
