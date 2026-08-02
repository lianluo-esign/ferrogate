/**
 * The MULTIPLEX include/**exclude** filter pair (#687 leg 1).
 *
 * `toolsToExecute` is the deny-by-default INCLUDE allowlist and has always
 * existed. `toolsToExclude` is its subtractive twin, and the two questions this
 * file answers are the ones an operator's security posture actually depends on:
 *
 *  1. **Which one wins when a tool matches BOTH?** EXCLUDE wins, and the reason
 *     is not a preference: `toolsToExecute` is deny-by-default, so a tool that
 *     is reachable at all is NECESSARILY on the include list. If include won,
 *     writing a name into the exclude list could never change any outcome — the
 *     feature would be decorative, and an operator who added an exclusion and
 *     watched nothing happen would have a security hole rather than a surprise.
 *
 *  2. **WHEN is it applied?** On every READ, not only when the upstream's tool
 *     list is first discovered. `HttpMcpUpstreams` caches the discovered list on
 *     the isolate AND publishes it to the shared `MCP_SESSION` Durable Object,
 *     so filtering only at discovery would leave a warm session serving an
 *     excluded tool until the next reconnect. A deny rule that takes effect
 *     "eventually" is not a deny rule.
 *
 * Every case is paired with a CONTROL: the same tool, same catalogue, WITHOUT
 * the exclusion, so "the list does not contain it" is never asserted on its own.
 */
import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { decodeServerDocument } from "../src/catalog.js";
import { decodeServerRow, ensureMcpIdentitySchema, loadServerCatalog } from "../src/durable.js";
import {
  McpDispatchHeaders,
  type McpServerConfig,
  type McpTool,
  inMemoryPorts,
  resetInMemoryPorts,
  toolPermitted,
} from "../src/ports.js";
import { MCP_PROTOCOL_VERSION } from "../src/protocol.js";
import { HttpMcpUpstreams } from "../src/transport.js";
import { EXEC_KEY, READ_KEY, TENANT, rpcRequest, tenantAuth, upstreamConfig } from "./fixtures.js";

const DB = env.DB as unknown as D1Database;

const context = { requestId: "req-filters", auth: tenantAuth() };

function jsonResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const DISCOVER_OK = {
  jsonrpc: "2.0",
  id: 1,
  result: { resultType: "complete", capabilities: {}, supportedVersions: [MCP_PROTOCOL_VERSION] },
};

/**
 * A stub fleet serving `search` and `write` from one upstream. `calls` records
 * every `tools/call` that actually reached it, which is how an "it was refused"
 * assertion is distinguished from "it succeeded and returned nothing".
 */
function stubFetch(calls: string[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as {
      method: string;
      params?: { name?: string };
    };
    if (body.method === "server/discover") return jsonResponse(DISCOVER_OK);
    if (body.method === "tools/list") {
      return jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        result: {
          tools: [
            { name: "search", inputSchema: { type: "object" } },
            { name: "write", inputSchema: { type: "object" } },
          ],
        },
      });
    }
    if (body.method === "tools/call") {
      calls.push(String(body.params?.name));
      return jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        result: { content: [{ type: "text", text: "ok" }] },
      });
    }
    return jsonResponse({ jsonrpc: "2.0", id: 1, result: {} });
  }) as unknown as typeof fetch;
}

function httpConfig(overrides: Partial<McpServerConfig> = {}): McpServerConfig {
  return {
    name: "srv",
    transport: "streamable_http",
    url: "https://srv.upstream.test/mcp",
    authType: "none",
    toolsToExecute: ["search", "write"],
    toolsToAutoExecute: ["search", "write"],
    timeoutMs: 5_000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// The precedence decision
// ---------------------------------------------------------------------------

describe("exclude beats include, because include is deny-by-default", () => {
  it("drops a tool that is on BOTH lists", () => {
    const config = httpConfig({ toolsToExclude: ["write"] });
    // The control: the SAME tool, on the same include list, with no exclusion.
    expect(toolPermitted(httpConfig(), "write")).toBe(true);
    expect(toolPermitted(config, "write")).toBe(false);
    expect(toolPermitted(config, "search")).toBe(true);
  });

  it("cannot be satisfied by include-wins, so the decision is forced", () => {
    // If include won, this call would have to be `true` — and since a tool must
    // be on the include list to be reachable at all, EVERY exclusion would then
    // be a no-op. This assertion is the whole argument, executable.
    const both = httpConfig({ toolsToExecute: ["write"], toolsToExclude: ["write"] });
    expect(toolPermitted(both, "write")).toBe(false);
  });

  it("treats an absent exclude list as excluding nothing", () => {
    const config = httpConfig();
    expect(config.toolsToExclude).toBeUndefined();
    expect(toolPermitted(config, "search")).toBe(true);
  });

  it("does not let one upstream's exclusion reach another upstream", () => {
    const excluded = httpConfig({ name: "a", toolsToExclude: ["write"] });
    const other = httpConfig({ name: "b" });
    expect(toolPermitted(excluded, "write")).toBe(false);
    expect(toolPermitted(other, "write")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The in-memory host
// ---------------------------------------------------------------------------

describe("InMemoryUpstreams honours the exclude list", () => {
  beforeEach(() => {
    resetInMemoryPorts();
  });

  it("never advertises an excluded tool and never dispatches one", async () => {
    const ports = inMemoryPorts();
    ports.upstreams.register(
      upstreamConfig({
        toolsToExecute: ["echo", "danger"],
        toolsToAutoExecute: ["echo", "danger"],
        toolsToExclude: ["danger"],
      }),
      [
        { name: "echo", input_schema: { type: "object" } },
        { name: "danger", input_schema: { type: "object" } },
      ],
      // eslint-disable-next-line @typescript-eslint/require-await
      async () => ({ content: { content: [] }, isError: false }),
    );

    const fan = await ports.upstreams.fanIn();
    // The control: `echo` shares every property with `danger` except the
    // exclusion, so a blanket failure cannot pass this test.
    expect(fan.tools.map((tool) => tool.name)).toEqual(["srv-echo"]);

    const tool: McpTool = {
      name: "srv-danger",
      serverName: "srv",
      remoteName: "danger",
      inputSchema: { type: "object" },
      autoExecute: true,
    };
    await expect(
      ports.upstreams.callTool(tool, {}, McpDispatchHeaders.empty(), context),
    ).rejects.toThrow(/not allowlisted for execution/);
  });
});

// ---------------------------------------------------------------------------
// The HTTP host — and the cache hazard a deny list cannot tolerate
// ---------------------------------------------------------------------------

describe("HttpMcpUpstreams honours the exclude list", () => {
  it("omits an excluded tool from the fan-in", async () => {
    const calls: string[] = [];
    const open = new HttpMcpUpstreams([httpConfig()], stubFetch(calls));
    expect((await open.fanIn()).tools.map((tool) => tool.remoteName).sort()).toEqual([
      "search",
      "write",
    ]);

    const fenced = new HttpMcpUpstreams(
      [httpConfig({ toolsToExclude: ["write"] })],
      stubFetch(calls),
    );
    expect((await fenced.fanIn()).tools.map((tool) => tool.remoteName)).toEqual(["search"]);
  });

  it("refuses to dispatch an excluded tool even when the caller names it", async () => {
    const calls: string[] = [];
    const host = new HttpMcpUpstreams(
      [httpConfig({ toolsToExclude: ["write"] })],
      stubFetch(calls),
    );
    const tool: McpTool = {
      name: "srv-write",
      serverName: "srv",
      remoteName: "write",
      inputSchema: { type: "object" },
      autoExecute: true,
    };
    await expect(host.callTool(tool, {}, McpDispatchHeaders.empty(), context)).rejects.toThrow(
      /not allowlisted for execution/,
    );
    // Not merely an error: the upstream must never have been asked.
    expect(calls).toEqual([]);
  });

  it("applies the exclusion on a WARM session, not only at discovery", async () => {
    const calls: string[] = [];
    const config = httpConfig();
    const host = new HttpMcpUpstreams([config], stubFetch(calls));
    // Discover with NO exclusion, so the isolate cache (and, in production, the
    // MCP_SESSION Durable Object) holds the unfiltered list.
    expect((await host.fanIn()).tools.map((tool) => tool.remoteName).sort()).toEqual([
      "search",
      "write",
    ]);

    // The operator now adds the exclusion. Filtering only at discovery would
    // keep serving `write` from the warm list until the next reconnect — a deny
    // rule that takes effect "eventually" is not a deny rule.
    config.toolsToExclude = ["write"];
    expect((await host.fanIn()).tools.map((tool) => tool.remoteName)).toEqual(["search"]);
  });
});

// ---------------------------------------------------------------------------
// The D1 catalogue carries it, from both sources
// ---------------------------------------------------------------------------

describe("the exclude list survives the D1 catalogue round trip", () => {
  it("decodes tools_to_exclude off a typed mcp_servers row", () => {
    const row = {
      name: "srv",
      transport: "streamable_http",
      url: "https://srv.test/mcp",
      auth_type: "none",
      tools_to_execute: JSON.stringify(["search", "write"]),
      tools_to_auto_execute: JSON.stringify([]),
      tools_to_exclude: JSON.stringify(["write"]),
      headers: null,
      oauth: null,
      signed_jwt_audience: null,
      timeout_ms: 5_000,
    };
    expect(decodeServerRow(row)?.toolsToExclude).toEqual(["write"]);
    // The control: a row from a database that predates the column decodes to a
    // server that excludes nothing, rather than to a refused row.
    expect(decodeServerRow({ ...row, tools_to_exclude: null })?.toolsToExclude).toBeUndefined();
  });

  it("refuses a typed row whose exclude list is not a JSON string array", () => {
    const row = {
      name: "srv",
      transport: "streamable_http",
      url: null,
      auth_type: "none",
      tools_to_execute: JSON.stringify(["search"]),
      tools_to_auto_execute: JSON.stringify([]),
      tools_to_exclude: JSON.stringify(["ok", 7]),
      headers: null,
      oauth: null,
      signed_jwt_audience: null,
      timeout_ms: 5_000,
    };
    // A deny list that silently drops its malformed entries permits more than
    // the operator wrote, so the row is refused instead.
    expect(decodeServerRow(row)).toBeUndefined();
  });

  it("decodes tools_to_exclude off an admin /admin/v1/mcp-servers document", () => {
    const document = {
      name: "srv",
      tenant_id: TENANT,
      transport: "http",
      url: "https://srv.test/mcp",
      tools_to_execute: ["search", "write"],
      tools_to_exclude: ["write"],
    };
    expect(decodeServerDocument(document)?.toolsToExclude).toEqual(["write"]);
    expect(decodeServerDocument({ ...document, toolsToExclude: ["search"] })?.toolsToExclude)
      // The snake_case spelling is authoritative when both are present, exactly
      // as every other field in this decoder resolves the pair.
      .toEqual(["write"]);
    // A non-array REFUSES the document rather than reading as "exclude nothing".
    expect(decodeServerDocument({ ...document, tools_to_exclude: "write" })).toBeUndefined();
  });

  it("reaches the tenant's host through loadServerCatalog", async () => {
    await ensureMcpIdentitySchema(DB);
    await DB.prepare("DELETE FROM mcp_servers").run();
    await DB.prepare(
      `INSERT INTO mcp_servers
         (tenant_id, name, transport, url, auth_type, tools_to_execute,
          tools_to_auto_execute, tools_to_exclude, headers, oauth,
          signed_jwt_audience, timeout_ms)
       VALUES (?, 'filtered', 'streamable_http', 'https://f.test/mcp', 'none', ?, ?, ?,
               NULL, NULL, NULL, 5000)`,
    )
      .bind(
        TENANT,
        JSON.stringify(["search", "write"]),
        JSON.stringify([]),
        JSON.stringify(["write"]),
      )
      .run();

    const configs = await loadServerCatalog(DB, TENANT);
    expect(configs).toHaveLength(1);
    expect(configs[0]?.toolsToExecute).toEqual(["search", "write"]);
    expect(configs[0]?.toolsToExclude).toEqual(["write"]);
  });
});

// ---------------------------------------------------------------------------
// End to end, over the exported Worker
// ---------------------------------------------------------------------------

describe("the exclude list on the wire", () => {
  let served: string[];

  beforeEach(() => {
    resetInMemoryPorts();
    served = [];
    const ports = inMemoryPorts();
    ports.auth
      .register(READ_KEY, tenantAuth({ scopes: ["tools.read"] }))
      .register(EXEC_KEY, tenantAuth());
    ports.upstreams.register(
      upstreamConfig({
        // BOTH names are on the include list. The only difference between them
        // is the exclusion, so nothing but the exclusion can explain the split.
        toolsToExecute: ["echo", "danger"],
        toolsToAutoExecute: ["echo", "danger"],
        toolsToExclude: ["danger"],
      }),
      [
        { name: "echo", input_schema: { type: "object" } },
        { name: "danger", input_schema: { type: "object" } },
      ],
      // eslint-disable-next-line @typescript-eslint/require-await
      async (tool) => {
        served.push(tool.remoteName);
        return { content: { content: [{ type: "text", text: "served" }] }, isError: false };
      },
    );
  });

  it("hides an excluded tool from tools/list and refuses tools/call on it", async () => {
    const listed = await SELF.fetch(
      rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: READ_KEY }),
    );
    const body = (await listed.json()) as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((tool) => tool.name);
    // The control: `echo` is listed through the very same path.
    expect(names).toContain("srv-echo");
    expect(names).not.toContain("srv-danger");

    const called = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "srv-danger" } },
        { key: EXEC_KEY },
      ),
    );
    // The chokepoint's deny-by-default arm: the catalogue no longer advertises
    // the tool, so it resolves as MISSING and is refused there — audited once,
    // and never dispatched.
    const error = (await called.json()) as { error?: { message?: string } };
    expect(error.error?.message ?? "").toContain("is not allowlisted for execution");
    expect(served).toEqual([]);

    // The control that makes the line above mean something: the sibling tool
    // reaches the upstream through the identical path.
    const ok = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "srv-echo" } },
        { key: EXEC_KEY },
      ),
    );
    expect(ok.status).toBe(200);
    expect(served).toEqual(["echo"]);
  });
});
