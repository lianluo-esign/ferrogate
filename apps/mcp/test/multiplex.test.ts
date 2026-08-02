/**
 * The MULTIPLEX contract (#687): one endpoint, one session, many upstreams.
 *
 * These tests drive the REAL production fan-in host (`HttpMcpUpstreams`) behind
 * a stubbed `fetch` and the REAL governed chokepoint (`tools.ts`), because the
 * three defects they pin are all seams BETWEEN those two — a fake port would
 * have reproduced the seam it was meant to test.
 *
 * The catalogue is deliberately hostile in exactly the way a real multi-server
 * tenant is: server names contain hyphens, and two servers' namespaced tool
 * names collide.
 *
 *   github-mcp : search      -> "github-mcp-search"
 *   docs       : search-v2   -> "docs-search-v2"   <-- collides
 *   docs-search: v2          -> "docs-search-v2"   <-- collides
 *   offline    : (unreachable)
 */
import { beforeEach, describe, expect, it } from "vitest";

import {
  MULTIPLEX_DEGRADED_META,
  MULTIPLEX_REMOTE_NAME_META,
  MULTIPLEX_SERVER_META,
} from "../src/multiplex.js";
import {
  inMemoryPorts,
  resetInMemoryPorts,
  type DispatchContext,
  type McpPorts,
  type McpServerConfig,
} from "../src/ports.js";
import { MCP_PROTOCOL_VERSION } from "../src/protocol.js";
import { executeToolWithGovernance, toolsList } from "../src/tools.js";
import { HttpMcpUpstreams } from "../src/transport.js";
import { tenantAuth } from "./fixtures.js";

const context: DispatchContext = { requestId: "req-1", auth: tenantAuth() };

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const DISCOVER_OK = {
  jsonrpc: "2.0",
  id: 1,
  result: { resultType: "complete", capabilities: {}, supportedVersions: [MCP_PROTOCOL_VERSION] },
};

/** One upstream in the stubbed fleet, addressed by its own URL. */
interface Upstream {
  readonly name: string;
  readonly tools: readonly string[];
  /** `true` ⇒ every request to it fails, which is the partial-failure leg. */
  readonly offline?: boolean;
}

const FLEET: readonly Upstream[] = [
  { name: "github-mcp", tools: ["search"] },
  { name: "docs", tools: ["search-v2"] },
  { name: "docs-search", tools: ["v2"] },
  { name: "offline", tools: ["ping"], offline: true },
];

function url(name: string): string {
  return `https://${name}.upstream.test/mcp`;
}

function configs(): McpServerConfig[] {
  return FLEET.map((server) => ({
    name: server.name,
    transport: "streamable_http" as const,
    url: url(server.name),
    authType: "none" as const,
    toolsToExecute: [...server.tools],
    toolsToAutoExecute: [...server.tools],
    timeoutMs: 5_000,
  }));
}

/** Which upstream served each `tools/call`, in order — the attribution ground truth. */
interface Dispatched {
  server: string;
  remoteName: string;
}

function fleetFetch(dispatched: Dispatched[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = String(input);
    const server = FLEET.find((entry) => url(entry.name) === target);
    if (server === undefined) throw new Error(`no stub for ${target}`);
    if (server.offline === true) throw new Error("ECONNREFUSED");
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params?: { name?: string };
    };
    if (body.method === "server/discover") return jsonResponse(DISCOVER_OK);
    if (body.method === "tools/list") {
      return jsonResponse({
        jsonrpc: "2.0",
        id: 2,
        result: {
          tools: server.tools.map((name) => ({ name, inputSchema: { type: "object" } })),
        },
      });
    }
    dispatched.push({ server: server.name, remoteName: String(body.params?.name) });
    return jsonResponse({
      jsonrpc: "2.0",
      id: 3,
      result: { content: [{ type: "text", text: `served by ${server.name}` }] },
    });
  }) as unknown as typeof fetch;
}

function fleetPorts(dispatched: Dispatched[]): McpPorts {
  const base = inMemoryPorts();
  return { ...base, upstreams: new HttpMcpUpstreams(configs(), fleetFetch(dispatched)) };
}

let dispatched: Dispatched[];
let ports: McpPorts;

beforeEach(() => {
  resetInMemoryPorts();
  dispatched = [];
  ports = fleetPorts(dispatched);
  inMemoryPorts().audit.clear();
});

function auditEvents(): ReadonlyArray<{ action: string; target: string; outcome: string }> {
  return inMemoryPorts()
    .audit.events()
    .map((event) => ({ action: event.action, target: event.target, outcome: event.outcome }));
}

describe("attribution survives multiplexing (#677/#678)", () => {
  it("attributes a call to the upstream that served it, not to the first hyphen", async () => {
    const executed = await executeToolWithGovernance(
      ports,
      context,
      { name: "github-mcp-search", arguments: { q: "ferrogate" } },
      "mcp",
    );
    expect(executed.ok).toBe(true);
    expect(dispatched).toEqual([{ server: "github-mcp", remoteName: "search" }]);

    // The audit target names the SERVER that ran the tool. Splitting the flat
    // name on its first hyphen yields `mcp:github/tool:mcp-search`, which is a
    // server that does not exist and a tool nobody called.
    const executeRow = auditEvents().find(
      (event) => event.action === "tool.execute" && event.outcome === "success",
    );
    expect(executeRow?.target).toBe("mcp:github-mcp/tool:search");
  });

  it("attributes the identity-resolution row to the serving upstream too", async () => {
    await executeToolWithGovernance(ports, context, { name: "github-mcp-search", arguments: {} }, "mcp");
    const identityRow = auditEvents().find((event) => event.action === "mcp.identity.use");
    expect(identityRow?.target).toBe("mcp:github-mcp/identity");
  });
});

describe("tool-name collisions across upstreams", () => {
  it("never silently routes a colliding name to one of the two servers", async () => {
    const executed = await executeToolWithGovernance(
      ports,
      context,
      { name: "docs-search-v2", arguments: { q: "x" } },
      "mcp",
    );
    // Today the longest-prefix rule silently picks `docs-search` and the `docs`
    // tool of the same flat name is unreachable forever. Guessing is the
    // failure: the arguments land on a server the caller did not choose, under
    // THAT server's credentials and allowlist.
    expect(executed.ok).toBe(false);
    if (!executed.ok) {
      expect(executed.error.code).toBe("mcp_tool_ambiguous");
      expect(executed.error.message).toContain("docs");
      expect(executed.error.message).toContain("docs-search");
    }
    expect(dispatched).toEqual([]);
  });

  it("keeps BOTH colliding tools callable through the explicit server selector", async () => {
    const viaDocs = await executeToolWithGovernance(
      ports,
      context,
      { name: "docs-search-v2", arguments: {}, server: "docs" },
      "mcp",
    );
    expect(viaDocs.ok).toBe(true);

    const viaDocsSearch = await executeToolWithGovernance(
      ports,
      context,
      { name: "docs-search-v2", arguments: {}, server: "docs-search" },
      "mcp",
    );
    expect(viaDocsSearch.ok).toBe(true);

    expect(dispatched).toEqual([
      { server: "docs", remoteName: "search-v2" },
      { server: "docs-search", remoteName: "v2" },
    ]);
  });

  it("refuses a selector naming an upstream that does not serve the tool", async () => {
    const executed = await executeToolWithGovernance(
      ports,
      context,
      { name: "docs-search-v2", arguments: {}, server: "github-mcp" },
      "mcp",
    );
    expect(executed.ok).toBe(false);
    expect(dispatched).toEqual([]);
  });

  it("advertises the owning server on every listed tool so the selector is derivable", async () => {
    const response = await toolsList(ports, context, 1);
    const result = response.result as {
      tools: Array<{ name: string; _meta?: Record<string, unknown> }>;
    };
    const colliding = result.tools.filter((tool) => tool.name === "docs-search-v2");
    expect(colliding).toHaveLength(2);
    expect(colliding.map((tool) => tool._meta?.[MULTIPLEX_SERVER_META]).sort()).toEqual([
      "docs",
      "docs-search",
    ]);
    const github = result.tools.find((tool) => tool.name === "github-mcp-search");
    expect(github?._meta?.[MULTIPLEX_SERVER_META]).toBe("github-mcp");
    expect(github?._meta?.[MULTIPLEX_REMOTE_NAME_META]).toBe("search");
  });
});

describe("partial upstream failure is reported, never silently shortened", () => {
  it("names the unreachable upstream in the tools/list result", async () => {
    const response = await toolsList(ports, context, 1);
    const result = response.result as {
      tools: Array<{ name: string }>;
      _meta?: Record<string, Array<{ server: string; code: string }>>;
    };
    // The reachable upstreams still list — one dead server must not blank the
    // fan-in.
    expect(result.tools.map((tool) => tool.name)).toEqual(
      expect.arrayContaining(["github-mcp-search", "docs-search-v2"]),
    );
    const degraded = result._meta?.[MULTIPLEX_DEGRADED_META];
    expect(degraded?.map((entry) => entry.server)).toEqual(["offline"]);
  });

  it("audits the degraded listing as degraded, not as an unqualified success", async () => {
    await toolsList(ports, context, 1);
    const listRow = auditEvents().find((event) => event.action === "tool.list");
    expect(listRow?.outcome).toBe("degraded");
  });
});
