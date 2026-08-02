/**
 * Outbound Streamable-HTTP / SSE host tests.
 *
 * `HttpMcpUpstreams` is the leg that talks to a REAL upstream MCP server: it
 * negotiates the era (modern `server/discover`, else the legacy `initialize`
 * handshake), mirrors the `Mcp-Method` / `Mcp-Name` routing headers, applies
 * the resolved per-request identity, and parses either an `application/json` or
 * a `text/event-stream` reply. A stubbed `fetch` lets every branch be asserted
 * deterministically — no network, no MSW needed for a JSON-RPC upstream.
 */
import { describe, expect, it } from "vitest";

import { McpDispatchHeaders, McpExecutionError, type DispatchContext } from "../src/ports.js";
import {
  MCP_METHOD_HEADER,
  MCP_NAME_HEADER,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_HEADER,
} from "../src/protocol.js";
import { encodeSseEvent, HttpMcpUpstreams, validateHttpEndpoint } from "../src/transport.js";
import { tenantAuth, upstreamConfig } from "./fixtures.js";

interface Seen {
  url: string;
  headers: Headers;
  body: { method: string; params?: Record<string, unknown> };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sseResponse(payload: unknown): Response {
  return new Response(encodeSseEvent({ event: "message", data: JSON.stringify(payload) }), {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

const DISCOVER_OK = {
  jsonrpc: "2.0",
  id: 1,
  result: {
    resultType: "complete",
    capabilities: {},
    supportedVersions: [MCP_PROTOCOL_VERSION],
  },
};

const TOOLS_OK = {
  jsonrpc: "2.0",
  id: 2,
  result: { tools: [{ name: "echo", inputSchema: { type: "object" } }, { name: "danger" }] },
};

function stubFetch(handler: (seen: Seen) => Response): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const record: Seen = {
      url: String(input),
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body)) as Seen["body"],
    };
    seen.push(record);
    return handler(record);
  }) as unknown as typeof fetch;
  return { fetch: impl, seen };
}

const context: DispatchContext = { requestId: "req-1", agentRunId: "run-1", auth: tenantAuth() };

describe("modern Streamable HTTP upstream", () => {
  it("negotiates via server/discover, lists only allowlisted tools, and namespaces them", async () => {
    const { fetch: impl, seen } = stubFetch((request) =>
      request.body.method === "server/discover"
        ? jsonResponse(DISCOVER_OK)
        : jsonResponse(TOOLS_OK),
    );
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);

    const tools = await upstreams.listTools();
    expect(tools.map((tool) => tool.name)).toEqual(["srv-echo"]);
    expect(seen[0]?.body.method).toBe("server/discover");
    // Modern requests carry `_meta` declaring the protocol revision.
    expect(seen[0]?.body.params?.["_meta"]).toMatchObject({
      "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
    });
    expect(seen[1]?.headers.get(MCP_METHOD_HEADER)).toBe("tools/list");
    expect(seen[1]?.headers.get(MCP_PROTOCOL_VERSION_HEADER)).toBe(MCP_PROTOCOL_VERSION);
  });

  it("mirrors Mcp-Name and the resolved identity on tools/call", async () => {
    const { fetch: impl, seen } = stubFetch((request) => {
      if (request.body.method === "server/discover") return jsonResponse(DISCOVER_OK);
      if (request.body.method === "tools/list") return jsonResponse(TOOLS_OK);
      return jsonResponse({
        jsonrpc: "2.0",
        id: 3,
        result: { content: [{ type: "text", text: "ok" }] },
      });
    });
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);
    const tool = await upstreams.toolByName("srv-echo");
    expect(tool).toBeDefined();

    const result = await upstreams.callTool(
      tool!,
      { text: "hi" },
      McpDispatchHeaders.bearer("grant-token"),
      context,
    );
    expect(result.isError).toBe(false);

    const call = seen.at(-1);
    expect(call?.body.method).toBe("tools/call");
    expect(call?.headers.get(MCP_NAME_HEADER)).toBe("echo");
    expect(call?.headers.get("authorization")).toBe("Bearer grant-token");
    expect(call?.headers.get("accept")).toBe("application/json, text/event-stream");
  });

  it("parses a text/event-stream reply identically to a JSON one", async () => {
    const { fetch: impl } = stubFetch((request) => {
      if (request.body.method === "server/discover") return sseResponse(DISCOVER_OK);
      if (request.body.method === "tools/list") return sseResponse(TOOLS_OK);
      return sseResponse({ jsonrpc: "2.0", id: 3, result: { isError: true } });
    });
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);
    const tool = await upstreams.toolByName("srv-echo");
    const result = await upstreams.callTool(tool!, {}, McpDispatchHeaders.empty(), context);
    expect(result.isError).toBe(true);
  });

  it("refuses to dispatch an un-allowlisted tool even if the caller forges the McpTool", async () => {
    const { fetch: impl, seen } = stubFetch(() => jsonResponse(DISCOVER_OK));
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);
    await expect(
      upstreams.callTool(
        {
          name: "srv-danger",
          serverName: "srv",
          remoteName: "danger",
          inputSchema: {},
          autoExecute: true,
        },
        {},
        McpDispatchHeaders.empty(),
        context,
      ),
    ).rejects.toThrow(/not allowlisted for execution/);
    expect(seen).toHaveLength(0);
  });

  it("maps a 401 to mcp_upstream_unauthorized", async () => {
    const { fetch: impl } = stubFetch((request) => {
      if (request.body.method === "server/discover") return jsonResponse(DISCOVER_OK);
      if (request.body.method === "tools/list") return jsonResponse(TOOLS_OK);
      return jsonResponse({ error: "nope" }, 401);
    });
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);
    const tool = await upstreams.toolByName("srv-echo");
    await expect(
      upstreams.callTool(tool!, {}, McpDispatchHeaders.empty(), context),
    ).rejects.toMatchObject({ code: "mcp_upstream_unauthorized" });
  });
});

describe("legacy downgrade", () => {
  it("falls back to the initialize handshake on an unstructured 405", async () => {
    const { fetch: impl, seen } = stubFetch((request) => {
      if (request.body.method === "server/discover") return new Response("nope", { status: 405 });
      if (request.body.method === "initialize") {
        return jsonResponse({
          jsonrpc: "2.0",
          id: 2,
          result: { protocolVersion: "2025-11-25" },
        });
      }
      return jsonResponse(TOOLS_OK);
    });
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);
    const tools = await upstreams.listTools();
    expect(tools.map((tool) => tool.name)).toEqual(["srv-echo"]);
    expect(seen.map((request) => request.body.method)).toEqual([
      "server/discover",
      "initialize",
      "tools/list",
    ]);
    // A legacy request must NOT carry the modern routing headers.
    expect(seen[2]?.headers.get(MCP_METHOD_HEADER)).toBeNull();
    expect(seen[2]?.body.params).toEqual({});
  });

  it("refuses an initialize that echoes an invalid legacy revision", async () => {
    const { fetch: impl } = stubFetch((request) => {
      if (request.body.method === "server/discover") return new Response("nope", { status: 400 });
      // Echoing the MODERN revision from `initialize` is never valid.
      return jsonResponse({
        jsonrpc: "2.0",
        id: 2,
        result: { protocolVersion: MCP_PROTOCOL_VERSION },
      });
    });
    const upstreams = new HttpMcpUpstreams([upstreamConfig()], impl);
    // A single unreachable upstream must not blank the catalog, so listTools
    // swallows it — the explicit call path is where it must surface.
    expect(await upstreams.listTools()).toEqual([]);
    await expect(
      upstreams.callTool(
        {
          name: "srv-echo",
          serverName: "srv",
          remoteName: "echo",
          inputSchema: {},
          autoExecute: true,
        },
        {},
        McpDispatchHeaders.empty(),
        context,
      ),
    ).rejects.toThrow(/invalid legacy protocol version/);
  });
});

describe("stdio upstreams have no Workers implementation", () => {
  it("refuses a stdio dispatch instead of silently treating it as HTTP", async () => {
    const { fetch: impl, seen } = stubFetch(() => jsonResponse(DISCOVER_OK));
    const upstreams = new HttpMcpUpstreams(
      [upstreamConfig({ transport: "stdio", url: undefined })],
      impl,
    );
    expect(await upstreams.listTools()).toEqual([]);
    await expect(
      upstreams.callTool(
        {
          name: "srv-echo",
          serverName: "srv",
          remoteName: "echo",
          inputSchema: {},
          autoExecute: true,
        },
        {},
        McpDispatchHeaders.empty(),
        context,
      ),
    ).rejects.toMatchObject({ code: "mcp_server_unavailable" });
    expect(seen).toHaveLength(0);
  });
});

describe("endpoint validation + identity header hygiene", () => {
  it("requires an http/https endpoint", () => {
    expect(() => validateHttpEndpoint("https://ok.test/mcp")).not.toThrow();
    expect(() => validateHttpEndpoint("file:///etc/passwd")).toThrow(/http or https/);
    expect(() => validateHttpEndpoint("not a url")).toThrow(/invalid MCP endpoint/);
  });

  it("refuses a bearer token that is not a legal header value", () => {
    expect(() => McpDispatchHeaders.bearer("bad\r\nInjected: yes")).toThrow(
      /not a valid HTTP header value/,
    );
  });

  it("surfaces McpExecutionError with a stable code", () => {
    const error = new McpExecutionError("tool_denied", "nope");
    expect(error.code).toBe("tool_denied");
    expect(error).toBeInstanceOf(Error);
  });
});
