/**
 * JSON-RPC 2.0 codec unit tests.
 *
 * Every malformed shape must produce the SPEC'd error code, not a generic
 * failure: a client distinguishes "your JSON is broken" (-32700) from "your
 * envelope is wrong" (-32600) from "no such method" (-32601) from "bad params"
 * (-32602), and FerroGate's application codes must not collide with them.
 */
import { describe, expect, it } from "vitest";

import {
  callToolParams,
  decodeMcpRequest,
  decodeMcpRequestValue,
  decodeStrictRequest,
  ensureNoJsonRpcError,
  isNotification,
  JSONRPC_VERSION,
  JsonRpcErrorCode,
  jsonRpcError,
  jsonRpcResult,
  mcpErrorCode,
  parseCallResult,
  parseToolsList,
  renderJsonRpcResponse,
} from "../src/jsonrpc.js";

describe("JSON-RPC request decoding", () => {
  it("accepts a well-formed request and defaults absent params", () => {
    const decoded = decodeMcpRequest('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.request.method).toBe("tools/list");
    expect(decoded.request.id).toBe(1);
    expect(decoded.request.params).toEqual({});
  });

  it("treats an absent id as a Notification", () => {
    const decoded = decodeMcpRequest('{"jsonrpc":"2.0","method":"notifications/initialized"}');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(isNotification(decoded.request)).toBe(true);
  });

  it("accepts a literal null id and does NOT treat it as a notification", () => {
    const decoded = decodeMcpRequest('{"jsonrpc":"2.0","id":null,"method":"ping"}');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.request.id).toBeNull();
    expect(isNotification(decoded.request)).toBe(false);
  });

  it("maps unparseable JSON to -32700 Parse error", () => {
    const decoded = decodeMcpRequest("{not json");
    expect(decoded.ok).toBe(false);
    if (decoded.ok) return;
    expect(decoded.response.error?.code).toBe(JsonRpcErrorCode.ParseError);
    expect(decoded.response.error?.message).toMatch(/^parse error: /);
    // The id could not be determined, so the member is OMITTED entirely.
    expect(renderJsonRpcResponse(decoded.response)).not.toHaveProperty("id");
  });

  it.each([
    ['{"id":1,"method":"tools/list"}', "missing jsonrpc member"],
    ['{"jsonrpc":"1.0","id":1,"method":"tools/list"}', "wrong jsonrpc version"],
    ['{"jsonrpc":"2.0","id":1}', "missing method"],
    ['{"jsonrpc":"2.0","id":1,"method":7}', "non-string method"],
    ['{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}', "object id"],
    ["[1,2,3]", "not an object"],
    ['"a string"', "scalar body"],
  ])("maps %s (%s) to -32600 Invalid Request", (body) => {
    const decoded = decodeMcpRequest(body);
    expect(decoded.ok).toBe(false);
    if (decoded.ok) return;
    expect(decoded.response.error?.code).toBe(JsonRpcErrorCode.InvalidRequest);
  });

  it("echoes a recoverable id on an Invalid Request so the client can correlate", () => {
    const decoded = decodeMcpRequestValue({ jsonrpc: "2.0", id: "req-9" });
    expect(decoded.ok).toBe(false);
    if (decoded.ok) return;
    expect(decoded.response.id).toBe("req-9");
  });

  it("the strict codec rejects non-structured params that the ingress tolerates", () => {
    const scalarParams = { jsonrpc: "2.0", id: 1, method: "ping", params: 5 };
    expect(decodeStrictRequest(scalarParams).ok).toBe(false);
    // The ingress shape mirrors the Rust `params: Value` default, so the
    // handler's own "params.x is required" -32602 stays reachable.
    expect(decodeMcpRequestValue(scalarParams).ok).toBe(true);
  });
});

describe("JSON-RPC response encoding", () => {
  it("omits absent members rather than emitting null (serde skip_serializing_if)", () => {
    const rendered = renderJsonRpcResponse(jsonRpcResult(undefined, { ok: true }));
    expect(rendered).toEqual({ jsonrpc: "2.0", result: { ok: true } });
    expect(rendered).not.toHaveProperty("id");
    expect(rendered).not.toHaveProperty("error");
  });

  it("renders an error with optional data", () => {
    const rendered = renderJsonRpcResponse(
      jsonRpcError(4, JsonRpcErrorCode.ModernUnsupportedVersion, "Unsupported protocol version", {
        requested: "1999-01-01",
      }),
    );
    expect(rendered).toEqual({
      jsonrpc: JSONRPC_VERSION,
      id: 4,
      error: {
        code: -32022,
        message: "Unsupported protocol version",
        data: { requested: "1999-01-01" },
      },
    });
  });

  it("omits `data` when absent", () => {
    const rendered = renderJsonRpcResponse(jsonRpcError(1, -32601, "nope"));
    expect(rendered["error"]).toEqual({ code: -32601, message: "nope" });
  });
});

describe("application error-code mapping", () => {
  it.each([
    ["tool_denied", -32001],
    ["tool_not_found", -32602],
    ["mcp_server_unavailable", -32002],
    ["anything_else", -32000],
  ])("maps %s to %i", (code, expected) => {
    expect(mcpErrorCode(code)).toBe(expected);
  });

  it("keeps every code inside the spec's reserved server-error band", () => {
    for (const code of Object.values(JsonRpcErrorCode)) {
      expect(code).toBeLessThanOrEqual(-32000);
      expect(code).toBeGreaterThanOrEqual(-32768);
    }
  });
});

describe("tools/list + tools/call payloads", () => {
  it("parses an upstream tools/list into canonical ToolDefs", () => {
    const tools = parseToolsList({
      jsonrpc: "2.0",
      id: 1,
      result: {
        tools: [
          { name: "echo", description: "echoes", inputSchema: { type: "object" } },
          { name: "add", inputSchema: { type: "object" } },
        ],
      },
    });
    expect(tools).toEqual([
      { name: "echo", input_schema: { type: "object" }, description: "echoes" },
      { name: "add", input_schema: { type: "object" } },
    ]);
  });

  it("raises on a JSON-RPC error member instead of returning an empty catalog", () => {
    expect(() =>
      parseToolsList({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "nope" } }),
    ).toThrow(/MCP JSON-RPC error/);
  });

  it("raises when the result member is missing entirely", () => {
    expect(() => parseToolsList({ jsonrpc: "2.0", id: 1 })).toThrow(/missing result/);
  });

  it("defaults isError to false and preserves the raw result value", () => {
    const parsed = parseCallResult({
      jsonrpc: "2.0",
      id: 1,
      result: { content: [{ type: "text", text: "hi" }] },
    });
    expect(parsed.isError).toBe(false);
    expect(parsed.content).toEqual({ content: [{ type: "text", text: "hi" }] });
  });

  it("honours an explicit isError", () => {
    expect(parseCallResult({ jsonrpc: "2.0", id: 1, result: { isError: true } }).isError).toBe(
      true,
    );
  });

  it("builds tools/call params and refuses non-object arguments", () => {
    expect(callToolParams("echo", { text: "hi" })).toEqual({
      name: "echo",
      arguments: { text: "hi" },
    });
    expect(callToolParams("echo", null)).toEqual({ name: "echo" });
    expect(() => callToolParams("echo", 5)).toThrow(/must be a JSON object/);
    expect(() => callToolParams("echo", ["a"])).toThrow(/must be a JSON object/);
  });

  it("ensureNoJsonRpcError passes a clean response through", () => {
    expect(() => ensureNoJsonRpcError({ jsonrpc: "2.0", id: 1, result: {} })).not.toThrow();
  });
});
