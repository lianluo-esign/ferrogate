/**
 * Dual-era protocol + routing-header unit tests.
 *
 * The routing-header verifier is a security control, not ergonomics: if
 * `Mcp-Method` / `Mcp-Name` could disagree with the body, a caller would be
 * scope-gated, rate-limited, and metered as one operation while executing
 * another. Every assertion below pins that door shut.
 */
import { describe, expect, it } from "vitest";

import { JsonRpcErrorCode, type McpIngressRequest } from "../src/jsonrpc.js";
import {
  completeModernResult,
  declaredAgentRunId,
  decodeMcpName,
  encodeMcpHeaderValue,
  httpLegacyDowngradeReason,
  ingressErrorCode,
  ingressErrorData,
  ingressMode,
  isSupportedModernMethod,
  isSupportedProtocolVersion,
  MCP_LEGACY_PROTOCOL_VERSION,
  MCP_METHOD_HEADER,
  MCP_NAME_HEADER,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_FALLBACK,
  MCP_PROTOCOL_VERSION_HEADER,
  modernRequestMeta,
  negotiateProtocolVersion,
  resolveLegacyProtocolVersion,
  validateIngress,
  verifyRoutingHeaders,
} from "../src/protocol.js";
import {
  DEFAULT_RECONNECT_POLICY,
  type McpSessionState,
  newSessionState,
  statusOf,
} from "../src/session.js";

function rpc(method: string, params: unknown = {}, id: number | string = 1): McpIngressRequest {
  return { jsonrpc: "2.0", method, params, id };
}

function modernParams(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { ...extra, _meta: modernRequestMeta() };
}

function headers(entries: Record<string, string>): Headers {
  return new Headers(entries);
}

describe("protocol version negotiation", () => {
  it("never echoes the modern revision from a legacy initialize", () => {
    expect(negotiateProtocolVersion(MCP_PROTOCOL_VERSION)).toBe(MCP_LEGACY_PROTOCOL_VERSION);
  });

  it("honours the exact supported legacy revisions", () => {
    expect(negotiateProtocolVersion(MCP_LEGACY_PROTOCOL_VERSION)).toBe(MCP_LEGACY_PROTOCOL_VERSION);
    expect(negotiateProtocolVersion(MCP_PROTOCOL_VERSION_FALLBACK)).toBe(
      MCP_PROTOCOL_VERSION_FALLBACK,
    );
  });

  it("falls back to the direct legacy predecessor for omitted/unknown versions", () => {
    expect(negotiateProtocolVersion(undefined)).toBe(MCP_LEGACY_PROTOCOL_VERSION);
    expect(negotiateProtocolVersion("1999-01-01")).toBe(MCP_LEGACY_PROTOCOL_VERSION);
  });

  it("refuses a modern or unknown version as an initialize result", () => {
    expect(resolveLegacyProtocolVersion(MCP_PROTOCOL_VERSION)).toBeUndefined();
    expect(resolveLegacyProtocolVersion(undefined)).toBeUndefined();
    expect(resolveLegacyProtocolVersion(MCP_LEGACY_PROTOCOL_VERSION)).toBe(
      MCP_LEGACY_PROTOCOL_VERSION,
    );
  });

  it("knows exactly which revisions FerroGate speaks", () => {
    expect(isSupportedProtocolVersion(MCP_PROTOCOL_VERSION)).toBe(true);
    expect(isSupportedProtocolVersion("2020-01-01")).toBe(false);
  });
});

describe("Mcp-Method / Mcp-Name verification", () => {
  it("accepts absent headers (legacy callers)", () => {
    expect(verifyRoutingHeaders(undefined, undefined, "tools/call", "echo")).toBeUndefined();
  });

  it("rejects a method header that disagrees with the body", () => {
    const mismatch = verifyRoutingHeaders("tools/list", undefined, "tools/call", "echo");
    expect(mismatch).toEqual({
      header: "Mcp-Method",
      headerValue: "tools/list",
      bodyValue: "tools/call",
    });
  });

  it("rejects a name header that disagrees with the body", () => {
    const mismatch = verifyRoutingHeaders("tools/call", "cheap", "tools/call", "expensive");
    expect(mismatch).toEqual({
      header: "Mcp-Name",
      headerValue: "cheap",
      bodyValue: "expensive",
    });
  });

  it("rejects a name header on a body that carries no name at all", () => {
    expect(verifyRoutingHeaders("tools/list", "echo", "tools/list", undefined)).toEqual({
      header: "Mcp-Name",
      headerValue: "echo",
      bodyValue: "",
    });
  });
});

describe("header value sentinel encoding", () => {
  it("passes clean visible ASCII through unchanged", () => {
    expect(encodeMcpHeaderValue("tools/call")).toBe("tools/call");
  });

  it.each([
    ["with\nnewline", "control byte"],
    [" leading", "leading whitespace"],
    ["trailing ", "trailing whitespace"],
    ["=?base64?ambiguous?=", "already looks encoded"],
    ["naïve", "non-ASCII"],
  ])("base64-wraps %s (%s)", (value) => {
    const encoded = encodeMcpHeaderValue(value);
    expect(encoded.startsWith("=?base64?")).toBe(true);
    const decoded = decodeMcpName(encoded);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.value).toBe(value);
  });

  it("refuses a malformed sentinel payload", () => {
    const decoded = decodeMcpName("=?base64?!!!not-base64!!!?=");
    expect(decoded.ok).toBe(false);
  });
});

describe("era classification", () => {
  it("selects legacy from the opening method regardless of modern metadata", () => {
    expect(
      ingressMode(
        headers({ [MCP_PROTOCOL_VERSION_HEADER]: MCP_PROTOCOL_VERSION }),
        rpc("initialize", modernParams()),
      ),
    ).toBe("legacy");
  });

  it("selects modern for server/discover and for modern body metadata", () => {
    expect(ingressMode(headers({}), rpc("server/discover", modernParams()))).toBe("modern");
    expect(ingressMode(headers({}), rpc("tools/list", modernParams()))).toBe("modern");
  });

  it("selects legacy when no protocol header and no modern metadata are present", () => {
    expect(ingressMode(headers({}), rpc("tools/list"))).toBe("legacy");
  });

  it("only implements the modern methods the candidate revision defines", () => {
    expect(isSupportedModernMethod("tools/call")).toBe(true);
    // `ping` and `initialize` were REMOVED by the modern revision.
    expect(isSupportedModernMethod("ping")).toBe(false);
    expect(isSupportedModernMethod("initialize")).toBe(false);
  });
});

describe("modern ingress validation", () => {
  const modernHeaders = (extra: Record<string, string> = {}): Headers =>
    headers({
      [MCP_PROTOCOL_VERSION_HEADER]: MCP_PROTOCOL_VERSION,
      [MCP_METHOD_HEADER]: "tools/call",
      [MCP_NAME_HEADER]: "srv-echo",
      ...extra,
    });

  const modernCall = rpc("tools/call", modernParams({ name: "srv-echo" }));

  it("accepts a complete modern request", () => {
    const validated = validateIngress(modernHeaders(), modernCall);
    expect(validated.ok).toBe(true);
    if (!validated.ok) return;
    expect(validated.ingress).toEqual({
      mode: "modern",
      metricMethod: "tools/call",
      metricName: "srv-echo",
    });
  });

  it("requires the Mcp-Method header on a modern request", () => {
    const stripped = new Headers(modernHeaders());
    stripped.delete(MCP_METHOD_HEADER);
    const validated = validateIngress(stripped, modernCall);
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(ingressErrorCode(validated.error)).toBe(JsonRpcErrorCode.ModernHeaderMismatch);
  });

  it("requires the Mcp-Name header for a named modern method", () => {
    const stripped = new Headers(modernHeaders());
    stripped.delete(MCP_NAME_HEADER);
    const validated = validateIngress(stripped, modernCall);
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(ingressErrorCode(validated.error)).toBe(JsonRpcErrorCode.ModernHeaderMismatch);
  });

  it("fails closed when the routing header names a different tool than the body", () => {
    const validated = validateIngress(
      modernHeaders({ [MCP_NAME_HEADER]: "srv-cheap" }),
      modernCall,
    );
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(validated.error.kind).toBe("header_mismatch");
  });

  it("rejects an unsupported requested revision with -32022 and the supported list", () => {
    const body = rpc("tools/list", {
      _meta: {
        "io.modelcontextprotocol/protocolVersion": "1999-01-01",
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    });
    const validated = validateIngress(
      headers({
        [MCP_PROTOCOL_VERSION_HEADER]: "1999-01-01",
        [MCP_METHOD_HEADER]: "tools/list",
      }),
      body,
    );
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(ingressErrorCode(validated.error)).toBe(JsonRpcErrorCode.ModernUnsupportedVersion);
    expect(ingressErrorData(validated.error)).toMatchObject({ requested: "1999-01-01" });
  });

  it("rejects a modern request whose header and body protocol versions disagree", () => {
    const validated = validateIngress(
      headers({
        [MCP_PROTOCOL_VERSION_HEADER]: MCP_LEGACY_PROTOCOL_VERSION,
        [MCP_METHOD_HEADER]: "tools/list",
      }),
      rpc("tools/list", modernParams()),
    );
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(validated.error.kind).toBe("header_mismatch");
  });

  it("rejects a modern request missing params._meta with -32602", () => {
    const validated = validateIngress(
      headers({
        [MCP_PROTOCOL_VERSION_HEADER]: MCP_PROTOCOL_VERSION,
        [MCP_METHOD_HEADER]: "tools/list",
      }),
      rpc("tools/list", {}),
    );
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(ingressErrorCode(validated.error)).toBe(JsonRpcErrorCode.InvalidParams);
  });

  it("rejects a malformed clientInfo without ever echoing its content", () => {
    const validated = validateIngress(
      headers({
        [MCP_PROTOCOL_VERSION_HEADER]: MCP_PROTOCOL_VERSION,
        [MCP_METHOD_HEADER]: "tools/list",
      }),
      rpc("tools/list", {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
          "io.modelcontextprotocol/clientCapabilities": {},
          "io.modelcontextprotocol/clientInfo": { name: "secret-fleet-id" },
        },
      }),
    );
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(validated.error.kind).toBe("invalid_params");
    expect(JSON.stringify(validated.error)).not.toContain("secret-fleet-id");
  });

  it("refuses an ambiguous repeated routing header rather than picking one", () => {
    const repeated = new Headers();
    repeated.append(MCP_METHOD_HEADER, "tools/list");
    repeated.append(MCP_METHOD_HEADER, "tools/call");
    const validated = validateIngress(repeated, rpc("tools/list"));
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(validated.error.kind).toBe("header_mismatch");
  });

  it("keeps routing headers optional for legacy requests", () => {
    const validated = validateIngress(headers({}), rpc("tools/list"));
    expect(validated.ok).toBe(true);
    if (!validated.ok) return;
    expect(validated.ingress.mode).toBe("legacy");
  });
});

describe("modern result completion", () => {
  it("stamps the discriminator and the private-cache hint on cacheable results", () => {
    const result: Record<string, unknown> = { tools: [] };
    completeModernResult(result as never, "tools/list");
    expect(result).toMatchObject({ resultType: "complete", ttlMs: 5000, cacheScope: "private" });
  });

  it("does not add a cache hint to tools/call", () => {
    const result: Record<string, unknown> = { content: [] };
    completeModernResult(result as never, "tools/call");
    expect(result["resultType"]).toBe("complete");
    expect(result).not.toHaveProperty("ttlMs");
  });
});

describe("declared agent_run_id parsing (#522)", () => {
  it("reports absence without fabricating an id", () => {
    const parsed = declaredAgentRunId(new Headers());
    expect(parsed).toEqual({ ok: true, value: undefined });
  });

  it("treats a whitespace-only declaration as absent", () => {
    expect(declaredAgentRunId(headers({ "x-ferrogate-agent-run-id": "   " }))).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it("accepts the documented charset and trims", () => {
    expect(declaredAgentRunId(headers({ "x-ferrogate-agent-run-id": " run-1.a:b_c " }))).toEqual({
      ok: true,
      value: "run-1.a:b_c",
    });
  });

  it("rejects an overlong or out-of-charset value", () => {
    expect(declaredAgentRunId(headers({ "x-ferrogate-agent-run-id": "a".repeat(129) })).ok).toBe(
      false,
    );
    expect(declaredAgentRunId(headers({ "x-ferrogate-agent-run-id": "has space" })).ok).toBe(false);
  });
});

describe("stdio downgrade evidence — the KEPT platform-limit vocabulary", () => {
  /**
   * `McpProtocolDowngradeReason` keeps four `stdio_*` variants this Worker can
   * never produce (no process to probe). The marker in `src/protocol.ts` says
   * they survive as the OPERATOR STATUS vocabulary shared with the Rust host,
   * and these two assertions are what stop that claim from rotting:
   *
   *  1. nothing here fabricates one — the single producer answers only `http_*`;
   *  2. nothing here swallows one — `statusOf` reports it verbatim.
   */
  const STDIO_REASONS = [
    "stdio_method_not_found",
    "stdio_unrecognized_error",
    "stdio_probe_timeout",
    "stdio_probe_process_exit",
  ] as const;

  it("never fabricates a stdio reason from an HTTP probe, on ANY status", () => {
    const produced = new Set<string>();
    for (let status = 100; status < 600; status += 1) {
      const reason = httpLegacyDowngradeReason(status, undefined);
      if (reason !== undefined) produced.add(reason);
    }
    // The whole producible vocabulary of this Worker, exhaustively.
    expect([...produced].sort()).toEqual([
      "http_400_unrecognized_response",
      "http_404_unrecognized_response",
      "http_405_unrecognized_response",
    ]);
    for (const reason of STDIO_REASONS) expect(produced.has(reason)).toBe(false);
  });

  it("reports a stdio reason VERBATIM on the status surface if a record carries one", () => {
    for (const reason of STDIO_REASONS) {
      const state: McpSessionState = {
        ...newSessionState(DEFAULT_RECONNECT_POLICY),
        connected: true,
        negotiation: {
          mode: "legacy",
          version: MCP_LEGACY_PROTOCOL_VERSION,
          downgradeReason: reason,
        },
      };
      // Not normalised, not dropped, not mapped onto an `http_*` neighbour: an
      // operator tool reading this Worker and the Rust host sees one vocabulary.
      expect(statusOf("local", state).protocolDowngradeReason).toBe(reason);
    }
  });
});
