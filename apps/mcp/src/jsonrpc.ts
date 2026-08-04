/**
 * Strict JSON-RPC 2.0 request / response / error codec.
 *
 * Clean-room port of `crates/ferrogate-mcp/src/jsonrpc.rs` (payload
 * construction + response parsing) and the envelope types in
 * `crates/ferrogate-gateway/src/server/mcp_rpc.rs` (`McpJsonRpcRequest`,
 * `McpJsonRpcResponse`, `McpJsonRpcError`).
 *
 * Serialization parity notes:
 *  - `McpJsonRpcResponse` uses `skip_serializing_if = Option::is_none` for
 *    `id` / `result` / `error`, so absent members are OMITTED, never `null`.
 *    {@link renderJsonRpcResponse} reproduces that.
 *  - Rust's `McpJsonRpcRequest` declared `jsonrpc: Option<String>` and never
 *    checked it, so a body missing the `jsonrpc` member was accepted. This
 *    port validates it per spec and answers `-32600 Invalid Request` instead.
 *    That is a deliberate tightening, not a dropped behavior:
 *    {@link mcpIngressRequestSchema} keeps every other lenience of the Rust
 *    shape (`id` optional ⇒ notification, `params` defaulted).
 */
import { z } from "zod";

import type { JsonValue } from "@ferrogate/core";

/** The only `jsonrpc` member value JSON-RPC 2.0 permits. */
export const JSONRPC_VERSION = "2.0" as const;

/**
 * Error codes. `-32768..=-32000` is reserved by the spec; `-32099..=-32000` is
 * the implementation-defined server-error band FerroGate's application codes
 * and the modern-candidate protocol codes both live in.
 */
export const JsonRpcErrorCode = {
  /** Invalid JSON was received by the server. */
  ParseError: -32700,
  /** The JSON sent is not a valid Request object. */
  InvalidRequest: -32600,
  /** The method does not exist / is not available. */
  MethodNotFound: -32601,
  /** Invalid method parameter(s). */
  InvalidParams: -32602,
  /** Internal JSON-RPC error. */
  InternalError: -32603,

  // --- FerroGate application codes (`mcp_rpc.rs`) ---------------------------
  /** Generic application failure (`mcp_error_code` default arm). */
  ApplicationError: -32000,
  /** Governed chokepoint denied the tool (`tool_denied`). */
  ToolDenied: -32001,
  /** Upstream MCP server is unavailable (`mcp_server_unavailable`). */
  McpServerUnavailable: -32002,
  /** Asset request from a key with no tenant attribution. */
  AssetTenantRequired: -32003,
  /** Asset above the gateway's in-memory inline budget. */
  AssetTooLarge: -32004,
  /** Read shed by the gateway's aggregate buffering budget. */
  GatewayBufferBudgetExhausted: -32005,
  /**
   * The flat `{server}-{tool}` name is claimed by more than one multiplexed
   * upstream (#687). Distinct from `ToolDenied` because it is not a policy
   * refusal — the caller is entitled to the tool and only has to say which
   * upstream it meant, and the message names every claimant.
   */
  McpToolAmbiguous: -32006,
  /** Asset egress monthly byte budget refused the read before storage access. */
  AssetEgressQuotaExceeded: -32007,
  /** Asset egress per-minute download cap refused the read. */
  AssetDownloadRateLimitExceeded: -32008,
  /** Shared asset egress counter backend could not make an admission decision. */
  AssetEgressCounterUnavailable: -32009,

  // --- Modern 2026-07-28 candidate protocol codes (`mcp_ingress.rs`) --------
  /** Routing/protocol header disagrees with the body. */
  ModernHeaderMismatch: -32020,
  /** A required client capability was not declared. */
  ModernMissingClientCapability: -32021,
  /** The requested protocol revision is not supported. */
  ModernUnsupportedVersion: -32022,
} as const;

export type JsonRpcErrorCodeValue = (typeof JsonRpcErrorCode)[keyof typeof JsonRpcErrorCode];

/**
 * Maps the governed chokepoint's string error code onto its JSON-RPC code.
 * Port of `mcp_rpc::mcp_error_code`.
 */
export function mcpErrorCode(code: string): number {
  switch (code) {
    case "tool_denied":
      return JsonRpcErrorCode.ToolDenied;
    case "tool_not_found":
      return JsonRpcErrorCode.InvalidParams;
    case "mcp_server_unavailable":
      return JsonRpcErrorCode.McpServerUnavailable;
    case "mcp_tool_ambiguous":
      return JsonRpcErrorCode.McpToolAmbiguous;
    case "asset_egress_quota_exceeded":
      return JsonRpcErrorCode.AssetEgressQuotaExceeded;
    case "asset_download_rate_limit_exceeded":
      return JsonRpcErrorCode.AssetDownloadRateLimitExceeded;
    case "governance_counter_unavailable":
      return JsonRpcErrorCode.AssetEgressCounterUnavailable;
    default:
      return JsonRpcErrorCode.ApplicationError;
  }
}

/**
 * A JSON-RPC id. The spec allows String, Number, or Null; Null is reserved for
 * responses to requests whose id could not be determined and SHOULD NOT be used
 * by clients. Fractional numbers are permitted by the grammar but discouraged.
 */
export const jsonRpcIdSchema = z.union([z.string(), z.number(), z.null()]);
export type JsonRpcId = z.infer<typeof jsonRpcIdSchema>;

/** Structured params: the spec permits only an Array or an Object. */
export const jsonRpcParamsSchema = z.union([
  z.array(z.unknown()),
  z.record(z.string(), z.unknown()),
]);

/** Strict JSON-RPC 2.0 Request object (an absent `id` makes it a Notification). */
export const jsonRpcRequestSchema = z.object({
  jsonrpc: z.literal(JSONRPC_VERSION),
  method: z.string(),
  params: jsonRpcParamsSchema.optional(),
  id: jsonRpcIdSchema.optional(),
});
export type JsonRpcRequest = z.infer<typeof jsonRpcRequestSchema>;

/** JSON-RPC 2.0 Error object. */
export const jsonRpcErrorObjectSchema = z.object({
  code: z.number().int(),
  message: z.string(),
  data: z.unknown().optional(),
});
export type JsonRpcErrorObject = z.infer<typeof jsonRpcErrorObjectSchema>;

/** JSON-RPC 2.0 Response object — exactly one of `result` / `error`. */
export const jsonRpcResponseSchema = z
  .object({
    jsonrpc: z.literal(JSONRPC_VERSION),
    id: jsonRpcIdSchema,
    result: z.unknown().optional(),
    error: jsonRpcErrorObjectSchema.optional(),
  })
  .refine((value) => "result" in value !== (value.error !== undefined), {
    message: "a JSON-RPC response must carry exactly one of result or error",
  });

/**
 * The gateway ingress shape: identical to {@link jsonRpcRequestSchema} but with
 * `params` defaulted to `{}` and typed as arbitrary JSON, mirroring
 * `McpJsonRpcRequest`'s `#[serde(default)] params: Value`. The MCP sub-handlers
 * index into `params` with `.get(...)`, which is a no-op on a non-object, so a
 * scalar `params` reaches the handler's own "params.x is required" `-32602`
 * rather than being rejected by the envelope.
 */
export const mcpIngressRequestSchema = z.object({
  jsonrpc: z.literal(JSONRPC_VERSION),
  method: z.string(),
  params: z.unknown().default({}),
  id: jsonRpcIdSchema.optional(),
});
export interface McpIngressRequest {
  jsonrpc: typeof JSONRPC_VERSION;
  method: string;
  params: unknown;
  id?: JsonRpcId;
}

/** A JSON-RPC response value in the FerroGate wire shape. */
export interface JsonRpcResponse {
  jsonrpc: typeof JSONRPC_VERSION;
  /** Omitted (never `null`) when the originating request carried no id. */
  id?: JsonRpcId;
  result?: JsonValue;
  error?: { code: number; message: string; data?: JsonValue };
}

/** Build a success response. Port of `mcp_rpc::result`. */
export function jsonRpcResult(id: JsonRpcId | undefined, result: JsonValue): JsonRpcResponse {
  const response: JsonRpcResponse = { jsonrpc: JSONRPC_VERSION, result };
  if (id !== undefined) response.id = id;
  return response;
}

/** Build an error response. Port of `mcp_rpc::error` / `error_with_data`. */
export function jsonRpcError(
  id: JsonRpcId | undefined,
  code: number,
  message: string,
  data?: JsonValue,
): JsonRpcResponse {
  const error: { code: number; message: string; data?: JsonValue } = { code, message };
  if (data !== undefined) error.data = data;
  const response: JsonRpcResponse = { jsonrpc: JSONRPC_VERSION, error };
  if (id !== undefined) response.id = id;
  return response;
}

/**
 * Serialize a response with serde's `skip_serializing_if = Option::is_none`
 * semantics: absent members are omitted, not emitted as `null`. (`JSON.stringify`
 * already drops `undefined` values, so this is mostly a documented guarantee —
 * it also strips an explicitly-`undefined` `data`.)
 */
export function renderJsonRpcResponse(response: JsonRpcResponse): Record<string, JsonValue> {
  const rendered: Record<string, JsonValue> = { jsonrpc: response.jsonrpc };
  if (response.id !== undefined) rendered["id"] = response.id;
  if (response.result !== undefined) rendered["result"] = response.result;
  if (response.error !== undefined) {
    const error: Record<string, JsonValue> = {
      code: response.error.code,
      message: response.error.message,
    };
    if (response.error.data !== undefined) error["data"] = response.error.data;
    rendered["error"] = error;
  }
  return rendered;
}

/** True when the request is a Notification (no `id` member ⇒ no reply). */
export function isNotification(request: { id?: JsonRpcId }): boolean {
  return request.id === undefined;
}

export type DecodedRequest =
  | { ok: true; request: McpIngressRequest }
  | { ok: false; response: JsonRpcResponse };

/**
 * Decode a raw request body into an {@link McpIngressRequest}, or into the
 * JSON-RPC error response the caller must return.
 *
 * - unparseable JSON            → `-32700 parse error` with a `null`-less id
 *   (the Rust handler returns `mcp_rpc::error(None, -32700, ...)` at HTTP 200)
 * - parseable but not a Request → `-32600 Invalid Request`
 *
 * A best-effort id is recovered from a structurally-invalid-but-parseable body
 * so a client can still correlate the failure; the spec permits `null` there
 * but correlating is strictly more useful and never wrong.
 */
export function decodeMcpRequest(body: string): DecodedRequest {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return {
      ok: false,
      response: jsonRpcError(undefined, JsonRpcErrorCode.ParseError, `parse error: ${detail}`),
    };
  }
  return decodeMcpRequestValue(value);
}

/** {@link decodeMcpRequest} for an already-parsed JSON value. */
export function decodeMcpRequestValue(value: unknown): DecodedRequest {
  const parsed = mcpIngressRequestSchema.safeParse(value);
  if (!parsed.success) {
    return {
      ok: false,
      response: jsonRpcError(
        recoverId(value),
        JsonRpcErrorCode.InvalidRequest,
        `Invalid Request: ${formatIssues(parsed.error)}`,
      ),
    };
  }
  const request: McpIngressRequest = {
    jsonrpc: JSONRPC_VERSION,
    method: parsed.data.method,
    params: parsed.data.params,
  };
  if (parsed.data.id !== undefined) request.id = parsed.data.id;
  return { ok: true, request };
}

/** Strict spec decode (rejects non-structured `params`). Used by the codec tests. */
export function decodeStrictRequest(
  value: unknown,
): { ok: true; request: JsonRpcRequest } | { ok: false; response: JsonRpcResponse } {
  const parsed = jsonRpcRequestSchema.safeParse(value);
  if (!parsed.success) {
    return {
      ok: false,
      response: jsonRpcError(
        recoverId(value),
        JsonRpcErrorCode.InvalidRequest,
        `Invalid Request: ${formatIssues(parsed.error)}`,
      ),
    };
  }
  return { ok: true, request: parsed.data };
}

function recoverId(value: unknown): JsonRpcId | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const id = (value as Record<string, unknown>)["id"];
  const parsed = jsonRpcIdSchema.safeParse(id);
  return parsed.success ? parsed.data : undefined;
}

function formatIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.join(".");
      return path.length > 0 ? `${path}: ${issue.message}` : issue.message;
    })
    .join("; ");
}

// ---------------------------------------------------------------------------
// tools/list + tools/call payload construction and result parsing
// (port of `ferrogate-mcp/src/jsonrpc.rs`)
// ---------------------------------------------------------------------------

/** MCP `Tool` as returned by an upstream `tools/list`. */
export const mcpToolSchema = z.object({
  name: z.string(),
  description: z.string().nullish(),
  inputSchema: z.unknown(),
});

/** MCP `ListToolsResult`. */
export const listToolsResultSchema = z.object({ tools: z.array(mcpToolSchema) });

/** MCP `CallToolResult` — only `isError` is load-bearing for the host. */
export const callToolResultSchema = z.object({
  content: z.unknown().optional(),
  isError: z.boolean().optional(),
});

/** The canonical `ToolDef` shape (`@ferrogate/core`, snake_case wire keys). */
export interface ParsedToolDef {
  name: string;
  description?: string;
  input_schema: JsonValue;
}

/** Result of an upstream `tools/call`. Port of `McpToolExecutionResult`. */
export interface McpToolExecutionResult {
  /** The raw JSON-RPC `result` value, preserved byte-for-byte in shape. */
  content: JsonValue;
  isError: boolean;
}

/**
 * The Multi Round-Trip Requests interim discriminator (SEP-2322, final
 * `2026-07-28`). A server that needs more information — what `roots/list`,
 * `sampling/createMessage` and `elicitation/create` used to ask for over a
 * held-open stream — answers `resultType: "input_required"` carrying
 * `inputRequests`, and expects the client to RETRY the original request with
 * `inputResponses`.
 */
export const INPUT_REQUIRED_RESULT_TYPE = "input_required";

/**
 * Refuse an MRTR interim result.
 *
 * FerroGate implements no client half of MRTR: it has nothing to put in
 * `inputResponses` and no retry loop to put it in. The ONLY safe reading of an
 * `input_required` envelope is therefore "this upstream cannot be served",
 * because the alternative is silently handing an agent a protocol control
 * message shaped like tool output — an `inputRequests` array where the model
 * expected `content`. That is a prompt-injection-adjacent failure, not a
 * cosmetic one.
 *
 * Deliberately keyed on the discriminator being EXACTLY `"input_required"`, not
 * on it being absent-or-complete: changelog major change 8 requires a client to
 * treat a result from an earlier-protocol server that OMITS `resultType` as
 * `"complete"`, and that is the dual-era fallback for every `2025-06-18` and
 * `2025-11-25` upstream FerroGate still talks to.
 */
function ensureNotInputRequired(result: unknown, method: string): void {
  if (typeof result !== "object" || result === null || Array.isArray(result)) return;
  if ((result as Record<string, unknown>)["resultType"] !== INPUT_REQUIRED_RESULT_TYPE) return;
  throw new Error(
    `MCP ${method} returned an ${INPUT_REQUIRED_RESULT_TYPE} multi-round-trip result; FerroGate does not implement the client half of MRTR (SEP-2322) and will not present an interim result as output`,
  );
}

/** Raise on a JSON-RPC error member. Port of `ensure_no_jsonrpc_error`. */
export function ensureNoJsonRpcError(response: unknown): void {
  if (typeof response === "object" && response !== null && "error" in response) {
    const error = (response as Record<string, unknown>)["error"];
    if (error !== undefined) {
      throw new Error(`MCP JSON-RPC error: ${JSON.stringify(error)}`);
    }
  }
}

/** Parse an upstream `tools/list` response into canonical `ToolDef`s. */
export function parseToolsList(response: unknown): ParsedToolDef[] {
  ensureNoJsonRpcError(response);
  const raw =
    typeof response === "object" && response !== null
      ? (response as Record<string, unknown>)["result"]
      : undefined;
  if (raw === undefined) throw new Error("MCP tools/list response missing result");
  ensureNotInputRequired(raw, "tools/list");
  const parsed = listToolsResultSchema.safeParse(raw);
  if (!parsed.success)
    throw new Error(`invalid MCP tools/list result: ${formatIssues(parsed.error)}`);
  return parsed.data.tools.map((tool) => {
    const def: ParsedToolDef = {
      name: tool.name,
      input_schema: (tool.inputSchema ?? {}) as JsonValue,
    };
    if (typeof tool.description === "string") def.description = tool.description;
    return def;
  });
}

/** Parse an upstream `tools/call` response. Port of `parse_call_result`. */
export function parseCallResult(response: unknown): McpToolExecutionResult {
  ensureNoJsonRpcError(response);
  const raw =
    typeof response === "object" && response !== null
      ? ((response as Record<string, unknown>)["result"] ?? null)
      : null;
  ensureNotInputRequired(raw, "tools/call");
  const parsed = callToolResultSchema.safeParse(raw ?? {});
  if (!parsed.success) {
    throw new Error(`invalid MCP tools/call result: ${formatIssues(parsed.error)}`);
  }
  return { content: (raw ?? null) as JsonValue, isError: parsed.data.isError ?? false };
}

/**
 * Build `tools/call` params. Port of `call_tool_params`: arguments must be a
 * JSON object (or absent), never a scalar or an array.
 */
export function callToolParams(name: string, args: JsonValue): Record<string, JsonValue> {
  if (args === null || args === undefined) return { name };
  if (typeof args !== "object" || Array.isArray(args)) {
    throw new Error("MCP tool arguments must be a JSON object");
  }
  return { name, arguments: args };
}
