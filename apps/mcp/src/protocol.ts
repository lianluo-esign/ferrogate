/**
 * MCP protocol revisions, version negotiation, and Streamable-HTTP routing
 * headers.
 *
 * Clean-room port of `crates/ferrogate-mcp/src/protocol.rs` plus the dual-era
 * ingress classifier in `crates/ferrogate-gateway/src/server/mcp_ingress.rs`.
 *
 * Protocol truth is pinned to official modelcontextprotocol commit
 * `71e306956a4959c9655e5036be215d41986596e6` rather than the obsolete
 * `2026-07-28-RC` tag — a candidate contract under validation, not a
 * final-conformance claim. Legacy requests remain `initialize`-based; modern
 * requests carry every piece of identity/capability metadata on the request
 * being validated. Nothing here caches client metadata: era selection is a
 * pure function of one request.
 */
import type { JsonValue } from "@ferrogate/core";

import { JsonRpcErrorCode, type McpIngressRequest } from "./jsonrpc.js";

/**
 * Modern MCP candidate revision accepted by FerroGate's stateless ingress. Adds
 * the `Mcp-Method` / `Mcp-Name` Streamable-HTTP routing headers; it is never
 * negotiated through `initialize`.
 */
export const MCP_PROTOCOL_VERSION = "2026-07-28";
/**
 * Direct legacy predecessor — the newest revision an `initialize` handshake may
 * negotiate.
 */
export const MCP_LEGACY_PROTOCOL_VERSION = "2025-11-25";
/** Older stable revision retained for existing FerroGate clients. */
export const MCP_PROTOCOL_VERSION_FALLBACK = "2025-06-18";
/** Protocol versions FerroGate can speak, newest first. */
export const SUPPORTED_MCP_PROTOCOL_VERSIONS = [
  MCP_PROTOCOL_VERSION,
  MCP_LEGACY_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_FALLBACK,
] as const;

/** Streamable-HTTP header carrying the per-request protocol revision. */
export const MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version";
/**
 * Streamable-HTTP routing header carrying the JSON-RPC method. Lets
 * gateways/load-balancers route, scope-gate, rate-limit, and meter per
 * operation without parsing the request body.
 */
export const MCP_METHOD_HEADER = "mcp-method";
/**
 * Streamable-HTTP routing header carrying the operation target name — for
 * `tools/call` this is the tool name.
 */
export const MCP_NAME_HEADER = "mcp-name";

/**
 * Validated original-bearer passthrough header (`McpAuthType.OriginalBearer`).
 * Mirrors `MCP_ORIGINAL_BEARER_HEADER` in `server/local.rs`.
 */
export const MCP_ORIGINAL_BEARER_HEADER = "x-ferrogate-mcp-bearer";

/**
 * The ONE validated correlation header the A2A / MCP / asset surfaces share
 * (#522). Threading it end to end is the load-bearing parity contract for this
 * app — see {@link declaredAgentRunId}.
 */
export const AGENT_RUN_ID_HEADER = "x-ferrogate-agent-run-id";

const PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO_META = "io.modelcontextprotocol/clientInfo";
const BASE64_SENTINEL_PREFIX = "=?base64?";
const BASE64_SENTINEL_SUFFIX = "?=";

/** Client identity stamped into modern `_meta` on outbound requests. */
export const FERROGATE_CLIENT_INFO = { name: "ferrogate", version: "1.0.0" } as const;

/** Private-cache hint on candidate cacheable modern results (`mcp_rpc.rs`). */
export const PRIVATE_CACHE_TTL_MS = 5_000;

/** The protocol era selected for one upstream process or HTTP endpoint. */
export type McpProtocolMode = "modern" | "legacy";

/** Bounded evidence explaining why a modern probe entered legacy mode. */
export type McpProtocolDowngradeReason =
  | "http_400_unrecognized_response"
  | "http_404_unrecognized_response"
  | "http_405_unrecognized_response"
  // PORT-TODO(inventory-edge-control §MCP): the `stdio_*` downgrade reasons are
  // unreachable on Workers — see `ports.ts` for the stdio transport note.
  | "stdio_method_not_found"
  | "stdio_unrecognized_error"
  | "stdio_probe_timeout"
  | "stdio_probe_process_exit";

export interface McpNegotiatedProtocol {
  mode: McpProtocolMode;
  version: string;
  downgradeReason?: McpProtocolDowngradeReason;
}

/** Returns true when `version` is a protocol revision FerroGate can speak. */
export function isSupportedProtocolVersion(version: string): boolean {
  return (SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]).includes(version);
}

/**
 * Legacy server-side negotiation for an `initialize` request.
 *
 * `2026-07-28` removed the initialize handshake, so it must never be echoed by
 * this function. Exact supported legacy revisions are honoured; omitted,
 * unknown, or modern values choose the direct legacy predecessor.
 */
export function negotiateProtocolVersion(requested: string | undefined): string {
  if (requested === MCP_LEGACY_PROTOCOL_VERSION) return MCP_LEGACY_PROTOCOL_VERSION;
  if (requested === MCP_PROTOCOL_VERSION_FALLBACK) return MCP_PROTOCOL_VERSION_FALLBACK;
  return MCP_LEGACY_PROTOCOL_VERSION;
}

/**
 * Strictly adopt a legacy revision returned by an upstream `initialize`.
 * Modern, omitted, and unknown versions are not valid initialize results.
 */
export function resolveLegacyProtocolVersion(
  serverVersion: string | undefined,
): string | undefined {
  if (serverVersion === MCP_LEGACY_PROTOCOL_VERSION) return MCP_LEGACY_PROTOCOL_VERSION;
  if (serverVersion === MCP_PROTOCOL_VERSION_FALLBACK) return MCP_PROTOCOL_VERSION_FALLBACK;
  return undefined;
}

/** The `_meta` block every modern outbound request carries. */
export function modernRequestMeta(): Record<string, JsonValue> {
  return {
    [PROTOCOL_VERSION_META]: MCP_PROTOCOL_VERSION,
    [CLIENT_INFO_META]: { ...FERROGATE_CLIENT_INFO },
    [CLIENT_CAPABILITIES_META]: {},
  };
}

/** Decorate outbound modern request params with `_meta`. Params must be an object. */
export function modernRequestParams(params: JsonValue): Record<string, JsonValue> {
  if (!isJsonObject(params)) {
    throw new TypeError("modern MCP request params must be an object");
  }
  return { ...params, _meta: modernRequestMeta() };
}

/** Params for a modern `server/discover` probe. */
export function modernDiscoverParams(): Record<string, JsonValue> {
  return { _meta: modernRequestMeta() };
}

/** True when a `server/discover` result advertises {@link MCP_PROTOCOL_VERSION}. */
export function discoverSupportsCurrentVersion(response: JsonValue): boolean {
  if (!isJsonObject(response)) return false;
  if (response["jsonrpc"] !== "2.0") return false;
  const id = response["id"];
  if (typeof id !== "string" && typeof id !== "number") return false;
  const result = response["result"];
  if (!isJsonObject(result)) return false;
  if (result["resultType"] !== "complete") return false;
  if (!isJsonObject(result["capabilities"])) return false;
  const versions = result["supportedVersions"];
  return Array.isArray(versions) && versions.some((version) => version === MCP_PROTOCOL_VERSION);
}

/** The JSON-RPC error code of a well-formed error response, if any. */
export function jsonRpcErrorCode(response: JsonValue): number | undefined {
  if (!isJsonObject(response) || response["jsonrpc"] !== "2.0") return undefined;
  const error = response["error"];
  if (!isJsonObject(error)) return undefined;
  if (typeof error["message"] !== "string") return undefined;
  const code = error["code"];
  return typeof code === "number" ? code : undefined;
}

/** Errors that prove modern protocol semantics independent of transport. */
export function isRecognizedModernProtocolError(response: JsonValue): boolean {
  const code = jsonRpcErrorCode(response);
  return (
    code === JsonRpcErrorCode.ModernHeaderMismatch ||
    code === JsonRpcErrorCode.ModernMissingClientCapability ||
    code === JsonRpcErrorCode.ModernUnsupportedVersion
  );
}

/**
 * Streamable HTTP uses specifically a structured HTTP 404 / JSON-RPC `-32601`
 * pair to distinguish a modern endpoint from a legacy endpoint's unstructured
 * HTTP error. The JSON-RPC code alone is not enough: on 400/405 it remains a
 * legacy downgrade signal.
 */
function isRecognizedHttpModernError(status: number, response: JsonValue): boolean {
  return (
    isRecognizedModernProtocolError(response) ||
    (status === 404 && jsonRpcErrorCode(response) === JsonRpcErrorCode.MethodNotFound)
  );
}

/** Which HTTP failures of a modern probe mean "this endpoint is legacy". */
export function httpLegacyDowngradeReason(
  status: number,
  response: JsonValue | undefined,
): McpProtocolDowngradeReason | undefined {
  if (response !== undefined && isRecognizedHttpModernError(status, response)) return undefined;
  if (status === 400) return "http_400_unrecognized_response";
  if (status === 404) return "http_404_unrecognized_response";
  if (status === 405) return "http_405_unrecognized_response";
  return undefined;
}

/**
 * Encode an outbound mirrored header value using the candidate's sentinel
 * rules. Values that are not unambiguous, trimmed, visible ASCII are Base64.
 */
export function encodeMcpHeaderValue(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const ambiguous =
    value.startsWith(BASE64_SENTINEL_PREFIX) && value.endsWith(BASE64_SENTINEL_SUFFIX);
  const hasUnsafeByte = bytes.some((byte) => byte !== 0x09 && (byte < 0x20 || byte > 0x7e));
  const first = bytes[0];
  const last = bytes[bytes.length - 1];
  const hasEdgeWhitespace = isAsciiWhitespace(first) || isAsciiWhitespace(last);
  if (ambiguous || hasUnsafeByte || hasEdgeWhitespace) {
    return `${BASE64_SENTINEL_PREFIX}${base64Encode(bytes)}${BASE64_SENTINEL_SUFFIX}`;
  }
  return value;
}

/** Rust `u8::is_ascii_whitespace`: space, tab, LF, FF, CR (deliberately not VT). */
function isAsciiWhitespace(byte: number | undefined): boolean {
  return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Decode(encoded: string): Uint8Array | undefined {
  try {
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return undefined;
  }
}

/**
 * Mismatch between a Streamable-HTTP routing header and the JSON-RPC body it
 * claims to describe. The ingress fails such a request closed so a caller
 * cannot be scope-gated / rate-limited / metered as one operation while the
 * body executes another.
 */
export interface RoutingHeaderMismatch {
  header: "Mcp-Method" | "Mcp-Name";
  headerValue: string;
  bodyValue: string;
}

/** Human-readable rendering matching the Rust `Display` impl. */
export function routingHeaderMismatchMessage(mismatch: RoutingHeaderMismatch): string {
  return `${mismatch.header} header ${JSON.stringify(mismatch.headerValue)} does not match request body value ${JSON.stringify(mismatch.bodyValue)}`;
}

/**
 * Verify the optional `Mcp-Method` / `Mcp-Name` routing headers against the
 * parsed JSON-RPC body. This low-level verifier accepts absent headers for
 * legacy callers; the modern ingress layer requires them. When present they
 * MUST agree with the body. `bodyName` is the tool/prompt name or resource URI
 * (`undefined` for methods that carry no name).
 */
export function verifyRoutingHeaders(
  headerMethod: string | undefined,
  headerName: string | undefined,
  bodyMethod: string,
  bodyName: string | undefined,
): RoutingHeaderMismatch | undefined {
  if (headerMethod !== undefined && headerMethod !== bodyMethod) {
    return { header: "Mcp-Method", headerValue: headerMethod, bodyValue: bodyMethod };
  }
  if (headerName !== undefined) {
    const body = bodyName ?? "";
    if (headerName !== body) {
      return { header: "Mcp-Name", headerValue: headerName, bodyValue: body };
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Dual-era ingress classification (port of `server/mcp_ingress.rs`)
// ---------------------------------------------------------------------------

export type McpIngressMode = "legacy" | "modern";

export interface ValidatedMcpIngress {
  mode: McpIngressMode;
  /** Bounded Prometheus label — never client-declared metadata. */
  metricMethod: string;
  /** Bounded Prometheus label — never client-declared metadata. */
  metricName: string;
}

export type McpIngressValidationError =
  | { kind: "invalid_params"; detail: string }
  | { kind: "header_mismatch"; detail: string }
  | { kind: "unsupported_version"; requested: string };

export function ingressErrorCode(error: McpIngressValidationError): number {
  switch (error.kind) {
    case "invalid_params":
      return JsonRpcErrorCode.InvalidParams;
    case "header_mismatch":
      return JsonRpcErrorCode.ModernHeaderMismatch;
    case "unsupported_version":
      return JsonRpcErrorCode.ModernUnsupportedVersion;
  }
}

export function ingressErrorMessage(error: McpIngressValidationError): string {
  switch (error.kind) {
    case "invalid_params":
      return `Invalid params: ${error.detail}`;
    case "header_mismatch":
      return `Header mismatch: ${error.detail}`;
    case "unsupported_version":
      return "Unsupported protocol version";
  }
}

export function ingressErrorData(error: McpIngressValidationError): JsonValue | undefined {
  if (error.kind !== "unsupported_version") return undefined;
  return {
    requested: error.requested,
    supported: [...SUPPORTED_MCP_PROTOCOL_VERSIONS],
  };
}

/** Display rendering used in the audit evidence string (Rust `Display`). */
export function ingressErrorDisplay(error: McpIngressValidationError): string {
  if (error.kind === "unsupported_version") {
    return `Unsupported protocol version requested: ${error.requested}`;
  }
  return ingressErrorMessage(error);
}

/**
 * Select the protocol era from this request alone. The modern contract is
 * stateless, so no previous initialize/discover request participates.
 */
export function ingressMode(headers: Headers, rpc: McpIngressRequest): McpIngressMode {
  if (rpc.method === "initialize") {
    // The pinned dual-era contract selects legacy semantics from the opening
    // method itself. Modern-looking metadata cannot turn an `initialize`
    // request into a modern request.
    return "legacy";
  }
  if (rpc.method === "server/discover" || bodyUsesModernMetadata(rpc)) return "modern";
  const protocolHeader = headers.get(MCP_PROTOCOL_VERSION_HEADER);
  if (protocolHeader === null) return "legacy";
  if (
    protocolHeader === MCP_LEGACY_PROTOCOL_VERSION ||
    protocolHeader === MCP_PROTOCOL_VERSION_FALLBACK
  ) {
    return "legacy";
  }
  return "modern";
}

export type IngressValidation =
  | { ok: true; ingress: ValidatedMcpIngress }
  | { ok: false; error: McpIngressValidationError };

export function validateIngress(headers: Headers, rpc: McpIngressRequest): IngressValidation {
  const mode = ingressMode(headers, rpc);

  const rawMethodHeader = optionalHeader(headers, MCP_METHOD_HEADER);
  if (!rawMethodHeader.ok) return rawMethodHeader;
  const headerMethod = rawMethodHeader.value;

  const rawNameHeader = optionalHeader(headers, MCP_NAME_HEADER);
  if (!rawNameHeader.ok) return rawNameHeader;
  let headerName: string | undefined;
  if (rawNameHeader.value !== undefined) {
    const decoded = decodeMcpName(rawNameHeader.value);
    if (!decoded.ok) return decoded;
    headerName = decoded.value;
  }

  const name = bodyName(rpc);

  if (mode === "modern") {
    const headerProtocol = headerMethodRequired(
      optionalHeader(headers, MCP_PROTOCOL_VERSION_HEADER),
      "MCP-Protocol-Version",
    );
    if (!headerProtocol.ok) return headerProtocol;

    const meta = isJsonObject(rpc.params) ? rpc.params["_meta"] : undefined;
    if (!isJsonObject(meta)) {
      return invalidParams("required params._meta object is missing or malformed");
    }
    const bodyProtocol = meta[PROTOCOL_VERSION_META];
    if (typeof bodyProtocol !== "string") {
      return invalidParams(
        `required params._meta["${PROTOCOL_VERSION_META}"] string is missing or malformed`,
      );
    }
    if (!isJsonObject(meta[CLIENT_CAPABILITIES_META])) {
      return invalidParams(
        `required params._meta["${CLIENT_CAPABILITIES_META}"] object is missing or malformed`,
      );
    }
    const clientInfo = meta[CLIENT_INFO_META];
    if (clientInfo !== undefined) {
      const valid =
        isJsonObject(clientInfo) &&
        typeof clientInfo["name"] === "string" &&
        typeof clientInfo["version"] === "string";
      if (!valid) {
        return invalidParams(
          `optional params._meta["${CLIENT_INFO_META}"] must be an Implementation object with string name and version when present`,
        );
      }
    }
    if (headerProtocol.value !== bodyProtocol) {
      return mismatch(
        `MCP-Protocol-Version header value ${JSON.stringify(headerProtocol.value)} does not match body value ${JSON.stringify(bodyProtocol)}`,
      );
    }
    if (bodyProtocol !== MCP_PROTOCOL_VERSION) {
      return { ok: false, error: { kind: "unsupported_version", requested: bodyProtocol } };
    }
    if (headerMethod === undefined) {
      return mismatch("required Mcp-Method header is missing or malformed");
    }
    if (methodRequiresName(rpc.method) && headerName === undefined) {
      return mismatch(`required Mcp-Name header for ${rpc.method} is missing or malformed`);
    }
    const conflict = verifyRoutingHeaders(headerMethod, headerName, rpc.method, name);
    if (conflict) return mismatch(routingHeaderMismatchMessage(conflict));
  } else {
    // Preserve the pre-candidate compatibility contract: routing headers are
    // optional for legacy requests, but an intermediary/body split-brain is
    // still rejected when either header is present.
    const conflict = verifyRoutingHeaders(headerMethod, headerName, rpc.method, name);
    if (conflict) return mismatch(routingHeaderMismatchMessage(conflict));
  }

  return {
    ok: true,
    ingress: {
      mode,
      metricMethod: headerMethod ?? rpc.method,
      metricName: headerName ?? name ?? "",
    },
  };
}

/** Methods the modern candidate revision actually implements here. */
export function isSupportedModernMethod(method: string): boolean {
  return (
    method === "server/discover" ||
    method === "resources/list" ||
    method === "resources/read" ||
    method === "tools/list" ||
    method === "tools/call"
  );
}

function bodyUsesModernMetadata(rpc: McpIngressRequest): boolean {
  const meta = isJsonObject(rpc.params) ? rpc.params["_meta"] : undefined;
  if (!isJsonObject(meta)) return false;
  return (
    PROTOCOL_VERSION_META in meta || CLIENT_CAPABILITIES_META in meta || CLIENT_INFO_META in meta
  );
}

/** The operation target carried in the body, per method. */
export function bodyName(rpc: McpIngressRequest): string | undefined {
  const params = isJsonObject(rpc.params) ? rpc.params : undefined;
  if (rpc.method === "tools/call" || rpc.method === "prompts/get") {
    const value = params?.["name"];
    return typeof value === "string" ? value : undefined;
  }
  if (rpc.method === "resources/read") {
    const value = params?.["uri"];
    return typeof value === "string" ? value : undefined;
  }
  return undefined;
}

function methodRequiresName(method: string): boolean {
  return method === "tools/call" || method === "resources/read" || method === "prompts/get";
}

type HeaderLookup =
  | { ok: true; value: string | undefined }
  | { ok: false; error: McpIngressValidationError };

/**
 * `Headers.get` joins repeated values with `", "`. The Rust verifier refuses an
 * ambiguous repeated routing header outright, so detect the join and refuse too
 * — a split-brain between two intermediaries must never silently pick one.
 */
function optionalHeader(headers: Headers, name: string): HeaderLookup {
  const value = headers.get(name);
  if (value === null) return { ok: true, value: undefined };
  if (value.includes(",")) {
    return mismatch(`${name} header occurs more than once and is ambiguous`);
  }
  return { ok: true, value };
}

function headerMethodRequired(
  lookup: HeaderLookup,
  displayName: string,
): { ok: true; value: string } | { ok: false; error: McpIngressValidationError } {
  if (!lookup.ok) return lookup;
  if (lookup.value === undefined) {
    return mismatch(`required ${displayName} header is missing or malformed`);
  }
  return { ok: true, value: lookup.value };
}

/** Decode the Base64 sentinel wrapping produced by {@link encodeMcpHeaderValue}. */
export function decodeMcpName(
  value: string,
): { ok: true; value: string } | { ok: false; error: McpIngressValidationError } {
  if (!value.startsWith(BASE64_SENTINEL_PREFIX) || !value.endsWith(BASE64_SENTINEL_SUFFIX)) {
    return { ok: true, value };
  }
  const encoded = value.slice(
    BASE64_SENTINEL_PREFIX.length,
    value.length - BASE64_SENTINEL_SUFFIX.length,
  );
  const bytes = base64Decode(encoded);
  if (bytes === undefined) {
    return mismatch("Mcp-Name header has malformed Base64 sentinel encoding");
  }
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
    return { ok: true, value: decoder.decode(bytes) };
  } catch {
    return mismatch("Mcp-Name header Base64 payload is not valid UTF-8");
  }
}

function mismatch(detail: string): { ok: false; error: McpIngressValidationError } {
  return { ok: false, error: { kind: "header_mismatch", detail } };
}

function invalidParams(detail: string): { ok: false; error: McpIngressValidationError } {
  return { ok: false, error: { kind: "invalid_params", detail } };
}

/**
 * Optional `x-ferrogate-agent-run-id` declaration on an agent-traffic ingress —
 * the ONE validated parser the A2A, MCP, and asset surfaces share (visible
 * ASCII, ≤128 chars, charset `[A-Za-z0-9_-.:]`). Returns `{ value: undefined }`
 * when absent/empty (nothing is fabricated — an absent declaration is the
 * "unjoinable action" signal) and an error message for a malformed value.
 */
export function declaredAgentRunId(
  headers: Headers,
): { ok: true; value: string | undefined } | { ok: false; message: string } {
  const raw = headers.get(AGENT_RUN_ID_HEADER);
  if (raw === null) return { ok: true, value: undefined };
  const value = raw.trim();
  if (value.length === 0) return { ok: true, value: undefined };
  if (value.length > 128) {
    return { ok: false, message: `${AGENT_RUN_ID_HEADER} must be at most 128 characters` };
  }
  if (!/^[A-Za-z0-9_\-.:]+$/.test(value)) {
    return {
      ok: false,
      message: `${AGENT_RUN_ID_HEADER} may only contain letters, numbers, _, -, ., or :`,
    };
  }
  return { ok: true, value };
}

/**
 * Modern results require an explicit result discriminator. Legacy responses
 * retain their historical shape, so the ingress calls this only after a request
 * has been validated as modern. Mutates in place, exactly as
 * `McpJsonRpcResponse::complete_modern_result` does.
 */
export function completeModernResult(result: Record<string, JsonValue>, method: string): void {
  if (!("resultType" in result)) result["resultType"] = "complete";
  if (method === "tools/list" || method === "resources/list" || method === "resources/read") {
    if (!("ttlMs" in result)) result["ttlMs"] = PRIVATE_CACHE_TTL_MS;
    if (!("cacheScope" in result)) result["cacheScope"] = "private";
  }
}

/** Narrowing helper: a JSON object (not null, not an array). */
export function isJsonObject(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
