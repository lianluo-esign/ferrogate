/**
 * The MCP JSON-RPC ingress: `Mcp-Method` / `Mcp-Name` routing-header
 * verification, method→scope gating, per-request identity, and — the
 * load-bearing parity contract of this app — `agent_run_id` threading.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/local.rs`'s
 * `handle_mcp_rpc` plus `server/mcp_rpc.rs`'s `handle_request` dispatch table.
 *
 * ## Why the routing headers are verified fail-closed
 *
 * `Mcp-Method` / `Mcp-Name` let a gateway scope-gate, rate-limit, and meter an
 * MCP operation without parsing the body. If a header could disagree with the
 * body, a caller would be metered/authorized as one operation while executing
 * another. So a disagreement fails the request CLOSED, before dispatch.
 *
 * ## Why `agent_run_id` is threaded (#522)
 *
 * The MCP ingress is governed agent traffic. The caller declares the run it
 * belongs to via the validated `x-ferrogate-agent-run-id` header — the SAME
 * header the chat / agent-run / A2A ingresses accept — and every audit row this
 * handler (and the governed tool chokepoint it delegates to) records joins on
 * that id. Absent the header the id stays `undefined`; it is NEVER fabricated.
 * That absence is the "unjoinable action" signal, counted per authenticated
 * tenant and surface.
 */
import type { JsonValue } from "@ferrogate/core";

import { mcpJsonRpcMethodScopes } from "./contract.js";
import {
  decodeMcpRequest,
  jsonRpcError,
  jsonRpcResult,
  JsonRpcErrorCode,
  renderJsonRpcResponse,
  type JsonRpcResponse,
  type McpIngressRequest,
} from "./jsonrpc.js";
import {
  completeModernResult,
  FERROGATE_CLIENT_INFO,
  ingressErrorCode,
  ingressErrorData,
  ingressErrorDisplay,
  ingressErrorMessage,
  ingressMode,
  isSupportedModernMethod,
  MCP_PROTOCOL_VERSION,
  negotiateProtocolVersion,
  SUPPORTED_MCP_PROTOCOL_VERSIONS,
  validateIngress,
} from "./protocol.js";
import { hasScope, isJsonObjectValue, type DispatchContext, type McpPorts } from "./ports.js";
import {
  assetContentEntry,
  assetUri,
  auditEvent,
  parseAssetUri,
  toolsCall,
  toolsList,
} from "./tools.js";

/**
 * The method→scope map, read STRAIGHT from the runtime API contract
 * (`operations[POST /v1/mcp].auth.scope_discriminator`). `method_dependent`
 * auth means the required scope is a function of the JSON-RPC method, resolved
 * BEFORE authentication so a caller is gated on the operation it actually
 * requested — ROUTE-MAP.md invariant 4: read the contract, never restate it.
 *
 * It is a `Map`, not an object literal, so an inherited `Object.prototype` key
 * (`toString`, `constructor`, `__proto__`) can never masquerade as a mapped
 * method with a non-`undefined` "scope".
 */
export const MCP_METHOD_SCOPES: ReadonlyMap<string, string> = mcpJsonRpcMethodScopes();

/**
 * Required scope for a method, or `undefined` when the contract has no mapping.
 * A modern unknown method still needs attributable auth before its
 * protocol-defined 404, so the caller substitutes the read-only discovery scope
 * on that branch (no handler or governed action runs there).
 */
export function requiredScope(method: string): string | undefined {
  return MCP_METHOD_SCOPES.get(method);
}

/** The ingress decision for one parsed request, before authentication. */
export interface IngressPlan {
  request: McpIngressRequest;
  mode: "modern" | "legacy";
  scope: string;
}

export type IngressPlanResult =
  | { ok: true; plan: IngressPlan }
  | { ok: false; status: number; response: JsonRpcResponse };

/**
 * Parse the body and resolve the required scope. This runs BEFORE
 * authentication precisely so an unauthenticated caller cannot probe which
 * scope a method needs by watching auth failures diverge.
 */
export function planIngress(headers: Headers, body: string): IngressPlanResult {
  const decoded = decodeMcpRequest(body);
  if (!decoded.ok) {
    // The Rust handler answers a parse error at HTTP 200 with a `-32700`
    // JSON-RPC body (a transport-level success carrying an application-level
    // failure, which is what a JSON-RPC client expects).
    return { ok: false, status: 200, response: decoded.response };
  }
  const request = decoded.request;
  const mode = ingressMode(headers, request);
  const scope = requiredScope(request.method);
  if (scope === undefined) {
    if (mode === "modern") {
      return { ok: true, plan: { request, mode, scope: "tools.read" } };
    }
    return {
      ok: false,
      status: 500,
      response: jsonRpcError(
        request.id,
        JsonRpcErrorCode.InternalError,
        `runtime API contract has no MCP scope mapping for method ${request.method}`,
      ),
    };
  }
  return { ok: true, plan: { request, mode, scope } };
}

export interface DispatchOutcome {
  status: number;
  response?: JsonRpcResponse;
  /** A JSON-RPC Notification is acknowledged with `202 Accepted` and no body. */
  empty?: true;
}

/**
 * Validate the request's protocol metadata and dispatch it.
 *
 * Runs, in order: routing-header verification (fail closed), the
 * modern-method allowlist, the bounded per-operation metric, the
 * notification short-circuit, then the method dispatch table. Every branch that
 * records an audit row does so through {@link auditEvent}, which stamps
 * `context.agentRunId` — that is how the declared run id reaches storage.
 */
export async function dispatchMcpRequest(
  ports: McpPorts,
  headers: Headers,
  plan: IngressPlan,
  context: DispatchContext,
): Promise<DispatchOutcome> {
  const rpc = plan.request;

  // --- routing-header / protocol-metadata verification (fail closed) -------
  const validation = validateIngress(headers, rpc);
  if (!validation.ok) {
    if (plan.mode === "legacy") {
      // Preserve the legacy contract: the modern candidate owns -32020 at HTTP
      // 400; changing old initialize-era failures would be an unrelated
      // compatibility break.
      ports.audit.record(
        auditEvent(
          context,
          "mcp.routing_header_mismatch",
          "mcp",
          "rejected",
          ingressErrorDisplay(validation.error),
        ),
      );
      return {
        status: 200,
        response: jsonRpcError(
          rpc.id,
          JsonRpcErrorCode.InvalidRequest,
          `MCP routing header mismatch: ${ingressErrorDisplay(validation.error)}`,
        ),
      };
    }
    // Attributable evidence uses authenticated tenant/key fields; the detail
    // deliberately excludes clientInfo and client-capability content, and no
    // client identifier becomes a metric label either.
    ports.audit.record(
      auditEvent(
        context,
        "mcp.protocol_rejected",
        "mcp",
        "rejected",
        `method=${rpc.method} ${ingressErrorDisplay(validation.error)}`,
      ),
    );
    return {
      status: 400,
      response: jsonRpcError(
        rpc.id,
        ingressErrorCode(validation.error),
        ingressErrorMessage(validation.error),
        ingressErrorData(validation.error),
      ),
    };
  }
  const ingress = validation.ingress;

  // --- modern method allowlist ---------------------------------------------
  if (ingress.mode === "modern" && !isSupportedModernMethod(rpc.method)) {
    ports.audit.record(
      auditEvent(
        context,
        "mcp.protocol_rejected",
        "mcp",
        "rejected",
        `protocol=${MCP_PROTOCOL_VERSION} method=${rpc.method} is not implemented`,
      ),
    );
    return {
      status: 404,
      response: jsonRpcError(
        rpc.id,
        JsonRpcErrorCode.MethodNotFound,
        `MCP method ${rpc.method} is not supported`,
      ),
    };
  }

  // Bounded operation/tool labels only — clientInfo and other per-client
  // metadata never enter a metric label.
  ports.metrics.recordMcpMethodRequest(ingress.metricMethod, ingress.metricName);

  // --- notification short-circuit ------------------------------------------
  if (rpc.id === undefined) return { status: 202, empty: true };

  const response = await handleRequest(ports, context, rpc);
  if (ingress.mode === "modern" && isJsonObjectValue(response.result)) {
    completeModernResult(response.result, rpc.method);
  }
  return { status: 200, response };
}

/**
 * The method dispatch table. Port of `mcp_rpc::handle_request`.
 *
 * `context` — and with it the declared `agent_run_id` — is passed into EVERY
 * sub-handler; none of them re-derive it.
 */
export async function handleRequest(
  ports: McpPorts,
  context: DispatchContext,
  rpc: McpIngressRequest,
): Promise<JsonRpcResponse> {
  switch (rpc.method) {
    case "initialize": {
      const params = isJsonObjectValue(rpc.params) ? rpc.params : {};
      const rawRequested = params["protocolVersion"];
      const requested = typeof rawRequested === "string" ? rawRequested : undefined;
      const negotiated = negotiateProtocolVersion(requested);
      const downgraded = requested !== undefined && requested !== negotiated;
      ports.audit.record(
        auditEvent(
          context,
          downgraded ? "mcp.protocol_downgraded" : "mcp.protocol_negotiated",
          `protocol:${negotiated}`,
          downgraded ? "fallback" : "success",
          `legacy initialize selected protocol ${negotiated} from requested ${requested ?? "<omitted>"}`,
        ),
      );
      return jsonRpcResult(rpc.id, initializeResult(negotiated));
    }

    case "server/discover":
      ports.audit.record(
        auditEvent(
          context,
          "mcp.protocol_negotiated",
          `protocol:${MCP_PROTOCOL_VERSION}`,
          "success",
          `served stateless server/discover for the pinned ${MCP_PROTOCOL_VERSION} candidate`,
        ),
      );
      return jsonRpcResult(rpc.id, discoverResult());

    // `ping` exists only on initialize-based legacy revisions. Modern ingress
    // rejects it before dispatch because the candidate revision removed it.
    case "ping":
      return jsonRpcResult(rpc.id, {});

    case "notifications/initialized":
      return jsonRpcResult(rpc.id, {});

    case "resources/list":
      return resourcesList(ports, context, rpc);

    case "resources/read":
      return resourcesRead(ports, context, rpc);

    case "tools/list":
      return toolsList(ports, context, rpc.id);

    case "tools/call":
      return toolsCall(ports, context, rpc.id, rpc.params);

    default:
      return jsonRpcError(
        rpc.id,
        JsonRpcErrorCode.MethodNotFound,
        `MCP method ${rpc.method} is not supported`,
      );
  }
}

function initializeResult(protocolVersion: string): JsonValue {
  return {
    protocolVersion,
    capabilities: {
      tools: { listChanged: false },
      resources: { subscribe: false, listChanged: false },
    },
    instructions:
      "Use FerroGate as a governed MCP gateway. Follow the server's auth, policy, approval, and billing rules for all tool calls.",
    serverInfo: { ...FERROGATE_CLIENT_INFO },
  };
}

function discoverResult(): JsonValue {
  return {
    resultType: "complete",
    supportedVersions: [...SUPPORTED_MCP_PROTOCOL_VERSIONS],
    capabilities: { tools: {}, resources: {} },
    _meta: { "io.modelcontextprotocol/serverInfo": { ...FERROGATE_CLIENT_INFO } },
    instructions:
      "Use FerroGate as a governed MCP gateway. Follow the server's auth, policy, approval, and billing rules for all tool calls.",
    ttlMs: 3_600_000,
    cacheScope: "public",
  };
}

/**
 * `resources/list`: the tenant's hosted assets as MCP resources. Visibility
 * reuses the EXACT authz of the REST asset list — the method→scope contract
 * maps `resources/list` to `assets.read`, so a key lacking it is rejected at
 * the ingress before dispatch (an error, never an empty list masking a 403).
 */
async function resourcesList(
  ports: McpPorts,
  context: DispatchContext,
  rpc: McpIngressRequest,
): Promise<JsonRpcResponse> {
  const tenantId = context.auth.organizationId;
  if (tenantId === undefined) {
    return jsonRpcError(
      rpc.id,
      JsonRpcErrorCode.AssetTenantRequired,
      "assets require a tenant-attributed API key",
    );
  }
  let assets;
  try {
    assets = await ports.assets.list(tenantId);
  } catch (cause) {
    return jsonRpcError(
      rpc.id,
      JsonRpcErrorCode.ApplicationError,
      `asset storage unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  // #366: the MCP resource listing withholds pending/quarantined assets,
  // matching the REST list/manifest and the read chokepoint.
  const downloadable = assets.filter((asset) => asset.downloadable);
  ports.audit.record(
    auditEvent(
      context,
      "resource.list",
      "mcp",
      "success",
      `listed ${downloadable.length} asset resources through native MCP endpoint`,
    ),
  );
  return jsonRpcResult(rpc.id, {
    resources: downloadable.map((asset) => ({
      uri: assetUri(asset.assetType, asset.name, asset.version),
      name: `${asset.name}@${asset.version}`,
      mimeType: asset.contentType,
      _meta: { "ferrogate/sha256": asset.sha256, "ferrogate/sizeBytes": asset.sizeBytes },
    })),
  });
}

/**
 * `resources/read`: a hosted asset's verified content by its `asset://` URI.
 * Reuses the EXACT authz + sha256 re-verification of the REST asset pull.
 * Inlining is bounded by the gateway buffer budget, NOT by the old push cap: an
 * over-budget object returns `-32004` naming the presigned download instead.
 */
async function resourcesRead(
  ports: McpPorts,
  context: DispatchContext,
  rpc: McpIngressRequest,
): Promise<JsonRpcResponse> {
  const params = isJsonObjectValue(rpc.params) ? rpc.params : {};
  const uri = params["uri"];
  if (typeof uri !== "string") {
    return jsonRpcError(
      rpc.id,
      JsonRpcErrorCode.InvalidParams,
      "resources/read params.uri is required",
    );
  }
  const parsed = parseAssetUri(uri);
  if (parsed === undefined) {
    return jsonRpcError(
      rpc.id,
      JsonRpcErrorCode.InvalidParams,
      `unsupported resource uri ${uri}; expected asset://{asset_type}/{name}/{version}`,
    );
  }
  const tenantId = context.auth.organizationId;
  if (tenantId === undefined) {
    return jsonRpcError(
      rpc.id,
      JsonRpcErrorCode.AssetTenantRequired,
      "assets require a tenant-attributed API key",
    );
  }
  const read = await ports.assets.read(tenantId, parsed.assetType, parsed.name, parsed.version);
  if (!read.ok) {
    switch (read.error.kind) {
      case "not_found":
        return jsonRpcError(
          rpc.id,
          JsonRpcErrorCode.InvalidParams,
          `no asset at ${parsed.assetType}/${parsed.name}/${parsed.version}`,
        );
      case "integrity":
        return jsonRpcError(
          rpc.id,
          JsonRpcErrorCode.ApplicationError,
          "stored asset content hash does not match recorded hash",
        );
      case "too_large":
        return jsonRpcError(rpc.id, JsonRpcErrorCode.AssetTooLarge, read.error.message);
      case "overloaded":
        return jsonRpcError(
          rpc.id,
          JsonRpcErrorCode.GatewayBufferBudgetExhausted,
          read.error.message,
        );
      case "bucket_unavailable":
        return jsonRpcError(rpc.id, JsonRpcErrorCode.McpServerUnavailable, read.error.message);
      case "storage":
        return jsonRpcError(
          rpc.id,
          JsonRpcErrorCode.ApplicationError,
          `asset storage unavailable: ${read.error.message}`,
        );
    }
  }
  ports.audit.record(
    auditEvent(
      context,
      "resource.read",
      assetUri(read.asset.assetType, read.asset.name, read.asset.version),
      "success",
      `read asset resource ${read.asset.name}@${read.asset.version} (${read.asset.sizeBytes} bytes)`,
    ),
  );
  return jsonRpcResult(rpc.id, { contents: [assetContentEntry(read.asset, read.content)] });
}

/** Render a dispatch outcome's JSON-RPC body. */
export function renderOutcome(outcome: DispatchOutcome): Record<string, JsonValue> | undefined {
  return outcome.response === undefined ? undefined : renderJsonRpcResponse(outcome.response);
}

/** Re-exported so callers can gate the built-in tool advertisement identically. */
export { hasScope };
