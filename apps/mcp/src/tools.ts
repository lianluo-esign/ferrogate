/**
 * `tools/list` and `tools/call`, plus the SINGLE governed tool chokepoint both
 * the JSON-RPC transport (`POST /v1/mcp`) and the REST transport
 * (`POST /v1/mcp/tool/execute`) run through.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/mcp_rpc.rs`
 * (`tools_list`, `tools_call`, the audit-target/message helpers) and the
 * `execute_tool_request_with_governance` chokepoint in `server/local.rs`.
 *
 * The chokepoint exists because an adversarial audit found the JSON-RPC
 * transport executing MCP tools directly, bypassing the managed-action
 * guardrails (input block/quarantine, output redaction/withhold), the approval
 * gate, and MCP identity resolution that the REST endpoint enforced. Both
 * transports delegate here so neither can drift.
 *
 * #522: every audit row this module emits — and the upstream dispatch itself —
 * carries the caller's DECLARED `agent_run_id`. That is what joins a
 * `tools/call` into its correlation chain. It is threaded through
 * {@link DispatchContext}, never re-derived and never fabricated.
 */
import type { JsonValue } from "@ferrogate/core";

import { resolveMcpIdentity } from "./identity/oauth.js";
import {
  jsonRpcError,
  jsonRpcResult,
  mcpErrorCode,
  type JsonRpcId,
  type JsonRpcResponse,
} from "./jsonrpc.js";
import {
  hasScope,
  isJsonObjectValue,
  McpDispatchHeaders,
  McpExecutionError,
  tenantContext,
  type AuditEvent,
  type DispatchContext,
  type McpPorts,
  type McpTool,
  type ToolExecuteBackend,
} from "./ports.js";

/** Scope the built-in `fetch_asset` tool enforces at execution. */
export const ASSET_READ_SCOPE = "assets.read";

/** Built-in gateway tools execute on the `builtin` backend, not an MCP upstream. */
export const BUILTIN_TOOL_PREFIX = "builtin.";

export function isBuiltinTool(name: string): boolean {
  return name.startsWith(BUILTIN_TOOL_PREFIX);
}

/** The built-in tool catalog (issue #257). */
export function builtinTools(): McpTool[] {
  return [
    {
      name: "builtin.fetch_asset",
      serverName: "builtin",
      remoteName: "fetch_asset",
      description:
        "Fetch a hosted FerroGate asset by type, name, and version. Enforces the same assets.read authorization as the REST asset pull.",
      inputSchema: {
        type: "object",
        properties: {
          asset_type: { type: "string" },
          name: { type: "string" },
          version: { type: "string" },
        },
        required: ["asset_type", "name", "version"],
      },
      autoExecute: true,
    },
  ];
}

/** One tool execution request. Port of `ToolExecutionRequest`. */
export interface ToolExecutionRequest {
  name: string;
  arguments: JsonValue;
  route?: string;
  sessionId?: string;
}

/** Port of `ToolExecutionResponse` (minus the buffer-budget guard). */
export interface ToolExecutionResponse {
  object: "tool_execution";
  name: string;
  content: JsonValue;
  is_error: boolean;
  request_id: string;
  session_id?: string;
  latency_ms: number;
}

/** Port of `ToolExecutionHttpError`. */
export interface ToolExecutionHttpError {
  status: number;
  code: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Audit helpers (port of `mcp_rpc.rs`)
// ---------------------------------------------------------------------------

/** Split a namespaced tool name into `(server, tool)` on its FIRST hyphen. */
export function toolAuditDetails(
  name: string,
): { serverName: string; toolName: string } | undefined {
  const separator = name.indexOf("-");
  if (separator === -1) return undefined;
  return { serverName: name.slice(0, separator), toolName: name.slice(separator + 1) };
}

export function toolAuditTarget(serverName: string, toolName: string): string {
  return `mcp:${serverName}/tool:${toolName}`;
}

export function toolSessionAuditTarget(sessionId: string): string {
  return `tool_session:${sessionId}`;
}

export function toolSessionMcpAuditTarget(
  sessionId: string,
  serverName: string,
  toolName: string,
): string {
  return `${toolSessionAuditTarget(sessionId)}/${toolAuditTarget(serverName, toolName)}`;
}

export function toolAuditMessage(
  details: { serverName: string; toolName: string } | undefined,
  toolName: string,
  action: string,
  latencyMs?: number,
): string {
  if (details !== undefined) {
    const latency = latencyMs === undefined ? "" : ` in ${latencyMs}ms`;
    return `MCP upstream mcp:${details.serverName} tool ${details.toolName} ${action}${latency}`;
  }
  return latencyMs === undefined
    ? `tool ${toolName} ${action}`
    : `tool ${toolName} ${action} in ${latencyMs}ms`;
}

export function toolAuditFailureMessage(
  details: { serverName: string; toolName: string } | undefined,
  toolName: string,
  code: string,
  message: string,
): string {
  if (details !== undefined) {
    return `MCP upstream mcp:${details.serverName} tool ${details.toolName} failed: ${code}: ${message}`;
  }
  return `tool ${toolName} failed: ${code}: ${message}`;
}

/** Port of `decorate_skill_audit`. */
function decorateSkillAudit(
  skill: DispatchContext["skill"],
  target: string,
  message: string,
): { target: string; message: string } {
  if (skill === undefined) return { target, message };
  const label = `${skill.id}@${skill.version}`;
  return {
    target: `skill_package:${label}/${target}`,
    message: `skill_package=${label} ${message}`,
  };
}

/**
 * Build an audit row for this dispatch.
 *
 * #522: `agent_run_id` is the caller's DECLARED, validated
 * `x-ferrogate-agent-run-id`, so these rows join the same correlation chain as
 * the chat / agent-run / A2A surfaces. `undefined` when the caller declared
 * none — never fabricated.
 */
export function auditEvent(
  context: DispatchContext,
  action: string,
  target: string,
  outcome: string,
  message: string,
): AuditEvent {
  const decorated = decorateSkillAudit(context.skill, target, message);
  const event: AuditEvent = {
    request_id: context.requestId,
    tenant: tenantContext(context.auth),
    action,
    target: decorated.target,
    outcome,
    message: decorated.message,
  };
  if (context.traceId !== undefined) event.trace_id = context.traceId;
  if (context.agentRunId !== undefined) event.agent_run_id = context.agentRunId;
  if (context.auth.apiKeyId !== undefined) event.actor_api_key_id = context.auth.apiKeyId;
  return event;
}

// ---------------------------------------------------------------------------
// tools/list
// ---------------------------------------------------------------------------

/**
 * `tools/list`: the tenant's allowlisted MCP tools plus the built-in gateway
 * tools — the latter advertised ONLY to keys holding the same `assets.read`
 * scope the tool enforces at execution, so a key never sees a tool every call
 * would deny.
 */
export async function toolsList(
  ports: McpPorts,
  context: DispatchContext,
  id: JsonRpcId | undefined,
): Promise<JsonRpcResponse> {
  const tools = [...(await ports.upstreams.listTools())];
  if (hasScope(context.auth, ASSET_READ_SCOPE)) tools.push(...builtinTools());
  ports.audit.record(
    auditEvent(
      context,
      "tool.list",
      "mcp",
      "success",
      `listed ${tools.length} MCP tools through native MCP endpoint`,
    ),
  );
  return jsonRpcResult(id, {
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description ?? null,
      inputSchema: tool.inputSchema,
    })),
  });
}

// ---------------------------------------------------------------------------
// tools/call
// ---------------------------------------------------------------------------

/**
 * `tools/call` over the JSON-RPC transport. Runs the entitlement gate and the
 * skill-capability check (both of which the REST handler also runs BEFORE the
 * chokepoint), then delegates to {@link executeToolWithGovernance}.
 */
export async function toolsCall(
  ports: McpPorts,
  context: DispatchContext,
  id: JsonRpcId | undefined,
  params: unknown,
): Promise<JsonRpcResponse> {
  const object = isJsonObjectValue(params) ? params : undefined;
  const name = object?.["name"];
  if (typeof name !== "string") {
    return jsonRpcError(id, mcpErrorCode("tool_not_found"), "tools/call params.name is required");
  }
  const backend: ToolExecuteBackend = isBuiltinTool(name) ? "builtin" : "mcp";

  // Plan/RBAC entitlement gate: this JSON-RPC transport executes the exact same
  // MCP tools as `POST /v1/mcp/tool/execute`, and was once a third call site
  // that bypassed the gate both REST endpoints enforce.
  const denial = await ports.entitlements.toolExecutionDenial(context.auth, backend);
  if (denial !== undefined) {
    return jsonRpcError(id, mcpErrorCode(denial.code), denial.message);
  }

  const args = object?.["arguments"] ?? {};
  const request: ToolExecutionRequest = { name, arguments: args as JsonValue, route: "/v1/mcp" };

  const result = await executeToolWithGovernance(ports, context, request, backend);
  if (!result.ok) {
    return jsonRpcError(id, mcpErrorCode(result.error.code), result.error.message);
  }
  // Unwrap an MCP-shaped `{ content: [...] }` result, else pass the payload
  // through unchanged — exactly what `tool_call_result` does.
  const content = isJsonObjectValue(result.response.content)
    ? (result.response.content["content"] ?? result.response.content)
    : result.response.content;
  return jsonRpcResult(id, { content, isError: result.response.is_error });
}

export type GovernedExecution =
  | { ok: true; response: ToolExecutionResponse }
  | { ok: false; error: ToolExecutionHttpError };

/**
 * THE governed tool chokepoint.
 *
 * Owns, in order: the deny-by-default allowlist check (`toolByName`), the
 * approval gate, the input guardrail, MCP identity resolution (fed the
 * validated original bearer), execution, the output guardrail, and the
 * `tool.execute` / guardrail / approval / identity audit rows. Callers must NOT
 * repeat these — doing so would double-govern and double-audit.
 */
export async function executeToolWithGovernance(
  ports: McpPorts,
  context: DispatchContext,
  request: ToolExecutionRequest,
  backend: ToolExecuteBackend,
): Promise<GovernedExecution> {
  const started = Date.now();
  const details = backend === "mcp" ? toolAuditDetails(request.name) : undefined;
  const auditTarget =
    details === undefined
      ? request.name
      : request.sessionId === undefined
        ? toolAuditTarget(details.serverName, details.toolName)
        : toolSessionMcpAuditTarget(request.sessionId, details.serverName, details.toolName);

  const fail = (
    status: number,
    code: string,
    message: string,
    outcome = "rejected",
  ): GovernedExecution => {
    ports.audit.record(
      auditEvent(
        context,
        "tool.execute",
        auditTarget,
        outcome,
        toolAuditFailureMessage(details, request.name, code, message),
      ),
    );
    return { ok: false, error: { status, code, message } };
  };

  // --- allowlist -----------------------------------------------------------
  let tool: McpTool | undefined;
  if (backend === "builtin") {
    tool = builtinTools().find((candidate) => candidate.name === request.name);
    if (tool === undefined) {
      return fail(404, "tool_not_found", `built-in tool ${request.name} does not exist`);
    }
    if (!hasScope(context.auth, ASSET_READ_SCOPE)) {
      return fail(
        403,
        "tool_denied",
        `built-in tool ${request.name} requires the ${ASSET_READ_SCOPE} scope`,
      );
    }
  } else {
    tool = await ports.upstreams.toolByName(request.name);
    if (tool === undefined) {
      // Deny-by-default: an un-allowlisted or unknown tool is refused here, at
      // the chokepoint, so the refusal is audited exactly once.
      const known = request.name.includes("-");
      return fail(
        403,
        "tool_denied",
        known
          ? `MCP tool ${request.name} is not allowlisted for execution`
          : `MCP tool ${request.name} must use serverName-toolName namespace`,
      );
    }
  }

  // --- approval gate -------------------------------------------------------
  if (!tool.autoExecute) {
    const pending = await ports.approvals.require(context, tool, request.arguments);
    if (pending !== undefined) {
      ports.audit.record(
        auditEvent(context, "tool.approval", auditTarget, "pending", pending.message),
      );
      return fail(403, pending.code, pending.message);
    }
  }

  // --- input guardrail -----------------------------------------------------
  const inputVerdict = await ports.guardrails.inspectInput(context, tool, request.arguments);
  if (inputVerdict.action === "block" || inputVerdict.action === "quarantine") {
    ports.audit.record(
      auditEvent(
        context,
        "tool.guardrail",
        auditTarget,
        inputVerdict.action,
        inputVerdict.reason ?? `input guardrail ${inputVerdict.action}ed the call`,
      ),
    );
    return fail(
      403,
      "tool_denied",
      inputVerdict.reason ?? `input guardrail ${inputVerdict.action}ed the call`,
    );
  }
  const args = inputVerdict.payload ?? request.arguments;

  // --- identity resolution + execution -------------------------------------
  let content: JsonValue;
  let isError: boolean;
  if (backend === "builtin") {
    const executed = await executeBuiltinTool(ports, context, args);
    if (!executed.ok)
      return fail(executed.error.status, executed.error.code, executed.error.message);
    content = executed.content;
    isError = false;
  } else {
    let identity = McpDispatchHeaders.empty();
    try {
      const resolution = await resolveMcpIdentity(ports, context, tool.serverName);
      identity = resolution.headers;
      ports.metrics.recordMcpIdentityResolution(true);
      ports.audit.record(
        auditEvent(
          context,
          "mcp.identity.use",
          `mcp:${tool.serverName}/identity`,
          "resolved",
          `server=${tool.serverName} source=${resolution.credentialSource} subject=${resolution.subject ?? "unknown"}`,
        ),
      );
    } catch (cause) {
      ports.metrics.recordMcpIdentityResolution(false);
      const error = cause as { status?: number; code?: string; message?: string };
      ports.audit.record(
        auditEvent(
          context,
          "mcp.identity.use",
          `mcp:${tool.serverName}/identity`,
          "rejected",
          `server=${tool.serverName} code=${error.code ?? "mcp_identity_unavailable"}`,
        ),
      );
      return fail(
        error.status ?? 401,
        error.code ?? "mcp_identity_unavailable",
        error.message ?? "MCP identity could not be resolved",
      );
    }

    try {
      const executed = await ports.upstreams.callTool(tool, args, identity, context);
      content = executed.content;
      isError = executed.isError;
    } catch (cause) {
      const code =
        cause instanceof McpExecutionError ? cause.code : ("tool_execution_failed" as const);
      const message = cause instanceof Error ? cause.message : String(cause);
      const status =
        code === "mcp_upstream_unauthorized" ? 401 : code === "tool_denied" ? 403 : 502;
      return fail(status, code, message);
    }
  }

  // --- output guardrail ----------------------------------------------------
  const outputVerdict = await ports.guardrails.inspectOutput(context, tool, content);
  if (outputVerdict.action === "withhold") {
    ports.audit.record(
      auditEvent(
        context,
        "tool.guardrail",
        auditTarget,
        "withheld",
        outputVerdict.reason ?? "output guardrail withheld the result",
      ),
    );
    return fail(403, "tool_denied", outputVerdict.reason ?? "output guardrail withheld the result");
  }
  if (outputVerdict.action === "redact" && outputVerdict.payload !== undefined) {
    ports.audit.record(
      auditEvent(
        context,
        "tool.guardrail",
        auditTarget,
        "redacted",
        outputVerdict.reason ?? "output guardrail redacted the result",
      ),
    );
    content = outputVerdict.payload;
  }

  const latencyMs = Date.now() - started;
  ports.audit.record(
    auditEvent(
      context,
      "tool.execute",
      auditTarget,
      isError ? "failed" : "success",
      toolAuditMessage(
        details,
        request.name,
        isError ? "returned an error" : "executed",
        latencyMs,
      ),
    ),
  );

  const response: ToolExecutionResponse = {
    object: "tool_execution",
    name: request.name,
    content,
    is_error: isError,
    request_id: context.requestId,
    latency_ms: latencyMs,
  };
  if (request.sessionId !== undefined) response.session_id = request.sessionId;
  return { ok: true, response };
}

/**
 * `builtin.fetch_asset` — the built-in gateway tool. Reuses the EXACT asset-read
 * authorization the REST pull enforces: `assets.read` (checked above) plus
 * tenant scoping (checked here).
 */
async function executeBuiltinTool(
  ports: McpPorts,
  context: DispatchContext,
  args: JsonValue,
): Promise<{ ok: true; content: JsonValue } | { ok: false; error: ToolExecutionHttpError }> {
  const object = isJsonObjectValue(args) ? args : {};
  const assetType = object["asset_type"];
  const name = object["name"];
  const version = object["version"];
  if (typeof assetType !== "string" || typeof name !== "string" || typeof version !== "string") {
    return {
      ok: false,
      error: {
        status: 400,
        code: "tool_not_found",
        message: "builtin.fetch_asset requires string asset_type, name, and version",
      },
    };
  }
  const tenantId = context.auth.organizationId;
  if (tenantId === undefined) {
    return {
      ok: false,
      error: {
        status: 403,
        code: "tenant_required",
        message: "assets require a tenant-attributed API key",
      },
    };
  }
  const read = await ports.assets.read(tenantId, assetType, name, version);
  if (!read.ok) {
    return { ok: false, error: assetReadHttpError(read.error, assetType, name, version) };
  }
  return { ok: true, content: { content: [assetContentEntry(read.asset, read.content)] } };
}

/** Map an asset read failure onto its REST status/code pair. */
export function assetReadHttpError(
  failure: import("./ports.js").AssetReadFailure,
  assetType: string,
  name: string,
  version: string,
): ToolExecutionHttpError {
  switch (failure.kind) {
    case "not_found":
      return {
        status: 404,
        code: "tool_not_found",
        message: `no asset at ${assetType}/${name}/${version}`,
      };
    case "integrity":
      return {
        status: 500,
        code: "asset_integrity_failed",
        message: "stored asset content hash does not match recorded hash",
      };
    case "too_large":
      return { status: 413, code: "asset_too_large_for_inline_pull", message: failure.message };
    case "overloaded":
      return { status: 503, code: "gateway_buffer_budget_exhausted", message: failure.message };
    case "bucket_unavailable":
      return { status: 503, code: "mcp_server_unavailable", message: failure.message };
    case "storage":
      return {
        status: 503,
        code: "asset_storage_unavailable",
        message: `asset storage unavailable: ${failure.message}`,
      };
  }
}

/** MCP resource-content entry: inline `text` for textual mime types, else base64 `blob`. */
export function assetContentEntry(
  asset: import("./ports.js").StoredAsset,
  content: Uint8Array,
): Record<string, JsonValue> {
  const uri = assetUri(asset.assetType, asset.name, asset.version);
  const entry: Record<string, JsonValue> = {
    uri,
    mimeType: asset.contentType,
    // The stored sha256 travels in `_meta` so the caller can re-verify the
    // fingerprint of the bytes it just received.
    _meta: { "ferrogate/sha256": asset.sha256, "ferrogate/sizeBytes": asset.sizeBytes },
  };
  if (isTextualMimeType(asset.contentType)) {
    entry["text"] = new TextDecoder().decode(content);
  } else {
    let binary = "";
    for (const byte of content) binary += String.fromCharCode(byte);
    entry["blob"] = btoa(binary);
  }
  return entry;
}

export function isTextualMimeType(contentType: string): boolean {
  const lowered = contentType.toLowerCase();
  return (
    lowered.startsWith("text/") ||
    lowered.includes("json") ||
    lowered.includes("xml") ||
    lowered.includes("yaml") ||
    lowered.includes("javascript")
  );
}

/** `asset://{asset_type}/{name}/{version}`. */
export function assetUri(assetType: string, name: string, version: string): string {
  return `asset://${assetType}/${name}/${version}`;
}

/** Parse an `asset://` URI back into its triple. */
export function parseAssetUri(
  uri: string,
): { assetType: string; name: string; version: string } | undefined {
  if (!uri.startsWith("asset://")) return undefined;
  const parts = uri.slice("asset://".length).split("/");
  if (parts.length !== 3) return undefined;
  const [assetType, name, version] = parts;
  if (!assetType || !name || !version) return undefined;
  return { assetType, name, version };
}
