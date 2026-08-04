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
import {
  ASSET_EGRESS_IDENTITY_ERROR,
  assetEgressTargetId,
  assetPullAuditMessage,
  readAssetWithEgress,
  type AssetEgressDenial,
  type ReadAssetWithEgressResult,
} from "@ferrogate/billing";

import { resolveMcpIdentity } from "./identity/oauth.js";
import {
  type JsonRpcId,
  type JsonRpcResponse,
  jsonRpcError,
  jsonRpcResult,
  mcpErrorCode,
} from "./jsonrpc.js";
import {
  EMPTY_FAN_IN,
  MULTIPLEX_AMBIGUOUS_META,
  MULTIPLEX_DEGRADED_META,
  TOOL_NAMESPACE_SEPARATOR,
  ambiguousMeta,
  ambiguousToolMessage,
  ambiguousToolNames,
  degradedMeta,
  readServerSelector,
  toolMeta,
} from "./multiplex.js";
import {
  type AuditEvent,
  type DispatchContext,
  McpDispatchHeaders,
  McpExecutionError,
  type McpPorts,
  type McpTool,
  type StoredAsset,
  type AssetReadFailure,
  type ToolExecuteBackend,
  hasScope,
  isJsonObjectValue,
  tenantContext,
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
  /**
   * #687: the upstream the caller means, when the flat `{server}-{tool}` name
   * is claimed by more than one of them.
   *
   * Carried as `params._meta["ferrogate/server"]` on the JSON-RPC transport and
   * as a top-level `server` field on `POST /v1/mcp/tool/execute`. It NARROWS —
   * a `server` that does not advertise this tool is a refusal, never a fallback
   * to a different upstream.
   */
  server?: string;
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

/** The `(server, tool)` pair an audit row is filed against. */
export interface ToolAuditDetails {
  serverName: string;
  toolName: string;
}

/**
 * Attribution for a RESOLVED tool — read off the catalogue entry, never parsed
 * out of the flat name (#687).
 *
 * This replaces a first-hyphen split of `{server}-{remote}`. That split was
 * wrong for every upstream whose own name contains a hyphen (`github-mcp`,
 * `slack-connector`): `github-mcp-search` was filed as server `github`, tool
 * `mcp-search` — a server that does not exist and a tool nobody called — so
 * every `tool.execute`, `tool.guardrail`, `tool.approval` and
 * `mcp.identity.use` row for those upstreams was misattributed, destroying the
 * per-upstream attribution #677/#678 built.
 *
 * `McpTool` already carries both halves exactly as the catalogue knows them,
 * so the correct answer was one field access away the whole time.
 */
export function toolAttribution(tool: McpTool): ToolAuditDetails {
  return { serverName: tool.serverName, toolName: tool.remoteName };
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
  // Gate upstream tools on the same entitlement decision as tools/call (#685).
  // Without this, tools/list DISCOVERS tools that tools/call would later DENY,
  // violating Envoy AI Gateway's "one control, two code paths" guarantee.
  const mcpDenial = await ports.entitlements.toolExecutionDenial(context.auth, "mcp");
  const fan = mcpDenial === undefined ? await ports.upstreams.fanIn() : EMPTY_FAN_IN;
  const tools = [...fan.tools];
  if (hasScope(context.auth, ASSET_READ_SCOPE)) tools.push(...builtinTools());

  // #687: what the caller did NOT get is part of the answer. A partial upstream
  // failure used to arrive as a silently shorter list, and an agent reading a
  // shorter list concludes the tool does not exist and stops — a worse outcome
  // than an error it can retry or route around.
  // #687: tell the client session which upstreams this listing spans and which
  // of them could not be reached. A degraded upstream is how a client session
  // learns that one leg of its fan-out dropped MID-CONVERSATION; the session
  // itself stays open, because one upstream falling over must not take the
  // whole multiplexed conversation with it.
  for (const tool of fan.tools) context.upstreams?.note(tool.serverName);
  for (const failure of fan.degraded) {
    context.upstreams?.noteFailure(failure.server, failure.message);
  }

  const collisions = ambiguousToolNames(tools);
  const meta: Record<string, JsonValue> = {};
  if (fan.degraded.length > 0) meta[MULTIPLEX_DEGRADED_META] = degradedMeta(fan.degraded);
  if (collisions.length > 0) meta[MULTIPLEX_AMBIGUOUS_META] = ambiguousMeta(collisions);

  ports.audit.record(
    auditEvent(
      context,
      "tool.list",
      "mcp",
      // A listing that could not reach every upstream is not a plain success,
      // and an operator watching the audit stream is the second reader who
      // needs to know before an agent starts reasoning from a short catalogue.
      fan.degraded.length > 0 ? "degraded" : "success",
      fan.degraded.length > 0
        ? `listed ${tools.length} MCP tools through native MCP endpoint; ` +
            `${fan.degraded.length} upstream(s) unreachable: ` +
            fan.degraded.map((failure) => failure.server).join(", ")
        : `listed ${tools.length} MCP tools through native MCP endpoint`,
    ),
  );

  const result: Record<string, JsonValue> = {
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description ?? null,
      inputSchema: tool.inputSchema,
      // Emitted for EVERY tool: this is the selector a caller sends back on
      // `tools/call` to name the upstream it meant, and a collision can appear
      // the moment an operator adds a server.
      _meta: toolMeta(tool),
    })),
  };
  if (Object.keys(meta).length > 0) result["_meta"] = meta;
  return jsonRpcResult(id, result);
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
  // #687: the caller's explicit upstream, from `params._meta["ferrogate/server"]`
  // — the same string `tools/list` put on that tool's own `_meta`. It is the
  // ONLY way a flat name claimed by two upstreams stays callable on both.
  const selector = readServerSelector(params);
  if (selector !== undefined) request.server = selector;

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
 * Owns, in order: the deny-by-default allowlist check (`resolveTool`), the
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

  // #687: attribution is UNKNOWN until the catalogue has resolved the tool.
  //
  // These were derived by splitting `request.name` on its first hyphen, which
  // is a guess — and a wrong one for any upstream whose own name contains a
  // hyphen. They now start empty (so a refusal that happens BEFORE resolution
  // is filed against the flat name the caller actually sent, which is the only
  // thing known at that point) and are retargeted by {@link retarget} the
  // instant the catalogue answers. `fail` reads them through the closure, so
  // every refusal after resolution carries the true owning upstream.
  let details: ToolAuditDetails | undefined;
  let auditTarget = request.name;
  const retarget = (tool: McpTool): void => {
    if (backend !== "mcp") return;
    details = toolAttribution(tool);
    auditTarget =
      request.sessionId === undefined
        ? toolAuditTarget(details.serverName, details.toolName)
        : toolSessionMcpAuditTarget(request.sessionId, details.serverName, details.toolName);
  };

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
  let tool: McpTool;
  if (backend === "builtin") {
    const builtin = builtinTools().find((candidate) => candidate.name === request.name);
    if (builtin === undefined) {
      return fail(404, "tool_not_found", `built-in tool ${request.name} does not exist`);
    }
    if (!hasScope(context.auth, ASSET_READ_SCOPE)) {
      return fail(
        403,
        "tool_denied",
        `built-in tool ${request.name} requires the ${ASSET_READ_SCOPE} scope`,
      );
    }
    tool = builtin;
  } else {
    // #687: the CATALOGUE resolves the name, not a split of it, and `server`
    // narrows to the upstream the caller named before the ambiguity test — that
    // ordering is what keeps both halves of a collision callable.
    const resolution = await ports.upstreams.resolveTool(request.name, request.server);
    if (resolution.kind === "ambiguous") {
      // REFUSING is the security decision. Picking one claimant would dispatch
      // arguments composed for upstream A to upstream B, over B's identity
      // grant (`resolveMcpIdentity` keys on `tool.serverName`) and past B's
      // execute allowlist — the shared session silently crossing the
      // per-server fence it exists to preserve. Nothing has been resolved, so
      // the row stays filed against the flat name the caller sent.
      return fail(
        409,
        "mcp_tool_ambiguous",
        ambiguousToolMessage(resolution.name, resolution.servers),
      );
    }
    if (resolution.kind === "missing") {
      // Deny-by-default: an un-allowlisted or unknown tool is refused here, at
      // the chokepoint, so the refusal is audited exactly once. A `server` that
      // names an upstream not advertising this tool lands here too, and NEVER
      // falls back to another upstream.
      const known = request.name.includes(TOOL_NAMESPACE_SEPARATOR);
      return fail(
        403,
        "tool_denied",
        known
          ? `MCP tool ${request.name} is not allowlisted for execution`
          : `MCP tool ${request.name} must use serverName-toolName namespace`,
      );
    }
    tool = resolution.tool;
  }
  // Everything audited from here on names the upstream that actually owns the
  // tool, whatever the flat name's hyphens suggest.
  retarget(tool);
  // #687: the same fact, told to the client session, so the replay log records
  // WHICH upstream a frame came from. Reported here — after resolution — for
  // exactly the reason the audit target is: only the catalogue knows.
  context.upstreams?.note(tool.serverName);

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
  const read = await readAssetForMcp(ports, context, assetType, name, version);
  if (!read.ok) {
    return {
      ok: false,
      error:
        read.kind === "quota"
          ? assetEgressHttpError(read.error)
          : assetReadHttpError(read.error, assetType, name, version),
    };
  }
  return { ok: true, content: { content: [assetContentEntry(read.asset, read.content)] } };
}

export type McpAssetReadResult = ReadAssetWithEgressResult<StoredAsset, AssetReadFailure>;

/**
 * The one MCP asset read adapter. Both resources/read and builtin.fetch_asset
 * resolve metadata here, then enter billing's gate/read/meter path.
 */
export async function readAssetForMcp(
  ports: McpPorts,
  context: DispatchContext,
  assetType: string,
  name: string,
  version: string,
): Promise<McpAssetReadResult> {
  const tenantId = context.auth.organizationId;
  if (tenantId === undefined) {
    return { ok: false, kind: "read", error: { kind: "not_found" } };
  }
  const assets = await ports.assets.list(tenantId);
  const asset = assets.find(
    (candidate) =>
      candidate.assetType === assetType &&
      candidate.name === name &&
      candidate.version === version,
  );
  if (asset === undefined || !asset.downloadable) {
    return { ok: false, kind: "read", error: { kind: "not_found" } };
  }

  let target: string;
  try {
    target = assetEgressTargetId(asset, tenantId);
  } catch (error) {
    if (error instanceof Error && error.message === ASSET_EGRESS_IDENTITY_ERROR) {
      return {
        ok: false,
        kind: "read",
        error: { kind: "storage", message: "stored asset has no valid durable ID" },
      };
    }
    throw error;
  }

  let result: McpAssetReadResult;
  try {
    result = await readAssetWithEgress<StoredAsset, AssetReadFailure>({
      quota: ports.assetEgress.quota ?? context.egressQuota ?? {},
      apiKeyId: context.auth.apiKeyId ?? "",
      tenantId,
      projectId: context.auth.projectId,
      requestId: context.requestId,
      agentRunId: context.agentRunId,
      asset,
      read: () => ports.assets.read(tenantId, assetType, name, version),
      pricePerGb: ports.assetEgress.pricePerGb,
      counters: ports.assetEgress.counters,
      meter: ports.assetEgress.meter,
      nowUnix: ports.now(),
    });
  } catch (error) {
    if (error instanceof Error && error.message === ASSET_EGRESS_IDENTITY_ERROR) {
      return {
        ok: false,
        kind: "read",
        error: { kind: "storage", message: "stored asset has no valid durable ID" },
      };
    }
    throw error;
  }
  if (!result.ok) return result;
  if (result.charge !== null) {
    target = assetEgressTargetId(result.asset, tenantId);
    ports.audit.record(
      auditEvent(
        context,
        "asset.pull",
        target,
        "served",
        assetPullAuditMessage(target, result.charge.bytes),
      ),
    );
  }
  return result;
}

function assetEgressHttpError(denial: AssetEgressDenial): ToolExecutionHttpError {
  return { status: denial.status, code: denial.code, message: denial.message };
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
