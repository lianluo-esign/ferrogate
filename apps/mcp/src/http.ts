/**
 * Shared HTTP-boundary helpers: the FerroGate error envelope, request identity,
 * and body-size admission.
 *
 * Mirrors `crates/ferrogate-gateway/src/responses.rs`
 * (`write_json_error` / `write_json_response`) so the wire shape of an MCP
 * failure is identical to every other FerroGate surface.
 */
import type { Context } from "hono";

import { declaredAgentRunId, MCP_ORIGINAL_BEARER_HEADER } from "./protocol.js";
import {
  isAuthError,
  type AuthContext,
  type AuthError,
  type DispatchContext,
  type McpPorts,
} from "./ports.js";

/** Maximum request body this Worker reads. Port of `limits().tool_body_max_bytes()`. */
export const TOOL_BODY_MAX_BYTES = 1024 * 1024;

/** The FerroGate error envelope. */
export interface ErrorEnvelope {
  error: { code: string; message: string; request_id: string };
}

export function errorEnvelope(code: string, message: string, requestId: string): ErrorEnvelope {
  return { error: { code, message, request_id: requestId } };
}

/** Per-request identity. `x-request-id` is honoured, else one is minted. */
export function requestIdentity(request: Request): { requestId: string; traceId?: string } {
  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const traceId = request.headers.get("x-trace-id") ?? undefined;
  return traceId === undefined ? { requestId } : { requestId, traceId };
}

/**
 * Read the request body with a hard cap, refusing an over-limit payload with
 * `413 payload_too_large` before it is buffered.
 */
export async function readCappedBody(
  request: Request,
  maxBytes = TOOL_BODY_MAX_BYTES,
): Promise<{ ok: true; body: string } | { ok: false; maxBytes: number }> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number.parseInt(declared, 10);
    if (Number.isFinite(length) && length > maxBytes) return { ok: false, maxBytes };
  }
  const body = await request.text();
  // `content-length` may be absent (chunked) or lie; re-check the real size.
  if (new TextEncoder().encode(body).byteLength > maxBytes) return { ok: false, maxBytes };
  return { ok: true, body };
}

export type AuthOutcome =
  | { ok: true; context: DispatchContext }
  | { ok: false; status: number; body: ErrorEnvelope };

/**
 * Authenticate, then build the {@link DispatchContext} — including the
 * validated `x-ferrogate-agent-run-id` (#522).
 *
 * `surface` labels the unjoinable-action metric. An absent declaration is the
 * "unjoinable action" signal: it is counted per authenticated tenant and
 * surface, and NEVER fabricated.
 */
export async function authenticateRequest(
  ports: McpPorts,
  request: Request,
  requiredScope: string,
  surface: string,
): Promise<AuthOutcome> {
  const { requestId, traceId } = requestIdentity(request);

  const agentRunId = declaredAgentRunId(request.headers);
  if (!agentRunId.ok) {
    return {
      ok: false,
      status: 400,
      body: errorEnvelope("invalid_agent_run_id_header", agentRunId.message, requestId),
    };
  }

  const authenticated: AuthContext | AuthError = await ports.auth.authenticate(
    request.headers,
    requiredScope,
  );
  if (isAuthError(authenticated)) {
    return {
      ok: false,
      status: authenticated.status,
      body: errorEnvelope(authenticated.code, authenticated.message, requestId),
    };
  }

  if (agentRunId.value === undefined) {
    ports.metrics.recordUnjoinableAction(governedActionTenantKey(authenticated), surface);
  }

  const context: DispatchContext = { requestId, auth: authenticated };
  if (traceId !== undefined) context.traceId = traceId;
  if (agentRunId.value !== undefined) context.agentRunId = agentRunId.value;
  const originalBearer = request.headers.get(MCP_ORIGINAL_BEARER_HEADER);
  if (originalBearer !== null) context.originalBearer = originalBearer;
  return { ok: true, context };
}

/**
 * The low-cardinality tenant key used both as the metric label and as the match
 * key for per-tenant enforcement. Derived ONLY from the authenticated tenant
 * context (never a client-declared value), preferring the broadest stable scope
 * down to the api key. Empty when the identity carries no tenant attribution.
 */
export function governedActionTenantKey(auth: AuthContext): string {
  return (
    auth.organizationId ??
    auth.teamId ??
    auth.projectId ??
    auth.workspaceId ??
    auth.userId ??
    auth.apiKeyId ??
    ""
  );
}

/** Render a FerroGate error envelope on a Hono context. */
export function respondError(c: Context, status: number, body: ErrorEnvelope): Response {
  return c.json(body as unknown as Record<string, unknown>, status as 400);
}
