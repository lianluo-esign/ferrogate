/**
 * Shared HTTP-boundary helpers: the FerroGate error envelope, request identity,
 * and body-size admission.
 *
 * Mirrors `crates/ferrogate-gateway/src/responses.rs`
 * (`write_json_error` / `write_json_response`) so the wire shape of an MCP
 * failure is identical to every other FerroGate surface.
 */
import type { Context } from "hono";

import { type WalletHold, releaseAll } from "./admission/index.js";
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
 * Reservations taken during admission, per in-flight request.
 *
 * The TS stand-in for Rust's `Drop`: `finalize_auth` took a
 * `WalletCreditReservation` and the guard released it when it fell out of
 * scope, whatever the outcome. JS has no destructor, so the holds are parked
 * here against the `Request` object and drained by ONE `finally` in
 * `src/routes/index.ts`, which wraps every registered operation. Keying on the
 * request (rather than returning them for each handler to remember) is what
 * makes the release impossible to forget at a call site.
 *
 * A `WeakMap` so a request that never reaches the drain — one that throws
 * before the router's `finally`, which cannot happen today — is collected
 * rather than leaked. The durable hold additionally carries an
 * `expires_at_unix`, which is the second release for the case a `finally`
 * cannot cover at all: an isolate that dies mid-request.
 */
const inFlightHolds = new WeakMap<Request, WalletHold[]>();

/** Release and forget every admission hold this request took. Never throws. */
export async function releaseAdmissionHolds(request: Request): Promise<void> {
  const holds = inFlightHolds.get(request);
  if (holds === undefined) return;
  inFlightHolds.delete(request);
  await releaseAll(holds);
}

/** Test seam: how many holds are still parked against a request. */
export function pendingAdmissionHolds(request: Request): number {
  return inFlightHolds.get(request)?.length ?? 0;
}

/**
 * Authenticate, ADMIT, then build the {@link DispatchContext} — including the
 * validated `x-ferrogate-agent-run-id` (#522).
 *
 * The two halves are Rust's two halves of `authenticate()`, in Rust's order:
 *
 *  1. `ports.auth` resolves the CREDENTIAL — 401 for anything unknown,
 *     disabled, revoked or expired; 403 only for a resolved caller missing the
 *     operation's scope.
 *  2. `ports.admission` is `auth.rs::finalize_auth` — 403 `quota_scope_disabled`,
 *     429 `monthly_budget_exceeded` / `wallet_balance_exhausted` /
 *     `rate_limit_exceeded`, 503 on any lookup failure.
 *
 * Running admission SECOND is the control, not a convenience: an under-scoped
 * caller must be refused without charging a counter, or a client with the wrong
 * scope could drain the RPM budget of the calls that ARE allowed.
 *
 * This function is called by all five authenticated MCP surfaces, which is what
 * makes the gate un-bypassable — in the Rust tree the equivalent property came
 * from `finalize_auth` living inside `authenticate()` itself.
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

  // THE ADMISSION HALF. Deleting this block re-opens the bypass recorded as
  // finding D1 in `docs/rewrite/CUTOVER-READINESS.md`: a credential at its RPM
  // ceiling, over its monthly budget or with an empty prepaid wallet is refused
  // on `/v1/chat/completions` and admitted here — and `tools/call` spends real
  // provider money. `test/admission.test.ts` drives that over `SELF`.
  const admitted = await ports.admission.admit(authenticated, requestId);
  if (!admitted.ok) {
    return {
      ok: false,
      status: admitted.error.status,
      body: errorEnvelope(admitted.error.code, admitted.error.message, requestId),
    };
  }
  if (admitted.holds.length > 0) {
    inFlightHolds.set(request, [...(inFlightHolds.get(request) ?? []), ...admitted.holds]);
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
