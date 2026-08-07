/**
 * The uniform error envelope.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/responses.rs`
 * (`write_json_error` / `ErrorBody` / `ErrorObject`). Every non-2xx the control
 * plane originates — auth denial, contract miss, Zod rejection, handler throw —
 * leaves through here, so the wire shape is identical for all of them:
 *
 * ```json
 * { "error": { "message": "...", "type": "ferrogate_error",
 *              "code": "invalid_api_key", "request_id": "..." } }
 * ```
 *
 * plus the `x-request-id` / `x-trace-id` headers Rust always attaches.
 */
import { type ErrorKind, FerrogateError, GatewayError } from "@ferrogate/core";
import type { Context, ErrorHandler, MiddlewareHandler, NotFoundHandler } from "hono";
import type { ControlPlaneEnv } from "../ports.js";

/** Rust `ErrorObject`. `type` is always the literal `ferrogate_error`. */
export interface ErrorObject {
  readonly message: string;
  readonly type: "ferrogate_error";
  readonly code: string;
  readonly request_id: string | null;
}

/** Rust `ErrorBody`. */
export interface ErrorBody {
  readonly error: ErrorObject;
}

export const FERROGATE_ERROR_TYPE = "ferrogate_error" as const;

/**
 * A boundary failure with an explicit HTTP status and stable machine-readable
 * code — the TS twin of Rust's `AuthError { status, code, message }`, reused for
 * every originated error so handlers can simply `throw`.
 */
export class HttpError extends Error {
  override readonly name = "HttpError";
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Build the envelope body. */
export function errorBody(code: string, message: string, requestId: string | null): ErrorBody {
  return { error: { message, type: FERROGATE_ERROR_TYPE, code, request_id: requestId } };
}

/** `@ferrogate/core` `ErrorKind` → HTTP status (the Rust error taxonomy). */
const STATUS_BY_KIND: Readonly<Record<ErrorKind, number>> = {
  invalid_request: 400,
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  rate_limited: 429,
  upstream: 502,
  internal: 500,
};

/**
 * `GatewayError` carries only `{ code, message }` (Rust's boundary error has no
 * status), so its status is recovered from the code. These are the codes the
 * Rust admin surface originates; anything unrecognized fails closed as 500.
 */
const STATUS_BY_CODE: Readonly<Record<string, number>> = {
  // --- 401: unauthenticated -------------------------------------------------
  missing_api_key: 401,
  invalid_api_key: 401,
  // --- 403: authenticated but denied ---------------------------------------
  api_key_disabled: 403,
  api_key_expired: 403,
  scope_denied: 403,
  tenant_scope_denied: 403,
  external_auth_denied: 403,
  tenancy_suspended: 403,
  tenancy_deleted: 403,
  guardrail_rbac_denied: 403,
  cross_site_admin_denied: 403,
  // --- 4xx: request shape ---------------------------------------------------
  invalid_request: 400,
  invalid_request_body: 400,
  method_not_allowed: 405,
  not_found: 404,
  conflict: 409,
  payload_too_large: 413,
  // --- 429 ------------------------------------------------------------------
  token_budget_exceeded: 429,
  rate_limited: 429,
  // --- 5xx ------------------------------------------------------------------
  external_auth_unavailable: 503,
  guardrail_rbac_unavailable: 503,
  rbac_unavailable: 503,
  storage_error: 503,
  internal_error: 500,
};

/** Resolve `(status, code, message)` for any thrown value. */
export function classifyError(error: unknown): { status: number; code: string; message: string } {
  if (error instanceof HttpError) {
    return { status: error.status, code: error.code, message: error.message };
  }
  if (error instanceof FerrogateError) {
    return { status: STATUS_BY_KIND[error.kind], code: error.code, message: error.message };
  }
  if (error instanceof GatewayError) {
    return { status: STATUS_BY_CODE[error.code] ?? 500, code: error.code, message: error.message };
  }
  return {
    status: 500,
    code: "internal_error",
    // Never leak an arbitrary throw's text to the client.
    message: "internal server error",
  };
}

/**
 * Write the envelope. Response headers mirror Rust `write_json_error`
 * (`x-request-id`, `x-trace-id`); a 401 additionally advertises the scheme the
 * control plane accepts.
 */
export function writeJsonError(
  c: Context<ControlPlaneEnv>,
  status: number,
  code: string,
  message: string,
): Response {
  const requestId = c.get("requestId") ?? null;
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (requestId !== null) {
    headers["x-request-id"] = requestId;
    headers["x-trace-id"] = requestId;
  }
  if (status === 401) headers["www-authenticate"] = `Bearer error="${code}"`;
  return new Response(JSON.stringify(errorBody(code, message, requestId)), { status, headers });
}

/** Hono `onError` — every throw becomes the uniform envelope. */
export const controlPlaneErrorHandler: ErrorHandler<ControlPlaneEnv> = (error, c) => {
  const { status, code, message } = classifyError(error);
  // A 5xx is an UNEXPECTED server fault. `classifyError` deliberately never
  // leaks an arbitrary throw's text to the client ("internal server error"), so
  // without this line the cause is lost entirely — an operator sees a 500 with
  // no way to tell whether it was a missing table, a null field or an outage.
  // `console.warn` reaches the Worker log stream (the same channel the request
  // log uses). 4xx are expected client errors and stay quiet.
  if (status >= 500) {
    const requestId = c.get("requestId") ?? "unknown";
    console.warn(
      `[ferrogate] control-plane ${code} (${status}) on ${c.req.method} ${c.req.path} [request ${requestId}]: ${
        error instanceof Error ? (error.stack ?? error.message) : String(error)
      }`,
    );
  }
  return writeJsonError(c, status, code, message);
};

/** Hono `notFound` — an undocumented path, in the same envelope. */
export const controlPlaneNotFoundHandler: NotFoundHandler<ControlPlaneEnv> = (c) =>
  writeJsonError(c, 404, "not_found", `no route for ${c.req.method} ${c.req.path}`);

/**
 * Assigns the request id every response echoes. Rust mints a monotonic id per
 * request (`AppState::next_request_id`); a Worker isolate has no such counter,
 * so an inbound `x-request-id` is honoured and otherwise a UUID is minted.
 */
export const requestId: MiddlewareHandler<ControlPlaneEnv> = async (c, next) => {
  const inbound = c.req.header("x-request-id")?.trim();
  c.set("requestId", inbound !== undefined && inbound !== "" ? inbound : crypto.randomUUID());
  await next();
  const id = c.get("requestId");
  if (id !== undefined && !c.res.headers.has("x-request-id")) {
    c.res.headers.set("x-request-id", id);
    c.res.headers.set("x-trace-id", id);
  }
};
