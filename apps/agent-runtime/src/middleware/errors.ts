import { GatewayError } from "@ferrogate/core";
/**
 * The uniform error envelope.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/responses.rs`
 * (`write_json_error` / `ErrorBody` / `ErrorObject`). Every non-2xx this Worker
 * originates leaves through here, so the wire shape is identical for all of
 * them:
 *
 * ```json
 * { "error": { "message": "...", "type": "ferrogate_error",
 *              "code": "invalid_api_key", "request_id": "..." } }
 * ```
 *
 * plus the `x-request-id` / `x-trace-id` response headers Rust always attaches.
 */
import type { Context, ErrorHandler, MiddlewareHandler, NotFoundHandler } from "hono";
import type { AgentRuntimeEnv } from "../ports.js";

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
 * A boundary failure with an explicit HTTP status and a stable machine-readable
 * code — the TS twin of Rust's `AuthError { status, code, message }`, reused for
 * every originated error so handlers can simply `throw`.
 */
export class HttpError extends Error {
  override readonly name = "HttpError";
  readonly status: number;
  readonly code: string;
  readonly headers: Readonly<Record<string, string>>;

  constructor(
    status: number,
    code: string,
    message: string,
    headers: Readonly<Record<string, string>> = {},
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

/** Build the envelope body. */
export function errorBody(code: string, message: string, requestId: string | null): ErrorBody {
  return { error: { message, type: FERROGATE_ERROR_TYPE, code, request_id: requestId } };
}

/**
 * `GatewayError` carries only `{ code, message }` (Rust's boundary error has no
 * status), so its status is recovered from the code. Anything unrecognized
 * fails closed as 500.
 */
const STATUS_BY_CODE: Readonly<Record<string, number>> = {
  missing_api_key: 401,
  invalid_api_key: 401,
  invalid_self_hosted_worker_identity: 401,
  invalid_self_hosted_worker_transport_security: 401,
  api_key_disabled: 403,
  api_key_expired: 403,
  scope_denied: 403,
  tenant_scope_denied: 403,
  inactive_self_hosted_worker: 403,
  tenancy_suspended: 403,
  agent_runtime_disabled: 403,
  invalid_request: 400,
  method_not_allowed: 405,
  not_found: 404,
  agent_job_not_terminal: 409,
  self_hosted_worker_payload_too_large: 413,
  payload_too_large: 413,
  agent_job_open_limit_reached: 429,
  rate_limited: 429,
  agent_job_dispatch_unavailable: 503,
  agent_runtime_unavailable: 503,
};

function statusForCode(code: string): number {
  return STATUS_BY_CODE[code] ?? 500;
}

function requestIdOf(c: Context<AgentRuntimeEnv>): string | null {
  return c.get("requestId") ?? null;
}

/** Write the envelope with the correlation headers Rust always attaches. */
export function writeError(
  c: Context<AgentRuntimeEnv>,
  status: number,
  code: string,
  message: string,
  headers: Readonly<Record<string, string>> = {},
): Response {
  const requestId = requestIdOf(c);
  const response = Response.json(errorBody(code, message, requestId), {
    status,
    headers: { ...headers },
  });
  if (requestId !== null) response.headers.set("x-request-id", requestId);
  const traceId = c.get("traceId");
  if (traceId !== undefined) response.headers.set("x-trace-id", traceId);
  return response;
}

/** Hono `onError`: every throw becomes the same envelope. */
export const errorHandler: ErrorHandler<AgentRuntimeEnv> = (err, c) => {
  if (err instanceof HttpError) {
    return writeError(c, err.status, err.code, err.message, err.headers);
  }
  if (err instanceof GatewayError) {
    return writeError(c, statusForCode(err.code), err.code, err.message);
  }
  // Never leak an internal message shape; the request id is the join key.
  return writeError(c, 500, "internal_error", "internal error");
};

/** Hono `notFound`: same envelope, so a miss is not distinguishable in shape. */
export const notFoundHandler: NotFoundHandler<AgentRuntimeEnv> = (c) =>
  writeError(c, 404, "not_found", "resource not found");

/**
 * Stamp `request_id` / `trace_id` on every request, honoring the caller's
 * `x-request-id` when present (Rust `ProxyContext::request_id`).
 */
export const correlation: MiddlewareHandler<AgentRuntimeEnv> = async (c, next) => {
  const inbound = c.req.header("x-request-id")?.trim();
  c.set("requestId", inbound !== undefined && inbound !== "" ? inbound : crypto.randomUUID());
  const trace = c.req.header("x-trace-id")?.trim();
  if (trace !== undefined && trace !== "") c.set("traceId", trace);
  await next();
  const requestId = c.get("requestId");
  if (requestId !== undefined) c.res.headers.set("x-request-id", requestId);
  const traceId = c.get("traceId");
  if (traceId !== undefined) c.res.headers.set("x-trace-id", traceId);
};
