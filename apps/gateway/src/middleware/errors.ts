/**
 * The uniform error envelope.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/responses.rs`
 * (`write_json_error` / `ErrorBody` / `ErrorObject`). Every non-2xx the gateway
 * originates — auth denial, contract miss, handler throw — leaves through here,
 * so the wire shape is identical for all of them:
 *
 * ```json
 * { "error": { "message": "...", "type": "ferrogate_error",
 *              "code": "invalid_api_key", "request_id": "..." } }
 * ```
 *
 * plus the `x-request-id` / `x-trace-id` response headers Rust always attaches.
 */
import { type ErrorKind, FerrogateError, GatewayError } from "@ferrogate/core";
import type { Context, ErrorHandler, MiddlewareHandler, NotFoundHandler } from "hono";
import type { GatewayEnv } from "../ports.js";
import { ingressTraceContext } from "./trace.js";

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
  /**
   * Extra response headers this refusal carries (#726).
   *
   * The rate limiter is the only producer today: a 429 has to tell the caller
   * when to come back and against which window (`src/ratelimit/headers.ts`).
   * It lives on the error rather than on a wrapper because the throw is the
   * only thing that crosses from the middleware to `onError`, and the previous
   * attempt — stashing `retryAfterSeconds` on the error for "a wrapper that
   * wants to emit it" — was never read by anything, which is precisely how the
   * gateway ended up with an opt-in header that no opt-in could switch on.
   */
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
 * status), so its status is recovered from the code. Codes below are the ones
 * the Rust gateway originates; anything unrecognized fails closed as 500.
 */
const STATUS_BY_CODE: Readonly<Record<string, number>> = {
  // --- 401: unauthenticated -------------------------------------------------
  missing_api_key: 401,
  invalid_api_key: 401,
  invalid_self_hosted_worker_identity: 401,
  // --- 403: authenticated but denied ---------------------------------------
  // `ip_denied` is PRE-auth (Rust `check_network_access`): the caller never got
  // as far as presenting a credential.
  ip_denied: 403,
  api_key_disabled: 403,
  api_key_expired: 403,
  scope_denied: 403,
  tenant_scope_denied: 403,
  external_auth_denied: 403,
  inactive_self_hosted_worker: 403,
  tenancy_suspended: 403,
  tenancy_deleted: 403,
  tenancy_disabled: 403,
  tenancy_inactive: 403,
  guardrail_rbac_denied: 403,
  // --- 4xx: request shape ---------------------------------------------------
  invalid_request: 400,
  method_not_allowed: 405,
  not_found: 404,
  self_hosted_worker_payload_too_large: 413,
  // --- 429 ------------------------------------------------------------------
  token_budget_exceeded: 429,
  rate_limited: 429,
  unauthenticated_rate_limited: 429,
  // --- 5xx ------------------------------------------------------------------
  network_access_misconfigured: 503,
  external_auth_unavailable: 503,
  guardrail_rbac_unavailable: 503,
  lifecycle_status_unavailable: 503,
  upstream_error: 502,
  internal_error: 500,
};

/** Resolve `(status, code)` for any thrown value. */
export function classifyError(error: unknown): {
  status: number;
  code: string;
  message: string;
  /** #726 — refusal-specific headers, present only on an {@link HttpError}. */
  headers?: Readonly<Record<string, string>>;
} {
  if (error instanceof HttpError) {
    return {
      status: error.status,
      code: error.code,
      message: error.message,
      headers: error.headers,
    };
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

/** Status for a bare `@ferrogate/core` error kind (exported for adapters). */
export function statusForErrorKind(kind: ErrorKind): number {
  return STATUS_BY_KIND[kind];
}

/**
 * Write the envelope. Response headers mirror Rust `write_json_error`
 * (`x-request-id`, `x-trace-id`); a 401 additionally advertises the scheme the
 * gateway accepts.
 */
export function writeJsonError(
  c: Context<GatewayEnv>,
  status: number,
  code: string,
  message: string,
  extra: Readonly<Record<string, string>> = {},
): Response {
  const requestId = c.get("requestId") ?? null;
  // `extra` FIRST, so nothing a refusal supplies can displace the correlation
  // ids or the `www-authenticate` challenge written below it.
  const headers: Record<string, string> = { ...extra, "content-type": "application/json" };
  if (requestId !== null) {
    headers["x-request-id"] = requestId;
    // The Anthropic SDK reads `err.requestID` from the distinct `request-id`
    // header. Emit it alongside `x-request-id` so both SDKs can correlate errors.
    headers["request-id"] = requestId;
    // The ADOPTED trace id when the caller arrived inside a trace, else the
    // request id — see `./trace.ts`. An error is exactly the response a caller
    // most needs to correlate, so the two must not diverge here.
    headers["x-trace-id"] = c.get("traceId") ?? requestId;
  }
  if (status === 401) {
    headers["www-authenticate"] = `Bearer error="${code}"`;
  }
  return new Response(JSON.stringify(errorBody(code, message, requestId)), { status, headers });
}

/** Hono `onError` — every throw becomes the uniform envelope. */
export const gatewayErrorHandler: ErrorHandler<GatewayEnv> = (error, c) => {
  const { status, code, message, headers } = classifyError(error);
  return writeJsonError(c, status, code, message, headers ?? {});
};

/**
 * The envelope BOUNDARY — a `try`/`catch` around `next()` (issue #733).
 *
 * ## Why `app.onError` is not enough, measured
 *
 * Hono's `compose` only routes an `Error` to the error handler:
 *
 * ```js
 * catch (err) {
 *   if (err instanceof Error && onError) { res = await onError(err, context) }
 *   else { throw err }        //  <-- everything else leaves the app
 * }
 * ```
 *
 * So a thrown STRING (or object, or `null`) — which is what a hand-written
 * port's `throw "unreachable"` and several third-party libraries produce —
 * propagates straight out of `app.fetch` and the client gets workerd's own
 * `text/plain` 500. `gatewayErrorHandler` is registered and simply never runs.
 * `test/inference/error-envelope.test.ts` pins this with a literal throw; it
 * was RED with the handler in place, which is the whole reason this middleware
 * exists rather than a better `onError`.
 *
 * A `catch` here is not the "wrap everything and stringify" this issue warns
 * against: nothing about the caught value is copied onto the wire.
 * `classifyError` keeps an `HttpError`/`FerrogateError`/`GatewayError`'s own
 * status, code and message — so a refusal that already had a taxonomy keeps it
 * — and gives everything else the constant `500 internal_error /
 * "internal server error"`.
 *
 * ## Why it is mounted TWICE
 *
 * Position is the difference between one failure and two. Mounted only at the
 * top, a throw below `requestLogging()` unwinds past that middleware's
 * `await next()` and no `request_logs` row is ever written — the outage the
 * client saw would leave no durable evidence at all (#664). Mounted only at the
 * bottom, a throw raised BY one of the cross-cutting middlewares (or by the
 * auth guard) is outside its window again.
 *
 * So `createGatewayApp` mounts it immediately below `requestMetrics` and again
 * immediately above the routes. The inner mount converts a handler's throw into
 * a `Response` that every middleware above it — the request log, the metering
 * drain, the telemetry emitter, the status counters — observes normally; the
 * outer mount is the last line for everything else. The two are idempotent: the
 * inner one has already produced a `Response`, so the outer one catches nothing
 * on that path.
 */
export const envelopeBoundary: MiddlewareHandler<GatewayEnv> =
  async function envelopeBoundaryMiddleware(c, next) {
    try {
      await next();
    } catch (error) {
      const { status, code, message } = classifyError(error);
      c.res = writeJsonError(c, status, code, message);
    }
  };

/** Hono `notFound` — an undocumented path, in the same envelope. */
export const gatewayNotFoundHandler: NotFoundHandler<GatewayEnv> = (c) =>
  writeJsonError(c, 404, "not_found", `no route for ${c.req.method} ${c.req.path}`);

/**
 * Assigns the request id every response echoes. Rust mints a monotonic id per
 * request (`AppState::next_request_id`); a Worker isolate has no such counter,
 * so an inbound `x-request-id` is honoured and otherwise a UUID is minted.
 */
export const requestId: MiddlewareHandler<GatewayEnv> = async (c, next) => {
  const inbound = c.req.header("x-request-id")?.trim();
  const id = inbound !== undefined && inbound !== "" ? inbound : crypto.randomUUID();
  c.set("requestId", id);

  // W3C trace-context ingress (Rust `ingress_trace_context`, step 3): a valid
  // inbound `traceparent` donates its trace id, so a caller's distributed trace
  // survives this hop. With no header — or a malformed one — the trace id IS
  // the request id, which is the behaviour every existing assertion pins.
  const trace = ingressTraceContext(c.req.raw.headers, id);
  c.set("traceId", trace.traceId);
  c.set("traceparent", trace.traceparent ?? null);
  c.set("tracestate", trace.tracestate ?? null);

  await next();
  if (!c.res.headers.has("x-request-id")) {
    c.res.headers.set("x-request-id", id);
    c.res.headers.set("request-id", id);
    c.res.headers.set("x-trace-id", trace.traceId);
  }
};
