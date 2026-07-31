/**
 * The FerroGate error envelope and the response-header contract every
 * inference operation writes.
 *
 * Clean-room port of `ferrogate-gateway/src/responses.rs`
 * (`ErrorBody`/`ErrorObject`, `write_json_error`, `write_json_response`,
 * `write_streaming_response`). See `docs/legacy/inventory-request-path.md` §1.4
 * ("Error envelope (every error path)") and §1.5.
 *
 * Wire shape, byte-identical to the Rust one:
 *
 * ```json
 * { "error": { "message": "...", "type": "ferrogate_error",
 *              "code": "invalid_request", "request_id": "fg-0000000000000001" } }
 * ```
 *
 * Key ordering matters for byte-level parity with the Rust `#[derive(Serialize)]`
 * struct (serde emits fields in declaration order), so the object literal below
 * is written in exactly that order and must not be reshuffled.
 */
import type { Context } from "hono";

/** `ErrorObject::kind` — the single constant `type` discriminator. */
export const FERROGATE_ERROR_TYPE = "ferrogate_error" as const;

/**
 * Value of the `x-ferrogate-runtime` response header.
 *
 * The Rust proxy wrote `"pingora"`. The Pingora data plane is eliminated by
 * this rewrite (PORT-PLAN "the single largest new build"), so the marker names
 * the runtime that actually served the request. This is a rename of a
 * diagnostic header, not a dropped behavior — the header itself is preserved.
 */
export const GATEWAY_RUNTIME = "workers" as const;

/** `ErrorObject` — the inner member of the envelope. */
export interface FerrogateErrorObject {
  readonly message: string;
  readonly type: typeof FERROGATE_ERROR_TYPE;
  readonly code: string;
  readonly request_id: string | null;
}

/** `ErrorBody` — the whole error response body. */
export interface FerrogateErrorEnvelope {
  readonly error: FerrogateErrorObject;
}

/** Build the envelope without touching a `Response` (used by tests + logs). */
export function errorEnvelope(
  code: string,
  message: string,
  requestId: string | null,
): FerrogateErrorEnvelope {
  return {
    error: {
      message,
      type: FERROGATE_ERROR_TYPE,
      code,
      request_id: requestId,
    },
  };
}

/**
 * Headers `write_json_response` / `write_streaming_response` set on *every*
 * gateway-originated response. `x-trace-id` deliberately mirrors the request id
 * exactly as the Rust code did.
 *
 * PORT-TODO(inventory-request-path §1.3): `apply_cors_headers` runs on EVERY
 * Rust-originated response (`responses.rs`, 9 call sites) and is **not ported
 * anywhere in `apps/gateway`** — re-checked, and the handoff this comment used
 * to describe as done has not been taken.
 *
 * Still correct that it does not belong here: CORS is app-wide, it must also
 * cover the ~245 non-inference operations, and it needs an `OPTIONS` preflight
 * route, which is a router concern. Duplicating it per module is how the
 * `Vary` header ends up on some responses and not others.
 *
 * Where it goes and what it must do, so the next owner does not have to
 * re-derive it from `crates/`:
 *
 *   - a middleware in `apps/gateway/src/index.ts` (out of this slice's scope);
 *   - reads one operator-configured origin (Rust: the `CORS_ALLOWED_ORIGIN`
 *     `OnceLock`, i.e. a Worker var here). **Unset ⇒ emit nothing at all** —
 *     that is the Rust default and it is a fail-closed one, so a port that
 *     hardcodes `*` would be strictly more permissive than the tree it
 *     replaces;
 *   - when set: `access-control-allow-origin: <origin>` + `vary: origin` on
 *     every response;
 *   - `write_cors_preflight_response`: `OPTIONS` ⇒ **204** with
 *     `content-length: 0`, `access-control-allow-methods: GET, POST, PUT,
 *     PATCH, DELETE, OPTIONS`, `access-control-allow-headers: authorization,
 *     content-type, x-api-key`, `access-control-max-age: 600` — and only when
 *     an origin is configured.
 *
 * `apps/control-plane/src/middleware/cors.ts` is the sibling port to copy the
 * shape from. Until it lands, a browser cannot call this gateway cross-origin.
 */
export function gatewayHeaders(requestId: string): Record<string, string> {
  return {
    "x-request-id": requestId,
    "x-trace-id": requestId,
    "x-ferrogate-runtime": GATEWAY_RUNTIME,
  };
}

/** A rejection that has already been classified into the Rust status+code pair. */
export interface InferenceRejection {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

/** Construct an {@link InferenceRejection} (mirrors the Rust `*Rejection` structs). */
export function reject(status: number, code: string, message: string): InferenceRejection {
  return { status, code, message };
}

/**
 * Render an {@link InferenceRejection} as the JSON error envelope.
 *
 * Uses a raw `Response` rather than `c.json` so the serialized key order is
 * exactly the order written above (Hono's `c.json` would too, but going through
 * `JSON.stringify` here keeps the guarantee local and testable).
 */
export function errorResponse(rejection: InferenceRejection, requestId: string): Response {
  const body = JSON.stringify(errorEnvelope(rejection.code, rejection.message, requestId));
  return new Response(body, {
    status: rejection.status,
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      ...gatewayHeaders(requestId),
    },
  });
}

/** Success counterpart of {@link errorResponse} — `write_json_response`. */
export function jsonResponse(value: unknown, requestId: string, status = 200): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      ...gatewayHeaders(requestId),
    },
  });
}

/**
 * Relay an upstream provider body through untouched.
 *
 * The Rust `write_raw_response` path echoes the provider's status and
 * `Content-Type` so a provider-side 429/400 reaches the caller with the
 * provider's own error object rather than being reshaped into the FerroGate
 * envelope (`inventory-request-path` §1.6 — only *transport* failures become
 * `provider_dispatch_error`).
 */
export function rawUpstreamResponse(
  status: number,
  contentType: string,
  body: string,
  requestId: string,
): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": contentType,
      "content-length": String(new TextEncoder().encode(body).byteLength),
      ...gatewayHeaders(requestId),
    },
  });
}

/** Hono-flavoured wrapper so handlers can `return errorFor(c, ...)`. */
export function errorFor(
  c: Context,
  requestId: string,
  status: number,
  code: string,
  message: string,
): Response {
  void c;
  return errorResponse(reject(status, code, message), requestId);
}
