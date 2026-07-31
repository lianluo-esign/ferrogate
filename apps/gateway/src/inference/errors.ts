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
 * PORT-TODO(inventory-request-path §1.3): `apply_cors_headers` is applied by
 * the Rust writer too. CORS is an app-wide concern owned by the router shell
 * (`apps/gateway/src/index.ts`), not by the inference module, so it is not
 * duplicated here.
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
