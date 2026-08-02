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
import { classifyError } from "../middleware/errors.js";

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
 * PORT-TODO(P: inventory-request-path §1.3): `apply_cors_headers` runs on EVERY
 * Rust-originated response (`responses.rs`, 9 call sites — re-counted this pass,
 * still 9) and is **not ported anywhere in `apps/gateway`**.
 *
 * ## THE ONE GENUINELY MISSING BEHAVIOR IN THIS POCKET
 *
 * Re-verified wave 5: `grep -rl "access-control-allow-origin" apps/**\/*.ts`
 * returns `apps/control-plane/src/middleware/cors.ts` (+ its test) and THIS
 * comment. Nothing under `apps/gateway/src/` emits a CORS header.
 *
 * This is NOT a platform limit and NOT a reproduced-Rust quirk — Workers do
 * this trivially, and `apps/control-plane` already does it. It is the only
 * marker in `inference/` + `streaming/` that names real, portable, unwritten
 * work, and it has now survived five burndown waves for ONE reason: every
 * agent that could write it is scoped to a directory that must not own it.
 * Consequence, stated plainly: a browser cannot call this gateway
 * cross-origin at all.
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
 * The code an unparseable upstream ERROR body is answered with (issue #733).
 *
 * Deliberately NOT `internal_error`: nothing about this failure is internal,
 * and a code that is always `internal_error` tells a caller no more than the
 * status line already did. It names the one thing that happened — the provider
 * refused, and the refusal did not arrive in a shape anybody can read — which
 * is the difference between "retry the provider" and "FerroGate is broken".
 */
export const PROVIDER_INVALID_ERROR_BODY = "provider_invalid_error_body" as const;

/** True when `text` decodes to a JSON OBJECT, i.e. something a client can read. */
function isJsonObjectBody(text: string): boolean {
  try {
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

/**
 * The `content-type` as it may appear inside an error MESSAGE.
 *
 * A header value is attacker-adjacent (it is chosen by whatever answered the
 * upstream request, which on a bad day is a captive portal), so only the media
 * type survives, only from a conservative charset, and only to 64 characters.
 * The envelope must never become a channel for an upstream's bytes.
 */
function safeMediaType(contentType: string): string {
  const media = (contentType.split(";")[0] ?? "").trim().toLowerCase();
  const cleaned = media.replaceAll(/[^a-z0-9!#$&^_.+-/]/g, "");
  return cleaned.length === 0 ? "unknown" : cleaned.slice(0, 64);
}

/**
 * Relay an upstream provider body through — verbatim when it is usable, in the
 * FerroGate envelope when it is not.
 *
 * The Rust `write_raw_response` path echoes the provider's status and
 * `Content-Type` so a provider-side 429/400 reaches the caller with the
 * provider's own error object rather than being reshaped into the FerroGate
 * envelope (`inventory-request-path` §1.6 — only *transport* failures became
 * `provider_dispatch_error`). That relay is still the default and it is worth
 * keeping: the provider's `type`/`param`/`code` are the caller's best
 * diagnostic, and reshaping them would break every client that switches on
 * them (`tools/sdk-conformance/test/errors.test.ts` pins exactly that).
 *
 * ## The exception, and why it is an exception (issue #733)
 *
 * When a CDN or a load balancer in front of the provider answers an error with
 * an HTML page, the verbatim relay puts markup on the wire under a 5xx: the
 * SDK's `err.error`, `err.code` and `err.type` are all `undefined` and
 * `err.message` is a chunk of `<html>`. From the caller's side that is the SAME
 * CLASS OF EVENT as a transport failure — the provider did not answer usefully
 * — and FerroGate already wraps a transport failure in its own envelope
 * (`502 provider_dispatch_error`). The asymmetry was the defect.
 *
 * Three decisions, all deliberate:
 *
 *  - the wrap is keyed on the BODY being unreadable (not JSON, or JSON that is
 *    not an object), never on the media type. A provider that mislabels a JSON
 *    error `text/plain` still gets relayed, and a provider that labels an HTML
 *    page `application/json` still gets wrapped;
 *  - the UPSTREAM STATUS is preserved rather than collapsed to 502. A 429 is
 *    paced, a 503 is retried and a 500 is not; flattening them would delete the
 *    only distinction the caller still had;
 *  - the upstream bytes are DROPPED, not truncated into the message. An error
 *    page is where a backend leaks its own internals (server banners, internal
 *    hostnames, occasionally a key echoed back), and none of that is FerroGate's
 *    to forward. What survives is the status and the media type, sanitized.
 *
 * Success bodies are untouched at any content type: `/v1/embeddings` and
 * `/v1/images` pass 2xx bytes through byte-for-byte and this rule must not
 * reach them.
 */
export function rawUpstreamResponse(
  status: number,
  contentType: string,
  body: string,
  requestId: string,
): Response {
  if (status >= 400 && !isJsonObjectBody(body)) {
    return errorResponse(
      reject(
        status,
        PROVIDER_INVALID_ERROR_BODY,
        `provider answered ${status} with an unreadable error body ` +
          `(content-type ${safeMediaType(contentType)})`,
      ),
      requestId,
    );
  }
  return new Response(body, {
    status,
    headers: {
      "content-type": contentType,
      "content-length": String(new TextEncoder().encode(body).byteLength),
      ...gatewayHeaders(requestId),
    },
  });
}

/**
 * Render ANY thrown value as the envelope (issue #733).
 *
 * The classification is `middleware/errors.ts::classifyError`, reused rather
 * than re-derived: an `HttpError`/`FerrogateError`/`GatewayError` keeps its own
 * status, code and message, and anything else becomes
 * `500 internal_error / "internal server error"`.
 *
 * That last arm is the security boundary, and the reason this function exists
 * instead of a `catch` that stringifies. An `Error` raised deep in a provider
 * port routinely carries the credential it was using, the upstream URL it was
 * calling or the binding name that was missing, and its `stack` names every
 * source file in the request path. None of it is the caller's, so the message
 * on the unknown arm is a CONSTANT — `classifyError` never copies `error`.
 */
export function envelopeForThrown(error: unknown, requestId: string): Response {
  const { status, code, message } = classifyError(error);
  return errorResponse(reject(status, code, message), requestId);
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
