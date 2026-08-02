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

// ---------------------------------------------------------------------------
// The pacing contract (#726) — upstream rate-limit headers, relayed
// ---------------------------------------------------------------------------

/**
 * Header-name PREFIXES whose whole family is relayed from the upstream.
 *
 * A prefix rule rather than a name table, and that is the safe direction here:
 * the values travel VERBATIM, so a provider that adds a dimension
 * (`x-ratelimit-limit-input-images`, `anthropic-ratelimit-input-tokens-reset`)
 * reaches the client with the name its own SDK is looking for instead of
 * waiting on a table update here. The risk a table would guard against —
 * emitting a subtly wrong NAME — does not exist for a pass-through.
 *
 * Deliberately narrow all the same: this is an allowlist of two documented
 * rate-limit families, not "copy the upstream's headers". A blanket copy would
 * hand the caller the provider's `x-request-id` (breaking the correlation id
 * that is also in our body), its `set-cookie`, and its org identifiers.
 */
export const RATE_LIMIT_RELAY_PREFIXES: readonly string[] = [
  // OpenAI, Azure OpenAI, Groq, Together, Fireworks, DeepSeek, xAI…
  "x-ratelimit-",
  // Anthropic's native family (`anthropic-ratelimit-requests-remaining`, …).
  "anthropic-ratelimit-",
];

/**
 * Exact header names relayed alongside the families above.
 *
 * `retry-after` is the RFC 9110 one both official SDKs read first;
 * `retry-after-ms` is OpenAI's sub-second refinement, which its SDK PREFERS
 * when present. Dropping either is what forces a client onto a blind
 * exponential schedule.
 */
export const RATE_LIMIT_RELAY_HEADERS: readonly string[] = ["retry-after", "retry-after-ms"];

/**
 * Set INSTEAD of the relayed family when a failover means the numbers describe
 * a route the caller did not ask for. See {@link relayedRateLimitHeaders}.
 */
export const RATE_LIMIT_RELAY_MARKER = "x-ferrogate-ratelimit-relay" as const;

/** The one value {@link RATE_LIMIT_RELAY_MARKER} currently takes. */
export const RATE_LIMIT_RELAY_SUPPRESSED = "suppressed-after-failover" as const;

/** The upstream response a relay is derived from, plus how we got to it. */
export interface UpstreamRelay {
  /** Headers of the response that ACTUALLY answered. */
  readonly headers: Headers;
  /**
   * True when the candidate that answered is not the caller's first-choice
   * route — i.e. the ladder moved them.
   */
  readonly failedOver: boolean;
}

/**
 * The rate-limit headers to put on a client response, given the upstream one.
 *
 * ## THE FAILOVER JUDGEMENT (#726)
 *
 * On a first-choice answer the numbers are relayed verbatim: they describe the
 * exact window the caller is being measured against, and they are the only
 * pacing signal that exists.
 *
 * After a FAILOVER they are DROPPED. The reasoning, stated so it is not
 * re-litigated by accident:
 *
 *  - the window belongs to a provider the caller never selected. `backup`'s
 *    `x-ratelimit-remaining-requests: 0` says nothing about `primary`, which is
 *    where the ladder will send them first next time;
 *  - the routing decision is not stable. Priority, weight, canary bucketing and
 *    the circuit breaker all decide per request, so "the provider that answered
 *    this one" is not a prediction of the next one;
 *  - the failure mode of relaying anyway is the ACTIVE one. An SDK that reads
 *    `retry-after: 600` off a saturated fallback sleeps ten minutes while the
 *    primary — which it would have been routed back to — was healthy the whole
 *    time. Emitting nothing costs the client its own (blind, but not wrong)
 *    schedule; emitting the wrong number costs it correctness.
 *
 * A same-provider RETRY is NOT a failover: the second attempt hit the same
 * route the caller asked for, so its numbers are theirs. That is why the caller
 * passes `failedOver` (derived from the candidate index) rather than "was this
 * the first attempt".
 *
 * The suppression is ANNOUNCED — {@link RATE_LIMIT_RELAY_MARKER} — and only
 * when something was actually dropped, so "no pacing headers because we failed
 * over" is distinguishable from "no pacing headers because the relay is
 * broken". Without that marker the two are identical from outside and the
 * decision above becomes indistinguishable from the bug it replaces.
 */
export function relayedRateLimitHeaders(
  upstream: UpstreamRelay | undefined,
): Record<string, string> {
  if (upstream === undefined) return {};

  const relayed: Record<string, string> = {};
  upstream.headers.forEach((value, name) => {
    // `Headers.forEach` already lower-cases the name in workerd; normalising
    // again keeps this independent of that guarantee.
    const key = name.toLowerCase();
    if (
      RATE_LIMIT_RELAY_HEADERS.includes(key) ||
      RATE_LIMIT_RELAY_PREFIXES.some((prefix) => key.startsWith(prefix))
    ) {
      relayed[key] = value;
    }
  });

  if (!upstream.failedOver) return relayed;
  return Object.keys(relayed).length === 0
    ? {}
    : { [RATE_LIMIT_RELAY_MARKER]: RATE_LIMIT_RELAY_SUPPRESSED };
}

/** A rejection that has already been classified into the Rust status+code pair. */
export interface InferenceRejection {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  /**
   * Extra response headers this refusal carries (#726).
   *
   * The only producer today is the rate limiter, whose 429 has to tell the
   * caller when to come back and against which window — see
   * `src/ratelimit/headers.ts`. Optional because the great majority of
   * rejections have nothing to add, and because `reject()` must stay a
   * three-argument call at its ~40 sites.
   */
  readonly headers?: Readonly<Record<string, string>>;
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
      // Before `gatewayHeaders` on purpose: a refusal must never be able to
      // overwrite the correlation ids the body also carries.
      ...(rejection.headers ?? {}),
      ...gatewayHeaders(requestId),
    },
  });
}

/**
 * Success counterpart of {@link errorResponse} — `write_json_response`.
 *
 * `upstream` is present on the paths that RESHAPE a provider response (the
 * Anthropic and embeddings translations): the body is ours, but the rate-limit
 * numbers are still the upstream's and the caller needs them just as much as on
 * the pass-through branch. See {@link relayedRateLimitHeaders}.
 */
export function jsonResponse(
  value: unknown,
  requestId: string,
  status = 200,
  upstream?: UpstreamRelay,
): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      ...relayedRateLimitHeaders(upstream),
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
 *
 * ## Headers, which are a separate axis (issue #726)
 *
 * "Untouched" used to stop at the body: the response was rebuilt with
 * `gatewayHeaders` and NOTHING else, so a provider 429 carrying `retry-after`
 * and the `x-ratelimit-*` family reached the caller with none of it. `upstream`
 * is how those come back — filtered to the two documented pacing families,
 * never a blanket copy. It is orthogonal to the wrap above: a body we WRAP still
 * relays the pacing headers, because the caller's need to back off does not
 * depend on whether the provider's error body was readable. */
export function rawUpstreamResponse(
  status: number,
  contentType: string,
  body: string,
  requestId: string,
  upstream?: UpstreamRelay,
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
      ...relayedRateLimitHeaders(upstream),
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
