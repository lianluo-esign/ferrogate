/**
 * The typed failure surface of the admin SDK.
 *
 * Every FerroGate control-plane error is the same envelope, written by ONE
 * function (`writeJsonError`, `apps/control-plane/src/middleware/errors.ts`):
 *
 * ```json
 * { "error": { "message": "...", "type": "ferrogate_error",
 *              "code": "scope_denied", "request_id": "fg-…" } }
 * ```
 *
 * so decoding it is the SDK's job and not every caller's. `code` is the stable
 * machine-readable member — application code switches on it, never on the
 * message — and `requestId` is what an operator quotes in a bug report.
 *
 * The decoding rules below are deliberately the SAME rules the FerroGate CLI
 * applies (`apps/cli/src/ports.ts::classifyFailure`), because a caller must not
 * see one error for `ferrogate get …` and a different one for the same request
 * from this client:
 *
 *  - a body that is not the envelope (an HTML 502 from a load balancer, an
 *    empty 504) still produces a typed error, never a `SyntaxError`;
 *  - the correlation id is read from `x-request-id` FIRST and from the
 *    envelope's `request_id` second, so it survives an edge that strips either;
 *  - every extra member of the `error` object is preserved in {@link
 *    FerrogateApiError.details}, since a resource-specific detail (which field
 *    failed validation, which quota was exceeded) is exactly what the caller
 *    needs on the one path where it is hardest to get.
 */

/** The four members every FerroGate error object carries. */
export const ERROR_ENVELOPE_FIELDS = ["message", "type", "code", "request_id"] as const;

/** The wire envelope, as the control plane writes it. */
export interface FerrogateErrorEnvelope {
  readonly error: {
    readonly message?: string;
    readonly type?: string;
    readonly code?: string;
    readonly request_id?: string | null;
    readonly [key: string]: unknown;
  };
}

/** Options {@link FerrogateApiError} is constructed from. */
export interface FerrogateApiErrorInit {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly requestId?: string | undefined;
  readonly traceId?: string | undefined;
  readonly retryAfterSeconds?: number | undefined;
  readonly details?: Readonly<Record<string, unknown>> | undefined;
  readonly body?: unknown;
  readonly headers?: Headers | undefined;
}

/**
 * A non-2xx answer from the control plane.
 *
 * Thrown by {@link unwrap} and by the `throwOnError` middleware, so a caller
 * uses ordinary `try`/`catch` and reads `status`/`code` rather than inspecting
 * a `Response`.
 */
export class FerrogateApiError extends Error {
  override readonly name = "FerrogateApiError";
  /** HTTP status. */
  readonly status: number;
  /** The envelope's `code`, or a status-derived fallback (see below). */
  readonly code: string;
  /** `x-request-id`, else the envelope's `request_id`, else `undefined`. */
  readonly requestId: string | undefined;
  /** `x-trace-id`, when the edge did not strip it. */
  readonly traceId: string | undefined;
  /** Parsed `Retry-After`, in seconds, when the server sent an integer one. */
  readonly retryAfterSeconds: number | undefined;
  /** Members of the `error` object beyond the four envelope fields. */
  readonly details: Readonly<Record<string, unknown>>;
  /** The decoded body (or the raw text when it was not JSON). */
  readonly body: unknown;
  /** Response headers, for anything this class does not model. */
  readonly headers: Headers | undefined;

  constructor(init: FerrogateApiErrorInit) {
    super(init.message);
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId;
    this.traceId = init.traceId;
    this.retryAfterSeconds = init.retryAfterSeconds;
    this.details = init.details ?? {};
    this.body = init.body;
    this.headers = init.headers;
  }
}

/** A request that never produced a response (DNS, TLS, timeout, abort). */
export class FerrogateTransportError extends Error {
  override readonly name = "FerrogateTransportError";
  /** The URL that was being requested. */
  readonly url: string;

  constructor(url: string, message: string, options?: { cause?: unknown }) {
    super(message, options as ErrorOptions);
    this.url = url;
  }
}

export function isFerrogateApiError(value: unknown): value is FerrogateApiError {
  return value instanceof FerrogateApiError;
}

/**
 * Fallback `code` for a body that carried none.
 *
 * The same buckets `apps/cli/src/errors.ts` exits on, so a caller can switch on
 * `code` even when a proxy answered instead of FerroGate.
 */
export function defaultCodeForStatus(status: number): string {
  if (status === 401 || status === 403) return "unauthorized";
  if (status === 404 || status === 409) return "not_found";
  if (status === 400 || status === 422) return "invalid_request";
  if (status === 408 || status === 429 || status === 503 || status === 504) {
    return "retryable_error";
  }
  if (status >= 500) return "server_error";
  return "error";
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function integerHeader(headers: Headers | undefined, name: string): number | undefined {
  const raw = headers?.get(name)?.trim();
  return raw !== undefined && raw !== "" && /^\d+$/.test(raw) ? Number(raw) : undefined;
}

/**
 * Build the typed error for a non-2xx response.
 *
 * `text` is taken rather than the `Response` so this is pure and testable, and
 * so a caller that has already consumed the body can still use it.
 */
export function apiErrorFrom(
  status: number,
  headers: Headers | undefined,
  text: string,
): FerrogateApiError {
  let body: unknown;
  try {
    body = text === "" ? undefined : JSON.parse(text);
  } catch {
    // NOT an error: a 502 from a load balancer is an HTML page, and the caller
    // still gets a typed exception with the right status.
    body = text;
  }

  const errorObject = asObject(asObject(body)?.["error"]);
  const envelopeMessage = errorObject?.["message"];
  const envelopeCode = errorObject?.["code"];
  const envelopeRequestId = errorObject?.["request_id"];

  const requestId =
    headers?.get("x-request-id") ??
    (typeof envelopeRequestId === "string" ? envelopeRequestId : undefined);
  const traceId = headers?.get("x-trace-id") ?? undefined;

  const details = Object.fromEntries(
    Object.entries(errorObject ?? {}).filter(
      ([key]) => !(ERROR_ENVELOPE_FIELDS as readonly string[]).includes(key),
    ),
  );

  const trimmed = text.trim();
  return new FerrogateApiError({
    status,
    code: typeof envelopeCode === "string" ? envelopeCode : defaultCodeForStatus(status),
    message:
      typeof envelopeMessage === "string"
        ? envelopeMessage
        : trimmed === ""
          ? `request failed with HTTP ${status}`
          : trimmed,
    requestId: requestId ?? undefined,
    traceId,
    retryAfterSeconds: integerHeader(headers, "retry-after"),
    details,
    body,
    headers,
  });
}
