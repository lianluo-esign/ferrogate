/**
 * The uniform error envelope, identical in shape to the one `apps/gateway`
 * emits (`src/middleware/errors.ts`, itself a port of the Rust
 * `write_json_error` / `ErrorBody` / `ErrorObject`):
 *
 * ```json
 * { "error": { "message": "...", "type": "ferrogate_error",
 *              "code": "telemetry_sink_unavailable", "request_id": "..." } }
 * ```
 *
 * Every non-2xx this Worker originates leaves through here, so an OTLP client
 * that already parses gateway errors parses collector errors unchanged.
 */

/** `type` is always the literal `ferrogate_error`. */
export const FERROGATE_ERROR_TYPE = "ferrogate_error" as const;

export interface ErrorObject {
  readonly message: string;
  readonly type: typeof FERROGATE_ERROR_TYPE;
  readonly code: string;
  readonly request_id: string | null;
}

export interface ErrorBody {
  readonly error: ErrorObject;
}

/** Machine-readable codes this Worker originates. */
export const TelemetryErrorCode = {
  /** Route exists but the method does not. */
  MethodNotAllowed: "method_not_allowed",
  /** Nothing is mounted at this path. */
  NotFound: "not_found",
  /** Missing or wrong `Authorization: Bearer`. */
  Unauthorized: "unauthorized",
  /** `COLLECTOR_TOKEN` is unset — the collector fails CLOSED. */
  CollectorUnconfigured: "telemetry_collector_unconfigured",
  /** No Analytics Engine binding: the sink cannot accept anything. */
  SinkUnavailable: "telemetry_sink_unavailable",
  /** Body exceeded the configured ceiling. */
  PayloadTooLarge: "payload_too_large",
  /** Body was not readable / not JSON. */
  MalformedBody: "malformed_request_body",
  /** Body was JSON but not the OTLP envelope for this signal. */
  InvalidOtlpPayload: "invalid_otlp_payload",
  /** Binary OTLP — Cloudflare supports no protobuf anywhere. */
  UnsupportedMediaType: "unsupported_media_type",
} as const;

export type TelemetryErrorCode = (typeof TelemetryErrorCode)[keyof typeof TelemetryErrorCode];

/** Build the envelope body. */
export function errorBody(
  code: string,
  message: string,
  requestId: string | null = null,
  extra?: Record<string, unknown>,
): ErrorBody & Record<string, unknown> {
  return {
    error: { message, type: FERROGATE_ERROR_TYPE, code, request_id: requestId },
    ...(extra ?? {}),
  };
}

/** A JSON `Response` carrying the envelope. */
export function errorResponse(
  status: number,
  code: string,
  message: string,
  requestId: string | null = null,
  extra?: Record<string, unknown>,
): Response {
  return new Response(JSON.stringify(errorBody(code, message, requestId, extra)), {
    status,
    headers: { "content-type": "application/json" },
  });
}
