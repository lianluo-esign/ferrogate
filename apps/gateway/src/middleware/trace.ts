const nn = <T>(v: T): NonNullable<T> => v as NonNullable<T>;
/**
 * W3C trace-context INGRESS — Rust `server/mod.rs:156 ingress_trace_context`.
 *
 * Step 3 of the Rust ingress order, and until now the only half of the pair
 * that was ported was the RESPONSE half: `x-request-id` / `x-trace-id` were
 * always the gateway's own minted id, so a caller that arrived inside a
 * distributed trace had that trace SEVERED at the gateway — every span past
 * this hop belonged to a new, unrelated trace, and correlating a client-side
 * incident with a gateway log meant a manual join on wall-clock time.
 *
 * This module adopts the caller's trace id when — and only when — the inbound
 * `traceparent` is a valid W3C header. The validity rules are the Rust ones,
 * character for character (`valid_traceparent`):
 *
 *   - exactly four `-`-separated fields: version, trace id, parent id, flags;
 *   - lengths 2 / 32 / 16 / 2;
 *   - LOWERCASE hex only (an uppercase digit is invalid per the spec, and
 *     accepting it would make the same logical trace hash two ways);
 *   - version `ff` is reserved and rejected;
 *   - an all-zero trace id or parent id is the spec's "invalid" sentinel.
 *
 * Anything that fails falls back to the gateway's own request id, so a
 * malformed or hostile header can never remove a correlation id — it can only
 * fail to add one. `tracestate` rides along ONLY with a valid `traceparent`,
 * trimmed, non-empty, and capped at 512 bytes (the Rust cap; the W3C limit is
 * advisory and an unbounded vendor blob is a header-amplification vector).
 *
 * ## What this port does NOT do
 *
 * It does not INJECT `traceparent`/`tracestate` toward the upstream — that is
 * `proxy.rs::apply_upstream_request_filter`, which belongs to the operator
 * reverse-proxy fall-through that does not exist in this tree yet (see the
 * marker in `routes/index.ts`). The adopted values are therefore parked on the
 * request context, where a dispatcher can read them the day it lands, and the
 * adopted TRACE ID is what every response and every error envelope reports.
 */

/** Rust `IngressTraceContext`. */
export interface IngressTraceContext {
  /** The adopted trace id, or the fallback request id. Never empty. */
  readonly traceId: string;
  /** The verbatim inbound header, when valid. */
  readonly traceparent: string | undefined;
  /** The inbound `tracestate`, only ever present alongside a valid parent. */
  readonly tracestate: string | undefined;
}

/** Rust `is_lower_hex`. */
function isLowerHex(value: string): boolean {
  for (const character of value) {
    const isDigit = character >= "0" && character <= "9";
    const isHexLetter = character >= "a" && character <= "f";
    if (!isDigit && !isHexLetter) return false;
  }
  return true;
}

function allZero(value: string): boolean {
  for (const character of value) {
    if (character !== "0") return false;
  }
  return true;
}

/** Rust `valid_traceparent` — the header itself when valid, else `undefined`. */
export function validTraceparent(value: string): string | undefined {
  const parts = value.split("-");
  if (parts.length !== 4) return undefined;
  const [version, traceId, parentId, flags] = parts as [string, string, string, string];
  if (
    version.length !== 2 ||
    traceId.length !== 32 ||
    parentId.length !== 16 ||
    flags.length !== 2 ||
    version === "ff" ||
    !isLowerHex(version) ||
    !isLowerHex(traceId) ||
    !isLowerHex(parentId) ||
    !isLowerHex(flags) ||
    allZero(traceId) ||
    allZero(parentId)
  ) {
    return undefined;
  }
  return value;
}

/** Rust `TRACESTATE` length cap. */
export const MAX_TRACESTATE_LENGTH = 512;

/** Rust `ingress_trace_context`. */
export function ingressTraceContext(
  headers: Headers,
  fallbackTraceId: string,
): IngressTraceContext {
  const rawParent = headers.get("traceparent")?.trim();
  const traceparent = rawParent === undefined ? undefined : validTraceparent(rawParent);

  const traceId = traceparent === undefined ? fallbackTraceId : nn(traceparent.split("-")[1]);

  let tracestate: string | undefined;
  if (traceparent !== undefined) {
    const raw = headers.get("tracestate")?.trim();
    if (raw !== undefined && raw !== "" && raw.length <= MAX_TRACESTATE_LENGTH) {
      tracestate = raw;
    }
  }

  return { traceId, traceparent, tracestate };
}
