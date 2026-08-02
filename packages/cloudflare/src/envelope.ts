/**
 * The Cloudflare REST response envelope.
 *
 * Ported from `crates/ferrogate-cloudflare/src/envelope.rs`. Every `client/v4`
 * endpoint wraps its payload in `{ success, errors[], messages[], result }`,
 * and paginated endpoints add a `result_info`.
 *
 * ## Why `result_info` is load-bearing
 *
 * Dropping it is why a list call could silently answer with only its first page
 * — "absent" then really meant "not on page 1", which is exactly how a live R2
 * probe once passed vacuously after a delete. Cloudflare uses TWO pagination
 * dialects and both must be walked:
 *
 *  - **cursor** (R2 bucket list): an opaque `cursor` echoed back as a query
 *    parameter. Terminate on an absent OR EMPTY cursor, on an empty page, and
 *    on a cursor the server repeats verbatim.
 *  - **page-numbered** (D1 database list): `page` / `per_page` / `count` /
 *    `total_count`.
 */
import { type CloudflareApiErrorEntry, CloudflareError } from "./errors.js";

/** A non-fatal advisory from the envelope's `messages[]` array. */
export interface CloudflareMessage {
  readonly code: number;
  readonly message: string;
}

/**
 * The `result_info` object on a paginated response. Every field is optional
 * because no endpoint sends all of them.
 */
export interface CloudflareResultInfo {
  /** Continuation token for the next page; absent or empty on the last page. */
  readonly cursor?: string;
  readonly per_page?: number;
  readonly count?: number;
  readonly page?: number;
  readonly total_count?: number;
}

/** A decoded Cloudflare response envelope. */
export interface CloudflareEnvelope<T> {
  readonly success: boolean;
  readonly errors: readonly CloudflareApiErrorEntry[];
  readonly messages: readonly CloudflareMessage[];
  readonly result?: T;
  readonly resultInfo?: CloudflareResultInfo;
}

/**
 * The continuation cursor, normalised: `undefined` when absent OR empty.
 * Cloudflare signals "last page" both ways, and treating `""` as a real cursor
 * loops forever.
 */
export function nextCursor(info: CloudflareResultInfo | undefined): string | undefined {
  const cursor = info?.cursor;
  return cursor === undefined || cursor === "" ? undefined : cursor;
}

function entries(value: unknown): readonly { code: number; message: string }[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (typeof entry !== "object" || entry === null) return [];
    const record = entry as Record<string, unknown>;
    return [
      {
        code: typeof record.code === "number" ? record.code : 0,
        message: typeof record.message === "string" ? record.message : "",
      },
    ];
  });
}

/**
 * Decode a response body into an envelope. `context` names the call for the
 * error message ("preflight", "R2 bucket list", …).
 *
 * A body that is not a JSON OBJECT is a decode error rather than an empty
 * envelope: Cloudflare edge failures answer with HTML, and silently treating
 * that as `{ success: false }` would report an infrastructure outage as an
 * ordinary API rejection.
 */
export function decodeEnvelope<T>(body: string, context: string): CloudflareEnvelope<T> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch (error) {
    throw CloudflareError.decode(
      `failed to decode Cloudflare ${context} envelope: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw CloudflareError.decode(
      `failed to decode Cloudflare ${context} envelope: expected a JSON object body`,
    );
  }
  const record = parsed as Record<string, unknown>;
  const resultInfo = record.result_info;
  const envelope: {
    success: boolean;
    errors: readonly CloudflareApiErrorEntry[];
    messages: readonly CloudflareMessage[];
    result?: T;
    resultInfo?: CloudflareResultInfo;
  } = {
    success: record.success === true,
    errors: entries(record.errors),
    messages: entries(record.messages),
  };
  if ("result" in record && record.result !== undefined) envelope.result = record.result as T;
  if (typeof resultInfo === "object" && resultInfo !== null) {
    envelope.resultInfo = resultInfo as CloudflareResultInfo;
  }
  return envelope;
}

function ensureSuccess<T>(
  envelope: CloudflareEnvelope<T>,
  status: number,
  retryAfterMs: number | undefined,
): void {
  if (envelope.success && status >= 200 && status < 300) return;
  throw CloudflareError.fromResponse(status, retryAfterMs, envelope.errors);
}

/**
 * Collapse an envelope into its typed `result`, or throw a typed error.
 *
 * The HTTP `status` is authoritative alongside `success`: a body claiming
 * success under a 500 is not a success, and — the case that actually happens —
 * `success: false` under a **200** is not one either. Cloudflare answers a
 * duplicate R2 bucket create exactly that way.
 *
 * A `success: true` envelope with a MISSING `result` is a decode error: the
 * caller asked for a body, and handing back `undefined` would push the failure
 * to some later property access.
 */
export function intoResult<T>(
  envelope: CloudflareEnvelope<T>,
  status: number,
  retryAfterMs?: number,
): T {
  ensureSuccess(envelope, status, retryAfterMs);
  if (envelope.result === undefined) {
    throw CloudflareError.decode("expected a `result` body but it was absent");
  }
  return envelope.result;
}

/** {@link intoResult} plus the pagination metadata, so a list caller can walk. */
export function intoResultWithInfo<T>(
  envelope: CloudflareEnvelope<T>,
  status: number,
  retryAfterMs?: number,
): { readonly result: T; readonly resultInfo: CloudflareResultInfo | undefined } {
  return { result: intoResult(envelope, status, retryAfterMs), resultInfo: envelope.resultInfo };
}

/**
 * {@link intoResult} for endpoints whose success carries no meaningful body
 * (delete/verify endpoints returning `result: null`).
 */
export function intoAck(
  envelope: CloudflareEnvelope<unknown>,
  status: number,
  retryAfterMs?: number,
): void {
  ensureSuccess(envelope, status, retryAfterMs);
}
