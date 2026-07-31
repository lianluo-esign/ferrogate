/**
 * Every Cloudflare observability hard limit this Worker has to respect, stated
 * once.
 *
 * Clean-room port of the collector limits described in
 * `docs/legacy/inventory-data-billing.md` §4.4/§4.5. Analytics Engine either
 * rejects an oversized data point outright or silently truncates it, so the
 * collector clamps FIRST and reports what it had to shorten or drop rather than
 * letting a `writeDataPoint()` throw in the middle of a batch.
 */

/**
 * Analytics Engine: **exactly one** index per data point.
 *
 * Not a formatting detail — the index is the axis Cloudflare samples and
 * partitions on, so whatever goes in it becomes the effective tenancy key of
 * the whole dataset. That is why the entire {@link AE_INDEX_MAX_BYTES} budget
 * is spent on the tenant id and nothing else.
 */
export const AE_INDEXES_PER_POINT = 1;

/** Analytics Engine: an index is truncated at 96 **bytes** (not characters). */
export const AE_INDEX_MAX_BYTES = 96;

/** Analytics Engine: at most 20 blobs per data point. */
export const AE_MAX_BLOBS = 20;

/** Analytics Engine: at most 20 doubles per data point. */
export const AE_MAX_DOUBLES = 20;

/**
 * Analytics Engine: the blobs of a single data point may total 16 KB. Past that
 * the write is rejected, so the collector truncates instead.
 */
export const AE_MAX_BLOB_BYTES = 16 * 1024;

/**
 * Analytics Engine: at most 250 `writeDataPoint()` calls per Worker invocation.
 *
 * Past the cap the runtime stops accepting points, so the writer counts its own
 * calls, stops at the cap, and reports the remainder as `dropped` in the
 * response body plus a `console.warn` — never a silent truncation.
 */
export const AE_MAX_WRITES_PER_INVOCATION = 250;

/**
 * Default per-request OTLP body ceiling: **4 MiB**.
 *
 * Overridable with the `MAX_BODY_BYTES` Worker var (Worker vars are strings —
 * see {@link resolveMaxBodyBytes}). Over the ceiling the receiver answers `413`
 * rather than buffering an unbounded batch into the isolate's memory.
 */
export const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;

/** Workers Logs: a single log line is capped at 256 KB by the platform. */
export const LOG_LINE_MAX_BYTES = 256 * 1024;

/**
 * The much tighter neighbouring limit, documented so nobody re-fattens the log
 * lines: the `workers_trace_events` Logpush dataset truncates `logs` +
 * `exceptions` at a COMBINED 16,384 characters per invocation.
 */
export const LOGPUSH_COMBINED_CHAR_BUDGET = 16_384;

/** Cap on a single emitted log field before it is elided (keeps lines lean). */
export const LOG_FIELD_MAX_CHARS = 1024;

/** Max attribute pairs carried on one log line before the rest are elided. */
export const LOG_MAX_ATTRIBUTES = 32;

/** Index value used when no tenant can be derived from headers or attributes. */
export const UNKNOWN_TENANT = "unknown";

const ENCODER = new TextEncoder();

/** Byte length of a string as UTF-8 — what Cloudflare actually measures. */
export function byteLength(value: string): number {
  return ENCODER.encode(value).length;
}

/**
 * Truncate `value` to at most `maxBytes` UTF-8 bytes without splitting a
 * multi-byte code point. A split would emit a lone surrogate / invalid UTF-8
 * that the Analytics Engine write would reject.
 */
export function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  const bytes = ENCODER.encode(value);
  if (bytes.length <= maxBytes) return value;
  let end = maxBytes;
  // Walk back off any continuation byte (0b10xxxxxx) so the cut lands on a
  // code-point boundary.
  while (end > 0 && ((bytes[end] ?? 0) & 0b1100_0000) === 0b1000_0000) end--;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

/**
 * Clamp a tenant id into a legal Analytics Engine index: non-empty, at most
 * {@link AE_INDEX_MAX_BYTES} bytes.
 */
export function clampIndex(tenant: string): string {
  const trimmed = tenant.trim();
  if (trimmed.length === 0) return UNKNOWN_TENANT;
  return truncateUtf8(trimmed, AE_INDEX_MAX_BYTES);
}

/** Outcome of fitting a candidate blob list into the AE per-point budget. */
export interface ClampedBlobs {
  blobs: string[];
  /** True when any blob was shortened or removed to fit the budget. */
  truncated: boolean;
}

/**
 * Fit `blobs` into the Analytics Engine per-data-point budget: at most
 * {@link AE_MAX_BLOBS} entries totalling at most {@link AE_MAX_BLOB_BYTES}.
 *
 * Earlier blobs are the identifying ones (kind, name, service), so the budget
 * is spent front-to-back: a blob that does not fit whole is truncated to the
 * remaining room, and once the budget is exhausted the rest are dropped. An
 * oversized point must never reach `writeDataPoint()` — that throws and loses
 * the entire point.
 */
export function clampBlobs(blobs: readonly string[]): ClampedBlobs {
  const kept: string[] = [];
  let used = 0;
  let truncated = blobs.length > AE_MAX_BLOBS;

  for (const blob of blobs.slice(0, AE_MAX_BLOBS)) {
    const remaining = AE_MAX_BLOB_BYTES - used;
    if (remaining <= 0) {
      truncated = true;
      break;
    }
    const size = byteLength(blob);
    if (size <= remaining) {
      kept.push(blob);
      used += size;
      continue;
    }
    const clipped = truncateUtf8(blob, remaining);
    kept.push(clipped);
    used += byteLength(clipped);
    truncated = true;
  }

  return { blobs: kept, truncated };
}

/** Fit `doubles` into the AE per-data-point budget; non-finite becomes 0. */
export function clampDoubles(doubles: readonly number[]): number[] {
  return doubles.slice(0, AE_MAX_DOUBLES).map((value) => (Number.isFinite(value) ? value : 0));
}

/**
 * The configured body ceiling, falling back to {@link DEFAULT_MAX_BODY_BYTES}.
 *
 * Worker vars are strings, and a malformed or non-positive value must not
 * disable the cap — an unparseable override falls back to the default rather
 * than to "unlimited".
 */
export function resolveMaxBodyBytes(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_BODY_BYTES;
}
