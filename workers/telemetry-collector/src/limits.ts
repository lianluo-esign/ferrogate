// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — the one place every Cloudflare
//   observability hard limit is stated (issue #520). Analytics Engine and Workers Logs
//   both fail or silently truncate past these numbers, so the collector clamps FIRST and
//   reports what it dropped rather than letting a write throw mid-batch.

/**
 * Analytics Engine: **exactly one** index per data point.
 *
 * This is not a formatting detail. The index is the axis Cloudflare samples and
 * partitions on, so whatever goes in it becomes the effective tenancy key of the
 * whole dataset — which is why {@link AE_INDEX_MAX_BYTES} is spent on the tenant
 * id and nothing else.
 */
export const AE_INDEXES_PER_POINT = 1;

/** Analytics Engine: an index is truncated at 96 bytes (not characters). */
export const AE_INDEX_MAX_BYTES = 96;

/** Analytics Engine: at most 20 blobs per data point. */
export const AE_MAX_BLOBS = 20;

/** Analytics Engine: at most 20 doubles per data point. */
export const AE_MAX_DOUBLES = 20;

/**
 * Analytics Engine: the blobs of a single data point may total 16 KB.
 * Over that, the write is rejected — so the collector truncates instead.
 */
export const AE_MAX_BLOB_BYTES = 16 * 1024;

/**
 * Analytics Engine: at most 250 `writeDataPoint()` calls per Worker invocation.
 *
 * Past the cap the runtime stops accepting points, so the collector counts its
 * own calls, stops at the cap, and reports the remainder as `dropped` in the
 * response body plus a `console.warn` — never a silent truncation.
 */
export const AE_MAX_WRITES_PER_INVOCATION = 250;

/**
 * Workers Logs: a single log line is capped at 256 KB; longer lines are truncated
 * by the platform.
 *
 * NOTE the much tighter neighbouring limit: the `workers_trace_events` Logpush
 * dataset truncates the `logs` and `exceptions` fields at a COMBINED 16,384
 * characters per invocation. Anyone shipping these lines onward via Logpush loses
 * everything past that budget, so keep each emitted object lean — a handful of
 * indexed scalar fields, not the raw OTLP record.
 */
export const LOG_LINE_MAX_BYTES = 256 * 1024;

/** The Logpush `logs`+`exceptions` combined character budget, for documentation. */
export const LOGPUSH_COMBINED_CHAR_BUDGET = 16_384;

/** Default max accepted request body; override with the `MAX_BODY_BYTES` var. */
export const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;

/** Cap on a single emitted log field before it is elided (keeps lines lean). */
export const LOG_FIELD_MAX_CHARS = 1024;

/** Index value used when no tenant can be determined from headers or attributes. */
export const UNKNOWN_TENANT = "unknown";

const ENCODER = new TextEncoder();

/** Byte length of a string as UTF-8 (what Cloudflare actually measures). */
export function byteLength(value: string): number {
  return ENCODER.encode(value).length;
}

/**
 * Truncate `value` to at most `maxBytes` UTF-8 bytes without splitting a
 * multi-byte code point (a split would produce a lone surrogate / invalid UTF-8
 * that the AE write would reject).
 */
export function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  const bytes = ENCODER.encode(value);
  if (bytes.length <= maxBytes) return value;
  let end = maxBytes;
  // Walk back off any continuation byte (0b10xxxxxx) so the cut lands on a
  // code-point boundary.
  while (end > 0 && (bytes[end] & 0b1100_0000) === 0b1000_0000) end--;
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
 * Earlier blobs are the identifying ones (kind, name, service), so the budget is
 * spent front-to-back: a blob that does not fit whole is truncated to the
 * remaining room, and once the budget is exhausted the rest are dropped. An
 * oversized point must never be handed to `writeDataPoint()` — that throws and
 * loses the entire point.
 */
export function clampBlobs(blobs: string[]): ClampedBlobs {
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

/** Fit `doubles` into the Analytics Engine per-data-point budget. */
export function clampDoubles(doubles: number[]): number[] {
  return doubles
    .slice(0, AE_MAX_DOUBLES)
    .map((value) => (Number.isFinite(value) ? value : 0));
}
