/**
 * Flatten the OTLP/JSON nesting into the record shapes the sink writes.
 *
 * Clean-room port of the collector parser described in
 * `docs/legacy/inventory-data-billing.md` §4.2/§4.4. Every level is validated
 * with the Zod schemas in `schemas.ts`: the **envelope** failing is a `400`
 * ({@link OtlpEnvelopeError}), an individual **record** failing is counted in
 * {@link ParseResult.skipped} and the rest of the batch still lands.
 */
import type { z } from "zod";
import {
  ENVELOPE_BY_SIGNAL,
  type OtlpAnyValue,
  type OtlpKeyValue,
  type Signal,
  histogramDataPointSchema,
  keyValueSchema,
  logRecordSchema,
  metricSchema,
  numberDataPointSchema,
  resourceLogsSchema,
  resourceMetricsSchema,
  resourceSpansSchema,
  scopeLogsSchema,
  scopeMetricsSchema,
  scopeSpansSchema,
  spanSchema,
} from "./schemas.js";

/** Attributes flattened to strings — the only form AE blobs accept. */
export type Attributes = Record<string, string>;

/** One metric data point, flattened out of its resource/scope/metric nesting. */
export interface ParsedMetricPoint {
  name: string;
  description: string;
  /** `sum` (what FerroGate emits), `gauge`, or `histogram`. */
  kind: "sum" | "gauge" | "histogram";
  value: number;
  attributes: Attributes;
  resourceAttributes: Attributes;
  scopeName: string;
  serviceName: string;
}

/** One span, flattened out of its resource/scope nesting. */
export interface ParsedSpan {
  traceId: string;
  spanId: string;
  parentSpanId: string;
  name: string;
  kind: number;
  /** Nanoseconds, kept as the JSON string they arrive as (they exceed 2^53). */
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  /** End minus start in ms, computed in BigInt to avoid precision loss. */
  durationMs: number;
  attributes: Attributes;
  resourceAttributes: Attributes;
  scopeName: string;
  serviceName: string;
}

/** One log record, flattened out of its resource/scope nesting. */
export interface ParsedLogRecord {
  timeUnixNano: string;
  traceId: string;
  spanId: string;
  severityText: string;
  severityNumber: number;
  body: string;
  attributes: Attributes;
  resourceAttributes: Attributes;
  scopeName: string;
  serviceName: string;
}

/** A body that is not this signal's OTLP envelope at all. Maps to HTTP 400. */
export class OtlpEnvelopeError extends Error {
  override readonly name = "OtlpEnvelopeError";
  /** Zod's own issue list, surfaced to the client as `detail`. */
  readonly issues: readonly string[];

  constructor(message: string, issues: readonly string[] = []) {
    super(message);
    this.issues = issues;
  }
}

/**
 * Records that parsed vs. records that were structurally unusable.
 *
 * A single junk record does NOT fail the batch — OTLP exporters retry whole
 * batches, so rejecting 5,000 good spans over one bad one amplifies load.
 * Unusable records are counted in `skipped` and surfaced in the response.
 */
export interface ParseResult<T> {
  records: T[];
  skipped: number;
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

/** Render an OTLP `AnyValue` as the flat string an AE blob / log field needs. */
export function anyValueToString(value: OtlpAnyValue | undefined): string {
  if (!value || typeof value !== "object") return "";
  if (typeof value.stringValue === "string") return value.stringValue;
  if (typeof value.intValue === "string") return value.intValue;
  if (typeof value.intValue === "number") return String(value.intValue);
  if (typeof value.doubleValue === "number") return String(value.doubleValue);
  if (typeof value.boolValue === "boolean") return String(value.boolValue);
  if (typeof value.bytesValue === "string") return value.bytesValue;
  if (value.arrayValue) {
    return JSON.stringify((value.arrayValue.values ?? []).map((v) => anyValueToString(v)));
  }
  if (value.kvlistValue) {
    return JSON.stringify(flattenAttributes(value.kvlistValue.values));
  }
  return "";
}

/**
 * Flatten an OTLP `KeyValue[]` into a plain string map. Entries that do not
 * validate are ignored rather than failing the record they belong to.
 */
export function flattenAttributes(list: readonly unknown[] | undefined): Attributes {
  const out: Attributes = {};
  for (const entry of list ?? []) {
    const parsed = keyValueSchema.safeParse(entry);
    if (!parsed.success) continue;
    const kv: OtlpKeyValue = parsed.data;
    if (!kv.key) continue;
    out[kv.key] = anyValueToString(kv.value);
  }
  return out;
}

/** OTLP nano timestamps arrive as strings or numbers; normalize to string. */
function nanoString(value: string | number | undefined): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

/** Nanosecond difference as milliseconds. BigInt because nanos exceed 2^53. */
export function durationMsOf(start: string, end: string): number {
  if (!/^\d+$/.test(start) || !/^\d+$/.test(end)) return 0;
  try {
    const delta = BigInt(end) - BigInt(start);
    if (delta <= 0n) return 0;
    return Number(delta) / 1e6;
  } catch {
    return 0;
  }
}

/** The `service.name` resource attribute, or `"unknown"`. */
function serviceNameOf(resourceAttributes: Attributes): string {
  return resourceAttributes["service.name"] || "unknown";
}

/**
 * Validate this signal's envelope, returning its top-level array.
 *
 * @throws {OtlpEnvelopeError} when the body is not the envelope — HTTP 400.
 */
export function envelopeEntries(signal: Signal, body: unknown): unknown[] {
  const { schema, key } = ENVELOPE_BY_SIGNAL[signal];
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new OtlpEnvelopeError(
      `expected a JSON object with an array "${key}"`,
      parsed.error.issues.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`),
    );
  }
  return (parsed.data as Record<string, unknown[]>)[key] ?? [];
}

/** Validate one nested record; `null` means "skip it, count it". */
function take<T>(schema: z.ZodType<T>, value: unknown): T | null {
  const parsed = schema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

// ---------------------------------------------------------------------------
// Per-signal parsers
// ---------------------------------------------------------------------------

/**
 * Parse `POST /v1/metrics`:
 * `{resourceMetrics:[{resource,scopeMetrics:[{scope,metrics:[...]}]}]}`.
 */
export function parseMetrics(body: unknown): ParseResult<ParsedMetricPoint> {
  const records: ParsedMetricPoint[] = [];
  let skipped = 0;

  for (const entry of envelopeEntries("metrics", body)) {
    const resourceMetrics = take(resourceMetricsSchema, entry);
    if (!resourceMetrics) {
      skipped++;
      continue;
    }
    const resourceAttributes = flattenAttributes(resourceMetrics.resource?.attributes);
    const serviceName = serviceNameOf(resourceAttributes);

    for (const scopeEntry of resourceMetrics.scopeMetrics ?? []) {
      const scopeMetrics = take(scopeMetricsSchema, scopeEntry);
      if (!scopeMetrics) {
        skipped++;
        continue;
      }
      const scopeName = scopeMetrics.scope?.name ?? "";

      for (const metricEntry of scopeMetrics.metrics ?? []) {
        const metric = take(metricSchema, metricEntry);
        // A metric with no name (or no recognized container) cannot be charted:
        // AE blob 1 IS the metric name, so an unnamed point is unqueryable.
        if (!metric) {
          skipped++;
          continue;
        }
        const kind: ParsedMetricPoint["kind"] = metric.sum
          ? "sum"
          : metric.gauge
            ? "gauge"
            : metric.histogram
              ? "histogram"
              : "sum";
        const container = metric.sum ?? metric.gauge ?? metric.histogram;
        if (!container) {
          skipped++;
          continue;
        }

        for (const pointEntry of container.dataPoints ?? []) {
          const point =
            kind === "histogram"
              ? take(histogramDataPointSchema, pointEntry)
              : take(numberDataPointSchema, pointEntry);
          if (!point) {
            skipped++;
            continue;
          }
          const value =
            kind === "histogram"
              ? histogramValueOf(point as z.infer<typeof histogramDataPointSchema>)
              : scalarValueOf(point as z.infer<typeof numberDataPointSchema>);
          if (value === null) {
            skipped++;
            continue;
          }
          records.push({
            name: metric.name,
            description: metric.description ?? "",
            kind,
            value,
            attributes: flattenAttributes(point.attributes),
            resourceAttributes,
            scopeName,
            serviceName,
          });
        }
      }
    }
  }

  return { records, skipped };
}

/** `asDouble`, else `asInt` (a JSON string in OTLP). `null` = unusable. */
function scalarValueOf(point: z.infer<typeof numberDataPointSchema>): number | null {
  if (typeof point.asDouble === "number" && Number.isFinite(point.asDouble)) return point.asDouble;
  if (point.asInt !== undefined) {
    const parsed = Number(point.asInt);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/** A histogram point's `sum`, else its `count`. `null` = unusable. */
function histogramValueOf(point: z.infer<typeof histogramDataPointSchema>): number | null {
  if (typeof point.sum === "number" && Number.isFinite(point.sum)) return point.sum;
  if (point.count !== undefined) {
    const parsed = Number(point.count);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/**
 * Parse `POST /v1/traces`:
 * `{resourceSpans:[{resource,scopeSpans:[{scope,spans:[...]}]}]}`.
 */
export function parseTraces(body: unknown): ParseResult<ParsedSpan> {
  const records: ParsedSpan[] = [];
  let skipped = 0;

  for (const entry of envelopeEntries("traces", body)) {
    const resourceSpans = take(resourceSpansSchema, entry);
    if (!resourceSpans) {
      skipped++;
      continue;
    }
    const resourceAttributes = flattenAttributes(resourceSpans.resource?.attributes);
    const serviceName = serviceNameOf(resourceAttributes);

    for (const scopeEntry of resourceSpans.scopeSpans ?? []) {
      const scopeSpans = take(scopeSpansSchema, scopeEntry);
      if (!scopeSpans) {
        skipped++;
        continue;
      }
      const scopeName = scopeSpans.scope?.name ?? "";

      for (const spanEntry of scopeSpans.spans ?? []) {
        // `spanSchema` requires traceId + spanId: an uncorrelatable span is
        // skipped, never written under a fabricated id.
        const span = take(spanSchema, spanEntry);
        if (!span) {
          skipped++;
          continue;
        }
        const startTimeUnixNano = nanoString(span.startTimeUnixNano);
        const endTimeUnixNano = nanoString(span.endTimeUnixNano);
        records.push({
          traceId: span.traceId,
          spanId: span.spanId,
          // `parentSpanId` is absent/null for a root span in the Rust encoder.
          parentSpanId: span.parentSpanId ?? "",
          name: span.name ?? "",
          kind: span.kind ?? 0,
          startTimeUnixNano,
          endTimeUnixNano,
          durationMs: durationMsOf(startTimeUnixNano, endTimeUnixNano),
          attributes: flattenAttributes(span.attributes),
          resourceAttributes,
          scopeName,
          serviceName,
        });
      }
    }
  }

  return { records, skipped };
}

/**
 * Parse `POST /v1/logs`:
 * `{resourceLogs:[{resource,scopeLogs:[{scope,logRecords:[...]}]}]}`.
 */
export function parseLogs(body: unknown): ParseResult<ParsedLogRecord> {
  const records: ParsedLogRecord[] = [];
  let skipped = 0;

  for (const entry of envelopeEntries("logs", body)) {
    const resourceLogs = take(resourceLogsSchema, entry);
    if (!resourceLogs) {
      skipped++;
      continue;
    }
    const resourceAttributes = flattenAttributes(resourceLogs.resource?.attributes);
    const serviceName = serviceNameOf(resourceAttributes);

    for (const scopeEntry of resourceLogs.scopeLogs ?? []) {
      const scopeLogs = take(scopeLogsSchema, scopeEntry);
      if (!scopeLogs) {
        skipped++;
        continue;
      }
      const scopeName = scopeLogs.scope?.name ?? "";

      for (const recordEntry of scopeLogs.logRecords ?? []) {
        const record = take(logRecordSchema, recordEntry);
        if (!record) {
          skipped++;
          continue;
        }
        records.push({
          timeUnixNano: nanoString(record.timeUnixNano ?? record.observedTimeUnixNano),
          traceId: record.traceId ?? "",
          spanId: record.spanId ?? "",
          severityText: record.severityText ?? "",
          severityNumber: record.severityNumber ?? 0,
          body: typeof record.body === "string" ? record.body : anyValueToString(record.body),
          attributes: flattenAttributes(record.attributes),
          resourceAttributes,
          scopeName,
          serviceName,
        });
      }
    }
  }

  return { records, skipped };
}
