// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — parse + validate the three OTLP/HTTP
//   JSON payload shapes the collector ingests (issue #520). JSON only: Cloudflare supports
//   no binary OTLP anywhere, so protobuf is off the table platform-wide.
//
//   Field names mirror crates/ferrogate-observability/src/otlp.rs exactly, and are the same
//   shapes Cloudflare's own native Workers OTLP export emits — one parser, both producers.

/** An OTLP `AnyValue`. FerroGate only ever emits `stringValue`; CF's export uses more. */
export interface OtlpAnyValue {
  stringValue?: string;
  /** OTLP encodes 64-bit ints as JSON STRINGS to survive `Number` precision. */
  intValue?: string | number;
  doubleValue?: number;
  boolValue?: boolean;
  arrayValue?: { values?: OtlpAnyValue[] };
  kvlistValue?: { values?: OtlpKeyValue[] };
}

/** An OTLP `KeyValue` attribute: `{key, value: {stringValue}}`. */
export interface OtlpKeyValue {
  key?: string;
  value?: OtlpAnyValue;
}

/** Attributes flattened to strings — the only form Analytics Engine blobs accept. */
export type Attributes = Record<string, string>;

/** One metric data point, already flattened out of its resource/scope/metric nesting. */
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
  /** Nanoseconds, kept as the JSON STRING they arrive as (they exceed 2^53). */
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  /** End minus start in milliseconds, computed in BigInt to avoid precision loss. */
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
  body: string;
  attributes: Attributes;
  resourceAttributes: Attributes;
  scopeName: string;
  serviceName: string;
}

/** A payload that is not the OTLP shape at all. Maps to HTTP 400. */
export class OtlpParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OtlpParseError";
  }
}

/**
 * Records that parsed vs. records that were structurally unusable.
 *
 * A single junk record does NOT fail the batch — OTLP exporters retry whole
 * batches, so rejecting 5,000 good spans over one bad one would amplify load.
 * Unusable records are counted in `skipped` and surfaced in the response.
 */
export interface ParseResult<T> {
  records: T[];
  skipped: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Render an OTLP `AnyValue` as the flat string an AE blob / log field needs. */
export function anyValueToString(value: OtlpAnyValue | undefined): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  if (typeof value.stringValue === "string") return value.stringValue;
  if (typeof value.intValue === "string") return value.intValue;
  if (typeof value.intValue === "number") return String(value.intValue);
  if (typeof value.doubleValue === "number") return String(value.doubleValue);
  if (typeof value.boolValue === "boolean") return String(value.boolValue);
  if (value.arrayValue) {
    return JSON.stringify(asArray(value.arrayValue.values).map((v) => anyValueToString(v as OtlpAnyValue)));
  }
  if (value.kvlistValue) {
    return JSON.stringify(flattenAttributes(value.kvlistValue.values));
  }
  return "";
}

/** Flatten an OTLP `KeyValue[]` into a plain string map. Malformed entries are ignored. */
export function flattenAttributes(list: unknown): Attributes {
  const out: Attributes = {};
  for (const entry of asArray(list)) {
    if (!isRecord(entry)) continue;
    const key = asString(entry.key);
    if (!key) continue;
    out[key] = anyValueToString(entry.value as OtlpAnyValue | undefined);
  }
  return out;
}

/** The `resource.attributes` of one resource block, flattened. */
function resourceAttributesOf(resource: unknown): Attributes {
  return isRecord(resource) ? flattenAttributes(resource.attributes) : {};
}

function scopeNameOf(scope: unknown): string {
  return isRecord(scope) ? asString(scope.name) : "";
}

/** Nanosecond difference as milliseconds. BigInt because nanos exceed 2^53. */
function durationMsOf(start: string, end: string): number {
  try {
    if (!/^\d+$/.test(start) || !/^\d+$/.test(end)) return 0;
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

/** Require the top-level envelope key and return its entries. */
function topLevelArray(body: unknown, key: string): unknown[] {
  if (!isRecord(body)) {
    throw new OtlpParseError(`expected a JSON object with a "${key}" array`);
  }
  const value = body[key];
  if (!Array.isArray(value)) {
    throw new OtlpParseError(`missing or non-array "${key}"`);
  }
  return value;
}

/** A numeric data-point value: `asDouble`, or `asInt` (a JSON string in OTLP). */
function numericValueOf(point: Record<string, unknown>): number | null {
  if (typeof point.asDouble === "number" && Number.isFinite(point.asDouble)) {
    return point.asDouble;
  }
  if (typeof point.asInt === "string" || typeof point.asInt === "number") {
    const parsed = Number(point.asInt);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/**
 * Parse `POST /v1/metrics`:
 * `{resourceMetrics:[{resource,scopeMetrics:[{scope,metrics:[...]}]}]}`.
 *
 * FerroGate emits every metric as a monotonic `sum` with one `dataPoints[]`
 * entry carrying `asDouble`; `gauge` and `histogram` are also accepted because
 * Cloudflare's native Workers OTLP export emits them into this same collector.
 */
export function parseMetrics(body: unknown): ParseResult<ParsedMetricPoint> {
  const records: ParsedMetricPoint[] = [];
  let skipped = 0;

  for (const resourceMetrics of topLevelArray(body, "resourceMetrics")) {
    if (!isRecord(resourceMetrics)) {
      skipped++;
      continue;
    }
    const resourceAttributes = resourceAttributesOf(resourceMetrics.resource);
    const serviceName = serviceNameOf(resourceAttributes);

    for (const scopeMetrics of asArray(resourceMetrics.scopeMetrics)) {
      if (!isRecord(scopeMetrics)) {
        skipped++;
        continue;
      }
      const scopeName = scopeNameOf(scopeMetrics.scope);

      for (const metric of asArray(scopeMetrics.metrics)) {
        if (!isRecord(metric)) {
          skipped++;
          continue;
        }
        const name = asString(metric.name);
        const description = asString(metric.description);
        const kind: ParsedMetricPoint["kind"] = isRecord(metric.sum)
          ? "sum"
          : isRecord(metric.gauge)
            ? "gauge"
            : isRecord(metric.histogram)
              ? "histogram"
              : "sum";
        const container = (metric.sum ?? metric.gauge ?? metric.histogram) as
          | Record<string, unknown>
          | undefined;
        if (!name || !isRecord(container)) {
          skipped++;
          continue;
        }

        for (const point of asArray(container.dataPoints)) {
          if (!isRecord(point)) {
            skipped++;
            continue;
          }
          // A histogram point carries `sum`/`count` rather than a scalar.
          const value =
            kind === "histogram"
              ? (typeof point.sum === "number" ? point.sum : Number(point.count ?? 0))
              : numericValueOf(point);
          if (value === null || !Number.isFinite(value)) {
            skipped++;
            continue;
          }
          records.push({
            name,
            description,
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

/**
 * Parse `POST /v1/traces`:
 * `{resourceSpans:[{resource,scopeSpans:[{scope,spans:[...]}]}]}`.
 *
 * A span with no `traceId`/`spanId` is unusable (nothing to correlate on) and is
 * skipped rather than written.
 */
export function parseTraces(body: unknown): ParseResult<ParsedSpan> {
  const records: ParsedSpan[] = [];
  let skipped = 0;

  for (const resourceSpans of topLevelArray(body, "resourceSpans")) {
    if (!isRecord(resourceSpans)) {
      skipped++;
      continue;
    }
    const resourceAttributes = resourceAttributesOf(resourceSpans.resource);
    const serviceName = serviceNameOf(resourceAttributes);

    for (const scopeSpans of asArray(resourceSpans.scopeSpans)) {
      if (!isRecord(scopeSpans)) {
        skipped++;
        continue;
      }
      const scopeName = scopeNameOf(scopeSpans.scope);

      for (const span of asArray(scopeSpans.spans)) {
        if (!isRecord(span)) {
          skipped++;
          continue;
        }
        const traceId = asString(span.traceId);
        const spanId = asString(span.spanId);
        if (!traceId || !spanId) {
          skipped++;
          continue;
        }
        const startTimeUnixNano = asString(span.startTimeUnixNano);
        const endTimeUnixNano = asString(span.endTimeUnixNano);
        records.push({
          traceId,
          spanId,
          // `parentSpanId` is `null` for a root span in the Rust encoder.
          parentSpanId: asString(span.parentSpanId),
          name: asString(span.name),
          kind: typeof span.kind === "number" ? span.kind : 0,
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

  for (const resourceLogs of topLevelArray(body, "resourceLogs")) {
    if (!isRecord(resourceLogs)) {
      skipped++;
      continue;
    }
    const resourceAttributes = resourceAttributesOf(resourceLogs.resource);
    const serviceName = serviceNameOf(resourceAttributes);

    for (const scopeLogs of asArray(resourceLogs.scopeLogs)) {
      if (!isRecord(scopeLogs)) {
        skipped++;
        continue;
      }
      const scopeName = scopeNameOf(scopeLogs.scope);

      for (const record of asArray(scopeLogs.logRecords)) {
        if (!isRecord(record)) {
          skipped++;
          continue;
        }
        const body = isRecord(record.body)
          ? anyValueToString(record.body as OtlpAnyValue)
          : asString(record.body);
        records.push({
          timeUnixNano: asString(record.timeUnixNano),
          traceId: asString(record.traceId),
          spanId: asString(record.spanId),
          severityText: asString(record.severityText),
          body,
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
