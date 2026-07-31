/**
 * Zod schemas for the three OTLP/HTTP **JSON** payload shapes this Worker
 * ingests (`docs/legacy/inventory-data-billing.md` §4.2 `otlp`, §4.4).
 *
 * JSON only, never protobuf: Cloudflare supports no binary OTLP anywhere, so
 * JSON is a platform constraint rather than a preference. The field names below
 * mirror `crates/ferrogate-observability/src/otlp.rs` and are the same shapes
 * Cloudflare's own native Workers OTLP export emits — one parser, both
 * producers.
 *
 * ## Two levels of strictness, on purpose
 *
 * - The **envelope** (`resourceMetrics` / `resourceSpans` / `resourceLogs`) is
 *   validated strictly. A body that is not the OTLP envelope at all is a client
 *   bug, and the receiver answers `400`.
 * - **Individual records** are validated with `safeParse` and *skipped* on
 *   failure, never 400. OTLP exporters retry whole batches, so failing 5,000
 *   good spans over one malformed span would amplify load instead of shedding
 *   it. Skipped records are counted and reported back in the response.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// AnyValue / KeyValue (recursive)
// ---------------------------------------------------------------------------

/** An OTLP `KeyValue` attribute: `{ key, value: { stringValue } }`. */
export interface OtlpKeyValue {
  key: string;
  value?: OtlpAnyValue;
}

/**
 * An OTLP `AnyValue`. FerroGate only ever emits `stringValue`; Cloudflare's
 * native Worker export uses the rest, and both land in this collector.
 */
export interface OtlpAnyValue {
  stringValue?: string;
  /** OTLP encodes 64-bit ints as JSON **strings** to survive `Number` precision. */
  intValue?: string | number;
  doubleValue?: number;
  boolValue?: boolean;
  bytesValue?: string;
  arrayValue?: { values?: OtlpAnyValue[] };
  kvlistValue?: { values?: OtlpKeyValue[] };
}

export const anyValueSchema: z.ZodType<OtlpAnyValue> = z.lazy(() =>
  z.object({
    stringValue: z.string().optional(),
    intValue: z.union([z.string(), z.number()]).optional(),
    doubleValue: z.number().optional(),
    boolValue: z.boolean().optional(),
    bytesValue: z.string().optional(),
    arrayValue: z.object({ values: z.array(anyValueSchema).optional() }).optional(),
    kvlistValue: z.object({ values: z.array(keyValueSchema).optional() }).optional(),
  }),
);

export const keyValueSchema: z.ZodType<OtlpKeyValue> = z.lazy(() =>
  z.object({ key: z.string(), value: anyValueSchema.optional() }),
);

/** `attributes` is optional everywhere in OTLP; absent means "no attributes". */
const attributesSchema = z.array(keyValueSchema).optional();

/** OTLP encodes nanosecond timestamps as strings; some producers send numbers. */
const unixNanoSchema = z.union([z.string(), z.number()]).optional();

// ---------------------------------------------------------------------------
// Shared resource / scope blocks
// ---------------------------------------------------------------------------

export const resourceSchema = z.object({ attributes: attributesSchema });
export const scopeSchema = z.object({ name: z.string().optional() });

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/**
 * `POST /v1/metrics` envelope:
 * `{ resourceMetrics: [{ resource, scopeMetrics: [{ scope, metrics: [...] }] }] }`.
 *
 * Entries stay `unknown` here so one malformed resource block cannot 400 the
 * whole batch; each is validated (and skipped) individually while parsing.
 */
export const otlpMetricsEnvelopeSchema = z.object({
  resourceMetrics: z.array(z.unknown()),
});

export const resourceMetricsSchema = z.object({
  resource: resourceSchema.optional(),
  scopeMetrics: z.array(z.unknown()).optional(),
});

export const scopeMetricsSchema = z.object({
  scope: scopeSchema.optional(),
  metrics: z.array(z.unknown()).optional(),
});

const dataPointsSchema = z.object({ dataPoints: z.array(z.unknown()).optional() });

/**
 * FerroGate emits every metric as a monotonic `sum`; `gauge` and `histogram`
 * are accepted too because Cloudflare's native Workers OTLP export emits them
 * into this same collector.
 */
export const metricSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  unit: z.string().optional(),
  sum: dataPointsSchema.optional(),
  gauge: dataPointsSchema.optional(),
  histogram: dataPointsSchema.optional(),
});

/** A scalar (`sum` / `gauge`) point: `asDouble`, or `asInt` as a JSON string. */
export const numberDataPointSchema = z.object({
  attributes: attributesSchema,
  timeUnixNano: unixNanoSchema,
  asDouble: z.number().optional(),
  asInt: z.union([z.string(), z.number()]).optional(),
});

/** A histogram point carries `sum`/`count` rather than a scalar value. */
export const histogramDataPointSchema = z.object({
  attributes: attributesSchema,
  timeUnixNano: unixNanoSchema,
  sum: z.number().optional(),
  count: z.union([z.string(), z.number()]).optional(),
});

// ---------------------------------------------------------------------------
// Traces
// ---------------------------------------------------------------------------

/**
 * `POST /v1/traces` envelope:
 * `{ resourceSpans: [{ resource, scopeSpans: [{ scope, spans: [...] }] }] }`.
 */
export const otlpTracesEnvelopeSchema = z.object({
  resourceSpans: z.array(z.unknown()),
});

export const resourceSpansSchema = z.object({
  resource: resourceSchema.optional(),
  scopeSpans: z.array(z.unknown()).optional(),
});

export const scopeSpansSchema = z.object({
  scope: scopeSchema.optional(),
  spans: z.array(z.unknown()).optional(),
});

/**
 * `traceId`/`spanId` are REQUIRED: a span with neither is uncorrelatable, so it
 * is skipped rather than written under a fabricated id.
 */
export const spanSchema = z.object({
  traceId: z.string().min(1),
  spanId: z.string().min(1),
  parentSpanId: z.string().optional(),
  name: z.string().optional(),
  kind: z.number().optional(),
  startTimeUnixNano: unixNanoSchema,
  endTimeUnixNano: unixNanoSchema,
  attributes: attributesSchema,
});

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

/**
 * `POST /v1/logs` envelope:
 * `{ resourceLogs: [{ resource, scopeLogs: [{ scope, logRecords: [...] }] }] }`.
 */
export const otlpLogsEnvelopeSchema = z.object({
  resourceLogs: z.array(z.unknown()),
});

export const resourceLogsSchema = z.object({
  resource: resourceSchema.optional(),
  scopeLogs: z.array(z.unknown()).optional(),
});

export const scopeLogsSchema = z.object({
  scope: scopeSchema.optional(),
  logRecords: z.array(z.unknown()).optional(),
});

/** `body` is an `AnyValue` in OTLP; a bare string is accepted for tolerance. */
export const logRecordSchema = z.object({
  timeUnixNano: unixNanoSchema,
  observedTimeUnixNano: unixNanoSchema,
  traceId: z.string().optional(),
  spanId: z.string().optional(),
  severityText: z.string().optional(),
  severityNumber: z.number().optional(),
  body: z.union([anyValueSchema, z.string()]).optional(),
  attributes: attributesSchema,
});

// ---------------------------------------------------------------------------
// Signal → envelope
// ---------------------------------------------------------------------------

/** The three OTLP signals this collector ingests. */
export type Signal = "metrics" | "traces" | "logs";

/** The envelope schema and its required top-level key, per signal. */
export const ENVELOPE_BY_SIGNAL = {
  metrics: { schema: otlpMetricsEnvelopeSchema, key: "resourceMetrics" },
  traces: { schema: otlpTracesEnvelopeSchema, key: "resourceSpans" },
  logs: { schema: otlpLogsEnvelopeSchema, key: "resourceLogs" },
} as const satisfies Record<Signal, { schema: z.ZodTypeAny; key: string }>;

/**
 * The OTLP `partialSuccess` field name per signal — the spec names the rejected
 * counter after the signal's record type, and clients key off exactly that.
 */
export const REJECTED_FIELD_BY_SIGNAL = {
  metrics: "rejectedDataPoints",
  traces: "rejectedSpans",
  logs: "rejectedLogRecords",
} as const satisfies Record<Signal, string>;
