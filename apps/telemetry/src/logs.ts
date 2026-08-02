/**
 * Structured Workers Logs emission.
 *
 * Workers Logs auto-extracts and INDEXES the fields of a JSON object passed to
 * `console.log`, so every record is emitted as one flat JSON line — the
 * searchable half of the store that Analytics Engine (positional blobs, SQL
 * read API) cannot serve. Lines are kept lean because the neighbouring
 * `workers_trace_events` Logpush dataset truncates `logs` + `exceptions` at a
 * COMBINED 16,384 characters per invocation (`LOGPUSH_COMBINED_CHAR_BUDGET` in
 * `limits.ts`).
 */
import {
  LOG_FIELD_MAX_CHARS,
  LOG_LINE_MAX_BYTES,
  LOG_MAX_ATTRIBUTES,
  byteLength,
  truncateUtf8,
} from "./limits.js";
import type { Attributes, ParsedLogRecord, ParsedSpan } from "./otlp.js";

/** Severities routed to `console.error` / `console.warn`. */
const ERROR_SEVERITIES = new Set(["ERROR", "FATAL", "CRITICAL", "SEVERE"]);
const WARN_SEVERITIES = new Set(["WARN", "WARNING"]);

/** Shorten a field so no single value can blow the line budget on its own. */
function field(value: string): string {
  return value.length > LOG_FIELD_MAX_CHARS ? `${value.slice(0, LOG_FIELD_MAX_CHARS)}…` : value;
}

/**
 * Flatten attributes onto the line as `attr.<key>`, capped in count and length.
 * Flat scalar fields are what Workers Logs indexes; a nested object is not.
 */
function attributeFields(attributes: Attributes): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of Object.keys(attributes).sort().slice(0, LOG_MAX_ATTRIBUTES)) {
    out[`attr.${key}`] = field(attributes[key] ?? "");
  }
  return out;
}

/**
 * Serialize one line, guaranteeing it stays under the 256 KB Workers Logs cap.
 *
 * Over budget, `attr.*` fields go first and the body is clipped: a truncated
 * but well-formed JSON line stays indexable, whereas a platform-truncated one
 * is unparseable and loses every field after the cut.
 */
export function serializeLine(entry: Record<string, unknown>): string {
  let line = JSON.stringify(entry);
  if (byteLength(line) <= LOG_LINE_MAX_BYTES) return line;

  const stripped: Record<string, unknown> = { ...entry, truncated: true };
  for (const key of Object.keys(stripped)) {
    if (key.startsWith("attr.")) delete stripped[key];
  }
  line = JSON.stringify(stripped);
  if (byteLength(line) <= LOG_LINE_MAX_BYTES) return line;

  if (typeof stripped.body === "string") {
    // Leave headroom for the rest of the envelope.
    stripped.body = truncateUtf8(stripped.body, Math.floor(LOG_LINE_MAX_BYTES / 2));
    line = JSON.stringify(stripped);
    if (byteLength(line) <= LOG_LINE_MAX_BYTES) return line;
  }

  return truncateUtf8(line, LOG_LINE_MAX_BYTES);
}

/** Route a line to the console method matching its severity. */
function emit(severityText: string, line: string): void {
  const severity = severityText.toUpperCase();
  if (ERROR_SEVERITIES.has(severity)) {
    console.error(line);
  } else if (WARN_SEVERITIES.has(severity)) {
    console.warn(line);
  } else {
    console.log(line);
  }
}

/**
 * Emit one OTLP log record as an indexed Workers Logs line. Returns the emitted
 * line so the behavior is assertable without capturing the console.
 */
export function emitLogRecord(record: ParsedLogRecord, tenant: string): string {
  const line = serializeLine({
    source: "ferrogate.otlp",
    signal: "log",
    tenant,
    service: record.serviceName,
    scope: record.scopeName,
    severity: record.severityText || "INFO",
    timeUnixNano: record.timeUnixNano,
    traceId: record.traceId,
    spanId: record.spanId,
    body: field(record.body),
    ...attributeFields(record.attributes),
  });
  emit(record.severityText, line);
  return line;
}

/**
 * Emit one span as an indexed Workers Logs line. Spans go to BOTH stores: the
 * AE point carries the queryable numeric summary, this line the correlatable
 * ids and attributes.
 */
export function emitSpan(span: ParsedSpan, tenant: string): string {
  const line = serializeLine({
    source: "ferrogate.otlp",
    signal: "span",
    tenant,
    service: span.serviceName,
    scope: span.scopeName,
    name: span.name,
    traceId: span.traceId,
    spanId: span.spanId,
    parentSpanId: span.parentSpanId,
    kind: span.kind,
    startTimeUnixNano: span.startTimeUnixNano,
    endTimeUnixNano: span.endTimeUnixNano,
    durationMs: span.durationMs,
    ...attributeFields(span.attributes),
  });
  console.log(line);
  return line;
}

/** Emit the per-request ingest summary (one line per accepted batch). */
export function emitIngestSummary(entry: Record<string, unknown>): string {
  const line = serializeLine({ source: "ferrogate.otlp", signal: "ingest", ...entry });
  console.log(line);
  return line;
}
