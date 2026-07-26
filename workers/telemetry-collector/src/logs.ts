// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — structured Workers Logs emission for
//   the telemetry-collector Worker (issue #520). Workers Logs auto-extracts and INDEXES the
//   fields of a JSON object logged with console.log, so every record is emitted as one flat
//   JSON line — the searchable half of the store that Analytics Engine cannot serve.

import type { ParsedLogRecord, ParsedSpan, Attributes } from "./otlp";
import { LOG_FIELD_MAX_CHARS, LOG_LINE_MAX_BYTES, byteLength, truncateUtf8 } from "./limits";

/** Max attribute pairs carried on a log line before the rest are elided. */
const MAX_LOG_ATTRIBUTES = 32;

/** Severities that should reach `console.error` / `console.warn`. */
const ERROR_SEVERITIES = new Set(["ERROR", "FATAL", "CRITICAL", "SEVERE"]);
const WARN_SEVERITIES = new Set(["WARN", "WARNING"]);

/** Shorten a field so no single value can blow the line budget on its own. */
function field(value: string): string {
  return value.length > LOG_FIELD_MAX_CHARS ? `${value.slice(0, LOG_FIELD_MAX_CHARS)}…` : value;
}

/**
 * Flatten attributes onto the line as `attr.<key>`, capped in count and length.
 *
 * Flat scalar fields (not a nested object) are what Workers Logs indexes, and a
 * bounded set of them is what keeps the line inside the much tighter Logpush
 * `logs`+`exceptions` budget (16,384 chars combined per invocation).
 */
function attributeFields(attributes: Attributes): Record<string, string> {
  const out: Record<string, string> = {};
  const keys = Object.keys(attributes).sort().slice(0, MAX_LOG_ATTRIBUTES);
  for (const key of keys) {
    out[`attr.${key}`] = field(attributes[key]);
  }
  return out;
}

/**
 * Serialize one line, guaranteeing it stays under the 256 KB Workers Logs cap.
 *
 * Over budget, `attr.*` fields go first and the body is clipped — a truncated but
 * well-formed JSON line stays indexable, whereas a platform-truncated one is
 * unparseable and loses every field after the cut.
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
 * line so the behaviour is assertable without capturing the console.
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
 * Emit one span as an indexed Workers Logs line. Spans go to BOTH stores: the AE
 * point carries the queryable numeric summary, this line carries the correlatable
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
