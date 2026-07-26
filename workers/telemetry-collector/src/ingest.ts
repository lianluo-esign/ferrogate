// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — the per-signal ingest pipeline of the
//   telemetry-collector Worker (issue #520): read + size-check the body, parse the OTLP/JSON
//   shape, fan each record into Analytics Engine and Workers Logs, and answer with the
//   accepted/dataPoints/dropped summary. Kept out of index.ts so routing stays logic-free.

import { json, resolveTenant, tenantFromHeaders } from "./auth";
import { AnalyticsWriter, type AnalyticsEngineLike } from "./analytics";
import { emitIngestSummary, emitLogRecord, emitSpan } from "./logs";
import { DEFAULT_MAX_BODY_BYTES } from "./limits";
import { OtlpParseError, parseLogs, parseMetrics, parseTraces } from "./otlp";

/** The three OTLP signals this collector ingests. */
export type Signal = "metrics" | "traces" | "logs";

/** Everything the pipeline needs from the environment. */
export interface IngestEnv {
  TELEMETRY?: AnalyticsEngineLike;
  MAX_BODY_BYTES?: string;
}

/** The response contract FerroGate's Rust exporter parses. */
export interface IngestSummary {
  /** Records taken from the payload (data points / spans / log records). */
  accepted: number;
  /** Analytics Engine `writeDataPoint()` calls actually made. */
  dataPoints: number;
  /** Records lost: unusable in the payload, or over the AE per-invocation cap. */
  dropped: number;
}

/** The configured body cap, falling back to {@link DEFAULT_MAX_BODY_BYTES}. */
export function maxBodyBytes(env: IngestEnv): number {
  const parsed = Number.parseInt(env.MAX_BODY_BYTES ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_BODY_BYTES;
}

type BodyRead =
  | { ok: true; value: unknown }
  | { ok: false; response: Response };

/**
 * Read the request body with a hard size ceiling, then parse it as JSON.
 *
 * The declared `Content-Length` is checked first so an oversized batch is
 * rejected without buffering it, and the buffered length is checked again
 * because the header is caller-supplied and may lie.
 */
export async function readJsonBody(request: Request, limit: number): Promise<BodyRead> {
  const declared = Number.parseInt(request.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > limit) {
    return { ok: false, response: json({ error: "payload too large", limit }, 413) };
  }

  let raw: ArrayBuffer;
  try {
    raw = await request.arrayBuffer();
  } catch {
    return { ok: false, response: json({ error: "could not read request body" }, 400) };
  }
  if (raw.byteLength > limit) {
    return { ok: false, response: json({ error: "payload too large", limit }, 413) };
  }

  try {
    return { ok: true, value: JSON.parse(new TextDecoder().decode(raw)) as unknown };
  } catch (error) {
    return {
      ok: false,
      response: json(
        { error: "malformed JSON body", detail: error instanceof Error ? error.message : "" },
        400,
      ),
    };
  }
}

/**
 * Run one OTLP batch end to end.
 *
 * Ordering matters: Workers Logs emission happens for every record, while
 * Analytics Engine writes stop at the 250-per-invocation cap. Logs are therefore
 * the complete record and AE the sampled/aggregate one — so an over-cap batch
 * still leaves a full trail, and the shortfall is reported as `dropped`.
 */
export async function handleIngest(
  signal: Signal,
  request: Request,
  env: IngestEnv,
): Promise<Response> {
  const body = await readJsonBody(request, maxBodyBytes(env));
  if (!body.ok) return body.response;

  const headerTenant = tenantFromHeaders(request);
  const writer = new AnalyticsWriter(env.TELEMETRY);

  let accepted = 0;
  let skipped = 0;

  try {
    if (signal === "metrics") {
      const parsed = parseMetrics(body.value);
      skipped = parsed.skipped;
      accepted = parsed.records.length;
      for (const metric of parsed.records) {
        const tenant = resolveTenant(headerTenant, metric.resourceAttributes, metric.attributes);
        writer.writeMetric(metric, tenant);
      }
    } else if (signal === "traces") {
      const parsed = parseTraces(body.value);
      skipped = parsed.skipped;
      accepted = parsed.records.length;
      for (const span of parsed.records) {
        const tenant = resolveTenant(headerTenant, span.resourceAttributes, span.attributes);
        writer.writeSpan(span, tenant);
        emitSpan(span, tenant);
      }
    } else {
      const parsed = parseLogs(body.value);
      skipped = parsed.skipped;
      accepted = parsed.records.length;
      for (const record of parsed.records) {
        const tenant = resolveTenant(headerTenant, record.resourceAttributes, record.attributes);
        emitLogRecord(record, tenant);
      }
    }
  } catch (error) {
    if (error instanceof OtlpParseError) {
      return json({ error: `invalid OTLP ${signal} payload`, detail: error.message }, 400);
    }
    throw error;
  }

  const analytics = writer.finish(signal);
  const summary: IngestSummary = {
    accepted,
    dataPoints: analytics.written,
    // Both loss modes are reported in one number the exporter can alert on; the
    // breakdown goes to the ingest log line below.
    dropped: analytics.dropped + skipped,
  };

  emitIngestSummary({
    signal,
    tenant: headerTenant ?? "",
    accepted,
    dataPoints: analytics.written,
    droppedOverCap: analytics.dropped,
    droppedUnusable: skipped,
    blobTruncated: analytics.truncated,
  });

  return json(summary, 200);
}
