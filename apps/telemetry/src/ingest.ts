/**
 * The per-signal OTLP ingest pipeline: size-check the body, parse and validate
 * the OTLP/JSON shape, fan each record into the sink (and Workers Logs), and
 * answer with the accepted/dataPoints/dropped summary.
 *
 * Kept out of `app.ts` so routing stays logic-free.
 *
 * ## Status taxonomy
 *
 * | Condition | Status | Code |
 * |---|---|---|
 * | binary OTLP (`application/x-protobuf`) | 415 | `unsupported_media_type` |
 * | no Analytics Engine binding | 503 | `telemetry_sink_unavailable` |
 * | body over the ceiling | 413 | `payload_too_large` |
 * | body unreadable / not JSON | 400 | `malformed_request_body` |
 * | JSON but not this signal's envelope | 400 | `invalid_otlp_payload` |
 * | accepted (possibly with skipped records) | 200 | — |
 *
 * The 503 is checked BEFORE the body is buffered: an unconfigured collector
 * must not spend the isolate's memory on a batch it cannot store.
 */
import { resolveTenant, tenantFromHeaders } from "./auth.js";
import { TelemetryErrorCode, errorResponse } from "./errors.js";
import { resolveMaxBodyBytes } from "./limits.js";
import { emitIngestSummary, emitLogRecord, emitSpan } from "./logs.js";
import { OtlpEnvelopeError, parseLogs, parseMetrics, parseTraces } from "./otlp.js";
import type { TelemetryEnv } from "./ports.js";
import { resolveSink } from "./ports.js";
import { REJECTED_FIELD_BY_SIGNAL, type Signal } from "./schemas.js";
import { SinkWriter, type TelemetrySink } from "./sink.js";

/** The response contract FerroGate's exporter parses. */
export interface IngestSummary {
  /** Records taken from the payload (data points / spans / log records). */
  accepted: number;
  /** Points actually handed to the sink. */
  dataPoints: number;
  /** Records lost: unusable in the payload, or over the AE per-invocation cap. */
  dropped: number;
  /**
   * OTLP's own partial-success field, present ONLY when something was lost. The
   * counter is named per signal (`rejectedDataPoints` / `rejectedSpans` /
   * `rejectedLogRecords`) because that is what OTLP clients read.
   */
  partialSuccess?: Record<string, unknown>;
}

type BodyRead = { ok: true; value: unknown } | { ok: false; response: Response };

/**
 * Read the request body with a hard size ceiling, then parse it as JSON.
 *
 * The declared `Content-Length` is checked first so an oversized batch is
 * rejected without buffering it, and the buffered length is checked again
 * because the header is caller-supplied and may lie (or be absent entirely on a
 * chunked upload).
 */
export async function readJsonBody(request: Request, limit: number): Promise<BodyRead> {
  const tooLarge = () =>
    errorResponse(
      413,
      TelemetryErrorCode.PayloadTooLarge,
      `OTLP payload exceeds the ${limit}-byte ceiling`,
      null,
      { limit },
    );

  const declared = Number.parseInt(request.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > limit) {
    return { ok: false, response: tooLarge() };
  }

  let raw: ArrayBuffer;
  try {
    raw = await request.arrayBuffer();
  } catch {
    return {
      ok: false,
      response: errorResponse(
        400,
        TelemetryErrorCode.MalformedBody,
        "could not read the request body",
      ),
    };
  }
  if (raw.byteLength > limit) {
    return { ok: false, response: tooLarge() };
  }

  try {
    return { ok: true, value: JSON.parse(new TextDecoder().decode(raw)) as unknown };
  } catch (error) {
    return {
      ok: false,
      response: errorResponse(400, TelemetryErrorCode.MalformedBody, "malformed JSON body", null, {
        detail: error instanceof Error ? error.message : "",
      }),
    };
  }
}

/**
 * Cloudflare runs no binary OTLP anywhere, so protobuf is refused explicitly
 * rather than failing as "malformed JSON" and sending the client hunting.
 */
function rejectProtobuf(request: Request): Response | null {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("protobuf")) return null;
  return errorResponse(
    415,
    TelemetryErrorCode.UnsupportedMediaType,
    "OTLP/JSON only: Cloudflare supports no binary OTLP; send application/json",
  );
}

/**
 * Run one OTLP batch end to end.
 *
 * Ordering matters: Workers Logs emission happens for every record, while sink
 * writes stop at the per-invocation cap. Logs are therefore the complete record
 * and the sink the sampled/aggregate one — an over-cap batch still leaves a
 * full trail, and the shortfall is reported as `dropped`.
 *
 * @param sinkOverride injected by callers that already resolved the port
 *   (tests); production passes nothing and the sink comes from `env`.
 */
export async function handleIngest(
  signal: Signal,
  request: Request,
  env: TelemetryEnv | undefined,
  sinkOverride?: TelemetrySink | null,
): Promise<Response> {
  const unsupportedMedia = rejectProtobuf(request);
  if (unsupportedMedia) return unsupportedMedia;

  const sink = sinkOverride ?? resolveSink(env);
  if (!sink) {
    // Mirrors `apps/gateway`'s `503 asset_bucket_unavailable`: the binding is
    // absent, so the whole family degrades with a clear, machine-readable
    // refusal instead of a binding-is-undefined TypeError.
    return errorResponse(
      503,
      TelemetryErrorCode.SinkUnavailable,
      "telemetry ingest requires an Analytics Engine dataset binding (TELEMETRY) to be configured",
    );
  }

  const body = await readJsonBody(request, resolveMaxBodyBytes(env?.MAX_BODY_BYTES));
  if (!body.ok) return body.response;

  const headerTenant = tenantFromHeaders(request);
  const writer = new SinkWriter(sink);

  let accepted = 0;
  let skipped = 0;

  try {
    if (signal === "metrics") {
      const parsed = parseMetrics(body.value);
      skipped = parsed.skipped;
      accepted = parsed.records.length;
      for (const metric of parsed.records) {
        writer.writeMetric(
          metric,
          resolveTenant(headerTenant, metric.resourceAttributes, metric.attributes),
        );
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
        writer.writeLog(record, tenant);
        emitLogRecord(record, tenant);
      }
    }
  } catch (error) {
    if (error instanceof OtlpEnvelopeError) {
      return errorResponse(
        400,
        TelemetryErrorCode.InvalidOtlpPayload,
        `invalid OTLP ${signal} payload: ${error.message}`,
        null,
        error.issues.length > 0 ? { detail: error.issues } : undefined,
      );
    }
    throw error;
  }

  const sinkSummary = writer.finish(signal);
  const dropped = sinkSummary.dropped + skipped;
  const summary: IngestSummary = {
    accepted,
    dataPoints: sinkSummary.written,
    // Both loss modes are reported in one number the exporter can alert on; the
    // breakdown goes to the ingest log line below.
    dropped,
    ...(dropped > 0
      ? {
          partialSuccess: {
            [REJECTED_FIELD_BY_SIGNAL[signal]]: dropped,
            errorMessage: `${skipped} unusable record(s), ${sinkSummary.dropped} over the per-invocation write cap`,
          },
        }
      : {}),
  };

  emitIngestSummary({
    signal,
    sink: sink.name,
    tenant: headerTenant ?? "",
    accepted,
    dataPoints: sinkSummary.written,
    droppedOverCap: sinkSummary.dropped,
    droppedUnusable: skipped,
    blobTruncated: sinkSummary.truncated,
  });

  return new Response(JSON.stringify(summary), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
