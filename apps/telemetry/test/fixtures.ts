/**
 * OTLP/JSON payload builders and test doubles shared by the suite.
 *
 * The payload shapes are the ones `@ferrogate/observability`'s OTLP builders
 * emit (`buildOtlpMetricsRequest` / `Traces` / `Logs`) and the ones Cloudflare's
 * native Workers OTLP export emits — the same wire format the deployed
 * collector must accept.
 */
import type { AnalyticsEngineLike, TelemetryEnv } from "../src/index.js";

/** Must match `COLLECTOR_TOKEN` in `vitest.config.ts`. */
export const COLLECTOR_TOKEN = "test-collector-token";

/** Must match `MAX_BODY_BYTES` in `vitest.config.ts`. */
export const TEST_MAX_BODY_BYTES = 2048;

export const TENANT = "tenant-a";
export const SERVICE = "ferrogate-gateway";
export const SCOPE = "ferrogate";

export const TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
export const SPAN_ID = "00f067aa0ba902b7";
export const PARENT_SPAN_ID = "00f067aa0ba902b6";
/** 500 ms apart, in nanoseconds — beyond 2^53, so BigInt math is required. */
export const START_NANO = "1700000000000000000";
export const END_NANO = "1700000000500000000";

/** Headers for an authorized OTLP POST. */
export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    authorization: `Bearer ${COLLECTOR_TOKEN}`,
    "content-type": "application/json",
    ...extra,
  };
}

function attr(key: string, value: string): unknown {
  return { key, value: { stringValue: value } };
}

/** The resource block every payload carries: service name + tenant attribute. */
function resource(): unknown {
  return { attributes: [attr("service.name", SERVICE), attr("ferrogate.tenant_id", TENANT)] };
}

/** A one-point OTLP metrics batch (`sum`, the kind FerroGate emits). */
export function metricsPayload(extraMetrics: unknown[] = []): unknown {
  return {
    resourceMetrics: [
      {
        resource: resource(),
        scopeMetrics: [
          {
            scope: { name: SCOPE },
            metrics: [
              {
                name: "ferrogate.requests.total",
                description: "total gateway requests",
                sum: {
                  isMonotonic: true,
                  aggregationTemporality: 2,
                  dataPoints: [
                    {
                      asDouble: 42,
                      timeUnixNano: END_NANO,
                      attributes: [attr("status", "200")],
                    },
                  ],
                },
              },
              ...extraMetrics,
            ],
          },
        ],
      },
    ],
  };
}

/** A one-span OTLP traces batch. */
export function tracesPayload(extraSpans: unknown[] = []): unknown {
  return {
    resourceSpans: [
      {
        resource: resource(),
        scopeSpans: [
          {
            scope: { name: SCOPE },
            spans: [
              {
                traceId: TRACE_ID,
                spanId: SPAN_ID,
                parentSpanId: PARENT_SPAN_ID,
                name: "ferrogate.request",
                kind: 2,
                startTimeUnixNano: START_NANO,
                endTimeUnixNano: END_NANO,
                attributes: [attr("http.route", "/v1/chat/completions")],
              },
              ...extraSpans,
            ],
          },
        ],
      },
    ],
  };
}

/** A one-record OTLP logs batch. */
export function logsPayload(extraRecords: unknown[] = []): unknown {
  return {
    resourceLogs: [
      {
        resource: resource(),
        scopeLogs: [
          {
            scope: { name: SCOPE },
            logRecords: [
              {
                timeUnixNano: END_NANO,
                severityText: "ERROR",
                severityNumber: 17,
                traceId: TRACE_ID,
                spanId: SPAN_ID,
                body: { stringValue: "upstream refused the request" },
                attributes: [attr("provider", "openai")],
              },
              ...extraRecords,
            ],
          },
        ],
      },
    ],
  };
}

/**
 * An Analytics Engine binding stub. The deployed `resolveSink` wraps whatever
 * `env.TELEMETRY` holds in an `AnalyticsEngineSink`, so handing the REAL
 * exported app one of these exercises the production resolver and the
 * production write path while making the points assertable — the live binding
 * cannot be read back from inside a Worker (its only read API is SQL).
 */
export class RecordingDataset implements AnalyticsEngineLike {
  readonly points: Array<{ indexes?: string[]; blobs?: string[]; doubles?: number[] }> = [];

  writeDataPoint(point: { indexes?: string[]; blobs?: string[]; doubles?: number[] }): void {
    this.points.push(point);
  }
}

/** An Analytics Engine binding that always throws, to prove writes are counted. */
export class ThrowingDataset implements AnalyticsEngineLike {
  calls = 0;

  writeDataPoint(): void {
    this.calls++;
    throw new Error("dataset rejected the point");
  }
}

/** A production-shaped env with the sink configured. */
export function envWithSink(dataset: AnalyticsEngineLike): TelemetryEnv {
  return { TELEMETRY: dataset, COLLECTOR_TOKEN, MAX_BODY_BYTES: String(TEST_MAX_BODY_BYTES) };
}

/** The same env with NO Analytics Engine binding — an unconfigured deploy. */
export function envWithoutSink(): TelemetryEnv {
  return { COLLECTOR_TOKEN, MAX_BODY_BYTES: String(TEST_MAX_BODY_BYTES) };
}
