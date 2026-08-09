/**
 * OTLP/HTTP export: span/log record types and JSON request builders for
 * metrics, traces, and logs. Clean-room port of
 * `ferrogate-observability::otlp`.
 *
 * OTLP/**JSON**, not protobuf — matching Cloudflare's native Workers OTLP
 * export so trace ids line up across a CF-hosted Worker hop and a gateway
 * request. Builders throw {@link ObservabilityConfigError} on a missing/invalid
 * endpoint (Rust returned `Err`); on success they return an
 * {@link OtlpHttpRequest} whose `body` is the serialized bytes.
 */
import { ObservabilityConfigError, ObservabilityExporterKind } from "./config.js";
import { genAiMetricsJson } from "./genai.js";
import type { GatewayMetricsSnapshot } from "./metrics.js";

/** Version stamped into the OTLP instrumentation scope. */
export const OBSERVABILITY_SCOPE_VERSION = "0.0.0";

export interface OtlpHttpRequest {
  method: "POST";
  url: string;
  contentType: "application/json";
  /** Serialized OTLP/JSON payload bytes (Rust `Vec<u8>`). */
  body: Uint8Array;
  /**
   * Extra `(name, value)` headers emitted after the standard headers (e.g. a
   * bearer credential). Values must not contain CR/LF.
   */
  headers: Array<[string, string]>;
}

export interface OtlpAttribute {
  key: string;
  value: string;
}

export function otlpAttribute(key: string, value: string): OtlpAttribute {
  return { key, value };
}

/**
 * One GAUGE data point — a named measurement with its own attributes (#692).
 *
 * ## Why this exists next to {@link GatewayMetricsSnapshot}
 *
 * The snapshot is a FIXED struct: the gateway's request/status/guardrail
 * counters, rendered by `gatewayMetricsJson`. It is the right shape for a
 * per-request delta of a known counter set and the wrong one for a measurement
 * whose series is data — an online-evaluation score is named by the TENANT's
 * criterion id, so its attribute set cannot be a field on a struct.
 *
 * A gauge rather than a sum, because a score is a LEVEL and not a count: the
 * collector's Analytics Engine sink stores `double1` per point and an operator
 * reads `AVG(double1)` over a window. Declaring it monotonic (as
 * `sumMetricJson` does) would tell any OTLP-compliant backend it may compute
 * rates over it, which for a 0-1 quality score is meaningless.
 */
export interface OtlpGaugePoint {
  name: string;
  description?: string;
  value: number;
  /** Milliseconds since the epoch; rendered as the point's `timeUnixNano`. */
  timeUnixMs?: number;
  attributes: OtlpAttribute[];
}

/**
 * Build an OTLP/JSON metrics request from arbitrary gauge points.
 *
 * The envelope is byte-identical in shape to the one
 * {@link buildOtlpMetricsRequest} produces — same resource, same instrumentation
 * scope, same path — so `apps/telemetry`'s existing metric ingest parses these
 * with no change: it reads `metric.gauge.dataPoints[]` generically and turns
 * each into one Analytics Engine point whose blobs carry the attributes.
 */
export function buildOtlpGaugeMetricsRequest(
  endpoint: string,
  serviceName: string,
  points: readonly OtlpGaugePoint[],
): OtlpHttpRequest {
  const body = {
    resourceMetrics: [
      {
        resource: resourceJson(serviceName),
        scopeMetrics: [
          {
            scope: instrumentationScopeJson(),
            metrics: points.map(gaugeMetricJson),
          },
        ],
      },
    ],
  };
  return buildOtlpRequest(endpoint, "/v1/metrics", body);
}

export interface OtlpSpanRecord {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  startTimeUnixNano: number;
  endTimeUnixNano: number;
  attributes: OtlpAttribute[];
}

export interface OtlpLogRecord {
  traceId?: string;
  spanId?: string;
  severityText: string;
  body: string;
  timeUnixNano: number;
  attributes: OtlpAttribute[];
}

const ENCODER = new TextEncoder();

export function buildOtlpMetricsRequest(
  endpoint: string,
  snapshot: GatewayMetricsSnapshot,
): OtlpHttpRequest {
  const body = {
    resourceMetrics: [
      {
        resource: resourceJson(snapshot.serviceName),
        scopeMetrics: [
          {
            scope: instrumentationScopeJson(),
            metrics: gatewayMetricsJson(snapshot),
          },
        ],
      },
    ],
  };
  return buildOtlpRequest(endpoint, "/v1/metrics", body);
}

export function buildOtlpTracesRequest(
  endpoint: string,
  serviceName: string,
  spans: readonly OtlpSpanRecord[],
): OtlpHttpRequest {
  const body = {
    resourceSpans: [
      {
        resource: resourceJson(serviceName),
        scopeSpans: [
          {
            scope: instrumentationScopeJson(),
            spans: spans.map(spanJson),
          },
        ],
      },
    ],
  };
  return buildOtlpRequest(endpoint, "/v1/traces", body);
}

export function buildOtlpLogsRequest(
  endpoint: string,
  serviceName: string,
  logs: readonly OtlpLogRecord[],
): OtlpHttpRequest {
  const body = {
    resourceLogs: [
      {
        resource: resourceJson(serviceName),
        scopeLogs: [
          {
            scope: instrumentationScopeJson(),
            logRecords: logs.map(logJson),
          },
        ],
      },
    ],
  };
  return buildOtlpRequest(endpoint, "/v1/logs", body);
}

function buildOtlpRequest(endpoint: string, path: string, body: unknown): OtlpHttpRequest {
  const trimmed = endpoint.trim();
  if (trimmed === "") {
    throw new ObservabilityConfigError("MissingEndpoint", {
      exporter: "otlp",
      kind: ObservabilityExporterKind.Otlp,
    });
  }
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
    throw new ObservabilityConfigError("InvalidEndpoint", {
      exporter: "otlp",
      endpoint: trimmed,
    });
  }

  return {
    method: "POST",
    url: `${trimEndMatches(trimmed, "/")}${path}`,
    contentType: "application/json",
    body: ENCODER.encode(JSON.stringify(body)),
    headers: [],
  };
}

function trimEndMatches(value: string, ch: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === ch) {
    end -= 1;
  }
  return value.slice(0, end);
}

function resourceJson(serviceName: string): unknown {
  return {
    attributes: [{ key: "service.name", value: { stringValue: serviceName } }],
  };
}

function instrumentationScopeJson(): unknown {
  return { name: "ferrogate", version: OBSERVABILITY_SCOPE_VERSION };
}

function gatewayMetricsJson(snapshot: GatewayMetricsSnapshot): unknown[] {
  const guardrailPassTotal = saturatingSub(
    saturatingSub(snapshot.guardrailEvaluationTotal, snapshot.guardrailEvaluationFailTotal),
    snapshot.guardrailEvaluationErrorTotal,
  );

  const metrics: unknown[] = [
    sumMetricJson(
      "ferrogate.request_logs",
      "Total structured request logs recorded by FerroGate.",
      snapshot.requestLogTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.request_errors",
      "Total structured request logs with errors or 4xx/5xx statuses.",
      snapshot.requestErrorTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.billing_events",
      "Total token metering events recorded by FerroGate.",
      snapshot.billingEventTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_tool.calls",
      "Total MCP tool calls executed by FerroGate.",
      snapshot.toolCallTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_tool.latency_ms",
      "Total MCP tool execution latency in milliseconds.",
      snapshot.toolLatencyMsTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_identity.resolutions",
      "Total per-request MCP identity resolution attempts.",
      snapshot.mcpIdentityResolutionTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_identity.failures",
      "Total MCP identity resolution attempts rejected before dispatch.",
      snapshot.mcpIdentityFailureTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_identity.refreshes",
      "Total successful MCP OAuth credential refreshes.",
      snapshot.mcpIdentityRefreshTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_identity.revocations",
      "Total locally enforced MCP identity revocations.",
      snapshot.mcpIdentityRevocationTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_refresh.response_deadlines",
      "Total MCP refresh storage operations that crossed the caller response deadline.",
      snapshot.mcpRefreshResponseDeadlineTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_refresh.storage_cancellations",
      "Total MCP refresh storage operations fenced before commit.",
      snapshot.mcpRefreshStorageCancellationTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_refresh.storage_outcome_unknown",
      "Total MCP refresh storage operations whose final outcome could not be proven in time.",
      snapshot.mcpRefreshStorageOutcomeUnknownTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_refresh.late_reconciliations",
      "Total MCP refresh storage outcomes reconciled after the response deadline.",
      snapshot.mcpRefreshLateReconciliationTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.mcp_identity.error_audit_deadlines",
      "Total MCP identity error audits fenced before they could delay the original response.",
      snapshot.mcpIdentityErrorAuditDeadlineTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.postgres.pool.acquires",
      "Total async PostgreSQL pool acquisition attempts.",
      snapshot.postgresPoolAcquireTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.postgres.pool.acquire_timeouts",
      "Total async PostgreSQL pool acquisition attempts that reached their Rust-side deadline.",
      snapshot.postgresPoolAcquireTimeoutTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.postgres.pool.acquire_wait_seconds",
      "Cumulative time spent waiting for async PostgreSQL pool acquisition.",
      snapshot.postgresPoolAcquireWaitMicrosTotal / 1_000_000.0,
      [],
    ),
    sumMetricJson(
      "ferrogate.ai_cache.requests",
      "AI response cache hits.",
      snapshot.cacheHitsTotal,
      [otlpAttribute("status", "hit")],
    ),
    sumMetricJson(
      "ferrogate.ai_cache.requests",
      "AI response cache misses.",
      snapshot.cacheMissesTotal,
      [otlpAttribute("status", "miss")],
    ),
    sumMetricJson(
      "ferrogate.ai_cache.requests",
      "AI response cache hits served by the semantic similarity layer.",
      snapshot.semanticCacheHitsTotal,
      [otlpAttribute("status", "semantic_hit")],
    ),
    sumMetricJson(
      "ferrogate.guardrail.matches",
      "Total configured guardrail rule matches.",
      snapshot.guardrailMatchTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.guardrail.denials",
      "Total guardrail matches that blocked a request or response.",
      snapshot.guardrailDenialTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.guardrail.redactions",
      "Total guardrail matches that redacted response content.",
      snapshot.guardrailRedactionTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.guardrail.detector_errors",
      "Total external guardrail detector evaluation errors.",
      snapshot.guardrailDetectorErrorTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.guardrail.evaluations",
      "Guardrail policy evaluations that passed.",
      guardrailPassTotal,
      [otlpAttribute("verdict", "pass")],
    ),
    sumMetricJson(
      "ferrogate.guardrail.evaluations",
      "Guardrail policy evaluations that failed.",
      snapshot.guardrailEvaluationFailTotal,
      [otlpAttribute("verdict", "fail")],
    ),
    sumMetricJson(
      "ferrogate.guardrail.evaluations",
      "Guardrail policy evaluations with detector errors.",
      snapshot.guardrailEvaluationErrorTotal,
      [otlpAttribute("verdict", "error")],
    ),
    sumMetricJson(
      "ferrogate.guardrail.shadow_evaluations",
      "Guardrail evaluations that were shadow-only or not enforced.",
      snapshot.guardrailEvaluationShadowTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.guardrail.evidence_persistence_failures",
      "Failures persisting Guardrail evaluation evidence.",
      snapshot.guardrailEvidencePersistenceFailureTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.guardrail.policy_cas_conflicts",
      "Guardrail policy binding writes rejected by optimistic generation comparison.",
      snapshot.guardrailPolicyCasConflictTotal,
      [],
    ),
    sumMetricJson(
      "ferrogate.tokens",
      "Total prompt tokens recorded by metering events.",
      snapshot.tokenTotals.promptTokens,
      [otlpAttribute("type", "prompt")],
    ),
    sumMetricJson(
      "ferrogate.tokens",
      "Total completion tokens recorded by metering events.",
      snapshot.tokenTotals.completionTokens,
      [otlpAttribute("type", "completion")],
    ),
    sumMetricJson(
      "ferrogate.tokens",
      "Total tokens recorded by metering events.",
      snapshot.tokenTotals.totalTokens,
      [otlpAttribute("type", "total")],
    ),
  ];

  for (const status of snapshot.requestStatusTotals) {
    metrics.push(
      sumMetricJson(
        "ferrogate.request_status",
        "Structured request logs grouped by HTTP status code.",
        status.count,
        [otlpAttribute("status_code", String(status.statusCode))],
      ),
    );
  }

  // #669 — the OTel GenAI metrics, alongside the `ferrogate.*` counters rather
  // than instead of them. They are HISTOGRAMS with a DELTA temporality, which
  // is why they are built by `genai.ts` and spliced in here rather than folded
  // into `sumMetricJson`'s cumulative-sum shape: a per-request token count is
  // an observation, not a running total, and publishing it as a monotonic sum
  // would make every backend's rate() read it as a counter reset.
  //
  // Empty for every request that reached no model, which is the whole
  // non-inference surface — see `GatewayMetricsSnapshot.genAiInvocations`.
  for (const invocation of snapshot.genAiInvocations ?? []) {
    metrics.push(...genAiMetricsJson(invocation));
  }

  for (const total of snapshot.modelProviderTotals) {
    const attributes = [
      otlpAttribute("logical_model", total.logicalModel),
      otlpAttribute("provider", total.provider),
    ];
    metrics.push(
      sumMetricJson(
        "ferrogate.model_provider_requests",
        "Billing events grouped by logical model and provider.",
        total.requests,
        attributes,
      ),
    );
    metrics.push(
      sumMetricJson(
        "ferrogate.model_provider_tokens",
        "Billing event token usage grouped by logical model and provider.",
        total.totalTokens,
        attributes,
      ),
    );
  }

  return metrics;
}

function sumMetricJson(
  name: string,
  description: string,
  value: number,
  attributes: OtlpAttribute[],
): unknown {
  return {
    name,
    description,
    sum: {
      aggregationTemporality: 2,
      isMonotonic: true,
      dataPoints: [{ asDouble: value, attributes: attributesJson(attributes) }],
    },
  };
}

const MS_TO_NS = 1_000_000;

function gaugeMetricJson(point: OtlpGaugePoint): unknown {
  return {
    name: point.name,
    description: point.description ?? "",
    gauge: {
      dataPoints: [
        {
          asDouble: point.value,
          timeUnixNano: (point.timeUnixMs ?? Date.now()) * MS_TO_NS,
          attributes: attributesJson(point.attributes),
        },
      ],
    },
  };
}

function spanJson(span: OtlpSpanRecord): unknown {
  return {
    traceId: span.traceId,
    spanId: span.spanId,
    parentSpanId: span.parentSpanId ?? null,
    name: span.name,
    kind: 2,
    startTimeUnixNano: String(span.startTimeUnixNano),
    endTimeUnixNano: String(span.endTimeUnixNano),
    attributes: attributesJson(span.attributes),
  };
}

function logJson(log: OtlpLogRecord): unknown {
  return {
    timeUnixNano: String(log.timeUnixNano),
    traceId: log.traceId ?? null,
    spanId: log.spanId ?? null,
    severityText: log.severityText,
    body: { stringValue: log.body },
    attributes: attributesJson(log.attributes),
  };
}

function attributesJson(attributes: readonly OtlpAttribute[]): unknown[] {
  return attributes.map((attribute) => ({
    key: attribute.key,
    value: { stringValue: attribute.value },
  }));
}

/** Saturating subtraction over the non-negative counter domain (Rust `u64`). */
function saturatingSub(a: number, b: number): number {
  return a > b ? a - b : 0;
}
