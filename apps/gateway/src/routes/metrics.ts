/**
 * `GET /metrics` — the Prometheus exposition, on the Worker that owns the
 * counters.
 *
 * ## The finding this closes
 *
 * The cutover certification recorded `/metrics` as DIVERGENT: Rust renders the
 * full `GatewayMetricsSnapshot` — 47 `ferrogate_*` series — and the TypeScript
 * control plane emits two gauges, on the stated (and sound) grounds that
 * `apps/control-plane` measures none of the others and a scrape full of zeros
 * reads as "no traffic". The consequence it named was not sound to ship:
 *
 * > *every existing FerroGate dashboard and alert breaks at cutover: the series
 * > they query no longer exist. The counters live in `apps/gateway`; exposing
 * > them means a gateway-side `/metrics` or an Analytics Engine query binding.*
 *
 * This is the first of those two. `packages/observability`'s
 * `renderPrometheusText` has rendered all 47 series since wave 2 and had no
 * caller; `src/cache/metrics.ts` has produced three of them and had no
 * exporter. This module joins the two and puts the result on a route.
 *
 * ## It is NOT an anonymous scrape endpoint
 *
 * `getMetrics` is contract operation `/metrics`, `visibility: internal`,
 * `auth.kind: bearer`, `auth.scope: admin.read` — Rust's `handle_metrics` opens
 * with an auth check and `test/contract.test.ts` has pinned that row since
 * wave 2. Because it is a CONTRACT operation, mounting it through
 * `GatewayRouter.register` puts it behind `contractAuth` automatically: the
 * ladder is `401 missing_api_key` / `403 scope_denied` / 200, with no bespoke
 * guard to get wrong. A Prometheus scraper is configured with a
 * bearer_token — this is the posture it expects.
 *
 * ## PLATFORM LIMIT — accumulation is ISOLATE-LOCAL, and stays that way here
 *
 * A Worker has no long-lived process to hold counters in. Every number below is
 * one isolate's own view since it warmed, exactly as `prometheus.ts` and
 * `src/cache/metrics.ts` have both said since wave 2. A fleet-wide total needs
 * a Durable Object accumulator or an Analytics Engine query binding, and
 * neither is invented here: the honest thing a scrape can report is what this
 * isolate saw, and Prometheus' own scrape model — many targets, `sum()` at
 * query time — is a reasonable fit for that.
 *
 * What the fix DOES buy, and it is the whole point of the finding: the series
 * EXIST, with real producers behind the ones this Worker measures. A dashboard
 * query resolves instead of returning nothing, which is the difference between
 * "traffic is zero" and "the metric is gone".
 *
 * ## Which counters have producers today
 *
 * | series | producer |
 * |---|---|
 * | `ferrogate_request_logs_total` | {@link recordRequestMetric}, from {@link requestMetrics} on every request |
 * | `ferrogate_request_errors_total` | same, on a 4xx/5xx — Rust's definition verbatim |
 * | `ferrogate_request_status_total{status_code}` | same |
 * | `ferrogate_ai_cache_requests_total{status}` | `src/cache/metrics.ts` (exact + semantic hits, misses) |
 * | everything else | rendered at its zero value |
 *
 * The zeros are deliberate and are NOT a fabrication: they are the same zeros
 * `defaultGatewayMetricsSnapshot()` defines, they say "this deployment does not
 * measure that yet", and rendering them is what keeps the series set stable for
 * the dashboards the finding is about. Each one that acquires a producer — the
 * guardrail counters, the billing counters, the #522 unjoinable-action counter
 * — is a one-line merge into {@link gatewayMetricsSnapshot}.
 */
import {
  type GatewayMetricsSnapshot,
  defaultGatewayMetricsSnapshot,
  renderPrometheusText,
} from "@ferrogate/observability";
import type { Context, MiddlewareHandler } from "hono";
import { responseCacheMetrics } from "../cache/metrics.js";
import type { GatewayEnv } from "../ports.js";
import { SERVICE_NAME } from "./service.js";

/** Prometheus text exposition format 0.0.4, as Rust's `handle_metrics` sets it. */
export const PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

// ---------------------------------------------------------------------------
// The isolate's request counters
// ---------------------------------------------------------------------------

let requestLogTotal = 0;
let requestErrorTotal = 0;
const statusTotals = new Map<number, number>();

/**
 * Rust `AppState::record_request_log`.
 *
 * `requestErrorTotal` follows the Rust definition exactly — "structured request
 * logs with errors or 4xx/5xx statuses" — so a 4xx the gateway itself produced
 * (a `model_not_found`, a `scope_denied`, a `node_draining`) counts as an
 * error. That is what makes the error RATIO actionable rather than
 * upstream-only.
 */
export function recordRequestMetric(statusCode: number): void {
  requestLogTotal += 1;
  if (statusCode >= 400) requestErrorTotal += 1;
  statusTotals.set(statusCode, (statusTotals.get(statusCode) ?? 0) + 1);
}

/** Zero the request counters. For tests that assert deltas. */
export function resetRequestMetrics(): void {
  requestLogTotal = 0;
  requestErrorTotal = 0;
  statusTotals.clear();
}

/**
 * This isolate's snapshot, in the shape the exporters render.
 *
 * Built from `defaultGatewayMetricsSnapshot()` so a field ADDED upstream
 * appears here at its zero value rather than making the render throw — the
 * series set is the contract with the dashboards, and losing one silently is
 * the failure this module exists to prevent.
 */
export function gatewayMetricsSnapshot(): GatewayMetricsSnapshot {
  return {
    ...defaultGatewayMetricsSnapshot(),
    serviceName: SERVICE_NAME,
    requestLogTotal,
    requestErrorTotal,
    requestStatusTotals: [...statusTotals.entries()]
      .sort(([left], [right]) => left - right)
      .map(([statusCode, count]) => ({ statusCode, count })),
    ...responseCacheMetrics(),
  };
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

/**
 * Count every request this Worker serves.
 *
 * Mounted by `createGatewayApp` immediately after `requestId` and AHEAD of the
 * pre-auth network gate, so a refusal counts too: an `ip_denied` flood is
 * exactly the traffic an operator needs the counter to show, and a middleware
 * mounted behind the gate would report the attack as silence.
 *
 * It wraps `await next()` and reads the FINAL status off `c.res`, which is why
 * it can be outermost and still see what the client got.
 */
export function requestMetrics(): MiddlewareHandler<GatewayEnv> {
  return async function requestMetricsMiddleware(c, next): Promise<void> {
    await next();
    recordRequestMetric(c.res.status);
  };
}

/** `handle_metrics` — render this isolate's snapshot. */
export function metricsHandler(c: Context<GatewayEnv>): Response {
  return new Response(renderPrometheusText(gatewayMetricsSnapshot()), {
    status: 200,
    headers: { "content-type": PROMETHEUS_CONTENT_TYPE },
  });
}
