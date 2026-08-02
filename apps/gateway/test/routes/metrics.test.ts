/**
 * `GET /metrics` on the gateway — the Prometheus exposition the cutover
 * certification found had no producer.
 *
 * ## The finding
 *
 * > *Rust renders the full `GatewayMetricsSnapshot` (47 `ferrogate_*` series).
 * > `packages/observability/src/prometheus.ts` ports `renderPrometheusText`
 * > with all 47 series, and `apps/control-plane/src/adapters.ts:491`
 * > deliberately does NOT call it — it emits 2 gauges … the consequence is that
 * > **every existing FerroGate dashboard and alert breaks at cutover**: the
 * > series they query no longer exist. The counters live in `apps/gateway`;
 * > exposing them means a gateway-side `/metrics` or an Analytics Engine query
 * > binding.*
 *
 * This file is the gateway-side `/metrics`. `getMetrics` is one of the 258
 * contract operations (`visibility: internal`, `auth.kind: bearer`,
 * `auth.scope: admin.read`), so mounting it puts it behind the SAME guard Rust
 * put it behind — `handle_metrics` opens with an auth check, and
 * `test/contract.test.ts` already pins that contract row. It is emphatically
 * NOT an anonymous scrape endpoint.
 *
 * ## What the numbers mean, and what this file will NOT claim
 *
 * Accumulation is isolate-local; `prometheus.ts` and `src/cache/metrics.ts`
 * have both carried that note since wave 2, and it is a real platform property,
 * not a shortcut. What changes here is that the SERIES EXIST with a producer
 * behind the ones this Worker measures — so a dashboard's queries resolve, and
 * a rate() over a fleet of isolates is a sample rather than a flat zero. No
 * assertion below claims a fleet-wide total.
 */
import { SELF, env } from "cloudflare:test";
import {
  defaultGatewayMetricsSnapshot,
  renderCacheTenantText,
  renderPrometheusText,
} from "@ferrogate/observability";
import { afterEach, describe, expect, it } from "vitest";
import { operationById } from "../../src/contract.js";
import { PROMETHEUS_CONTENT_TYPE, gatewayMetricsSnapshot } from "../../src/routes/metrics.js";

const BASE = "https://gw.test";
const mutable = env as unknown as Record<string, unknown>;
const ROOT = { authorization: "Bearer fg_root" } as const;

afterEach(() => {
  delete mutable.GATEWAY_NATIVE_API_KEYS;
});

/** Every `# HELP <name>` metric name in an exposition body. */
function helpNames(body: string): Set<string> {
  return new Set(
    body
      .split("\n")
      .filter((line) => line.startsWith("# HELP "))
      .map((line) => line.slice("# HELP ".length).split(" ")[0] ?? ""),
  );
}

async function scrape(): Promise<{ status: number; body: string; contentType: string | null }> {
  const res = await SELF.fetch(`${BASE}/metrics`, { headers: ROOT });
  return {
    status: res.status,
    body: await res.text(),
    contentType: res.headers.get("content-type"),
  };
}

describe("the contract row this mount honours", () => {
  it("is internal + bearer + admin.read, exactly as ROUTE-MAP invariant 5 says", () => {
    const metrics = operationById("getMetrics");
    expect(metrics?.path).toBe("/metrics");
    expect(metrics?.method).toBe("GET");
    expect(metrics?.visibility).toBe("internal");
    expect(metrics?.auth.kind).toBe("bearer");
    expect(metrics?.auth.scope).toBe("admin.read");
  });
});

describe("GET /metrics is guarded, not anonymous", () => {
  it("answers 401 to an anonymous scrape", async () => {
    const res = await SELF.fetch(`${BASE}/metrics`);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("missing_api_key");
  });

  it("answers 403 to a credential without admin.read", async () => {
    // A data-plane key must not be able to read the deployment's traffic
    // counters. `hasScope([], "admin.read")` is false by construction — the
    // durable/virtual-key asymmetry `test/contract.test.ts` pins.
    mutable.GATEWAY_NATIVE_API_KEYS = JSON.stringify([
      { key: "fg_dataplane", id: "key_dp", tenant_id: "tenant_a", scopes: [] },
    ]);
    const res = await SELF.fetch(`${BASE}/metrics`, {
      headers: { authorization: "Bearer fg_dataplane" },
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("scope_denied");
  });
});

describe("GET /metrics renders the exposition Rust rendered", () => {
  it("answers 200 in the Prometheus text-exposition content type", async () => {
    const { status, contentType } = await scrape();
    expect(status).toBe(200);
    expect(contentType).toBe(PROMETHEUS_CONTENT_TYPE);
  });

  it("exposes EVERY series the renderer defines — not a hand-picked subset", async () => {
    // The whole finding is that dashboards query series that stopped existing.
    // The expected set is DERIVED from `renderPrometheusText` itself, so a
    // series added upstream is automatically required here rather than being
    // silently dropped, and a subset (the control plane's 2 gauges) is red.
    const { body } = await scrape();
    // #695 added a SECOND renderer to the body: `renderCacheTenantText`, whose
    // family is variable-length and fed by its own accumulator. It is composed
    // in here rather than hand-listed, for the same reason the first one is —
    // a series added to either renderer becomes required automatically. Passing
    // `[]` is deliberate: an empty tenant list still emits both `# HELP`
    // headers, so the SERIES SET is asserted without depending on which tenants
    // happen to have traffic in this isolate.
    const expected = helpNames(
      renderPrometheusText(defaultGatewayMetricsSnapshot()) + renderCacheTenantText([]),
    );
    expect(expected.size).toBeGreaterThan(40);
    expect(helpNames(body)).toEqual(expected);
  });

  it("names the series a dashboard actually queries", async () => {
    // A handful spelled out, because a derived comparison alone would pass if
    // BOTH sides were renamed together.
    const { body } = await scrape();
    for (const series of [
      "ferrogate_info",
      "ferrogate_request_logs_total",
      "ferrogate_request_errors_total",
      "ferrogate_request_status_total",
      "ferrogate_ai_cache_requests_total",
      "ferrogate_billing_events_total",
      "ferrogate_guardrail_denials_total",
    ]) {
      expect(body, series).toContain(`# HELP ${series} `);
    }
    expect(body).toContain('ferrogate_info{service="ferrogate-gateway"} 1');
  });
});

describe("the counters have a PRODUCER, which is the point", () => {
  it("moves ferrogate_request_logs_total when the gateway serves a request", async () => {
    const before = gatewayMetricsSnapshot().requestLogTotal;
    await SELF.fetch(`${BASE}/v1/models`, { headers: ROOT });
    const after = gatewayMetricsSnapshot().requestLogTotal;
    // Two: the served request, and nothing else — the assertion is a strict
    // INCREASE, because a constant-zero exposition is exactly the failure the
    // certification described.
    expect(after).toBeGreaterThan(before);
  });

  it("counts a 4xx as an error and files it under its status code", async () => {
    // Rust's definition, verbatim: "structured request logs with errors or
    // 4xx/5xx statuses". A gateway-produced 401 is an error by that rule.
    const before = gatewayMetricsSnapshot();
    await SELF.fetch(`${BASE}/v1/models`);
    const after = gatewayMetricsSnapshot();
    expect(after.requestErrorTotal).toBeGreaterThan(before.requestErrorTotal);
    const row = after.requestStatusTotals.find((entry) => entry.statusCode === 401);
    expect(row?.count).toBeGreaterThan(0);
  });

  it("does not count a 200 as an error", async () => {
    const before = gatewayMetricsSnapshot().requestErrorTotal;
    const res = await SELF.fetch(`${BASE}/healthz`);
    expect(res.status).toBe(200);
    expect(gatewayMetricsSnapshot().requestErrorTotal).toBe(before);
  });

  it("renders the counter it just moved, in the scrape body", async () => {
    await SELF.fetch(`${BASE}/healthz`);
    const { body } = await scrape();
    const total = gatewayMetricsSnapshot().requestLogTotal;
    // The scrape itself is a request, so the rendered figure is the snapshot
    // taken DURING it — at least the value observed before it started.
    const rendered = Number(/^ferrogate_request_logs_total (\d+)$/m.exec(body)?.[1] ?? "-1");
    expect(rendered).toBeGreaterThan(0);
    expect(rendered).toBeLessThanOrEqual(total);
  });
});
