/**
 * The cross-tenant billing fleet read side (#956) — the parts provable OFFLINE.
 *
 * The Analytics Engine READ side is the account-scoped `/analytics_engine/sql`
 * REST endpoint, which has no local emulation, so the real round-trip is
 * exercised live. Everything else — the SQL the query builds, the row mapping,
 * the sampling correction, and the adapter's request shape + failure mapping —
 * is pure over its inputs and pinned here. The `fetch` seam is injected so the
 * adapter's HTTP contract is asserted without a network.
 */
import { describe, expect, it } from "vitest";
import { CloudflareAnalyticsEngineQuery } from "../src/adapters.js";
import {
  BillingFleetUnavailableError,
  type FleetQuery,
  buildFleetSql,
  mapFleetRows,
  runFleetReport,
} from "../src/store/billing-fleet.js";

const BASE_QUERY: FleetQuery = {
  groupBy: "tenant",
  sinceUnix: 1_000,
  untilUnix: 2_000,
  limit: 20,
};

describe("buildFleetSql", () => {
  it("aggregates the grouped blob column, sample-corrected, bounded by the window", () => {
    const sql = buildFleetSql("ferrogate_billing", BASE_QUERY);
    expect(sql).toContain("SELECT blob1 AS key,");
    // Sampling correction: every aggregate multiplies by _sample_interval.
    expect(sql).toContain("SUM(double1 * _sample_interval) AS offer_usd");
    expect(sql).toContain("SUM(double2 * _sample_interval) AS final_usd");
    expect(sql).toContain("SUM(double6 * _sample_interval) AS provider_cost_usd");
    expect(sql).toContain("SUM(_sample_interval) AS events");
    expect(sql).toContain("FROM ferrogate_billing");
    expect(sql).toContain("WHERE timestamp >= toDateTime(1000) AND timestamp < toDateTime(2000)");
    expect(sql).toContain("ORDER BY final_usd DESC");
    expect(sql).toContain("LIMIT 20");
  });

  it("maps each group_by dimension to its blob column", () => {
    const column = (groupBy: FleetQuery["groupBy"]): string => {
      const line = buildFleetSql("ds", { ...BASE_QUERY, groupBy }).split("\n")[0];
      return line?.replace("SELECT ", "").replace(" AS key,", "") ?? "";
    };
    expect(column("tenant")).toBe("blob1");
    expect(column("project")).toBe("blob2");
    expect(column("logical_model")).toBe("blob3");
    expect(column("provider")).toBe("blob4");
    expect(column("billing_group")).toBe("blob5");
    expect(column("provider_model")).toBe("blob6");
  });

  it("rejects a dataset name that is not a bare identifier (no injection)", () => {
    expect(() => buildFleetSql("bad name; DROP", BASE_QUERY)).toThrow(/dataset name/);
    expect(() => buildFleetSql("ferrogate_billing", BASE_QUERY)).not.toThrow();
  });
});

describe("mapFleetRows", () => {
  it("maps raw AE rows and coerces non-finite doubles to 0", () => {
    const rows = mapFleetRows([
      {
        key: "tenant-a",
        offer_usd: 10,
        final_usd: 8,
        provider_cost_usd: 4,
        prompt_tokens: 100,
        completion_tokens: 50,
        events: 3,
      },
      { key: "tenant-b", offer_usd: "not-a-number", final_usd: 2 },
    ]);
    expect(rows[0]).toEqual({
      key: "tenant-a",
      offer_usd: 10,
      final_usd: 8,
      provider_cost_usd: 4,
      prompt_tokens: 100,
      completion_tokens: 50,
      events: 3,
    });
    expect(rows[1]?.offer_usd).toBe(0);
    expect(rows[1]?.final_usd).toBe(2);
  });
});

describe("runFleetReport", () => {
  it("flags the report sampled and passes the built SQL to the port verbatim", async () => {
    let seenSql = "";
    const report = await runFleetReport(
      {
        runSql: async (sql) => {
          seenSql = sql;
          return [{ key: "t1", offer_usd: 5, final_usd: 4, events: 1 }];
        },
      },
      "ferrogate_billing",
      BASE_QUERY,
    );
    expect(seenSql).toBe(buildFleetSql("ferrogate_billing", BASE_QUERY));
    expect(report.object).toBe("billing_fleet_report");
    expect(report.sampled).toBe(true);
    expect(report.group_by).toBe("tenant");
    expect(report.rows).toHaveLength(1);
    expect(report.rows[0]?.final_usd).toBe(4);
  });
});

describe("CloudflareAnalyticsEngineQuery", () => {
  it("POSTs the SQL to the account endpoint with the bearer token and returns data", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fakeFetch: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ data: [{ key: "t1", final_usd: 9 }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const port = new CloudflareAnalyticsEngineQuery("acct-123", "secret-token", fakeFetch);
    const rows = await port.runSql("SELECT 1");

    const call = calls[0];
    expect(call?.url).toBe(
      "https://api.cloudflare.com/client/v4/accounts/acct-123/analytics_engine/sql",
    );
    expect(call?.init.method).toBe("POST");
    expect((call?.init.headers as Record<string, string>).authorization).toBe(
      "Bearer secret-token",
    );
    expect(call?.init.body).toBe("SELECT 1");
    expect(rows).toEqual([{ key: "t1", final_usd: 9 }]);
  });

  it("maps a non-2xx response to BillingFleetUnavailableError (⇒ 503, never 500)", async () => {
    const fakeFetch: typeof fetch = async () => new Response("nope", { status: 403 });
    const port = new CloudflareAnalyticsEngineQuery("a", "t", fakeFetch);
    await expect(port.runSql("SELECT 1")).rejects.toBeInstanceOf(BillingFleetUnavailableError);
  });

  it("maps a transport failure to BillingFleetUnavailableError", async () => {
    const fakeFetch: typeof fetch = async () => {
      throw new Error("network down");
    };
    const port = new CloudflareAnalyticsEngineQuery("a", "t", fakeFetch);
    await expect(port.runSql("SELECT 1")).rejects.toBeInstanceOf(BillingFleetUnavailableError);
  });

  it("calls fetch bound to globalThis, not the instance (Workers Illegal-invocation guard)", async () => {
    // A REGULAR (non-arrow) fake records its `this`. The Workers global `fetch`
    // throws "Illegal invocation" unless called with `this === globalThis`; the
    // adapter must bind it, so a detached `this.#fetch(...)` cannot smuggle the
    // instance in as `this`. Without the constructor's `.bind(globalThis)` this
    // records the adapter instance and the assertion fails.
    const seen: unknown[] = [];
    const fakeFetch = function (this: unknown): Promise<Response> {
      seen.push(this);
      return Promise.resolve(new Response(JSON.stringify({ data: [] }), { status: 200 }));
    } as unknown as typeof fetch;
    const port = new CloudflareAnalyticsEngineQuery("a", "t", fakeFetch);
    await port.runSql("SELECT 1");
    expect(seen[0]).toBe(globalThis);
  });
});
