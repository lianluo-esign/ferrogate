/**
 * A1 — PROACTIVE BUDGET-THRESHOLD ALERTS (issue #170/#228), end to end.
 *
 * ## The regression this file exists to catch
 *
 * Rust ships this behaviour COMPLETE and WIRED:
 * `crates/ferrogate-gateway/src/state_billing_metering.rs:231` (and :778, :905,
 * :1048) calls `dispatch_budget_threshold_alerts` after every settlement;
 * `state_wallets.rs:643,652` builds `BudgetAlertWebhookPayload` and calls
 * `dispatch_budget_alert_webhook`; `budget_alerts.rs:24-38` signs it with
 * HMAC-SHA256; `ferrogate-storage/src/budget_alerts.rs` makes it fire once per
 * `(scope, period, tier)`.
 *
 * The TypeScript port dropped the DECISION and the DELIVERY. The idempotency
 * ledger survived (`@ferrogate/storage`'s `D1BudgetAlertStore`), but nothing
 * ever compared committed spend against `quota_policies.alert_threshold_pcts_json`
 * and nothing ever sent a webhook — so an operator who configures a budget alert
 * gets a 200 from the control plane and is then never told they are approaching
 * or over budget. Silent, and money-shaped.
 *
 * ## Why the assertions are written against the SINK and a real `globalThis.fetch`
 *
 * The alert is a consequence of SETTLEMENT, not of admission: Rust fires it from
 * the metering path, immediately after the usage rollup that feeds it has been
 * updated. `MeteringUsageSink` is that path here, so driving it (and, in the
 * last describe, a whole request through `createGatewayApp`) is what proves the
 * behaviour is MOUNTED rather than merely implemented. Nothing is substituted
 * for D1: the `quota_policies` row, the `usage_monthly_rollups` row and the
 * `budget_alert_notifications` claim are all real rows in the real local SQLite
 * that `@cloudflare/vitest-pool-workers` provisions from `wrangler.toml`.
 *
 * The webhook itself is intercepted at `globalThis.fetch` for the reason
 * `test/inference/provider-mock.ts` gives (no `msw` in this workspace, and the
 * dispatcher reads the global at CALL time). The RAW body string is captured,
 * not a parsed object, because the HMAC is computed over exact bytes and a
 * re-serialised object would silently "verify" a signature the receiver would
 * reject.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import {
  ManualClock,
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
} from "../../src/metering/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";
import {
  resetTenantBillingState,
  resetTenantObjectState,
  tenantObjectDb,
} from "../tenant-object.js";
import { RecordingQueue, resetMeteringTables } from "./d1-harness.js";
import { pricedBook, usageFixture } from "./fixtures.js";

const db = (env as unknown as { DB: D1Database }).DB;

const BASE = "https://gw.test";
const WEBHOOK_URL = "https://alerts.test/budget";
const SIGNING_SECRET = "s3cr3t-budget-alerts";

/** 1_700_000_000 ⇒ 2023-11-14, so every derived period month is `2023-11`. */
const NOW_UNIX = 1_700_000_000;
const PERIOD_MONTH = "2023-11";

/**
 * `usageFixture()` under `pricedBook()` costs 4.05e-6 USD.
 *
 * A 5e-6 budget puts one request at 81% — past an 80% tier and short of a 90%
 * one, which is what makes "fires the crossed tier and ONLY the crossed tier"
 * assertable from a single settlement instead of from a contrived number.
 */
const BUDGET_USD = 5e-6;
const SPENT_USD = 4.05e-6;

const ATTRIBUTION = {
  requestId: "fg-000000000000002a",
  tenantId: "tenant_a",
  projectId: "project_1",
} as const;

// ---------------------------------------------------------------------------
// Webhook interception — raw bytes, because a signature is over bytes
// ---------------------------------------------------------------------------

interface WebhookCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

interface WebhookInterceptor {
  readonly calls: readonly WebhookCall[];
  restore(): void;
}

/**
 * Install a `globalThis.fetch` stub that records the webhook POST verbatim.
 *
 * `respond` decides the outcome so the "endpoint is down / 5xx" posture can be
 * exercised for real (a rejected fetch and a 503 are different failures and the
 * dispatcher must survive both).
 */
function interceptWebhook(
  respond: (call: WebhookCall) => Response | Promise<Response> = () =>
    new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
): WebhookInterceptor {
  const original = globalThis.fetch;
  const calls: WebhookCall[] = [];

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const headers: Record<string, string> = {};
    new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).forEach(
      (value, key) => {
        headers[key.toLowerCase()] = value;
      },
    );
    const raw = init?.body;
    const body =
      typeof raw === "string"
        ? raw
        : raw instanceof Uint8Array
          ? new TextDecoder().decode(raw)
          : "";
    const call: WebhookCall = {
      url,
      method: init?.method ?? (input instanceof Request ? input.method : "GET"),
      headers,
      body,
    };
    calls.push(call);
    return respond(call);
  }) as typeof globalThis.fetch;

  return {
    calls,
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

/** An INDEPENDENT HMAC-SHA256, so the assertion is not the implementation. */
async function expectedSignature(secret: string, signedMaterial: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedMaterial));
  return `sha256=${[...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// ---------------------------------------------------------------------------
// Fixture wiring
// ---------------------------------------------------------------------------

async function seedQuotaPolicy(
  scopeType: string,
  scopeId: string,
  budgetUsd: number,
  thresholdPcts: readonly number[],
): Promise<void> {
  // Track A hard-cut: the alert sink resolves the OWNING tenant (`tenant_a`) and
  // reads every quota scope from that tenant's OWN object — the shared control
  // mirror was removed. So even a `project`-scope row belongs to `tenant_a`'s
  // object, never `project_1`'s.
  await tenantObjectDb("tenant_a")
    .prepare(
      "INSERT OR REPLACE INTO quota_policies " +
        "(id, scope_type, scope_id, monthly_budget_usd, alert_threshold_pcts_json, enabled) " +
        "VALUES (?, ?, ?, ?, ?, 1)",
    )
    .bind(
      `${scopeType}:${scopeId}`,
      scopeType,
      scopeId,
      budgetUsd,
      JSON.stringify([...thresholdPcts]),
    )
    .run();
}

function alertBindings(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...(env as unknown as Record<string, unknown>),
    BILLING: new RecordingQueue(),
    BILLING_ALERTS_WEBHOOK_URL: WEBHOOK_URL,
    BILLING_ALERTS_WEBHOOK_SIGNING_SECRET: SIGNING_SECRET,
    ...overrides,
  };
}

function alertSink() {
  return createMeteringUsageSink({
    priceBook: pricedBook(),
    bindings: meteringBindingsFromEnv,
    clock: new ManualClock(NOW_UNIX),
  });
}

/** Every claimed `(scope, period, tier)`, ascending. */
async function claimedThresholds(): Promise<{ id: string; threshold_pct: number }[]> {
  const result = await tenantObjectDb("tenant_a")
    .prepare("SELECT id, threshold_pct FROM budget_alert_notifications ORDER BY threshold_pct ASC")
    .all<{ id: string; threshold_pct: number }>();
  return result.results;
}

beforeEach(async () => {
  await resetMeteringTables();
  await db.prepare("DELETE FROM usage_aggregate_rollups").run();
  await db.prepare("DELETE FROM usage_monthly_rollups").run();
  await db.prepare("DELETE FROM tenant_contexts").run();
  await tenantObjectDb("tenant_a").prepare("DELETE FROM quota_policies").run();
  await resetTenantObjectState(["tenant_a"]);
  // Post-#863 the settle, the rollup and the alert claim are all
  // tenant-object rows, and the object's `ctx.storage.sql` is NOT part of this
  // pool's per-test isolated-storage rollback. Without these resets a ledger
  // entry recorded by an earlier test makes a later test's identical settle a
  // `duplicate` (`stats.recorded` stays 0) and the spent rollup double-counts.
  await resetTenantBillingState(["tenant_a"]);
  const tenantObject = tenantObjectDb("tenant_a");
  await tenantObject.prepare("DELETE FROM usage_event_claims").run();
  await tenantObject.prepare("DELETE FROM usage_aggregate_rollups").run();
  await tenantObject.prepare("DELETE FROM usage_monthly_rollups").run();
  await tenantObject.prepare("DELETE FROM tenant_contexts").run();
});

// ---------------------------------------------------------------------------
// The dispatch
// ---------------------------------------------------------------------------

describe("A1: crossing a configured budget threshold dispatches a signed webhook", () => {
  test("exactly one correctly-signed webhook, with the Rust payload shape", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80, 90]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      // The settlement itself must still have happened.
      expect(sink.stats.recorded).toBe(1);
      expect(sink.stats.aggregated).toBe(1);

      // ONE delivery: 81% crosses the 80 tier and not the 90 tier, and the
      // tenant scope is the only one carrying a policy row.
      expect(webhook.calls.length).toBe(1);
      const call = webhook.calls[0] as WebhookCall;
      expect(call.url).toBe(WEBHOOK_URL);
      expect(call.method).toBe("POST");
      expect(call.headers["content-type"]).toBe("application/json");

      // The wire payload — flat, self-describing, and in the field order
      // `BudgetAlertWebhookPayload`'s `#[derive(Serialize)]` emits, because the
      // HMAC is over these exact bytes.
      const payload = JSON.parse(call.body) as Record<string, unknown>;
      expect(Object.keys(payload)).toEqual([
        "event",
        "scope_type",
        "scope_id",
        "period_month",
        "threshold_pct",
        "spent_usd",
        "budget_usd",
        "fired_at_unix",
      ]);
      expect(payload.event).toBe("budget_threshold_crossed");
      expect(payload.scope_type).toBe("tenant");
      expect(payload.scope_id).toBe("tenant_a");
      expect(payload.period_month).toBe(PERIOD_MONTH);
      expect(payload.threshold_pct).toBe(80);
      expect(payload.spent_usd).toBeCloseTo(SPENT_USD, 12);
      expect(payload.budget_usd).toBeCloseTo(BUDGET_USD, 12);
      expect(payload.fired_at_unix).toBe(NOW_UNIX);

      // `budget_alerts.rs:24-38`: `sha256=<hex>` of HMAC-SHA256 over
      // "<fired_at_unix>.<body>", with the timestamp also carried as a header
      // so a receiver can reject replays. A different scheme is a silent
      // integration break for every operator already verifying these.
      expect(call.headers["x-ferrogate-timestamp"]).toBe(String(NOW_UNIX));
      expect(call.headers["x-ferrogate-signature"]).toBe(
        await expectedSignature(SIGNING_SECRET, `${NOW_UNIX}.${call.body}`),
      );
    } finally {
      webhook.restore();
    }
  });

  test("with NO signing secret the alert is unsigned (legacy posture), not unsent", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({
        env: alertBindings({ BILLING_ALERTS_WEBHOOK_SIGNING_SECRET: undefined }),
        attribution: ATTRIBUTION,
      });

      expect(webhook.calls.length).toBe(1);
      const call = webhook.calls[0] as WebhookCall;
      expect(call.headers["x-ferrogate-signature"]).toBeUndefined();
      expect(call.headers["x-ferrogate-timestamp"]).toBeUndefined();
    } finally {
      webhook.restore();
    }
  });

  test("a threshold that has NOT been crossed does not fire", async () => {
    // 81% of budget: the 90 and 100 tiers must stay silent.
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [90, 100]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      expect(sink.stats.recorded).toBe(1);
      expect(webhook.calls.length).toBe(0);
      expect(await claimedThresholds()).toEqual([]);
    } finally {
      webhook.restore();
    }
  });

  test("every crossed tier fires, each exactly once", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [25, 50, 80, 90]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      const tiers = webhook.calls.map(
        (call) => (JSON.parse(call.body) as { threshold_pct: number }).threshold_pct,
      );
      expect(tiers).toEqual([25, 50, 80]);
      expect((await claimedThresholds()).map((row) => row.threshold_pct)).toEqual([25, 50, 80]);
    } finally {
      webhook.restore();
    }
  });

  test("a policy with a budget but NO thresholds, or a zero budget, fires nothing", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, []);
    await seedQuotaPolicy("project", "project_1", 0, [10]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      expect(sink.stats.recorded).toBe(1);
      expect(webhook.calls.length).toBe(0);
    } finally {
      webhook.restore();
    }
  });

  test("with no webhook_url configured nothing is dispatched and nothing throws", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({
        env: alertBindings({ BILLING_ALERTS_WEBHOOK_URL: undefined }),
        attribution: ATTRIBUTION,
      });

      expect(sink.stats.recorded).toBe(1);
      expect(webhook.calls.length).toBe(0);
    } finally {
      webhook.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Idempotence — the whole point of `budget_alert_notification_id`
// ---------------------------------------------------------------------------

describe("A1: a threshold notifies ONCE per (scope, period, tier)", () => {
  test("crossing the same threshold again does not re-notify", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      const rc = { env: alertBindings(), attribution: ATTRIBUTION };

      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush(rc);
      expect(webhook.calls.length).toBe(1);

      // A SECOND, DIFFERENT request — a new ledger entry, a new accumulate,
      // still past 80%. Rust checks `budget_alert_already_notified` and skips.
      sink.record(usageFixture({ requestId: "fg-000000000000002b" }));
      await sink.flush({
        ...rc,
        attribution: { ...ATTRIBUTION, requestId: "fg-000000000000002b" },
      });

      expect(sink.stats.recorded).toBe(2);
      expect(webhook.calls.length).toBe(1);
      expect(await claimedThresholds()).toEqual([
        { id: `tenant:tenant_a:${PERIOD_MONTH}:80`, threshold_pct: 80 },
      ]);
    } finally {
      webhook.restore();
    }
  });

  test("the id is the Rust derivation `{scope}:{id}:{period}:{tier}`, not an invented one", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      // `budget_alerts.rs::budget_alert_notification_id`. A different id would
      // not collide with rows written by a Rust deployment (or by a control
      // plane that lists them), so the alert would re-fire after a cutover.
      expect(await claimedThresholds()).toEqual([
        { id: `tenant:tenant_a:${PERIOD_MONTH}:80`, threshold_pct: 80 },
      ]);
    } finally {
      webhook.restore();
    }
  });

  test("a row already claimed by someone else suppresses the webhook entirely", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    // Another isolate got there first, this billing period.
    await tenantObjectDb("tenant_a")
      .prepare(
        "INSERT INTO budget_alert_notifications " +
          "(id, tenant_id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) " +
          "VALUES (?, 'tenant_a', 'tenant', 'tenant_a', ?, 80, ?)",
      )
      .bind(`tenant:tenant_a:${PERIOD_MONTH}:80`, PERIOD_MONTH, NOW_UNIX - 60)
      .run();

    const webhook = interceptWebhook();
    try {
      const sink = alertSink();
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      expect(sink.stats.recorded).toBe(1);
      expect(webhook.calls.length).toBe(0);
    } finally {
      webhook.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Delivery posture — a broken receiver is the operator's problem, not ours
// ---------------------------------------------------------------------------

describe("A1: a failing webhook endpoint never touches the customer request", () => {
  test("a REJECTED fetch does not fail the drain, the ledger, or the rollup", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    const webhook = interceptWebhook(() => {
      throw new Error("connection refused");
    });
    try {
      const sink = alertSink();
      await expect(
        sink.flush({ env: alertBindings(), attribution: ATTRIBUTION }),
      ).resolves.toBeUndefined();

      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush({ env: alertBindings(), attribution: ATTRIBUTION });

      expect(webhook.calls.length).toBe(1);
      // The charge settled and the rollup accumulated regardless.
      expect(sink.stats.recorded).toBe(1);
      expect(sink.stats.aggregated).toBe(1);
      expect(sink.stats.deliveryFailures).toBe(0);
    } finally {
      webhook.restore();
    }
  });

  test("a 5xx endpoint is NOT retried — the tier is burned, matching Rust", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);
    const webhook = interceptWebhook(() => new Response("boom", { status: 503 }));
    try {
      const sink = alertSink();
      const rc = { env: alertBindings(), attribution: ATTRIBUTION };
      sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
      await sink.flush(rc);
      expect(webhook.calls.length).toBe(1);

      // `state_wallets.rs`: "Recorded regardless of delivery success: retrying a
      // permanently-unreachable webhook on every subsequent request for the rest
      // of the billing period would be worse than a single missed notification."
      expect(await claimedThresholds()).toEqual([
        { id: `tenant:tenant_a:${PERIOD_MONTH}:80`, threshold_pct: 80 },
      ]);

      sink.record(usageFixture({ requestId: "fg-000000000000002c" }));
      await sink.flush({
        ...rc,
        attribution: { ...ATTRIBUTION, requestId: "fg-000000000000002c" },
      });
      expect(webhook.calls.length).toBe(1);
    } finally {
      webhook.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// THE MOUNT GATE — a real request, through the real composition
// ---------------------------------------------------------------------------

describe("A1, mounted: a served request fires the alert without delaying the client", () => {
  test("200 to the caller, webhook on ctx.waitUntil", async () => {
    await seedQuotaPolicy("tenant", "tenant_a", BUDGET_USD, [80]);

    const queue = new RecordingQueue();
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: meteringBindingsFromEnv,
      clock: new ManualClock(NOW_UNIX),
    });
    const { app } = createGatewayApp({
      modules: [
        inferenceRouteModule({
          models: new InMemoryModelResolver([OPENAI_ROUTE]),
          requestIds: { next: () => "fg-00000000000000ef" },
          usage: sink,
        }),
      ],
      middleware: [meteringDrain(sink)],
    });

    const bindings: Record<string, unknown> = {
      ...(env as unknown as Record<string, unknown>),
      BILLING: queue,
      BILLING_ALERTS_WEBHOOK_URL: WEBHOOK_URL,
      BILLING_ALERTS_WEBHOOK_SIGNING_SECRET: SIGNING_SECRET,
      GATEWAY_NATIVE_API_KEYS: JSON.stringify([
        {
          key: "fg_alerting",
          id: "key_alerting",
          tenant_id: "tenant_a",
          project_id: "project_1",
          scopes: [],
        },
      ]),
    };

    const webhookCalls: WebhookCall[] = [];
    // ONE stub for both legs: the provider call and the webhook call go through
    // the same `globalThis.fetch`, and routing on the URL is what proves the
    // webhook is a genuinely separate outbound request rather than a fixture.
    const provider = interceptProviderFetch((request) => {
      if (request.url.startsWith(WEBHOOK_URL)) {
        webhookCalls.push({
          url: request.url,
          method: request.method,
          headers: request.headers,
          body: typeof request.body === "string" ? request.body : JSON.stringify(request.body),
        });
        return new Response("{}", { status: 200 });
      }
      return providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      });
    });

    try {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request(`${BASE}/v1/chat/completions`, {
          method: "POST",
          headers: { authorization: "Bearer fg_alerting", "content-type": "application/json" },
          body: JSON.stringify({
            model: "gpt-4o-mini",
            messages: [{ role: "user", content: "hi" }],
          }),
        }),
        bindings,
        ctx,
      );

      // The client is served BEFORE the alert leg has had a chance to run.
      expect(response.status).toBe(200);
      expect(webhookCalls.length).toBe(0);

      await waitOnExecutionContext(ctx);
    } finally {
      provider.restore();
    }

    expect(webhookCalls.length).toBe(1);
    const payload = JSON.parse((webhookCalls[0] as WebhookCall).body) as Record<string, unknown>;
    expect(payload.event).toBe("budget_threshold_crossed");
    expect(payload.threshold_pct).toBe(80);
    expect(payload.scope_id).toBe("tenant_a");
  });
});
