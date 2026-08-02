/**
 * Issue #695 — the per-tenant cache hit rate is on the wire, not just in a
 * function nobody calls.
 *
 * `@ferrogate/observability` has carried a labelled renderer that nothing calls
 * since wave 22 (`renderUnjoinableActionsText`), so its series have never
 * appeared on a scrape. That is the failure mode this file exists to stop for
 * the cache family: every assertion goes through the REAL `GET /metrics`
 * handler on the REAL `createGatewayApp` composition, driving REAL cacheable
 * traffic through the REAL `responseCache()` middleware first. Nothing here
 * calls `renderCacheTenantText` directly — that would prove the renderer works
 * and prove nothing about whether an operator can see the number.
 *
 * Deleting the `renderCacheTenantText(...)` concatenation from
 * `src/routes/metrics.ts` turns this file red.
 */
import { describe, expect, it } from "vitest";
import {
  CACHE_TENANT_UNSCOPED,
  resetResponseCacheMetrics,
  responseCacheTenantMetrics,
} from "../../src/cache/metrics.js";
import { SemanticResponseCache } from "../../src/cache/semantic.js";
import { MemoryResponseCacheStore } from "../../src/cache/store.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { responseCache } from "../../src/middleware/response-cache.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { ALL_ROUTES, fixedRequestIds } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";

const BASE = "https://gw.test";
const CHAT = `${BASE}/v1/chat/completions`;
const METRICS = `${BASE}/metrics`;

/**
 * `fg_root` is the operator key `test/setup-d1.ts` seeds; it carries
 * `admin.read`, which `getMetrics` requires. `fg_a` / `fg_b` are two tenants'
 * data-plane keys — the partition the per-tenant series has to reproduce.
 */
const NATIVE_KEYS = JSON.stringify([
  { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: [] },
  { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: [] },
]);
const STATIC_KEYS = JSON.stringify([{ key: "fg_root", id: "key_root", platform_operator: true }]);

const ENV = {
  GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
  GATEWAY_STATIC_API_KEYS: STATIC_KEYS,
  GATEWAY_CACHE_ENABLED: "true",
  GATEWAY_CACHE_TTL_SECONDS: "300",
};

const CHAT_BODY = { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] };

function completion(marker: string) {
  return {
    id: `chatcmpl-${marker}`,
    object: "chat.completion",
    model: "gpt-4o-mini-2024-07-18",
    choices: [{ index: 0, message: { role: "assistant", content: marker }, finish_reason: "stop" }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  };
}

function gateway() {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(ALL_ROUTES),
        requestIds: fixedRequestIds,
      }),
    ],
    responseCache: responseCache({
      store: new MemoryResponseCacheStore({ now: () => 1_000 }),
      semanticStore: new SemanticResponseCache(),
      now: () => 1_000,
      // This suite is about TELEMETRY, so the durable governance leg is pinned
      // out: `test/cache/governance.test.ts` owns it, and leaving it in would
      // make a governance regression fail here too, in a file whose name says
      // nothing about governance.
      governance: null,
    }),
  });
  return {
    chat: (key: string) =>
      app.request(
        CHAT,
        {
          method: "POST",
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
          body: JSON.stringify(CHAT_BODY),
        },
        ENV,
      ),
    metrics: () => app.request(METRICS, { headers: { authorization: "Bearer fg_root" } }, ENV),
  };
}

describe("per-tenant cache hit rate reaches GET /metrics", () => {
  it("renders one series per tenant, and the ratio a tenant would act on", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("m")));
    try {
      resetResponseCacheMetrics();
      const gw = gateway();

      // tenant_a: one miss then one hit -> ratio 0.5.
      await gw.chat("fg_a");
      await gw.chat("fg_a");
      // tenant_b: one miss only -> ratio 0. Its traffic is a DIFFERENT body?
      // No: the same body. The point is that it still misses, because the key
      // is bound to the identity — so tenant_b's ratio being 0 while tenant_a's
      // is 0.5 is simultaneously the telemetry assertion and a restatement of
      // the fence.
      await gw.chat("fg_b");

      const text = await (await gw.metrics()).text();

      expect(text).toContain('ferrogate_ai_cache_requests_total{tenant="tenant_a",status="hit"} 1');
      expect(text).toContain(
        'ferrogate_ai_cache_requests_total{tenant="tenant_a",status="miss"} 1',
      );
      expect(text).toContain('ferrogate_ai_cache_hit_ratio{tenant="tenant_a"} 0.5');

      expect(text).toContain('ferrogate_ai_cache_requests_total{tenant="tenant_b",status="hit"} 0');
      expect(text).toContain(
        'ferrogate_ai_cache_requests_total{tenant="tenant_b",status="miss"} 1',
      );
      expect(text).toContain('ferrogate_ai_cache_hit_ratio{tenant="tenant_b"} 0');

      // The deployment-wide family the dashboards already read is unchanged and
      // still agrees with the sum of the per-tenant ones.
      expect(text).toContain('ferrogate_ai_cache_requests_total{status="hit"} 1');
      expect(text).toContain('ferrogate_ai_cache_requests_total{status="miss"} 2');
    } finally {
      resetResponseCacheMetrics();
      provider.restore();
    }
  });

  it("labels a credential with no tenancy rather than dropping it", async () => {
    // A platform-operator key resolves with no tenant. Dropping its requests
    // would make the per-tenant series disagree with the aggregate one, and an
    // operator comparing the two would be chasing a phantom.
    const provider = interceptProviderFetch(() => providerJson(completion("m")));
    try {
      resetResponseCacheMetrics();
      const gw = gateway();
      await gw.chat("fg_root");
      const totals = responseCacheTenantMetrics();
      expect(totals.map((total) => total.tenant)).toEqual([CACHE_TENANT_UNSCOPED]);
      expect(totals[0]?.misses).toBe(1);
    } finally {
      resetResponseCacheMetrics();
      provider.restore();
    }
  });
});
