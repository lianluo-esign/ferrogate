/**
 * ANTI-UNMOUNT, one level up: the cache is live in the **Worker the platform
 * boots**, not merely in a factory a test calls.
 *
 * `test/cache/middleware.test.ts` drives `createGatewayApp` directly. That
 * proves the composition FUNCTION mounts the middleware — but the defect class
 * this wave exists to close is precisely a correct factory that the deployed
 * entry module never reaches with the right arguments. So this file goes
 * through `SELF.fetch`, which dispatches into `src/worker.ts` → `src/index.ts`
 * → `createGatewayApp` exactly as a production request does, against the real
 * `wrangler.toml` bindings.
 *
 * That also makes this the ONLY place the durable half of the guardrail-policy
 * fingerprint runs: `wrangler.toml` binds `CONTROL_DB`, so
 * `guardrailPolicyFingerprint` takes the `D1GuardrailPolicyStore.listBindings()`
 * branch (`src/cache/fingerprint.ts`) instead of the vars-only one. If that read
 * failed the middleware would fail CLOSED and no `x-ferrogate-cache` header
 * would appear at all — so every assertion here doubles as proof the D1 leg
 * works.
 *
 * `env` from `cloudflare:test` is the same object the Worker sees, so the vars
 * are set here and restored afterwards rather than pinned in `vitest.config.ts`
 * (which this agent does not own).
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CACHE_STATUS_HEADER } from "../../src/middleware/response-cache.js";

const BASE = "https://gw.test";

/** A provider + model pair, so an inference request can reach a 2xx. */
const PROVIDERS = JSON.stringify([
  { name: "fake-openai", kind: "openai", base_url: "https://api.openai.example/v1" },
]);
const MODELS = JSON.stringify([
  { name: "cache-probe", provider: "fake-openai", provider_model: "cache-probe-physical" },
]);

/** A durable key with an EMPTY scope set: every data-plane scope, no admin one. */
const KEYS = JSON.stringify([
  { key: "fg_cache_probe", id: "key_cache_probe", tenant_id: "tenant_a", scopes: [] },
]);

const ORIGINAL: Record<string, unknown> = {};
const OVERRIDES: Record<string, string> = {
  GATEWAY_CACHE_ENABLED: "true",
  GATEWAY_CACHE_TTL_SECONDS: "300",
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
};

const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

/** One upstream call, counted, returning a distinguishable body. */
function interceptUpstream(): { count: () => number; restore: () => void } {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes("api.openai.example")) {
      return await original(input as RequestInfo, init);
    }
    calls += 1;
    return new Response(
      JSON.stringify({
        id: `chatcmpl-${calls}`,
        object: "chat.completion",
        model: "cache-probe-physical",
        choices: [
          { index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
  return { count: () => calls, restore: () => void (globalThis.fetch = original) };
}

function post(body: unknown, extra: Record<string, string> = {}): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: {
      authorization: "Bearer fg_cache_probe",
      "content-type": "application/json",
      ...extra,
    },
    body: JSON.stringify(body),
  });
}

describe("the deployed Worker serves from the response cache", () => {
  it("hits on the second identical request, and does NOT call the upstream again", async () => {
    const upstream = interceptUpstream();
    try {
      const body = { model: "cache-probe", messages: [{ role: "user", content: "self" }] };

      const first = await post(body);
      expect(first.status).toBe(200);
      // Present at all ⇒ the middleware is mounted in the exported app AND the
      // `CONTROL_DB` guardrail-binding read succeeded (a failure fails closed).
      expect(first.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      expect((await first.json()) as { id: string }).toMatchObject({ id: "chatcmpl-1" });
      expect(upstream.count()).toBe(1);

      const second = await post(body);
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
      // The Cache API entry survives across `SELF.fetch` invocations, which an
      // isolate-local `Map` in the middleware would not guarantee.
      expect((await second.json()) as { id: string }).toMatchObject({ id: "chatcmpl-1" });
      expect(upstream.count()).toBe(1);
    } finally {
      upstream.restore();
    }
  });

  it("a different prompt is a different entry, through the deployed chain", async () => {
    const upstream = interceptUpstream();
    try {
      await post({ model: "cache-probe", messages: [{ role: "user", content: "alpha" }] });
      const other = await post({
        model: "cache-probe",
        messages: [{ role: "user", content: "beta" }],
      });
      expect(other.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      expect(upstream.count()).toBe(2);
    } finally {
      upstream.restore();
    }
  });

  it("still refuses an unauthenticated request — the cache never runs before auth", async () => {
    const res = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "cache-probe", messages: [] }),
    });
    expect(res.status).toBe(401);
    // A 401 is not a cache outcome; labelling it would mean the middleware ran
    // ahead of `contractAuth` and had no identity to key on.
    expect(res.headers.get(CACHE_STATUS_HEADER)).toBeNull();
  });
});
