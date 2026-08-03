/**
 * ANTI-UNMOUNT: the response cache is wired into the app the Worker exports.
 *
 * This repo has now shipped THREE fully-implemented, fully-tested things that
 * nothing called (24 unreachable gateway operations; a metering drain whose
 * deletion left 794 tests green; and the dead half of `@ferrogate/storage`,
 * `@ferrogate/routing` and `@ferrogate/providers`). So every assertion below is
 * written against the REAL `createGatewayApp` composition with the REAL
 * `contractAuth` guard and the REAL inference route module, and the load-bearing
 * ones do **not** trust a header: they count the requests the intercepted
 * provider `fetch` actually saw. A cache that does not prevent an upstream call
 * is not a cache, and a header can be written by code that cached nothing.
 *
 * Deleting `app.use("*", options.responseCache ?? responseCache())` from
 * `src/routes/index.ts` turns this file red. So does deleting the tenant from
 * the cache key. Both mutations were run; the observations are in the slice
 * report.
 */
import { describe, expect, it } from "vitest";
import {
  recordCacheHit,
  recordCacheMiss,
  resetResponseCacheMetrics,
  responseCacheMetrics,
} from "../../src/cache/metrics.js";
import { MemoryResponseCacheStore } from "../../src/cache/store.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { CACHE_STATUS_HEADER, responseCache } from "../../src/middleware/response-cache.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { ALL_ROUTES, fixedRequestIds } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";

const BASE = "https://gw.test";
const CHAT = `${BASE}/v1/chat/completions`;
const EMBEDDINGS = `${BASE}/v1/embeddings`;

/**
 * Two tenants holding two different durable keys.
 *
 * An empty durable scope set grants every data-plane scope and no `admin.*`
 * one, so both pass the contract scope check for the inference operations while
 * staying tenant-confined — the exact credential shape a shared response cache
 * must keep apart.
 */
const NATIVE_KEYS = JSON.stringify([
  { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: [] },
  { key: "fg_a2", id: "key_a2", tenant_id: "tenant_a", scopes: [] },
  { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: [] },
]);

const CACHE_ON = {
  GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
  GATEWAY_CACHE_ENABLED: "true",
  GATEWAY_CACHE_TTL_SECONDS: "300",
};

const CHAT_BODY = { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] };

/** A distinguishable provider body, so a cross-tenant leak is unmistakable. */
function completion(marker: string) {
  return {
    id: `chatcmpl-${marker}`,
    object: "chat.completion",
    model: "gpt-4o-mini-2024-07-18",
    choices: [{ index: 0, message: { role: "assistant", content: marker }, finish_reason: "stop" }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  };
}

interface Gateway {
  post(url: string, key: string, body: unknown, extra?: Record<string, string>): Promise<Response>;
}

/**
 * The real composition root, with an isolate-local store and a fixed clock so
 * TTL is observable. The MIDDLEWARE is the shipped `responseCache()` — only its
 * storage is swapped, exactly as `networkAccess` swaps its limiter.
 */
function gateway(
  env: Record<string, string> = {},
  store = new MemoryResponseCacheStore({ now: () => 1_000 }),
): Gateway {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(ALL_ROUTES),
        requestIds: fixedRequestIds,
      }),
    ],
    responseCache: responseCache({ store }),
  });
  const fullEnv = { ...CACHE_ON, ...env };
  return {
    post: async (url, key, body, extra = {}) =>
      await app.request(
        url,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${key}`,
            "content-type": "application/json",
            ...extra,
          },
          body: JSON.stringify(body),
        },
        fullEnv,
      ),
  };
}

// ---------------------------------------------------------------------------
// 1. The mount — a hit is served, and the upstream is NOT called
// ---------------------------------------------------------------------------

describe("the response cache is mounted by createGatewayApp", () => {
  it("serves the second identical request from cache WITHOUT an upstream call", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const gw = gateway();
      const first = await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(first.status).toBe(200);
      expect(first.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      expect(provider.requests).toHaveLength(1);

      const second = await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(second.status).toBe(200);
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
      // THE assertion. Not the header — the absence of a second upstream call.
      // Unmount the middleware and this is 2.
      expect(provider.requests).toHaveLength(1);
      expect(await second.json()).toEqual(completion("first"));
    } finally {
      provider.restore();
    }
  });

  it("counts the hit and the miss — the first producer for `ferrogate_ai_cache_requests_total`", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("m")));
    try {
      resetResponseCacheMetrics();
      const gw = gateway();
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      const metrics = responseCacheMetrics();
      expect(metrics.cacheMissesTotal).toBe(1);
      expect(metrics.cacheHitsTotal).toBe(1);
      // 0 because this gateway is in `exact_match` mode. The semantic layer
      // now exists (`src/cache/semantic.ts`) and has a real producer, so this
      // is no longer "no producer" but the stronger claim: an EXACT hit must
      // never be counted as a semantic one. `test/cache/semantic.test.ts`
      // holds the other side — a semantic hit counts in both.
      expect(metrics.semanticCacheHitsTotal).toBe(0);
    } finally {
      resetResponseCacheMetrics();
      provider.restore();
    }
  });

  it("is INERT until GATEWAY_CACHE_ENABLED=true — an unconfigured deployment is unchanged", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway({ GATEWAY_CACHE_ENABLED: "" });
      const first = await gw.post(CHAT, "fg_a", CHAT_BODY);
      const second = await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(provider.requests).toHaveLength(2);
      // Rust records `cache_status: None` when caching is off; the header is
      // absent rather than reporting a miss that never had a chance to hit.
      expect(first.headers.get(CACHE_STATUS_HEADER)).toBeNull();
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBeNull();
    } finally {
      provider.restore();
    }
  });

  it("reports `bypass` — never silence — for a DECLARED but unusable cache config", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway({ GATEWAY_CACHE_TTL_SECONDS: "0" });
      const res = await gw.post(CHAT, "fg_a", CHAT_BODY);
      // Availability is never traded for a cache: the request is served.
      expect(res.status).toBe(200);
      expect(res.headers.get(CACHE_STATUS_HEADER)).toBe("bypass");
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Isolation — the property the mutation proof targets
// ---------------------------------------------------------------------------

describe("cache isolation", () => {
  it("a SECOND TENANT never sees the first tenant's cached body", async () => {
    let call = 0;
    const provider = interceptProviderFetch(() =>
      providerJson(completion(call++ === 0 ? "tenant_a_secret" : "tenant_b_own")),
    );
    try {
      const gw = gateway();
      const a = await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect((await a.json()) as { id: string }).toMatchObject({ id: "chatcmpl-tenant_a_secret" });

      // Byte-identical request, different tenant's credential.
      const b = await gw.post(CHAT, "fg_b", CHAT_BODY);
      expect(b.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      // Removing `tenantId` from the cache key makes this `tenant_a_secret`.
      expect((await b.json()) as { id: string }).toMatchObject({ id: "chatcmpl-tenant_b_own" });
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("two DIFFERENT KEYS of the SAME tenant do not share an entry", async () => {
    let call = 0;
    const provider = interceptProviderFetch(() =>
      providerJson(completion(call++ === 0 ? "key_a" : "key_a2")),
    );
    try {
      const gw = gateway();
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      const second = await gw.post(CHAT, "fg_a2", CHAT_BODY);
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      expect((await second.json()) as { id: string }).toMatchObject({ id: "chatcmpl-key_a2" });
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("a DIFFERENT BODY is a different entry", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway();
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      await gw.post(CHAT, "fg_a", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "different" }],
      });
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("a DIFFERENT OPERATION is a different entry even with the same body shape", async () => {
    const provider = interceptProviderFetch(() => providerJson({ object: "list", data: [] }));
    try {
      const gw = gateway();
      const body = { model: "text-embed", input: "hi" };
      await gw.post(EMBEDDINGS, "fg_a", body);
      await gw.post(EMBEDDINGS, "fg_a", body);
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  it("MEMBER ORDER in the body is not identity — the same request hits", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway();
      await gw.post(CHAT, "fg_a", { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }], temperature: 0.2 });
      const second = await gw.post(CHAT, "fg_a", {
        temperature: 0.2,
        messages: [{ role: "user", content: "hi" }],
        model: "gpt-4o-mini",
      });
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. What must never be cached
// ---------------------------------------------------------------------------

describe("what is never cached", () => {
  it("a STREAMING request — Rust `if request.stream { None }`", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response('data: {"choices":[]}\n\ndata: [DONE]\n\n', {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
    );
    try {
      const gw = gateway();
      const body = { ...CHAT_BODY, stream: true };
      const first = await gw.post(CHAT, "fg_a", body);
      await first.text();
      const second = await gw.post(CHAT, "fg_a", body);
      await second.text();
      expect(provider.requests).toHaveLength(2);
      expect(first.headers.get(CACHE_STATUS_HEADER)).toBeNull();
    } finally {
      provider.restore();
    }
  });

  it("a NON-SUCCESS response — Rust stored only `if final_status.is_success()`", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response(JSON.stringify({ error: { message: "upstream is down" } }), {
          status: 500,
          headers: { "content-type": "application/json" },
        }),
    );
    try {
      const gw = gateway();
      const first = await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(first.status).toBeGreaterThanOrEqual(400);
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      // Caching a 5xx would pin an outage in place for the whole TTL.
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("a request that says `Cache-Control: no-store`", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway();
      await gw.post(CHAT, "fg_a", CHAT_BODY, { "cache-control": "no-store" });
      await gw.post(CHAT, "fg_a", CHAT_BODY, { "cache-control": "no-store" });
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  /**
   * The unshareable-response rules are asserted against a STUB route module
   * rather than the inference one, and that is the honest framing.
   *
   * `src/inference/handlers.ts` synthesizes its outgoing headers — it forwards
   * the upstream `content-type` and nothing else (`:983`, `:995`, `:1106`, …) —
   * so an upstream `Cache-Control: private` never reaches this middleware
   * through that path today. The guard therefore governs the response THE
   * GATEWAY EMITS, which is precisely the object being stored, and a stub
   * handler is the only way to emit one and see the rule fire. When a handler
   * that DOES relay upstream cache directives lands, the same guard covers it
   * with no change. The composition root, the auth guard and the middleware are
   * all the real ones; only the terminal handler differs.
   */
  function stubGateway(responseFor: () => Response): Gateway {
    const { app } = createGatewayApp({
      modules: [
        {
          operationIds: ["createChatCompletion"],
          register: (router) => {
            router.register("createChatCompletion", () => responseFor());
          },
        },
      ],
      responseCache: responseCache({ store: new MemoryResponseCacheStore({ now: () => 1_000 }) }),
    });
    return {
      post: async (url, key, body, extra = {}) =>
        await app.request(
          url,
          {
            method: "POST",
            headers: {
              authorization: `Bearer ${key}`,
              "content-type": "application/json",
              ...extra,
            },
            body: JSON.stringify(body),
          },
          CACHE_ON,
        ),
    };
  }

  it("a response marked `private` / `no-store` is served but never stored", async () => {
    let served = 0;
    const gw = stubGateway(() => {
      served += 1;
      return new Response(JSON.stringify({ n: served }), {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "private, no-store" },
      });
    });
    await gw.post(CHAT, "fg_a", CHAT_BODY);
    const second = await gw.post(CHAT, "fg_a", CHAT_BODY);
    expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
    expect(served).toBe(2);
  });

  it("a response carrying `Set-Cookie` is never stored", async () => {
    let served = 0;
    const gw = stubGateway(() => {
      served += 1;
      return new Response(JSON.stringify({ n: served }), {
        status: 200,
        headers: { "content-type": "application/json", "set-cookie": "session=abc" },
      });
    });
    await gw.post(CHAT, "fg_a", CHAT_BODY);
    await gw.post(CHAT, "fg_a", CHAT_BODY);
    // Replaying one caller's session cookie to another is the leak this stops.
    expect(served).toBe(2);
  });

  it("a plain response from the same stub IS stored — the rules above are the exception", async () => {
    // Without this, the two assertions above would also pass if the stub route
    // were never cacheable for some unrelated reason.
    let served = 0;
    const gw = stubGateway(() => {
      served += 1;
      return new Response(JSON.stringify({ n: served }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    await gw.post(CHAT, "fg_a", CHAT_BODY);
    const second = await gw.post(CHAT, "fg_a", CHAT_BODY);
    expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
    expect(served).toBe(1);
  });

  it("an operation outside the AI endpoints (an anonymous health probe)", async () => {
    // `/healthz` has no credential and no body; the middleware must not touch
    // it. If it did, every probe would share one entry across the deployment.
    const { app } = createGatewayApp({
      responseCache: responseCache({ store: new MemoryResponseCacheStore({ now: () => 0 }) }),
    });
    const res = await app.request(`${BASE}/healthz`, {}, CACHE_ON);
    expect(res.status).toBe(200);
    expect(res.headers.get(CACHE_STATUS_HEADER)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 4. The four-level opt-out and the TTL, through the mounted app
// ---------------------------------------------------------------------------

describe("the config opt-outs reach the mounted middleware", () => {
  it("a model on GATEWAY_CACHE_DISABLED_MODELS is never cached", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway({ GATEWAY_CACHE_DISABLED_MODELS: "gpt-4o-mini" });
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("an api-key id on GATEWAY_CACHE_DISABLED_API_KEYS is never cached", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway({ GATEWAY_CACHE_DISABLED_API_KEYS: "key_a" });
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      expect(provider.requests).toHaveLength(2);
      // …while a DIFFERENT key of the same tenant still caches.
      await gw.post(CHAT, "fg_a2", CHAT_BODY);
      await gw.post(CHAT, "fg_a2", CHAT_BODY);
      expect(provider.requests).toHaveLength(3);
    } finally {
      provider.restore();
    }
  });

  it("an `x-ferrogate-config` profile on GATEWAY_CACHE_DISABLED_PROFILES is never cached", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway({ GATEWAY_CACHE_DISABLED_PROFILES: "no_cache_profile" });
      const headers = { "x-ferrogate-config": "no_cache_profile" };
      await gw.post(CHAT, "fg_a", CHAT_BODY, headers);
      await gw.post(CHAT, "fg_a", CHAT_BODY, headers);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("an entry EXPIRES at cache.ttl_secs and the upstream is called again", async () => {
    let now = 1_000;
    const store = new MemoryResponseCacheStore({ now: () => now });
    const provider = interceptProviderFetch(() => providerJson(completion("x")));
    try {
      const gw = gateway({ GATEWAY_CACHE_TTL_SECONDS: "60" }, store);
      await gw.post(CHAT, "fg_a", CHAT_BODY);
      now = 1_059;
      expect((await gw.post(CHAT, "fg_a", CHAT_BODY)).headers.get(CACHE_STATUS_HEADER)).toBe("hit");
      expect(provider.requests).toHaveLength(1);
      now = 1_060;
      expect((await gw.post(CHAT, "fg_a", CHAT_BODY)).headers.get(CACHE_STATUS_HEADER)).toBe(
        "miss",
      );
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 5. The metrics recorders themselves
// ---------------------------------------------------------------------------

describe("responseCacheMetrics", () => {
  it("accumulates and resets", () => {
    resetResponseCacheMetrics();
    expect(responseCacheMetrics()).toEqual({
      cacheHitsTotal: 0,
      cacheMissesTotal: 0,
      semanticCacheHitsTotal: 0,
    });
    recordCacheHit();
    recordCacheHit();
    recordCacheMiss();
    expect(responseCacheMetrics().cacheHitsTotal).toBe(2);
    expect(responseCacheMetrics().cacheMissesTotal).toBe(1);
    resetResponseCacheMetrics();
    expect(responseCacheMetrics().cacheHitsTotal).toBe(0);
  });
});
