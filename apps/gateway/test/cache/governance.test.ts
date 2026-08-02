/**
 * Issue #695 — the response cache stops being a deploy-time var.
 *
 * Every assertion here drives the REAL `createGatewayApp` composition with the
 * REAL `contractAuth` guard and the REAL inference route module, against a REAL
 * `CONTROL_DB` (the `cloudflare:test` D1 binding, migrated by
 * `test/setup-d1.ts`). Only the two cache STORES are swapped for isolate-local
 * ones with a fixed clock, exactly as `test/cache/semantic.test.ts` does.
 *
 * The load-bearing assertions do NOT trust the `x-ferrogate-cache` header: they
 * count the requests the intercepted provider `fetch` actually saw. A header
 * can be written by code that cached nothing, and a governance control that
 * reports the right thing while dispatching (or not dispatching) the wrong one
 * is precisely the defect class this repository keeps shipping.
 *
 * ## What each section pins
 *
 *  1. **Enable** — a tenant row can switch its own traffic to `semantic` in a
 *     deployment whose `GATEWAY_CACHE_MODE` var says `exact_match`.
 *  2. **Tune** — a tenant row's `similarity_threshold` decides the match, and
 *     the CONTROL half (a threshold the paraphrase cannot reach) proves the
 *     number is read rather than merely present.
 *  3. **THE TRAP (issue text, verbatim): "if you make the threshold tunable,
 *     the threshold must be part of that fingerprint too — otherwise loosening
 *     it silently reuses entries that the tighter setting would never have
 *     matched."** A threshold change must ROTATE the key, so entries admitted
 *     under the old number are unreachable rather than re-matched under the new
 *     one. Without the governance fingerprint in `cache/key.ts` the second
 *     lookup lands in the same bucket and hits.
 *  4. **Invalidate** — bumping `invalidation_epoch` makes an entry that was
 *     hitting a moment ago unreachable, for the exact layer as well as the
 *     semantic one. This is the only invalidation primitive available: the
 *     Cloudflare Cache API cannot enumerate keys.
 *  5. **The fence** — one tenant's governance row must never move another
 *     tenant's key, and two tenants must never share an entry however
 *     identically they are configured. This is the property the mutation proof
 *     in the PR body targets.
 *  6. **Fail closed** — an unreadable `semantic_cache_policies` table bypasses
 *     the cache instead of silently falling back to the deployment vars. The
 *     failure direction matters: falling back would re-enable caching for a
 *     tenant that had turned it off and would ignore an invalidation the
 *     operator had just performed.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { SemanticResponseCache } from "../../src/cache/semantic.js";
import { MemoryResponseCacheStore } from "../../src/cache/store.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { CACHE_STATUS_HEADER, responseCache } from "../../src/middleware/response-cache.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { ALL_ROUTES, fixedRequestIds } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";

const BASE = "https://gw.test";
const CHAT = `${BASE}/v1/chat/completions`;

const CONTROL_DB = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;

/** Two tenants, two credentials — the partition a governed cache must keep. */
const NATIVE_KEYS = JSON.stringify([
  { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: [] },
  { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: [] },
]);

/**
 * The DEPLOYMENT's vars: caching on, `exact_match`, Rust's default threshold.
 *
 * Deliberately NOT semantic. Every "the tenant enabled it" assertion below is
 * therefore proving that the durable row moved the decision, not that a var
 * already agreed with it.
 */
const DEPLOYMENT_VARS = {
  GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
  GATEWAY_CACHE_ENABLED: "true",
  GATEWAY_CACHE_MODE: "exact_match",
  GATEWAY_CACHE_TTL_SECONDS: "300",
};

/** The prompt, and the SAME words re-ordered — cosine ~1.0 (a bag of words). */
const PROMPT = "summarize the quarterly revenue report for the board";
const PARAPHRASE = "for the board summarize the quarterly revenue report";

function chatBody(prompt: string) {
  return { model: "gpt-4o-mini", messages: [{ role: "user", content: prompt }] };
}

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
  post(key: string, prompt: string): Response | Promise<Response>;
}

/**
 * The real composition root, sharing ONE pair of stores across every `gateway()`
 * built from the same call.
 *
 * The stores are created by the caller when a test needs two DIFFERENT
 * governance states to see the SAME entries — which is exactly what the
 * "a threshold change rotates the key" and "invalidation" assertions need. If
 * the stores were rebuilt per gateway those tests would pass for the wrong
 * reason (an empty cache always misses).
 */
function gateway(
  stores: { exact: MemoryResponseCacheStore; semantic: SemanticResponseCache },
  overrides: Record<string, unknown> = {},
): Gateway {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(ALL_ROUTES),
        requestIds: fixedRequestIds,
      }),
    ],
    responseCache: responseCache({
      store: stores.exact,
      semanticStore: stores.semantic,
      now: () => 1_000,
    }),
  });
  // A FRESH env object per gateway: `guardrailPolicyFingerprint` memoizes on
  // the env identity, and reusing one would carry a memo across a test that
  // changes durable state.
  const fullEnv = { ...DEPLOYMENT_VARS, CONTROL_DB, ...overrides };
  return {
    post: (key, prompt) =>
      app.request(
        CHAT,
        {
          method: "POST",
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
          body: JSON.stringify(chatBody(prompt)),
        },
        fullEnv,
      ),
  };
}

function freshStores() {
  return {
    exact: new MemoryResponseCacheStore({ now: () => 1_000 }),
    semantic: new SemanticResponseCache(),
  };
}

/** Upsert the governed row the gateway reads. `undefined` leaves a column NULL. */
async function setPolicy(
  scopeId: string,
  row: {
    enabled?: number;
    mode?: string;
    similarityThreshold?: number;
    ttlSeconds?: number;
    scopedModels?: string;
    invalidationEpoch?: number;
  },
): Promise<void> {
  await CONTROL_DB.prepare(
    "INSERT INTO semantic_cache_policies " +
      "(scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds, scoped_models, " +
      " invalidation_epoch, updated_at_unix, updated_by, generation) " +
      "VALUES ('tenant', ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1000, 'test', 1) " +
      "ON CONFLICT (scope_type, scope_id) DO UPDATE SET " +
      "enabled = excluded.enabled, mode = excluded.mode, " +
      "similarity_threshold = excluded.similarity_threshold, ttl_seconds = excluded.ttl_seconds, " +
      "scoped_models = excluded.scoped_models, invalidation_epoch = excluded.invalidation_epoch, " +
      "generation = semantic_cache_policies.generation + 1",
  )
    .bind(
      scopeId,
      row.enabled ?? null,
      row.mode ?? null,
      row.similarityThreshold ?? null,
      row.ttlSeconds ?? null,
      row.scopedModels ?? null,
      row.invalidationEpoch ?? 0,
    )
    .run();
}

beforeEach(async () => {
  await CONTROL_DB.prepare("DELETE FROM semantic_cache_policies").run();
});

// ---------------------------------------------------------------------------
// 1. ENABLE — a tenant switches its own traffic to the semantic layer
// ---------------------------------------------------------------------------

describe("a tenant can enable the semantic cache the deployment vars leave off", () => {
  it("serves a PARAPHRASE without an upstream call once its row says `semantic`", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 0.9 });
      const stores = freshStores();

      const first = await gateway(stores).post("fg_a", PROMPT);
      expect(first.status).toBe(200);
      expect(provider.requests).toHaveLength(1);

      // A DIFFERENT body, so a different EXACT key. Only the similarity layer
      // can answer it — and the deployment var says `exact_match`, so the only
      // thing that could have turned it on is the durable row.
      const second = await gateway(stores).post("fg_a", PARAPHRASE);
      expect(second.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
      expect(await second.json()).toEqual(completion("first"));
    } finally {
      provider.restore();
    }
  });

  it("CONTROL: with NO row the deployment var still governs — the paraphrase dispatches", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const stores = freshStores();
      await gateway(stores).post("fg_a", PROMPT);
      await gateway(stores).post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("a tenant row can turn its OWN caching off inside an enabled deployment", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { enabled: 0 });
      const stores = freshStores();

      const first = await gateway(stores).post("fg_a", PROMPT);
      const second = await gateway(stores).post("fg_a", PROMPT);
      // Identical body, identical credential: the exact layer would hit. The
      // tenant's own opt-out is what stops it.
      expect(provider.requests).toHaveLength(2);
      expect(first.headers.get(CACHE_STATUS_HEADER)).toBeNull();
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBeNull();
    } finally {
      provider.restore();
    }
  });

  it("`scoped_models` narrows caching to the named models and nothing else", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      // The "scope it" lever. A non-empty list is an ALLOWLIST: only these
      // logical models are cached for this tenant. The failure direction that
      // matters is the widening one — a tenant who excluded a model finding it
      // cached anyway — so the assertion is on the EXCLUDED model.
      await setPolicy("tenant_a", { scopedModels: JSON.stringify(["some-other-model"]) });
      const stores = freshStores();

      await gateway(stores).post("fg_a", PROMPT);
      const second = await gateway(stores).post("fg_a", PROMPT);
      // `gpt-4o-mini` is not in the tenant's scope, so an identical body under
      // an identical credential still dispatches.
      expect(provider.requests).toHaveLength(2);
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBeNull();
    } finally {
      provider.restore();
    }
  });

  it("CONTROL: a scope that NAMES the model leaves caching on", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      // Without this, the assertion above would also pass for a projection that
      // treated any `scoped_models` value as "cache nothing".
      await setPolicy("tenant_a", { scopedModels: JSON.stringify(["gpt-4o-mini"]) });
      const stores = freshStores();

      await gateway(stores).post("fg_a", PROMPT);
      const second = await gateway(stores).post("fg_a", PROMPT);
      expect(provider.requests).toHaveLength(1);
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
    } finally {
      provider.restore();
    }
  });

  it("the OPERATOR master switch still wins: a tenant cannot cache in a disabled deployment", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { enabled: 1, mode: "semantic", similarityThreshold: 0.5 });
      const stores = freshStores();
      const off = { GATEWAY_CACHE_ENABLED: "" };
      await gateway(stores, off).post("fg_a", PROMPT);
      await gateway(stores, off).post("fg_a", PROMPT);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 2. TUNE — the tenant's threshold decides the match
// ---------------------------------------------------------------------------

describe("the similarity threshold is tunable per tenant", () => {
  it("a threshold the paraphrase clears serves it from cache", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 0.9 });
      const stores = freshStores();
      await gateway(stores).post("fg_a", PROMPT);
      await gateway(stores).post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  it("CONTROL: a threshold the paraphrase cannot reach dispatches", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      // 1.0 is in range and reachable only by a vector identical to the stored
      // one; an f32 round-trip of a re-ordered bag lands just under it.
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 1.0 });
      const stores = freshStores();
      await gateway(stores).post("fg_a", PROMPT);
      await gateway(stores).post("fg_a", `${PARAPHRASE} urgently`);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. THE TRAP — a threshold change must ROTATE the key
// ---------------------------------------------------------------------------

describe("a governance change rotates the cache key", () => {
  it("LOOSENING the threshold does not re-match entries admitted under the tighter one", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 0.99 });
      const stores = freshStores();

      // Stored while the tenant was strict.
      await gateway(stores).post("fg_a", PROMPT);
      expect(provider.requests).toHaveLength(1);

      // The tenant loosens. The stored entry is a ~1.0 match for the
      // paraphrase, so WITHOUT the threshold in the key this is a hit and the
      // count stays at 1 — an entry admitted under the old governance being
      // reused under the new one, with nothing recording that it was.
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 0.6 });
      await gateway(stores).post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("the EXACT layer rotates too — the same body under a changed policy misses", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { ttlSeconds: 300 });
      const stores = freshStores();
      await gateway(stores).post("fg_a", PROMPT);
      await gateway(stores).post("fg_a", PROMPT);
      // Same governance, identical body: a hit, so the next assertion is about
      // the CHANGE and not about a cache that never worked.
      expect(provider.requests).toHaveLength(1);

      await setPolicy("tenant_a", { ttlSeconds: 60 });
      await gateway(stores).post("fg_a", PROMPT);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 4. INVALIDATE — the epoch is the only primitive that reaches both stores
// ---------------------------------------------------------------------------

describe("explicit invalidation", () => {
  it("bumping `invalidation_epoch` makes a hitting entry unreachable", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { invalidationEpoch: 0 });
      const stores = freshStores();

      await gateway(stores).post("fg_a", PROMPT);
      const hit = await gateway(stores).post("fg_a", PROMPT);
      expect(hit.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
      expect(provider.requests).toHaveLength(1);

      await setPolicy("tenant_a", { invalidationEpoch: 1 });
      const afterPurge = await gateway(stores).post("fg_a", PROMPT);
      expect(afterPurge.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("reaches the SEMANTIC bucket as well, which no key enumeration could", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 0.9 });
      const stores = freshStores();
      await gateway(stores).post("fg_a", PROMPT);
      await gateway(stores).post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(1);

      await setPolicy("tenant_a", {
        mode: "semantic",
        similarityThreshold: 0.9,
        invalidationEpoch: 7,
      });
      await gateway(stores).post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 5. THE FENCE — governance is per tenant, and so is every entry
// ---------------------------------------------------------------------------

describe("the tenant fence survives governance", () => {
  it("tenant_b never receives tenant_a's body, however identical the request", async () => {
    let call = 0;
    const provider = interceptProviderFetch(() =>
      providerJson(completion(call++ === 0 ? "tenant_a_secret" : "tenant_b_own")),
    );
    try {
      // The SAME governance for both, so nothing but the identity in the key
      // can be keeping them apart.
      await setPolicy("tenant_a", { mode: "semantic", similarityThreshold: 0.5 });
      await setPolicy("tenant_b", { mode: "semantic", similarityThreshold: 0.5 });
      const stores = freshStores();

      const a = await gateway(stores).post("fg_a", PROMPT);
      expect(await a.json()).toEqual(completion("tenant_a_secret"));

      const b = await gateway(stores).post("fg_b", PROMPT);
      expect(provider.requests).toHaveLength(2);
      expect(await b.json()).toEqual(completion("tenant_b_own"));
    } finally {
      provider.restore();
    }
  });

  it("one tenant's invalidation does not rotate another tenant's key", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const stores = freshStores();
      await gateway(stores).post("fg_b", PROMPT);
      expect(provider.requests).toHaveLength(1);

      // tenant_a purges. tenant_b's entry must be untouched — an invalidation
      // that reached every tenant would be a denial-of-service one tenant can
      // inflict on the whole deployment's cache spend.
      await setPolicy("tenant_a", { invalidationEpoch: 99 });
      const stillHit = await gateway(stores).post("fg_b", PROMPT);
      expect(stillHit.headers.get(CACHE_STATUS_HEADER)).toBe("hit");
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 6. FAIL CLOSED
// ---------------------------------------------------------------------------

describe("an unreadable governance table fails closed", () => {
  it("bypasses the cache rather than falling back to the deployment vars", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const stores = freshStores();
      // A TARGETED fault: every other control read this request makes (the
      // drain document, the guardrail policy bindings) is delegated to the real
      // database, and only the governance query rejects. A wholesale broken
      // binding would 503 on the drain gate long before the cache ran, and the
      // test would pass for a reason that has nothing to do with the cache.
      const brokenGovernance = {
        prepare(sql: string) {
          if (sql.includes("semantic_cache_policies")) {
            return {
              bind: () => ({
                all: () => Promise.reject(new Error("no such table: semantic_cache_policies")),
              }),
            };
          }
          return CONTROL_DB.prepare(sql);
        },
        batch: (statements: unknown) =>
          (CONTROL_DB as unknown as { batch(s: unknown): unknown }).batch(statements),
      };
      const first = await gateway(stores, { CONTROL_DB: brokenGovernance }).post("fg_a", PROMPT);
      const second = await gateway(stores, { CONTROL_DB: brokenGovernance }).post("fg_a", PROMPT);

      // Availability is never traded for a cache: both requests are served.
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      // But nothing was stored or served from store, and the operator is told.
      expect(provider.requests).toHaveLength(2);
      expect(second.headers.get(CACHE_STATUS_HEADER)).toBe("bypass");
    } finally {
      provider.restore();
    }
  });
});
