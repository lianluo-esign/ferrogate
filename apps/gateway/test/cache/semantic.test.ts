/**
 * The SEMANTIC response cache (#273) — algorithm parity AND the mount.
 *
 * ## Why this file exists
 *
 * `cache.mode = "semantic"` was ACCEPTED by the config parser and did nothing:
 * two PORT-TODOs (in `cache/config.ts` and `cache/metrics.ts`) said the layer
 * needed Vectorize + Workers AI bindings that this Worker does not declare.
 * Reading `crates/ferrogate-gateway/src/semantic_cache.rs` instead of the
 * marker showed the opposite — *"In-tree cosine similarity over stored f32
 * vectors; no external vector DB"* — so the whole layer is arithmetic over the
 * prompt string and ports with no binding at all.
 *
 * ## The two kinds of assertion below, and why both are needed
 *
 * **Algorithm parity** is checked against something OUTSIDE this repo where it
 * can be: `fnv1a64` is pinned to the published FNV-1a-64 test vectors, not to
 * whatever this implementation happens to produce. A hash function checked only
 * against itself is a hash function with no spec.
 *
 * **The mount** is checked the way this project learned to check mounts: by
 * counting the requests the intercepted provider `fetch` actually saw. A
 * semantic hit is the ONLY thing that can serve a request whose exact cache key
 * has never been stored without dispatching upstream, so a paraphrase answered
 * with zero new upstream calls is a fact only the real layer can produce — trap
 * (1) in the project brief, the `real ?? fallback` shape, cannot apply here.
 *
 * Deleting the semantic branch from `src/middleware/response-cache.ts` turns
 * this file red. So does deleting `semanticStore.insert(...)`, and so does
 * dropping the tenant from `semanticScopeMaterial`. The observations are in the
 * slice report.
 */
import { describe, expect, it } from "vitest";
import { CACHE_SEMANTIC_THRESHOLD_VAR, responseCachePolicy } from "../../src/cache/config.js";
import { canonicalJson, semanticScopeMaterial } from "../../src/cache/key.js";
import { resetResponseCacheMetrics, responseCacheMetrics } from "../../src/cache/metrics.js";
import {
  SEMANTIC_EMBED_DIMS,
  SemanticResponseCache,
  cosineSimilarity,
  embedText,
  fnv1a64,
  promptTextForEmbedding,
  resetSharedSemanticCache,
  sharedSemanticCache,
} from "../../src/cache/semantic.js";
import type { CachedResponse } from "../../src/cache/store.js";
import { MemoryResponseCacheStore } from "../../src/cache/store.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { CACHE_STATUS_HEADER, responseCache } from "../../src/middleware/response-cache.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { ALL_ROUTES, fixedRequestIds } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";

// ---------------------------------------------------------------------------
// 1. `fnv1a64` — pinned to the PUBLISHED vectors, not to itself
// ---------------------------------------------------------------------------

describe("fnv1a64 is the real FNV-1a-64, in 32-bit halves", () => {
  const hex = (bytes: string): string => {
    const { hi, lo } = fnv1a64(new TextEncoder().encode(bytes));
    return hi.toString(16).padStart(8, "0") + lo.toString(16).padStart(8, "0");
  };

  it("matches the published 64-bit test vectors", () => {
    // The FNV reference vectors. These are the spec, not this implementation's
    // output, which is the entire point: the Rust embedder's bucket assignment
    // is determined by this hash, so a hash that is merely self-consistent
    // would produce a self-consistent but WRONG vector space.
    expect(hex("")).toBe("cbf29ce484222325");
    expect(hex("a")).toBe("af63dc4c8601ec8c");
    expect(hex("foobar")).toBe("85944171f73967e8");
  });

  it("agrees with an independent BigInt implementation over many inputs", () => {
    // The halves arithmetic is the risky part (carries, ToUint32 truncation).
    // BigInt is slow but obviously correct, so it is the oracle here.
    const encoder = new TextEncoder();
    for (let n = 0; n < 200; n += 1) {
      const input = `token-${n}-${"x".repeat(n % 17)}`;
      let reference = 0xcbf29ce484222325n;
      for (const byte of encoder.encode(input)) {
        reference ^= BigInt(byte);
        reference = BigInt.asUintN(64, reference * 0x100000001b3n);
      }
      expect(hex(input)).toBe(reference.toString(16).padStart(16, "0"));
    }
  });
});

// ---------------------------------------------------------------------------
// 2. `embedText` — the Rust feature-hashing embedder
// ---------------------------------------------------------------------------

describe("embedText reproduces Rust `embed_text`", () => {
  it("produces a 256-dimension L2-normalized vector", () => {
    const vector = embedText("the quarterly revenue report");
    expect(vector).toBeInstanceOf(Float32Array);
    expect(vector.length).toBe(SEMANTIC_EMBED_DIMS);
    let norm = 0;
    for (const value of vector) norm += value * value;
    expect(Math.sqrt(norm)).toBeCloseTo(1, 5);
  });

  it("is a BAG of words: re-ordering the clauses is the SAME vector", () => {
    // This is what makes the layer able to answer a paraphrase at all, and it
    // is a property of the Rust algorithm, not of this port.
    const a = embedText("summarize the quarterly revenue report for the board");
    const b = embedText("for the board summarize the quarterly revenue report");
    expect(cosineSimilarity(a, b)).toBeCloseTo(1, 6);
  });

  it("ignores punctuation and whitespace runs, and lowercases ASCII", () => {
    expect(cosineSimilarity(embedText("Hello, World!"), embedText("hello   world"))).toBeCloseTo(
      1,
      6,
    );
  });

  it("lowercases ASCII ONLY — Rust used `to_ascii_lowercase`", () => {
    // `String.prototype.toLowerCase()` would fold these together; Rust's
    // `to_ascii_lowercase` leaves every non-ASCII character alone, so they are
    // DIFFERENT tokens and must land in different buckets.
    const upper = embedText("ÄÖÜ");
    const lower = embedText("äöü");
    expect(cosineSimilarity(upper, lower)).not.toBeCloseTo(1, 6);
    // …while the ASCII half of the same rule DOES fold.
    expect(cosineSimilarity(embedText("ABC"), embedText("abc"))).toBeCloseTo(1, 6);
  });

  it("tokenizes on Unicode alphanumerics, not on [a-zA-Z0-9]", () => {
    // Rust split on `!char::is_alphanumeric()`. A CJK or Cyrillic word is one
    // token under that rule; an ASCII-only tokenizer would shred it.
    expect(cosineSimilarity(embedText("привет мир"), embedText("мир привет"))).toBeCloseTo(1, 6);
    expect(cosineSimilarity(embedText("привет мир"), embedText("привет"))).toBeLessThan(0.95);
  });

  it("puts disjoint vocabularies far apart", () => {
    const a = embedText("summarize the quarterly revenue report for the board");
    const b = embedText("translate this haiku into portuguese with furigana");
    expect(cosineSimilarity(a, b)).toBeLessThan(0.5);
  });

  it("is deterministic — the same text always yields the same vector", () => {
    expect([...embedText("deterministic please")]).toEqual([...embedText("deterministic please")]);
  });

  it("an empty prompt is the ZERO vector, which can never hit", () => {
    // Rust returns the un-normalized zero vector when `norm == 0.0`, and
    // `cosine_similarity` answers 0.0 for a zero-magnitude input. So an empty
    // prompt is similar to NOTHING, including another empty prompt — the
    // fail-safe direction.
    const empty = embedText("   ...   ");
    expect([...empty].every((value) => value === 0)).toBe(true);
    expect(cosineSimilarity(empty, empty)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 3. `cosineSimilarity` — the Rust fail-safe rules
// ---------------------------------------------------------------------------

describe("cosineSimilarity", () => {
  it("returns 0 for length-mismatched vectors rather than throwing", () => {
    expect(cosineSimilarity(new Float32Array([1, 0]), new Float32Array([1, 0, 0]))).toBe(0);
  });

  it("returns 0 for a zero-magnitude vector — never a false hit", () => {
    expect(cosineSimilarity(new Float32Array([0, 0]), new Float32Array([1, 1]))).toBe(0);
  });

  it("is 1 for identical and 0 for orthogonal vectors", () => {
    expect(cosineSimilarity(new Float32Array([3, 4]), new Float32Array([3, 4]))).toBeCloseTo(1, 6);
    expect(cosineSimilarity(new Float32Array([1, 0]), new Float32Array([0, 1]))).toBeCloseTo(0, 6);
  });
});

// ---------------------------------------------------------------------------
// 4. `promptTextForEmbedding` — the Rust extraction precedence
// ---------------------------------------------------------------------------

describe("promptTextForEmbedding reproduces Rust `prompt_text_for_embedding`", () => {
  const extract = (body: unknown): string => promptTextForEmbedding(body, canonicalJson);

  it("joins `messages[].content` strings with newlines", () => {
    expect(
      extract({
        messages: [
          { role: "system", content: "be terse" },
          { role: "user", content: "hello" },
        ],
      }),
    ).toBe("be terse\nhello");
  });

  it("reads content-part arrays — `{text}` objects and bare strings", () => {
    expect(
      extract({
        messages: [{ role: "user", content: [{ type: "text", text: "part one" }, "part two"] }],
      }),
    ).toBe("part one\npart two");
  });

  it("skips non-text parts (an image_url part contributes nothing)", () => {
    expect(
      extract({
        messages: [
          { role: "user", content: [{ type: "image_url", image_url: { url: "https://x/y" } }] },
        ],
      }),
    ).toBe(
      canonicalJson({
        messages: [
          { role: "user", content: [{ type: "image_url", image_url: { url: "https://x/y" } }] },
        ],
      }),
    );
  });

  it("falls back to `input`, then to `prompt`, in the Rust order", () => {
    expect(extract({ input: "responses-style input" })).toBe("responses-style input");
    expect(extract({ prompt: "bare prompt" })).toBe("bare prompt");
    // `messages` wins when it produced text…
    expect(extract({ messages: [{ content: "from messages" }], input: "from input" })).toBe(
      "from messages",
    );
    // …and yields to `input` when it produced only whitespace. Note the exact
    // shape: Rust tests `collected.trim().is_empty()` but APPENDS to
    // `collected`, and `push_with_separator` inserts a `\n` because the buffer
    // is not EMPTY (it holds the whitespace). So the whitespace is retained
    // and the result is `"   \nfrom input"`, not `"from input"`. It makes no
    // difference to the embedding — whitespace produces no tokens — and it is
    // reproduced rather than tidied because "tidier than the reference" is how
    // a port stops being one.
    expect(extract({ messages: [{ content: "   " }], input: "from input" })).toBe(
      "   \nfrom input",
    );
  });

  it("falls back to the SERIALIZED body when no known field carries text", () => {
    const body = { model: "gpt-4o-mini", temperature: 0.2 };
    expect(extract(body)).toBe(canonicalJson(body));
  });
});

// ---------------------------------------------------------------------------
// 5. `SemanticResponseCache` — the Rust data structure
// ---------------------------------------------------------------------------

function entry(marker: string): CachedResponse {
  return {
    statusCode: 200,
    contentType: "application/json",
    body: new TextEncoder().encode(marker),
  };
}

function markerOf(response: CachedResponse): string {
  return new TextDecoder().decode(response.body);
}

describe("SemanticResponseCache", () => {
  it("returns the HIGHEST-similarity live entry at or above the threshold", () => {
    const cache = new SemanticResponseCache();
    const query = embedText("alpha beta gamma delta");
    cache.insert("scope", embedText("alpha beta gamma epsilon"), entry("near"), 60, 100, 0);
    cache.insert("scope", embedText("alpha beta gamma delta"), entry("exact"), 60, 100, 0);
    cache.insert("scope", embedText("zeta eta theta iota"), entry("far"), 60, 100, 0);
    const hit = cache.lookup("scope", query, 0.5, 0);
    if (hit === undefined) throw new Error("expected a hit above the threshold");
    expect(markerOf(hit.response)).toBe("exact");
    // The similarity is REPORTED, not just used: Rust returns it so the debug
    // log can say how close the match was, and a layer that always reported
    // 1.0 would be indistinguishable from an exact cache.
    expect(hit.similarity).toBeGreaterThan(0.99);
  });

  it("misses when nothing clears the threshold", () => {
    const cache = new SemanticResponseCache();
    cache.insert("scope", embedText("alpha beta gamma"), entry("stored"), 60, 100, 0);
    const query = embedText("alpha beta gamma");
    const similarity = cosineSimilarity(query, embedText("alpha beta gamma"));
    // Measured, then bracketed — no hardcoded float, so a change in the
    // embedder shows up as a changed MEASUREMENT rather than a broken test.
    expect(cache.lookup("scope", query, similarity - 0.01, 0)).toBeDefined();
    expect(cache.lookup("scope", embedText("omega psi chi"), similarity - 0.01, 0)).toBeUndefined();
  });

  it("never serves an EXPIRED entry — Rust's `expires_at <= now`, not `<`", () => {
    const cache = new SemanticResponseCache();
    cache.insert("scope", embedText("alpha beta"), entry("stored"), 60, 100, 1_000);
    const query = embedText("alpha beta");
    expect(cache.lookup("scope", query, 0.5, 1_059)).toBeDefined();
    // Exactly at expiry is already expired.
    expect(cache.lookup("scope", query, 0.5, 1_060)).toBeUndefined();
  });

  it("buckets by SCOPE — a different scope never sees the entry", () => {
    const cache = new SemanticResponseCache();
    cache.insert("tenant-a", embedText("alpha beta"), entry("a"), 60, 100, 0);
    expect(cache.lookup("tenant-b", embedText("alpha beta"), 0.5, 0)).toBeUndefined();
  });

  it("evicts GLOBALLY FIFO past `max_records`, across scopes", () => {
    // Rust's `order` deque is (scope, seq) in insertion order and the cap is on
    // `total`, not per bucket — so a busy scope cannot pin a quiet one's
    // entries. Two scopes, cap 2, three inserts: the FIRST goes, whichever
    // bucket it was in.
    const cache = new SemanticResponseCache();
    cache.insert("scope-1", embedText("alpha"), entry("first"), 60, 2, 0);
    cache.insert("scope-2", embedText("beta"), entry("second"), 60, 2, 0);
    cache.insert("scope-2", embedText("gamma"), entry("third"), 60, 2, 0);
    expect(cache.size).toBe(2);
    expect(cache.lookup("scope-1", embedText("alpha"), 0.5, 0)).toBeUndefined();
    expect(cache.lookup("scope-2", embedText("beta"), 0.5, 0)).toBeDefined();
    expect(cache.lookup("scope-2", embedText("gamma"), 0.5, 0)).toBeDefined();
  });

  it("stores nothing at a non-positive TTL or cap", () => {
    const cache = new SemanticResponseCache();
    cache.insert("scope", embedText("alpha"), entry("x"), 0, 100, 0);
    cache.insert("scope", embedText("alpha"), entry("x"), 60, 0, 0);
    expect(cache.size).toBe(0);
  });

  // The Workers-only bound. Rust had gigabytes of process heap; a Workers
  // isolate has 128 MiB, and `max_records=1000` × a 1 MiB body would be ~1 GB.
  // Exceeding it kills the isolate, so the cache would cause the outage.
  it("evicts on the BYTE bound too, in the same global FIFO order", () => {
    const big = (marker: string): CachedResponse => ({
      statusCode: 200,
      contentType: "application/json",
      body: new Uint8Array(400).fill(marker.charCodeAt(0)),
    });
    // 1000 records allowed, but only 1000 bytes — so bytes bind, not records.
    const cache = new SemanticResponseCache({ maxBytes: 1_000 });
    cache.insert("scope", embedText("alpha"), big("a"), 60, 1_000, 0);
    cache.insert("scope", embedText("beta"), big("b"), 60, 1_000, 0);
    expect(cache.size).toBe(2);
    expect(cache.byteSize).toBe(800);

    cache.insert("scope", embedText("gamma"), big("c"), 60, 1_000, 0);
    // Three would be 1200 > 1000, so the OLDEST goes — the same FIFO the
    // record cap uses, not a different policy.
    expect(cache.size).toBe(2);
    expect(cache.byteSize).toBe(800);
    expect(cache.lookup("scope", embedText("alpha"), 0.5, 0)).toBeUndefined();
    expect(cache.lookup("scope", embedText("gamma"), 0.5, 0)).toBeDefined();
  });

  it("REFUSES a single body larger than the whole budget rather than flushing", () => {
    const cache = new SemanticResponseCache({ maxBytes: 1_000 });
    cache.insert("scope", embedText("alpha"), entry("keep me"), 60, 1_000, 0);
    cache.insert(
      "scope",
      embedText("beta"),
      { statusCode: 200, contentType: "application/json", body: new Uint8Array(2_000) },
      60,
      1_000,
      0,
    );
    // Admitting the oversized body would have evicted everything on its way
    // back out, so one pathological response would empty the cache.
    expect(cache.size).toBe(1);
    expect(cache.lookup("scope", embedText("alpha"), 0.5, 0)).toBeDefined();
  });

  it("byteSize returns to zero as entries leave", () => {
    const cache = new SemanticResponseCache({ maxBytes: 1_000 });
    cache.insert("a", embedText("alpha"), entry("xxxx"), 60, 1, 0);
    cache.insert("b", embedText("beta"), entry("yy"), 60, 1, 0);
    // The record cap of 1 evicted the first; the accounting must follow it out,
    // or a long-running isolate would drift toward a permanently "full" cache
    // that can never admit anything again.
    expect(cache.size).toBe(1);
    expect(cache.byteSize).toBe(2);
  });
});

describe("the isolate singleton", () => {
  it("is ONE instance per isolate — Rust's process-global, as close as a Worker gets", () => {
    // The residual platform limit named in `src/cache/semantic.ts`: entries are
    // shared by every request THIS isolate serves (which is what makes the
    // layer useful at all) and by no other isolate (which is what Rust's single
    // process did have). Asserting the first half here keeps the approximation
    // honest — if this ever stopped being a singleton the layer would degrade
    // to a per-request cache that can never hit, silently.
    expect(sharedSemanticCache()).toBe(sharedSemanticCache());
  });

  it("a SEPARATE instance shares nothing — the cross-isolate residue, made visible", () => {
    const one = new SemanticResponseCache();
    const two = new SemanticResponseCache();
    one.insert("scope", embedText("alpha beta"), entry("a"), 60, 100, 0);
    expect(two.lookup("scope", embedText("alpha beta"), 0.5, 0)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 6. Config — `cache.semantic_similarity_threshold`
// ---------------------------------------------------------------------------

describe("GATEWAY_CACHE_SEMANTIC_THRESHOLD", () => {
  const policy = (env: Record<string, string>) =>
    responseCachePolicy({ GATEWAY_CACHE_ENABLED: "true", ...env });

  it("defaults to the Rust 0.92", () => {
    expect(policy({}).semanticSimilarityThreshold).toBe(0.92);
  });

  it("is read when declared", () => {
    expect(
      policy({ GATEWAY_CACHE_MODE: "semantic", GATEWAY_CACHE_SEMANTIC_THRESHOLD: "0.75" })
        .semanticSimilarityThreshold,
    ).toBe(0.75);
  });

  it("refuses a non-number in EITHER mode — serde parses the field regardless", () => {
    for (const mode of ["exact_match", "semantic"]) {
      const result = policy({
        GATEWAY_CACHE_MODE: mode,
        GATEWAY_CACHE_SEMANTIC_THRESHOLD: "0,92",
      });
      expect(result.enabled).toBe(false);
      expect(result.misconfiguration).toContain(CACHE_SEMANTIC_THRESHOLD_VAR);
    }
  });

  it("refuses an out-of-range value in SEMANTIC mode only — Rust `validate_cache`", () => {
    for (const bad of ["0", "-0.5", "1.5"]) {
      const semantic = policy({
        GATEWAY_CACHE_MODE: "semantic",
        GATEWAY_CACHE_SEMANTIC_THRESHOLD: bad,
      });
      expect(semantic.enabled).toBe(false);
      expect(semantic.misconfiguration).toContain("(0.0, 1.0]");
      // Rust reads the field only `if matches!(mode, CacheMode::Semantic)`, so
      // the same value is inert — not an error — in exact-match mode.
      const exact = policy({
        GATEWAY_CACHE_MODE: "exact_match",
        GATEWAY_CACHE_SEMANTIC_THRESHOLD: bad,
      });
      expect(exact.enabled).toBe(true);
      expect(exact.misconfiguration).toBeNull();
    }
  });

  it("1.0 is IN range (the interval is half-open at the bottom only)", () => {
    const result = policy({
      GATEWAY_CACHE_MODE: "semantic",
      GATEWAY_CACHE_SEMANTIC_THRESHOLD: "1.0",
    });
    expect(result.enabled).toBe(true);
    expect(result.semanticSimilarityThreshold).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 7. The scope bucket carries the identity — derived from the exact key
// ---------------------------------------------------------------------------

describe("semanticScopeMaterial is the exact key minus the body", () => {
  const identity = {
    route: "createChatCompletion",
    path: "/v1/chat/completions",
    tenantId: "tenant_a",
    workspaceId: null,
    projectId: null,
    userId: null,
    apiKeyId: "key_a",
    keySource: "native",
    platformOperator: false,
    scopeDigest: "[]",
    logicalModel: "gpt-4o-mini",
    stream: false as const,
    requestBody: { messages: [{ content: "hello" }] },
    guardrailPolicyFingerprint: "gp",
    registryFingerprint: "rf",
    governanceFingerprint: "ungoverned",
  };

  it("drops the body and the stream flag, and NOTHING else", () => {
    const material = JSON.parse(semanticScopeMaterial(identity)) as Record<string, unknown>;
    expect(material).not.toHaveProperty("request_body");
    expect(material).not.toHaveProperty("stream");
    // Every isolation field survives. This list is what a semantic hit is
    // allowed to be shared across; anything missing here is a leak that the
    // exact layer would have caught and this one would not.
    for (const field of [
      "route",
      "path",
      "tenant_id",
      "workspace_id",
      "project_id",
      "user_id",
      "api_key_id",
      "key_source",
      "platform_operator",
      "scope_digest",
      "logical_model",
      "provider_registry_fingerprint",
      "guardrail_policy_fingerprint",
      // #695: the governed rules an entry was admitted under travel into the
      // BUCKET, not just into the exact key. Drop it here and a tenant's
      // threshold change or invalidation stops reaching the similarity layer —
      // the one place a stale entry is hardest to notice, because a semantic
      // hit does not have to match the request byte for byte to be served.
      "governance_fingerprint",
    ]) {
      expect(material).toHaveProperty(field);
    }
  });

  it("changes when ANY identity field changes, and not when the body changes", () => {
    const base = semanticScopeMaterial(identity);
    expect(semanticScopeMaterial({ ...identity, requestBody: { other: 1 } })).toBe(base);
    expect(semanticScopeMaterial({ ...identity, tenantId: "tenant_b" })).not.toBe(base);
    expect(semanticScopeMaterial({ ...identity, apiKeyId: "key_z" })).not.toBe(base);
    expect(semanticScopeMaterial({ ...identity, scopeDigest: '["admin.write"]' })).not.toBe(base);
    expect(semanticScopeMaterial({ ...identity, logicalModel: "gpt-4o" })).not.toBe(base);
    expect(semanticScopeMaterial({ ...identity, guardrailPolicyFingerprint: "gp2" })).not.toBe(
      base,
    );
    expect(semanticScopeMaterial({ ...identity, registryFingerprint: "rf2" })).not.toBe(base);
    expect(
      semanticScopeMaterial({ ...identity, governanceFingerprint: "scope=tenant:a|epoch=1" }),
    ).not.toBe(base);
  });
});

// ---------------------------------------------------------------------------
// 8. THE MOUNT — a paraphrase is served without an upstream call
// ---------------------------------------------------------------------------

const BASE = "https://gw.test";
const CHAT = `${BASE}/v1/chat/completions`;

const NATIVE_KEYS = JSON.stringify([
  { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: [] },
  { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: [] },
]);

const SEMANTIC_ON = {
  GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
  GATEWAY_CACHE_ENABLED: "true",
  GATEWAY_CACHE_MODE: "semantic",
  GATEWAY_CACHE_TTL_SECONDS: "300",
  // Well clear of the ~1.0 a pure re-ordering produces, and well clear of the
  // <0.5 a disjoint vocabulary produces, so neither assertion below is
  // balanced on a float.
  GATEWAY_CACHE_SEMANTIC_THRESHOLD: "0.9",
};

/** The prompt, and the SAME words in a different order — cosine ~1.0. */
const PROMPT = "summarize the quarterly revenue report for the board";
const PARAPHRASE = "for the board summarize the quarterly revenue report";
const UNRELATED = "translate this haiku into portuguese with furigana";

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

/**
 * The REAL composition root. Only the two STORES are swapped (isolate-local,
 * fixed clock), exactly as `test/cache/middleware.test.ts` does — the
 * middleware under test is the shipped `responseCache()`.
 */
function gateway(env: Record<string, string> = {}) {
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
    }),
  });
  const fullEnv = { ...SEMANTIC_ON, ...env };
  return {
    post: (key: string, prompt: string) =>
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

describe("the semantic layer is mounted on the app the Worker exports", () => {
  it("serves a PARAPHRASE without an upstream call — impossible for the exact layer", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const gw = gateway();

      const first = await gw.post("fg_a", PROMPT);
      expect(first.status).toBe(200);
      expect(first.headers.get(CACHE_STATUS_HEADER)).toBe("miss");
      expect(provider.requests).toHaveLength(1);

      // A DIFFERENT body — so a different exact key, which the exact store has
      // never seen. Only the similarity layer can answer this without
      // dispatching. Delete the semantic branch from the middleware and
      // `provider.requests` is 2 here.
      const second = await gw.post("fg_a", PARAPHRASE);
      expect(second.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
      expect(await second.json()).toEqual(completion("first"));
    } finally {
      provider.restore();
    }
  });

  it("CONTROL: an UNRELATED prompt in the same scope still dispatches", async () => {
    // Without this the test above would also pass for a cache that returns the
    // last response to everything.
    const provider = interceptProviderFetch((request) =>
      providerJson(completion(JSON.stringify(request.body).includes("haiku") ? "second" : "first")),
    );
    try {
      const gw = gateway();
      await gw.post("fg_a", PROMPT);
      const other = await gw.post("fg_a", UNRELATED);
      expect(provider.requests).toHaveLength(2);
      expect(await other.json()).toEqual(completion("second"));
    } finally {
      provider.restore();
    }
  });

  it("CONTROL: the same paraphrase in `exact_match` mode dispatches — the mode gate is real", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const gw = gateway({ GATEWAY_CACHE_MODE: "exact_match" });
      await gw.post("fg_a", PROMPT);
      await gw.post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("CONTROL: a threshold above what a paraphrase reaches dispatches", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      // 1.0 is in range and reachable only by a vector identical to the stored
      // one; an f32 round-trip of a re-ordered bag lands just under it.
      const gw = gateway({ GATEWAY_CACHE_SEMANTIC_THRESHOLD: "1.0" });
      await gw.post("fg_a", PROMPT);
      await gw.post("fg_a", `${PARAPHRASE} urgently`);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("ISOLATION: another tenant's identical prompt is NEVER served from the bucket", async () => {
    const provider = interceptProviderFetch((request) =>
      providerJson(
        completion(
          (request.headers.authorization ?? "").includes("b_upstream") ? "tenant-b" : "tenant-a",
        ),
      ),
    );
    try {
      const gw = gateway();
      const a = await gw.post("fg_a", PROMPT);
      expect(await a.json()).toEqual(completion("tenant-a"));

      // Same prompt, same model, different credential and tenant. The scope
      // bucket carries both, so this must dispatch. Drop `tenant_id` from
      // `semanticScopeMaterial` and this is a cross-tenant body disclosure.
      const b = await gw.post("fg_b", PROMPT);
      expect(provider.requests).toHaveLength(2);
      expect(b.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("counts a semantic hit in BOTH counters, as Rust does", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      resetResponseCacheMetrics();
      const gw = gateway();
      await gw.post("fg_a", PROMPT);
      await gw.post("fg_a", PARAPHRASE);
      const metrics = responseCacheMetrics();
      // `record_semantic_cache_hit` inside the lookup…
      expect(metrics.semanticCacheHitsTotal).toBe(1);
      // …and `record_ai_cache_hit` at the shared hit site, so the semantic
      // count is a SUBSET of the total and never larger than it.
      expect(metrics.cacheHitsTotal).toBe(1);
      expect(metrics.semanticCacheHitsTotal).toBeLessThanOrEqual(metrics.cacheHitsTotal);
      expect(metrics.cacheMissesTotal).toBe(1);
    } finally {
      resetResponseCacheMetrics();
      provider.restore();
    }
  });

  it("does not store a FAILED response for a later paraphrase to match", async () => {
    // Rust stores only `if final_status.is_success()`, and the semantic mirror
    // sits inside that branch. A 5xx that became a semantically-matched answer
    // would be the worst possible cache entry.
    const provider = interceptProviderFetch(
      () => new Response('{"error":{"message":"upstream boom"}}', { status: 500 }),
    );
    try {
      const gw = gateway();
      const first = await gw.post("fg_a", PROMPT);
      expect(first.status).toBeGreaterThanOrEqual(400);
      await gw.post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("stays inert when the cache is OFF, even in semantic mode", async () => {
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const gw = gateway({ GATEWAY_CACHE_ENABLED: "" });
      await gw.post("fg_a", PROMPT);
      await gw.post("fg_a", PARAPHRASE);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("the production default is the ISOLATE singleton, not a per-app store", async () => {
    // `responseCache()` with no options is what `src/routes/index.ts` mounts.
    // If the default were a fresh cache per middleware construction the layer
    // would never hit in production and every test above — which injects a
    // store — would still pass. So this asserts the DEFAULT specifically.
    resetSharedSemanticCache();
    const provider = interceptProviderFetch(() => providerJson(completion("first")));
    try {
      const build = () =>
        createGatewayApp({
          modules: [
            inferenceRouteModule({
              models: new InMemoryModelResolver(ALL_ROUTES),
              requestIds: fixedRequestIds,
            }),
          ],
        }).app;
      const post = (app: ReturnType<typeof build>, prompt: string) =>
        app.request(
          CHAT,
          {
            method: "POST",
            headers: { authorization: "Bearer fg_a", "content-type": "application/json" },
            body: JSON.stringify(chatBody(prompt)),
          },
          SEMANTIC_ON,
        );

      // Two SEPARATE apps, i.e. two separate `responseCache()` constructions —
      // the same isolate, which is what a Worker re-serving a request is.
      await post(build(), PROMPT);
      const second = await post(build(), PARAPHRASE);
      expect(second.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
    } finally {
      resetSharedSemanticCache();
      provider.restore();
    }
  });
});
