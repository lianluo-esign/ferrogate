/**
 * The two stores — `src/cache/store.ts`.
 *
 * `MemoryResponseCacheStore` is the faithful port of the Rust
 * `AiResponseCache` structure (`state.rs:3826-3868`), and it carries the TTL /
 * `max_records` proofs because the Cache API's expiry belongs to the platform
 * and no test can fast-forward it. `CacheApiResponseStore` carries the proof
 * that the PRODUCTION path — `caches.open()` in real `workerd` — round-trips a
 * body and a status exactly.
 */
import { describe, expect, it } from "vitest";
import {
  CACHED_STATUS_HEADER,
  CacheApiResponseStore,
  type CachedResponse,
  MemoryResponseCacheStore,
  cacheRequestFor,
} from "../../src/cache/store.js";

function entry(text: string, statusCode = 200): CachedResponse {
  return {
    statusCode,
    contentType: "application/json",
    body: new TextEncoder().encode(text),
  };
}

function decode(value: CachedResponse | undefined): string | undefined {
  return value === undefined ? undefined : new TextDecoder().decode(value.body);
}

describe("MemoryResponseCacheStore — Rust `AiResponseCache`", () => {
  it("round-trips an entry", async () => {
    const store = new MemoryResponseCacheStore({ now: () => 100 });
    await store.put("k", entry('{"a":1}'), 60);
    const hit = await store.get("k");
    expect(decode(hit)).toBe('{"a":1}');
    expect(hit?.statusCode).toBe(200);
    expect(hit?.contentType).toBe("application/json");
  });

  it("misses an unknown key", async () => {
    expect(await new MemoryResponseCacheStore().get("nope")).toBeUndefined();
  });

  it("expires at `expires_at_unix <= now` — Rust's `<=`, not `<`", async () => {
    let now = 100;
    const store = new MemoryResponseCacheStore({ now: () => now });
    await store.put("k", entry("v"), 10);
    now = 109;
    expect(decode(await store.get("k"))).toBe("v");
    // 100 + 10 == 110; Rust drops the entry when `expires_at <= now`, so the
    // boundary second is already a miss.
    now = 110;
    expect(await store.get("k")).toBeUndefined();
    // …and the expired entry is REMOVED, not merely hidden.
    expect(store.size).toBe(0);
  });

  it("never stores a non-positive ttl", async () => {
    const store = new MemoryResponseCacheStore({ now: () => 0 });
    await store.put("k", entry("v"), 0);
    expect(await store.get("k")).toBeUndefined();
  });

  it("evicts the OLDEST past max_records", async () => {
    const store = new MemoryResponseCacheStore({ maxRecords: 2, now: () => 0 });
    await store.put("a", entry("A"), 60);
    await store.put("b", entry("B"), 60);
    await store.put("c", entry("C"), 60);
    expect(store.size).toBe(2);
    expect(await store.get("a")).toBeUndefined();
    expect(decode(await store.get("b"))).toBe("B");
    expect(decode(await store.get("c"))).toBe("C");
  });

  it("re-inserting a key moves it to the BACK of the eviction queue", async () => {
    // Rust: `if self.entries.contains_key(&key) { self.order.retain(...) }`
    // before pushing. Without that, `order` grows a duplicate and the eviction
    // loop drops a LIVE key.
    const store = new MemoryResponseCacheStore({ maxRecords: 2, now: () => 0 });
    await store.put("a", entry("A"), 60);
    await store.put("b", entry("B"), 60);
    await store.put("a", entry("A2"), 60);
    await store.put("c", entry("C"), 60);
    expect(decode(await store.get("a"))).toBe("A2");
    expect(await store.get("b")).toBeUndefined();
    expect(decode(await store.get("c"))).toBe("C");
  });
});

describe("CacheApiResponseStore — the production store, in real workerd", () => {
  it("is available on this platform (no binding required)", () => {
    // The reason the cache could be wired in this slice at all: `caches.open()`
    // is ambient, while `[[kv_namespaces]] CACHE` is still undeclared in
    // `apps/gateway/wrangler.toml` and this agent may not add it.
    expect(CacheApiResponseStore.isAvailable()).toBe(true);
  });

  it("round-trips body, content-type and STATUS through `caches.open()`", async () => {
    const store = new CacheApiResponseStore("test-roundtrip");
    const key = `ai-cache:${crypto.randomUUID()}`;
    await store.put(key, { ...entry('{"ok":true}', 201), contentType: "application/json" }, 60);
    const hit = await store.get(key);
    expect(decode(hit)).toBe('{"ok":true}');
    // A 201 must come back as a 201. The Cache API is only guaranteed to
    // round-trip 200, so the true status rides in its own header.
    expect(hit?.statusCode).toBe(201);
    expect(hit?.contentType).toBe("application/json");
  });

  it("misses a key that was never stored", async () => {
    const store = new CacheApiResponseStore("test-miss");
    expect(await store.get(`ai-cache:${crypto.randomUUID()}`)).toBeUndefined();
  });

  it("keeps two namespaces apart", async () => {
    const key = `ai-cache:${crypto.randomUUID()}`;
    await new CacheApiResponseStore("test-ns-a").put(key, entry("A"), 60);
    expect(await new CacheApiResponseStore("test-ns-b").get(key)).toBeUndefined();
  });

  it("declines a non-positive ttl instead of caching forever", async () => {
    const store = new CacheApiResponseStore("test-ttl");
    const key = `ai-cache:${crypto.randomUUID()}`;
    await store.put(key, entry("V"), 0);
    expect(await store.get(key)).toBeUndefined();
  });

  it("writes a `max-age` matching cache.ttl_secs", async () => {
    const store = new CacheApiResponseStore("test-maxage");
    const key = `ai-cache:${crypto.randomUUID()}`;
    await store.put(key, entry("V"), 42);
    const raw = await (await caches.open("test-maxage")).match(cacheRequestFor(key));
    expect(raw?.headers.get("cache-control")).toContain("max-age=42");
    expect(raw?.headers.get(CACHED_STATUS_HEADER)).toBe("200");
  });
});

describe("cacheRequestFor", () => {
  it("addresses the entry by digest on an unresolvable `.invalid` host", () => {
    const request = cacheRequestFor("ai-cache:abc");
    // The Cache API only keys on GET; the real request is a POST with a body.
    expect(request.method).toBe("GET");
    expect(request.url).toContain("ai-cache.ferrogate.invalid");
    expect(request.url).toContain(encodeURIComponent("ai-cache:abc"));
  });

  it("gives two digests two different URLs", () => {
    expect(cacheRequestFor("a").url).not.toBe(cacheRequestFor("b").url);
  });
});
