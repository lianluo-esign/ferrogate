/**
 * Where a cached response actually lives.
 *
 * Rust held `AiResponseCache` in an `Arc<Mutex<_>>` inside `AppState` — a
 * process-global `HashMap` + `VecDeque` with a TTL and an LRU bound
 * (`state.rs:3345`, `insert`/`get` at `state.rs:3826-3868`). A Worker has no
 * process, so the two halves of that structure split apart on this platform:
 *
 *   - {@link CacheApiResponseStore} is the PRODUCTION store: the Cloudflare
 *     **Cache API**, which `docs/legacy/inventory-request-path.md` §1.8 names
 *     for exactly this ("Exact response cache → KV / Cache API"). It needs no
 *     binding — `caches.open()` is ambient — which is why the cache could be
 *     wired in this slice at all: `apps/gateway/wrangler.toml`'s NOT-DECLARED
 *     section still has no `[[kv_namespaces]] CACHE` entry, and this agent may
 *     not add one. It is shared by every isolate in a colo, so a second request
 *     hits even when it lands on a different isolate, which the Rust
 *     process-global also did and an isolate-local `Map` would NOT.
 *   - {@link MemoryResponseCacheStore} is the faithful port of the Rust data
 *     structure — TTL expiry on read, LRU eviction past `max_records`, and
 *     re-insertion moving a key to the back of the queue. It exists because
 *     those semantics have to be TESTABLE: the Cache API's expiry is the
 *     platform's and no test can fast-forward it, so a suite that only drove
 *     the Cache API would assert nothing about TTL or `max_records` and
 *     `cache.ttl_secs` / `cache.max_records` would be config with no proof.
 *     It is also the store the middleware falls back to where `caches` is
 *     absent.
 *
 * ## Why the Cache API needs a synthetic GET
 *
 * The Cache API keys on a `Request`, and only `GET` requests are cacheable —
 * the operations being cached here are all `POST` with a body. So the entry is
 * addressed by a synthetic `GET https://<CACHE_KEY_HOST>/<digest>`: the digest
 * from `./key.ts` IS the identity, and the real request never touches the
 * lookup. The host is a `.invalid` name (RFC 6761) so the URL can never be
 * resolved or fetched by anything.
 *
 * ## The entry is (status, content-type, body) and NOTHING else
 *
 * {@link CachedResponse} carries the same three fields as Rust's
 * `AiCachedResponse`, so no other upstream header can be replayed to a
 * different caller. That is a deliberate narrowing of the seam rather than a
 * filter to maintain: `Set-Cookie`, `Authorization`-echoing headers and
 * per-request rate-limit counters cannot leak through a struct that has no
 * field for them. `middleware/response-cache.ts` additionally refuses to STORE
 * a response that carries `set-cookie` or `cache-control: no-store` / `private`
 * at all, so such a response is never even reduced to an entry.
 */

/** A response as an entry: exactly Rust's `AiCachedResponse`. */
export interface CachedResponse {
  readonly statusCode: number;
  readonly contentType: string;
  readonly body: Uint8Array;
}

/** The seam the middleware talks to. */
export interface ResponseCacheStore {
  /** The entry for `key`, or `undefined` on a miss / expiry. */
  get(key: string): Promise<CachedResponse | undefined>;
  /** Store `response` under `key` for `ttlSeconds`. Never throws. */
  put(key: string, response: CachedResponse, ttlSeconds: number): Promise<void>;
}

/** `.invalid` per RFC 6761 — guaranteed never resolvable. */
export const CACHE_KEY_HOST = "ai-cache.ferrogate.invalid";
/** The Cache API namespace. Bump with {@link CACHE_KEY_VERSION} in `key.ts`. */
export const CACHE_NAMESPACE = "ferrogate-ai-response-v1";

/** The synthetic `GET` a digest is addressed by. */
export function cacheRequestFor(key: string): Request {
  return new Request(`https://${CACHE_KEY_HOST}/${encodeURIComponent(key)}`, { method: "GET" });
}

/**
 * The header the entry's original status is carried in.
 *
 * A `Response` put into the Cache API keeps its status, but only 200 is
 * guaranteed to round-trip unchanged across implementations, and a cached 201
 * that came back as 200 would silently rewrite the API's contract. Storing the
 * status explicitly and restoring from it makes the round-trip exact and
 * independent of that.
 */
export const CACHED_STATUS_HEADER = "x-ferrogate-cached-status";

/** The Cloudflare Cache API, as a {@link ResponseCacheStore}. */
export class CacheApiResponseStore implements ResponseCacheStore {
  readonly #namespace: string;
  #cache: Promise<Cache> | undefined;

  constructor(namespace: string = CACHE_NAMESPACE) {
    this.#namespace = namespace;
  }

  /** True when the platform exposes a Cache API at all. */
  static isAvailable(): boolean {
    return typeof caches !== "undefined" && typeof caches.open === "function";
  }

  #open(): Promise<Cache> {
    this.#cache ??= caches.open(this.#namespace);
    return this.#cache;
  }

  async get(key: string): Promise<CachedResponse | undefined> {
    let hit: Response | undefined;
    try {
      hit = await (await this.#open()).match(cacheRequestFor(key));
    } catch {
      // A cache read that fails is a MISS, never an error: the request must be
      // served from the upstream, not refused because an optimization broke.
      return undefined;
    }
    if (hit === undefined) return undefined;
    const declared = Number(hit.headers.get(CACHED_STATUS_HEADER));
    return {
      statusCode: Number.isSafeInteger(declared) && declared >= 100 ? declared : hit.status,
      contentType: hit.headers.get("content-type") ?? "application/json",
      body: new Uint8Array(await hit.arrayBuffer()),
    };
  }

  async put(key: string, response: CachedResponse, ttlSeconds: number): Promise<void> {
    if (ttlSeconds <= 0) return;
    try {
      const stored = new Response(response.body, {
        // 200 on the wire; the true status rides in the header above, so a
        // platform that only caches 200 still round-trips a 201 exactly.
        status: 200,
        headers: {
          "content-type": response.contentType,
          [CACHED_STATUS_HEADER]: String(response.statusCode),
          // The ONLY expiry signal the Cache API honours. `cache.ttl_secs`.
          "cache-control": `max-age=${ttlSeconds}`,
        },
      });
      await (await this.#open()).put(cacheRequestFor(key), stored);
    } catch {
      // Same posture as `get`: a write failure degrades to "not cached".
    }
  }
}

interface MemoryEntry {
  readonly response: CachedResponse;
  readonly expiresAtUnix: number;
}

/**
 * The Rust `AiResponseCache` structure, verbatim.
 *
 * `entries` + `order` reproduce `HashMap` + `VecDeque`: `get` drops an entry
 * whose `expires_at_unix <= now` (Rust's `<=`, not `<`), `insert` moves an
 * existing key to the back before re-inserting, and the eviction loop pops from
 * the front `while entries.len() > max_records`.
 */
export class MemoryResponseCacheStore implements ResponseCacheStore {
  readonly #entries = new Map<string, MemoryEntry>();
  readonly #order: string[] = [];
  readonly #maxRecords: number;
  readonly #now: () => number;

  constructor(options: { maxRecords?: number; now?: () => number } = {}) {
    this.#maxRecords = options.maxRecords ?? 1000;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Live entry count, for the LRU/TTL assertions. */
  get size(): number {
    return this.#entries.size;
  }

  get(key: string): Promise<CachedResponse | undefined> {
    const entry = this.#entries.get(key);
    if (entry === undefined) return Promise.resolve(undefined);
    if (entry.expiresAtUnix <= this.#now()) {
      this.#entries.delete(key);
      this.#removeFromOrder(key);
      return Promise.resolve(undefined);
    }
    return Promise.resolve(entry.response);
  }

  put(key: string, response: CachedResponse, ttlSeconds: number): Promise<void> {
    if (ttlSeconds <= 0) return Promise.resolve();
    if (this.#entries.has(key)) this.#removeFromOrder(key);
    this.#entries.set(key, { response, expiresAtUnix: this.#now() + ttlSeconds });
    this.#order.push(key);
    while (this.#entries.size > this.#maxRecords) {
      const oldest = this.#order.shift();
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    return Promise.resolve();
  }

  #removeFromOrder(key: string): void {
    const at = this.#order.indexOf(key);
    if (at >= 0) this.#order.splice(at, 1);
  }
}
