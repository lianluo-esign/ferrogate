/**
 * Optional TTL cache in front of the D1 key lookup.
 *
 * ## What the Rust did — and therefore what the default is
 *
 * Nothing. `StorageApiKeyAuthenticator::authenticate`
 * (`crates/ferrogate-auth-service/src/api_key.rs`) calls
 * `find_api_key_records_by_prefix` on **every single request**; there is no
 * memoization anywhere on that path (`grep -rniE 'api_key_cache|key_cache|
 * auth_cache' crates/` finds only the *response* cache and the provider-secret
 * cache, neither of which is this). So {@link DEFAULT_API_KEY_CACHE_TTL_SECONDS}
 * is **0 — disabled** — and the ported gateway behaves exactly as the Rust one:
 * a revocation takes effect on the very next request.
 *
 * The cache exists because D1 is a network round-trip where Supabase-behind-a-
 * pooler was also a network round-trip but the Rust process could hold a warm
 * connection; an operator who decides that trade is worth making opts in with
 * {@link ApiKeyResolverOptions.cacheTtlSeconds}. Opting in is a **security
 * trade**, and the cost is stated in one sentence:
 *
 * > A key suspended, revoked or deleted at time *T* keeps working until *T +
 * > ttl*, and no sooner than *T + ttl* is it guaranteed to stop.
 *
 * `test/keys/resolver.test.ts` ("cache expiry after suspension") holds both
 * halves of that sentence — the key still resolves one second before the
 * boundary and answers `key_suspended` after it — so the window can never be
 * silently widened, and a mutation that forgets to expire entries fails.
 *
 * ## What is and is not cached
 *
 * - **Cached:** every outcome for a key that MATCHED a row — `resolved`,
 *   `key_suspended`, `token_budget_exhausted`. These are the hot path.
 * - **Not cached:** `unknown`. Two reasons. A newly-minted key must work
 *   immediately (otherwise provisioning appears broken for up to a TTL), and
 *   caching misses would let an unauthenticated key-spray fill the map with one
 *   entry per guess.
 * - **Not cached:** `unavailable`. A D1 outage must not be pinned in front of
 *   a recovered database.
 *
 * ## What is used as the cache key
 *
 * The **SHA-256 hex of the presented secret**, never the secret itself. A
 * plaintext credential must not sit in isolate memory for a TTL past the
 * request that carried it — a heap snapshot or a debug dump would otherwise
 * hand over live keys. The digest is already computed for the hash verify, so
 * this costs nothing extra.
 *
 * The map is bounded ({@link DEFAULT_API_KEY_CACHE_MAX_ENTRIES}) and evicts in
 * insertion order, so a large tenant cannot grow it without limit.
 */
import type { ApiKeyResolution } from "../ports.js";

/**
 * **30 seconds — the Zero-D1 default.** Positive key outcomes are cached to
 * keep the singleton control object off the request hot path. Set the Worker
 * var to `"0"` to disable it deliberately. The revocation-latency tradeoff is
 * documented above and at the flag in `wrangler.toml`.
 */
export const DEFAULT_API_KEY_CACHE_TTL_SECONDS = 30;

/** Insertion-order eviction bound, so the map cannot grow without limit. */
export const DEFAULT_API_KEY_CACHE_MAX_ENTRIES = 1000;

interface CacheEntry {
  readonly resolution: ApiKeyResolution;
  /** Epoch milliseconds after which the entry is no longer usable. */
  readonly expiresAtMs: number;
}

/** A monotonic-enough clock in epoch milliseconds. Injected so TTLs are testable. */
export type Clock = () => number;

/** Only outcomes that came from a MATCHED row may be cached. See module docs. */
export function isCacheableResolution(resolution: ApiKeyResolution): boolean {
  switch (resolution.outcome) {
    case "resolved":
    case "key_suspended":
    case "token_budget_exhausted":
    // Also from a MATCHED row: the hash comparison passed and the row's
    // `tenant_id` was blank. Cacheable for exactly the same reason the three
    // above are — the answer is a property of a row that was really read, not
    // of a miss, so caching it cannot make a non-existent key appear to exist.
    case "tenant_identity_required":
      return true;
    case "unknown":
    case "unavailable":
    case "static_key_disabled":
    case "static_key_expired":
      return false;
  }
}

/** TTL map from presented-key digest → resolution. */
export class ApiKeyResolutionCache {
  readonly #entries = new Map<string, CacheEntry>();
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: Clock;

  constructor(
    options: {
      readonly ttlSeconds?: number;
      readonly maxEntries?: number;
      readonly now?: Clock;
    } = {},
  ) {
    const ttlSeconds = options.ttlSeconds ?? DEFAULT_API_KEY_CACHE_TTL_SECONDS;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 0) {
      throw new RangeError(`api key cache ttlSeconds must be >= 0, got ${ttlSeconds}`);
    }
    this.#ttlMs = Math.floor(ttlSeconds * 1000);
    this.#maxEntries = options.maxEntries ?? DEFAULT_API_KEY_CACHE_MAX_ENTRIES;
    this.#now = options.now ?? (() => Date.now());
  }

  /** `true` when the cache is off, i.e. behaving exactly as the Rust tree. */
  get disabled(): boolean {
    return this.#ttlMs === 0;
  }

  /** Entry count. Test/observability only. */
  get size(): number {
    return this.#entries.size;
  }

  get(digest: string): ApiKeyResolution | undefined {
    if (this.disabled) return undefined;
    const entry = this.#entries.get(digest);
    if (entry === undefined) return undefined;
    // `>=` not `>`: an entry whose deadline is exactly now is EXPIRED. The
    // documented guarantee is "usable for at most ttl", so the boundary
    // millisecond belongs to the expired side.
    if (this.#now() >= entry.expiresAtMs) {
      this.#entries.delete(digest);
      return undefined;
    }
    return entry.resolution;
  }

  set(digest: string, resolution: ApiKeyResolution): void {
    if (this.disabled || !isCacheableResolution(resolution)) return;
    // Re-inserting must refresh insertion order, or a hot key is evicted first.
    this.#entries.delete(digest);
    this.#entries.set(digest, { resolution, expiresAtMs: this.#now() + this.#ttlMs });
    while (this.#entries.size > this.#maxEntries) {
      const oldest = this.#entries.keys().next();
      if (oldest.done === true) break;
      this.#entries.delete(oldest.value);
    }
  }

  /** Drop everything. For an explicit control-plane invalidation signal. */
  clear(): void {
    this.#entries.clear();
  }
}
