/**
 * The producer for `ferrogate_ai_cache_requests_total`.
 *
 * `@ferrogate/observability` has rendered three cache counters since wave 2 —
 * `status="hit"`, `status="miss"`, `status="semantic_hit"`
 * (`packages/observability/src/prometheus.ts:250-256`, `otlp.ts:289-302`) — and
 * until this module existed **nothing anywhere incremented any of them**. All
 * three read 0 forever, which on a dashboard is indistinguishable from a cold
 * cache and is why the missing cache went unnoticed. This is the first real
 * importer of that package inside `apps/gateway`.
 *
 * The counters are typed against the package's own
 * {@link GatewayMetricsSnapshot} rather than a local shape, so a field rename
 * upstream breaks the build here instead of silently zeroing an export.
 *
 * ## `semantic_hit` is NEVER incremented, and that is the honest reading
 *
 * PORT-TODO(inventory-request-path §1.7 "Caches", issue #273): the semantic
 * layer is `SemanticResponseCache` — feature-hashed embeddings + a cosine
 * threshold — which maps to **Vectorize + Workers AI** on this platform
 * (inventory §1.8). Neither binding is declared for this Worker. Rather than
 * fake the counter by relabelling exact-match hits, {@link recordSemanticHit}
 * does not exist and {@link responseCacheMetrics} reports
 * `semanticCacheHitsTotal: 0` unconditionally. A 0 that is CORRECT is worth
 * more than a number that is wrong.
 *
 * ## Accumulation is isolate-local, and says so
 *
 * `prometheus.ts` already carries the PORT-TODO for this: a Worker has no
 * long-lived process to hold counters in, so a real `/metrics` surface must be
 * fed from a Durable Object or an Analytics Engine read. These counters are
 * therefore an isolate's own view, exported for tests and for whichever
 * aggregator lands. What the REQUEST path exposes instead is per-response and
 * exact: the `x-ferrogate-cache` header written by
 * `middleware/response-cache.ts`.
 */
import type { GatewayMetricsSnapshot } from "@ferrogate/observability";

/** The three fields of {@link GatewayMetricsSnapshot} this module owns. */
export type ResponseCacheMetrics = Pick<
  GatewayMetricsSnapshot,
  "cacheHitsTotal" | "cacheMissesTotal" | "semanticCacheHitsTotal"
>;

let hits = 0;
let misses = 0;

/** Rust `AppState::record_ai_cache_hit`. */
export function recordCacheHit(): void {
  hits += 1;
}

/** Rust `AppState::record_ai_cache_miss`. */
export function recordCacheMiss(): void {
  misses += 1;
}

/** This isolate's counters, in the shape the exporters render. */
export function responseCacheMetrics(): ResponseCacheMetrics {
  return {
    cacheHitsTotal: hits,
    cacheMissesTotal: misses,
    // See the header: no producer, and deliberately not faked.
    semanticCacheHitsTotal: 0,
  };
}

/** Zero the counters. For tests that assert deltas. */
export function resetResponseCacheMetrics(): void {
  hits = 0;
  misses = 0;
}
