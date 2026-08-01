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
 * ## `semantic_hit` has a real producer now, and it is NOT a relabelled hit
 *
 * It read `semanticCacheHitsTotal: 0` unconditionally until `./semantic.ts`
 * landed, on a marker claiming the semantic layer needed Vectorize + Workers
 * AI. It does not (see that file). {@link recordSemanticCacheHit} is called
 * from exactly one place — the semantic branch of
 * `middleware/response-cache.ts`, reached only after the EXACT lookup has
 * already missed — so the counter can never be an exact-match hit wearing a
 * different label.
 *
 * Rust increments BOTH on a semantic hit: `lookup_semantic_response_cache`
 * calls `record_semantic_cache_hit`, and the caller in `chat.rs:485` then calls
 * `record_ai_cache_hit` for either kind of hit. So `cacheHitsTotal` is the
 * total served-from-cache count and `semanticCacheHitsTotal` is the subset of
 * it that came from the similarity layer — `semanticCacheHitsTotal` is never
 * larger, and `test/cache/semantic.test.ts` asserts that relationship rather
 * than the two numbers separately.
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
let semanticHits = 0;

/** Rust `AppState::record_ai_cache_hit`. Both kinds of hit reach it. */
export function recordCacheHit(): void {
  hits += 1;
}

/** Rust `AppState::record_ai_cache_miss`. */
export function recordCacheMiss(): void {
  misses += 1;
}

/**
 * Rust `AppState::record_semantic_cache_hit` (`state_routing.rs:367`), called
 * from inside `lookup_semantic_response_cache` on a similarity hit only.
 */
export function recordSemanticCacheHit(): void {
  semanticHits += 1;
}

/** This isolate's counters, in the shape the exporters render. */
export function responseCacheMetrics(): ResponseCacheMetrics {
  return {
    cacheHitsTotal: hits,
    cacheMissesTotal: misses,
    semanticCacheHitsTotal: semanticHits,
  };
}

/** Zero the counters. For tests that assert deltas. */
export function resetResponseCacheMetrics(): void {
  hits = 0;
  misses = 0;
  semanticHits = 0;
}
