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

// ---------------------------------------------------------------------------
// PER-TENANT totals — the hit rate a tenant can actually act on (#695)
// ---------------------------------------------------------------------------

/**
 * One governed scope's cache outcomes.
 *
 * The three deployment-wide counters above answer "is the cache working"; they
 * cannot answer "is it working FOR ME", which is the question a tenant tuning
 * their own similarity threshold is asking and the reason #695 lists hit-rate
 * telemetry beside the tunable. A single deployment number also hides the case
 * that matters most: one tenant's traffic being entirely uncacheable while the
 * aggregate looks healthy.
 */
export interface CacheTenantMetric {
  readonly tenant: string;
  readonly hits: number;
  readonly misses: number;
  readonly semanticHits: number;
  /** `hits / (hits + misses)`, or 0 when nothing has been observed. */
  readonly hitRatio: number;
}

interface TenantCounters {
  hits: number;
  misses: number;
  semanticHits: number;
}

/**
 * The cardinality bound, and why there is one at all.
 *
 * A Prometheus label whose value is a tenant id is unbounded by construction,
 * and an unbounded label set is how a metrics endpoint takes down the thing it
 * is monitoring. Issue #500's low-cardinality rule is the tree's standing
 * answer; this is that rule applied. Past the bound new tenants are folded into
 * {@link CACHE_TENANT_OVERFLOW} rather than dropped, so the deployment totals
 * derived from these series still add up — a silently dropped tenant would make
 * the per-tenant view disagree with the aggregate one, which is worse than a
 * coarse bucket.
 */
export const CACHE_TENANT_LABEL_LIMIT = 64;
export const CACHE_TENANT_OVERFLOW = "__other__";

/** Credentials with no tenancy (a static operator key) share one label. */
export const CACHE_TENANT_UNSCOPED = "__unscoped__";

const tenantCounters = new Map<string, TenantCounters>();

function countersFor(tenant: string | null | undefined): TenantCounters {
  const label =
    tenant === null || tenant === undefined || tenant === "" ? CACHE_TENANT_UNSCOPED : tenant;
  const existing = tenantCounters.get(label);
  if (existing !== undefined) return existing;
  const key = tenantCounters.size >= CACHE_TENANT_LABEL_LIMIT ? CACHE_TENANT_OVERFLOW : label;
  const created = tenantCounters.get(key) ?? { hits: 0, misses: 0, semanticHits: 0 };
  tenantCounters.set(key, created);
  return created;
}

/**
 * Rust `AppState::record_ai_cache_hit`. Both kinds of hit reach it.
 *
 * `tenant` is optional so the deployment-wide counters keep their pre-#695
 * call shape; the middleware always passes the AUTHENTICATED tenancy, never
 * anything a client asserted.
 */
export function recordCacheHit(tenant?: string | null): void {
  hits += 1;
  countersFor(tenant).hits += 1;
}

/** Rust `AppState::record_ai_cache_miss`. */
export function recordCacheMiss(tenant?: string | null): void {
  misses += 1;
  countersFor(tenant).misses += 1;
}

/**
 * Rust `AppState::record_semantic_cache_hit` (`state_routing.rs:367`), called
 * from inside `lookup_semantic_response_cache` on a similarity hit only.
 */
export function recordSemanticCacheHit(tenant?: string | null): void {
  semanticHits += 1;
  countersFor(tenant).semanticHits += 1;
}

/** Per-tenant totals, sorted so the exposition is stable across scrapes. */
export function responseCacheTenantMetrics(): readonly CacheTenantMetric[] {
  return [...tenantCounters.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([tenant, counters]) => {
      const looked = counters.hits + counters.misses;
      return {
        tenant,
        hits: counters.hits,
        misses: counters.misses,
        semanticHits: counters.semanticHits,
        // 0 rather than NaN for an untouched tenant: NaN renders as `NaN` in
        // the Prometheus text format and poisons every aggregation over it.
        hitRatio: looked === 0 ? 0 : counters.hits / looked,
      };
    });
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
  tenantCounters.clear();
}
