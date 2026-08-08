/**
 * `RoutingStrategy` — the ORDER the failover ladder walks its eligible
 * candidates in.
 *
 * Port of `state_routing.rs:517-598` (`candidate_model_routes`'s four match
 * arms) plus the six free functions in `state.rs` they call:
 *
 * | this module                          | Rust                                          |
 * |--------------------------------------|-----------------------------------------------|
 * | {@link orderCandidatesByStrategy}    | `candidate_model_routes` match arms           |
 * | {@link totalWeight}                  | `state.rs:6866 total_weight`                  |
 * | {@link weightedStartIndex}           | `state.rs:6853 weighted_start_index`          |
 * | {@link priorityGroupEnd}             | `state.rs:6844 fallback_priority_group`       |
 * | {@link routeEstimatedCost}           | `state.rs:6925 route_estimated_cost`          |
 * | {@link routeEstimatedUnitCost}       | `state.rs:7009 route_estimated_unit_cost`     |
 * | {@link providerHealthRank}           | `state.rs:6974 provider_health_rank_from_signals` |
 * | {@link latencyRank}                  | `state.rs:6997 latency_rank`                  |
 * | {@link balancedRouteScore}           | `state.rs:7001 balanced_route_score`          |
 * | {@link ProviderRoutingMetrics}       | `state.rs:3351 ProviderRoutingMetrics`        |
 *
 * This is the second half of the parity audit's **F6**. The first half — the
 * `priority`→`weight` total order — has been in `candidates.ts::orderCandidates`
 * since the ladder landed; what was missing was that the ladder had exactly ONE
 * order, so `routing_strategy` was a value `@ferrogate/providers` declared and
 * nothing in the data plane could ever read.
 *
 * ## Pricing is not re-derived here
 *
 * `routeEstimatedCost` calls `@ferrogate/billing`'s `modelPriceUsd` +
 * `estimateCost`, which are the port of `ModelPrice::usd` / `ModelPrice::estimate`
 * the Rust `route_estimated_cost` itself calls. Re-implementing the division by
 * 1e6 here would be a second definition of the price of a token — the thing the
 * billing package exists to be the only copy of.
 *
 * ## The two approximations, both named and both bounded
 *
 * 1. **The round-robin cursor** ({@link nextRoutingCursor}) is per-ISOLATE, where
 *    Rust's `model_route_counter` is per-PROCESS. That is the same relationship a
 *    Workers isolate has to a Rust process for every unshared counter in this
 *    tree, and here it is harmless in a way the circuit breaker's is not: the
 *    cursor only chooses a STARTING OFFSET inside one priority group, so a
 *    per-isolate cursor spreads load across the group in the configured weight
 *    proportions independently on each isolate, which is the same distribution.
 *    Nothing about correctness or spend depends on two isolates agreeing.
 * 2. **The latency/failure observations** ({@link ProviderRoutingMetrics}) are
 *    per-isolate for the same reason (Rust holds them in an
 *    `Arc<Mutex<ProviderRoutingMetrics>>` inside one process). An isolate
 *    therefore steers on what IT has seen. The error direction is "slower to
 *    react", never "reacts wrongly": an isolate with no observations scores every
 *    provider identically and falls through to the priority→weight order, i.e.
 *    exactly the pre-strategy behavior.
 *
 * Neither approximation can make a route ELIGIBLE that eligibility refused —
 * every arm here is a permutation of the list `candidates.ts::eligibleCandidates`
 * already approved (`model_routing.rs` runs "before any strategy reads price or
 * health", and this module is that strategy).
 */
import { estimateCost, modelPriceUsd } from "@ferrogate/billing";
import type { EstimatedUsage } from "./estimate.js";
import type { PhysicalRoute } from "./ports.js";

// ---------------------------------------------------------------------------
// The strategy vocabulary
// ---------------------------------------------------------------------------

/**
 * `ferrogate_providers::RoutingStrategy`, in the snake_case serde form the
 * Rust config table uses.
 */
export const ROUTING_STRATEGIES = [
  "priority",
  "lowest_cost",
  "lowest_latency",
  "balanced",
] as const;

export type RoutingStrategy = (typeof ROUTING_STRATEGIES)[number];

/** `RoutingStrategy::default()` — `Priority` (`models.rs:170`). */
export const DEFAULT_ROUTING_STRATEGY: RoutingStrategy = "priority";

// ---------------------------------------------------------------------------
// Observations — `ProviderRoutingMetrics`
// ---------------------------------------------------------------------------

/** `ProviderRoutingScore` (`state.rs:3411`). */
export interface ProviderRoutingScore {
  /** `checked_div` — `undefined` when a provider has no SUCCESSFUL request yet. */
  readonly averageLatencyMs: number | undefined;
  readonly failureRate: number;
  readonly observedRequests: number;
}

/** `ProviderRoutingScore::default()` — what an unobserved provider scores. */
export const NO_ROUTING_OBSERVATIONS: ProviderRoutingScore = {
  averageLatencyMs: undefined,
  failureRate: 0,
  observedRequests: 0,
};

/**
 * The seam `handlers.ts::dispatchCandidates` feeds and the two health-aware
 * strategies read.
 *
 * Split out as an interface so a test can inject a pre-loaded set of
 * observations without having to drive real dispatches, AND so the recording
 * side is a dependency rather than a module-global the handler reaches into —
 * a module-global here would be indistinguishable from an unwired one.
 */
export interface RoutingMetrics {
  /** `record_request_log`'s success arm: counts the request and its latency. */
  recordSuccess(provider: string, latencyMs: number): void;
  /**
   * `record_request_log`'s failure arm — `status_code >= 400 || error_code`.
   * Rust deliberately does NOT add latency for a failed request, so a provider
   * that fails fast does not look fast.
   */
  recordFailure(provider: string): void;
  /** `ProviderRoutingMetrics::score` — `default()` for an unknown provider. */
  score(provider: string): ProviderRoutingScore;
}

interface ProviderRoutingMetric {
  successfulRequests: number;
  failedRequests: number;
  totalLatencyMs: number;
}

/**
 * Per-isolate {@link RoutingMetrics} — see approximation 2 in the module docs.
 *
 * Deliberately unbounded in neither time nor size: the key set is the operator's
 * OWN provider table (a handful of names from `GATEWAY_PROVIDERS`), not anything
 * a client can influence, so there is no growth a request can drive. Rust's map
 * is keyed the same way and is equally unbounded.
 */
export class ProviderRoutingMetrics implements RoutingMetrics {
  readonly #providers = new Map<string, ProviderRoutingMetric>();

  #metric(provider: string): ProviderRoutingMetric {
    const existing = this.#providers.get(provider);
    if (existing !== undefined) {
      return existing;
    }
    const created: ProviderRoutingMetric = {
      successfulRequests: 0,
      failedRequests: 0,
      totalLatencyMs: 0,
    };
    this.#providers.set(provider, created);
    return created;
  }

  recordSuccess(provider: string, latencyMs: number): void {
    const metric = this.#metric(provider);
    metric.successfulRequests += 1;
    // Rust `saturating_add` on a u64; a negative clock delta is impossible in
    // Rust and merely nonsensical here, so it is floored rather than trusted.
    metric.totalLatencyMs += Math.max(0, Math.round(latencyMs));
  }

  recordFailure(provider: string): void {
    this.#metric(provider).failedRequests += 1;
  }

  score(provider: string): ProviderRoutingScore {
    const metric = this.#providers.get(provider);
    if (metric === undefined) {
      return NO_ROUTING_OBSERVATIONS;
    }
    const total = metric.successfulRequests + metric.failedRequests;
    return {
      // `checked_div`: no successes ⇒ no average, NOT an average of zero.
      averageLatencyMs:
        metric.successfulRequests === 0
          ? undefined
          : Math.floor(metric.totalLatencyMs / metric.successfulRequests),
      failureRate: total === 0 ? 0 : metric.failedRequests / total,
      observedRequests: total,
    };
  }
}

/** A {@link RoutingMetrics} that observes nothing — the injected-test default. */
export const NO_ROUTING_METRICS: RoutingMetrics = {
  recordSuccess(): void {
    /* not observing */
  },
  recordFailure(): void {
    /* not observing */
  },
  score(): ProviderRoutingScore {
    return NO_ROUTING_OBSERVATIONS;
  },
};

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/**
 * `route_estimated_unit_cost` — the price of the route with no usage to size it.
 *
 * The `None`/`None` arm is `f64::INFINITY` on purpose and it is the whole
 * fail-closed shape of `LowestCost`: an unpriced route is not free, it is
 * *unknown*, and sorting it last means an operator who prices only some of the
 * ladder still gets the priced ones first instead of having the unpriced one win.
 */
export function routeEstimatedUnitCost(route: PhysicalRoute): number {
  const input = route.inputPricePer1m;
  const output = route.outputPricePer1m;
  if (input !== undefined && output !== undefined) {
    return input + output;
  }
  if (input !== undefined) {
    return input;
  }
  if (output !== undefined) {
    return output;
  }
  return Number.POSITIVE_INFINITY;
}

/**
 * `route_estimated_cost` — the pre-dispatch estimate priced at this route's
 * rates, falling back to the unit cost when there is no estimate or the route
 * is only half-priced.
 */
export function routeEstimatedCost(
  route: PhysicalRoute,
  usage: EstimatedUsage | undefined,
): number {
  if (usage === undefined) {
    return routeEstimatedUnitCost(route);
  }
  const input = route.inputPricePer1m;
  const output = route.outputPricePer1m;
  if (input === undefined || output === undefined) {
    return routeEstimatedUnitCost(route);
  }
  return estimateCost(modelPriceUsd(input, output), {
    prompt_tokens: usage.promptTokens,
    completion_tokens: usage.completionTokens,
    total_tokens: usage.totalTokens,
  }).total_cost;
}

/**
 * `provider_health_rank_from_signals` — 0 healthy, 1 observed-unhealthy,
 * 2 circuit-open. Lower sorts first.
 *
 * ## The circuit leg, and why it is not read here
 *
 * Rust's `provider_health_rank` folds in `state.provider_circuit_allows(provider)`
 * and ranks an open provider LAST but still in the list. This port takes
 * `circuitAllows` as an argument and every caller in the data plane passes
 * `true`, because on this platform the circuit is consulted one layer down and
 * more strictly: `reliability.ts::dispatchWithFailover` calls
 * `await circuit.allows(provider)` per candidate and SKIPS an open one entirely
 * (`chat.rs:283`, ported whole). So the open-circuit provider is not merely
 * ranked last, it is not attempted at all — strictly stronger than rank 2, and
 * unreachable from an ordering function because `ProviderCircuit.allows` is
 * `async` (it may be a Durable Object hop) while ordering is pure and sync.
 *
 * The parameter is kept rather than dropped so this stays a faithful, testable
 * port of the Rust predicate, and so a future synchronous circuit snapshot has
 * somewhere to land without changing the ranking rule.
 */
export function providerHealthRank(circuitAllows: boolean, score: ProviderRoutingScore): 0 | 1 | 2 {
  if (!circuitAllows) {
    return 2;
  }
  if (score.observedRequests >= 3 && score.failureRate >= 0.5) {
    return 1;
  }
  return 0;
}

/**
 * `latency_rank` — `u64::MAX` for a provider with no successful observation, so
 * an unmeasured provider sorts BEHIND every measured one.
 */
export function latencyRank(score: ProviderRoutingScore): number {
  return score.averageLatencyMs ?? Number.MAX_SAFE_INTEGER;
}

/**
 * `balanced_route_score` — `cost + latency_seconds + failure_rate * 10`.
 *
 * The three magic constants are Rust's and are reproduced exactly: an unpriced
 * route scores `1_000` (not infinity — `Balanced` is meant to keep using an
 * unpriced route, unlike `LowestCost`), an unmeasured provider scores `1_000` ms
 * i.e. one second, and the failure rate is weighted ten-fold so a provider
 * failing half its requests carries +5, which dominates any realistic latency
 * term.
 */
export function balancedRouteScore(route: PhysicalRoute, score: ProviderRoutingScore): number {
  const input = route.inputPricePer1m;
  const output = route.outputPricePer1m;
  const cost = input !== undefined && output !== undefined ? input + output : 1_000;
  const latency = (score.averageLatencyMs ?? 1_000) / 1_000;
  return cost + latency + score.failureRate * 10;
}

// ---------------------------------------------------------------------------
// Weighted round-robin — the `Priority` arm
// ---------------------------------------------------------------------------

/** `total_weight` — `weight.max(1)` summed, itself floored at 1. */
export function totalWeight(routes: readonly PhysicalRoute[]): number {
  const sum = routes.reduce(
    (accumulated, route) => accumulated + Math.max(1, route.weight ?? 0),
    0,
  );
  return Math.max(1, sum);
}

/**
 * `weighted_start_index` — walk the group consuming `weight.max(1)` units of the
 * cursor and start at whichever route the cursor lands inside.
 *
 * This is what makes `weight` SPREAD rather than merely ORDER: a group of
 * `{a: 3, b: 1}` puts `a` first for cursors 0,1,2 and `b` first for cursor 3, so
 * over a cycle `a` leads 3 requests out of 4. `orderCandidates` alone would put
 * `a` first every single time and `b` would only ever be reached by failover.
 */
export function weightedStartIndex(routes: readonly PhysicalRoute[], cursor: number): number {
  const total = totalWeight(routes);
  let remaining = cursor % total;
  for (const [index, route] of routes.entries()) {
    const weight = Math.max(1, route.weight ?? 0);
    if (remaining < weight) {
      return index;
    }
    remaining -= weight;
  }
  return 0;
}

/**
 * `fallback_priority_group` — the length of the leading run of equal priority.
 *
 * Returns `0` for an empty list, which is the `None` arm of the Rust `Option`.
 * Contiguity is what makes this correct, and it holds because the list handed in
 * has already been through `candidates.ts::orderCandidates` (priority ASCENDING
 * is its first key), exactly as Rust's fallbacks arrive priority-ordered.
 */
export function priorityGroupEnd(routes: readonly PhysicalRoute[]): number {
  const first = routes[0];
  if (first === undefined) {
    return 0;
  }
  const priority = first.priority ?? 0;
  const end = routes.findIndex((route) => (route.priority ?? 0) !== priority);
  return end === -1 ? routes.length : end;
}

/**
 * The per-isolate `model_route_counter` (approximation 1 in the module docs).
 *
 * `Number.MAX_SAFE_INTEGER` is the wrap point rather than `u64::MAX`; both are
 * unreachable, and wrapping to 0 is the same `fetch_add` semantics.
 */
let routingCursor = 0;

/** `model_route_counter.fetch_add(1, Relaxed)` — returns the PREVIOUS value. */
export function nextRoutingCursor(): number {
  const current = routingCursor;
  routingCursor = current >= Number.MAX_SAFE_INTEGER ? 0 : current + 1;
  return current;
}

/**
 * The `RoutingStrategy::Priority` arm.
 *
 * Rust pins the primary route at the head and rotates only the fallback groups.
 * This port rotates every priority group including the first, and the two agree
 * for every configuration Rust can express, because `model_registry_entry`
 * builds the primary with `priority = 0, weight = 1` (`ModelRoute::new`) and each
 * fallback with `priority.unwrap_or(100)` — so the primary is alone in priority
 * group 0 and `weightedStartIndex` over a one-route group is always `0`.
 * `catalog.ts` reproduces those two defaults for exactly this reason.
 *
 * Where they differ is a configuration Rust CANNOT express and this tree can: an
 * operator who explicitly gives a fallback the primary's priority has asked for
 * the two to share a group, and rotating the shared group is the only reading of
 * `weight` that is not a silent no-op.
 */
function orderByPriorityRotation(
  routes: readonly PhysicalRoute[],
  cursor: number,
): readonly PhysicalRoute[] {
  const ordered: PhysicalRoute[] = [];
  let rest = routes;
  let remainingCursor = cursor;
  while (rest.length > 0) {
    const end = priorityGroupEnd(rest);
    const group = rest.slice(0, end);
    const start = weightedStartIndex(group, remainingCursor);
    ordered.push(...group.slice(start), ...group.slice(0, start));
    // Rust `cursor /= total_weight(group)` — each group consumes its own digit
    // of the cursor, so two groups do not rotate in lockstep.
    remainingCursor = Math.floor(remainingCursor / totalWeight(group));
    rest = rest.slice(end);
  }
  return ordered;
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

/** Everything the four arms read that they do not get from the route itself. */
export interface StrategyContext {
  /** The pre-dispatch estimate, sizing `LowestCost`. Absent ⇒ unit cost. */
  readonly estimatedUsage?: EstimatedUsage | undefined;
  /** Observations backing `LowestLatency` / `Balanced`. */
  readonly metrics?: RoutingMetrics | undefined;
  /** `model_route_counter.fetch_add` — injected so a test is deterministic. */
  readonly cursor?: number | undefined;
  /**
   * #894 — the ladder's per-leg online-eval verdicts, ALREADY RESOLVED.
   *
   * `undefined` for every request until an isolate has warmed the memo, and for
   * every tenant that never opted into online evaluation, which is the ordering
   * this function had before #894.
   */
  readonly quality?: RoutingQuality | undefined;
}

// ---------------------------------------------------------------------------
// #894 — the quality input, and why it is shaped as a resolved predicate
// ---------------------------------------------------------------------------

/**
 * One ladder's quality verdicts, as a SYNCHRONOUS predicate.
 *
 * The implementation lives in `src/evals/quality-source.ts`; only this
 * inference-owned interface is declared here, the same way
 * {@link RoutingMetrics} is a port rather than an import of a metrics store.
 * The evaluation slice may know about inference; inference may not know about
 * the evaluation slice (`./identity.ts` states the rule for #693's leg
 * publisher and it holds for this too).
 *
 * `lags` is "this leg's mean is at least the tenant's `regressionDrop` below the
 * BEST leg of the same ladder, under the same judge and criterion, with the
 * tenant's `regressionMinSamples` on both sides". It is never an absolute floor
 * — `src/evals/policy.ts:20-46` on why an absolute quality number is meaningless
 * — and an unmeasured leg answers `false`, i.e. "no reason to demote it", never
 * "it is good".
 */
export interface RoutingQuality {
  lags(route: PhysicalRoute): boolean;
  /**
   * #699 — the tenant's COST/QUALITY DIAL, read off the same governance row the
   * `lags` predicate's thresholds come from. Absent or `false` is OFF, which is
   * the default and the pre-#699 behaviour: the router demotes lagging legs
   * (#894, a permutation) but never FILTERS one and never overrides the
   * operator's strategy with cost. It is carried HERE, on the resolved quality
   * snapshot, rather than fetched separately, because the router already peeks
   * this object synchronously and a second lookup would be a second seam that
   * could disagree with the first about whether the tenant opted in.
   *
   * `orderCandidatesByStrategy` deliberately IGNORES this field — it stays a
   * pure permutation. Only `handlers.ts::planUpstream`, which may filter, reads
   * it (via {@link applyCostQualityDial}).
   */
  readonly costQualityRouting?: boolean;
}

/**
 * The per-request resolver `handlers.ts` holds in `deps`.
 *
 * Returns `undefined` — not an empty {@link RoutingQuality} — when the memo is
 * cold, so "we have no snapshot" and "the snapshot demotes nothing" stay
 * distinguishable at the one place a test can assert them apart.
 *
 * MUST NOT do I/O: it is called from `planUpstream`, which is synchronous.
 */
export interface RoutingQualityPort {
  ladderQuality(tenantId: string, logicalModel: string): RoutingQuality | undefined;
}

/** The port a deployment with no evaluation storage gets. */
export const NO_ROUTING_QUALITY: RoutingQualityPort = {
  ladderQuality(): undefined {
    return undefined;
  },
};

/**
 * Move every lagging leg behind every non-lagging one, preserving the strategy's
 * own order inside each part.
 *
 * A PERMUTATION, never a filter — the same invariant the four arms hold, and the
 * reason it matters more here than there: a judge score is a noisy proxy
 * (`src/evals/policy.ts`), so it may reorder a ladder and must never be able to
 * remove the leg that would have served the request. A ladder whose legs ALL
 * lag is returned untouched: "everything is behind everything" is not an
 * ordering, and demoting the whole list would only cost the sort.
 *
 * ## The CANARY is exempt, and that is not a loophole
 *
 * `candidates.ts::applyCanary` puts the canary at the HEAD of the list for the
 * sticky subset of callers it selected, and that head position survives
 * `orderByPriorityRotation` because the canary is alone in its priority group.
 * A quality partition with no exemption would move it straight to the tail for
 * every one of those callers, so an operator-declared `canary_percent = 10`
 * would silently divert 0% — and it could not recover, because a leg that stops
 * being served stops accumulating scores. Worse, the thing the operator is
 * running the canary to FIND OUT is exactly whether the new route is worse; a
 * router that answers the question by cancelling the experiment has destroyed
 * the evidence rather than acted on it.
 *
 * So a route carrying `canaryPercent` keeps whatever position the strategy gave
 * it. The signal is not discarded — the leg aggregate still records it and
 * `evals/regression.ts` still alerts on it — it just does not get to turn an
 * operator's declared rollout off without the operator.
 */
function demoteLaggingLegs(
  ordered: readonly PhysicalRoute[],
  quality: RoutingQuality | undefined,
): readonly PhysicalRoute[] {
  if (quality === undefined) return ordered;
  const lagging: PhysicalRoute[] = [];
  const kept: PhysicalRoute[] = [];
  for (const route of ordered) {
    if (route.canaryPercent === undefined && quality.lags(route)) lagging.push(route);
    else kept.push(route);
  }
  if (lagging.length === 0 || kept.length === 0) return ordered;
  return [...kept, ...lagging];
}

/** The tail every Rust arm shares: priority ASC, weight DESC, then a total order. */
function tiebreak(left: PhysicalRoute, right: PhysicalRoute): number {
  const priority = (left.priority ?? 0) - (right.priority ?? 0);
  if (priority !== 0) {
    return priority;
  }
  const weight = (right.weight ?? 0) - (left.weight ?? 0);
  if (weight !== 0) {
    return weight;
  }
  const provider = left.provider.localeCompare(right.provider);
  return provider !== 0 ? provider : left.providerModel.localeCompare(right.providerModel);
}

/** Rust's `partial_cmp(...).unwrap_or(Ordering::Equal)` over two `f64`s. */
function compareScores(left: number, right: number): number {
  if (Number.isNaN(left) || Number.isNaN(right)) {
    return 0;
  }
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

/**
 * `candidate_model_routes`'s four match arms, over an ALREADY-ELIGIBLE,
 * already-`orderCandidates`-ordered list.
 *
 * Never filters — every arm returns a permutation of its input, so a strategy
 * cannot drop a route that eligibility approved, and the failover ladder still
 * reaches every candidate. That is Rust's shape too (`decision.eligible_routes`
 * is re-appended whole) and it is what keeps `lowest_cost` from becoming a
 * single-route gateway when a price is missing.
 */
export function orderCandidatesByStrategy(
  routes: readonly PhysicalRoute[],
  strategy: RoutingStrategy,
  context: StrategyContext = {},
): readonly PhysicalRoute[] {
  if (routes.length < 2) {
    return routes;
  }
  const metrics = context.metrics ?? NO_ROUTING_METRICS;
  // #894 — applied to whatever the arm produced, not folded into each arm's
  // comparator. Quality is a different KIND of input from cost and latency: it
  // is a sampled, judge-derived proxy with a minimum-sample gate, so it can only
  // ever say "this leg is measurably worse than a sibling", never "this leg
  // ranks 0.13 better". A last-pass partition expresses exactly that and leaves
  // all four arms' Rust-derived comparators byte-identical.
  return demoteLaggingLegs(orderByStrategyArm(routes, strategy, context, metrics), context.quality);
}

function orderByStrategyArm(
  routes: readonly PhysicalRoute[],
  strategy: RoutingStrategy,
  context: StrategyContext,
  metrics: RoutingMetrics,
): readonly PhysicalRoute[] {
  switch (strategy) {
    case "priority":
      return orderByPriorityRotation(routes, context.cursor ?? nextRoutingCursor());

    case "lowest_cost": {
      const cost = new Map<PhysicalRoute, number>(
        routes.map((route) => [route, routeEstimatedCost(route, context.estimatedUsage)]),
      );
      return [...routes].sort(
        (left, right) =>
          compareScores(cost.get(left) as number, cost.get(right) as number) ||
          tiebreak(left, right),
      );
    }

    case "lowest_latency": {
      const scored = scoresFor(routes, metrics);
      return [...routes].sort((left, right) => {
        const leftScore = scored.get(left) as ProviderRoutingScore;
        const rightScore = scored.get(right) as ProviderRoutingScore;
        return (
          providerHealthRank(true, leftScore) - providerHealthRank(true, rightScore) ||
          latencyRank(leftScore) - latencyRank(rightScore) ||
          tiebreak(left, right)
        );
      });
    }

    case "balanced": {
      const scored = scoresFor(routes, metrics);
      return [...routes].sort((left, right) => {
        const leftScore = scored.get(left) as ProviderRoutingScore;
        const rightScore = scored.get(right) as ProviderRoutingScore;
        return (
          providerHealthRank(true, leftScore) - providerHealthRank(true, rightScore) ||
          compareScores(
            balancedRouteScore(left, leftScore),
            balancedRouteScore(right, rightScore),
          ) ||
          tiebreak(left, right)
        );
      });
    }
  }
}

/**
 * Score each route ONCE.
 *
 * Not an optimisation: `Array.prototype.sort` calls the comparator O(n log n)
 * times and `RoutingMetrics.score` is only guaranteed to be pure for the
 * shipped implementations. Snapshotting keeps the comparator consistent, and an
 * inconsistent comparator is undefined behaviour in every JS engine.
 */
function scoresFor(
  routes: readonly PhysicalRoute[],
  metrics: RoutingMetrics,
): Map<PhysicalRoute, ProviderRoutingScore> {
  const byProvider = new Map<string, ProviderRoutingScore>();
  const scored = new Map<PhysicalRoute, ProviderRoutingScore>();
  for (const route of routes) {
    let score = byProvider.get(route.provider);
    if (score === undefined) {
      score = metrics.score(route.provider);
      byProvider.set(route.provider, score);
    }
    scored.set(route, score);
  }
  return scored;
}
