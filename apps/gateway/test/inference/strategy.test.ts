/**
 * `RoutingStrategy` — the F6 half of the reliability layer.
 *
 * ## WHY THIS FILE IS SHAPED LIKE THIS
 *
 * `strategy.ts` is a pure module of comparators. Unit-testing it alone would go
 * green whether or not `handlers.ts` ever calls it — which is the exact defect
 * class this wave exists to remove (`packages/routing` was fully implemented,
 * fully tested and reached by zero call sites). So the strategy assertions are
 * split in two:
 *
 *  - §1–§3 pin the Rust ARITHMETIC (`route_estimated_cost`, `balanced_route_score`,
 *    `weighted_start_index`, `ProviderRoutingMetrics::score`) directly, because a
 *    comparator that is wired but wrong is just as broken as one that is unwired;
 *  - §4–§6 are MOUNT GATES: every one of them drives the REAL inference router
 *    end to end with only the outbound provider `fetch` intercepted, and is
 *    constructed so that the priority order (the pre-F6 behavior) gives the
 *    OPPOSITE answer to the strategy under test. Remove the
 *    `orderCandidatesByStrategy` call from `planUpstream`, or the
 *    `deps.routingMetrics` recording from `dispatchCandidates`, or the
 *    `routing_strategy` / price columns from `catalog.ts`, and they go red.
 *
 * The mount gates, named, so a future reader can check them by deletion:
 *
 *  - "dispatches the cheapest eligible route first" — red if `planUpstream`
 *    stops re-ordering by strategy (the cheap route carries the WORSE priority).
 *  - "prices the request, not just the unit rate" — red if `estimatedUsage`
 *    stops being threaded into `planUpstream`.
 *  - "steers away from a provider it has watched fail" — red if
 *    `dispatchCandidates` stops recording into `deps.routingMetrics`.
 *  - "observations survive across requests" — red if `resolveDeps` builds a
 *    fresh recorder per request instead of resolving the isolate singleton.
 *  - "reads routing_strategy and the prices off GATEWAY_MODELS" — red if
 *    `catalog.ts` drops either column.
 *  - "an undeclared fallback never outranks the primary" — red if the Rust
 *    `priority.unwrap_or(100)` fallback default is dropped.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_ROUTING_STRATEGY,
  NO_ROUTING_OBSERVATIONS,
  ProviderRoutingMetrics,
  ROUTING_STRATEGIES,
  balancedRouteScore,
  buildModelCatalog,
  isolateRoutingMetrics,
  latencyRank,
  modelCatalogFromEnv,
  orderCandidatesByStrategy,
  priorityGroupEnd,
  providerHealthRank,
  resolveDeps,
  routeEstimatedCost,
  routeEstimatedUnitCost,
  totalWeight,
  weightedStartIndex,
} from "../../src/inference/index.js";
import type {
  Caller,
  InferenceDeps,
  PhysicalRoute,
  RoutingMetrics,
} from "../../src/inference/index.js";
import { harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const MODEL = "strategy-model";

const CHAT_BODY = { model: MODEL, messages: [{ role: "user", content: "hello there" }] };

const CHAT_OK = {
  id: "chatcmpl-strategy",
  object: "chat.completion",
  model: "gpt-4o-mini",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

function route(overrides: Partial<PhysicalRoute> & { provider: string }): PhysicalRoute {
  return {
    logicalModel: MODEL,
    providerModel: "gpt-4o-mini",
    providerKind: "openai",
    baseUrl: `https://${overrides.provider}.test/v1`,
    apiKey: "sk-test",
    enabled: true,
    ...overrides,
  };
}

/** Which provider an intercepted URL belongs to (`https://<provider>.test/...`). */
function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

function keyedCaller(apiKeyId: string): InferenceDeps["caller"] {
  return (): Caller => ({ scope: { kind: "platform_operator" }, apiKeyId });
}

// ---------------------------------------------------------------------------
// §1 — the cost arithmetic (`route_estimated_cost` / `route_estimated_unit_cost`)
// ---------------------------------------------------------------------------

describe("route cost scoring reproduces state.rs", () => {
  it("sums both rates when the route is fully priced and there is no estimate", () => {
    expect(
      routeEstimatedUnitCost(
        route({ provider: "a", inputPricePer1m: 0.15, outputPricePer1m: 0.6 }),
      ),
    ).toBeCloseTo(0.75, 12);
  });

  it("uses whichever single rate is declared", () => {
    expect(routeEstimatedUnitCost(route({ provider: "a", inputPricePer1m: 2 }))).toBe(2);
    expect(routeEstimatedUnitCost(route({ provider: "a", outputPricePer1m: 7 }))).toBe(7);
  });

  it("scores an UNPRICED route as infinitely expensive, never as free", () => {
    // The fail-closed shape: `(None, None) => f64::INFINITY`. If this were 0 an
    // operator who priced only part of the ladder would have `lowest_cost`
    // always pick the route they forgot to price.
    expect(routeEstimatedUnitCost(route({ provider: "a" }))).toBe(Number.POSITIVE_INFINITY);
  });

  it("prices the ESTIMATE when one is supplied, via @ferrogate/billing", () => {
    // `ModelPrice::usd(0.15, 0.60).estimate(TokenUsage::new(1_000, 2_000, 3_000))`
    // — the exact numbers Rust's own `estimates_model_cost_from_token_usage`
    // asserts: 0.00015 + 0.0012.
    const cost = routeEstimatedCost(
      route({ provider: "a", inputPricePer1m: 0.15, outputPricePer1m: 0.6 }),
      { promptTokens: 1_000, completionTokens: 2_000, totalTokens: 3_000 },
    );
    expect(cost).toBeCloseTo(0.00135, 12);
  });

  it("falls back to the unit cost when the route is only half priced", () => {
    // Rust's `_ => route_estimated_unit_cost(route)` arm: a half-priced route
    // cannot be scored against usage without inventing the missing rate.
    expect(
      routeEstimatedCost(route({ provider: "a", inputPricePer1m: 3 }), {
        promptTokens: 1_000_000,
        completionTokens: 1_000_000,
        totalTokens: 2_000_000,
      }),
    ).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// §2 — health / latency / balanced scoring
// ---------------------------------------------------------------------------

describe("ProviderRoutingMetrics reproduces the Rust scoring", () => {
  it("reports no average latency until a request has SUCCEEDED", () => {
    const metrics = new ProviderRoutingMetrics();
    metrics.recordFailure("p");
    metrics.recordFailure("p");
    // `checked_div` by zero successes ⇒ `None`, NOT an average of 0. A 0 here
    // would make a provider that has only ever failed look instantaneous.
    expect(metrics.score("p").averageLatencyMs).toBeUndefined();
    expect(metrics.score("p").failureRate).toBe(1);
    expect(metrics.score("p").observedRequests).toBe(2);
  });

  it("averages latency over SUCCESSES only", () => {
    const metrics = new ProviderRoutingMetrics();
    metrics.recordSuccess("p", 100);
    metrics.recordSuccess("p", 300);
    metrics.recordFailure("p");
    expect(metrics.score("p").averageLatencyMs).toBe(200);
    expect(metrics.score("p").failureRate).toBeCloseTo(1 / 3, 12);
  });

  it("scores an unobserved provider as the Rust default", () => {
    expect(new ProviderRoutingMetrics().score("never-seen")).toEqual(NO_ROUTING_OBSERVATIONS);
  });

  it("ranks health on the 3-observation / 50%-failure threshold", () => {
    expect(providerHealthRank(true, NO_ROUTING_OBSERVATIONS)).toBe(0);
    // Two observations is below the floor even at 100% failure — Rust refuses
    // to declare a provider unhealthy on a sample of two.
    expect(
      providerHealthRank(true, { averageLatencyMs: 5, failureRate: 1, observedRequests: 2 }),
    ).toBe(0);
    expect(
      providerHealthRank(true, { averageLatencyMs: 5, failureRate: 0.5, observedRequests: 3 }),
    ).toBe(1);
    expect(providerHealthRank(false, NO_ROUTING_OBSERVATIONS)).toBe(2);
  });

  it("sorts an unmeasured provider BEHIND every measured one", () => {
    expect(latencyRank({ averageLatencyMs: 9_999, failureRate: 0, observedRequests: 1 })).toBe(
      9_999,
    );
    expect(latencyRank(NO_ROUTING_OBSERVATIONS)).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("weights the balanced score exactly as balanced_route_score does", () => {
    // cost(0.15+0.60) + latency(250/1000) + failure(0.25*10)
    expect(
      balancedRouteScore(route({ provider: "a", inputPricePer1m: 0.15, outputPricePer1m: 0.6 }), {
        averageLatencyMs: 250,
        failureRate: 0.25,
        observedRequests: 8,
      }),
    ).toBeCloseTo(0.75 + 0.25 + 2.5, 12);
    // An UNPRICED route scores 1_000 here, not Infinity — `balanced` is meant
    // to keep using it, unlike `lowest_cost`.
    expect(balancedRouteScore(route({ provider: "a" }), NO_ROUTING_OBSERVATIONS)).toBeCloseTo(
      1_000 + 1 + 0,
      12,
    );
  });
});

// ---------------------------------------------------------------------------
// §3 — the weighted round-robin
// ---------------------------------------------------------------------------

describe("weighted round-robin reproduces weighted_start_index", () => {
  const group = [route({ provider: "heavy", weight: 3 }), route({ provider: "light", weight: 1 })];

  it("treats weight 0 (and absent) as 1, and floors the total at 1", () => {
    expect(totalWeight(group)).toBe(4);
    expect(totalWeight([route({ provider: "a", weight: 0 }), route({ provider: "b" })])).toBe(2);
    expect(totalWeight([])).toBe(1);
  });

  it("lands inside the weight band the cursor points at", () => {
    expect(weightedStartIndex(group, 0)).toBe(0);
    expect(weightedStartIndex(group, 1)).toBe(0);
    expect(weightedStartIndex(group, 2)).toBe(0);
    expect(weightedStartIndex(group, 3)).toBe(1);
    // Wraps on the group total, so the cycle repeats.
    expect(weightedStartIndex(group, 4)).toBe(0);
    expect(weightedStartIndex(group, 7)).toBe(1);
  });

  it("groups only the CONTIGUOUS leading run of one priority", () => {
    const routes = [
      route({ provider: "a", priority: 0 }),
      route({ provider: "b", priority: 0 }),
      route({ provider: "c", priority: 100 }),
    ];
    expect(priorityGroupEnd(routes)).toBe(2);
    expect(priorityGroupEnd(routes.slice(2))).toBe(1);
    expect(priorityGroupEnd([])).toBe(0);
  });

  it("SPREADS across a priority group instead of only ordering it", () => {
    // This is the behavior `orderCandidates` alone cannot produce: with a fixed
    // priority→weight order, `heavy` would be first on every single request.
    const leaders = [0, 1, 2, 3, 4, 5, 6, 7].map(
      (cursor) =>
        (orderCandidatesByStrategy(group, "priority", { cursor })[0] as PhysicalRoute).provider,
    );
    expect(leaders).toEqual([
      "heavy",
      "heavy",
      "heavy",
      "light",
      "heavy",
      "heavy",
      "heavy",
      "light",
    ]);
  });

  it("rotates each priority group on its own digit of the cursor", () => {
    // Rust `cursor /= total_weight(group)` between groups: group 2 must not
    // rotate in lockstep with group 1.
    const routes = [
      route({ provider: "a", priority: 0, weight: 1 }),
      route({ provider: "b", priority: 0, weight: 1 }),
      route({ provider: "c", priority: 100, weight: 1 }),
      route({ provider: "d", priority: 100, weight: 1 }),
    ];
    const at = (cursor: number): string[] =>
      orderCandidatesByStrategy(routes, "priority", { cursor }).map((r) => r.provider);
    expect(at(0)).toEqual(["a", "b", "c", "d"]);
    expect(at(1)).toEqual(["b", "a", "c", "d"]);
    // cursor 2 → group1 start 0, then cursor/2 = 1 → group2 start 1.
    expect(at(2)).toEqual(["a", "b", "d", "c"]);
    expect(at(3)).toEqual(["b", "a", "d", "c"]);
  });

  it("never drops a candidate, whatever the strategy", () => {
    const routes = [
      route({ provider: "a", inputPricePer1m: 9, outputPricePer1m: 9 }),
      route({ provider: "b" }),
      route({ provider: "c", inputPricePer1m: 1, outputPricePer1m: 1 }),
    ];
    for (const strategy of ROUTING_STRATEGIES) {
      const ordered = orderCandidatesByStrategy(routes, strategy, { cursor: 0 });
      expect([...ordered].sort()).toHaveLength(3);
      expect(new Set(ordered.map((r) => r.provider))).toEqual(new Set(["a", "b", "c"]));
    }
  });

  it("defaults to priority, so a catalog written before F6 keeps its order", () => {
    expect(DEFAULT_ROUTING_STRATEGY).toBe("priority");
  });
});

// ---------------------------------------------------------------------------
// §4 — MOUNT GATE: the strategy is applied on the real request path
// ---------------------------------------------------------------------------

describe("lowest_cost on the deployed request path", () => {
  // `cheap` carries the WORSE priority, so priority ordering alone puts
  // `pricey` first. Only the strategy can reverse it.
  const ROUTES: readonly PhysicalRoute[] = [
    route({
      provider: "pricey",
      priority: 0,
      inputPricePer1m: 10,
      outputPricePer1m: 30,
      routingStrategy: "lowest_cost",
    }),
    route({
      provider: "cheap",
      priority: 100,
      inputPricePer1m: 0.15,
      outputPricePer1m: 0.6,
      routingStrategy: "lowest_cost",
    }),
  ];

  it("dispatches the cheapest eligible route first — MOUNT GATE", async () => {
    const seen: string[] = [];
    const provider = interceptProviderFetch((request) => {
      seen.push(providerOf(request.url));
      return providerJson(CHAT_OK);
    });
    try {
      const response = await harness({}, ROUTES).post("/v1/chat/completions", CHAT_BODY);
      expect(response.status).toBe(200);
    } finally {
      provider.restore();
    }
    expect(seen).toEqual(["cheap"]);
  });

  it("keeps priority order when the strategy is left unset — the control", async () => {
    // Without this, "cheap went first" would not prove the STRATEGY did it:
    // the same list under the default strategy must go the other way.
    const unset = ROUTES.map(({ routingStrategy: _dropped, ...rest }) => rest);
    const seen: string[] = [];
    const provider = interceptProviderFetch((request) => {
      seen.push(providerOf(request.url));
      return providerJson(CHAT_OK);
    });
    try {
      await harness({}, unset).post("/v1/chat/completions", CHAT_BODY);
    } finally {
      provider.restore();
    }
    expect(seen).toEqual(["pricey"]);
  });

  it("prices the REQUEST, not just the unit rate — MOUNT GATE", async () => {
    // The two rankings are made to DISAGREE, which is the only way this can
    // distinguish `routeEstimatedCost` from `routeEstimatedUnitCost`.
    //
    // A chat request with no `max_tokens` reserves the Rust default of 512
    // completion tokens against a ~20-token prompt, so the OUTPUT rate
    // dominates the priced score while the unit score weighs both equally:
    //
    //   unit-cheap  : unit 0.1 + 50 =  50.1   priced ≈ (20*0.1 + 512*50)/1e6
    //   priced-cheap: unit 100 +  1 = 101.0   priced ≈ (20*100 + 512*1)/1e6
    //
    // so `unit-cheap` wins by unit and loses by a factor of ~10 once priced.
    // It also carries the better PRIORITY, so both the pre-F6 ordering and a
    // unit-cost-only implementation would pick it.
    const routes: readonly PhysicalRoute[] = [
      route({
        provider: "unit-cheap",
        priority: 0,
        inputPricePer1m: 0.1,
        outputPricePer1m: 50,
        routingStrategy: "lowest_cost",
      }),
      route({
        provider: "priced-cheap",
        priority: 100,
        inputPricePer1m: 100,
        outputPricePer1m: 1,
        routingStrategy: "lowest_cost",
      }),
    ];
    // Verify the arithmetic drives the choice rather than asserting a guess:
    // score both directly, then assert the router agrees with the winner.
    const estimated = { promptTokens: 20, completionTokens: 512, totalTokens: 532 };
    const scored = [...routes].sort(
      (left, right) => routeEstimatedCost(left, estimated) - routeEstimatedCost(right, estimated),
    );
    const pricedWinner = (scored[0] as PhysicalRoute).provider;
    const unitWinner = [...routes].sort(
      (left, right) => routeEstimatedUnitCost(left) - routeEstimatedUnitCost(right),
    )[0]?.provider;
    // The fixture is only meaningful if the two disagree.
    expect(pricedWinner).not.toBe(unitWinner);

    const seen: string[] = [];
    const provider = interceptProviderFetch((request) => {
      seen.push(providerOf(request.url));
      return providerJson(CHAT_OK);
    });
    try {
      await harness({}, routes).post("/v1/chat/completions", CHAT_BODY);
    } finally {
      provider.restore();
    }
    expect(seen).toEqual([pricedWinner]);
  });
});

// ---------------------------------------------------------------------------
// §5 — MOUNT GATE: observations are recorded from the dispatch loop
// ---------------------------------------------------------------------------

/** A recorder that also remembers what it was told, so the wiring is visible. */
class SpyRoutingMetrics extends ProviderRoutingMetrics {
  readonly calls: string[] = [];

  override recordSuccess(provider: string, latencyMs: number): void {
    this.calls.push(`success:${provider}`);
    super.recordSuccess(provider, latencyMs);
  }

  override recordFailure(provider: string): void {
    this.calls.push(`failure:${provider}`);
    super.recordFailure(provider);
  }
}

describe("the dispatch loop feeds ProviderRoutingMetrics", () => {
  it("records a success with the served provider — MOUNT GATE", async () => {
    const routingMetrics = new SpyRoutingMetrics();
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    try {
      const response = await harness({ routingMetrics }, [route({ provider: "solo" })]).post(
        "/v1/chat/completions",
        CHAT_BODY,
      );
      expect(response.status).toBe(200);
    } finally {
      provider.restore();
    }
    expect(routingMetrics.calls).toEqual(["success:solo"]);
    expect(routingMetrics.score("solo").observedRequests).toBe(1);
    expect(routingMetrics.score("solo").failureRate).toBe(0);
  });

  it("counts a 400 as a FAILED request, matching the Rust request log", async () => {
    // `status_code >= 400 || error_code.is_some()`. Note this deliberately
    // differs from the circuit breaker, which ignores a non-retryable 400 —
    // the two counters answer different questions and must not be merged.
    const routingMetrics = new SpyRoutingMetrics();
    const provider = interceptProviderFetch(() => providerJson({ error: { message: "bad" } }, 400));
    try {
      await harness({ routingMetrics }, [route({ provider: "solo" })]).post(
        "/v1/chat/completions",
        CHAT_BODY,
      );
    } finally {
      provider.restore();
    }
    expect(routingMetrics.calls).toEqual(["failure:solo"]);
    expect(routingMetrics.score("solo").failureRate).toBe(1);
    // A failed request contributes NO latency, so a provider that fails fast
    // must not look fast.
    expect(routingMetrics.score("solo").averageLatencyMs).toBeUndefined();
  });

  it("steers lowest_latency away from a provider it watched fail — MOUNT GATE", async () => {
    // `flaky` has the BETTER priority, so only the observations can demote it.
    const routes: readonly PhysicalRoute[] = [
      route({ provider: "flaky", priority: 0, routingStrategy: "lowest_latency" }),
      route({ provider: "steady", priority: 100, routingStrategy: "lowest_latency" }),
    ];
    const routingMetrics = new ProviderRoutingMetrics();
    // Three observations at 100% failure ⇒ health rank 1 (Rust's floor is 3).
    routingMetrics.recordFailure("flaky");
    routingMetrics.recordFailure("flaky");
    routingMetrics.recordFailure("flaky");
    routingMetrics.recordSuccess("steady", 40);

    const seen: string[] = [];
    const provider = interceptProviderFetch((request) => {
      seen.push(providerOf(request.url));
      return providerJson(CHAT_OK);
    });
    try {
      await harness({ routingMetrics }, routes).post("/v1/chat/completions", CHAT_BODY);
    } finally {
      provider.restore();
    }
    expect(seen).toEqual(["steady"]);
  });

  it("leaves the priority order alone while nothing has been observed", async () => {
    // The control for the test above: with an EMPTY recorder both providers
    // score identically and the tiebreak is the Rust priority chain, so
    // `flaky` must lead. Without this, "steady went first" would be consistent
    // with a strategy that simply reverses the list.
    const routes: readonly PhysicalRoute[] = [
      route({ provider: "flaky", priority: 0, routingStrategy: "lowest_latency" }),
      route({ provider: "steady", priority: 100, routingStrategy: "lowest_latency" }),
    ];
    const seen: string[] = [];
    const provider = interceptProviderFetch((request) => {
      seen.push(providerOf(request.url));
      return providerJson(CHAT_OK);
    });
    try {
      await harness({ routingMetrics: new ProviderRoutingMetrics() }, routes).post(
        "/v1/chat/completions",
        CHAT_BODY,
      );
    } finally {
      provider.restore();
    }
    expect(seen).toEqual(["flaky"]);
  });

  it("observations survive across requests — MOUNT GATE", async () => {
    // `resolveDeps` runs per request. If it built a fresh recorder each time,
    // every score would read `NO_ROUTING_OBSERVATIONS` forever: a metric
    // faithfully written and never read.
    const first = resolveDeps({}, {});
    const second = resolveDeps({}, {});
    const marker = `probe-${Math.random().toString(36).slice(2)}`;
    first.routingMetrics.recordSuccess(marker, 120);
    expect(second.routingMetrics.score(marker).observedRequests).toBe(1);
    expect(second.routingMetrics.score(marker).averageLatencyMs).toBe(120);
    // …and it is the module singleton the app resolves, not a per-call one.
    expect((isolateRoutingMetrics as RoutingMetrics).score(marker).observedRequests).toBe(1);
  });

  it("still steers when the caller supplies no injected recorder", async () => {
    // An end-to-end pass over the DEFAULT (unset `routingMetrics`) path, so the
    // gates above cannot be satisfied only by the injected arm.
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    const marker = `default-arm-${Math.random().toString(36).slice(2)}`;
    try {
      const response = await harness({ caller: keyedCaller("k1") }, [
        route({ provider: marker }),
      ]).post("/v1/chat/completions", CHAT_BODY);
      expect(response.status).toBe(200);
    } finally {
      provider.restore();
    }
    expect(isolateRoutingMetrics.score(marker).observedRequests).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// §5b — MOUNT GATE: the provider attempt index reaches the metering event
// ---------------------------------------------------------------------------

describe("Usage.providerAttemptIndex is threaded from the ladder", () => {
  it("is 0 for a request served on the first attempt", async () => {
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    const gateway = harness({}, [route({ provider: "solo" })]);
    try {
      expect((await gateway.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
    } finally {
      provider.restore();
    }
    expect(gateway.usage.records).toHaveLength(1);
    expect(gateway.usage.records[0]?.providerAttemptIndex).toBe(0);
  });

  it("counts the failed attempts that preceded it — MOUNT GATE", async () => {
    // `metering/event.ts::providerAttemptIndexFor` folds this into
    // `ledgerEntryId`, a PRIMARY KEY in three tables. Hard-code it to 0 and two
    // attempts of one request derive ONE ledger id, so the second is absorbed by
    // `ON CONFLICT DO NOTHING` as a healthy replay — a silent under-bill.
    //
    // `first` answers a retryable 503 and the ladder falls over to `second`, so
    // the served response is attempt index 1.
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "first"
        ? providerJson({ error: { message: "upstream down" } }, 503)
        : providerJson(CHAT_OK),
    );
    const gateway = harness({}, [
      route({ provider: "first", priority: 0 }),
      route({ provider: "second", priority: 100 }),
    ]);
    try {
      const response = await gateway.post("/v1/chat/completions", CHAT_BODY);
      expect(response.status).toBe(200);
    } finally {
      provider.restore();
    }
    expect(gateway.usage.records).toHaveLength(1);
    expect(gateway.usage.records[0]?.provider).toBe("second");
    expect(gateway.usage.records[0]?.providerAttemptIndex).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// §6 — MOUNT GATE: the config vocabulary
// ---------------------------------------------------------------------------

describe("GATEWAY_MODELS carries the F6 columns", () => {
  const PROVIDERS = JSON.stringify([
    { name: "p1", kind: "openai", base_url: "https://p1.test/v1", api_key_var: "K" },
    { name: "p2", kind: "openai", base_url: "https://p2.test/v1", api_key_var: "K" },
  ]);

  it("reads routing_strategy and the prices off the var — MOUNT GATE", () => {
    const models = JSON.stringify([
      {
        name: MODEL,
        provider: "p1",
        provider_model: "m1",
        routing_strategy: "lowest_cost",
        input_price_per_1m: 10,
        output_price_per_1m: 30,
        fallbacks: [
          {
            provider: "p2",
            provider_model: "m2",
            input_price_per_1m: 0.15,
            output_price_per_1m: 0.6,
          },
        ],
      },
    ]);
    const built = modelCatalogFromEnv({
      GATEWAY_PROVIDERS: PROVIDERS,
      GATEWAY_MODELS: models,
      K: "sk-test",
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const [primary, fallback] = built.routes as [PhysicalRoute, PhysicalRoute];
    expect(primary.routingStrategy).toBe("lowest_cost");
    expect(primary.inputPricePer1m).toBe(10);
    expect(primary.outputPricePer1m).toBe(30);
    // `routing_strategy` belongs to the ENTRY, so the fallback inherits it even
    // though `fallbackRouteSchema` is `.strict()` and cannot declare its own.
    expect(fallback.routingStrategy).toBe("lowest_cost");
    expect(fallback.inputPricePer1m).toBe(0.15);
  });

  it("refuses a routing_strategy outside the Rust enum", () => {
    const built = modelCatalogFromEnv({
      GATEWAY_PROVIDERS: PROVIDERS,
      GATEWAY_MODELS: JSON.stringify([
        { name: MODEL, provider: "p1", provider_model: "m1", routing_strategy: "cheapest" },
      ]),
      K: "sk-test",
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toContain("routing_strategy");
  });

  it("an undeclared fallback never outranks the primary — MOUNT GATE", () => {
    // `model_registry_entry`: primary `priority = 0`, fallback
    // `priority.unwrap_or(100)`. `aaa` sorts alphabetically before `zzz`, so if
    // both defaulted to 0 the total order's provider tiebreak would put the
    // FALLBACK first on a config that declares no ordering at all.
    const built = buildModelCatalog(
      [
        { name: "zzz", kind: "openai", base_url: "https://zzz.test/v1" },
        { name: "aaa", kind: "openai", base_url: "https://aaa.test/v1" },
      ],
      [
        {
          name: MODEL,
          provider: "zzz",
          provider_model: "m",
          fallbacks: [{ provider: "aaa", provider_model: "m" }],
        },
      ],
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const primary = built.routes.find((r) => r.provider === "zzz");
    const fallback = built.routes.find((r) => r.provider === "aaa");
    expect(primary?.priority).toBe(0);
    expect(fallback?.priority).toBe(100);
    // Rust's weight default is 1, not 0 — `weighted_start_index` reads
    // `weight.max(1)` and the DESCENDING weight tiebreak would otherwise rank a
    // declared `weight: 0` above an undeclared one.
    expect(primary?.weight).toBe(1);
    expect(fallback?.weight).toBe(1);
  });

  it("dispatches the primary on EVERY request of an unordered fallback config", async () => {
    // The end-to-end consequence of the defaults above, through the real router.
    //
    // Four requests, not one, and that is the whole point. With the Rust
    // defaults the primary is ALONE in priority group 0, so the weighted
    // round-robin has nothing to rotate and it leads deterministically. Collapse
    // the two defaults to a shared priority and the pair becomes one rotating
    // group of total weight 2, so the fallback takes the lead on every other
    // request — a single-request assertion would pass or fail on the isolate's
    // cursor parity, which is exactly the kind of gate that rots into a flake.
    const built = buildModelCatalog(
      [
        { name: "zzz", kind: "openai", base_url: "https://zzz.test/v1" },
        { name: "aaa", kind: "openai", base_url: "https://aaa.test/v1" },
      ],
      [
        {
          name: MODEL,
          provider: "zzz",
          provider_model: "m",
          fallbacks: [{ provider: "aaa", provider_model: "m" }],
        },
      ],
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const seen: string[] = [];
    const provider = interceptProviderFetch((request) => {
      seen.push(providerOf(request.url));
      return providerJson(CHAT_OK);
    });
    try {
      const gateway = harness({}, built.routes);
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const response = await gateway.post("/v1/chat/completions", CHAT_BODY);
        expect(response.status).toBe(200);
      }
    } finally {
      provider.restore();
    }
    expect(seen).toEqual(["zzz", "zzz", "zzz", "zzz"]);
  });
});

describe("orderCandidatesByStrategy stays a pure, synchronous permutation (#699)", () => {
  function leg(provider: string, overrides: Partial<PhysicalRoute> = {}): PhysicalRoute {
    return {
      logicalModel: "m",
      provider,
      providerModel: "gpt-4o-mini",
      providerKind: "openai",
      baseUrl: `https://${provider}.test/v1`,
      apiKey: "sk-test",
      enabled: true,
      ...overrides,
    };
  }

  it("returns a value, never a thenable — no awaited storage read was added", () => {
    // #699's cost/quality FILTER lives in `handlers.ts::planUpstream`, NOT here,
    // precisely so this function keeps returning synchronously. A regression
    // that put a D1 read in front of ordering would have to make it async.
    const result = orderCandidatesByStrategy([leg("a"), leg("b")], "priority", { cursor: 0 });
    expect(Array.isArray(result)).toBe(true);
    expect((result as unknown as { then?: unknown }).then).toBeUndefined();
  });

  it("never filters, even when the quality snapshot has the dial on and every leg lags", () => {
    // The dial flag on `RoutingQuality` is #699's, but this permutation IGNORES
    // it: a filter here would break the failover ladder's "reaches every
    // candidate" contract. `demoteLaggingLegs` may only reorder.
    const routes = [leg("a", { priority: 0 }), leg("b", { priority: 1 })];
    const dialOnAllLag = { lags: (): boolean => true, costQualityRouting: true };
    const ordered = orderCandidatesByStrategy(routes, "priority", { quality: dialOnAllLag });
    expect(ordered).toHaveLength(routes.length);
    expect([...ordered].map((r) => r.provider).sort()).toEqual(["a", "b"]);
  });
});
