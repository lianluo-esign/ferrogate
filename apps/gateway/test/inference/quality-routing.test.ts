/**
 * #894 acceptance box 3 — the ROUTER actually consumes the eval aggregate.
 *
 * ## Why this file exists
 *
 * `test/evals/leg-quality.test.ts` holds the aggregate, the comparator and the
 * memo, and it calls `orderCandidatesByStrategy` with a hand-written `{ lags }`
 * literal. None of that touches the WIRE: nothing built `deps.routingQuality`,
 * nothing drove `planUpstream`, and nothing asserted that a real request's
 * candidate order changed. Severing `handlers.ts`'s
 * `deps.routingQuality.ladderQuality(...)` — i.e. making the router blind to
 * every eval score there is — left 160 tests green. That is the headline
 * feature of the issue held by nothing.
 *
 * So every case here goes through `harness(...)` → `createInferenceRouter` →
 * `planUpstream` → `orderCandidatesByStrategy` → `dispatchWithFailover`, with
 * only the OUTBOUND provider `fetch` intercepted, and the port is the REAL
 * `routingQualityPortFrom` over the REAL `tenantLegQualityFrom(legQualityVerdicts(...))`
 * — the same objects `quality-source.ts` builds from D1 — rather than a double
 * that could agree with a broken comparator.
 *
 * ## MUTATION LOG
 *
 * Every row below was applied to `src/`, run, and reverted.
 *
 * | mutation                                                                    | red |
 * |-------------------------------------------------------------------------------|-----|
 * | `handlers.ts:849`: `const quality = undefined; void deps.routingQuality;`        | `serves the comparable leg even when priority puts the lagging one first` |
 * | `strategy.ts::orderCandidatesByStrategy`: drop the `demoteLaggingLegs` last pass | `serves the comparable leg even when priority puts the lagging one first` |
 * | `handlers.ts:849`: drop the `caller.scope.kind === "tenant"` guard               | `gives a platform-operator credential the pre-#894 ordering` |
 * | `strategy.ts::demoteLaggingLegs`: drop the `route.canaryPercent === undefined` exemption | `never demotes an operator-declared canary off the head` |
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  type OnlineEvalLegAggregate,
  legQualityVerdicts,
  routingQualityPortFrom,
  tenantLegQualityFrom,
} from "../../src/evals/index.js";
import type { Caller, InferenceDeps, PhysicalRoute } from "../../src/inference/index.js";
import type { RoutingQualityPort } from "../../src/inference/strategy.js";
import { harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const TENANT = "acme";
const MODEL = "ladder-model";
const BODY = { model: MODEL, messages: [{ role: "user", content: "hi" }] };
const POLICY = { regressionDrop: 0.1, regressionMinSamples: 20 };

function route(provider: string, overrides: Partial<PhysicalRoute> = {}): PhysicalRoute {
  return {
    logicalModel: MODEL,
    provider,
    providerModel: "gpt-4o-mini",
    providerKind: "openai",
    baseUrl: `https://${provider}.test/v1`,
    apiKey: "sk-test",
    enabled: true,
    ...overrides,
  };
}

function cell(provider: string, mean: number): OnlineEvalLegAggregate {
  return {
    tenantId: TENANT,
    criterionId: "grounded",
    judgeModel: "judge-model",
    logicalModel: MODEL,
    provider,
    providerModel: "gpt-4o-mini",
    scoreTotal: mean * 20,
    scoreCount: 20,
  };
}

/**
 * The port the gateway resolves from D1, built over the REAL comparator.
 *
 * Only the storage seam is replaced: `peek` answers the snapshot a warmed
 * `cachedOnlineEvalLegQualitySource` would have answered. Everything from
 * `legQualityVerdicts` outward is production code.
 */
function warmPort(aggregates: readonly OnlineEvalLegAggregate[]): RoutingQualityPort {
  const quality = tenantLegQualityFrom(legQualityVerdicts(aggregates, POLICY));
  return routingQualityPortFrom({
    qualityFor: async () => ({ ok: true, quality }),
    peek: (tenantId: string) => (tenantId === TENANT ? { ok: true, quality } : undefined),
  });
}

function tenantCaller(): InferenceDeps["caller"] {
  return (): Caller => ({ scope: { kind: "tenant", tenantId: TENANT }, apiKeyId: "key_q" });
}

function operatorCaller(): InferenceDeps["caller"] {
  return (): Caller => ({ scope: { kind: "platform_operator" }, apiKeyId: "key_q" });
}

function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

let provider: ReturnType<typeof interceptProviderFetch> | undefined;

function answerFromEachProvider(): void {
  provider = interceptProviderFetch((request) => {
    const name = providerOf(request.url);
    return providerJson({
      id: `chatcmpl-${name}`,
      object: "chat.completion",
      model: MODEL,
      choices: [{ index: 0, message: { role: "assistant", content: name }, finish_reason: "stop" }],
      usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
    });
  });
}

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

async function servedBy(deps: InferenceDeps, routes: readonly PhysicalRoute[]): Promise<string> {
  const app = harness(deps, routes);
  const response = await app.post("/v1/chat/completions", BODY);
  expect(response.status, await response.clone().text()).toBe(200);
  return ((await response.json()) as { id: string }).id.replace("chatcmpl-", "");
}

describe("the router consumes the per-leg eval aggregate", () => {
  it("serves the comparable leg even when priority puts the lagging one first", async () => {
    answerFromEachProvider();
    // `azure-eu` is priority 0, so the pre-#894 ladder dials it first. Its mean
    // is 0.50 against `openai-main`'s 0.90 — four times the tenant's threshold.
    const routes = [route("azure-eu", { priority: 0 }), route("openai-main", { priority: 1 })];
    const aggregates = [cell("openai-main", 0.9), cell("azure-eu", 0.5)];

    // WITHOUT the quality port: priority alone, i.e. every deployment before
    // this slice. This is the anti-vacuity baseline for the line below.
    expect(await servedBy({ caller: tenantCaller() }, routes)).toBe("azure-eu");

    // WITH it, through `deps.routingQuality` → `planUpstream`.
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmPort(aggregates) }, routes),
    ).toBe("openai-main");
  });

  it("leaves the ladder alone when the memo is cold", async () => {
    answerFromEachProvider();
    const routes = [route("azure-eu", { priority: 0 }), route("openai-main", { priority: 1 })];
    // `peek` answering `undefined` is the state EVERY isolate starts in. The
    // router must fall back to the configured strategy, never block on a read.
    const cold: RoutingQualityPort = { ladderQuality: () => undefined };
    expect(await servedBy({ caller: tenantCaller(), routingQuality: cold }, routes)).toBe(
      "azure-eu",
    );
  });

  it("leaves the ladder alone when no leg has enough samples", async () => {
    answerFromEachProvider();
    const routes = [route("azure-eu", { priority: 0 }), route("openai-main", { priority: 1 })];
    // 19 scores against `regressionMinSamples: 20`, and a catastrophic mean.
    // `no_signal` is not `lagging`, so nothing moves — the guard that stops the
    // router acting on four samples of noise.
    const thin = [
      { ...cell("openai-main", 0.9), scoreCount: 19, scoreTotal: 17.1 },
      { ...cell("azure-eu", 0.1), scoreCount: 19, scoreTotal: 1.9 },
    ];
    expect(await servedBy({ caller: tenantCaller(), routingQuality: warmPort(thin) }, routes)).toBe(
      "azure-eu",
    );
  });

  it("gives a platform-operator credential the pre-#894 ordering", async () => {
    answerFromEachProvider();
    const routes = [route("azure-eu", { priority: 0 }), route("openai-main", { priority: 1 })];
    // A platform-operator credential carries no tenancy, so there is no tenant
    // whose criteria and thresholds the comparison could be made under. The port
    // above WOULD demote `azure-eu` if it were asked — the test before this one
    // proves that with the same aggregate — so this is the tenancy guard.
    const port = warmPort([cell("openai-main", 0.9), cell("azure-eu", 0.5)]);
    expect(await servedBy({ caller: operatorCaller(), routingQuality: port }, routes)).toBe(
      "azure-eu",
    );
  });

  it("never demotes an operator-declared canary off the head", async () => {
    answerFromEachProvider();
    // `applyCanary` promotes the canary to the head for a selected caller, and
    // the head survives `orderByPriorityRotation` because the canary is alone in
    // its priority group. A quality partition with no exemption would move it
    // straight to the tail for every selected caller, so `canary_percent = 100`
    // would divert 0% — and it could never recover, because a leg that stops
    // being served stops accumulating scores.
    const routes = [
      route("openai-main", { priority: 0 }),
      route("azure-eu", { priority: 5, canaryPercent: 100 }),
    ];
    const aggregates = [cell("openai-main", 0.9), cell("azure-eu", 0.5)];
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmPort(aggregates) }, routes),
    ).toBe("azure-eu");

    // ANTI-VACUITY: the SAME aggregate against the same two providers WITHOUT
    // the canary declaration does demote `azure-eu`, so the line above is the
    // exemption and not a quality signal that never fires.
    const plain = [route("azure-eu", { priority: 0 }), route("openai-main", { priority: 1 })];
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmPort(aggregates) }, plain),
    ).toBe("openai-main");
  });

  it("never drops a leg, so a ladder whose legs all lag still serves", async () => {
    answerFromEachProvider();
    const routes = [route("azure-eu", { priority: 0 }), route("openai-main", { priority: 1 })];
    const port: RoutingQualityPort = { ladderQuality: () => ({ lags: () => true }) };
    // A judge score is a noisy proxy: it may reorder a ladder and must never be
    // able to remove the leg that would have served the request.
    expect(await servedBy({ caller: tenantCaller(), routingQuality: port }, routes)).toBe(
      "azure-eu",
    );
  });
});

/**
 * #699 — the cost/quality dial, on the SAME wire (`harness` → `planUpstream` →
 * `applyCostQualityDial` → `orderCandidatesByStrategy`), the OUTBOUND fetch the
 * only mock. Every case pairs a dial-ON assertion with a dial-OFF one over the
 * same routes and aggregate, so a green line means the DIAL fired and not that
 * the ladder happened to order this way.
 */
function warmDialPort(aggregates: readonly OnlineEvalLegAggregate[]): RoutingQualityPort {
  // Identical to `warmPort` but with the dial ON — the one bit #699 adds.
  const quality = tenantLegQualityFrom(legQualityVerdicts(aggregates, POLICY), true);
  return routingQualityPortFrom({
    qualityFor: async () => ({ ok: true, quality }),
    peek: (tenantId: string) => (tenantId === TENANT ? { ok: true, quality } : undefined),
  });
}

async function servedByWith(
  deps: InferenceDeps,
  routes: readonly PhysicalRoute[],
  body: unknown,
): Promise<string> {
  const app = harness(deps, routes);
  const response = await app.post("/v1/chat/completions", body);
  expect(response.status, await response.clone().text()).toBe(200);
  return ((await response.json()) as { id: string }).id.replace("chatcmpl-", "");
}

describe("the cost/quality dial (#699)", () => {
  const PREMIUM = route("premium", { priority: 0, inputPricePer1m: 100, outputPricePer1m: 100 });
  const CHEAP = route("cheap", { priority: 1, inputPricePer1m: 1, outputPricePer1m: 1 });
  const HARD_BODY = { ...BODY, tools: [{ type: "function", function: { name: "f" } }] };

  it("routes an easy prompt to the cheapest candidate that clears the floor", async () => {
    answerFromEachProvider();
    const routes = [PREMIUM, CHEAP];
    // Both legs are comparable (equal means), so neither is below the floor.
    const aggregates = [cell("premium", 0.9), cell("cheap", 0.9)];

    // Dial OFF is byte-identical to today: the model's `priority` strategy dials
    // the priority-0 PREMIUM leg first, cost never entering the decision.
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmPort(aggregates) }, routes),
    ).toBe("premium");

    // Dial ON + an easy prompt overrides to lowest_cost over the floor-clearers.
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmDialPort(aggregates) }, routes),
    ).toBe("cheap");
  });

  it("cost-picks the cheapest FLOOR-CLEARER, not the cheapest leg overall", async () => {
    answerFromEachProvider();
    // `cheap` is the cheapest leg overall AND it lags; two comparable legs sit
    // above the floor at different prices. Priorities are set so the dial-OFF
    // and dial-ON answers DIFFER — the anti-vacuity this whole file is about.
    const cheapLag = route("cheap", { priority: 2, inputPricePer1m: 1, outputPricePer1m: 1 });
    const goodMid = route("goodmid", { priority: 1, inputPricePer1m: 50, outputPricePer1m: 50 });
    const goodTop = route("goodtop", { priority: 0, inputPricePer1m: 100, outputPricePer1m: 100 });
    const routes = [goodTop, goodMid, cheapLag];
    const aggregates = [cell("goodtop", 0.9), cell("goodmid", 0.9), cell("cheap", 0.5)];

    // Dial OFF: priority dials `goodtop` (priority 0) first; `cheap` is demoted
    // by #894 but stays in the ladder. Cost never enters.
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmPort(aggregates) }, routes),
    ).toBe("goodtop");

    // Dial ON + easy: the cost pick serves `goodmid` (50 < 100), NOT the cheapest
    // leg `cheap` (1). NOTE this SERVED-LEG outcome is shared with #894's demote
    // pass — `lowest_cost` puts `cheap` first, demote pushes the lagging leg to
    // the tail, and the mock succeeds on the head either way — so this line alone
    // does NOT prove `cheap` was FILTERED rather than merely demoted. That
    // distinction (the leg is gone from the FAILOVER ladder, not just its tail)
    // is what the failover-exclusion test below holds; this case pins that the
    // dial overrides the operator's `priority` strategy with a cost pick taken
    // over the floor-clearers.
    expect(
      await servedBy({ caller: tenantCaller(), routingQuality: warmDialPort(aggregates) }, routes),
    ).toBe("goodmid");
  });

  it("keeps the operator's hand-written ladder for a HARD prompt", async () => {
    answerFromEachProvider();
    const routes = [PREMIUM, CHEAP];
    const aggregates = [cell("premium", 0.9), cell("cheap", 0.9)];

    // A tool-calling body is HARD, so the dial does not cost-override: PREMIUM
    // (priority 0) still serves.
    expect(
      await servedByWith(
        { caller: tenantCaller(), routingQuality: warmDialPort(aggregates) },
        routes,
        HARD_BODY,
      ),
    ).toBe("premium");

    // ANTI-VACUITY: the SAME routes and dial with an EASY body do cost-override,
    // so the line above is the hard-task branch and not a dial that never fires.
    expect(
      await servedByWith(
        { caller: tenantCaller(), routingQuality: warmDialPort(aggregates) },
        routes,
        BODY,
      ),
    ).toBe("cheap");
  });

  it("removes a below-floor leg from the FAILOVER ladder, not merely its tail", async () => {
    // The one behaviour that separates #699's FILTER from #894's DEMOTE, and the
    // gap the served-leg cases above cannot reach: with the mock succeeding on
    // the head, filter and demote pick the same first candidate, so the filter is
    // only observable when the floor-clearer FAILS and the ladder must fall back.
    //
    // `good` clears the floor but faults every attempt; `cheap` is the cheapest
    // leg AND lags. Under demote-only `cheap` sits at the ladder tail and rescues
    // the request when `good` fails (200, served by `cheap`). #699's filter drops
    // `cheap` from the eligible set entirely, so the ladder fails over `good`'s
    // fault to NOTHING: the upstream 503 reaches the client and `cheap` is never
    // dispatched.
    const dispatched: string[] = [];
    provider = interceptProviderFetch((request) => {
      const name = providerOf(request.url);
      dispatched.push(name);
      if (name === "good") {
        return providerJson({ error: "overloaded" }, 503);
      }
      return providerJson({
        id: "chatcmpl-cheap",
        object: "chat.completion",
        model: MODEL,
        choices: [
          { index: 0, message: { role: "assistant", content: "cheap" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
      });
    });
    const good = route("good", { priority: 0, inputPricePer1m: 50, outputPricePer1m: 50 });
    const cheapLag = route("cheap", { priority: 1, inputPricePer1m: 1, outputPricePer1m: 1 });
    const routes = [good, cheapLag];
    const aggregates = [cell("good", 0.9), cell("cheap", 0.5)];

    const app = harness(
      { caller: tenantCaller(), routingQuality: warmDialPort(aggregates) },
      routes,
    );
    const response = await app.post("/v1/chat/completions", BODY);

    // The floor-clearer exhausted its retries with no survivor to fall to, so the
    // upstream 503 reaches the client — the lagging leg did NOT rescue it.
    expect(response.status, await response.clone().text()).toBe(503);
    // ANTI-VACUITY: `good` WAS attempted, and `cheap` NEVER was. Restore the
    // filter to a demote (drop the `filtered.push` branch in
    // `applyCostQualityDial`) and `cheap` reappears at the ladder tail, serving a
    // 200 — so both assertions below go red on that mutation.
    expect(dispatched).toContain("good");
    expect(dispatched).not.toContain("cheap");
  });
});
