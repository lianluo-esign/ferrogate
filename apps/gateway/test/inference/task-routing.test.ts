/**
 * #699 — the pure half: the task classifier and the cost/quality dial's filter.
 *
 * These functions are the ONLY place a candidate may be dropped, so this file
 * holds them to the two contracts that matter: (1) the classifier's easy/hard
 * call is exactly the thresholds it documents, and (2) the dial never leaves a
 * ladder empty and never touches an operator who did not opt in. The wired
 * end-to-end behaviour (which provider actually serves, and the log row) lives
 * in `quality-routing.test.ts` and `routing-decision-log.test.ts`; here nothing
 * is mocked because there is nothing to mock — both functions are pure.
 *
 * ## MUTATION LOG (applied to `src/inference/task-routing.ts`, run, reverted)
 *
 * | mutation                                                                 | red |
 * |--------------------------------------------------------------------------|-----|
 * | `classifyTask`: drop the `tools`/`functions` check                       | `classifies a tool-calling request as hard` |
 * | `classifyTask`: `>` → `>=` on the prompt ceiling                         | `treats a prompt exactly at the ceiling as easy` |
 * | `applyCostQualityDial`: drop the `costQualityRouting !== true` guard     | `an off dial returns the ladder unchanged with no decision` |
 * | `applyCostQualityDial`: drop the `kept.length === 0` fall-back           | `keeps the whole ladder when every leg lags` |
 * | `applyCostQualityDial`: drop the `canaryPercent === undefined` exemption | `never filters an operator-declared canary` |
 * | `applyCostQualityDial`: return input `routes` instead of `kept`          | `drops the below-floor candidate from the served set` |
 */
import { describe, expect, it } from "vitest";
import type { EstimatedUsage } from "../../src/inference/index.js";
import type { PhysicalRoute } from "../../src/inference/index.js";
import type { RoutingQuality } from "../../src/inference/strategy.js";
import {
  EASY_COMPLETION_TOKEN_CEILING,
  EASY_PROMPT_TOKEN_CEILING,
  ROUTING_NOTE_ALL_BELOW_FLOOR,
  ROUTING_NOTE_HARD_TASK,
  TASK_REASON_LONG_COMPLETION,
  TASK_REASON_LONG_PROMPT,
  TASK_REASON_SHORT,
  TASK_REASON_TOOLS,
  applyCostQualityDial,
  classifyTask,
  renderCostQualityDecision,
} from "../../src/inference/task-routing.js";

const EASY_BODY = { model: "m", messages: [{ role: "user", content: "hi" }] };

function estimate(promptTokens: number): EstimatedUsage {
  return { promptTokens, completionTokens: 1, totalTokens: promptTokens + 1 };
}

function route(provider: string, overrides: Partial<PhysicalRoute> = {}): PhysicalRoute {
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

/** A quality snapshot with the dial ON and a caller-chosen set of lagging legs. */
function dialOn(lagging: readonly string[] = []): RoutingQuality {
  return {
    lags: (r: PhysicalRoute): boolean => lagging.includes(r.provider),
    costQualityRouting: true,
  };
}

describe("classifyTask", () => {
  it("classifies a short single-turn prompt as easy", () => {
    const verdict = classifyTask(EASY_BODY, estimate(10));
    expect(verdict).toEqual({ complexity: "easy", reason: TASK_REASON_SHORT });
  });

  it("classifies a tool-calling request as hard", () => {
    const verdict = classifyTask({ ...EASY_BODY, tools: [{ type: "function" }] }, estimate(10));
    expect(verdict).toEqual({ complexity: "hard", reason: TASK_REASON_TOOLS });
    // Legacy `functions` is the same signal.
    expect(
      classifyTask({ ...EASY_BODY, functions: [{ name: "f" }] }, estimate(10)).complexity,
    ).toBe("hard");
    // ANTI-VACUITY: an EMPTY tools array is not tool use.
    expect(classifyTask({ ...EASY_BODY, tools: [] }, estimate(10)).complexity).toBe("easy");
  });

  it("classifies a long prompt as hard", () => {
    expect(classifyTask(EASY_BODY, estimate(EASY_PROMPT_TOKEN_CEILING + 1)).reason).toBe(
      TASK_REASON_LONG_PROMPT,
    );
  });

  it("treats a prompt exactly at the ceiling as easy", () => {
    // The threshold is `>`, not `>=`: the ceiling itself is still easy.
    expect(classifyTask(EASY_BODY, estimate(EASY_PROMPT_TOKEN_CEILING)).complexity).toBe("easy");
  });

  it("classifies a request asking for a long completion as hard", () => {
    const body = { ...EASY_BODY, max_completion_tokens: EASY_COMPLETION_TOKEN_CEILING + 1 };
    expect(classifyTask(body, estimate(10)).reason).toBe(TASK_REASON_LONG_COMPLETION);
    // The legacy `max_tokens` spelling is read too.
    expect(
      classifyTask({ ...EASY_BODY, max_tokens: EASY_COMPLETION_TOKEN_CEILING + 1 }, estimate(10))
        .complexity,
    ).toBe("hard");
    // ANTI-VACUITY: a small cap is still easy.
    expect(classifyTask({ ...EASY_BODY, max_tokens: 16 }, estimate(10)).complexity).toBe("easy");
  });
});

describe("applyCostQualityDial", () => {
  const routes = [route("cheap"), route("premium")];

  it("an off dial returns the ladder unchanged with no decision", () => {
    // No quality snapshot at all (cold memo / platform operator).
    const cold = applyCostQualityDial({
      routes,
      quality: undefined,
      body: EASY_BODY,
      estimated: undefined,
    });
    expect(cold.routes).toBe(routes);
    expect(cold.strategy).toBeUndefined();
    expect(cold.decision).toBeUndefined();

    // A warm snapshot whose dial is OFF is just as inert.
    const off: RoutingQuality = { lags: () => true, costQualityRouting: false };
    const result = applyCostQualityDial({
      routes,
      quality: off,
      body: EASY_BODY,
      estimated: undefined,
    });
    expect(result.routes).toBe(routes);
    expect(result.decision).toBeUndefined();
  });

  it("drops the below-floor candidate from the served set and forces lowest_cost", () => {
    const result = applyCostQualityDial({
      routes,
      quality: dialOn(["cheap"]),
      body: EASY_BODY,
      estimated: undefined,
    });
    expect(result.routes.map((r) => r.provider)).toEqual(["premium"]);
    expect(result.strategy).toBe("lowest_cost");
    expect(result.decision).toMatchObject({
      applied: true,
      task: "easy",
      eligible: ["premium/gpt-4o-mini"],
      filtered: ["cheap/gpt-4o-mini"],
    });
  });

  it("keeps the whole ladder when every leg lags", () => {
    const result = applyCostQualityDial({
      routes,
      quality: dialOn(["cheap", "premium"]),
      body: EASY_BODY,
      estimated: undefined,
    });
    // A noisy judge score must never be able to refuse a request.
    expect(result.routes).toBe(routes);
    expect(result.strategy).toBeUndefined();
    expect(result.decision).toMatchObject({
      applied: false,
      note: ROUTING_NOTE_ALL_BELOW_FLOOR,
      filtered: [],
    });
  });

  it("never filters an operator-declared canary, even when it lags", () => {
    const withCanary = [route("cheap"), route("premium", { canaryPercent: 100 })];
    const result = applyCostQualityDial({
      routes: withCanary,
      quality: dialOn(["cheap", "premium"]),
      body: EASY_BODY,
      estimated: undefined,
    });
    // `premium` lags but is a canary, so it survives; `cheap` lags and is dropped.
    expect(result.routes.map((r) => r.provider)).toEqual(["premium"]);
    expect(result.decision).toMatchObject({ filtered: ["cheap/gpt-4o-mini"] });
  });

  it("keeps the operator ladder for a hard task and still explains it", () => {
    const result = applyCostQualityDial({
      routes,
      quality: dialOn(["cheap"]),
      body: { ...EASY_BODY, tools: [{ type: "function" }] },
      estimated: undefined,
    });
    expect(result.routes).toBe(routes);
    expect(result.strategy).toBeUndefined();
    expect(result.decision).toMatchObject({
      applied: false,
      task: "hard",
      note: ROUTING_NOTE_HARD_TASK,
    });
  });
});

describe("renderCostQualityDecision", () => {
  it("renders a flat, deterministic line", () => {
    const line = renderCostQualityDecision({
      dialOn: true,
      task: "easy",
      taskReason: TASK_REASON_SHORT,
      applied: true,
      eligible: ["premium/gpt-4o-mini"],
      filtered: ["cheap/gpt-4o-mini"],
    });
    expect(line).toBe(
      "cost_quality task=easy(short_single_turn) applied=true eligible=premium/gpt-4o-mini filtered=cheap/gpt-4o-mini",
    );
  });

  it("renders empty candidate lists as none and includes the note", () => {
    const line = renderCostQualityDecision({
      dialOn: true,
      task: "hard",
      taskReason: TASK_REASON_TOOLS,
      applied: false,
      note: ROUTING_NOTE_HARD_TASK,
      eligible: [],
      filtered: [],
    });
    expect(line).toBe(
      "cost_quality task=hard(tools_requested) applied=false note=hard_task_kept_ladder eligible=none filtered=none",
    );
  });
});
