/**
 * #699 — task-aware auto-routing with a cost/quality dial.
 *
 * ============================================================================
 * WHAT THIS ADDS, AND WHAT IT DELIBERATELY DOES NOT TOUCH
 * ============================================================================
 *
 * `./strategy.ts::orderCandidatesByStrategy` is a PURE, SYNCHRONOUS PERMUTATION
 * of an already-eligible ladder: every one of its four arms returns a
 * reordering of its input and none of them can drop a route (the docstring
 * there, and the `quality-routing.test.ts` case "never drops a leg", pin that).
 * #894 layered a quality signal on as a last-pass DEMOTE — still a permutation,
 * a lagging leg goes to the tail but stays servable.
 *
 * #699 is the first thing that may REMOVE a candidate, and that is exactly why
 * it lives here and not in the strategy sorter: a filter is a different contract
 * from an ordering, and folding it into `orderCandidatesByStrategy` would break
 * the invariant every failover test relies on. `handlers.ts::planUpstream` calls
 * {@link applyCostQualityDial} over the eligible+narrowed candidate set, BEFORE
 * ordering, and only when the tenant turned the dial on.
 *
 * Two pure functions, no I/O, no bindings:
 *
 *  1. {@link classifyTask} — is this request EASY or HARD, from the body and the
 *     pre-dispatch token estimate alone. No model call, no heuristic that needs
 *     a network; a classifier that had to make a request to decide how to route
 *     a request would defeat its own purpose.
 *
 *  2. {@link applyCostQualityDial} — when the dial is on and the task is easy,
 *     drop every below-floor (lagging) candidate and hand the survivors back
 *     tagged `lowest_cost`, so `orderCandidatesByStrategy` serves the CHEAPEST
 *     one that cleared the floor. When the dial is off, or the task is hard, or
 *     dropping would empty the ladder, the candidate set is returned UNCHANGED —
 *     the operator's hand-written order stands.
 *
 * The FLOOR is not a number. It is the SAME relative predicate #894 built
 * (`RoutingQuality.lags`: this leg is `regressionDrop` below the best sibling,
 * with `regressionMinSamples` on both sides), for the reason `src/evals/policy.ts:20-46`
 * gives — an absolute quality score is meaningless across judges and criteria.
 * "Clears the floor" therefore means "is not measurably worse than a sibling",
 * and an UNMEASURED leg clears it (a cost router's whole point is to try the
 * cheap-but-unscored candidate).
 */
import type { EstimatedUsage } from "./estimate.js";
import type { PhysicalRoute } from "./ports.js";
import type { RoutingQuality, RoutingStrategy } from "./strategy.js";

/**
 * The classifier's verdict. Two arms, never three: the dial only ever needs to
 * know whether it is safe to trade quality headroom for cost, and "medium" is
 * not a decision — it is a threshold argument dressed as a category.
 */
export type TaskComplexity = "easy" | "hard";

/** A classifier answer, carrying WHY so the request log can explain it. */
export interface TaskClassification {
  readonly complexity: TaskComplexity;
  /** A stable, log-safe token — never free text; see the `TASK_REASON_*` set. */
  readonly reason: string;
}

/**
 * Above this many ESTIMATED prompt tokens a request is `hard`.
 *
 * A long prompt is the cheapest available proxy for "this needs a capable
 * model": retrieval-augmented answers, long documents to summarise and
 * multi-turn agent transcripts all land here, and none of them is a request an
 * operator wants silently rerouted to the cheapest leg. `2000` is roughly a
 * few pages of text; it is deliberately generous, because the failure that
 * matters is routing a HARD prompt cheap, not leaving an easy one on the
 * operator's ladder.
 */
export const EASY_PROMPT_TOKEN_CEILING = 2000;

/**
 * Above this many REQUESTED completion tokens a request is `hard`.
 *
 * A caller asking for a long generation is asking for sustained coherence,
 * which is where cheaper models fall down first. Read from
 * `max_completion_tokens` (or the legacy `max_tokens`); absent leaves this leg
 * unarmed, which is correct — an unspecified cap is not evidence of a long
 * answer.
 */
export const EASY_COMPLETION_TOKEN_CEILING = 1024;

/** The stable reason tokens, so a reader (and a test) can compare by value. */
export const TASK_REASON_TOOLS = "tools_requested";
export const TASK_REASON_LONG_PROMPT = "long_prompt";
export const TASK_REASON_LONG_COMPLETION = "long_completion";
export const TASK_REASON_SHORT = "short_single_turn";

function nonEmptyArray(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

function finitePositive(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : undefined;
}

/**
 * Classify a request as EASY or HARD from its body and token estimate.
 *
 * PURE: the same inputs always give the same answer, and the answer never
 * depends on anything the request path has to `await`. The order of the checks
 * is the order of confidence — a tool call is the strongest "hard" signal and a
 * short single-turn prompt is the residual "easy" — and the FIRST hard signal
 * wins, so the reason names the strongest reason present.
 */
export function classifyTask(
  body: Record<string, unknown>,
  estimated: EstimatedUsage | undefined,
): TaskClassification {
  // Tool / function calling: the caller is orchestrating, not chatting. The
  // cheapest leg is the one most likely to emit a malformed tool call, and a
  // malformed tool call is not a quality regression a judge would ever score —
  // it is a broken response. So this is `hard` regardless of length.
  if (nonEmptyArray(body["tools"]) || nonEmptyArray(body["functions"])) {
    return { complexity: "hard", reason: TASK_REASON_TOOLS };
  }

  if ((estimated?.promptTokens ?? 0) > EASY_PROMPT_TOKEN_CEILING) {
    return { complexity: "hard", reason: TASK_REASON_LONG_PROMPT };
  }

  const requestedCompletion =
    finitePositive(body["max_completion_tokens"]) ?? finitePositive(body["max_tokens"]);
  if (requestedCompletion !== undefined && requestedCompletion > EASY_COMPLETION_TOKEN_CEILING) {
    return { complexity: "hard", reason: TASK_REASON_LONG_COMPLETION };
  }

  return { complexity: "easy", reason: TASK_REASON_SHORT };
}

/**
 * The explainable routing decision, written to the request log so an operator
 * can answer "why did this request get that model".
 *
 * Only ever produced when the dial is ON — a tenant who did not opt in has an
 * absent `routing_decision` column and a byte-identical log to before #699.
 */
export interface CostQualityDecision {
  /** Always `true` when a decision exists; the field makes the log self-describing. */
  readonly dialOn: boolean;
  readonly task: TaskComplexity;
  readonly taskReason: string;
  /** Whether the candidate set was actually filtered/re-ranked by cost. */
  readonly applied: boolean;
  /** Why the dial did NOT act, when `applied` is false (`hard_task`, `all_below_floor`). */
  readonly note?: string;
  /** The candidates that survived the floor, as `provider/providerModel`. */
  readonly eligible: readonly string[];
  /** The candidates dropped for lagging, as `provider/providerModel`. */
  readonly filtered: readonly string[];
}

export const ROUTING_NOTE_HARD_TASK = "hard_task_kept_ladder";
export const ROUTING_NOTE_ALL_BELOW_FLOOR = "all_below_floor";

/** `provider/providerModel` — the leg label used in the explainable log. */
function legLabel(route: PhysicalRoute): string {
  return `${route.provider}/${route.providerModel}`;
}

export interface CostQualityDialInput {
  readonly routes: readonly PhysicalRoute[];
  /** The peeked quality snapshot, or `undefined` for a cold memo / no tenancy. */
  readonly quality: RoutingQuality | undefined;
  readonly body: Record<string, unknown>;
  readonly estimated: EstimatedUsage | undefined;
}

export interface CostQualityDialResult {
  /** The candidate set to order — narrowed only when the dial fired on an easy task. */
  readonly routes: readonly PhysicalRoute[];
  /** `lowest_cost` when the dial fired; `undefined` leaves the model's own strategy. */
  readonly strategy?: RoutingStrategy | undefined;
  /** The explainable decision, present iff the dial is ON. */
  readonly decision?: CostQualityDecision | undefined;
}

/**
 * Apply the cost/quality dial to an eligible, workflow-narrowed candidate set.
 *
 * Returns the set UNCHANGED (and `decision: undefined`) whenever the dial is
 * off, which is the default and the whole "byte-identical when off" guarantee:
 * a tenant who did not opt in never reaches the classifier, the filter, or the
 * strategy override.
 *
 * ## The two ways the dial is ON but does not act
 *
 *  - **hard task** — the operator's hand-written ladder is exactly what a hard
 *    request should keep, so nothing is filtered and no strategy is forced. The
 *    decision is still emitted (`applied: false`, `note: hard_task_...`) because
 *    "we looked and left it alone" is itself the explanation an operator wants.
 *  - **every leg lags** — dropping them all would leave no route to serve, and a
 *    noisy judge score must never be able to refuse a request (`policy.ts`). So
 *    the whole set is kept, `applied: false`, `note: all_below_floor`.
 *
 * ## Canary is exempt from the filter, for the reason it is exempt from #894's
 * demote (`strategy.ts::demoteLaggingLegs`): filtering an operator-declared
 * canary out would silently cancel a rollout the operator is running precisely
 * to find out whether the new route is worse, and the leg could never recover
 * because a route that stops being served stops accumulating scores.
 */
export function applyCostQualityDial(input: CostQualityDialInput): CostQualityDialResult {
  const { routes, quality } = input;
  if (quality === undefined || quality.costQualityRouting !== true) {
    return { routes };
  }

  const classification = classifyTask(input.body, input.estimated);
  const base = {
    dialOn: true as const,
    task: classification.complexity,
    taskReason: classification.reason,
  };

  if (classification.complexity === "hard") {
    return {
      routes,
      decision: {
        ...base,
        applied: false,
        note: ROUTING_NOTE_HARD_TASK,
        eligible: routes.map(legLabel),
        filtered: [],
      },
    };
  }

  const kept: PhysicalRoute[] = [];
  const filtered: PhysicalRoute[] = [];
  for (const route of routes) {
    if (route.canaryPercent === undefined && quality.lags(route)) filtered.push(route);
    else kept.push(route);
  }

  if (kept.length === 0) {
    return {
      routes,
      decision: {
        ...base,
        applied: false,
        note: ROUTING_NOTE_ALL_BELOW_FLOOR,
        eligible: routes.map(legLabel),
        filtered: [],
      },
    };
  }

  return {
    routes: kept,
    strategy: "lowest_cost",
    decision: {
      ...base,
      applied: true,
      eligible: kept.map(legLabel),
      filtered: filtered.map(legLabel),
    },
  };
}

/**
 * Render a {@link CostQualityDecision} to the single compact TEXT line the request
 * log stores. Deterministic and flat — a log column is text, and a structured
 * blob would need a decision about shape at both the writer and every reader.
 */
export function renderCostQualityDecision(decision: CostQualityDecision): string {
  const parts = [
    "cost_quality",
    `task=${decision.task}(${decision.taskReason})`,
    `applied=${decision.applied}`,
  ];
  if (decision.note !== undefined) parts.push(`note=${decision.note}`);
  parts.push(`eligible=${decision.eligible.join(",") || "none"}`);
  parts.push(`filtered=${decision.filtered.join(",") || "none"}`);
  return parts.join(" ");
}
