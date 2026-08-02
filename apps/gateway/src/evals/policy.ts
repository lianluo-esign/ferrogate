/**
 * The per-tenant ONLINE-EVALUATION policy and the pure sampling decision it
 * produces. No I/O, no bindings, no Hono.
 *
 * ============================================================================
 * WHAT A SCORE FROM THIS SLICE MEANS — AND WHAT IT CANNOT MEAN
 * ============================================================================
 *
 * This is written at the top of the first file a reader opens because a number
 * presented as "quality" that is actually a proxy is worse than no number: it
 * will be used to make rollout decisions, and nothing downstream will remind
 * anyone what it measured.
 *
 * **There is no ground truth in production.** Nobody knows the right answer to
 * the request a customer just made; if anybody did, the gateway would have
 * served it. So what is produced here is NOT accuracy, NOT correctness and NOT
 * "quality". It is one model's judgement, under a criterion the TENANT wrote,
 * of a response it did not produce.
 *
 * Concretely, a score in `online_eval_scores` means exactly:
 *
 *   > The judge model `judge_model`, shown this prompt and this response and
 *   > asked criterion `criterion_id`, answered with this number at this time.
 *
 * That supports exactly one class of inference, and it is the one the issue
 * asks for: **a RELATIVE comparison between two populations scored by the SAME
 * judge under the SAME criteria** — before vs after a model swap, canary vs
 * control, one route vs another. It is a difference-in-differences instrument.
 *
 * It does NOT support, and an operator must not act as if it does:
 *
 *  - **an absolute claim.** "Our quality is 0.82" is meaningless: judges are
 *    biased, they systematically prefer longer answers, answers in their own
 *    family's style, and answers that agree with the prompt's framing.
 *  - **a comparison across judges or across criteria wordings.** Changing the
 *    judge model or editing a criterion RESETS the series. The score row
 *    therefore carries `judge_model` and `criterion_id` as grouping keys, and
 *    a reader that averages across them is averaging two different instruments.
 *  - **a per-request verdict about one customer's answer.** The sample is a
 *    fraction of traffic and the judge is noisy per item; the signal lives in
 *    the aggregate. Do not page anyone because one request scored 0.2, and do
 *    not show a single score to an end user as a quality badge.
 *  - **a safety or compliance control.** Guardrails (#665/#688) are the control
 *    that decides; this is a measurement taken after the fact on a sample. A
 *    regression here is a reason to LOOK, not a reason to believe.
 *
 * The regression detector in `./regression.ts` is deliberately built on exactly
 * the one inference this instrument supports: same tenant, same criterion, same
 * judge, same logical model, two time windows, with a minimum sample count on
 * both sides.
 *
 * ============================================================================
 * SAMPLING IS PER-TENANT OPT-IN, AND THE DEFAULT IS OFF
 * ============================================================================
 *
 * Evaluating a customer's traffic copies their prompts and their model's
 * responses to a judge model and stores a derived record of both. That is a new
 * data flow over regulated content, so it is not a fleet default and cannot be
 * turned on for a tenant from anywhere except that tenant's own governance row.
 * {@link onlineEvalSamplingDecision} answers `not_opted_in` for a tenant with no
 * policy, a disabled policy, or a policy this module could not parse.
 *
 * And a **zero-data-retention tenant is never sampled**, whatever its own eval
 * policy says (#681). ZDR is a promise that the content of a request is not
 * retained anywhere; shipping the prompt to a judge and writing a scored row
 * derived from it breaks that promise, and doing so because a second control was
 * switched on is precisely the "silently sampled" failure the brief names. The
 * skip is a DISTINCT reason rather than a silent non-sample, so an operator
 * looking at an empty score table can tell the two apart.
 *
 * Region gating is treated differently and deliberately so: it does not forbid
 * evaluation, it constrains WHERE the judge may run. That is enforced per judge
 * route in `./consumer.ts` with the same `residencyViolations` function route
 * eligibility uses, rather than by refusing to sample here — refusing here would
 * turn a region policy into a silent opt-out from a control the tenant asked
 * for.
 */
import type { ResidencyPolicy } from "../residency/policy.js";
import { sampleBucket } from "./sampling.js";

/**
 * What the sample is a sample OF.
 *
 * `request` — each request is bucketed independently. Cheap, unbiased across
 * requests, and unable to answer any question about a CONVERSATION, because two
 * turns of one conversation land on opposite sides of the sample.
 *
 * `conversation` — the bucket is taken on a conversation key, so a conversation
 * is sampled whole or not at all. This is what makes "did this conversation get
 * worse after the swap" answerable, and it is the unit anyone comparing a
 * multi-turn agent against itself needs.
 *
 * There is no `session` third spelling: the conversation key is resolved from
 * whatever stable identity the request already carries (see
 * `./middleware.ts::conversationKeyFor`), and adding a second name for the same
 * bucket would let two policies mean the same thing and be compared as if they
 * did not.
 */
export type OnlineEvalSamplingUnit = "request" | "conversation";

/** One thing the judge is asked about a sampled exchange. */
export interface OnlineEvalCriterion {
  /**
   * The stable grouping key a score is filed under, and the axis a trend is
   * read along. It is the tenant's own string: renaming it starts a new series
   * rather than continuing the old one, which is correct — a renamed criterion
   * is usually a re-worded criterion, and that is a different instrument.
   */
  readonly id: string;
  /** The question, verbatim, as it is put to the judge. */
  readonly definition: string;
}

/** One tenant's online-evaluation policy. */
export interface OnlineEvalPolicy {
  /** OPT-IN. Never defaulted true anywhere in this slice. */
  readonly enabled: boolean;
  /** Fraction of the sampling unit to evaluate, in [0, 1]. */
  readonly sampleRate: number;
  readonly samplingUnit: OnlineEvalSamplingUnit;
  /**
   * The measuring instrument. Required: choosing a judge for the tenant would
   * make the meaning of their scores depend on a default they never agreed to,
   * and would silently change it the day the default changed.
   */
  readonly judgeModel: string;
  readonly criteria: readonly OnlineEvalCriterion[];
  /**
   * How far the mean may fall between the baseline window and the recent one
   * before `./regression.ts` records a regression. Per TENANT rather than per
   * fleet because the noise floor of a judge depends on the criteria wording,
   * which is the tenant's.
   */
  readonly regressionDrop: number;
  /** Minimum scored samples in BOTH windows before a drop is believed. */
  readonly regressionMinSamples: number;
}

/** Defaults for the two regression knobs, applied when a row omits them. */
export const DEFAULT_REGRESSION_DROP = 0.1;
export const DEFAULT_REGRESSION_MIN_SAMPLES = 20;

/**
 * The columns/fields a policy row supplies, before validation. Deliberately
 * `unknown`-typed: the same parser reads a D1 row (SQLite integers for
 * booleans, TEXT for JSON) and a Worker var (already-parsed JSON).
 */
export interface OnlineEvalPolicyRow {
  readonly enabled?: unknown;
  readonly sampleRate?: unknown;
  readonly samplingUnit?: unknown;
  readonly judgeModel?: unknown;
  readonly criteria?: unknown;
  readonly regressionDrop?: unknown;
  readonly regressionMinSamples?: unknown;
}

/**
 * `policy: null` is "this tenant did not opt in" and is a COMPLETE answer.
 * `ok: false` is "the row says it opted in and then failed to say how", which is
 * a different thing and must not collapse into either "opted in" or "did not".
 */
export type ParsedOnlineEvalPolicy =
  | { readonly ok: true; readonly policy: OnlineEvalPolicy | null }
  | { readonly ok: false; readonly detail: string };

function truthy(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const lowered = value.trim().toLowerCase();
    return lowered === "1" || lowered === "true" || lowered === "yes" || lowered === "on";
  }
  return false;
}

function finiteNumber(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

/** Parse `criteria`, refusing anything a judge could not be asked. */
function parseCriteria(value: unknown): OnlineEvalCriterion[] | string {
  if (!Array.isArray(value)) return "criteria must be an array";
  const criteria: OnlineEvalCriterion[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) return "each criterion must be an object";
    const id = (entry as { id?: unknown }).id;
    const definition = (entry as { definition?: unknown }).definition;
    if (typeof id !== "string" || id.trim() === "") return "each criterion needs a non-empty id";
    if (typeof definition !== "string" || definition.trim() === "") {
      // A criterion with an id and no definition is the shape that produces a
      // number nobody can interpret: the column would say `helpfulness` and
      // nothing anywhere would record what the judge was actually asked.
      return `criterion '${id}' has no definition`;
    }
    if (seen.has(id)) return `duplicate criterion id '${id}'`;
    seen.add(id);
    criteria.push({ id: id.trim(), definition: definition.trim() });
  }
  return criteria;
}

/**
 * Read one governance row into a policy.
 *
 * FAILS CLOSED in the direction that matters: an unreadable policy yields
 * `ok: false`, which every caller turns into "do not sample". Sampling a tenant
 * whose opt-in could not be read is the one outcome that cannot be undone —
 * the prompt has already been copied.
 */
export function parseOnlineEvalPolicyRow(row: OnlineEvalPolicyRow): ParsedOnlineEvalPolicy {
  const enabled = truthy(row.enabled);
  const hasAnything =
    row.sampleRate !== undefined || row.judgeModel !== undefined || row.criteria !== undefined;
  if (!enabled && !hasAnything) return { ok: true, policy: null };
  if (!enabled) {
    // The row exists and is switched OFF. That is a complete answer, and it is
    // "not opted in" — a disabled policy is not a misconfiguration.
    return { ok: true, policy: null };
  }

  const sampleRate = finiteNumber(row.sampleRate);
  if (sampleRate === undefined || sampleRate < 0 || sampleRate > 1) {
    return { ok: false, detail: `sample rate must be a number in [0, 1], got ${row.sampleRate}` };
  }

  const unitRaw = row.samplingUnit;
  const samplingUnit: OnlineEvalSamplingUnit =
    unitRaw === undefined || unitRaw === null || unitRaw === ""
      ? "request"
      : unitRaw === "request" || unitRaw === "conversation"
        ? unitRaw
        : "invalid";
  if (samplingUnit === ("invalid" as OnlineEvalSamplingUnit)) {
    return { ok: false, detail: `sampling unit must be 'request' or 'conversation'` };
  }

  const judgeModel = row.judgeModel;
  if (typeof judgeModel !== "string" || judgeModel.trim() === "") {
    return { ok: false, detail: "an enabled policy must name a judge model" };
  }

  const criteria = parseCriteria(row.criteria);
  if (typeof criteria === "string") return { ok: false, detail: criteria };

  const regressionDrop = finiteNumber(row.regressionDrop) ?? DEFAULT_REGRESSION_DROP;
  if (regressionDrop <= 0 || regressionDrop > 1) {
    return { ok: false, detail: `regression drop must be in (0, 1], got ${row.regressionDrop}` };
  }
  const regressionMinSamples =
    finiteNumber(row.regressionMinSamples) ?? DEFAULT_REGRESSION_MIN_SAMPLES;
  if (!Number.isInteger(regressionMinSamples) || regressionMinSamples < 1) {
    return { ok: false, detail: "regression min samples must be a positive integer" };
  }

  return {
    ok: true,
    policy: {
      enabled: true,
      sampleRate,
      samplingUnit,
      judgeModel: judgeModel.trim(),
      criteria,
      regressionDrop,
      regressionMinSamples,
    },
  };
}

/**
 * Why a request was NOT sampled. Every arm is distinguishable on purpose: an
 * operator staring at an empty score table needs to know whether the sampler
 * excluded this tenant deliberately (`zero_data_retention`), the tenant never
 * asked (`not_opted_in`), the configuration is broken (`no_criteria`), or the
 * sampler simply did its job (`not_in_sample`).
 */
export type OnlineEvalSkipReason =
  | "not_opted_in"
  | "no_criteria"
  | "zero_data_retention"
  | "no_conversation_key"
  | "not_in_sample";

export type OnlineEvalSamplingDecision =
  | {
      readonly sampled: true;
      /** The key the bucket was taken on — the request id or the conversation. */
      readonly samplingKey: string;
      readonly rate: number;
      readonly unit: OnlineEvalSamplingUnit;
    }
  | { readonly sampled: false; readonly reason: OnlineEvalSkipReason };

export interface OnlineEvalSamplingInput {
  readonly policy: OnlineEvalPolicy | null;
  /** The tenant's #681 residency policy, or `null` when it is not governed. */
  readonly residency: ResidencyPolicy | null;
  readonly requestId: string;
  /** A stable conversation identity, when the request carries one. */
  readonly conversationKey?: string | undefined;
}

/**
 * Should this request be evaluated?
 *
 * PURE and synchronous — the whole point, because this runs on the request path
 * (see `./middleware.ts`) and the only thing allowed to happen there is
 * arithmetic. The gate ORDER is load-bearing: opt-in, then ZDR, then
 * configuration, then the bucket. Checking the bucket first would be cheaper and
 * would report `not_in_sample` for a ZDR tenant 90% of the time, hiding the
 * exclusion that actually applies.
 */
export function onlineEvalSamplingDecision(
  input: OnlineEvalSamplingInput,
): OnlineEvalSamplingDecision {
  const { policy, residency } = input;
  if (policy === null || !policy.enabled) return { sampled: false, reason: "not_opted_in" };

  // ZDR BEFORE anything the tenant configured. A tenant that bought zero data
  // retention does not get its prompts copied to a judge because someone also
  // switched evaluation on; see the module docs.
  if (residency?.requireZeroDataRetention === true) {
    return { sampled: false, reason: "zero_data_retention" };
  }

  if (policy.criteria.length === 0) return { sampled: false, reason: "no_criteria" };

  const key =
    policy.samplingUnit === "conversation"
      ? (input.conversationKey ?? "")
      : (input.requestId ?? "");
  if (key === "") {
    // Under the conversation unit with nothing stable to bucket on, the honest
    // answer is "not sampled", never "fall back to the request id": that would
    // sample a random slice of every conversation instead of a stable slice of
    // conversations, and the resulting series cannot be compared to itself.
    return {
      sampled: false,
      reason: policy.samplingUnit === "conversation" ? "no_conversation_key" : "not_in_sample",
    };
  }

  // `rate <= 0` short-circuits so a zero-rate policy costs no hash, and
  // `bucket < rate` (not `<=`) keeps rate 0 empty and rate 1 total, since the
  // bucket is in [0, 1).
  if (policy.sampleRate <= 0) return { sampled: false, reason: "not_in_sample" };
  if (policy.sampleRate < 1 && sampleBucket(key) >= policy.sampleRate) {
    return { sampled: false, reason: "not_in_sample" };
  }

  return { sampled: true, samplingKey: key, rate: policy.sampleRate, unit: policy.samplingUnit };
}
