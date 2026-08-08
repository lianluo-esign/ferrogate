/**
 * SCORING THE ARM NOBODY WAS SERVED — how a shadow mirror's response reaches
 * the judge (#693, on top of #692).
 *
 * ============================================================================
 * THE DEFECT THIS FILE CLOSES
 * ============================================================================
 *
 * `#693`'s first cut gave the shadow arm cost, latency and an error rate and no
 * eval score, because `servedArmFor` can only ever answer `control` or `canary`
 * — a mirror is stripped from the servable ladder, so no served response can
 * come from it, so `facts.experimentArm` was never `shadow` and no row in
 * `online_eval_scores` ever carried that arm. A control+shadow experiment
 * therefore reported `comparisons: []` and one `variant_arm_not_scored` cell:
 * the operator learned what the variant COST and never whether it was BETTER,
 * which is the only question a shadow experiment exists to answer.
 *
 * ============================================================================
 * THE SHAPE — TWO ONE-WAY SIGNALS ON THE SAME `Request`
 * ============================================================================
 *
 * ```
 *  onlineEvaluation()  ──(1) requestShadowEvalRetention(req) ──┐  BEFORE next()
 *        │                                                     │
 *        └── next() ─→ inference router ─→ spawnShadowMirror ──┘
 *                            │      publishShadowEvalLeg(req, leg)  (2)
 *                            └── runShadowMirror ─→ leg.body resolves
 *        ┌────────────────────────────────────────────────────────┘
 *  onlineEvaluation()'s DEFERRED half:  await leg.body
 *                                       shadowArmSampleFrom(servedSample, leg)
 *                                       sink.enqueue(...)
 * ```
 *
 * **(1) is a REQUEST, and it is the retention gate.** The mirror's response is
 * discarded by design; it is retained ONLY when `onlineEvalCapturePlan` already
 * said this exchange's content may be captured. So a tenant that did not opt
 * in, a ZERO-DATA-RETENTION tenant, a tenant with no criteria and a request the
 * sampler did not select all leave the mirror exactly as it was — read under
 * the byte cap for its token counts and dropped. Retaining first and deciding
 * later would mean holding a third copy of every mirrored completion in the
 * isolate for traffic nobody was ever allowed to score.
 *
 * **(2) is the retained response**, published as a PROMISE because the mirror
 * is fire-and-forget: it is spawned during `next()` and is normally still in
 * flight when the response is flushed. The deferred half awaits it inside the
 * same `ctx.waitUntil` window the mirror itself lives in, so nothing here is in
 * front of a client byte.
 *
 * Both signals ride a `WeakMap`/`WeakSet` keyed by the OUTER inbound `Request`,
 * the same device `requestlog/facts.ts` and `inference/identity.ts` use and for
 * the reasons they give: a module-scoped "current request" slot is a
 * cross-request leak the moment two requests interleave on an `await`, and a
 * wrapper `env` would defeat the `WeakMap`-by-env memoization the model
 * registry relies on.
 *
 * ============================================================================
 * THE COMPARABILITY RULE IS INHERITED, NOT PARALLELED
 * ============================================================================
 *
 * This is the constraint that decides the whole design. A comparison between
 * two arms is legitimate only between populations scored by the SAME judge
 * under the SAME criterion (`./policy.ts` states the full reading), and
 * `compareExperimentQuality` enforces it structurally by grouping on
 * `(judge_model, criterion_id)` and refusing to pair across groups.
 *
 * A shadow path that resolved its own policy would satisfy that rule *usually*
 * — same tenant, same source — and violate it exactly when it matters: the
 * moment a policy is edited between the served leg and the mirrored one, the
 * two arms would be scored by two instruments and the report would show a
 * difference that is partly an instrument change. The refusal would still fire,
 * so nothing would be WRONG, but a comparison that silently stops being
 * possible is a feature that silently stops working.
 *
 * So {@link shadowArmSampleFrom} does not resolve anything. It takes the
 * SERVED sample object and replaces the four fields that are genuinely
 * different — the leg id, the provider identity, the completion and the arm —
 * and copies everything else BY VALUE. `judge_model`, `criteria`,
 * `sampling_key`, `sample_rate`, the prompt and the tenancy axes are therefore
 * not "the same by construction", they are the same VALUES. There is no code
 * path by which the two arms of one request can be scored differently, because
 * there is no second decision.
 *
 * The corollary is that the two arms are a PAIRED sample on one prompt, which
 * is a stronger comparison than two independent populations — and it is free,
 * because the mirror is by definition the same request sent twice.
 *
 * ============================================================================
 * WHAT A SHADOW SCORE ROW MEANS — #692'S HONESTY RULE, UNCHANGED
 * ============================================================================
 *
 * A row still means exactly:
 *
 *   > the judge `judge_model`, shown this prompt and THIS response and asked
 *   > criterion `criterion_id`, answered `score` at `scored_at_unix`.
 *
 * The shadow arm claims no exemption. The response it was shown is the one the
 * mirrored provider produced and NO CLIENT RECEIVED — which is a fact about the
 * population, not about the instrument, and is exactly what `experiment_arm`
 * records. It supports the same single inference: a relative comparison against
 * the control population scored by the same judge under the same criterion.
 *
 * Three things it deliberately does NOT do:
 *
 *  - **It stores no content.** Same as every other score row: prompt and
 *    completion exist in flight only (`0009_online_eval.sql` has no column for
 *    either), and the mirrored completion is dropped once the sample is on the
 *    queue.
 *  - **It is not scored when the mirror did not answer 200.** A refusal has no
 *    answer to judge, and scoring error envelopes would drag the arm's mean
 *    down whenever the mirrored provider had a bad hour — turning a reliability
 *    problem into a fake quality regression. That is the SAME rule
 *    `./middleware.ts::evaluableResponse` applies to the served arm; the leg's
 *    failure is still recorded operationally in `experiment_shadow_legs`, so
 *    the arm's error rate is unaffected by this.
 *  - **It is filed under the LEG id**, `{clientRequestId}~shadow`, never under
 *    the client's request id. `online_eval_scores`' primary key is
 *    `(request_id, criterion_id)`, so a shadow score filed under the client's
 *    id would OVERWRITE the served arm's score for the same criterion — one arm
 *    silently deleting the other's evidence. The leg id is the same one
 *    `experiment_shadow_legs.leg_id` carries, which is what makes a shadow
 *    score joinable to the shadow leg's cost and latency.
 */
import { captureHead, completionTextFrom } from "./content.js";
import type { OnlineEvalSample } from "./record.js";

/**
 * The arm a sample built here is filed under.
 *
 * A constant rather than a literal at the one use site because
 * `packages/routing::ExperimentArm` is the authority on the spelling and this
 * module must not import the routing package (it is loaded by the request-path
 * middleware). `test/experiments/shadow-scored.test.ts` pins the string against
 * what the reporting surface groups on.
 */
export const SHADOW_EVAL_ARM = "shadow";

/**
 * One mirrored dispatch, published by the inference router for the sampler to
 * pick up.
 *
 * The identity fields are the MIRROR's, not the served route's: a sample
 * carrying the primary's provider under the shadow label would be an arm
 * measured with the other arm's facts, which is worse than an unmeasured arm.
 */
export interface ShadowEvalLeg {
  /** `{clientRequestId}~shadow` — the id the leg row is filed under. */
  readonly legId: string;
  readonly experimentId: string;
  readonly logicalModel: string;
  readonly provider: string;
  readonly providerModel: string;
  /**
   * The mirrored provider's response body, verbatim, or `undefined` when there
   * is nothing to score (the mirror failed, was refused by the budget, or did
   * not answer 200).
   *
   * NEVER REJECTS and ALWAYS SETTLES: `runShadowMirror` resolves it from a
   * `finally`, because the sampler awaits it from inside `ctx.waitUntil` and a
   * promise that never settled would hold the isolate open until the platform
   * killed it.
   */
  readonly body: Promise<string | undefined>;
}

/**
 * Requests whose mirrored response may be retained for scoring.
 *
 * A `WeakSet` rather than a flag on the leg map because the two signals travel
 * in OPPOSITE directions and at different times: this one is written before
 * `next()` by the sampler and read during `next()` by the inference wiring,
 * while {@link publishShadowEvalLeg} is written during `next()` and read after
 * it. One structure serving both would have to distinguish "not asked" from
 * "asked, nothing published yet".
 */
const RETENTION_REQUESTED = new WeakSet<Request>();

/** The published leg, one per request at most. */
const LEGS = new WeakMap<Request, ShadowEvalLeg>();

/**
 * "This exchange's content may be captured, so the mirror's response may be
 * retained too."
 *
 * Called by `./middleware.ts` only inside the `plan.capture` branch — i.e. only
 * once `onlineEvalCapturePlan` has cleared opt-in, ZDR, criteria and the sample
 * bucket. That is the whole retention gate; see the module docs on why it is a
 * request rather than an unconditional retain.
 */
export function requestShadowEvalRetention(request: Request): void {
  try {
    RETENTION_REQUESTED.add(request);
  } catch {
    // A `WeakSet` rejects a non-object key. A unit test calling a handler
    // directly loses the shadow sample, never the request.
  }
}

/** Has the sampler asked for this request's mirror to be retained? */
export function shadowEvalRetentionRequested(request: Request): boolean {
  try {
    return RETENTION_REQUESTED.has(request);
  } catch {
    return false;
  }
}

/** Publish the mirror the inference router spawned for this request. */
export function publishShadowEvalLeg(request: Request, leg: ShadowEvalLeg): void {
  try {
    LEGS.set(request, leg);
  } catch {
    // As above: best-effort at the seam, never a failed request.
  }
}

/** The mirror published for this request, or `undefined` when there was none. */
export function shadowEvalLegFor(request: Request): ShadowEvalLeg | undefined {
  try {
    return LEGS.get(request);
  } catch {
    return undefined;
  }
}

/**
 * The SHADOW arm's sample, derived from the served arm's.
 *
 * `undefined` — meaning "there is nothing honest to score" — when the mirror
 * produced no body, when the body is not JSON, or when `completionTextFrom`
 * cannot read an answer out of it. None of those may become an empty string: an
 * empty completion handed to a judge produces a confident score of nothing.
 *
 * See the module docs for why every other field is COPIED rather than resolved.
 */
export function shadowArmSampleFrom(
  served: OnlineEvalSample,
  leg: ShadowEvalLeg,
  body: string | undefined,
): OnlineEvalSample | undefined {
  if (body === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
  const completion = completionTextFrom(parsed);
  if (completion === undefined) return undefined;
  // The SAME ceiling and the same marker the served arm's completion gets. A
  // shadow arm captured under a different bound would be shown to the judge in
  // a different amount of detail from the control, and judges systematically
  // prefer longer answers.
  const captured = captureHead(completion);

  return {
    ...served,
    requestId: leg.legId,
    provider: leg.provider,
    logicalModel: leg.logicalModel,
    providerModel: leg.providerModel,
    experimentId: leg.experimentId,
    experimentArm: SHADOW_EVAL_ARM,
    completion: captured.text,
    completionTruncated: captured.truncated,
  };
}

// ---------------------------------------------------------------------------
// #894 — CANDIDATE COVERAGE, the same three seams one level over
// ---------------------------------------------------------------------------

/**
 * The arm a coverage sample is filed under.
 *
 * DISTINCT from {@link SHADOW_EVAL_ARM} on purpose. `shadow` means "the mirror
 * an EXPERIMENT declared", and the experiment reporting surface
 * (`apps/control-plane/src/routes/admin_experiment.ts::QUALITY_AGGREGATE_SQL`,
 * which groups on `experiment_arm`) — so
 * filing coverage under `shadow` would make a phantom third population appear
 * inside a real experiment's comparison. A coverage row carries no experiment at
 * all: it is a measurement of a ROUTING candidate, read by
 * `./leg-quality.ts` along `(provider, provider_model)`, and experiment
 * reporting must not see it.
 */
export const COVERAGE_EVAL_ARM = "coverage";

/**
 * One coverage mirror, published by the inference router.
 *
 * Structurally {@link ShadowEvalLeg} minus `experimentId`, and that absence is
 * the point — see {@link COVERAGE_EVAL_ARM}.
 */
export interface CoverageEvalLeg {
  /** `{clientRequestId}~coverage~{provider}:{providerModel}`. */
  readonly legId: string;
  readonly logicalModel: string;
  readonly provider: string;
  readonly providerModel: string;
  /** The mirrored body, or `undefined`. NEVER rejects; ALWAYS settles. */
  readonly body: Promise<string | undefined>;
}

/**
 * The tenant's coverage percentage for THIS request.
 *
 * Written by `./middleware.ts` inside the same `plan.capture` branch that calls
 * {@link requestShadowEvalRetention}, so coverage inherits the entire retention
 * gate rather than re-deciding any part of it: a request the sampler refused
 * carries no percentage, and the router therefore mirrors nothing for coverage.
 */
const COVERAGE_PERCENTS = new WeakMap<Request, number>();

/** The published coverage legs — plural, one per covered candidate. */
const COVERAGE_LEGS = new WeakMap<Request, CoverageEvalLeg[]>();

export function requestCoverageEval(request: Request, coveragePercent: number): void {
  if (!(coveragePercent > 0)) return;
  try {
    COVERAGE_PERCENTS.set(request, coveragePercent);
  } catch {
    // A `WeakMap` rejects a non-object key. Costs the coverage sample, never
    // the request — the same reading `requestShadowEvalRetention` takes.
  }
}

/** `0` — i.e. OFF — for every request the sampler did not clear. */
export function coverageEvalPercentFor(request: Request): number {
  try {
    return COVERAGE_PERCENTS.get(request) ?? 0;
  } catch {
    return 0;
  }
}

export function publishCoverageEvalLeg(request: Request, leg: CoverageEvalLeg): void {
  try {
    const legs = COVERAGE_LEGS.get(request) ?? [];
    legs.push(leg);
    COVERAGE_LEGS.set(request, legs);
  } catch {
    // Best-effort at the seam, never a failed request.
  }
}

/** Every coverage leg published for this request, oldest first. */
export function coverageEvalLegsFor(request: Request): readonly CoverageEvalLeg[] {
  try {
    return COVERAGE_LEGS.get(request) ?? [];
  } catch {
    return [];
  }
}

/**
 * The COVERAGE arm's sample, derived from the served arm's.
 *
 * Identical in construction to {@link shadowArmSampleFrom} — same ceiling, same
 * `undefined`-on-nothing-honest-to-score rule — and different in exactly two
 * fields: the arm, and the experiment identity, which is DROPPED rather than
 * copied. A coverage leg that inherited the served request's `experiment_id`
 * would be counted by the experiment comparator as a third arm of an experiment
 * it was never part of.
 */
export function coverageArmSampleFrom(
  served: OnlineEvalSample,
  leg: CoverageEvalLeg,
  body: string | undefined,
): OnlineEvalSample | undefined {
  if (body === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
  const completion = completionTextFrom(parsed);
  if (completion === undefined) return undefined;
  const captured = captureHead(completion);

  const { experimentId: _experimentId, ...rest } = served;
  return {
    ...rest,
    requestId: leg.legId,
    provider: leg.provider,
    logicalModel: leg.logicalModel,
    providerModel: leg.providerModel,
    experimentArm: COVERAGE_EVAL_ARM,
    completion: captured.text,
    completionTruncated: captured.truncated,
  };
}

/** `{clientRequestId}~coverage~{provider}:{providerModel}` — the leg's id. */
export function coverageLegId(
  clientRequestId: string,
  provider: string,
  providerModel: string,
): string {
  // The candidate identity is IN the id because `online_eval_scores` is keyed
  // `(request_id, criterion_id)`: two coverage legs on one request under a
  // shared `{id}~coverage` would silently overwrite each other's score and the
  // second candidate would look unmeasured.
  return `${clientRequestId}~coverage~${provider}:${providerModel}`;
}
