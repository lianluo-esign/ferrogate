/**
 * `onlineEvaluation()` — the sampling hook on the gateway's response path.
 *
 * ============================================================================
 * THE ONE PROPERTY THIS FILE EXISTS TO GUARANTEE
 * ============================================================================
 *
 * **The caller's latency is untouched, and no judge token is spent while a
 * client is waiting.** Everything this middleware does before `next()` is
 * arithmetic on already-resolved values: one memo lookup (`policies.peek`,
 * which by construction does no I/O), one hash, and — only when the request has
 * already been SELECTED — one `Request.clone()`, which tees a stream and reads
 * nothing.
 *
 * Everything else happens inside `ctx.waitUntil`, after the response object
 * exists: reading the cloned bodies, parsing them, extracting the transcript,
 * serializing the envelope and handing it to the Queue. The JUDGE does not run
 * here at all — it runs in a different Worker invocation, driven by the queue
 * consumer (`./consumer.ts`), which is what makes "evaluation costs money and
 * time" a background cost rather than a tail-latency regression.
 *
 * `test/evals/middleware.test.ts` holds this directly: with a queue whose
 * `send` never settles, the client's response is returned and its body is
 * readable, and the enqueue is proven to happen strictly after the handler
 * returned.
 *
 * ============================================================================
 * WHY THE DECISION IS TAKEN IN TWO PLACES
 * ============================================================================
 *
 * A request body can only be cloned before the inner app consumes it. The
 * bucket is nevertheless drawn EXACTLY ONCE — see
 * `./policy.ts::onlineEvalCapturePlan`, which explains why drawing it twice
 * would turn a configured 10% into a measured 1% with nothing to show for it.
 *
 * ## The cold-isolate hole, stated
 *
 * `policies.peek()` answers only from the isolate memo. On the first request an
 * isolate serves for a tenant the memo is empty, nothing is captured, and the
 * deferred half warms it for the next request. So a cold isolate UNDER-samples.
 * That is the deliberate trade: the alternative is a D1 read in front of every
 * client response — a latency regression on 100% of traffic in order to measure
 * a few percent of it. Under-sampling shrinks the sample without biasing which
 * KEYS are in it, because the hash is unchanged.
 *
 * ============================================================================
 * WHAT IS NOT SAMPLED, AND WHY EACH ONE IS A COUNTED SKIP
 * ============================================================================
 *
 *  - **Anything that is not a completion-shaped operation.** A score needs a
 *    prompt and a response; `listModels` has neither.
 *  - **Anything that did not answer 200.** A refusal has no answer to judge, and
 *    scoring error envelopes would drag every mean down whenever the upstream
 *    had a bad hour — turning a reliability incident into a fake quality
 *    regression.
 *  - **Streamed responses.** Reassembling an SSE body means buffering the whole
 *    stream in the isolate for every sampled request; naive bounding would
 *    silently over-represent short answers. Counted as `response_not_evaluable`
 *    rather than quietly dropped, because a deployment whose traffic is
 *    entirely streamed would otherwise see an empty score table and no reason.
 *  - **A response whose body this gateway cannot parse as one of the three
 *    ingress dialects** (`./content.ts`).
 */
import type { Context, MiddlewareHandler } from "hono";
import { isEventStream } from "../middleware/body-completion.js";
import type { AuthContext, GatewayEnv } from "../ports.js";
import { requestLogFactsFor } from "../requestlog/facts.js";
import { residencyPolicyFor } from "../residency/carrier.js";
import { captureHead, captureTail, completionTextFrom, promptTranscriptFrom } from "./content.js";
import {
  type OnlineEvalPolicy,
  onlineEvalCapturePlan,
  onlineEvalSamplingDecision,
} from "./policy.js";
import type { OnlineEvalSample } from "./record.js";
import {
  coverageArmSampleFrom,
  coverageEvalLegsFor,
  requestCoverageEval,
  requestShadowEvalRetention,
  shadowArmSampleFrom,
  shadowEvalLegFor,
} from "./shadow-leg.js";
import type { OnlineEvalSink } from "./sink.js";
import { warmLegQuality } from "./quality-source.js";
import {
  type OnlineEvalBindings,
  type OnlineEvalPolicySource,
  onlineEvalPolicySourceFromEnv,
} from "./source.js";

/**
 * The operations an online evaluation can be taken on: the three that produce a
 * natural-language ANSWER to a natural-language PROMPT.
 *
 * `createEmbedding`, `createRerank` and the audio family are absent on purpose.
 * A judge model cannot say anything meaningful about an embedding vector, and a
 * score column filled from one would be a number with no referent — the exact
 * failure mode `./policy.ts` opens by warning about. `createImage` is absent for
 * the same reason plus a practical one: judging it needs a multimodal judge and
 * a decision about shipping image bytes to it, which is a different slice.
 */
export const ONLINE_EVAL_OPERATION_IDS: readonly string[] = [
  "createChatCompletion",
  "createResponse",
  "createMessage",
];

/**
 * The header a client may use to say which conversation a request belongs to.
 *
 * Client-declared, and that is safe here: the only thing it can influence is
 * which bucket this request falls in, and a caller gains nothing by moving
 * between buckets of a measurement they cannot read. What it BUYS is the
 * property the conversation unit exists for — a multi-turn client that stamps
 * the same value on every turn gets whole conversations sampled or skipped.
 *
 * With no header, the agent run id (#305/#522) is used, which gives agent
 * traffic conversation-stable sampling with no client change at all.
 */
export const CONVERSATION_HEADER = "x-ferrogate-conversation-id";

/** The largest response body this middleware will read back for capture. */
const MAX_RESPONSE_BODY_BYTES = 512 * 1024;

export interface OnlineEvalMiddlewareOptions {
  /** Override the policy source. Production reads it from `env`. */
  readonly policies?:
    | OnlineEvalPolicySource
    | ((env: OnlineEvalBindings) => OnlineEvalPolicySource);
  /** Override the evaluated operation set (tests narrow it). */
  readonly operationIds?: readonly string[];
  readonly now?: () => number;
}

/** `c.executionCtx` without the throw (`app.request()` creates none). */
function executionContextOf(c: {
  executionCtx: { waitUntil(work: Promise<unknown>): void };
}): { waitUntil(work: Promise<unknown>): void } | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

/** The conversation identity available BEFORE the inner app has run. */
function headerConversationKey(c: Context<GatewayEnv>): string | undefined {
  const value = c.req.header(CONVERSATION_HEADER);
  return value !== undefined && value.trim() !== "" ? value.trim() : undefined;
}

/** Is this response one a judge could be shown? */
function evaluableResponse(response: Response): boolean {
  if (response.status !== 200 || response.body === null) return false;
  if (isEventStream(response)) return false;
  return (response.headers.get("content-type") ?? "").includes("json");
}

/** Read a cloned body as JSON under a hard ceiling. `undefined` on anything else. */
async function boundedJson(clone: Response | Request | undefined): Promise<unknown> {
  if (clone === undefined) return undefined;
  try {
    const declared = clone.headers.get("content-length");
    if (declared !== null && Number(declared) > MAX_RESPONSE_BODY_BYTES) return undefined;
    const text = await clone.text();
    if (text.length > MAX_RESPONSE_BODY_BYTES) return undefined;
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Build the sample from the two captured bodies and the authenticated context.
 *
 * Exported so the assembly is assertable directly; the middleware is its only
 * production caller.
 */
export function onlineEvalSampleFrom(input: {
  readonly c: Context<GatewayEnv>;
  readonly policy: OnlineEvalPolicy;
  readonly requestBody: unknown;
  readonly responseBody: unknown;
  readonly samplingKey: string;
  readonly rate: number;
  readonly nowUnix: number;
}): OnlineEvalSample | undefined {
  const { c, policy } = input;
  const prompt = promptTranscriptFrom(input.requestBody);
  const completion = completionTextFrom(input.responseBody);
  if (prompt === undefined || completion === undefined) return undefined;

  const auth = c.get("auth") as AuthContext | null | undefined;
  // A sample with no AUTHENTICATED tenant is never produced: the opt-in is the
  // tenant's, so a sample that cannot name one has no consent behind it. A
  // platform-operator credential carries no tenancy at all, which is exactly
  // the `null` arm here.
  const tenantId = auth?.tenancy.tenantId ?? undefined;
  if (tenantId === undefined || tenantId === "") return undefined;

  const facts = requestLogFactsFor(c.req.raw);
  const capturedPrompt = captureTail(prompt);
  const capturedCompletion = captureHead(completion);

  return {
    // The id the CLIENT was told, read off the RESPONSE — the same choice
    // `requestlog/middleware.ts` makes and for the same reason: it is the id a
    // cost row is filed under, so it is the only id that makes a score and a
    // charge joinable.
    requestId: c.res.headers.get("x-request-id") ?? c.get("requestId") ?? "",
    tenantId,
    projectId: auth?.tenancy.projectId ?? undefined,
    workspaceId: auth?.tenancy.workspaceId ?? undefined,
    apiKeyId: auth?.subject ?? undefined,
    agentRunId: facts.agentRunId,
    operationId: c.get("operation")?.operationId,
    provider: facts.provider,
    logicalModel: facts.logicalModel,
    providerModel: facts.providerModel,
    // #693 — read off the SAME fact set the model and provider come from, which
    // the inference router contributed at dispatch. So a score's arm and the
    // request log's arm are one fact recorded twice, never two facts that could
    // disagree, and a canary-vs-control comparison groups on exactly the arm
    // that produced the response the judge was shown.
    experimentId: facts.experimentId,
    experimentArm: facts.experimentArm,
    samplingKey: input.samplingKey,
    samplingUnit: policy.samplingUnit,
    sampleRate: input.rate,
    judgeModel: policy.judgeModel,
    criteria: policy.criteria,
    prompt: capturedPrompt.text,
    completion: capturedCompletion.text,
    promptTruncated: capturedPrompt.truncated,
    completionTruncated: capturedCompletion.truncated,
    sampledAtUnix: input.nowUnix,
  };
}

/**
 * #693 — enqueue the SHADOW arm's sample beside the served arm's, when this
 * request had a mirror.
 *
 * A no-op for the overwhelming majority of requests: no mirror was spawned, so
 * `shadowEvalLegFor` answers `undefined` and this costs one `WeakMap` lookup.
 *
 * ## Why this awaits the mirror
 *
 * `spawnShadowMirror` is fire-and-forget, so the mirrored dispatch is normally
 * still in flight when the client's response is flushed. The wait happens
 * INSIDE the sampler's own `ctx.waitUntil` block — the same window the mirror
 * itself lives in — so no client byte is behind it and the isolate is already
 * being kept alive for the mirror regardless.
 *
 * The wait is bounded by the mirror, not by a second timer here: `shadow.ts`
 * dispatches under `dispatchDeadline(deps.limits.dispatchTimeoutMs)` and
 * resolves `leg.body` from a `finally`, so `leg.body` always settles. A timeout
 * of this module's own would be a second, differently-configured deadline for
 * one operation.
 *
 * ## Why the sample is derived rather than built
 *
 * See `./shadow-leg.ts`: the served sample IS the instrument, and copying it is
 * what makes "same judge, same criterion" a fact about the values rather than a
 * property two independent resolutions happen to share.
 */
async function enqueueShadowArmSample(
  c: Context<GatewayEnv>,
  sink: OnlineEvalSink,
  served: OnlineEvalSample,
): Promise<void> {
  const leg = shadowEvalLegFor(c.req.raw);
  if (leg === undefined) return;
  const shadow = shadowArmSampleFrom(served, leg, await leg.body);
  if (shadow === undefined) {
    // DISTINCT from `content_not_extractable`, which is about the served
    // response. This one says "a mirror ran and produced nothing a judge could
    // be shown" — a shadow arm reported without a quality number, which an
    // operator staring at `variant_arm_not_scored` needs to be able to tell
    // apart from "no mirror ran at all".
    sink.skip("shadow_arm_not_evaluable");
    return;
  }
  await sink.enqueue(shadow, { env: c.env });
}

/**
 * #894 — enqueue one sample per CANDIDATE-COVERAGE leg this request mirrored.
 *
 * A no-op for every request that covered nothing, which is every request of
 * every tenant that left `online_eval_coverage_percent` at 0: `coverageEvalLegsFor`
 * answers an empty array and this costs one `WeakMap` lookup.
 *
 * Sequential rather than `Promise.all`, matching `enqueueShadowArmSample`'s
 * shape: the legs settle independently and the sink is the same queue, so
 * concurrency here would buy nothing and would make a partial failure harder to
 * reason about.
 */
async function enqueueCoverageArmSamples(
  c: Context<GatewayEnv>,
  sink: OnlineEvalSink,
  served: OnlineEvalSample,
): Promise<void> {
  const legs = coverageEvalLegsFor(c.req.raw);
  if (legs.length === 0) return;
  for (const leg of legs) {
    const coverage = coverageArmSampleFrom(served, leg, await leg.body);
    if (coverage === undefined) {
      // DISTINCT from `shadow_arm_not_evaluable`: that one says an experiment's
      // mirror produced nothing scoreable, this one says a ROUTING candidate
      // was dispatched to and still has no score — which is the difference
      // between an incomplete experiment and a candidate that will keep reading
      // `no_signal` to the router no matter how much coverage is bought.
      sink.skip("coverage_arm_not_evaluable");
      continue;
    }
    await sink.enqueue(coverage, { env: c.env });
  }
}

/** Mount the sampler. See the module docblock for the position and the rules. */
export function onlineEvaluation(
  sink: OnlineEvalSink,
  options: OnlineEvalMiddlewareOptions = {},
): MiddlewareHandler<GatewayEnv> {
  const operationIds = new Set(options.operationIds ?? ONLINE_EVAL_OPERATION_IDS);
  const now = options.now ?? (() => Date.now());
  const sourceFor = (env: OnlineEvalBindings): OnlineEvalPolicySource =>
    typeof options.policies === "function"
      ? options.policies(env)
      : (options.policies ?? onlineEvalPolicySourceFromEnv(env));

  return async function onlineEvaluationMiddleware(c, next): Promise<void> {
    const operationId = c.get("operation")?.operationId;
    if (operationId === undefined || !operationIds.has(operationId)) {
      await next();
      return;
    }

    const auth = c.get("auth") as AuthContext | null | undefined;
    const tenantId = auth?.tenancy.tenantId ?? undefined;
    if (tenantId === undefined || tenantId === "") {
      await next();
      return;
    }

    const policies = sourceFor(c.env as OnlineEvalBindings);
    // NO I/O. The memo answer, or nothing — see the module docs on the
    // cold-isolate hole.
    const resolution = policies.peek(tenantId);
    const conversationKey = headerConversationKey(c);
    const outerRequestId = c.get("requestId") ?? "";

    let requestClone: Request | undefined;
    let plannedDecision: { samplingKey: string; rate: number } | undefined;
    let policy: OnlineEvalPolicy | null = null;

    if (resolution !== undefined && resolution.ok) {
      policy = resolution.policy;
      const plan = onlineEvalCapturePlan({
        policy,
        residency: residencyPolicyFor(c.req.raw),
        requestId: outerRequestId,
        conversationKey,
      });
      if (plan.capture) {
        if (plan.decision?.sampled === true) {
          plannedDecision = { samplingKey: plan.decision.samplingKey, rate: plan.decision.rate };
        }
        // #693 — THE RETENTION GATE for the shadow arm. A mirror's response is
        // discarded by design, so it may only be held long enough to build a
        // sample once THIS plan has cleared opt-in, ZDR, criteria and the
        // bucket. Asking here, inside the same branch that authorises cloning
        // the client's own body, is what makes the shadow arm inherit every one
        // of those refusals instead of re-deciding them: a tenant that must not
        // be sampled is never shadow-SCORED either, and nothing about the
        // mirror is retained for it. See `./shadow-leg.ts`.
        requestShadowEvalRetention(c.req.raw);
        // #894 — CANDIDATE COVERAGE, in the same branch and therefore behind
        // exactly the same four refusals. `0` (the default for every tenant
        // that did not ask for coverage) writes nothing, so the router sees no
        // coverage percentage and mirrors no non-primary candidate.
        requestCoverageEval(c.req.raw, policy?.coveragePercent ?? 0);
        try {
          // Cloning tees the body stream; it reads nothing and awaits nothing.
          // A failure here (an already-disturbed body) costs the sample, never
          // the request.
          requestClone = c.req.raw.clone();
        } catch {
          requestClone = undefined;
        }
      } else {
        sink.skip(plan.reason);
      }
    } else if (resolution !== undefined && !resolution.ok) {
      sink.skip("policy_unreadable");
    } else {
      // Cold memo. Counted, so a deployment that never samples anything can see
      // that its isolates are churning rather than that its policy is wrong.
      sink.skip("policy_not_warm");
    }

    await next();

    const ctx = executionContextOf(c);
    const defer = (work: Promise<unknown>): void => {
      if (ctx === undefined) void work;
      else ctx.waitUntil(work);
    };

    // Warm the memo for the NEXT request regardless of what happened to this
    // one — this is the only thing that ever populates `peek`, and it must run
    // even when the policy said "do not sample", or a tenant that opts in would
    // never be sampled at all.
    const warm = policies.policyFor(tenantId).catch(() => undefined);
    // #894 — and the per-leg quality memo the ROUTER peeks, warmed in the same
    // deferred window and for the same reason: `orderCandidatesByStrategy` is
    // synchronous, so the only moment a snapshot can be fetched is after this
    // request has already been served. Warmed unconditionally alongside the
    // policy, including for a tenant whose capture plan refused this request —
    // the memo is what the NEXT request reads, and gating it on being sampled
    // would leave a 5%-sampled tenant's router cold 95% of the time.
    const warmQuality = warmLegQuality(c.env as OnlineEvalBindings, tenantId).catch(
      () => undefined,
    );

    if (requestClone === undefined) {
      defer(Promise.all([warm, warmQuality]));
      return;
    }

    const response = c.res;
    if (!evaluableResponse(response)) {
      sink.skip("response_not_evaluable");
      defer(Promise.all([warm, warmQuality]));
      return;
    }
    // Cloned SYNCHRONOUSLY, while the response is still intact; read later.
    let responseClone: Response | undefined;
    try {
      responseClone = response.clone();
    } catch {
      responseClone = undefined;
    }
    if (responseClone === undefined) {
      sink.skip("response_not_evaluable");
      defer(Promise.all([warm, warmQuality]));
      return;
    }

    const capturedPolicy = policy;
    const captured = requestClone;
    const capturedResponse = responseClone;
    defer(
      (async (): Promise<void> => {
        await warm;
        try {
          if (capturedPolicy === null) return;

          let samplingKey = plannedDecision?.samplingKey;
          let rate = plannedDecision?.rate;
          if (samplingKey === undefined) {
            // The provisional case: a conversation-unit request whose key is
            // contributed by an inner slice. This draws the ONE bucket.
            const facts = requestLogFactsFor(c.req.raw);
            const decision = onlineEvalSamplingDecision({
              policy: capturedPolicy,
              residency: residencyPolicyFor(c.req.raw),
              requestId: outerRequestId,
              conversationKey: conversationKey ?? facts.agentRunId,
            });
            if (!decision.sampled) {
              sink.skip(decision.reason);
              return;
            }
            samplingKey = decision.samplingKey;
            rate = decision.rate;
          }

          const [requestBody, responseBody] = await Promise.all([
            boundedJson(captured),
            boundedJson(capturedResponse),
          ]);
          const sample = onlineEvalSampleFrom({
            c,
            policy: capturedPolicy,
            requestBody,
            responseBody,
            samplingKey,
            rate: rate ?? capturedPolicy.sampleRate,
            nowUnix: Math.floor(now() / 1000),
          });
          if (sample === undefined) {
            // DIFFERENT from `response_not_evaluable` above, deliberately: that
            // one is "this response was never a candidate" (streamed, refused,
            // not JSON), this one is "it was a candidate and the body was not a
            // shape `./content.ts` could read". The first is a property of the
            // deployment's traffic; the second is a gap in the extractor, i.e.
            // a bug to fix. One counter for both would hide the second inside
            // the first on any deployment that streams.
            sink.skip("content_not_extractable");
            return;
          }
          await sink.enqueue(sample, { env: c.env });
          // #693 — and the SHADOW arm of the same exchange, if this request had
          // a mirror and the mirror answered. Strictly after the served sample:
          // an arm that has no control to be compared against is not worth
          // spending a judge call on, and enqueuing it first would let a queue
          // failure on the served sample leave an orphan shadow population.
          await enqueueShadowArmSample(c, sink, sample);
          // #894 — and every CANDIDATE-COVERAGE leg, last. Same ordering rule
          // as the shadow arm and one more reason for it: a coverage population
          // exists only to be compared against the leg that served, so a
          // coverage sample enqueued before its control would be an orphan if
          // the served enqueue failed.
          await enqueueCoverageArmSamples(c, sink, sample);
        } catch {
          // The response has already been served. Nothing here may surface.
        }
      })(),
    );
  };
}
