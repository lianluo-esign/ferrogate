/**
 * `apps/gateway/src/evals` — ONLINE EVALUATION OF SAMPLED PRODUCTION TRAFFIC
 * (#692).
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES
 * ============================================================================
 *
 * A gateway sees every request and every response, which makes it the only
 * place an outcome can be measured without the customer instrumenting
 * anything. Before this slice nothing in `apps/*` measured one: `grep -rn
 * "judge\|score" apps/*\/src` found the guardrail LLM-judge detector and
 * nothing else, there was no score table in any migration, and canary routing
 * (`inference/strategy.ts`) split traffic while measuring no outcome at all. An
 * operator swapping a model could see cost and latency move and could not see
 * whether the answers got worse — so every rollout decision was a guess.
 *
 * ============================================================================
 * THE SHAPE
 * ============================================================================
 *
 * ```
 *  request ─→ onlineEvaluation()  ─→ … routes … ─→ response to the client
 *                    │                                    ▲
 *                    │  (nothing below is in front of this)
 *                    └── ctx.waitUntil:
 *                          policy → sampling decision → capture → Queue ONLINE_EVAL
 *                                                                     │
 *                    ┌────────────────────────────────────────────────┘
 *                    ▼
 *          queue() ─→ consumeOnlineEvalBatch
 *                        ├── residency gate on the JUDGE route (#681)
 *                        ├── judge dispatch (chat.completions, temperature 0)
 *                        ├── D1  `online_eval_scores`   (joins #677 cost on request_id)
 *                        └── Analytics Engine gauge via apps/telemetry
 *                    ▼
 *          scheduled() ─→ sweepOnlineEvalRegressions  → `online_eval_regressions`
 * ```
 *
 * | file            | job                                                     |
 * |-----------------|---------------------------------------------------------|
 * | `policy.ts`     | the per-tenant opt-in, and WHAT A SCORE MEANS. Read it. |
 * | `sampling.ts`   | the salted, deterministic bucket                        |
 * | `source.ts`     | where a tenant's policy comes from, and the isolate memo |
 * | `content.ts`    | the bounded prompt/response capture                     |
 * | `record.ts`     | the sample envelope and its queue wire                  |
 * | `sink.ts`       | the producer half — never on the request path           |
 * | `middleware.ts` | the response-path hook                                  |
 * | `judge.ts`      | the judge request and the verdict parser (pure)         |
 * | `d1.ts`         | `online_eval_scores` / `online_eval_regressions`         |
 * | `consumer.ts`   | the queue consumer: judge → D1 → Analytics Engine        |
 * | `regression.ts` | the cron-side regression detector                        |
 *
 * ============================================================================
 * THE FOUR PROPERTIES THIS SLICE IS BUILT AROUND
 * ============================================================================
 *
 * 1. **The caller's latency is untouched.** `onlineEvaluation()` awaits
 *    `next()` and nothing else; the policy read, the capture, the serialization
 *    and the enqueue all happen inside `ctx.waitUntil`, and the JUDGE runs in a
 *    different Worker invocation entirely (a queue consumer). No judge token is
 *    ever spent while a client is waiting.
 * 2. **Sampling is deliberate.** A fraction the tenant configures, taken by a
 *    salted hash of a stable key, with the unit — request or conversation —
 *    stated, because a per-request random sampler cannot compare a conversation
 *    against itself.
 * 3. **Nobody is sampled who did not ask.** Per-tenant opt-in, off by default,
 *    and a zero-data-retention tenant is excluded outright (#681) because
 *    evaluating a prompt means copying it somewhere.
 * 4. **The score is joinable to cost.** The row carries `request_id` plus the
 *    same attribution axes #677's cost records carry — tenant, project, key,
 *    model, agent run — so "did quality move WITH cost" is one join and not two
 *    silos.
 *
 * ============================================================================
 * WHAT IS DELIBERATELY NOT HERE
 * ============================================================================
 *
 *  - **Streamed responses are not evaluated.** Reassembling an SSE body to
 *    recover the completion text means buffering the whole stream in the
 *    isolate for every sampled request; that is a memory decision with its own
 *    limits, and the sample would silently over-represent short answers if it
 *    were bounded naively. `./middleware.ts` records the skip as
 *    `response_not_evaluable` rather than pretending a streamed request was
 *    considered and not selected.
 *  - **No admin read API.** The scores land in the CONTROL database next to
 *    `request_logs` and `billing_events`; adding six contract operations for a
 *    surface whose query shape is still being learned would freeze that shape
 *    before anyone has read a single trend. The join that answers the issue's
 *    real question is documented in `./d1.ts`.
 *  - **No webhook delivery for a regression.** A regression is recorded as a
 *    claimed durable row plus an Analytics Engine series, which is what an
 *    operator alerts on. Shipping an unsigned webhook, or borrowing the
 *    billing-alert signing secret for a quality signal, would be a worse answer
 *    than the honest boundary — see `./regression.ts`.
 */
export {
  DEFAULT_REGRESSION_DROP,
  DEFAULT_REGRESSION_MIN_SAMPLES,
  onlineEvalSamplingDecision,
  parseOnlineEvalPolicyRow,
} from "./policy.js";
export type {
  OnlineEvalCriterion,
  OnlineEvalPolicy,
  OnlineEvalPolicyRow,
  OnlineEvalSamplingDecision,
  OnlineEvalSamplingInput,
  OnlineEvalSamplingUnit,
  OnlineEvalSkipReason,
  ParsedOnlineEvalPolicy,
} from "./policy.js";

export { ONLINE_EVAL_SAMPLING_SALT, fnv1a32, sampleBucket } from "./sampling.js";
