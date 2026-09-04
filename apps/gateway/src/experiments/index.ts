/**
 * `apps/gateway/src/experiments` — OUTCOME METRICS FOR CANARY AND SHADOW SPLITS
 * (#693).
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES
 * ============================================================================
 *
 * `packages/routing` has split traffic since #276. `applyCanary` promotes a
 * sticky percentage of callers onto a variant route and `shadowMirrorFor`
 * mirrors a budgeted fraction to a second provider — and nothing anywhere
 * recorded WHICH ARM served a request. #664 filed latency and status per
 * request, #677 filed cost per request, #692 filed eval scores per request, and
 * not one of them could be grouped by arm. The shadow leg was worse than
 * ungroupable: it produced no durable record at all, so an entire arm's cost,
 * latency and error rate were invisible by construction.
 *
 * So "is the canary better" was unanswerable from data the product already
 * held, and every rollout decision stayed a guess about everything except
 * price.
 *
 * ============================================================================
 * THE SHAPE
 * ============================================================================
 *
 * ```
 *  planUpstream ── experimentAssignmentFor(resolved) ─┐
 *                                                     │  (pure, no I/O)
 *  dispatch ────── servedArmFor(assignment, served) ──┤
 *                                                     ├─→ request_logs
 *                                                     │     .experiment_id
 *                                                     │     .experiment_arm
 *  spawnShadowMirror ─→ runShadowMirror ──────────────┴─→ experiment_shadow_legs
 *                            │                              (the arm with no
 *                            │                               request log)
 *                            └─→ online_eval_scores.experiment_arm = 'shadow'
 *
 *  apps/control-plane  ──→ GET /admin/v1/experiments{,/{id}}
 *                            └── compareExperimentQuality (@ferrogate/routing)
 * ```
 *
 * | file            | job                                                     |
 * |-----------------|---------------------------------------------------------|
 * | `assignment.ts` | which experiment, and which arm served — pure           |
 * | `record.ts`     | the shadow leg's evidence row                           |
 * | `d1.ts`         | `experiment_shadow_legs`                                |
 * | `sink.ts`       | the observer port `inference/shadow.ts` depends on       |
 *
 * The COMPARISON itself is not here: it is `packages/routing/src/experiment.ts`,
 * beside the split primitive, because the reader in `apps/control-plane` and
 * the writer here must compute the same experiment id from the same inputs.
 *
 * ============================================================================
 * THE FOUR THINGS THIS SLICE REFUSES TO DO
 * ============================================================================
 *
 * 1. **Compare arms scored differently.** Both arms must be scored by the SAME
 *    judge under the SAME criterion or the difference measures two instruments
 *    rather than two models. Enforced structurally — the score aggregate is
 *    grouped by `(judge_model, criterion_id)` and `compareExperimentQuality`
 *    only pairs arms inside one group, so there is no code path that subtracts
 *    across them.
 * 2. **Show a number on a sample too small to support one.** Below the floor
 *    the means are absent from the result object entirely.
 * 3. **Bill the tenant for the shadow arm.** The customer never saw that
 *    response. `armChargedTo` is a function of the arm, not a stored field, and
 *    `inference/shadow.ts` has no code path to metering at all.
 * 4. **Shadow a tenant that bought zero data retention or region pinning.** A
 *    mirror is a second copy of the prompt at a second provider. `#681`'s
 *    `residencyViolations` already gates `shadowMirrorFor` before sampling, and
 *    `#692`'s `onlineEvalSamplingDecision` refuses a ZDR tenant outright — so
 *    the new shadow-arm SCORING inherits both refusals rather than re-deciding
 *    them.
 */
export { experimentAssignmentFor, servedArmFor } from "./assignment.js";
export type { ExperimentAssignment } from "./assignment.js";
export {
  EXPERIMENT_SHADOW_LEG_TABLE,
  EXPERIMENT_SHADOW_LEG_UPSERT_SQL,
  experimentTenantDatabaseFrom,
  shadowLegBindings,
  writeShadowLeg,
} from "./d1.js";
export type { ExperimentDatabase } from "./d1.js";
export type { ShadowLegErrorCode, ShadowLegRecord } from "./record.js";
export {
  createExperimentObserver,
  D1ExperimentObserver,
  experimentObserverFor,
  experimentObserverStats,
  NO_EXPERIMENT_OBSERVER,
} from "./sink.js";
export type {
  ExperimentObserver,
  ExperimentSinkOptions,
  ExperimentSinkStats,
} from "./sink.js";
