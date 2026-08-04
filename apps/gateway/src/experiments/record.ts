/**
 * The SHADOW ARM's observation — the one leg of an experiment that has no
 * request log and never will.
 *
 * A mirror's response is never delivered to a caller. It is therefore not a
 * client request, gets no `request_logs` row, and must not get one: every
 * count, latency percentile and SIEM export over that table would silently
 * start including responses no customer ever received. This record is the
 * shadow arm's own evidence, carrying the same operational facts the request
 * log carries for the served arms so a report can put the arms side by side
 * without measuring them differently.
 *
 * ## What is NOT here
 *
 * No prompt and no completion, exactly as #692's score table refuses them. The
 * mirrored content exists only in flight.
 *
 * No `chargedTo` either, and that omission is load-bearing: who pays is a
 * function of the ARM (`armChargedTo` in `@ferrogate/routing`), so there is no
 * field a writer could fill in wrongly and no column a report could read as
 * "the tenant was billed for this". `cost_usd` here is the OPERATOR's cost of
 * taking the measurement, priced from the mirror route's own registry rates.
 */

/** One mirrored dispatch, as it lands in `experiment_shadow_legs`. */
export interface ShadowLegRecord {
  /**
   * `{clientRequestId}~shadow`. DERIVED rather than random so a retried mirror
   * overwrites its own row instead of inflating the arm's sample — and so a
   * shadow-arm SCORE can be filed in `online_eval_scores` under this id without
   * colliding with the served arm's score for the same request.
   */
  readonly legId: string;
  /** The id the CLIENT was told. The join back to the served arm. */
  readonly clientRequestId: string;
  readonly experimentId: string;
  readonly tenantId: string;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  readonly apiKeyId?: string | undefined;
  readonly logicalModel: string;
  readonly provider: string;
  readonly providerModel: string;
  /** The provider's status, or absent when the mirror never got one. */
  readonly statusCode?: number | undefined;
  /**
   * Why the mirror produced no response. A leg refused before dispatch is
   * still recorded: an arm whose failures are invisible looks healthier than
   * the arm it is being compared against, which is the direction that promotes
   * a bad variant.
   */
  readonly errorCode?: ShadowLegErrorCode | undefined;
  readonly latencyMs: number;
  readonly promptTokens?: number | undefined;
  readonly completionTokens?: number | undefined;
  readonly totalTokens?: number | undefined;
  /** OPERATOR-side cost. Absent when the route states no usable price. */
  readonly costUsd?: number | undefined;
  readonly observedAtUnix: number;
}

/**
 * Why a mirrored leg produced nothing.
 *
 * Each arm is distinguishable because they mean different things to an operator
 * reading a shadow arm with a high failure rate: a budget refusal is the
 * operator's own cap doing its job, an adapter refusal is a capability
 * mismatch to fix, and a dispatch error is the mirrored provider actually
 * failing — which is the only one of the three that says anything about the
 * variant being evaluated.
 */
export type ShadowLegErrorCode =
  | "shadow_budget_exhausted"
  | "adapter_unavailable"
  | "adapter_refused"
  | "provider_dispatch_error";
