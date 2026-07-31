/**
 * `Usage` (the inference data plane's metering seam) → `BillingEvent` (the
 * `@ferrogate/billing` wire event).
 *
 * This is the whole reason the two sides can stay decoupled:
 * `src/inference/ports.ts` declares a `Usage` that names only what the request
 * path actually observed, and `ferrogate-billing` declares the event the ledger
 * is priced from. The Rust equivalent is the struct literal built in
 * `state_billing_metering.rs::settle_request`, and the mapping below follows it
 * field for field.
 */
import {
  type BillingEvent,
  type BillingUsageSource,
  type TokenUsage,
  providerAttemptForRequest,
  validateRequestMetadata,
} from "@ferrogate/billing";
import type { TenantContext } from "@ferrogate/core";
import type { Usage } from "../inference/ports.js";
import type { MeteringDiagnostics } from "./ports.js";

/**
 * The DEFAULT provider-attempt index — the value used when the dispatch that
 * produced a `Usage` did not say which attempt it was.
 *
 * `ProviderAttempt::for_request(request_id, index)` exists because ONE logical
 * request can fan out into several provider dispatches (a failover retry), and
 * each is separately billable (issue #213).
 *
 * ## The marker this constant used to carry, corrected
 *
 * It read "the TS data plane has no failover yet — `handlers.ts` dispatches
 * exactly once", and it listed two blockers: a failover ladder in
 * `@ferrogate/routing`, and the index being carried through `recordUsage`.
 * **The first has landed.** `handlers.ts::dispatchCandidates` walks
 * `reliability.ts::dispatchWithFailover` and CAN make several attempts per
 * request, so a note claiming a single dispatch is no longer true and must not
 * be left in place — that is how a stale marker becomes a shipped under-bill.
 *
 * ## What is closed here, and what is still open
 *
 * CLOSED: this module no longer hard-codes the index. {@link providerAttemptIndexFor}
 * reads `providerAttemptIndex` off the usage record when the dispatcher supplies
 * one, and only falls back to this constant when it does not. So the moment the
 * inference slice threads the index, `ledgerEntryId` partitions on it correctly
 * with no further change here, and the failure mode below simply cannot arrive
 * silently.
 *
 * STILL OPEN — PORT-TODO(inventory-request-path §"routing/failover"), a SCOPE
 * boundary, not a platform limit: nothing SETS the field yet. `Usage` is
 * declared in `src/inference/ports.ts` and populated by
 * `src/inference/handlers.ts`, neither of which this module owns. The exact
 * remaining change, in those two files:
 *
 * ```ts
 * // src/inference/ports.ts — interface Usage
 * readonly providerAttemptIndex?: number;
 * // src/inference/handlers.ts — recordUsage(), from the dispatch loop
 * providerAttemptIndex: attempt.index,
 * ```
 *
 * The consequence while it is open is bounded and NOT currently live: usage is
 * recorded exactly once per request, from the attempt that produced the served
 * response, and abandoned attempts are never metered — so every recorded event
 * really is attempt 0 today. It becomes live the day a FAILED attempt is metered
 * for provider-cost attribution. At that point, without the field, two attempts
 * of one request collapse onto one `ledgerEntryId` and the second is absorbed by
 * `ON CONFLICT DO NOTHING` as a healthy replay — a silent under-bill, not a
 * crash. `test/metering/durable.test.ts` ("does not double-charge the SAME
 * request id") pins that absorption, so it reads as the description of the
 * failure this marker guards against.
 */
export const SINGLE_PROVIDER_ATTEMPT_INDEX = 0;

/**
 * `Usage`, plus the attempt index the failover ladder will thread onto it.
 *
 * Declared structurally HERE rather than added to `Usage` because
 * `src/inference/ports.ts` is another slice's file. Widening it here is what
 * makes the metering half land ahead of the inference half instead of after it.
 */
export type UsageWithProviderAttempt = Usage & {
  /** Zero-based dispatch index within one logical request (Rust `#135`). */
  readonly providerAttemptIndex?: number | undefined;
};

/**
 * The attempt index to bill under.
 *
 * Anything that is not a non-negative safe integer falls back to
 * {@link SINGLE_PROVIDER_ATTEMPT_INDEX}. That guard is not defensive noise: the
 * index is folded into `ledgerEntryId`, which is a PRIMARY KEY in three tables,
 * and a `NaN`/`-1`/`1.5` reaching it would produce a key no replay of the same
 * request could ever match — turning idempotent retry into double-billing.
 */
export function providerAttemptIndexFor(usage: UsageWithProviderAttempt): number {
  const declared = usage.providerAttemptIndex;
  if (declared === undefined) return SINGLE_PROVIDER_ATTEMPT_INDEX;
  if (!Number.isSafeInteger(declared) || declared < 0) return SINGLE_PROVIDER_ATTEMPT_INDEX;
  return declared;
}

/** Where the token counts came from. */
export interface BillingEventContext {
  /** `now_unix_seconds()` at settlement — `occurred_at_unix` (issue #153). */
  readonly nowUnixSeconds: number;
  /**
   * A gateway-settled cost, when the request path priced and budget-enforced
   * the call itself. `undefined` ⇒ the rate card decides and `charge()` fails
   * closed if it cannot.
   */
  readonly settledCostUsd?: number | undefined;
  /** `cluster_identity.cluster_id` — a Worker's colo/deployment identity. */
  readonly clusterId?: string | undefined;
  /** `cluster_identity.node_id`. */
  readonly nodeId?: string | undefined;
  readonly diagnostics?: MeteringDiagnostics | undefined;
}

/**
 * `TokenUsage` from the observed counts.
 *
 * A missing count is 0, NOT "unknown": the split is repaired downstream by
 * `reconcileSplit` inside `charge()` (issue #140 — a provider-omitted side must
 * not be billed at $0), and `charge()` is where that reconciliation belongs so
 * the pure billing package stays the single source of the rule.
 */
function tokenUsageFrom(usage: Usage): TokenUsage {
  return {
    prompt_tokens: usage.promptTokens ?? 0,
    completion_tokens: usage.completionTokens ?? 0,
    total_tokens: usage.totalTokens ?? 0,
  };
}

/**
 * `TenantContext` from the attribution the inference path resolved.
 *
 * `organization_id` IS the tenant id (`packages/core/src/context.ts`), so the
 * mapping is `tenantId → organization_id`, never a new field.
 */
function tenantFrom(usage: Usage): TenantContext {
  return {
    ...(usage.tenantId !== undefined ? { organization_id: usage.tenantId } : {}),
    ...(usage.projectId !== undefined ? { project_id: usage.projectId } : {}),
  };
}

/**
 * Was this metering event produced from real provider-reported usage, or from
 * a gateway-side estimate?
 *
 * `BillingUsageSource` exists so a downstream report can tell a measured charge
 * from an inferred one. The tap reports `undefined` when it scraped nothing —
 * a non-2xx upstream, or a stream the client cut before any usage frame — and
 * that is exactly the `GatewayEstimate` case in Rust.
 */
export function usageSourceFor(usage: Usage): BillingUsageSource {
  return usage.promptTokens === undefined &&
    usage.completionTokens === undefined &&
    usage.totalTokens === undefined
    ? "gateway_estimate"
    : "provider_usage";
}

/**
 * Build the wire `BillingEvent` a charge is settled from.
 *
 * Deliberately NOT lossy on the two fields that decide idempotency: the
 * `request_id` and the provider-attempt id, which together produce
 * `ledger_entry_id(event)` — the primary key of `billing_ledger`,
 * `billing_events` and `billing_report_outbox` alike.
 */
export function billingEventFromUsage(
  usage: UsageWithProviderAttempt,
  context: BillingEventContext,
): BillingEvent {
  const metadata = usage.metadata === undefined ? {} : { ...usage.metadata };
  if (usage.metadata !== undefined) {
    // Defence in depth only: `Usage.metadata` is documented as already
    // bounds-checked at ingress (issue #171). The map is NOT dropped on a
    // violation — losing attribution silently is worse than carrying it — but
    // the diagnostic fires so an ingress regression is visible rather than
    // showing up as unbounded `usage_metadata_rollups` cardinality.
    const violation = validateRequestMetadata(metadata);
    if (violation !== null) {
      context.diagnostics?.onError?.("metadata_bounds", new Error(violation));
    }
  }

  return {
    request_id: usage.requestId,
    // The gateway mints one id and uses it for both (`streamingHeaders` emits
    // `x-request-id` and `x-trace-id` with the same value), so the trace id is
    // carried explicitly rather than left blank — `ledger_entry_id` prefers the
    // provider-attempt key anyway, but a report reader needs the correlation.
    trace_id: usage.requestId,
    provider_attempt: providerAttemptForRequest(usage.requestId, providerAttemptIndexFor(usage)),
    ...(context.clusterId !== undefined ? { cluster_id: context.clusterId } : {}),
    ...(context.nodeId !== undefined ? { node_id: context.nodeId } : {}),
    tenant: tenantFrom(usage),
    logical_model: usage.logicalModel,
    provider: usage.provider,
    provider_model: usage.providerModel,
    usage: tokenUsageFrom(usage),
    usage_source: usageSourceFor(usage),
    status_code: usage.status,
    occurred_at_unix: context.nowUnixSeconds,
    ...(context.settledCostUsd !== undefined ? { cost_usd: context.settledCostUsd } : {}),
    metadata,
  };
}
