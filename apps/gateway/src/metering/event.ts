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
  providerAttemptForRequest,
  validateRequestMetadata,
  type BillingEvent,
  type BillingUsageSource,
  type TokenUsage,
} from "@ferrogate/billing";
import type { TenantContext } from "@ferrogate/core";
import type { Usage } from "../inference/ports.js";
import type { MeteringDiagnostics } from "./ports.js";

/**
 * The provider-attempt index for a gateway-dispatched request.
 *
 * `ProviderAttempt::for_request(request_id, index)` exists because ONE logical
 * request can fan out into several provider dispatches (a failover retry), and
 * each is separately billable (issue #213). The TS data plane has no failover
 * yet — `handlers.ts` dispatches exactly once — so every attempt is index 0.
 *
 * PORT-TODO(inventory-request-path §"routing/failover"): when
 * `@ferrogate/routing` lands its failover ladder, the attempt index must come
 * from the dispatch loop, not from this constant, or two attempts on one
 * request would collapse onto one idempotency key and the second would be
 * absorbed as a duplicate — i.e. silently unbilled.
 */
export const SINGLE_PROVIDER_ATTEMPT_INDEX = 0;

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
  usage: Usage,
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
    provider_attempt: providerAttemptForRequest(usage.requestId, SINGLE_PROVIDER_ATTEMPT_INDEX),
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
