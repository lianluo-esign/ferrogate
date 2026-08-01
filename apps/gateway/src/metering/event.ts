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
 * ## The marker that stood here is CLOSED. Both halves landed.
 *
 * It read "nothing SETS the field yet", named the two edits that would close it
 * (`Usage.providerAttemptIndex` in `src/inference/ports.ts`, and
 * `providerAttemptIndex: attempt.index` in `recordUsage`), and warned that until
 * both landed a metered failover would collapse two attempts onto ONE
 * `ledgerEntryId` and be absorbed by `ON CONFLICT DO NOTHING` as a healthy
 * replay — a silent under-bill.
 *
 * Both edits are now in the tree: `inference/ports.ts` declares
 * `readonly providerAttemptIndex?: number` on `Usage`, and `handlers.ts` sets it
 * from the dispatch loop's `attemptIndex` on all four metering call sites. This
 * side was already ready — {@link providerAttemptIndexFor} reads the field and
 * falls back to this constant only when the dispatcher does not supply one.
 *
 * ## Why the closure is not taken on trust
 *
 * The threading lives in a file this module does not own, so "the marker is
 * stale" is exactly the kind of claim that decays back into a defect. It is
 * therefore pinned across the boundary by
 * `test/metering/gateway.test.ts` → "the provider-attempt index reaches the
 * ledger key": two candidates for one logical model, the priority-0 one answers
 * 503, the ladder fails over, and the resulting CHARGE is required to carry
 * `provider-attempt:1`. Because the fallback here is `0` — and `0` is precisely
 * what an unfailed request produces — a served-by-attempt-1 request is the only
 * observation that can distinguish threaded from unthreaded. Removing
 * `providerAttemptIndex: attemptIndex` from `handlers.ts::recordUsage` was
 * verified to turn that assertion red with `provider-attempt:0`, and a negative
 * control in the same block pins the unfailed request at `0` so the gate cannot
 * be satisfied by a constant.
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
