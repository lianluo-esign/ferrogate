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
import { agentRunIdFor } from "./agent-run.js";
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
  /**
   * `x-ferrogate-agent-run-id` (#305/#522), as validated by the request path.
   *
   * ## THE ONE-LINE CHANGE THE INFERENCE SLICE OWES THIS FIELD
   *
   * Cutover finding D3 was that the header is read on assets, on MCP and in
   * `apps/agent-runtime`, and NOWHERE on the inference path — so the surface
   * that produces the token spend was the one surface whose spend could not be
   * joined to the agent run that caused it.
   *
   * The metering half is closed two ways. The one that works TODAY is the
   * drain-side fallback: `./middleware.ts` reads the header off the request and
   * `./agent-run.ts::chargeWithAgentRun` stamps it under the request-id guard.
   * The one that matches RUST is this field, and it needs exactly one line in a
   * file this slice does not own:
   *
   * ```ts
   * // apps/gateway/src/inference/handlers.ts, in `recordUsage(...)`,
   * // alongside `providerAttemptIndex: attemptIndex`:
   * agentRunId: c.req.header("x-ferrogate-agent-run-id"),
   * ```
   *
   * When it lands this value WINS over the drain-side one (see
   * `chargeWithAgentRun`), because an ingress-validated id is the one Rust
   * stamps. The remaining Rust behaviour that is genuinely inference-side is
   * the REFUSAL — `400 invalid_agent_run_id_header` at `chat.rs:2767`, which
   * belongs in the validation ladder next to `invalid_json`, and which a
   * middleware running on the way OUT cannot produce. Both halves are pinned
   * from here by `test/metering/agent-run-correlation.test.ts`, so they cannot
   * land out of order or drift apart.
   */
  readonly agentRunId?: string | undefined;
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
   * the call itself. In legacy rate-card mode, `undefined` lets `charge()` try
   * the configured card; production serving-offering mode refuses it as
   * unpriced instead.
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
    // #667. Subsets of the two counts above, never additions — the capture
    // layer (`inference/usage.ts`) has already normalized every provider family
    // onto that invariant, so `charge()` subtracts them back out and prices each
    // at its own rate. `0` for an absent counter is right here for the same
    // reason it is right above: `reconcileSplit`/`estimateCost` treat it as "no
    // cached tokens", which is what a provider that reported none means.
    cached_input_tokens: usage.cachedInputTokens ?? 0,
    cache_write_tokens: usage.cacheWriteTokens ?? 0,
    reasoning_tokens: usage.reasoningTokens ?? 0,
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
    // #305/#522. Validated, never trusted: an id the request path threaded is
    // still a client-declared string, and a malformed one poisons the join it
    // exists to enable. Absent stays ABSENT — serde's
    // `skip_serializing_if = "Option::is_none"` — so "no run declared" is
    // distinguishable from "a run declared nothing".
    ...(agentRunIdFor(usage.agentRunId) === undefined
      ? {}
      : { agent_run_id: agentRunIdFor(usage.agentRunId) }),
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
    // #703. The audio quantities, on the EVENT rather than folded into
    // `usage` — see `BillingEvent.audio_seconds`. Carrying them is what lets
    // `charge()` price an audio row off the rate card at all, and therefore
    // what arms its >5% divergence check for the two newest units: without
    // them the card estimate is $0 against a positive settled cost, so a
    // mispriced transcription would never trip the one detector built to catch
    // a mispriced row.
    //
    // ABSENT, never zero, exactly as `Usage.audioSeconds` is: a provider that
    // reported no duration has not reported zero, and settling a real call
    // authoritatively at $0 is the #129 bug.
    ...(usage.audioSeconds !== undefined ? { audio_seconds: usage.audioSeconds } : {}),
    ...(usage.audioCharacters !== undefined ? { audio_characters: usage.audioCharacters } : {}),
    metadata,
  };
}
