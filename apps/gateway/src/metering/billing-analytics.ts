/**
 * Billing dual-write to Analytics Engine (#956) — the cross-tenant fleet view.
 *
 * The authoritative per-transaction cost lives in the tenant's own Durable
 * Object (`billing_events`, read one tenant at a time — `cost-records` routes
 * there, #954). That copy is exact, transactional and long-lived but cannot
 * answer a CROSS-TENANT question ("top spenders this month", "fleet billed by
 * model") without an O(N) fan-out to every tenant object, and Cloudflare offers
 * no cross-object query primitive.
 *
 * So a settled, delivered charge is ALSO mirrored to Analytics Engine — a
 * write-cheap, columnar, SQL-queryable, SAMPLED, bounded-retention store the
 * control plane aggregates across the fleet in ONE query, with no tenant-private
 * data copied into the control database. AE is the ANALYTICS mirror, never the
 * invoicing authority — that stays the tenant object.
 *
 * ## Why the write happens in the DRAIN, from the event
 *
 * The Analytics Engine binding is a per-request Worker binding, reachable only
 * from `rc.env` on the metering DRAIN (`meteringDrain` builds it). The
 * synchronous settle path runs with NO request env (usage is captured and drained
 * later), so the mirror is written from `#deliverOnce`, off the delivered
 * `BillingEvent` — which carries the final `cost_usd`, the tenant/model/provider
 * dimensions, and (when a billing group applied) the `billing_multiplier` and the
 * pre-multiplier `offer_cost_usd` stamped on its metadata.
 */
import type { BillingEvent } from "@ferrogate/billing";

/**
 * The slice of `AnalyticsEngineDataset` used here. Declared locally so the seam
 * is a plain object a test can record against, mirroring `apps/telemetry`.
 */
export interface BillingAnalyticsDataset {
  writeDataPoint(point: {
    blobs?: (string | null)[];
    doubles?: number[];
    indexes?: string[];
  }): void;
}

/** `env.BILLING_ANALYTICS`, when the binding is present and usable. */
export function billingAnalyticsFromEnv(env: unknown): BillingAnalyticsDataset | null {
  const dataset = (env as { BILLING_ANALYTICS?: unknown } | null | undefined)?.BILLING_ANALYTICS;
  if (
    dataset === null ||
    dataset === undefined ||
    typeof (dataset as BillingAnalyticsDataset).writeDataPoint !== "function"
  ) {
    return null;
  }
  return dataset as BillingAnalyticsDataset;
}

/** A finite non-negative number, else `0` — a data point never carries NaN. */
function finiteOrZero(value: number | undefined): number {
  return value !== undefined && Number.isFinite(value) && value >= 0 ? value : 0;
}

function parseNumber(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

/**
 * Mirror one settled `BillingEvent` to Analytics Engine. Fire-and-forget and
 * MUST NOT throw — the analytics mirror can never fail the request or the
 * authoritative settlement already committed to the tenant object.
 *
 * Both the OFFER price (the provider's official price) and the FINAL price
 * (offer × the key's billing-group multiplier) are written: when a group applied
 * the offer is read from the `offer_cost_usd` metadata the settle path stamped;
 * with no group the multiplier is `1`, so offer == the final `cost_usd`.
 */
export function writeBillingAnalyticsForEvent(
  dataset: BillingAnalyticsDataset,
  event: BillingEvent,
): void {
  try {
    const finalCostUsd = finiteOrZero(event.cost_usd);
    const multiplier = parseNumber(event.metadata?.billing_multiplier) ?? 1;
    // A group's real offer is stamped on metadata (recoverable even for a 0×
    // comp, where final is $0); with no group the offer is the final cost.
    const offerCostUsd = finiteOrZero(parseNumber(event.metadata?.offer_cost_usd) ?? finalCostUsd);
    dataset.writeDataPoint({
      blobs: [
        event.tenant.organization_id ?? "",
        event.tenant.project_id ?? "",
        event.logical_model,
        event.provider,
        event.metadata?.billing_group_id ?? "",
        event.provider_model,
      ],
      doubles: [
        offerCostUsd,
        finalCostUsd,
        Number.isFinite(multiplier) ? multiplier : 1,
        finiteOrZero(event.usage?.prompt_tokens),
        finiteOrZero(event.usage?.completion_tokens),
      ],
      indexes: [event.tenant.organization_id ?? ""],
    });
  } catch {
    // The analytics mirror is best-effort; the tenant object holds the truth.
  }
}
