/**
 * Billing dual-write to Analytics Engine (#956, epic — the fleet view).
 *
 * The authoritative per-transaction cost lives in the tenant's own Durable
 * Object (`billing_events`) and is read one tenant at a time (`cost-records`
 * routes to that object). That copy is EXACT, transactional and long-lived, but
 * it cannot answer a CROSS-TENANT question — "which tenants spent the most this
 * month", "fleet billed total by model" — without an O(N) fan-out to every
 * tenant object, and Cloudflare offers no cross-object query primitive.
 *
 * So settlement ALSO writes one Analytics Engine data point per priced event.
 * Analytics Engine is a write-cheap, columnar, time-series store with a SQL API:
 * the control plane queries it with ONE aggregate query for the whole fleet, no
 * fan-out and NO tenant-private data copied into the control database. It is
 * SAMPLED at high volume and bounded-retention, so it is the ANALYTICS mirror,
 * never the invoicing authority — that stays the tenant object.
 *
 * Both the OFFER price (the provider's official price) and the FINAL price
 * (offer × the key's billing-group multiplier) are written, so a fleet report
 * can show the markup/discount the multiplier applied, exactly like the
 * per-transaction view does.
 */
import type { Usage } from "../inference/ports.js";

/**
 * The slice of `AnalyticsEngineDataset` used here. Declared locally (rather than
 * leaning on the ambient `AnalyticsEngineDataset`) so the seam is a plain object
 * a test can record against, mirroring `apps/telemetry/src/sink.ts`.
 */
export interface BillingAnalyticsDataset {
  writeDataPoint(point: {
    blobs?: (string | null)[];
    doubles?: number[];
    indexes?: string[];
  }): void;
}

/** `env.BILLING_ANALYTICS`, when the binding is present. */
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

/**
 * Write one billing data point. Fire-and-forget and MUST NOT throw — a billing
 * ANALYTICS write can never fail the request or the authoritative settlement
 * that already committed to the tenant object. `writeDataPoint` is a synchronous
 * local binding call (no network), so a throw would be a programming error, but
 * it is guarded anyway.
 *
 * Blobs are the query dimensions; doubles are the measures; the index is the
 * sampling key (the tenant, so a per-tenant rollup samples coherently).
 */
export function writeBillingAnalytics(
  dataset: BillingAnalyticsDataset,
  usage: Usage,
  offerCostUsd: number | undefined,
  finalCostUsd: number | undefined,
): void {
  try {
    dataset.writeDataPoint({
      blobs: [
        usage.tenantId ?? "",
        usage.projectId ?? "",
        usage.logicalModel,
        usage.provider,
        usage.billingGroupId ?? "",
        usage.providerModel,
      ],
      doubles: [
        finiteOrZero(offerCostUsd),
        finiteOrZero(finalCostUsd),
        usage.billingMultiplier !== undefined && Number.isFinite(usage.billingMultiplier)
          ? usage.billingMultiplier
          : 1,
        finiteOrZero(usage.promptTokens),
        finiteOrZero(usage.completionTokens),
      ],
      indexes: [usage.tenantId ?? ""],
    });
  } catch {
    // The analytics mirror is best-effort; the tenant object holds the truth.
  }
}
