import type { TenantDatabaseRouter } from "@ferrogate/storage";

/**
 * Maximum number of tenant objects one admin request may read live. A page
 * above this bound is explicit so an inventory never looks complete merely
 * because the product acquired another tenant.
 */
export const FLEET_FANOUT_MAX_TENANTS = 50;

export interface TenantFanoutPage {
  readonly tenantIds: readonly string[];
  readonly offset: number;
  readonly limit: number;
  readonly total: number;
  readonly hasMore: boolean;
}

/** Read the control roster and select one bounded live-fan-out page. */
export async function provisionedTenantPage(
  router: TenantDatabaseRouter,
  requestedOffset = 0,
): Promise<TenantFanoutPage> {
  const offset =
    Number.isSafeInteger(requestedOffset) && requestedOffset >= 0 ? requestedOffset : 0;
  const tenantIds = [...(await router.provisionedTenants())].sort();
  const page = tenantIds.slice(offset, offset + FLEET_FANOUT_MAX_TENANTS);
  return {
    tenantIds: page,
    offset,
    limit: FLEET_FANOUT_MAX_TENANTS,
    total: tenantIds.length,
    hasMore: offset + page.length < tenantIds.length,
  };
}

/** Parse the separate tenant-page cursor used by cross-tenant admin reads. */
export function tenantFanoutOffset(url: URL): number {
  const raw = url.searchParams.get("tenant_offset");
  if (raw === null) return 0;
  const parsed = Number.parseInt(raw, 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
}
