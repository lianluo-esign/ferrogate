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

/**
 * Fan ONE read out over EVERY provisioned tenant object and concatenate the
 * results — the unbounded sibling of {@link provisionedTenantPage}, for reads
 * whose answer is an AGGREGATE (a sum, a fold) rather than a page of rows, where
 * a roster cursor would return a partial total that reads as a whole one.
 *
 * Per-object isolation: a tenant whose object is unreachable, or that is not a
 * durable object, contributes nothing rather than failing the fleet read — the
 * same discipline the finops spend sweep and the evidence fleet pages apply.
 * Objects are read concurrently; each read is one subrequest per tenant, so a
 * caller should batch its statements per object rather than call this once per
 * statement.
 */
export async function fanOutProvisionedTenants<T>(
  router: TenantDatabaseRouter,
  read: (db: D1Database, tenantId: string) => Promise<T[]>,
  label = "fleet",
): Promise<T[]> {
  const tenantIds = [...(await router.provisionedTenants())].sort();
  const perTenant = await Promise.all(
    tenantIds.map(async (tenantId) => {
      try {
        const handle = await router.forTenant(tenantId);
        if (handle.source !== "durable_object") return [];
        return await read(handle.db, tenantId);
      } catch (error) {
        console.warn(
          `control-plane: ${label} fan-out failed for tenant`,
          tenantId,
          error instanceof Error ? error.name : "",
        );
        return [];
      }
    }),
  );
  return perTenant.flat();
}

/** Parse the separate tenant-page cursor used by cross-tenant admin reads. */
export function tenantFanoutOffset(url: URL): number {
  const raw = url.searchParams.get("tenant_offset");
  if (raw === null) return 0;
  const parsed = Number.parseInt(raw, 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
}
