import {
  TENANT_STATUS_ROWS_SQL,
  TENANT_STATUS_SNAPSHOT_KEY,
  type TenantStatusRow,
  type TenantStatusSnapshot,
  tenantStatusMapFromRows,
} from "../../../gateway/src/tenant-status-snapshot.js";

export type TenantStatusCachePublishResult =
  | { readonly status: "unconfigured" }
  | {
      readonly status: "published";
      readonly rows: number;
    };

/**
 * Publish the whole `tenants(id → status)` map to `PLATFORM_CONFIG`, mirroring
 * {@link publishPlatformCatalogCache}. The gateway lifecycle gate reads this
 * snapshot colo-locally instead of issuing `LIFECYCLE_TENANT_SQL` against the
 * control authority on every request (see `gateway/src/tenant-status-snapshot.ts`).
 *
 * Unconditional and cheap (one indexed read of a small table), so the scheduled
 * pass can republish every tick to self-heal a lost write — the same contract
 * the catalog and billing-group caches use. Rows carry the raw `status` column
 * verbatim; the gateway reader applies the `active`/deny semantics.
 */
export async function publishTenantStatusCache(options: {
  readonly db: D1Database;
  readonly kv?: KVNamespace;
  readonly nowUnix?: number;
}): Promise<TenantStatusCachePublishResult> {
  if (options.kv === undefined) return { status: "unconfigured" };

  const rows = await options.db.prepare(TENANT_STATUS_ROWS_SQL).all<TenantStatusRow>();
  const statuses = tenantStatusMapFromRows(rows.results ?? []);

  const snapshot: TenantStatusSnapshot = {
    schema_version: 1,
    published_at_unix: options.nowUnix ?? Math.floor(Date.now() / 1000),
    statuses,
  };
  await options.kv.put(TENANT_STATUS_SNAPSHOT_KEY, JSON.stringify(snapshot));
  return { status: "published", rows: Object.keys(statuses).length };
}
