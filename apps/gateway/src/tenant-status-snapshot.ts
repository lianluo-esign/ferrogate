/**
 * The `tenants.status` KV projection — one shared snapshot that lets the gateway
 * lifecycle gate answer "is this tenant admitted?" WITHOUT a per-request read of
 * the control authority.
 *
 * ## Why this exists
 *
 * `LIFECYCLE_TENANT_SQL` (`SELECT id, status FROM tenants WHERE id = ?1`, see
 * `adapters.ts`) runs on the auth hot path of EVERY request. It is the one
 * lifecycle read with no cache and no per-tenant isolation: under the `"d1"`
 * control posture it is a colo-local replica read (cheap), but under the
 * `"durable_object"` posture it becomes one round trip to the SINGLETON control
 * object per request — the fleet-scale bottleneck that the D1→DO cutover has to
 * remove before it is safe. This snapshot removes that read under BOTH postures:
 * the whole `tenants(id → status)` map is published to `PLATFORM_CONFIG` (the
 * same KV the model-catalog and billing-group snapshots use) and the gate reads
 * it colo-locally, exactly like {@link PLATFORM_CATALOG_SNAPSHOT_KEY}.
 *
 * ## The snapshot is only ever a FAST PATH, never a new authority
 *
 * The reader in `adapters.ts` trusts this snapshot ONLY when it names the tenant
 * AND the stored status parses to `active` — the 99.9% hot case. Anything else —
 * a non-active status, a tenant absent from the snapshot, a malformed blob, or a
 * KV read that fails — falls THROUGH to the unchanged control read, which stays
 * the deny authority. So the snapshot can only ever let an ACTIVE tenant skip a
 * read it would have passed anyway; it can never invent an admission a fresh
 * control read would have denied. The single behavioural delta is propagation
 * latency in the active→suspended direction, bounded by the publish cadence.
 */

/** One shared KV object, atomically replaced after every `tenants` projection. */
export const TENANT_STATUS_SNAPSHOT_KEY = "platform-config:tenant-status:v1";

/**
 * The columns the gateway lifecycle read consumes. Same table and same two
 * columns as `LIFECYCLE_TENANT_SQL`, minus its `WHERE id = ?1` — the publisher
 * materialises the WHOLE map in one read so the per-id lookup is a KV hit.
 */
export const TENANT_STATUS_ROWS_SQL = "SELECT id, status FROM tenants";

export interface TenantStatusSnapshot {
  readonly schema_version: 1;
  readonly published_at_unix: number;
  /** `tenant id → raw status string`, verbatim from the `tenants.status` column. */
  readonly statuses: Readonly<Record<string, string>>;
}

/** A `tenants` row as the publisher reads it (id + raw status column). */
export interface TenantStatusRow {
  readonly id: string;
  readonly status: string | null;
}

/**
 * Fold `SELECT id, status FROM tenants` rows into the snapshot map. A NULL or
 * absent status is stored as `""` — the SAME value `asLifecycleRow` substitutes,
 * so the reader parses it to `active` (the fail-OPEN #514 default) identically
 * whether the answer came from KV or from the control row.
 */
export function tenantStatusMapFromRows(rows: readonly TenantStatusRow[]): Record<string, string> {
  const statuses: Record<string, string> = {};
  for (const row of rows) {
    if (typeof row.id !== "string" || row.id === "") continue;
    statuses[row.id] = typeof row.status === "string" ? row.status : "";
  }
  return statuses;
}

/** Parse and validate a stored snapshot; any shape violation is `null`. */
export function parseTenantStatusSnapshot(raw: string): TenantStatusSnapshot | null {
  try {
    const parsed = JSON.parse(raw) as Partial<TenantStatusSnapshot>;
    if (
      parsed.schema_version !== 1 ||
      !Number.isSafeInteger(parsed.published_at_unix) ||
      (parsed.published_at_unix ?? -1) < 0 ||
      typeof parsed.statuses !== "object" ||
      parsed.statuses === null ||
      Array.isArray(parsed.statuses)
    ) {
      return null;
    }
    return parsed as TenantStatusSnapshot;
  } catch {
    return null;
  }
}

/**
 * The `KVNamespace.get` subset the reader needs — kept structural so a test can
 * pass a stub and so this module never has to import worker types.
 */
export interface TenantStatusKvReader {
  get(key: string, options?: { cacheTtl?: number }): Promise<string | null>;
}

/**
 * Read the current snapshot from KV, or `null` when it is absent, malformed, or
 * the read throws. A `null` here is the reader's signal to fall back to the
 * control read, so a KV outage degrades to exactly today's behaviour rather than
 * to a lifecycle failure.
 */
export async function readTenantStatusSnapshot(
  kv: TenantStatusKvReader,
): Promise<TenantStatusSnapshot | null> {
  let raw: string | null;
  try {
    raw = await kv.get(TENANT_STATUS_SNAPSHOT_KEY, { cacheTtl: 30 });
  } catch {
    return null;
  }
  if (raw === null) return null;
  return parseTenantStatusSnapshot(raw);
}
