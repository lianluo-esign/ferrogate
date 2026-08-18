/**
 * Isolate-local cache of a tenant's IMMUTABLE Durable Object address
 * (`jurisdiction` + `locationHint`).
 *
 * ## Why
 *
 * `SplitControlPlaneStore` resolves a tenant object for every tenant-private
 * read/write. Resolving it needs the tenant's {@link TenantObjectAddress}, which
 * today comes from a `SELECT ... FROM tenant_databases` read on the single
 * `ControlDataObject` (the control DO facade). That singleton is the platform's
 * latency chokepoint — each RPC to it is a cross-region, single-threaded hop —
 * so paying a registry read on the hot path of every authenticated tenant
 * request is a per-request tax on the one object we most want to avoid.
 *
 * A tenant's address is IMMUTABLE after creation: `jurisdiction` is a hard
 * namespace boundary that cannot change without a data migration, and
 * `locationHint` is a best-effort placement preference that Cloudflare only
 * honours at the object's FIRST instantiation (it is a no-op for an existing
 * object). Because it never changes, it is safe to cache for the life of the
 * isolate. This is the same isolate-local-map pattern the gateway already uses
 * for its api-key resolution cache (`apps/gateway/src/keys/cache.ts`).
 *
 * ## Correctness
 *
 * Only a PRESENT registration is cached. An ABSENT one (the brief window during
 * self-registration before `provisionTenantStorageFor` writes the roster row)
 * is never memoised as "no address", so a tenant that later gains a jurisdiction
 * can never be pinned to the wrong (default-namespace) object by a stale miss.
 * The address a caller reads back is byte-identical to the registry row, so a
 * cache hit and a cache miss address exactly the same Durable Object.
 */
import type { TenantObjectAddress } from "@ferrogate/storage";

/**
 * Bound the map so a long-lived isolate serving a large fleet cannot grow it
 * without limit. The entries are tiny (two optional enum strings), so this is a
 * memory backstop rather than a tuned working-set size.
 */
const MAX_ENTRIES = 8192;

const cache = new Map<string, TenantObjectAddress>();

/** The cached immutable address for `tenantId`, or `undefined` on a miss. */
export function getCachedTenantAddress(tenantId: string): TenantObjectAddress | undefined {
  const hit = cache.get(tenantId);
  if (hit === undefined) return undefined;
  // Re-insert to keep the most-recently-used key last for the size eviction.
  cache.delete(tenantId);
  cache.set(tenantId, hit);
  return hit;
}

/** Memoise a tenant's immutable address. Call ONLY for a present registration. */
export function setCachedTenantAddress(tenantId: string, address: TenantObjectAddress): void {
  if (cache.has(tenantId)) cache.delete(tenantId);
  cache.set(tenantId, address);
  while (cache.size > MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

/** Test-only: drop all memoised addresses. */
export function clearTenantAddressCache(): void {
  cache.clear();
}
