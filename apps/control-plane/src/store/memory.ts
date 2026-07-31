/**
 * In-memory {@link ControlPlaneStore} — the reference implementation.
 *
 * Its job is to make the Worker RUNNABLE and the behaviour TESTABLE now, while
 * `@ferrogate/storage` (D1) is written concurrently. It is a full, honest
 * implementation of the port's contract, not a stub: create/replace/merge/
 * remove/list all behave, and — the part that actually matters — **tenant
 * isolation is enforced here rather than in each of the 197 handlers.**
 *
 * That placement is deliberate. The repeat defect class in the Rust tree
 * (issues #185, #186) was a handler that resolved a row by bare id and forgot
 * the tenant check, turning "read another tenant's self-hosted worker" into a
 * one-line omission. Putting the check in the store makes cross-tenant leakage
 * impossible to reintroduce by forgetting something in a handler.
 *
 * Rust parity notes:
 *  - a tenant-scoped caller sees only rows whose `tenant_id` equals its own,
 *    and `get`/`replace`/`merge`/`remove` return "absent" (→ 404) rather than
 *    403 for a row it cannot see — "nonexistent means safe to touch" is
 *    explicitly the wrong default, so resolution failure denies;
 *  - `create` stamps the caller's `tenant_id` and refuses to let a tenant-scoped
 *    caller declare someone else's;
 *  - a platform operator sees every row and may address any tenant.
 *
 * PORT-TODO(inventory-data-billing §storage): replace with a D1-backed adapter
 * over `@ferrogate/storage` once that package lands. The port surface does not
 * change; only this file is swapped in the composition root.
 */
import {
  type CallerScope,
  type ControlPlaneStore,
  type ListPage,
  type ListQuery,
  StoreConflictError,
  type StoreRecord,
} from "../ports.js";

/** Fields a `?search=` scans, in the order Rust's `matches_search` receives them. */
const SEARCH_FIELDS = ["id", "name", "hostname", "status", "description", "kind", "type"];

function matchesSearch(record: StoreRecord, search: string | null): boolean {
  if (search === null) return true;
  const needle = search.toLowerCase();
  return SEARCH_FIELDS.some((field) => {
    const value = record[field];
    return typeof value === "string" && value.toLowerCase().includes(needle);
  });
}

function matchesFilters(record: StoreRecord, filters: Readonly<Record<string, string>>): boolean {
  return Object.entries(filters).every(([key, expected]) => {
    const value = record[key];
    if (value === undefined || value === null) return false;
    return String(value) === expected;
  });
}

/** A tenant-scoped caller may only see rows attributed to its own tenant. */
function visibleTo(record: StoreRecord, scope: CallerScope): boolean {
  if (scope.kind === "platform_operator") return true;
  // An un-attributed row is global/platform data; a tenant caller may read it
  // but (see `create`/`replace`) never claims it. Rows belonging to another
  // tenant are invisible.
  const owner = record.tenant_id;
  if (owner === undefined || owner === null) return true;
  return owner === scope.tenantId;
}

export interface MemoryStoreSeed {
  readonly [collection: string]: readonly StoreRecord[];
}

/**
 * A `Map<collection, Map<id, record>>`. Insertion order is preserved, so list
 * ordering is stable and pagination is deterministic across calls.
 */
export class MemoryControlPlaneStore implements ControlPlaneStore {
  readonly #collections = new Map<string, Map<string, StoreRecord>>();

  constructor(seed: MemoryStoreSeed = {}) {
    for (const [collection, records] of Object.entries(seed)) {
      for (const record of records) this.#bucket(collection).set(record.id, { ...record });
    }
  }

  #bucket(collection: string): Map<string, StoreRecord> {
    let bucket = this.#collections.get(collection);
    if (bucket === undefined) {
      bucket = new Map<string, StoreRecord>();
      this.#collections.set(collection, bucket);
    }
    return bucket;
  }

  /** Every collection that currently holds at least one row (test helper). */
  collections(): readonly string[] {
    return [...this.#collections.keys()];
  }

  list(collection: string, scope: CallerScope, query: ListQuery): Promise<ListPage> {
    const all = [...this.#bucket(collection).values()].filter(
      (record) =>
        visibleTo(record, scope) &&
        matchesSearch(record, query.search) &&
        matchesFilters(record, query.filters),
    );
    if (!query.paginate) return Promise.resolve({ items: all, total: all.length });
    return Promise.resolve({
      items: all.slice(query.offset, query.offset + query.limit),
      total: all.length,
    });
  }

  get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null> {
    const record = this.#bucket(collection).get(id);
    if (record === undefined || !visibleTo(record, scope)) return Promise.resolve(null);
    return Promise.resolve(record);
  }

  create(collection: string, scope: CallerScope, record: StoreRecord): Promise<StoreRecord> {
    const bucket = this.#bucket(collection);
    if (bucket.has(record.id)) throw new StoreConflictError(collection, record.id);
    const stored: StoreRecord = {
      ...record,
      // A tenant-scoped caller cannot mint a row into another tenant.
      tenant_id: scope.kind === "tenant" ? scope.tenantId : (record.tenant_id ?? null),
    };
    bucket.set(stored.id, stored);
    return Promise.resolve(stored);
  }

  async replace(
    collection: string,
    scope: CallerScope,
    id: string,
    record: Omit<StoreRecord, "id">,
  ): Promise<StoreRecord | null> {
    const existing = await this.get(collection, scope, id);
    if (existing === null) return null;
    const stored: StoreRecord = { ...record, id, tenant_id: existing.tenant_id ?? null };
    this.#bucket(collection).set(id, stored);
    return stored;
  }

  async merge(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
  ): Promise<StoreRecord | null> {
    const existing = await this.get(collection, scope, id);
    if (existing === null) return null;
    // `id` and `tenant_id` are structural, never patchable.
    const { id: _ignoredId, tenant_id: _ignoredTenant, ...fields } = patch;
    const stored: StoreRecord = {
      ...existing,
      ...fields,
      id,
      tenant_id: existing.tenant_id ?? null,
    };
    this.#bucket(collection).set(id, stored);
    return stored;
  }

  async remove(collection: string, scope: CallerScope, id: string): Promise<boolean> {
    const existing = await this.get(collection, scope, id);
    if (existing === null) return false;
    return this.#bucket(collection).delete(id);
  }
}
