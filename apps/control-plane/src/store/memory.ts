/**
 * In-memory {@link ControlPlaneStore} — the reference implementation.
 *
 * No longer the production store — `src/store/d1.ts` is, whenever the `DB`
 * binding exists — but still the one the unit suites run against and still the
 * one that DEFINES the contract. It is a full, honest implementation of the
 * port, not a stub: create/replace/merge/
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
 * It remains the store the unit suites run against (`CONTROL_PLANE_STORE
 * = "memory"`), and the reference the D1 store is held to: both are driven
 * through the SAME conformance suite (`test/store-conformance.test.ts`) so a
 * behavioural difference between them is a test failure rather than a
 * production-only surprise. The list/search/filter predicates they share live in
 * `./query.ts`.
 */
import {
  type CallerScope,
  type ControlPlaneStore,
  type ListPage,
  type ListQuery,
  StoreConflictError,
  type StoreMutation,
  type StoreRecord,
} from "../ports.js";
import { pageOf, visibleTo } from "./query.js";

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
    const visible = [...this.#bucket(collection).values()].filter((record) =>
      visibleTo(record, scope),
    );
    return Promise.resolve(pageOf(visible, query));
  }

  get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null> {
    const record = this.#bucket(collection).get(id);
    if (record === undefined || !visibleTo(record, scope)) return Promise.resolve(null);
    return Promise.resolve(record);
  }

  // `async` on purpose: a durable store can only REJECT on a conflict, and a
  // synchronous `throw` here would mean `store.create(...).catch(...)` worked
  // against D1 and blew up against memory. The conformance suite holds both to
  // the rejecting form.
  async create(collection: string, scope: CallerScope, record: StoreRecord): Promise<StoreRecord> {
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

  /**
   * {@link ControlPlaneStore.atomic}, the reference semantics.
   *
   * Every reason the unit can fail — a merge target that is absent or invisible,
   * a `create` id that is taken — is decided BEFORE the first `Map.set`, so
   * "nothing was written" holds here for the same reason it holds on D1, and
   * the conformance suite can hold both stores to one contract. The writes
   * themselves are then a synchronous loop with no `await` between them, which
   * on a single-threaded isolate no other request can interleave with.
   *
   * The two passes are in the order the D1 store is FORCED into (it resolves
   * every merge target before it can build a single statement), so which of two
   * simultaneous problems a caller is told about does not depend on which store
   * is bound: an unresolvable merge target is `null` (→ 404) even when the unit
   * also carries a taken `create` id. Deciding it per-mutation-position, as this
   * did, made `[create(taken), merge(missing)]` a 409 here and a 404 on D1.
   */
  async atomic(
    scope: CallerScope,
    mutations: readonly StoreMutation[],
  ): Promise<readonly StoreRecord[] | null> {
    // Pass 1 — resolve every merge target. A missing/invisible one aborts the
    // whole unit before anything else is decided.
    const resolved = new Map<number, StoreRecord>();
    for (const [index, mutation] of mutations.entries()) {
      if (mutation.kind !== "merge") continue;
      const existing = await this.get(mutation.collection, scope, mutation.id);
      if (existing === null) return null;
      resolved.set(index, existing);
    }

    // Pass 2 — plan the writes. A `create` id is refused if it is already
    // stored OR if this same unit already mints it: without the second check
    // the later `Map.set` would silently overwrite the earlier one and the unit
    // would report two records where one row exists.
    const planned: { collection: string; record: StoreRecord }[] = [];
    const mintedIds = new Set<string>();
    for (const [index, mutation] of mutations.entries()) {
      if (mutation.kind === "create") {
        const key = `${mutation.collection} ${mutation.record.id}`;
        if (this.#bucket(mutation.collection).has(mutation.record.id) || mintedIds.has(key)) {
          throw new StoreConflictError(mutation.collection, mutation.record.id);
        }
        mintedIds.add(key);
        planned.push({
          collection: mutation.collection,
          record: {
            ...mutation.record,
            tenant_id:
              scope.kind === "tenant" ? scope.tenantId : (mutation.record.tenant_id ?? null),
          },
        });
        continue;
      }
      // Unreachable: every `merge` resolved in pass 1 or the unit returned.
      const existing = resolved.get(index);
      if (existing === undefined) throw new Error("atomic: unresolved merge target");
      const { id: _ignoredId, tenant_id: _ignoredTenant, ...fields } = mutation.patch;
      planned.push({
        collection: mutation.collection,
        record: {
          ...existing,
          ...fields,
          id: mutation.id,
          tenant_id: existing.tenant_id ?? null,
        },
      });
    }

    for (const { collection, record } of planned) {
      this.#bucket(collection).set(record.id, record);
    }
    return planned.map((entry) => entry.record);
  }
}
