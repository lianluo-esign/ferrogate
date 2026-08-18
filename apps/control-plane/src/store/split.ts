/**
 * Kind-routed control-plane document store (#861).
 *
 * The control D1 store remains the implementation for platform and derived
 * kinds. Tenant-private kinds resolve one `TenantDatabaseHandle`, backfill the
 * legacy compatibility rows into that database, and use an object-local
 * `D1ControlPlaneStore` whose only isolation boundary is the object identity.
 */
import {
  ControlDatabaseTenantRegistry,
  type TenantDatabaseRouter,
  type TenantObjectAddress,
} from "@ferrogate/storage";
import type {
  CallerScope,
  ControlPlaneStore,
  ListPage,
  ListQuery,
  MergeIfOutcome,
  StoreMutation,
  StoreRecord,
} from "../ports.js";
import type { AuditSink } from "./audit-sink.js";
import {
  D1ControlPlaneStore,
  type D1ControlPlaneStoreOptions,
  RESOURCE_TABLE,
  TENANT_RESOURCE_TABLE,
  TENANT_RESOURCE_TOMBSTONE_MARK_PREFIX,
} from "./d1.js";
import { pageOf } from "./query.js";
import { backfillTenantResourceKinds } from "./resource-backfill.js";
import { resourceKindPlacement } from "./resource-kinds.js";
import { getCachedTenantAddress, setCachedTenantAddress } from "./tenant-address-cache.js";

interface TenantStoreMatch {
  readonly tenantId: string;
  readonly store: D1ControlPlaneStore;
  readonly record: StoreRecord;
}

interface TenantStoreTarget {
  /** `null` when the target is an un-attributed platform row on control D1. */
  readonly tenantId: string | null;
  readonly store: D1ControlPlaneStore;
}

/** Collections whose document id IS the owning tenant's id. */
const ID_KEYED_TENANT_COLLECTIONS: ReadonlySet<string> = new Set(["tenant-accounts", "wallets"]);

const UNPAGED_QUERY = (query: ListQuery): ListQuery => ({
  ...query,
  offset: 0,
  limit: Number.MAX_SAFE_INTEGER,
  paginate: false,
});

export interface SplitControlPlaneStoreOptions {
  readonly requestId?: string | null;
  readonly now?: () => number;
  readonly newId?: () => string;
  /**
   * Per-request audit-append sink. When present AND active, control/tenant
   * stores defer audit-chain writes off the synchronous path (login mint). It
   * flows via `#options` into BOTH the control store and every tenant store
   * (whose `auditDatabase` is this same control DB), so a single sink governs
   * deferral across the whole split. Absent for every non-login path/test.
   */
  readonly auditSink?: AuditSink | null;
}

export class SplitControlPlaneStore implements ControlPlaneStore {
  readonly #control: D1ControlPlaneStore;
  readonly #controlDb: D1Database;
  readonly #tenantRouter: TenantDatabaseRouter;
  readonly #registry: ControlDatabaseTenantRegistry;
  readonly #options: SplitControlPlaneStoreOptions;
  // Per-request memo (this store is constructed per request — `#options.requestId`).
  readonly #tenantStores = new Map<string, Promise<D1ControlPlaneStore>>();

  constructor(
    controlDb: D1Database,
    tenantRouter: TenantDatabaseRouter,
    options: SplitControlPlaneStoreOptions = {},
  ) {
    this.#controlDb = controlDb;
    this.#tenantRouter = tenantRouter;
    this.#registry = new ControlDatabaseTenantRegistry(controlDb);
    this.#options = options;
    this.#control = new D1ControlPlaneStore(controlDb, options);
  }

  #controlStore(): D1ControlPlaneStore {
    return this.#control;
  }

  #hasTenantDestination(scope: CallerScope): boolean {
    return scope.kind === "tenant" && scope.tenantId.trim() !== "";
  }

  #tenantStore(tenantId: string): Promise<D1ControlPlaneStore> {
    const normalized = tenantId.trim();
    if (normalized === "")
      throw new Error("tenant-private resource requires a non-empty tenant_id");
    // One admit resolves the SAME declaredTenant up to three times (workspace,
    // project, tenant-account reads), and the roster fan-out re-touches tenants;
    // without this memo each resolution re-ran `registry.get` + the
    // `backfillTenantResourceKinds` probe against the same object. The resolved
    // store is stateless and this instance is per request, so caching the Promise
    // (which also collapses concurrent callers onto one build) is safe. A rejected
    // build is evicted so it never poisons a later reader in the same request.
    const cached = this.#tenantStores.get(normalized);
    if (cached !== undefined) return cached;
    const building = this.#buildTenantStore(normalized);
    this.#tenantStores.set(normalized, building);
    building.catch(() => this.#tenantStores.delete(normalized));
    return building;
  }

  async #buildTenantStore(normalized: string): Promise<D1ControlPlaneStore> {
    // A tenant's object address (jurisdiction + locationHint) is immutable, so an
    // isolate-local hit lets us address the object WITHOUT the per-request read of
    // the single control DO's `tenant_databases` roster — the platform's latency
    // chokepoint. A miss falls back to that read and memoises the result. Only a
    // PRESENT registration is cached (see `tenant-address-cache.ts`): the address
    // a hit yields is byte-identical to the row, so it resolves the same object.
    let address: TenantObjectAddress | undefined = getCachedTenantAddress(normalized);
    if (address === undefined) {
      const registration = await this.#registry.get(normalized);
      if (registration !== undefined) {
        address = {
          ...(registration.locationHint === undefined
            ? {}
            : { locationHint: registration.locationHint }),
          ...(registration.jurisdiction === undefined
            ? {}
            : { jurisdiction: registration.jurisdiction }),
        };
        setCachedTenantAddress(normalized, address);
      }
    }
    const handle = await this.#tenantRouter.forTenant(normalized, address);
    await backfillTenantResourceKinds(this.#controlDb, handle.db, normalized);
    const options: D1ControlPlaneStoreOptions = {
      ...this.#options,
      resourceTable: TENANT_RESOURCE_TABLE,
      isolation: "object",
      objectTenantId: normalized,
      auditDatabase: this.#controlDb,
      tombstoneMarkPrefix: TENANT_RESOURCE_TOMBSTONE_MARK_PREFIX,
    };
    return new D1ControlPlaneStore(handle.db, options);
  }

  /**
   * The tenant a record belongs to, or `null` for an UN-ATTRIBUTED platform
   * row. Those stay on control D1 (see the #861 migration matrix: "un-attributed
   * platform rows stay on control D1"), where `tenantScopeSql`'s read fence
   * keeps them visible to every tenant and `tenantWriteScopeSql` keeps tenant
   * writes off them.
   */
  #ownerForRecord(collection: string, record: StoreRecord): string | null {
    const explicit = typeof record.tenant_id === "string" ? record.tenant_id.trim() : "";
    if (explicit !== "") return explicit;
    // An id-keyed document (tenant account, wallet) is owned by the tenant its
    // id names; the create routes historically allowed the body to omit a
    // duplicate tenant_id.
    if (
      ID_KEYED_TENANT_COLLECTIONS.has(collection) &&
      typeof record.id === "string" &&
      record.id !== ""
    ) {
      return record.id;
    }
    return null;
  }

  /** `record` is an un-attributed platform row control D1 remains authoritative for. */
  #isPlatformRow(collection: string, record: StoreRecord): boolean {
    return this.#ownerForRecord(collection, record) === null;
  }

  /** The un-attributed control-D1 row under this id, or `null`. */
  async #platformRow(
    collection: string,
    scope: CallerScope,
    id: string,
  ): Promise<StoreRecord | null> {
    const record = await this.#control.get(collection, scope, id);
    if (record === null) return null;
    return this.#isPlatformRow(collection, record) ? record : null;
  }

  async #matchTenantResource(collection: string, id: string): Promise<TenantStoreMatch | null> {
    // Documents KEYED BY the tenant id (`tenant-accounts`, `wallets`) resolve
    // their object from the id alone, without the roster: the object's own
    // stamped `tenant_id` validates the addressing, and a tenant whose roster
    // row was never written (or was repaired away) stays reachable. A miss
    // falls through to the roster fan-out for legacy attributions.
    if (ID_KEYED_TENANT_COLLECTIONS.has(collection)) {
      const store = await this.#tenantStore(id);
      const record = await store.get(collection, { kind: "platform_operator" }, id);
      if (record !== null) return { tenantId: id, store, record };
    }
    const matches: TenantStoreMatch[] = [];
    for (const tenantId of await this.#tenantRouter.provisionedTenants()) {
      const store = await this.#tenantStore(tenantId);
      const record = await store.get(collection, { kind: "platform_operator" }, id);
      if (record !== null) matches.push({ tenantId, store, record });
    }
    if (matches.length > 1) {
      throw new Error(`${collection}/${id} has multiple tenant destinations`);
    }
    if (matches.length === 1) return matches[0] ?? null;

    // MCP keeps a named control projection solely as a directory for a fresh
    // tenant that has not entered the roster fan-out yet. The returned record
    // must still come from the object; control D1 is never the resource reader.
    if (collection === "mcp-servers") {
      const directory = await this.#control.get(collection, { kind: "platform_operator" }, id);
      if (directory !== null && this.#ownerForRecord(collection, directory) !== null) {
        const tenantId = this.#ownerForRecord(collection, directory) as string;
        const store = await this.#tenantStore(tenantId);
        const record = await store.get(collection, { kind: "platform_operator" }, id);
        if (record !== null) return { tenantId, store, record };
        // A failed compatibility cleanup can leave only the directory row.
        // It is not an authority row, so repair the stale pointer while the
        // object remains the sole source of the returned resource.
        await this.#controlDb
          .prepare(
            "DELETE FROM control_plane_resources WHERE resource_kind = ? AND resource_id = ?",
          )
          .bind(collection, id)
          .run();
      }
    }
    return null;
  }

  /**
   * Where a mutation of `collection/{id}` must run.
   *
   * A tenant-scoped caller mutates only inside its own object — the write fence
   * never widens onto platform rows, exactly as `tenantWriteScopeSql` refuses
   * them. A platform operator reaches every tenant object through the roster
   * fan-out, and falls back to control D1 only for a row that is genuinely
   * un-attributed (never for a stale tenant-attributed compatibility copy).
   */
  async #tenantMutationStore(
    collection: string,
    scope: CallerScope,
    id: string,
  ): Promise<TenantStoreTarget | null> {
    if (scope.kind === "tenant") {
      if (!this.#hasTenantDestination(scope)) return null;
      const tenantId = scope.tenantId.trim();
      return { tenantId, store: await this.#tenantStore(tenantId) };
    }
    const match = await this.#matchTenantResource(collection, id);
    if (match !== null) return { tenantId: match.tenantId, store: match.store };
    if ((await this.#platformRow(collection, scope, id)) !== null) {
      return { tenantId: null, store: this.#control };
    }
    return null;
  }

  async #listTenantResources(collection: string, query: ListQuery): Promise<ListPage> {
    const seen = new Set<string>();
    const records: StoreRecord[] = [];
    for (const tenantId of await this.#tenantRouter.provisionedTenants()) {
      const local = await (await this.#tenantStore(tenantId)).list(
        collection,
        { kind: "platform_operator" },
        UNPAGED_QUERY(query),
      );
      for (const record of local.items) {
        if (seen.has(String(record.id))) continue;
        seen.add(String(record.id));
        records.push(record);
      }
    }
    for (const record of await this.#platformRows(
      collection,
      { kind: "platform_operator" },
      query,
    )) {
      if (seen.has(String(record.id))) continue;
      seen.add(String(record.id));
      records.push(record);
    }

    return pageOf(records, query);
  }

  /** The kind's UN-ATTRIBUTED control-D1 rows visible to `scope`. */
  async #platformRows(
    collection: string,
    scope: CallerScope,
    query: ListQuery,
  ): Promise<readonly StoreRecord[]> {
    const page = await this.#control.list(collection, scope, UNPAGED_QUERY(query));
    return page.items.filter((record) => this.#isPlatformRow(collection, record));
  }

  #isTenantPrivate(collection: string): boolean {
    return resourceKindPlacement(collection) === "tenant_private";
  }

  async list(collection: string, scope: CallerScope, query: ListQuery): Promise<ListPage> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().list(collection, scope, query);
    if (scope.kind === "tenant") {
      // Full tenant/control isolation (#948): a tenant reads a tenant-private
      // kind from its OWN object only. Shared config no longer merges in at
      // read time — it is pushed one-way into the tenant's read-only mirror
      // tables (`shared_*`) through the async channel, so this hot path never
      // takes a synchronous round trip to the single control object. A tenant
      // credential with no destination has its own (empty) object to read.
      if (!this.#hasTenantDestination(scope)) return pageOf([], query);
      return (await this.#tenantStore(scope.tenantId)).list(collection, scope, query);
    }
    return this.#listTenantResources(collection, query);
  }

  async get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection)) return this.#controlStore().get(collection, scope, id);
    if (scope.kind === "tenant") {
      // Full isolation (#948): a tenant resolves a tenant-private kind from its
      // OWN object, never from control D1. Shared config reaches the tenant
      // through the async mirror push, not a read-time fence, so a get miss is
      // a genuine miss — no synchronous control-object hop on the hot path.
      if (!this.#hasTenantDestination(scope)) return null;
      return (await this.#tenantStore(scope.tenantId)).get(collection, scope, id);
    }
    const match = await this.#matchTenantResource(collection, id);
    if (match !== null) return match.record;
    return this.#platformRow(collection, scope, id);
  }

  async create(collection: string, scope: CallerScope, record: StoreRecord): Promise<StoreRecord> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().create(collection, scope, record);
    if (scope.kind === "tenant") {
      if (this.#hasTenantDestination(scope)) {
        // The object store clamps the stored tenant_id onto the caller's own
        // tenant, exactly as the control-isolation reference does.
        return (await this.#tenantStore(scope.tenantId)).create(collection, scope, record);
      }
      // An unclassified tenant credential stamps its (empty) tenant onto the
      // row — the reference control-store behaviour, kept on control D1.
      return this.#controlStore().create(collection, scope, record);
    }
    const owner = this.#ownerForRecord(collection, record);
    if (owner === null) {
      // A platform-authored row with no tenant destination is an un-attributed
      // platform row, and those stay on control D1 (#861 matrix).
      return this.#controlStore().create(collection, scope, record);
    }
    return (await this.#tenantStore(owner)).create(collection, scope, record);
  }

  async replace(
    collection: string,
    scope: CallerScope,
    id: string,
    record: Omit<StoreRecord, "id">,
  ): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().replace(collection, scope, id, record);
    const target = await this.#tenantMutationStore(collection, scope, id);
    if (target === null) return null;
    return target.store.replace(collection, scope, id, record);
  }

  async merge(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
  ): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().merge(collection, scope, id, patch);
    const target = await this.#tenantMutationStore(collection, scope, id);
    if (target === null) return null;
    return target.store.merge(collection, scope, id, patch);
  }

  async mergeIf(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
    precondition: (current: StoreRecord) => boolean,
  ): Promise<MergeIfOutcome> {
    if (!this.#isTenantPrivate(collection)) {
      return this.#controlStore().mergeIf(collection, scope, id, patch, precondition);
    }
    const target = await this.#tenantMutationStore(collection, scope, id);
    if (target === null) return { kind: "not_found" };
    return target.store.mergeIf(collection, scope, id, patch, precondition);
  }

  async remove(collection: string, scope: CallerScope, id: string): Promise<boolean> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().remove(collection, scope, id);
    const target = await this.#tenantMutationStore(collection, scope, id);
    if (target === null) return false;
    const removed = await target.store.remove(collection, scope, id);
    if (!removed) return false;
    // An un-attributed platform row lives on control D1 itself — the delete
    // above was the authoritative one and there is no compatibility copy.
    if (target.tenantId === null) return true;
    try {
      await this.#controlDb
        .prepare(
          `DELETE FROM ${RESOURCE_TABLE}
            WHERE resource_kind = ? AND resource_id = ?
              AND json_extract(document_json, '$.tenant_id') = ?`,
        )
        .bind(collection, id, target.tenantId)
        .run();
    } catch (error) {
      // The object delete is authoritative and already tombstoned. A stale
      // compatibility row is harmless to runtime reads and is repaired by the
      // next named-directory lookup; do not report a committed delete as 500.
      console.warn("control-plane: tenant resource compatibility cleanup failed", {
        collection,
        id,
        tenantId: target.tenantId,
        error,
      });
    }
    return true;
  }

  async atomic(
    scope: CallerScope,
    mutations: readonly StoreMutation[],
  ): Promise<readonly StoreRecord[] | null> {
    if (mutations.length === 0) return [];
    const placements = mutations.map((mutation) => resourceKindPlacement(mutation.collection));
    if (placements.every((placement) => placement !== "tenant_private")) {
      return this.#controlStore().atomic(scope, mutations);
    }
    if (placements.some((placement) => placement !== "tenant_private")) {
      throw new Error("atomic control-plane mutations cannot span control D1 and a tenant object");
    }

    // `undefined` = not yet decided; `null` = the un-attributed platform rows
    // on control D1; a string = that tenant's object.
    let destination: string | null | undefined =
      scope.kind === "tenant" && scope.tenantId.trim() !== "" ? scope.tenantId : undefined;
    if (destination === undefined) {
      for (const mutation of mutations) {
        // A tenant-scoped unit is clamped onto the caller's own object above;
        // only a platform-authored unit resolves its destination from the
        // records themselves.
        if (mutation.kind !== "create") continue;
        const owner = this.#ownerForRecord(mutation.collection, mutation.record);
        if (destination === undefined) {
          destination = owner;
        } else if (destination !== owner) {
          throw new Error("atomic tenant mutations must share one tenant destination");
        }
      }
    }
    if (destination === undefined) {
      // Merges only: resolve the destination from where the first target row
      // actually lives — a tenant object via the roster fan-out, else the
      // un-attributed control row.
      const first = mutations[0];
      if (first === undefined || first.kind !== "merge") {
        throw new Error("atomic: unresolved tenant mutation");
      }
      const match = await this.#matchTenantResource(first.collection, first.id);
      if (match !== null) {
        destination = match.tenantId;
      } else if (
        (await this.#platformRow(first.collection, { kind: "platform_operator" }, first.id)) !==
        null
      ) {
        destination = null;
      } else {
        return null;
      }
    }
    if (destination === null) return this.#controlStore().atomic(scope, mutations);
    return (await this.#tenantStore(destination)).atomic(scope, mutations);
  }
}

export { RESOURCE_TABLE };
