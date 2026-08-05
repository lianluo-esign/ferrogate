/**
 * Kind-routed control-plane document store (#861).
 *
 * The control D1 store remains the implementation for platform and derived
 * kinds. Tenant-private kinds resolve one `TenantDatabaseHandle`, backfill the
 * legacy compatibility rows into that database, and use an object-local
 * `D1ControlPlaneStore` whose only isolation boundary is the object identity.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import {
  type CallerScope,
  type ControlPlaneStore,
  type ListPage,
  type ListQuery,
  type MergeIfOutcome,
  type StoreMutation,
  type StoreRecord,
  StoreConflictError,
} from "../ports.js";
import { pageOf } from "./query.js";
import {
  D1ControlPlaneStore,
  type D1ControlPlaneStoreOptions,
  RESOURCE_TABLE,
  TENANT_RESOURCE_TABLE,
} from "./d1.js";
import { backfillTenantResourceKinds } from "./resource-backfill.js";
import { resourceKindPlacement } from "./resource-kinds.js";

interface TenantStoreMatch {
  readonly tenantId: string;
  readonly store: D1ControlPlaneStore;
  readonly record: StoreRecord;
}

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
}

export class SplitControlPlaneStore implements ControlPlaneStore {
  readonly #control: D1ControlPlaneStore;
  readonly #controlDb: D1Database;
  readonly #tenantRouter: TenantDatabaseRouter;
  readonly #options: SplitControlPlaneStoreOptions;

  constructor(
    controlDb: D1Database,
    tenantRouter: TenantDatabaseRouter,
    options: SplitControlPlaneStoreOptions = {},
  ) {
    this.#controlDb = controlDb;
    this.#tenantRouter = tenantRouter;
    this.#options = options;
    this.#control = new D1ControlPlaneStore(controlDb, options);
  }

  #controlStore(): D1ControlPlaneStore {
    return this.#control;
  }

  async #tenantStore(tenantId: string): Promise<D1ControlPlaneStore> {
    const normalized = tenantId.trim();
    if (normalized === "")
      throw new Error("tenant-private resource requires a non-empty tenant_id");
    const handle = await this.#tenantRouter.forTenant(normalized);
    await backfillTenantResourceKinds(this.#controlDb, handle.db, normalized);
    const options: D1ControlPlaneStoreOptions = {
      ...this.#options,
      resourceTable: TENANT_RESOURCE_TABLE,
      isolation: "object",
      objectTenantId: normalized,
      auditDatabase: this.#controlDb,
    };
    return new D1ControlPlaneStore(handle.db, options);
  }

  #ownerForRecord(collection: string, record: StoreRecord): string {
    const explicit = typeof record.tenant_id === "string" ? record.tenant_id.trim() : "";
    if (explicit !== "") return explicit;
    // The tenant-account document is keyed by the tenant id and its create
    // route historically allowed the body to omit a duplicate tenant_id.
    if (collection === "tenant-accounts" && typeof record.id === "string" && record.id !== "") {
      return record.id;
    }
    throw new Error(`${collection}/${String(record.id)} has no named tenant destination`);
  }

  #ownerForScope(scope: CallerScope, collection: string, record?: StoreRecord): string {
    if (scope.kind === "tenant") return scope.tenantId;
    if (record !== undefined) return this.#ownerForRecord(collection, record);
    throw new Error(`${collection} platform operation requires a tenant destination`);
  }

  async #matchTenantResource(collection: string, id: string): Promise<TenantStoreMatch | null> {
    const matches: TenantStoreMatch[] = [];
    for (const tenantId of await this.#tenantRouter.provisionedTenants()) {
      const store = await this.#tenantStore(tenantId);
      const record = await store.get(collection, { kind: "platform_operator" }, id);
      if (record !== null) matches.push({ tenantId, store, record });
    }
    if (matches.length > 1) {
      throw new Error(`${collection}/${id} has multiple tenant destinations`);
    }
    return matches[0] ?? null;
  }

  async #tenantMutationStore(
    collection: string,
    scope: CallerScope,
    id: string,
  ): Promise<D1ControlPlaneStore | null> {
    if (scope.kind === "tenant") return this.#tenantStore(scope.tenantId);
    const match = await this.#matchTenantResource(collection, id);
    if (match !== null) return match.store;
    const legacy = await this.#control.get(collection, { kind: "platform_operator" }, id);
    if (legacy === null) return null;
    return this.#tenantStore(this.#ownerForRecord(collection, legacy));
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

    // Compatibility rows are retained in control D1 until the backfill is
    // complete. An object-local row wins on duplicate id, so a resumed copy can
    // never make an older control document visible over a newer object write.
    const legacy = await this.#control.list(
      collection,
      { kind: "platform_operator" },
      UNPAGED_QUERY(query),
    );
    for (const record of legacy.items) {
      if (seen.has(String(record.id))) continue;
      seen.add(String(record.id));
      records.push(record);
    }
    return pageOf(records, query);
  }

  #isTenantPrivate(collection: string): boolean {
    return resourceKindPlacement(collection) === "tenant_private";
  }

  async list(collection: string, scope: CallerScope, query: ListQuery): Promise<ListPage> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().list(collection, scope, query);
    if (scope.kind === "tenant") {
      return (await this.#tenantStore(scope.tenantId)).list(collection, scope, query);
    }
    return this.#listTenantResources(collection, query);
  }

  async get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection)) return this.#controlStore().get(collection, scope, id);
    if (scope.kind === "tenant")
      return (await this.#tenantStore(scope.tenantId)).get(collection, scope, id);
    const match = await this.#matchTenantResource(collection, id);
    if (match !== null) return match.record;
    return this.#controlStore().get(collection, scope, id);
  }

  async create(collection: string, scope: CallerScope, record: StoreRecord): Promise<StoreRecord> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().create(collection, scope, record);
    const tenantId = this.#ownerForScope(scope, collection, record);
    return (await this.#tenantStore(tenantId)).create(collection, scope, record);
  }

  async replace(
    collection: string,
    scope: CallerScope,
    id: string,
    record: Omit<StoreRecord, "id">,
  ): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().replace(collection, scope, id, record);
    const store = await this.#tenantMutationStore(collection, scope, id);
    if (store === null) return null;
    return store.replace(collection, scope, id, record);
  }

  async merge(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
  ): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().merge(collection, scope, id, patch);
    const store = await this.#tenantMutationStore(collection, scope, id);
    if (store === null) return null;
    return store.merge(collection, scope, id, patch);
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
    const store = await this.#tenantMutationStore(collection, scope, id);
    if (store === null) return { kind: "not_found" };
    return store.mergeIf(collection, scope, id, patch, precondition);
  }

  async remove(collection: string, scope: CallerScope, id: string): Promise<boolean> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().remove(collection, scope, id);
    const store = await this.#tenantMutationStore(collection, scope, id);
    if (store === null) return false;
    return store.remove(collection, scope, id);
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

    let tenantId: string | null = scope.kind === "tenant" ? scope.tenantId : null;
    for (const mutation of mutations) {
      const candidate =
        mutation.kind === "create"
          ? this.#ownerForRecord(mutation.collection, mutation.record)
          : tenantId;
      if (candidate === null) {
        if (mutation.kind !== "merge") throw new Error("atomic: unresolved tenant mutation");
        const match = await this.#matchTenantResource(mutation.collection, mutation.id);
        if (match === null) return null;
        tenantId = match.tenantId;
      } else if (tenantId === null) {
        tenantId = candidate;
      } else if (tenantId !== candidate) {
        throw new Error("atomic tenant mutations must share one tenant destination");
      }
    }
    if (tenantId === null) throw new Error("atomic tenant mutations have no named destination");
    return (await this.#tenantStore(tenantId)).atomic(scope, mutations);
  }
}

export { RESOURCE_TABLE };
