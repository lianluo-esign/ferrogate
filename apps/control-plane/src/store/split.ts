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

interface TenantStoreMatch {
  readonly tenantId: string;
  readonly store: D1ControlPlaneStore;
  readonly record: StoreRecord;
}

interface TenantStoreTarget {
  readonly tenantId: string;
  readonly store: D1ControlPlaneStore;
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
  readonly #registry: ControlDatabaseTenantRegistry;
  readonly #options: SplitControlPlaneStoreOptions;

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

  async #tenantStore(tenantId: string): Promise<D1ControlPlaneStore> {
    const normalized = tenantId.trim();
    if (normalized === "")
      throw new Error("tenant-private resource requires a non-empty tenant_id");
    const registration = await this.#registry.get(normalized);
    const address: TenantObjectAddress | undefined =
      registration === undefined
        ? undefined
        : {
            ...(registration.locationHint === undefined
              ? {}
              : { locationHint: registration.locationHint }),
            ...(registration.jurisdiction === undefined
              ? {}
              : { jurisdiction: registration.jurisdiction }),
          };
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

  async #knownTenantAccount(id: string): Promise<boolean> {
    const row = await this.#controlDb
      .prepare("SELECT 1 AS present FROM tenants WHERE id = ? LIMIT 1")
      .bind(id)
      .first<{ present: number }>();
    return row !== null;
  }

  async #matchTenantResource(collection: string, id: string): Promise<TenantStoreMatch | null> {
    // The tenant-account document is addressed by its tenant id. Its typed
    // projection remains the durable existence signal even if a provisioning
    // repair test or an operator has removed the storage roster row.
    if (collection === "tenant-accounts" && (await this.#knownTenantAccount(id))) {
      const store = await this.#tenantStore(id);
      const record = await store.get(collection, { kind: "platform_operator" }, id);
      return record === null ? null : { tenantId: id, store, record };
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
      if (directory !== null) {
        const tenantId = this.#ownerForRecord(collection, directory);
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

    return pageOf(records, query);
  }

  #isTenantPrivate(collection: string): boolean {
    return resourceKindPlacement(collection) === "tenant_private";
  }

  async list(collection: string, scope: CallerScope, query: ListQuery): Promise<ListPage> {
    if (!this.#isTenantPrivate(collection))
      return this.#controlStore().list(collection, scope, query);
    if (scope.kind === "tenant") {
      if (!this.#hasTenantDestination(scope)) {
        return pageOf([], query);
      }
      return (await this.#tenantStore(scope.tenantId)).list(collection, scope, query);
    }
    return this.#listTenantResources(collection, query);
  }

  async get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null> {
    if (!this.#isTenantPrivate(collection)) return this.#controlStore().get(collection, scope, id);
    if (scope.kind === "tenant" && this.#hasTenantDestination(scope))
      return (await this.#tenantStore(scope.tenantId)).get(collection, scope, id);
    if (scope.kind === "tenant") return null;
    const match = await this.#matchTenantResource(collection, id);
    return match?.record ?? null;
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
