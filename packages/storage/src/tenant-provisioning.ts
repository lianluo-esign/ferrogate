/**
 * Tenant onboarding on the Durable-Object backend (#820).
 *
 * ## What onboarding used to be, and what is left of it
 *
 * Before the Durable Object backend it required creating a D1 database,
 * writing a `[[d1_databases]]` stanza, deploying, and applying migrations.
 * Every one of those steps is gone. A
 * Durable Object materialises the instant `idFromName(tenantId)` is addressed,
 * and `TenantDataObject` applies `sql/d1-ts/tenant/*.sql` to itself under
 * `blockConcurrencyWhile` on every cold start (#822). There is no database to
 * create, no deploy, and no migration runner to write.
 *
 * What is left is the part the old design never had to think about, because a
 * human ran it:
 *
 *  1. **Refusing.** First touch is now the provisioning event. An object exists
 *     the moment anyone calls `idFromName` and writes a byte — a typo, a probe,
 *     a deleted tenant. A namespace that accumulates junk objects bills for
 *     their storage forever and cannot be enumerated to find them. So this
 *     module checks the `tenants` row FIRST, and refuses BEFORE the object is
 *     addressed. That ordering is the whole guard: checking afterwards creates
 *     exactly the object it was meant to prevent.
 *  2. **Recording.** A DO namespace cannot be listed in production, so
 *     `tenant_databases` is the only roster there is, and
 *     `provisionedTenants()` — which `apps/control-plane/src/store/asset_fleet.ts`
 *     fans out over — reads it. Nothing wrote it. A tenant created today would
 *     be invisible to every fleet view.
 *  3. **Seeding.** The tenant's own `catalog_models` and priced offerings, so per-tenant visibility
 *     and per-tenant pricing have rows to read when the reader lands, rather
 *     than needing a backfill over objects a namespace cannot enumerate. This
 *     list used to say an unseeded tenant answers `400 model_not_found` on
 *     every inference request; it does not, and `./tenant-model-catalog.ts`
 *     records what was actually true.
 *
 * ## Two stores, one operation, and therefore no transaction
 *
 * Steps 2 and 3 land in DIFFERENT stores — the control D1 and the tenant's own
 * object — and there is no cross-store transaction anywhere on this platform. So
 * a crash between them is not an edge case, it is a matter of time, and the only
 * question that matters is whether the result is DISTINGUISHABLE from a healthy
 * tenant. The ordering here makes it so:
 *
 * | order | a crash right after leaves | detected by |
 * |---|---|---|
 * | 1. verify the `tenants` row | nothing; no object addressed, no row written | — |
 * | 2. write `pending` | a roster row that says "started, never finished" | `listUnfinished()` |
 * | 3. observe the schema version | the same | `listUnfinished()` |
 * | 4. seed the catalog | a tenant marked `incomplete` with the seed error | `listUnfinished()`; the resume re-reads the object's own seed mark and does NOT re-seed |
 * | 5. write `ready` | a healthy tenant | — |
 *
 * The inverse ordering is the tempting one and it is wrong: writing `ready`
 * first and provisioning afterwards makes a crashed onboarding
 * indistinguishable from a finished one, which is precisely the shape of "some
 * tenants mysteriously have no models".
 *
 * Every failure is also RECORDED. Structural failures write `failed` with the
 * refusal's own message before re-raising; a catalog-only failure writes
 * `incomplete` and returns normally because the gateway's current env catalog
 * remains usable. A tenant that failed because it had no `tenants` row, one that
 * failed because schema apply threw, and one waiting for a seed retry get
 * different fixes.
 *
 * ## Idempotent, by construction rather than by convention
 *
 * Re-running is a no-op that cannot clobber: the catalog seed is gated on a mark
 * inside the tenant's OWN storage (not on the control row, which this slice's
 * own migration rebuilds), and the roster write is an upsert whose
 * `provisioned_at_unix` is not re-stamped. So "resume the unfinished tenants" is
 * safe to run over the whole fleet, including the healthy ones.
 */
import { StorageError } from "./errors.js";
import { parseLifecycleStatus } from "./lifecycle-status.js";
import {
  DEFAULT_TENANT_MODEL_CATALOG,
  type TenantModelCatalogEntry,
  listTenantModelCatalog,
  seedTenantModelCatalog,
} from "./tenant-model-catalog.js";
import {
  ControlDatabaseTenantRegistry,
  type TenantDatabaseRegistration,
  type TenantDatabaseRouter,
  type TenantDatabaseSource,
  type TenantProvisioningStatus,
} from "./tenant-router.js";

/** What one provisioning run did. Every field is an observation, not a plan. */
export interface TenantProvisioningOutcome {
  readonly tenantId: string;
  /** `ready` on success; `incomplete` when only catalog seeding needs a retry. */
  readonly status: TenantProvisioningStatus;
  /** Where this tenant's data physically lives, taken from the resolved handle. */
  readonly storageBackend: TenantDatabaseSource;
  /** The version the tenant's own `storage_schema_migrations` ledger reported. */
  readonly schemaVersion: number;
  /** `true` when THIS call seeded the catalog; `false` when it was already seeded. */
  readonly catalogSeeded: boolean;
  /** Rows in the tenant's catalog after this call — the "non-empty" evidence. */
  readonly catalogEntries: number;
  /**
   * `true` when a roster row already existed in a non-`ready` state, i.e. this
   * call resumed a half-provisioned tenant rather than onboarding a new one.
   */
  readonly resumed: boolean;
}

/** Options for {@link provisionTenantStorage}. */
export interface TenantProvisioningOptions {
  /** Unix SECONDS. Injected so a test can pin the timestamps it asserts on. */
  readonly nowUnix?: number;
  /** Seed content. Defaults to the platform card in `./tenant-model-catalog.ts`. */
  readonly catalog?: readonly TenantModelCatalogEntry[];
  /**
   * The `locationHint` the object was addressed with, recorded for audit. A
   * Durable Object is homed near its first `get()` and CANNOT be moved
   * afterwards, so this choice is permanent; recording it is what makes it
   * auditable rather than accidental (cost #1 in the design doc).
   */
  readonly locationHint?: string;
}

/**
 * The `tenants` row this module refuses without.
 *
 * Only the two columns that decide admission. `status` gates exactly one value,
 * `deleted`; `suspended` and `disabled` are admitted on purpose — see
 * {@link assertTenantRegistered}.
 */
interface TenantRow {
  id: string;
  status: string;
}

/**
 * Refuse a tenant id that has no `tenants` row, BEFORE anything addresses its
 * object.
 *
 * This is the guard the slice exists for. `idFromName` is a pure function, so a
 * typo, a probe or a long-deleted tenant id all name a perfectly valid object,
 * and the object is CREATED by the first write to it. A namespace cannot be
 * enumerated in production, so a junk object is unfindable and bills for its
 * storage indefinitely. Under the old D1 topology the same mistake did not
 * materialize storage until an explicit provisioning call.
 *
 * The read is against the CONTROL database's typed `tenants` table rather than
 * the `tenant-accounts` document collection, because `tenants` is what the data
 * plane itself gates on (`LIFECYCLE_TENANT_SQL` in `apps/gateway/src/adapters.ts`
 * and the plan join in `apps/gateway/src/assets/entitlements.ts`). A tenant that
 * this table does not know is a tenant the gateway will refuse anyway; giving it
 * storage first would only mean paying for the storage of a tenant that can
 * never use it.
 *
 * A SUSPENDED tenant is admitted, and that is deliberate. Suspension is
 * reversible and its data must survive it — refusing to provision a suspended
 * tenant would mean a tenant suspended between its creation and its first
 * provisioning attempt could never be resumed, which turns a billing control
 * into data loss. `disabled` is admitted for the same reason. Admission is a
 * question about EXISTENCE; whether a request may be served is the lifecycle
 * gate's question and it is asked per request.
 *
 * ## `deleted` is NOT admitted, and existence alone could never have caught it
 *
 * There is no `deleteTenantAccount` operation in the contract. The teardown
 * request is `PATCH {"status":"deleted"}`
 * (`apps/control-plane/src/routes/tenant_hierarchy.ts`), the spec declares no
 * `unproject`, and `mergeHandler` runs `runProjection`, which runs `project`
 * and then `provision` unconditionally. So deleting a tenant used to PROVISION
 * it: a tenant that predates this slice (or whose first provisioning failed)
 * had `idFromName(t)` addressed for the first time by the request that deleted
 * it, materialising an object, seeding it, and recording a `ready` roster row —
 * manufacturing exactly the permanently-billable object this function's own
 * header says it exists to prevent, for a tenant that will never serve a
 * request again. The header even named "a deleted tenant" as the category, and
 * an EXISTENCE check structurally cannot refuse it, because the typed `tenants`
 * row survives the delete.
 *
 * It is a refusal rather than a silent skip because `provisionTenantStorageFor`
 * swallows it: the delete still succeeds, and the reason is recorded rather than
 * invented. Undeleting is `PATCH {"status":"active"}`, which provisions on its
 * way through — so this costs a deleted tenant nothing it can still use.
 *
 * @throws {@link StorageError} `notFound` when there is no row.
 * @throws {@link StorageError} `conflict` when the row says `deleted`.
 */
export async function assertTenantRegistered(
  controlDb: D1Database,
  tenantId: string,
): Promise<TenantRow> {
  if (tenantId.trim() === "") {
    throw StorageError.runtime(
      [
        "tenant storage provisioning requires a non-empty tenant id.",
        'idFromName("") is a valid Durable Object id, so a blank id here would provision ONE',
        "shared object that every unclassified caller lands in.",
      ].join(" "),
    );
  }
  const row = await controlDb
    .prepare("SELECT id, status FROM tenants WHERE id = ?")
    .bind(tenantId)
    .first<TenantRow>();
  if (row === null) {
    throw StorageError.notFound(
      [
        `tenant ${tenantId} has no row in the control database's tenants table, so its storage`,
        "will not be provisioned. Under the Durable Object topology an object is created by",
        "being addressed, so provisioning an unregistered id would leave an unenumerable,",
        "billable object behind for a tenant that does not exist.",
      ].join(" "),
    );
  }
  if (parseLifecycleStatus(row.status ?? "") === "deleted") {
    throw StorageError.conflict(
      [
        `tenant ${tenantId} is marked deleted, so its storage will not be provisioned. The only`,
        'teardown request the contract has is PATCH {"status":"deleted"}, and the projection that',
        "serves it runs this provisioner on its way through — so without this refusal deleting a",
        "tenant would ADDRESS its object for the first time, materialise it, seed it and record",
        "it ready. Undeleting (status: active) provisions it then, when it can be used again.",
      ].join(" "),
    );
  }
  return row;
}

/**
 * Provision (or resume, or re-run) one tenant's storage. Idempotent.
 *
 * Returns the observed state on success. A catalog seed failure records
 * `incomplete` and returns normally because the gateway's current model source
 * is independent of this future per-tenant catalog. Schema, routing, and
 * control-database failures still record `failed` and re-raise, so onboarding
 * cannot report storage as ready when the object itself is unavailable.
 *
 * @throws {@link StorageError} `notFound` for an unregistered tenant (nothing is
 *   written and no object is addressed), or whatever the storage layer raised
 *   for a failure after that point.
 */
export async function provisionTenantStorage(
  router: TenantDatabaseRouter,
  tenantId: string,
  options: TenantProvisioningOptions = {},
): Promise<TenantProvisioningOutcome> {
  const nowUnix = options.nowUnix ?? Math.floor(Date.now() / 1000);
  const controlDb = router.control();
  const registry = new ControlDatabaseTenantRegistry(controlDb);

  // (1) REFUSE FIRST. Nothing below this line may run for an id the control
  // database does not know, and in particular nothing may address the object.
  await assertTenantRegistered(controlDb, tenantId);

  const existing = await registry.get(tenantId);
  const resumed = existing !== undefined && existing.status !== "ready";

  // (2) Record the INTENT before acting on it, so a crash leaves "started" and
  // not silence. The prior row's D1-topology fields are carried across verbatim:
  // this function has no opinion about a `native_binding` tenant's binding name
  // and must not erase one by omission.
  //
  // The BACKEND is stated here rather than left to the registry's
  // `native_binding` default, and that is not cosmetic. Until it was, a new
  // tenant carried no `storageBackend` into this write (`existing` is absent, so
  // the spread contributes nothing), so `pending` — and, more damagingly,
  // `failed`, which is the row that SURVIVES — labelled every Durable Object
  // tenant `native_binding` with a NULL binding. A binding router then read that
  // row as "provisioned but not yet redeployed" and 503'd every control-plane
  // tenant-data route for a tenant that had worked fine when it had no row at
  // all. `router.backend` is knowable without resolving anything, so the label
  // is right from the first write; a router that has no single answer leaves it
  // absent and the roster's prior belief stands.
  const base: TenantDatabaseRegistration = {
    ...(existing ?? { tenantId, schemaVersion: 0 }),
    tenantId,
    ...(router.backend === undefined ? {} : { storageBackend: router.backend }),
    ...(options.locationHint === undefined ? {} : { locationHint: options.locationHint }),
  };
  await registry.upsert({ ...base, status: "pending", lastError: undefined }, nowUnix);

  try {
    // (3) Resolve, then TOUCH. Under `durable_object` `forTenant()` performs no
    // I/O at all — the address is a pure function of the id — so the object is
    // first created by the schema read below, which is also the first thing that
    // proves it migrated itself.
    const handle = await router.forTenant(tenantId);
    const schemaVersion = await observedSchemaVersion(handle.db, tenantId);

    // (4) Seed, at most once ever, gated inside the tenant's own storage. A
    // catalog failure is recoverable and must not turn a tenant creation into a
    // failed document write.
    let catalogStepComplete = false;
    try {
      const seed = await seedTenantModelCatalog(
        handle.db,
        tenantId,
        nowUnix,
        options.catalog ?? DEFAULT_TENANT_MODEL_CATALOG,
      );
      const catalog = await listTenantModelCatalog(handle.db, tenantId);
      if (catalog.length === 0) {
        // The seed helper repairs only the known legacy empty-seed mark. Keep
        // the roster incomplete if a tenant-owned catalog is still empty after
        // a rerun; reseeding would resurrect models the tenant deleted.
        throw StorageError.runtime(
          [
            `tenant ${tenantId} catalog seeding completed without any rows; retry provisioning`,
          ].join(" "),
        );
      }
      catalogStepComplete = true;

      // (5) Only now is the tenant healthy.
      const ready: TenantDatabaseRegistration = {
        ...base,
        schemaVersion,
        storageBackend: handle.source,
        status: "ready",
        catalogSeededAtUnix: seed.seededAtUnix,
        lastError: undefined,
      };
      await registry.upsert(ready, nowUnix);

      return {
        tenantId,
        status: "ready",
        storageBackend: handle.source,
        schemaVersion,
        catalogSeeded: seed.seeded,
        catalogEntries: catalog.length,
        resumed,
      };
    } catch (error) {
      if (catalogStepComplete) throw error;
      const message = error instanceof Error ? error.message : String(error);
      const incompleteBase: TenantDatabaseRegistration = { ...base };
      incompleteBase.catalogSeededAtUnix = undefined;
      await registry.upsert(
        {
          ...incompleteBase,
          schemaVersion,
          storageBackend: handle.source,
          status: "incomplete",
          lastError: message,
        },
        nowUnix,
      );
      return {
        tenantId,
        status: "incomplete",
        storageBackend: handle.source,
        schemaVersion,
        catalogSeeded: false,
        catalogEntries: 0,
        resumed,
      };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // Structural failures are recorded, then re-raised. Catalog failures are
    // handled by the nested block above because they do not make storage
    // unreachable.
    await registry.upsert({ ...base, status: "failed", lastError: message }, nowUnix).catch(() => {
      // The control database is the thing that just failed, plausibly. There
      // is nowhere else to put this, and masking the ORIGINAL refusal with a
      // bookkeeping error would hide the cause behind its symptom.
    });
    throw error;
  }
}

/**
 * The version the tenant's own ledger reports.
 *
 * Read through the routed handle rather than through a backend-specific RPC, so
 * the same query answers for a `durable_object` tenant and a `native_binding`
 * one. The two report DIFFERENT numbers for the same schema and that is not a
 * bug in either: inside an object this ledger is authoritative (there is no
 * `wrangler` and no `d1_migrations` table, so `TenantDataObject` writes a row per
 * file), while in D1 it is vestigial — only `0001_init_tenant` ever inserts, and
 * `wrangler d1 migrations apply` does the real bookkeeping elsewhere. So a D1
 * tenant legitimately reports `1`. The column records what was OBSERVED, and
 * nothing reads it back to decide what to apply.
 *
 * A missing table, or version `0`, is a refusal rather than a default: it means
 * the object never migrated, and a tenant whose schema is absent must not be
 * recorded as provisioned.
 */
async function observedSchemaVersion(db: D1Database, tenantId: string): Promise<number> {
  const row = await db
    .prepare("SELECT MAX(version) AS version FROM storage_schema_migrations")
    .first<{ version: number | null }>();
  const version = row?.version ?? 0;
  if (version <= 0) {
    throw StorageError.runtime(
      [
        `tenant ${tenantId} storage reports schema version 0: its storage_schema_migrations`,
        "ledger is empty, so the tenant schema was never applied. Refusing to record this",
        "tenant as provisioned against a database with no tables.",
      ].join(" "),
    );
  }
  return version;
}

/** A tenant's storage health, as {@link describeTenantStorage} reports it. */
export interface TenantStorageReport {
  readonly tenantId: string;
  /** Absent when there is no roster row at all — the tenant was never provisioned. */
  readonly registration?: TenantDatabaseRegistration;
  /** `true` only when the roster says `ready` AND the catalog is actually non-empty. */
  readonly healthy: boolean;
  /** Every reason `healthy` is `false`, in the order they were checked. */
  readonly problems: readonly string[];
  /** Rows in the tenant's catalog, or `undefined` if the storage could not be read. */
  readonly catalogEntries?: number;
}

/**
 * Report one tenant's storage health WITHOUT changing anything.
 *
 * Deliberately separate from {@link provisionTenantStorage}: a diagnostic that
 * repairs what it finds cannot be used to answer "how many tenants are broken",
 * because asking the question fixes the answer.
 *
 * It reads the roster row AND the tenant's own catalog, and treats a
 * disagreement between them as unhealthy. A roster row saying `ready` over an
 * empty catalog is the exact state this slice exists to make impossible, so the
 * check is worth its round trip: the roster is a projection and a projection can
 * be stale, restored, or rebuilt (this slice's own control migration rebuilds
 * the table it lives in).
 *
 * It does NOT address the object for a tenant with no roster row — the same
 * junk-object rule {@link assertTenantRegistered} enforces, applied to the
 * read path, where it is even easier to violate by accident.
 */
export async function describeTenantStorage(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<TenantStorageReport> {
  const registry = new ControlDatabaseTenantRegistry(router.control());
  const registration = await registry.get(tenantId);
  const problems: string[] = [];
  if (registration === undefined) {
    return {
      tenantId,
      healthy: false,
      problems: [
        `tenant ${tenantId} has no tenant_databases row: its storage was never provisioned, and its object is deliberately NOT addressed here to avoid creating one`,
      ],
    };
  }
  if (registration.status !== "ready") {
    problems.push(
      `provisioning_status is ${registration.status ?? "unset"}${
        registration.lastError === undefined ? "" : `: ${registration.lastError}`
      }`,
    );
  }

  let catalogEntries: number | undefined;
  try {
    const handle = await router.forTenant(tenantId);
    catalogEntries = (await listTenantModelCatalog(handle.db, tenantId)).length;
    if (catalogEntries === 0) {
      problems.push(
        "the model catalog is EMPTY: the seed step either never ran or ran against a mark " +
          "that suppressed it, so per-tenant model visibility and pricing have no rows. " +
          "Inference falls back to GATEWAY_MODELS / GATEWAY_PROVIDERS until this catalog " +
          "is populated",
      );
    }
  } catch (error) {
    problems.push(
      `the tenant's storage could not be read: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  return {
    tenantId,
    registration,
    healthy: problems.length === 0,
    problems,
    ...(catalogEntries === undefined ? {} : { catalogEntries }),
  };
}

/**
 * DEPROVISIONING IS A DATA-RETENTION DECISION, AND THIS IS THE DECISION.
 *
 * **Deleting a tenant RETAINS its object. Nothing here calls `deleteAll()`.**
 *
 * The three options and why this one:
 *
 *  * `ctx.storage.deleteAll()` on delete — irreversible, immediate, and taken by
 *    whatever code path happened to handle the DELETE. A mis-scoped admin call,
 *    a replayed request or a `PATCH {"status":"deleted"}` would destroy a
 *    tenant's ledger, wallet settlements and audit rows with no undo and no
 *    30-day PITR window left to restore from (PITR is per object, and an object
 *    whose storage was deleted still exists but has nothing to restore FROM
 *    unless someone thought to take a bookmark first). Deletion also races the
 *    money paths: a settlement in flight would land in an object that is being
 *    emptied.
 *  * A tombstone that refuses reads — plausible, and it is a THIRD source of
 *    truth about whether a tenant exists, next to `tenants.status` and the
 *    lifecycle gate. The gate already refuses a deleted tenancy's traffic
 *    (`apps/control-plane/src/store/lifecycle.ts` walks tenant → project →
 *    workspace on every admission), so a tombstone inside the object would only
 *    duplicate a refusal that already happens strictly earlier.
 *  * **Retain, and remove the ROSTER row.** What this function does. The
 *    tenant's data stays exactly where it was, the lifecycle gate stops its
 *    traffic, and the object drops out of `provisionedTenants()` so no fleet
 *    view fans out into it.
 *
 * The honest cost, stated rather than discovered later: a retained object keeps
 * billing for its storage ($0.20/GB-month past the free tier) and is no longer
 * enumerable through the roster, so a fleet of deleted tenants becomes an
 * invisible, growing bill. That is a real gap and it is why this function
 * RETURNS the object's address in its receipt rather than dropping it: the
 * erasure job that eventually runs — bounded by whatever retention window the
 * operator's policy states, which this repo does not yet encode — needs a list of
 * what to erase, and after the roster row is gone that list has to have been
 * captured HERE. Wire the receipt into an audit event or a retention queue
 * before deleting tenants at volume.
 *
 * Deliberately NOT decided here: the retention WINDOW. It is a legal and
 * contractual question (GDPR erasure requests, SOC 2 retention commitments and
 * an operator's own contracts all bear on it), it differs per deployment, and
 * guessing a number would give the guess the authority of an implementation.
 */
export interface TenantDeprovisioningReceipt {
  readonly tenantId: string;
  /** `false` when there was no roster row to remove — already retired, or never provisioned. */
  readonly rosterRowRemoved: boolean;
  /** The registration as it stood, so the retained data can still be located. */
  readonly retained?: TenantDatabaseRegistration;
  /** Always `true`. Stated as data so a caller cannot assume otherwise. */
  readonly tenantDataRetained: true;
}

/** Retire a tenant from the roster, RETAINING its data. See {@link TenantDeprovisioningReceipt}. */
export async function retireTenantStorage(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<TenantDeprovisioningReceipt> {
  const registry = new ControlDatabaseTenantRegistry(router.control());
  const retained = await registry.get(tenantId);
  const rosterRowRemoved = await registry.remove(tenantId);
  return {
    tenantId,
    rosterRowRemoved,
    ...(retained === undefined ? {} : { retained }),
    tenantDataRetained: true,
  };
}
