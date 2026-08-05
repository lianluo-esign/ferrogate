/**
 * `TenantDatabaseRouter` — the tenantId → D1 handle seam (JOB 3).
 *
 * ## The constraint this module exists to answer
 *
 * The user directive is **one D1 database per tenant** plus one account-global
 * **CONTROL** database. Cloudflare resolves bindings at **DEPLOY** time: a
 * `[[d1_databases]]` entry in `wrangler.toml` becomes a property on `env`, and
 * there is **no runtime API to open D1 database `<uuid>`**. `env.DB` is handed
 * to the isolate already connected; you cannot ask the runtime for a different
 * one. That is the whole difficulty — and it is exactly why the Rust tree
 * needed a `d1-proxy` Worker (`workers/d1-proxy`, issue #450): the D1 **REST**
 * query API *can* address a database by uuid at runtime, but it **cannot run an
 * atomic `batch()`** — the multi-statement primitive every money-path guard in
 * this package is built on. (It CAN return `RETURNING` rows; this header used to
 * claim otherwise. See the `rest` entry of {@link D1_BINDING_STRATEGIES} for why
 * that correction matters and which direction the old claim failed in.)
 *
 * ## The resolution, and why it is not a workaround
 *
 * Bindings are *declared* at deploy time but **selected at runtime by name**:
 * `env` is an ordinary object, so `env[bindingName]` is a runtime lookup over a
 * deploy-time-declared set. So the router does not need a "bind by uuid" API —
 * it needs a **registry** mapping tenantId → binding name, which is the
 * control-database `tenant_databases` table
 * (`sql/d1-ts/control/0001_init_control.sql`).
 *
 * That gives a **native** `D1Database` per tenant, with real `batch()` and real
 * `RETURNING`, and the whole `d1-proxy` HTTP hop disappears. The price is
 * explicit and is stated in `packages/storage/README.md`: **onboarding a tenant
 * requires a deploy** (a new `[[d1_databases]]` stanza), and a Worker has a
 * finite binding budget. See {@link D1_BINDING_STRATEGIES} for the three
 * strategies, what each costs, and which one a given tenant count wants.
 *
 * ## Fail-closed is the invariant
 *
 * Every unresolvable tenant is an **error**, never a fallback. A router that
 * quietly returned the control database (or any other tenant's database) on a
 * miss would write one tenant's money into another tenant's ledger — the exact
 * cross-tenant isolation property the DB-per-tenant topology exists to
 * guarantee. There is deliberately **no** "default database" parameter in this
 * module.
 */
import { StorageError } from "./errors.js";
import type { TenantDataStatement } from "./tenant-data-object.js";

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/**
 * How a handle was obtained. Load-bearing, not diagnostic: the money paths
 * assert on {@link TenantDatabaseHandle.supportsAtomicBatch}, which is a
 * function of this.
 */
export type TenantDatabaseSource =
  /** A real `[[d1_databases]]` binding on `env`. Full `batch()` + `RETURNING`. */
  | "native_binding"
  /** A `[[services]]` binding to a proxy Worker that holds the native binding. */
  | "proxy_service"
  /**
   * The D1 HTTP query API addressed by uuid. No atomic multi-statement batch —
   * single-statement guarded writes and their `RETURNING` rows DO work, which is
   * exactly the half {@link NonAtomicD1RestTenantDatabaseRouter} serves.
   */
  | "rest"
  /**
   * A SQLite-backed Durable Object, one per tenant, addressed
   * `env.TENANT_DATA.idFromName(tenantId)` — `./tenant-do.ts` (#823).
   *
   * The only source that is BOTH deploy-free and money-safe, which is why it
   * exists: the object is created by being addressed, so onboarding a tenant is
   * not a `wrangler deploy`, and `ctx.storage.transactionSync()` is a real
   * SQLite transaction, so `batch()` is one commit and `RETURNING` rows come
   * back. `supportsAtomicBatch` is therefore `true` and the 13
   * {@link requireAtomicBatch} money paths RUN over it rather than refusing.
   */
  | "durable_object"
  /**
   * One shared database standing in for every tenant. DEVELOPMENT AND
   * SINGLE-TENANT DEPLOYMENTS ONLY — it provides no physical isolation.
   */
  | "shared_development";

/** A resolved, ready-to-query per-tenant database. */
export interface TenantDatabaseHandle {
  readonly tenantId: string;
  /** The live D1 handle. Native bindings expose the full `D1Database` surface. */
  readonly db: D1Database;
  readonly source: TenantDatabaseSource;
  /**
   * Whether `db.batch([...])` is a single transaction AND `RETURNING` rows come
   * back. **Every algorithm in `src/d1/` requires `true`** and refuses to run
   * otherwise — see {@link requireAtomicBatch}. This is the honest expression
   * of the REST limitation: a REST-backed handle can serve reads, and must
   * never serve a wallet reserve.
   */
  readonly supportsAtomicBatch: boolean;
  /** `tenant_databases.database_uuid`; the identity the D1 REST/admin API uses. */
  readonly databaseUuid?: string;
  /** `tenant_databases.schema_version`; which tenant migration the DB is at. */
  readonly schemaVersion?: number;
}

/**
 * The port. `packages/*` and `apps/*` depend on THIS, never on a concrete
 * implementation, so a deployment can swap binding-based routing for a proxy
 * Worker without touching a single algorithm.
 */
export interface TenantDatabaseRouter {
  /**
   * Which topology this router serves, knowable WITHOUT resolving a tenant.
   *
   * ## Why a router has to be able to say this before it routes
   *
   * `provisionTenantStorage` writes a `pending` roster row BEFORE it touches
   * anything, so a crashed provisioner leaves "started, never finished" instead
   * of silence. That row has to state a `storage_backend`, and until this
   * property existed there was nothing to state it from: the backend was only
   * learned at step (5), from the resolved handle's `source`. So every `pending`
   * row — and every `failed` row, which is the one that SURVIVES — was written
   * with the registry's `native_binding` default, mislabelling every Durable
   * Object tenant whose provisioning had not finished.
   *
   * It is a property rather than a method because it is a constant per router
   * instance, and it is OPTIONAL because a router that dispatches per tenant
   * (or refuses everything) genuinely does not have one answer. An absent value
   * means "do not overwrite whatever the roster already believes"; it never
   * means `native_binding`.
   */
  readonly backend?: TenantDatabaseSource;
  /** The account-global CONTROL database. Always a native binding. */
  control(): D1Database;
  /** Resolve one tenant's database, or throw. NEVER falls back. */
  forTenant(tenantId: string): Promise<TenantDatabaseHandle>;
  /**
   * Optional operator-only batch used for authority projections such as tenant
   * RBAC bindings. Durable Object routers forward this to the private RPC;
   * native/shared routers implement the same capability only at this trusted
   * composition-root boundary. REST routers do not expose it, so callers must
   * fail closed instead of routing a privileged write through a normal tenant
   * SQL handle.
   */
  privilegedBatch?(
    tenantId: string,
    statements: readonly TenantDataStatement[],
  ): Promise<void>;
  /** Arm the earliest schedule deadline in a tenant Durable Object. */
  setScheduleAlarm?(tenantId: string, scheduledAtUnix: number): Promise<void>;
  /** Clear a tenant Durable Object's schedule alarm when no schedule remains. */
  clearScheduleAlarm?(tenantId: string): Promise<void>;
  /** Recompute and arm the single alarm from current tenant-local schedule rows. */
  rearmScheduleAlarm?(tenantId: string): Promise<void>;
  /**
   * Every provisioned tenant id, ascending.
   *
   * Needed because several Rust trait signatures carry ONLY an entity id and no
   * tenant (`settle_wallet_reservation(reservation_id)`,
   * `release_wallet_reservation(reservation_id)`), so locating the owning
   * database is an id-only **fan-out**. That fan-out is O(tenants) round trips
   * and belongs on admin paths only — never on the inference hot path. The hot
   * path resolves its tenant from the credential first (control
   * `api_key_directory`) and then makes exactly one routed call.
   */
  provisionedTenants(): Promise<readonly string[]>;
}

/**
 * Assert a handle can run the atomic primitives, or refuse.
 *
 * Called at the top of every guarded write in `src/d1/`. A REST-backed handle
 * reaching a no-oversell reserve would silently degrade the guard to
 * read-then-write with a race window between them, i.e. it would **oversell**.
 * Failing closed here is the only correct behavior.
 */
export function requireAtomicBatch(
  handle: TenantDatabaseHandle,
  operation: string,
): TenantDatabaseHandle {
  if (!handle.supportsAtomicBatch) {
    throw StorageError.runtime(
      [
        `${operation} requires atomic batch()+RETURNING, which the`,
        `"${handle.source}" database handle for tenant ${handle.tenantId} does not`,
        "provide; refusing to run the guard non-atomically",
      ].join(" "),
    );
  }
  return handle;
}

// ---------------------------------------------------------------------------
// The control-database registry
// ---------------------------------------------------------------------------

/**
 * How far a tenant's storage got through onboarding (#820).
 *
 * The states exist because recording the row and provisioning the storage span
 * the control database and the tenant's own object, and those two CANNOT be one
 * transaction. A crash between them is therefore not an edge case, it is a
 * matter of time — so the only question is whether the resulting state is
 * distinguishable from a healthy one. These make it so.
 *
 * `pending` is written BEFORE anything is touched, so the failure mode of a
 * crashed provisioner is a row that says "started, never finished" rather than
 * no row at all. Under `durable_object` that ordering matters more than it did
 * under D1: the object materialises by being addressed, so by the time a
 * provisioner has touched one there is already storage to account for.
 */
export type TenantProvisioningStatus =
  /** Recorded, not yet confirmed. The resumable state. */
  | "pending"
  /** Every provisioning step confirmed: schema applied, catalog seeded. */
  | "ready"
  /** The tenant storage is usable, but catalog seeding needs a retry. */
  | "incomplete"
  /** A step refused. `lastError` says which; re-running resumes from there. */
  | "failed";

/** Independent data migration state for issue #824. */
export type TenantMigrationState = "shared" | "copying" | "verifying" | "cut" | "done";

/** States that must continue resolving to the legacy shared tenant database. */
export const PRE_CUTOVER_TENANT_MIGRATION_STATES: readonly TenantMigrationState[] = [
  "shared",
  "copying",
  "verifying",
];

/**
 * One `tenant_databases` row — the tenant's PROVISIONING STATE, since #820.
 *
 * It used to be a routing table, and under `native_binding` it still is: the
 * binding router reads `bindingName` on the request path, and `undefined` there
 * means "provisioned but not yet redeployed", which it treats as unresolvable
 * rather than as "use the control database". Under `durable_object` the address
 * is `idFromName(tenantId)` and nothing in this row participates in resolution;
 * what it carries instead is the roster (a DO namespace cannot be enumerated in
 * production) and the answer to "did onboarding finish".
 *
 * The three D1-topology fields are optional because a `durable_object` tenant
 * has none of them: no database uuid, no database name, no binding. See
 * `sql/d1-ts/control/0012_tenant_storage_provisioning.sql` for why the columns
 * are kept rather than dropped, and which slice gets to drop each one.
 */
export interface TenantDatabaseRegistration {
  tenantId: string;
  /** D1 topology only. Absent for a `durable_object` tenant. */
  databaseUuid?: string;
  /** D1 topology only. Absent for a `durable_object` tenant. */
  databaseName?: string;
  /** D1 topology only. Absent for a `durable_object` tenant, and for one whose stanza is undeployed. */
  bindingName?: string;
  /**
   * The tenant schema version. Under D1 it is what an operator's
   * `wrangler d1 migrations apply` reached; under `durable_object` it is the
   * version the OBJECT last reported out of its own `storage_schema_migrations`
   * ledger — an observation, never an instruction. The object migrates itself
   * on every cold start and consults nothing here to decide what to apply.
   */
  schemaVersion: number;
  /**
   * Which topology this tenant's data physically lives in. Absent means the row
   * predates #820, and every writer that predates #820 is a binding-topology
   * one — which is why the column's SQL default is `native_binding` and not the
   * newer value.
   */
  storageBackend?: TenantDatabaseSource;
  /** Absent for a row written before #820; such a row is not yet classifiable. */
  status?: TenantProvisioningStatus;
  /** When the model catalog was seeded. Absent = never. */
  catalogSeededAtUnix?: number;
  /** The refusal that stopped the last provisioning attempt, verbatim. */
  lastError?: string;
  /**
   * The `locationHint` the object was FIRST addressed with. A Durable Object is
   * homed near its first `get()` and cannot be moved, so the choice is permanent
   * and recorded rather than inferred.
   */
  locationHint?: string;
  /** The independent #824 data migration state. */
  migrationState?: TenantMigrationState;
  migrationEpoch?: number;
  migrationFrozenAtUnix?: number;
  migrationCutoverAtUnix?: number;
  migrationRetentionUntilUnix?: number;
  migrationLastError?: string;
  migrationReceiptJson?: string;
  migrationProgressJson?: string;
}

/**
 * The `control_plane_resources` kind/id under which the Rust backend persisted
 * the same mapping as a JSON document.
 *
 * These are `D1_TENANT_DATABASE_REGISTRY_KIND` / `_ID` from
 * `crates/ferrogate-storage/src/control_plane_store_d1/mod.rs` VERBATIM. They
 * are the primary key of a row in a real, already-deployed control database, so
 * inventing a different pair here would silently make
 * {@link migrateTenantDatabaseRegistryDocument} find nothing and report an
 * empty, successful migration.
 */
export const TENANT_DATABASE_REGISTRY_KIND = "d1_tenant_database";
export const TENANT_DATABASE_REGISTRY_ID = "registry";

/**
 * The Rust-era registry document (`D1TenantDatabaseRegistry`), as persisted.
 *
 * `tenantDatabases` is `tenant_id -> D1 database uuid`. There is NO binding
 * name and NO database name in it: the Rust backend reached D1 over the HTTP
 * API by uuid, so neither existed. That absence is the whole shape of the
 * migration — see {@link migrateTenantDatabaseRegistryDocument}.
 */
export interface TenantDatabaseRegistryDocument {
  /** The uuid of the database holding tenants + config documents + this doc. */
  controlDatabaseId: string;
  /** `tenant_id -> database_uuid`, deterministic (Rust `BTreeMap`). */
  tenantDatabases: Record<string, string>;
}

/** Wire (serde) form of {@link TenantDatabaseRegistryDocument}: snake_case. */
interface TenantDatabaseRegistryDocumentWire {
  control_database_id?: string;
  tenant_databases?: Record<string, string>;
}

/** Decode the persisted registry document (ports `from_document_json`). */
export function parseTenantDatabaseRegistryDocument(
  documentJson: string,
): TenantDatabaseRegistryDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(documentJson);
  } catch (error) {
    throw StorageError.runtime(
      `tenant database registry document is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw StorageError.runtime("tenant database registry document must be a JSON object");
  }
  const wire = parsed as TenantDatabaseRegistryDocumentWire;
  const map = wire.tenant_databases ?? {};
  if (map === null || typeof map !== "object" || Array.isArray(map)) {
    throw StorageError.runtime(
      "tenant database registry document field tenant_databases must be an object",
    );
  }
  const tenantDatabases: Record<string, string> = {};
  for (const [tenantId, uuid] of Object.entries(map)) {
    if (typeof uuid !== "string" || uuid.trim() === "") {
      throw StorageError.runtime(
        [
          `tenant database registry document maps tenant ${tenantId} to a non-string`,
          "or empty database uuid",
        ].join(" "),
      );
    }
    tenantDatabases[tenantId] = uuid;
  }
  // `#[serde(default)]` on both fields: an absent key decodes to the empty value.
  return { controlDatabaseId: wire.control_database_id ?? "", tenantDatabases };
}

/** What {@link migrateTenantDatabaseRegistryDocument} did. */
export interface TenantDatabaseRegistryMigration {
  /** `false` when no Rust-era document exists — nothing to migrate, not an error. */
  documentFound: boolean;
  /** Rows inserted for a tenant that had no `tenant_databases` row. */
  inserted: readonly string[];
  /**
   * Tenants already in the table. Their rows are left ALONE — the table is the
   * newer, richer record (it carries `binding_name`, which the document cannot),
   * so the document must never overwrite it.
   */
  skipped: readonly string[];
  /** `control_database_id` from the document, for the operator to verify. */
  controlDatabaseId: string;
}

/** Options for {@link migrateTenantDatabaseRegistryDocument}. */
export interface TenantDatabaseRegistryMigrationOptions {
  /**
   * The `database_name` to record for a migrated tenant. The document has none
   * (see {@link TenantDatabaseRegistryDocument}), and the column is NOT NULL.
   * Default: `ferrogate-tenant-<tenantId>`.
   */
  databaseName?: (tenantId: string, databaseUuid: string) => string;
  /** `schema_version` for migrated rows. Default `1`. */
  schemaVersion?: number;
}

/**
 * Migrate a Rust-era `control_plane_resources` registry DOCUMENT into the
 * `tenant_databases` TABLE (inventory-data-billing §1.7).
 *
 * ## Why this is a migration and not a read path
 *
 * The document maps `tenant_id -> database_uuid` and nothing else, because the
 * Rust backend addressed D1 over the HTTP API by uuid. This port runs INSIDE a
 * Worker, where a database handle is a deploy-time BINDING NAME
 * (`env[bindingName]`), and a uuid buys you nothing at runtime. So a migrated
 * row necessarily lands with `binding_name = NULL`, and
 * {@link EnvBindingTenantDatabaseRouter} FAILS CLOSED on it until a redeploy
 * adds the `[[d1_databases]]` stanza and
 * {@link ControlDatabaseTenantRegistry.upsert} records the name.
 *
 * That is the correct outcome, not a shortcoming: a migrated tenant is
 * "provisioned but not yet routable", and inventing a plausible binding name
 * here would produce a router that resolves to `undefined` at request time — or,
 * far worse, to some OTHER tenant's binding if the guess collided.
 *
 * ## Idempotent, and never destructive
 *
 * Existing `tenant_databases` rows are left untouched (reported in `skipped`),
 * because the table is strictly richer than the document. Re-running after a
 * redeploy therefore cannot erase the `binding_name` that redeploy assigned.
 *
 * @throws {@link StorageError} `runtime` if the document is malformed, or if
 *   two tenants claim one `database_uuid` (the table's `UNIQUE (database_uuid)`
 *   refuses it — two tenants sharing a database is precisely the cross-tenant
 *   leak the DB-per-tenant topology exists to prevent).
 */
export async function migrateTenantDatabaseRegistryDocument(
  controlDb: D1Database,
  nowUnix: number,
  options: TenantDatabaseRegistryMigrationOptions = {},
): Promise<TenantDatabaseRegistryMigration> {
  const nameFor = options.databaseName ?? ((tenantId: string) => `ferrogate-tenant-${tenantId}`);
  const schemaVersion = options.schemaVersion ?? 1;

  const row = await controlDb
    .prepare(
      "SELECT document_json FROM control_plane_resources " +
        "WHERE resource_kind = ? AND resource_id = ?",
    )
    .bind(TENANT_DATABASE_REGISTRY_KIND, TENANT_DATABASE_REGISTRY_ID)
    .first<{ document_json: string }>();
  if (row === null) {
    return { documentFound: false, inserted: [], skipped: [], controlDatabaseId: "" };
  }

  const document = parseTenantDatabaseRegistryDocument(row.document_json);
  const registry = new ControlDatabaseTenantRegistry(controlDb);
  const existing = new Set((await registry.list()).map((r) => r.tenantId));

  const inserted: string[] = [];
  const skipped: string[] = [];
  // Sorted so the migration is deterministic and its report is stable, matching
  // the Rust `BTreeMap` iteration order.
  for (const tenantId of Object.keys(document.tenantDatabases).sort()) {
    if (existing.has(tenantId)) {
      skipped.push(tenantId);
      continue;
    }
    const databaseUuid = document.tenantDatabases[tenantId] as string;
    try {
      await controlDb
        .prepare(
          // `native_binding` / `pending` are stated rather than defaulted: a
          // migrated row names a real D1 database with no deployed stanza, which
          // is precisely "provisioned but not yet routable" — the state #820
          // spells `pending`. Leaving it to the column default would give the
          // same two values by luck rather than by intent.
          "INSERT INTO tenant_databases " +
            "(tenant_id, database_uuid, database_name, binding_name, schema_version, " +
            " storage_backend, provisioning_status, provisioned_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, NULL, ?, 'native_binding', 'pending', ?, ?)",
        )
        .bind(
          tenantId,
          databaseUuid,
          nameFor(tenantId, databaseUuid),
          schemaVersion,
          nowUnix,
          nowUnix,
        )
        .run();
    } catch (error) {
      throw StorageError.runtime(
        `migrating tenant ${tenantId} (database ${databaseUuid}) into tenant_databases ` +
          `failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    inserted.push(tenantId);
  }

  return {
    documentFound: true,
    inserted,
    skipped,
    controlDatabaseId: document.controlDatabaseId,
  };
}

/** Every column {@link registrationFromRow} decodes. One list, so the reads cannot drift. */
const TENANT_DATABASE_COLUMNS =
  "tenant_id, database_uuid, database_name, binding_name, schema_version, " +
  "storage_backend, provisioning_status, catalog_seeded_at_unix, last_error, location_hint, " +
  "migration_state, migration_epoch, migration_frozen_at_unix, migration_cutover_at_unix, " +
  "migration_retention_until_unix, migration_last_error, migration_receipt_json, " +
  "migration_progress_json";

/** Reads and writes the tenant provisioning registry in the CONTROL database. */
export class ControlDatabaseTenantRegistry {
  constructor(private readonly controlDb: D1Database) {}

  async get(tenantId: string): Promise<TenantDatabaseRegistration | undefined> {
    const row = await this.controlDb
      .prepare(`SELECT ${TENANT_DATABASE_COLUMNS} FROM tenant_databases WHERE tenant_id = ?`)
      .bind(tenantId)
      .first<TenantDatabaseRow>();
    return row ? registrationFromRow(row) : undefined;
  }

  async list(): Promise<TenantDatabaseRegistration[]> {
    const result = await this.controlDb
      .prepare(`SELECT ${TENANT_DATABASE_COLUMNS} FROM tenant_databases ORDER BY tenant_id`)
      .all<TenantDatabaseRow>();
    return result.results.map(registrationFromRow);
  }

  /**
   * Every tenant NOT in `ready`, ascending — the resume worklist (#820).
   *
   * This is the query the whole `provisioning_status` column exists to make
   * answerable. Without it, "some tenants mysteriously have no models" is
   * diagnosed one tenant at a time, by someone who already suspects it.
   */
  async listUnfinished(): Promise<TenantDatabaseRegistration[]> {
    const result = await this.controlDb
      .prepare(
        `SELECT ${TENANT_DATABASE_COLUMNS} FROM tenant_databases WHERE provisioning_status <> 'ready' ORDER BY tenant_id`,
      )
      .all<TenantDatabaseRow>();
    return result.results.map(registrationFromRow);
  }

  /**
   * Delete a tenant's registration row.
   *
   * Deliberately narrow: this removes the tenant from the ROSTER and touches no
   * tenant data whatsoever. Under `durable_object` the object survives, holding
   * every row the tenant ever wrote — documented behaviour rather than an
   * omission, see the deprovisioning section of
   * `docs/design/per-tenant-durable-object-storage-2026-08.md`. Erasing tenant
   * data is a data-retention decision with legal weight, and a registry method
   * is the wrong place to take it silently.
   */
  async remove(tenantId: string): Promise<boolean> {
    const result = await this.controlDb
      .prepare("DELETE FROM tenant_databases WHERE tenant_id = ? RETURNING tenant_id")
      .bind(tenantId)
      .all<{ tenant_id: string }>();
    return result.results.length > 0;
  }

  /**
   * Register (or re-register) a tenant. Idempotent by `tenant_id`; a redeploy
   * that assigns a binding name, and a provisioner advancing a tenant from
   * `pending` to `ready`, are both the common second call.
   *
   * Every field is written from `excluded`, including the nullable ones, so this
   * REPLACES the row's meaning rather than merging into it: a caller that omits
   * a field is stating the field is absent, not declining to comment. The one
   * exception is `provisioned_at_unix` — a tenant's first provisioning time is
   * not re-stamped by a later resume, the same rule `projectPlan` follows for
   * `created_at_unix`.
   */
  async upsert(registration: TenantDatabaseRegistration, nowUnix: number): Promise<void> {
    await this.controlDb
      .prepare(
          "INSERT INTO tenant_databases " +
          "(tenant_id, database_uuid, database_name, binding_name, schema_version, " +
          " storage_backend, provisioning_status, catalog_seeded_at_unix, last_error, " +
          " location_hint, migration_state, provisioned_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT (tenant_id) DO UPDATE SET " +
          "database_uuid = excluded.database_uuid, " +
          "database_name = excluded.database_name, " +
          "binding_name = excluded.binding_name, " +
          "schema_version = excluded.schema_version, " +
          "storage_backend = excluded.storage_backend, " +
          "provisioning_status = excluded.provisioning_status, " +
          "catalog_seeded_at_unix = excluded.catalog_seeded_at_unix, " +
          "last_error = excluded.last_error, " +
          "location_hint = excluded.location_hint, " +
          "updated_at_unix = excluded.updated_at_unix",
      )
      .bind(
        registration.tenantId,
        registration.databaseUuid ?? null,
        registration.databaseName ?? null,
        registration.bindingName ?? null,
        registration.schemaVersion,
        // The column's own DEFAULT is `native_binding`, for rows written by SQL
        // that predates #820. A caller reaching THIS method through the typed
        // API has no such excuse, so the same value is stated here where a
        // reader of the code sees it rather than left to the DDL.
        registration.storageBackend ?? "native_binding",
        registration.status ?? "pending",
        registration.catalogSeededAtUnix ?? null,
        registration.lastError ?? null,
        registration.locationHint ?? null,
        registration.migrationState ??
          (registration.storageBackend === "durable_object" ? "done" : "shared"),
        nowUnix,
        nowUnix,
      )
      .run();
  }
}

interface TenantDatabaseRow {
  tenant_id: string;
  database_uuid: string | null;
  database_name: string | null;
  binding_name: string | null;
  schema_version: number;
  storage_backend: string | null;
  provisioning_status: string | null;
  catalog_seeded_at_unix: number | null;
  last_error: string | null;
  location_hint: string | null;
  migration_state: string | null;
  migration_epoch: number | null;
  migration_frozen_at_unix: number | null;
  migration_cutover_at_unix: number | null;
  migration_retention_until_unix: number | null;
  migration_last_error: string | null;
  migration_receipt_json: string | null;
  migration_progress_json: string | null;
}

/** The legal `provisioning_status` spellings. Anything else decodes to ABSENT. */
const PROVISIONING_STATUSES: readonly TenantProvisioningStatus[] = [
  "pending",
  "ready",
  "incomplete",
  "failed",
];

const MIGRATION_STATES: readonly TenantMigrationState[] = [
  "shared",
  "copying",
  "verifying",
  "cut",
  "done",
];

/**
 * Row → registration.
 *
 * Absent optional fields are OMITTED rather than set to `undefined`, because
 * `exactOptionalPropertyTypes` is on for this package. An unrecognised
 * `provisioning_status` decodes to absent rather than to `failed`: inventing a
 * failure for a value we merely do not recognise would make a schema drift look
 * like a broken tenant, and the two get opposite fixes.
 */
function registrationFromRow(row: TenantDatabaseRow): TenantDatabaseRegistration {
  const status = PROVISIONING_STATUSES.find((candidate) => candidate === row.provisioning_status);
  return {
    tenantId: row.tenant_id,
    ...(row.database_uuid === null ? {} : { databaseUuid: row.database_uuid }),
    ...(row.database_name === null ? {} : { databaseName: row.database_name }),
    ...(row.binding_name === null ? {} : { bindingName: row.binding_name }),
    schemaVersion: row.schema_version,
    ...(row.storage_backend === null
      ? {}
      : { storageBackend: row.storage_backend as TenantDatabaseSource }),
    ...(status === undefined ? {} : { status }),
    ...(row.catalog_seeded_at_unix === null
      ? {}
      : { catalogSeededAtUnix: row.catalog_seeded_at_unix }),
    ...(row.last_error === null ? {} : { lastError: row.last_error }),
    ...(row.location_hint === null ? {} : { locationHint: row.location_hint }),
    ...(MIGRATION_STATES.includes(row.migration_state as TenantMigrationState)
      ? { migrationState: row.migration_state as TenantMigrationState }
      : {}),
    ...(row.migration_epoch === null ? {} : { migrationEpoch: row.migration_epoch }),
    ...(row.migration_frozen_at_unix === null
      ? {}
      : { migrationFrozenAtUnix: row.migration_frozen_at_unix }),
    ...(row.migration_cutover_at_unix === null
      ? {}
      : { migrationCutoverAtUnix: row.migration_cutover_at_unix }),
    ...(row.migration_retention_until_unix === null
      ? {}
      : { migrationRetentionUntilUnix: row.migration_retention_until_unix }),
    ...(row.migration_last_error === null
      ? {}
      : { migrationLastError: row.migration_last_error }),
    ...(row.migration_receipt_json === null
      ? {}
      : { migrationReceiptJson: row.migration_receipt_json }),
    ...(row.migration_progress_json === null
      ? {}
      : { migrationProgressJson: row.migration_progress_json }),
  };
}

// ---------------------------------------------------------------------------
// (a) The native-binding router — the implementation to deploy
// ---------------------------------------------------------------------------

/** The `env` slice the router needs: an arbitrary bag of possible bindings. */
export type BindingEnvironment = Record<string, unknown>;

export interface EnvBindingTenantRouterOptions {
  /**
   * How long a resolved registration is cached in-isolate, in ms. Default
   * 30_000. The cache holds the *registry row*, never a stale binding: bindings
   * cannot change without a deploy (which replaces the isolate), but a
   * registration CAN change under a live isolate, so it must expire.
   * `0` disables caching.
   */
  registrationTtlMs?: number;
}

/**
 * **(a) in JOB 3** — routes to real, deploy-time-declared `[[d1_databases]]`
 * bindings, selected at runtime by the name the control registry records.
 *
 * This is the implementation to deploy. It yields native `D1Database` handles,
 * so `batch()` is one transaction and `RETURNING` works, so every algorithm in
 * `src/d1/` keeps the exact atomicity the Postgres row lock gave.
 *
 * Wiring (the composition root, NOT this package):
 *
 * ```toml
 * # apps/gateway/wrangler.toml  (or apps/control-plane)
 * [[d1_databases]]
 * binding = "CONTROL_DB"
 * database_name = "ferrogate-control"
 * database_id = "<deploy-time>"
 *
 * [[d1_databases]]
 * binding = "TENANT_DB_ACME"      # <- the name stored in tenant_databases.binding_name
 * database_name = "ferrogate-tenant-acme"
 * database_id = "<deploy-time>"
 * ```
 *
 * ```ts
 * import { EnvBindingTenantDatabaseRouter } from "@ferrogate/storage";
 * const router = new EnvBindingTenantDatabaseRouter(env, env.CONTROL_DB);
 * const handle = await router.forTenant(caller.tenantId);
 * ```
 */
export class EnvBindingTenantDatabaseRouter implements TenantDatabaseRouter {
  /** Every tenant this router can serve is a `[[d1_databases]]` stanza. */
  readonly backend = "native_binding" as const;
  private readonly registry: ControlDatabaseTenantRegistry;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, { at: number; value: TenantDatabaseRegistration }>();

  constructor(
    private readonly env: BindingEnvironment,
    private readonly controlDb: D1Database,
    options: EnvBindingTenantRouterOptions = {},
  ) {
    this.registry = new ControlDatabaseTenantRegistry(controlDb);
    this.ttlMs = options.registrationTtlMs ?? 30_000;
  }

  control(): D1Database {
    return this.controlDb;
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    if (tenantId === "") {
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    const registration = await this.registration(tenantId);
    if (!registration) {
      throw StorageError.notFound(
        `tenant ${tenantId} has no provisioned D1 database in the control registry`,
      );
    }
    const bindingName = registration.bindingName;
    if (bindingName === undefined || bindingName === "") {
      // A row that says `durable_object` is not a mis-deployed D1 tenant, and
      // reporting it as one is worse than useless: since #820 the onboarding
      // path writes a roster row the moment a tenant is created, carrying no
      // binding because a Durable Object has none. Read as "provisioned but not
      // yet redeployed" that row turns every such tenant into a hard `runtime`
      // refusal — which is how registering a tenant started answering 503 on a
      // deployment whose control plane still routes its DATA paths through
      // bindings.
      //
      // `not_found` is the honest kind: this router serves D1 bindings, and this
      // tenant has no D1 database registered for it — the same answer it gives
      // for a tenant with no row at all, because from a binding router's point of
      // view those are the same fact. Callers that distinguish the two kinds
      // (`apps/control-plane/src/store/tenancy.ts` maps `not_found` to a
      // document-only outcome and everything else to a 503) then behave exactly
      // as they did before a roster row existed.
      if (registration.storageBackend === "durable_object") {
        throw StorageError.notFound(
          [
            `tenant ${tenantId} is provisioned on the durable_object backend and has no D1`,
            "binding; this router serves [[d1_databases]] bindings only. Route it through",
            "DurableObjectTenantDatabaseRouter instead.",
          ].join(" "),
        );
      }
      const databaseUuid = registration.databaseUuid;
      if (databaseUuid === undefined || databaseUuid === "") {
        // NO binding AND no database uuid: there is nothing to be un-redeployed
        // FROM. The row records that a tenant exists and that its storage is
        // somewhere else (or nowhere yet) — a `pending` row written before
        // provisioning touched anything, a `failed` one left behind when it
        // stopped, or any backend that has no D1 database at all.
        //
        // The old code reported that as `runtime` and printed "database
        // undefined has no binding_name", which is a claim that a database
        // EXISTS. It does not, and the difference is operator-visible: `runtime`
        // becomes a 503 on every control-plane tenant-data route
        // (`apps/control-plane/src/store/tenancy.ts` maps every other kind that
        // way), so the moment onboarding wrote its `pending` row a tenant that
        // had worked started failing. `not_found` is the honest kind and the one
        // callers already handle as "no tenant database, act on the document
        // only" — the same answer this router gives for a tenant with no row.
        throw StorageError.notFound(
          [
            `tenant ${tenantId} has a control-registry row but no D1 database: neither a`,
            "binding_name nor a database_uuid is recorded, so nothing has been provisioned",
            "for it in D1. This router serves [[d1_databases]] bindings only.",
          ].join(" "),
        );
      }
      // Provisioned but not yet bound: the database exists in the account, the
      // Worker has not been redeployed with its binding. Fail closed — falling
      // back to the control database here is precisely how a tenant's ledger
      // ends up in the account-global one.
      throw StorageError.runtime(
        [
          `tenant ${tenantId} database ${databaseUuid} has no binding_name;`,
          "the Worker must be redeployed with its [[d1_databases]] stanza before it can",
          "be routed to",
        ].join(" "),
      );
    }
    const bound = this.env[bindingName];
    if (!isD1Database(bound)) {
      throw StorageError.runtime(
        [
          `tenant ${tenantId} names binding "${bindingName}", which is not a D1 database`,
          "on this Worker's env; the control registry and the deployed wrangler config",
          "disagree",
        ].join(" "),
      );
    }
    return {
      tenantId,
      db: bound,
      source: "native_binding",
      supportsAtomicBatch: true,
      // Spread rather than assigned: since #820 a registration may legitimately
      // carry no uuid (a `durable_object` tenant has none), and under
      // `exactOptionalPropertyTypes` an explicit `undefined` is not the same
      // thing as an absent key.
      ...(registration.databaseUuid === undefined
        ? {}
        : { databaseUuid: registration.databaseUuid }),
      schemaVersion: registration.schemaVersion,
    };
  }

  /** Trusted migration/projection path; ordinary tenant callers only get `db`. */
  async privilegedBatch(
    tenantId: string,
    statements: readonly TenantDataStatement[],
  ): Promise<void> {
    const handle = await this.forTenant(tenantId);
    await handle.db.batch(
      statements.map((statement) => handle.db.prepare(statement.sql).bind(...(statement.params ?? []))),
    );
  }

  async provisionedTenants(): Promise<readonly string[]> {
    const rows = await this.registry.list();
    return rows.map((r) => r.tenantId);
  }

  /** Drop the in-isolate registration cache (call after a provisioning write). */
  invalidate(tenantId?: string): void {
    if (tenantId === undefined) this.cache.clear();
    else this.cache.delete(tenantId);
  }

  private async registration(tenantId: string): Promise<TenantDatabaseRegistration | undefined> {
    if (this.ttlMs > 0) {
      const hit = this.cache.get(tenantId);
      if (hit && Date.now() - hit.at < this.ttlMs) return hit.value;
    }
    const value = await this.registry.get(tenantId);
    if (value && this.ttlMs > 0) this.cache.set(tenantId, { at: Date.now(), value });
    return value;
  }
}

/**
 * Structural D1 check. Deliberately narrow — `prepare`/`batch` are the two
 * methods every algorithm here uses, and a binding that lacks `batch` (a KV
 * namespace, a service binding, a plain var) must not pass.
 */
function isD1Database(value: unknown): value is D1Database {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<D1Database>;
  return typeof candidate.prepare === "function" && typeof candidate.batch === "function";
}

// ---------------------------------------------------------------------------
// An explicit, opt-in single-database router (development / single tenant)
// ---------------------------------------------------------------------------

/**
 * Routes EVERY tenant to ONE database. There is **no physical isolation**: two
 * tenants share a table, and the only thing separating them is the `tenant_id`
 * column — i.e. exactly the Postgres-era posture that this topology replaces.
 *
 * Legitimate uses, and no others:
 *   * `wrangler dev --local` with one seeded tenant;
 *   * a genuinely single-tenant (self-hosted) deployment.
 *
 * It is a separate named class rather than a flag on the real router so that it
 * can never be reached by a config typo, and so a code search for
 * `SharedDatabaseTenantRouter` finds every deployment that accepted the
 * tradeoff. `source` is reported as `"shared_development"` so a handle can be
 * recognized downstream.
 */
export class SharedDatabaseTenantRouter implements TenantDatabaseRouter {
  /** One database standing in for every tenant — no physical isolation. */
  readonly backend = "shared_development" as const;

  constructor(
    private readonly db: D1Database,
    private readonly tenantIds: readonly string[] = [],
  ) {}

  control(): D1Database {
    return this.db;
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    if (tenantId === "") {
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    return {
      tenantId,
      db: this.db,
      // A native binding is still underneath, so the atomic primitives are real
      // even though the isolation is not.
      source: "shared_development",
      supportsAtomicBatch: true,
    };
  }

  /** Trusted migration/projection path; this class is development-only. */
  async privilegedBatch(
    tenantId: string,
    statements: readonly TenantDataStatement[],
  ): Promise<void> {
    const handle = await this.forTenant(tenantId);
    await handle.db.batch(
      statements.map((statement) => handle.db.prepare(statement.sql).bind(...(statement.params ?? []))),
    );
  }

  async provisionedTenants(): Promise<readonly string[]> {
    return [...this.tenantIds].sort();
  }
}

// ---------------------------------------------------------------------------
// (b) The documented strategies for per-tenant databases
// ---------------------------------------------------------------------------

/**
 * The four ways to reach a per-tenant database from a Worker, with the honest
 * cost of each. This constant is documentation that ships with the code (and is
 * asserted by a test, so it cannot silently rot); the same table is in
 * `packages/storage/README.md`.
 *
 * Three of the four reach a per-tenant **D1** database and are constrained by
 * the same fact — bindings resolve at DEPLOY time. The fourth,
 * `durable_object`, is not a D1 strategy at all: it replaces the database with
 * a SQLite-backed Durable Object and is the reason `test/platform-limits.test.ts`
 * no longer asserts that the deploy-free × money-safe cell is empty.
 */
export const D1_BINDING_STRATEGIES = {
  /**
   * One `[[d1_databases]]` stanza per tenant; the registry maps tenantId →
   * binding name; `env[bindingName]` selects it at runtime.
   * Implemented by {@link EnvBindingTenantDatabaseRouter}.
   */
  native_binding: {
    atomicBatch: true,
    returning: true,
    /** Onboarding a tenant requires a `wrangler deploy`. */
    requiresDeployPerTenant: true,
    /** Bindings live in the Worker's config/metadata; the practical ceiling is low hundreds. */
    tenantCeiling: "low hundreds",
    extraNetworkHop: false,
  },
  /**
   * A dedicated proxy Worker holds the per-tenant bindings and exposes
   * `/d1/query` + `/d1/batch` behind a `[[services]]` binding — the shape
   * `workers/d1-proxy` had (issue #450), minus the public HTTP hop, since a
   * service binding is an in-network RPC call.
   *
   * Buys: the tenant fleet's binding churn is confined to ONE Worker, so
   * onboarding redeploys the proxy instead of the gateway. Costs: one extra
   * hop, and `RETURNING` rows must be serialized across it.
   */
  proxy_service: {
    atomicBatch: true,
    returning: true,
    requiresDeployPerTenant: true,
    tenantCeiling: "low hundreds per proxy Worker; shard across proxies beyond that",
    extraNetworkHop: true,
  },
  /**
   * The D1 HTTP query API, addressed by a **runtime** database uuid — the only
   * strategy with no deploy-time coupling at all, and the reason it is
   * tempting.
   *
   * It is **not usable for the money paths**, but the reason is narrower than
   * this entry used to claim, and the correction matters because the two claims
   * lead an engineer to opposite designs.
   *
   * CORRECTED (`returning: false` → `true`). The REST `/query` response is
   * `{ result: [{ results, success, meta }, …] }` — one entry per statement,
   * and `results` is where a `RETURNING` clause's rows land. `RETURNING` is
   * therefore NOT lost over REST; {@link D1RestDatabase} reads exactly that
   * field, and both `packages/storage/test/d1/rest-transport.test.ts` and
   * `apps/gateway/test/tenancy/rest.spec.ts` drive a guarded
   * `UPDATE … RETURNING` through it and get the row back. The old `false` was
   * inherited from the pre-`d1-proxy` Rust marshalling, which lost the rows for
   * its own reasons. Believing it costs money in the dangerous direction: an
   * engineer who thinks a single-statement CAS cannot report whether its guard
   * held will hand-roll a SELECT-then-UPDATE, and THAT is the race.
   *
   * What is genuinely missing is `atomicBatch`, i.e. an envelope that makes the
   * wallet reserve's 3 statements one commit whose guard cannot be raced. One
   * statement is its own implicit transaction in SQLite, so a single guarded
   * `UPDATE … WHERE <cas> RETURNING` is a real CAS over REST; N statements
   * issued as N calls are not, and issuing them that way is an oversell, not a
   * slower reserve. The Rust tree built `d1-proxy` for exactly this reason.
   *
   * OPEN QUESTION, deliberately NOT resolved by assertion: Cloudflare's REST
   * docs say the `sql` field "supports multiple statements, joined by
   * semicolons, which will be executed as a batch", and the request body also
   * accepts a `{ batch: [{ sql, params }] }` form. If that envelope carries the
   * SAME all-or-nothing semantics as the binding's `batch()`, then
   * {@link NonAtomicD1RestTenantDatabaseRouter} could serve the money paths and
   * the deploy-per-tenant ceiling would stop being an architectural constraint.
   * It is left `false` because that is unverifiable here — the local
   * miniflare/workerd D1 does not implement the HTTP API at all, and this
   * project is LOCAL-FIRST — and because the failure mode of guessing wrong is
   * an oversell. Verify against a real account before flipping it, and prove it
   * with a rolled-back mid-batch failure, not with a doc quote.
   */
  rest: {
    atomicBatch: false,
    returning: true,
    requiresDeployPerTenant: false,
    tenantCeiling: "unbounded",
    extraNetworkHop: true,
  },
  /**
   * One SQLite-backed **Durable Object** per tenant, addressed
   * `env.TENANT_DATA.idFromName(tenantId)` — `./tenant-do.ts` (#823),
   * `docs/design/per-tenant-durable-object-storage-2026-08.md`.
   *
   * This is the row the other three exist to be compared against, because it is
   * the one that answers the OPEN QUESTION in the `rest` entry from a different
   * direction: it gives runtime addressing AND a multi-statement transaction.
   * Not by finding a transaction envelope in the D1 HTTP API — that question is
   * still open and still unverified — but by not using D1 for the tenant plane
   * at all.
   *
   * `atomicBatch: true` is the load-bearing claim and it is not a doc-derived
   * one: `TenantDataObject.batch()` runs the whole statement array inside ONE
   * `ctx.storage.transactionSync()`, which is a real SQLite transaction that
   * rolls back on throw. `packages/storage/test/do/tenant-do-facade.test.ts`
   * proves it the way the `rest` entry says such a claim must be proved — with
   * a rolled-back mid-batch failure, not with a doc quote.
   *
   * `requiresDeployPerTenant: false` because a Durable Object is created by
   * being addressed. There is no stanza, no `wrangler deploy`, and no binding
   * budget: ONE `[[durable_objects.bindings]]` entry serves every tenant that
   * will ever exist. That is what makes `tenantCeiling` unbounded in a way the
   * `native_binding` row can never be.
   *
   * `extraNetworkHop: true` and it must stay honest. A stub call is an RPC to
   * wherever the object lives, which may be another colo; it is cheaper than
   * the `rest` row's public HTTP round trip and it is not free. The facade's
   * `batch()` makes the WHOLE statement array cross in ONE hop for exactly this
   * reason — N sequential stub calls would be the `rest` strategy with extra
   * steps, and would lose the transaction too.
   *
   * The costs this row does NOT hide: 10 GB per object (vs D1's 10 GB per
   * database — the same number, but now a hard per-tenant wall with no shard),
   * ~1,000 req/s per object single-threaded, and no way to ENUMERATE a
   * namespace in production, which is why a `durable_object` router still reads
   * `tenant_databases` to answer `provisionedTenants()`.
   */
  durable_object: {
    atomicBatch: true,
    returning: true,
    requiresDeployPerTenant: false,
    tenantCeiling: "unbounded; one binding serves every tenant, 10 GB per object",
    extraNetworkHop: true,
  },
} as const;

/**
 * The D1 REST strategy in its **strictest posture**: the seam exists, and
 * `forTenant` refuses outright so REST cannot be reached by accident.
 *
 * PORT-TODO(L: inventory-data-billing §1.7 "per-tenant D1 binding at runtime") —
 * PLATFORM LIMIT, KEPT AND SHARPENED.
 *
 * THE LIMIT (unchanged, and not closable): **Cloudflare bindings resolve at
 * DEPLOY time.** `env` is an ordinary object handed to the handler, populated
 * from the stanzas in `wrangler.toml` at deploy; there is no
 * `env.openD1("<uuid>")`, no runtime bind API, and no way for a Worker to
 * acquire a native `D1Database` for a tenant that was not declared before the
 * deploy. That is what makes "one database per tenant" cost a redeploy per
 * tenant, and it is the single largest architectural constraint in this port.
 *
 * CLOSEST BEHAVIOR IMPLEMENTED: {@link TenantDatabaseRouter} — a runtime lookup
 * by NAME over the deploy-time-declared set, driven by the control database's
 * `tenant_databases` registry ({@link EnvBindingTenantDatabaseRouter}), which
 * fails closed on every tenant it cannot resolve rather than falling back to the
 * control database. It has real importers in `apps/{gateway,control-plane,mcp}`
 * and `test/mount-inventory.test.ts` reddens if any of them drops it.
 *
 * WHAT THIS MARKER USED TO SAY, AND WHY IT WAS STALE: it read "Implementing it
 * means either (i) restricting it to read-only surfaces … or (ii) waiting on a
 * D1 API that offers a runtime-addressed transaction. Until one of those lands,
 * every method throws." **(i) HAS landed** —
 * {@link NonAtomicD1RestTenantDatabaseRouter} in `./tenant-rest.ts` serves
 * runtime-uuid-addressed reads and single-statement guarded writes over the
 * HTTP query API, reports `supportsAtomicBatch: false`, and is mounted in
 * `apps/gateway/src/tenancy/resolver.ts`. So "every method throws" describes
 * THIS class only, and it is now a deliberate posture rather than the state of
 * the port: the safest default, for a deployment that wants REST to be
 * unreachable, next to a fail-closed one for a tenant fleet too large for the
 * binding budget. Both are kept; see `./tenant-rest.ts`.
 *
 * STILL OPEN: (ii). No strategy gives runtime addressing AND a multi-statement
 * transaction — see the `rest` entry of {@link D1_BINDING_STRATEGIES} for the
 * one experiment that could change that and the reason it is not asserted here.
 */
export class D1RestTenantDatabaseRouter implements TenantDatabaseRouter {
  /** The topology it REFUSES to serve — see `forTenant`. */
  readonly backend = "rest" as const;

  constructor(
    private readonly controlDb: D1Database,
    private readonly config: { accountId: string; apiTokenRef: string },
  ) {}

  control(): D1Database {
    return this.controlDb;
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    // The message names the ONE primitive that is actually missing. It used to
    // say "neither atomic batch() nor RETURNING", which was wrong about
    // RETURNING (the /query response carries `results` per statement) and wrong
    // in the expensive direction: an operator who believes a single guarded
    // `UPDATE … RETURNING` cannot report its own guard over REST reaches for a
    // SELECT-then-UPDATE, which is the race this refusal exists to prevent.
    throw StorageError.runtime(
      [
        `D1 REST tenant routing is refused by this router (tenant ${tenantId}, account`,
        `${this.config.accountId}): the REST query API has no transaction envelope that makes N`,
        "statements one commit, so the wallet no-oversell guard and the workflow-budget CAS",
        "cannot be run over it. Single-statement guarded writes and their RETURNING rows DO",
        "work — use NonAtomicD1RestTenantDatabaseRouter if that is the half you need, or",
        "EnvBindingTenantDatabaseRouter / a proxy Worker holding native bindings behind a",
        "service binding for the money paths.",
      ].join(" "),
    );
  }

  async provisionedTenants(): Promise<readonly string[]> {
    return new ControlDatabaseTenantRegistry(this.controlDb)
      .list()
      .then((r) => r.map((x) => x.tenantId));
  }
}
