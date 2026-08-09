/**
 * `TenantDatabaseRouter` — the tenantId → D1 handle seam (JOB 3).
 *
 * ## The constraint this module exists to answer
 *
 * The current tenant data plane is a SQLite-backed Durable Object addressed by
 * tenant id. CONTROL remains an account-global D1 database for the roster,
 * provisioning state, and cross-tenant projections. Cloudflare resolves the DO
 * namespace once at deploy time; individual tenant objects are addressed at
 * runtime with `idFromName(tenantId)` and carry their own transaction boundary.
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
 * An explicit native-binding router remains for single-tenant and self-hosted
 * compatibility deployments. It selects a deploy-time binding by the optional
 * `tenant_databases.binding_name` value. See {@link D1_BINDING_STRATEGIES} for
 * the supported sources and their constraints.
 *
 * ## Fail-closed is the invariant
 *
 * Every unresolvable tenant is an **error**, never a fallback. A router that
 * quietly returned the control database (or any other tenant's database) on a
 * miss would write one tenant's money into another tenant's ledger — the exact
 * cross-tenant isolation property the tenant object topology exists to
 * guarantee. There is deliberately **no** "default database" parameter in this
 * module.
 */
import { StorageError } from "./errors.js";
import type { TenantDataStatement } from "./tenant-data-object.js";
import type {
  TenantJurisdiction,
  TenantLocationHint,
  TenantObjectAddress,
} from "./tenant-placement.js";

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
   * of the source: all supported tenant-data sources preserve the transaction
   * contract required by the guarded write paths.
   */
  readonly supportsAtomicBatch: boolean;
  /** `tenant_databases.schema_version`; which tenant migration the DB is at. */
  readonly schemaVersion?: number;
}

/**
 * The port. `packages/*` and `apps/*` depend on THIS, never on a concrete
 * implementation, so a deployment can keep native-binding compatibility without
 * touching a single algorithm.
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
  forTenant(tenantId: string, address?: TenantObjectAddress): Promise<TenantDatabaseHandle>;
  /**
   * Optional operator-only batch used for authority projections such as tenant
   * RBAC bindings. Durable Object routers forward this to the private RPC;
   * native/shared routers implement the same capability only at this trusted
   * composition-root boundary. Callers must fail closed instead of routing a
   * privileged write through a normal tenant SQL handle.
   */
  privilegedBatch?(
    tenantId: string,
    statements: readonly TenantDataStatement[],
    address?: TenantObjectAddress,
  ): Promise<void>;
  /** Arm the earliest schedule deadline in a tenant Durable Object. */
  setScheduleAlarm?(
    tenantId: string,
    scheduledAtUnix: number,
    address?: TenantObjectAddress,
  ): Promise<void>;
  /** Clear a tenant Durable Object's schedule alarm when no schedule remains. */
  clearScheduleAlarm?(tenantId: string, address?: TenantObjectAddress): Promise<void>;
  /** Recompute and arm the single alarm from current tenant-local schedule rows. */
  rearmScheduleAlarm?(tenantId: string, address?: TenantObjectAddress): Promise<void>;
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
 * Called at the top of every guarded write in `src/d1/`. All supported tenant
 * handles preserve the atomic guard contract; this check keeps future routers
 * from silently degrading a no-oversell reserve to read-then-write.
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
 * `bindingName` is optional because a Durable Object tenant has no deploy-time
 * tenant binding. It remains only for explicit native-binding compatibility.
 */
export interface TenantDatabaseRegistration {
  tenantId: string;
  /** Native-binding compatibility only; absent for a Durable Object tenant. */
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
  locationHint?: TenantLocationHint;
  /** The Cloudflare request signal used to derive the first hint. */
  locationHintSource?: string;
  /** Unix time when the first-resolution placement decision was recorded. */
  locationHintRecordedAtUnix?: number;
  /** The hard Durable Object namespace jurisdiction, when one was selected. */
  jurisdiction?: TenantJurisdiction;
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

/** Every column {@link registrationFromRow} decodes. One list, so the reads cannot drift. */
const TENANT_DATABASE_COLUMNS =
  "tenant_id, binding_name, schema_version, storage_backend, provisioning_status, " +
  "catalog_seeded_at_unix, last_error, location_hint, location_hint_source, " +
  "location_hint_recorded_at_unix, jurisdiction, " +
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
          "(tenant_id, binding_name, schema_version, storage_backend, provisioning_status, " +
          " catalog_seeded_at_unix, last_error, location_hint, location_hint_source, " +
          " location_hint_recorded_at_unix, jurisdiction, migration_state, " +
          " provisioned_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT (tenant_id) DO UPDATE SET " +
          "binding_name = excluded.binding_name, " +
          "schema_version = excluded.schema_version, " +
          "storage_backend = excluded.storage_backend, " +
          "provisioning_status = excluded.provisioning_status, " +
          "catalog_seeded_at_unix = excluded.catalog_seeded_at_unix, " +
          "last_error = excluded.last_error, " +
          "location_hint = excluded.location_hint, " +
          "location_hint_source = excluded.location_hint_source, " +
          "location_hint_recorded_at_unix = excluded.location_hint_recorded_at_unix, " +
          "jurisdiction = excluded.jurisdiction, " +
          "migration_state = excluded.migration_state, " +
          "updated_at_unix = excluded.updated_at_unix",
      )
      .bind(
        registration.tenantId,
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
        registration.locationHintSource ?? null,
        registration.locationHintRecordedAtUnix ?? null,
        registration.jurisdiction ?? null,
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
  binding_name: string | null;
  schema_version: number;
  storage_backend: string | null;
  provisioning_status: string | null;
  catalog_seeded_at_unix: number | null;
  last_error: string | null;
  location_hint: string | null;
  location_hint_source: string | null;
  location_hint_recorded_at_unix: number | null;
  jurisdiction: string | null;
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
    ...(row.location_hint === null
      ? {}
      : { locationHint: row.location_hint as TenantLocationHint }),
    ...(row.location_hint_source === null ? {} : { locationHintSource: row.location_hint_source }),
    ...(row.location_hint_recorded_at_unix === null
      ? {}
      : { locationHintRecordedAtUnix: row.location_hint_recorded_at_unix }),
    ...(row.jurisdiction === null ? {} : { jurisdiction: row.jurisdiction as TenantJurisdiction }),
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
    ...(row.migration_last_error === null ? {} : { migrationLastError: row.migration_last_error }),
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
      // A row without a binding is either a Durable Object tenant, which must
      // use the object router, or a native-binding tenant that has not been
      // deployed with its binding yet. Both cases fail closed here.
      throw StorageError.notFound(
        `tenant ${tenantId} has no native D1 binding_name; this router serves explicit self-hosted [[d1_databases]] bindings only`,
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
      statements.map((statement) =>
        handle.db.prepare(statement.sql).bind(...(statement.params ?? [])),
      ),
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
      statements.map((statement) =>
        handle.db.prepare(statement.sql).bind(...(statement.params ?? [])),
      ),
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
 * The supported tenant storage sources. This table is asserted by the
 * platform-limits test so the documented topology cannot silently expand.
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
   * One SQLite-backed Durable Object per tenant, addressed by
   * `env.TENANT_DATA.idFromName(tenantId)`. It provides runtime addressing and
   * transaction-backed batches without a per-tenant deploy or binding stanza.
   */
  durable_object: {
    atomicBatch: true,
    returning: true,
    requiresDeployPerTenant: false,
    tenantCeiling: "unbounded; one binding serves every tenant, 10 GB per object",
    extraNetworkHop: true,
  },
  shared_development: {
    atomicBatch: true,
    returning: true,
    requiresDeployPerTenant: false,
    tenantCeiling: "single development database",
    extraNetworkHop: false,
  },
} as const;
