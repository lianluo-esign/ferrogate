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
  /** The account-global CONTROL database. Always a native binding. */
  control(): D1Database;
  /** Resolve one tenant's database, or throw. NEVER falls back. */
  forTenant(tenantId: string): Promise<TenantDatabaseHandle>;
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
 * One `tenant_databases` row. `bindingName` is `undefined` for a tenant whose
 * database exists but whose binding has not been deployed yet — the router
 * treats that as unresolvable, not as "use the control database".
 */
export interface TenantDatabaseRegistration {
  tenantId: string;
  databaseUuid: string;
  databaseName: string;
  bindingName?: string;
  schemaVersion: number;
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
        `tenant database registry document maps tenant ${tenantId} to a non-string ` +
          "or empty database uuid",
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
          "INSERT INTO tenant_databases " +
            "(tenant_id, database_uuid, database_name, binding_name, schema_version, " +
            " provisioned_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, NULL, ?, ?, ?)",
        )
        .bind(tenantId, databaseUuid, nameFor(tenantId, databaseUuid), schemaVersion, nowUnix, nowUnix)
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

/** Reads the tenant→database registry from the CONTROL database. */
export class ControlDatabaseTenantRegistry {
  constructor(private readonly controlDb: D1Database) {}

  async get(tenantId: string): Promise<TenantDatabaseRegistration | undefined> {
    const row = await this.controlDb
      .prepare(
        "SELECT tenant_id, database_uuid, database_name, binding_name, schema_version " +
          "FROM tenant_databases WHERE tenant_id = ?",
      )
      .bind(tenantId)
      .first<TenantDatabaseRow>();
    return row ? registrationFromRow(row) : undefined;
  }

  async list(): Promise<TenantDatabaseRegistration[]> {
    const result = await this.controlDb
      .prepare(
        "SELECT tenant_id, database_uuid, database_name, binding_name, schema_version " +
          "FROM tenant_databases ORDER BY tenant_id",
      )
      .all<TenantDatabaseRow>();
    return result.results.map(registrationFromRow);
  }

  /**
   * Register (or re-register) a tenant's database. Idempotent by `tenant_id`;
   * a redeploy that assigns a binding name is the common second call.
   */
  async upsert(registration: TenantDatabaseRegistration, nowUnix: number): Promise<void> {
    await this.controlDb
      .prepare(
        "INSERT INTO tenant_databases " +
          "(tenant_id, database_uuid, database_name, binding_name, schema_version, " +
          " provisioned_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT (tenant_id) DO UPDATE SET " +
          "database_uuid = excluded.database_uuid, " +
          "database_name = excluded.database_name, " +
          "binding_name = excluded.binding_name, " +
          "schema_version = excluded.schema_version, " +
          "updated_at_unix = excluded.updated_at_unix",
      )
      .bind(
        registration.tenantId,
        registration.databaseUuid,
        registration.databaseName,
        registration.bindingName ?? null,
        registration.schemaVersion,
        nowUnix,
        nowUnix,
      )
      .run();
  }
}

interface TenantDatabaseRow {
  tenant_id: string;
  database_uuid: string;
  database_name: string;
  binding_name: string | null;
  schema_version: number;
}

function registrationFromRow(row: TenantDatabaseRow): TenantDatabaseRegistration {
  return {
    tenantId: row.tenant_id,
    databaseUuid: row.database_uuid,
    databaseName: row.database_name,
    ...(row.binding_name === null ? {} : { bindingName: row.binding_name }),
    schemaVersion: row.schema_version,
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
      // Provisioned but not yet bound: the database exists in the account, the
      // Worker has not been redeployed with its binding. Fail closed — falling
      // back to the control database here is precisely how a tenant's ledger
      // ends up in the account-global one.
      throw StorageError.runtime(
        [
          `tenant ${tenantId} database ${registration.databaseUuid} has no binding_name;`,
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
      databaseUuid: registration.databaseUuid,
      schemaVersion: registration.schemaVersion,
    };
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

  async provisionedTenants(): Promise<readonly string[]> {
    return [...this.tenantIds].sort();
  }
}

// ---------------------------------------------------------------------------
// (b) The documented strategies for per-tenant databases
// ---------------------------------------------------------------------------

/**
 * The three ways to reach a per-tenant D1 database from a Worker, with the
 * honest cost of each. This constant is documentation that ships with the code
 * (and is asserted by a test, so it cannot silently rot); the same table is in
 * `packages/storage/README.md`.
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
} as const;

/**
 * The D1 REST strategy in its **strictest posture**: the seam exists, and
 * `forTenant` refuses outright so REST cannot be reached by accident.
 *
 * PORT-TODO(inventory-data-billing §1.7 "per-tenant D1 binding at runtime") —
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
