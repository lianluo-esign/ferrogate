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
 * atomic `batch()` and cannot return `RETURNING` rows**, which are the two
 * primitives every money-path guard in this package is built on.
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
  /** The D1 HTTP query API addressed by uuid. No atomic batch, no `RETURNING`. */
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
 * the same mapping as a JSON document (`D1_TENANT_DATABASE_REGISTRY_KIND` /
 * `_ID`). Retained so a Rust-era control database can be read by this port and
 * migrated into the `tenant_databases` table.
 *
 * PORT-TODO(inventory-data-billing §1.7): the document→table migration itself
 * is an `apps/control-plane` provisioning slice; this package only names the
 * key so neither side invents a different one.
 */
export const TENANT_DATABASE_REGISTRY_KIND = "d1_tenant_database_registry";
export const TENANT_DATABASE_REGISTRY_ID = "default";

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
   * It is **not usable for the money paths**. The REST query API executes one
   * statement per call with no transaction spanning calls, and does not return
   * `RETURNING` rows. So the wallet reserve's 3-statement guard would become
   * three independent round trips with a race window between the guard and the
   * insert — that is an oversell, not a slower reserve. The Rust tree built
   * `d1-proxy` for exactly this reason.
   */
  rest: {
    atomicBatch: false,
    returning: false,
    requiresDeployPerTenant: false,
    tenantCeiling: "unbounded",
    extraNetworkHop: true,
  },
} as const;

/**
 * **(b) in JOB 3, unresolved half** — the D1 REST strategy, declared so the
 * seam exists and refused so it cannot be used by accident.
 *
 * PORT-TODO(inventory-data-billing §1.7 "per-tenant D1 binding at runtime"):
 * this is the biggest architectural open question in the port. Implementing it
 * means either (i) restricting it to read-only surfaces and keeping every
 * guarded write on a native/proxy handle, or (ii) waiting on a D1 API that
 * offers a runtime-addressed transaction. Until one of those lands, every
 * method throws — a stub that "worked" for reads and silently lost atomicity on
 * writes is the more dangerous artifact.
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
    throw StorageError.runtime(
      [
        `D1 REST tenant routing is not implemented (tenant ${tenantId}, account`,
        `${this.config.accountId}): the REST query API provides neither atomic batch() nor`,
        "RETURNING, so the wallet no-oversell guard and the workflow-budget CAS cannot be",
        "run over it. Use EnvBindingTenantDatabaseRouter, or a proxy Worker holding native",
        "bindings behind a service binding.",
      ].join(" "),
    );
  }

  async provisionedTenants(): Promise<readonly string[]> {
    return new ControlDatabaseTenantRegistry(this.controlDb)
      .list()
      .then((r) => r.map((x) => x.tenantId));
  }
}
