/**
 * The **D1 REST** leg of the tenant router — strategy (c) of
 * {@link D1_BINDING_STRATEGIES}, implemented rather than merely described.
 *
 * ## Why this file exists at all
 *
 * `EnvBindingTenantDatabaseRouter` (`./tenant-router.ts`) is the strategy to
 * DEPLOY: it hands back a native `D1Database`, so `batch()` is one transaction
 * and `RETURNING` reports the guard, and every algorithm in `./d1/` keeps the
 * exact atomicity the Postgres row lock gave. Its price is that onboarding a
 * tenant requires a `wrangler deploy` (a new `[[d1_databases]]` stanza) and a
 * Worker's binding budget is finite — practically low hundreds.
 *
 * The D1 **HTTP query API** is the only way to address a database by **runtime
 * uuid**, which is what the `tenant_databases.database_uuid` column has always
 * held and what the Rust backend used. It removes the deploy-time coupling
 * entirely. So it is the escape hatch for tenant counts the binding budget
 * cannot hold — and it is *unsafe for the money paths*, for one specific and
 * unfixable reason.
 *
 * ## EXACTLY what can and cannot be atomic through this path
 *
 * The REST endpoint is `POST /accounts/{account}/d1/database/{uuid}/query` with
 * `{ sql, params }`. It executes the statement(s) of ONE request and returns.
 * There is:
 *
 *   * **no interactive transaction** — you cannot `BEGIN` in one call, read in
 *     a second, and `COMMIT` in a third. Each call is independent, so a guard
 *     evaluated in call *n* is stale by call *n+1*;
 *   * **no `D1Database.batch()` semantics** — `batch()` on a native binding is
 *     one implicit transaction over an array of prepared statements; the REST
 *     API has no equivalent envelope, so the closest honest translation is
 *     "N independent round trips", which is *not* what `batch()` promises.
 *
 * Therefore, through a REST handle:
 *
 * | operation | atomic? | why |
 * |---|---|---|
 * | a single `SELECT` | n/a | reads are fine, and are most of the read path |
 * | a single `INSERT` / `UPDATE` / `DELETE` | **yes** | one statement is its own implicit transaction in SQLite, so a guarded `UPDATE … WHERE <cas> ` is still a real CAS |
 * | a single guarded write that needs its `RETURNING` rows | **yes for the write, and the rows come back** — see {@link D1RestDatabase} | the REST result carries `results`, so `RETURNING` is *not* lost the way the pre-`d1-proxy` Rust marshalling lost it |
 * | `batch([...])` — the wallet no-oversell reserve (3 statements), the workflow-budget CAS, the billing-outbox enqueue (#150) | **NO** | there is no envelope that makes N statements one transaction. This class REFUSES rather than issuing them serially: serial issue is an oversell, not a slower reserve |
 *
 * That last row is precisely why the Rust tree grew `workers/d1-proxy` (issue
 * #450): a Worker holding the NATIVE binding, exposed behind a bearer-auth HTTP
 * API (a `[[services]]` binding, in this port), so `batch()`/`RETURNING` survive
 * a runtime-addressed hop. If you need runtime addressing *and* the money paths,
 * that is the shape to build — not this one.
 *
 * ## Fail-closed, expressed in the type system
 *
 * A handle produced here reports `supportsAtomicBatch: false`, and
 * {@link requireAtomicBatch} — which every guarded write in `./d1/` calls
 * first — refuses it. So wiring a REST router into a deployment cannot
 * silently downgrade the no-oversell guard: the guarded write throws instead of
 * running non-atomically. `batch()` itself throws for the same reason, so even
 * a caller that skipped `requireAtomicBatch` cannot get a half-applied reserve.
 */
import { StorageError } from "./errors.js";
import {
  ControlDatabaseTenantRegistry,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
} from "./tenant-router.js";

/** Default origin of the Cloudflare v4 API. Overridable for tests. */
export const D1_REST_API_BASE = "https://api.cloudflare.com/client/v4";

/** Minimal `fetch` shape, so a test can inject one without a network. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Everything the REST transport needs. `apiToken` is a SECRET. */
export interface D1RestTransportConfig {
  readonly accountId: string;
  /** Cloudflare API token with D1 edit permission. Cloudflare Secrets Store. */
  readonly apiToken: string;
  /** Injected for tests; defaults to the global `fetch`. */
  readonly fetch?: FetchLike;
  /** Defaults to {@link D1_REST_API_BASE}. */
  readonly baseUrl?: string;
}

/** The `result[]` element the D1 query API returns per statement. */
interface D1RestQueryResult {
  results?: unknown[];
  success?: boolean;
  meta?: Record<string, unknown>;
}

interface D1RestEnvelope {
  success?: boolean;
  errors?: { code?: number; message?: string }[];
  result?: D1RestQueryResult[];
}

/**
 * One prepared statement over the REST query API.
 *
 * Deliberately NOT `implements D1PreparedStatement`: `D1PreparedStatement` is
 * an ambient ABSTRACT CLASS with overloaded `first`/`raw` signatures that only
 * workerd can supply, so a hand-written class can never satisfy it nominally.
 * The single structural cast lives in {@link D1RestDatabase.prepare}, where it
 * is visible, rather than being sprinkled over every call site.
 */
export class D1RestPreparedStatement {
  readonly #query: string;
  readonly #params: readonly unknown[];
  readonly #execute: (sql: string, params: readonly unknown[]) => Promise<D1RestQueryResult>;

  constructor(
    query: string,
    params: readonly unknown[],
    execute: (sql: string, params: readonly unknown[]) => Promise<D1RestQueryResult>,
  ) {
    this.#query = query;
    this.#params = params;
    this.#execute = execute;
  }

  bind(...values: unknown[]): D1RestPreparedStatement {
    return new D1RestPreparedStatement(this.#query, values, this.#execute);
  }

  async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
    const rows = (await this.#execute(this.#query, this.#params)).results ?? [];
    const row = rows[0];
    if (row === undefined) return null;
    if (colName === undefined) return row as T;
    return (row as Record<string, unknown>)[colName] as T;
  }

  async all<T = Record<string, unknown>>(): Promise<{
    results: T[];
    success: true;
    meta: Record<string, unknown>;
  }> {
    const result = await this.#execute(this.#query, this.#params);
    return { results: (result.results ?? []) as T[], success: true, meta: result.meta ?? {} };
  }

  async run<T = Record<string, unknown>>(): Promise<{
    results: T[];
    success: true;
    meta: Record<string, unknown>;
  }> {
    return this.all<T>();
  }

  async raw<T = unknown[]>(options?: { columnNames?: boolean }): Promise<T[] | [string[], ...T[]]> {
    const rows = ((await this.#execute(this.#query, this.#params)).results ?? []) as Record<
      string,
      unknown
    >[];
    const columns = rows.length === 0 ? [] : Object.keys(rows[0] as Record<string, unknown>);
    const values = rows.map((row) => columns.map((column) => row[column]) as unknown as T);
    return options?.columnNames === true ? [columns, ...values] : values;
  }
}

/**
 * A `D1Database`-shaped client bound to ONE database uuid over the REST query
 * API. See the file docblock for the atomicity table this class implements.
 */
export class D1RestDatabase {
  readonly #url: string;
  readonly #apiToken: string;
  readonly #fetch: FetchLike;

  constructor(
    readonly databaseUuid: string,
    config: D1RestTransportConfig,
  ) {
    const base = config.baseUrl ?? D1_REST_API_BASE;
    this.#url = `${base}/accounts/${config.accountId}/d1/database/${databaseUuid}/query`;
    this.#apiToken = config.apiToken;
    this.#fetch = config.fetch ?? ((input, init) => fetch(input, init));
  }

  /**
   * The structural cast to `D1Database`. One place, deliberately: see the note
   * on {@link D1RestPreparedStatement}. Everything `./d1/` actually calls
   * (`prepare().bind().first()/all()/run()`, and `batch`, which throws) is
   * implemented here; `exec`, `dump` and `withSession` are not reachable over
   * the query API and throw with the reason.
   */
  asD1Database(): D1Database {
    return this as unknown as D1Database;
  }

  prepare(query: string): D1PreparedStatement {
    return new D1RestPreparedStatement(query, [], (sql, params) =>
      this.#query(sql, params),
    ) as unknown as D1PreparedStatement;
  }

  /**
   * REFUSED, always.
   *
   * `batch()` on a native binding is ONE transaction over N statements. The
   * REST query API has no envelope that provides that, so the only available
   * translation is N independent round trips — which turns the wallet
   * no-oversell reserve's in-statement guard into a read-then-write with a race
   * window, i.e. an OVERSELL, and turns the billing-outbox enqueue (#150) into
   * a ledger row that can exist without its outbox row. Throwing is the only
   * correct behaviour; see the file docblock and `workers/d1-proxy`.
   */
  batch<T = unknown>(_statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    return Promise.reject(
      StorageError.runtime(
        [
          `D1 REST database ${this.databaseUuid} cannot run batch(): the HTTP query API has no`,
          "transaction envelope, so N statements would be N independent round trips. Running the",
          "no-oversell reserve or the billing-outbox enqueue that way is an oversell / a torn",
          "write, not a slower one. Use a native [[d1_databases]] binding, or a proxy Worker that",
          "holds one behind a [[services]] binding.",
        ].join(" "),
      ),
    );
  }

  exec(_query: string): Promise<D1ExecResult> {
    return Promise.reject(
      StorageError.runtime(
        `D1 REST database ${this.databaseUuid} does not expose exec(); use prepare().run()`,
      ),
    );
  }

  dump(): Promise<ArrayBuffer> {
    return Promise.reject(
      StorageError.runtime(`D1 REST database ${this.databaseUuid} does not expose dump()`),
    );
  }

  withSession(): never {
    throw StorageError.runtime(
      `D1 REST database ${this.databaseUuid} does not expose D1 Sessions over the query API`,
    );
  }

  async #query(sql: string, params: readonly unknown[]): Promise<D1RestQueryResult> {
    let response: Response;
    try {
      response = await this.#fetch(this.#url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.#apiToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sql, params: [...params] }),
      });
    } catch (error) {
      throw StorageError.runtime(
        `D1 REST query to database ${this.databaseUuid} failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    let envelope: D1RestEnvelope;
    try {
      envelope = (await response.json()) as D1RestEnvelope;
    } catch (error) {
      throw StorageError.runtime(
        `D1 REST query to database ${this.databaseUuid} returned status ${response.status} with a ` +
          `non-JSON body: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!response.ok || envelope.success !== true) {
      const detail = (envelope.errors ?? [])
        .map((e) => `${e.code ?? "?"}: ${e.message ?? "unknown"}`)
        .join("; ");
      throw StorageError.runtime(
        `D1 REST query to database ${this.databaseUuid} failed with status ${response.status}${
          detail === "" ? "" : ` (${detail})`
        }`,
      );
    }
    const first = (envelope.result ?? [])[0];
    if (first === undefined) {
      throw StorageError.runtime(
        `D1 REST query to database ${this.databaseUuid} returned an empty result envelope`,
      );
    }
    return first;
  }
}

/**
 * Routes tenants to REST-addressed databases by `tenant_databases.database_uuid`.
 *
 * This is the strategy with **no deploy-time coupling**: onboarding a tenant is
 * a row in the control database, not a redeploy. Every handle it produces
 * reports `supportsAtomicBatch: false`, so {@link requireAtomicBatch} refuses it
 * on every guarded write in `./d1/` — the class name says which half of the
 * store it can serve, and the type system enforces it.
 *
 * Contrast with `D1RestTenantDatabaseRouter` in `./tenant-router.ts`, which
 * refuses to hand out a handle AT ALL. Both are correct and both are kept: that
 * one is the "REST is not an option for this deployment" posture (the safest
 * default, and what a money-path deployment should configure); this one is the
 * "REST reads only, and the store will refuse anything else" posture for a
 * tenant fleet too large for the binding budget.
 *
 * Fail-closed is unchanged: an unregistered tenant throws, and there is no
 * default-database parameter.
 */
export class NonAtomicD1RestTenantDatabaseRouter implements TenantDatabaseRouter {
  readonly #registry: ControlDatabaseTenantRegistry;

  constructor(
    private readonly controlDb: D1Database,
    private readonly config: D1RestTransportConfig,
  ) {
    this.#registry = new ControlDatabaseTenantRegistry(controlDb);
  }

  control(): D1Database {
    return this.controlDb;
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    if (tenantId === "") {
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    if (this.config.accountId === "" || this.config.apiToken === "") {
      throw StorageError.runtime(
        [
          "D1 REST tenant routing needs both an account id and an API token;",
          `refusing to route tenant ${tenantId} without them`,
        ].join(" "),
      );
    }
    const registration = await this.#registry.get(tenantId);
    if (!registration) {
      throw StorageError.notFound(
        `tenant ${tenantId} has no provisioned D1 database in the control registry`,
      );
    }
    if (registration.databaseUuid === "") {
      throw StorageError.runtime(
        `tenant ${tenantId} has a registry row with an empty database_uuid; refusing to route`,
      );
    }
    return {
      tenantId,
      db: new D1RestDatabase(registration.databaseUuid, this.config).asD1Database(),
      source: "rest",
      // The whole point. `requireAtomicBatch` refuses this handle, so the
      // no-oversell reserve and the workflow-budget CAS cannot run over it.
      supportsAtomicBatch: false,
      databaseUuid: registration.databaseUuid,
      schemaVersion: registration.schemaVersion,
    };
  }

  async provisionedTenants(): Promise<readonly string[]> {
    return (await this.#registry.list()).map((row) => row.tenantId);
  }
}
