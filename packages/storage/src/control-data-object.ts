/**
 * `ControlDataObject` — the SQLite-backed Durable Object that **is** the
 * control database (Zero-D1 slice S1, issue #877,
 * `docs/design/zero-d1-control-object-2026-08.md`).
 *
 * ## One class, ONE instance
 *
 * The control database answers "which tenant?" — `api_key_directory`,
 * `tenants`, plans, RBAC — so it cannot itself be tenant-routed
 * (`apps/gateway/src/tenancy/ports.ts`, the chicken-and-egg rule). Every
 * Worker addresses the SAME object: `idFromName(CONTROL_DATA_ADDRESS)`, where
 * the address is the constant `"control"`. There is deliberately no second
 * name: a caller that addresses anything else is refused by {@link #admit},
 * because two control objects would be two divergent control databases and
 * nothing would ever notice which one a Worker read.
 *
 * ## What is inherited from `TenantDataObject`, and what is not
 *
 * The SQL discipline is identical and deliberately shared —
 * {@link sqlStatements} splits migration files, {@link connectionCounters}
 * measures the `total_changes()` delta, every cursor is drained in the same
 * synchronous stretch that opened it, `transactionSync()` is the only
 * transaction, and the lazy migration runs under `blockConcurrencyWhile` so no
 * RPC can observe a half-migrated database.
 *
 * This is a SEPARATE class rather than a subclass because the tenant object's
 * schema-specific machinery is wrong for the control schema, in ways that fail
 * closed but late: `#assertLedgerHonest` witnesses the tenant table
 * `projects` (absent here — the second cold start would refuse everything),
 * the aggregate-flush alarm writes tenant rollup tables (absent here), and
 * the operator-audit chain appends to the tenant `audit_events` shape. A slim
 * control class keeps each object honest about its own schema.
 *
 * ## The applier gates by NAME, not by version — this is load-bearing
 *
 * `sql/d1-ts/control/` has NON-UNIQUE `NNNN` prefixes (three `0003_*` files,
 * two `0004_*`): `wrangler d1 migrations apply` bookkeeps by filename and
 * never cared. The tenant applier's `MAX(version)` gate over these files
 * would apply `0003_audit_chain` and silently skip the other two `0003`s. So
 * this applier keeps its own ledger, `control_schema_applied`, keyed by
 * MIGRATION NAME, and applies every file whose name is not yet recorded, in
 * filename order. `storage_schema_migrations` (which `0001_init_control`
 * creates and writes a row into) is left exactly as the migration bytes wrote
 * it — the object does not fight the schema's own bookkeeping, it just does
 * not trust a non-unique key.
 *
 * ## RPC shape
 *
 * `query`/`batch` take the SAME request shapes as `TenantDataObject`
 * (`tenantId` carrying the fixed address `"control"`), so the existing
 * `DurableObjectD1Database` facade works over this stub UNCHANGED — the whole
 * point of S1 is that the ~87 `D1Database`-shaped store modules port by
 * re-pointing a binding seam, not by rewriting SQL. There is no `fetch()`
 * surface: every method is RPC over the binding.
 */
import { DurableObject } from "cloudflare:workers";
import { CONTROL_MIGRATIONS, type ControlMigration } from "./control-schema-sql.js";
import {
  type TenantDataBatchRequest,
  type TenantDataQueryRequest,
  type TenantDataResult,
  type TenantDataStatement,
  type TenantDataValue,
  connectionCounters,
  sqlStatements,
} from "./tenant-data-object.js";

/**
 * The single well-known address of the control object.
 *
 * Re-homed from `"control"` to `"control-apac"` for the D1→DO cutover. Two
 * reasons, both load-bearing:
 *  1. Region. The original `"control"` object first materialized WITHOUT a
 *     valid location hint and is pinned in US-East; a `locationHint` is honored
 *     only on an address's FIRST `get()`, so an already-placed object cannot be
 *     relocated. A fresh address gets a clean first `get()` (hinted `"apac"`,
 *     in-region for this APAC fleet — see control-do.ts).
 *  2. Backfill correctness. The D1→DO backfill copies with `INSERT OR IGNORE`,
 *     so a NON-empty destination would keep its own rows and silently drop the
 *     current D1 value on any shared primary key. Only a guaranteed-empty
 *     (never-before-addressed) object copies every current D1 row faithfully.
 * The old US-East `"control"` object is abandoned.
 */
export const CONTROL_DATA_ADDRESS = "control-apac";

/** Prefix on every refusal this object raises, so a caller can recognise one. */
const REFUSAL = "control_data_object";

/**
 * The ledger-vs-reality witness. `api_key_directory` is created by
 * `0001_init_control` and is the one table the whole fleet cannot
 * authenticate without — a ledger that claims 0001 applied while this table
 * is absent is a corrupt database, and the object refuses every query rather
 * than serving it.
 */
const WITNESS_TABLE = "api_key_directory";

/** Status RPC result — see {@link ControlDataObject.schemaStatus}. */
export interface ControlSchemaStatus {
  readonly address: string;
  /** Names applied on THIS wake (empty on a warm start of a current object). */
  readonly appliedThisWake: readonly string[];
  /** Count of ledgered migrations vs. the compiled-in set. */
  readonly appliedCount: number;
  readonly knownCount: number;
  readonly databaseSize: number;
  /**
   * The recorded schema failure, or `null` on a healthy object. Surfaced here
   * (this RPC alone is not gated on it) so an operator sees WHICH file the
   * apply stopped at instead of only the refusal every data RPC raises.
   */
  readonly failure: string | null;
}

export class ControlDataObject extends DurableObject {
  readonly #state: DurableObjectState;
  #appliedThisWake: string[] = [];
  #failure: string | null = null;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx as never, env as never);
    this.#state = ctx;
    // Same lock discipline as the tenant object: no RPC is delivered until
    // this settles, and a failure is RECORDED, not swallowed — every later
    // RPC refuses with the message instead of the object aborting opaquely.
    ctx.blockConcurrencyWhile(async () => {
      try {
        this.#migrate();
      } catch (error) {
        this.#failure = error instanceof Error ? error.message : String(error);
      }
    });
  }

  /**
   * The migration set. Overridable so a test can drive a schema that FAILS —
   * a method rather than a field because subclass field initializers run
   * after `super()`, i.e. after the constructor has already migrated.
   */
  protected migrations(): readonly ControlMigration[] {
    return CONTROL_MIGRATIONS;
  }

  // -------------------------------------------------------------------------
  // RPC surface
  // -------------------------------------------------------------------------

  /**
   * Run one statement. One statement is still a transaction: the `changes`
   * delta must not straddle a commit boundary, and a bare `query()` gets the
   * same rollback-on-throw semantics `batch()` has.
   */
  async query(request: TenantDataQueryRequest): Promise<TenantDataResult> {
    await this.#admit(request.tenantId);
    return this.#state.storage.transactionSync(() => this.#exec(request));
  }

  /**
   * Run N statements as ONE transaction — the property the money-adjacent
   * control writes (key mint + directory row, plan + quota row) rely on, and
   * the property the D1 facade's `batch()` promises. Exactly one result per
   * submitted statement, in order.
   */
  async batch(request: TenantDataBatchRequest): Promise<TenantDataResult[]> {
    await this.#admit(request.tenantId);
    return this.#state.storage.transactionSync(() => {
      const results: TenantDataResult[] = [];
      for (const statement of request.statements) {
        results.push(this.#exec(statement));
      }
      return results;
    });
  }

  /**
   * Schema/health probe for deploy verification and the S5 cutover checks.
   *
   * Deliberately NOT gated on the recorded failure — this is the one RPC that
   * stays answerable on a broken object, so the operator reads which file the
   * apply stopped at instead of only the refusal. The address check still
   * applies: a mis-addressed probe is a caller bug even when broken.
   */
  async schemaStatus(request: { readonly tenantId: string }): Promise<ControlSchemaStatus> {
    await this.#admitAddress(request.tenantId);
    let appliedCount = 0;
    try {
      const applied = this.#state.storage.sql
        .exec<{ n: number }>("SELECT COUNT(*) AS n FROM control_schema_applied")
        .toArray();
      appliedCount = applied[0]?.n ?? 0;
    } catch {
      // A failure so early the ledger table never existed; 0 is the honest count.
    }
    return {
      address: CONTROL_DATA_ADDRESS,
      appliedThisWake: [...this.#appliedThisWake],
      appliedCount,
      knownCount: this.migrations().length,
      databaseSize: this.#state.storage.sql.databaseSize,
      failure: this.#failure,
    };
  }

  // -------------------------------------------------------------------------
  // Admission
  // -------------------------------------------------------------------------

  /**
   * Refuse a failed schema and any address other than the constant.
   *
   * Unlike the tenant object there is no adopt-first-id step: the correct
   * address is knowable at compile time, so anything else is a caller bug —
   * most plausibly a seam that passed a TENANT id, which must never be
   * answered with control data. The `typeof` check is not redundant with the
   * declared type: the value arrived over an RPC boundary as a structured
   * clone, and a guard does not take the caller's word for its own input.
   */
  /**
   * `async` although nothing inside awaits: an RPC method that throws BEFORE
   * its first `await` throws synchronously into the RPC plumbing, which
   * workerd additionally reports as an uncaught exception in the object's
   * context even though the caller receives the rejection. Refusing from
   * inside the async machinery keeps a refusal a single, ordinary rejection.
   */
  async #admit(address: string): Promise<void> {
    if (this.#failure !== null) {
      throw new Error(`${REFUSAL}: ${this.#failure}`);
    }
    await this.#admitAddress(address);
  }

  /** Same `async`-for-rejection-shape rationale as {@link #admit}. */
  async #admitAddress(address: string): Promise<void> {
    if (typeof address !== "string" || address !== CONTROL_DATA_ADDRESS) {
      throw new Error(
        `${REFUSAL}: this object is the control database and answers only address "${CONTROL_DATA_ADDRESS}"; it was addressed as "${String(address)}". A tenant id here means a routing seam leaked tenant traffic to control storage.`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Execution
  // -------------------------------------------------------------------------

  /**
   * Run one statement and materialize its result. SYNCHRONOUS and called only
   * from inside a `transactionSync` callback — the cursor is drained in the
   * same synchronous stretch, so it is never held across an `await` where it
   * could observe rows a rollback later removes. Identical measurement
   * discipline to `TenantDataObject.#exec`.
   */
  #exec(statement: TenantDataStatement): TenantDataResult {
    const sql = this.#state.storage.sql;
    const before = connectionCounters(sql).changes;
    const cursor = sql.exec<Record<string, TenantDataValue>>(
      statement.sql,
      ...(statement.params ?? []),
    );
    const results = cursor.toArray();
    const rowsRead = cursor.rowsRead;
    const rowsWritten = cursor.rowsWritten;
    const after = connectionCounters(sql);
    return {
      results,
      changes: after.changes - before,
      rowsRead,
      rowsWritten,
      lastRowId: after.lastRowId,
      databaseSize: sql.databaseSize,
    };
  }

  // -------------------------------------------------------------------------
  // Schema migration
  // -------------------------------------------------------------------------

  /**
   * Apply every migration whose NAME is not yet ledgered, in filename order.
   *
   * One transaction per FILE: the file's DDL and its `control_schema_applied`
   * row commit or roll back together, which is what makes the ALTER-only
   * control files safe to gate on the ledger — SQLite has no `ADD COLUMN IF
   * NOT EXISTS`, so a re-apply throws `duplicate column name`, and the only
   * way that can happen is a ledger row that committed without its DDL, which
   * the shared transaction makes impossible.
   *
   * The ledger table itself is created OUTSIDE the version gate and is
   * idempotent; it exists before the first file runs so the applied-set read
   * below never races its own bootstrap.
   */
  #migrate(): void {
    this.#state.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS control_schema_applied (" +
        "name TEXT PRIMARY KEY, " +
        "ordinal INTEGER NOT NULL, " +
        "applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch()))",
    );
    const applied = new Set(
      this.#state.storage.sql
        .exec<{ name: string }>("SELECT name FROM control_schema_applied")
        .toArray()
        .map((row) => row.name),
    );
    this.#assertLedgerHonest(applied);
    for (const migration of this.migrations()) {
      if (applied.has(migration.name)) continue;
      try {
        this.#state.storage.transactionSync(() => {
          for (const statement of sqlStatements(migration.sql)) {
            this.#state.storage.sql.exec(statement);
          }
          // Recorded LAST and inside the same transaction, into the
          // name-keyed ledger this applier trusts. The row some migrations
          // also write into `storage_schema_migrations` is left as the
          // migration bytes wrote it.
          this.#state.storage.sql.exec(
            "INSERT INTO control_schema_applied (name, ordinal) VALUES (?, ?)",
            migration.name,
            migration.ordinal,
          );
        });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
          `control schema migration stopped at ${migration.name} (ordinal ` +
            `${migration.ordinal} of ${this.migrations().length}); the control database is ` +
            `refusing every query. cause: ${detail}`,
        );
      }
      this.#appliedThisWake.push(migration.name);
    }
  }

  /**
   * Refuse a ledger that claims a schema the database does not have. Can only
   * disagree if a ledger row committed without its DDL — which the per-file
   * transaction prevents — so this should never fire; failing closed on an
   * impossible state costs one `sqlite_master` probe per cold start.
   */
  #assertLedgerHonest(applied: ReadonlySet<string>): void {
    if (applied.size >= 1 && !this.#tableExists(WITNESS_TABLE)) {
      throw new Error(
        [
          `control schema ledger records ${applied.size} applied migrations but table`,
          `${WITNESS_TABLE} is absent; the ledger and the database disagree, so the`,
          "control object is refusing every query rather than serving an incomplete schema",
        ].join(" "),
      );
    }
  }

  #tableExists(name: string): boolean {
    return (
      this.#state.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
          name,
        )
        .toArray().length > 0
    );
  }
}

/** The `[[durable_objects.bindings]]` namespace type for `env.CONTROL_DATA`. */
export type ControlDataNamespace = DurableObjectNamespace<ControlDataObject>;
