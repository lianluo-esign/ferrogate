/**
 * `PlatformDataObject` — the SQLite-backed Durable Object that is the
 * authoritative home for PLATFORM-SCOPED / unattributed evidence (Zero-D1
 * Plan B, the removal of the control D1).
 *
 * ## One class, ONE instance
 *
 * Platform evidence is `scope_type = 'platform'` screening of platform-operator
 * / anonymous calls — it has no owning tenant, so it cannot live in a
 * per-tenant `TenantDataObject`, and it used to sit in the control projection
 * only. A pure DO fan-out over the tenant roster structurally cannot reach it
 * (there is no roster tenant for an unattributed call). This singleton is the
 * one place those rows live once the control D1 is gone: every Worker addresses
 * the SAME object, `idFromName(PLATFORM_DATA_ADDRESS)`, where the address is the
 * constant `"platform"`. A caller that addresses anything else is refused by
 * {@link #admit} — two platform objects would be two divergent stores and
 * nothing would notice which one a reader saw.
 *
 * ## The SQL discipline mirrors `ControlDataObject`
 *
 * This is a deliberate sibling of `ControlDataObject`, not a subclass of it or
 * of `TenantDataObject`: {@link sqlStatements} splits migration files,
 * {@link connectionCounters} measures the `total_changes()` delta, every cursor
 * is drained in the same synchronous stretch that opened it, `transactionSync()`
 * is the only transaction, and the lazy migration runs under
 * `blockConcurrencyWhile` so no RPC observes a half-migrated database. A slim
 * class per store keeps each object honest about its own schema (the tenant
 * object's rollup alarms and `projects` witness are wrong here; the control
 * object's `api_key_directory` witness is wrong here too).
 *
 * ## The applier gates by NAME
 *
 * Copied from `ControlDataObject`: a `platform_schema_applied` ledger keyed by
 * migration NAME, applying every file whose name is not yet recorded, in
 * filename order, one transaction per file. The platform directory's `NNNN`
 * prefixes are unique today so a `MAX(version)` gate would also work, but the
 * name gate is strictly more general and matches the copied skeleton.
 *
 * ## RPC shape
 *
 * `query`/`batch` take the SAME request shapes as `TenantDataObject`
 * (`tenantId` carrying the fixed address `"platform"`), so the existing
 * `DurableObjectD1Database` facade works over this stub UNCHANGED. There is no
 * `fetch()` surface: every method is RPC over the binding.
 */
import { DurableObject } from "cloudflare:workers";
import { PLATFORM_MIGRATIONS, type PlatformMigration } from "./platform-schema-sql.js";
import {
  type TenantDataBatchRequest,
  type TenantDataQueryRequest,
  type TenantDataResult,
  type TenantDataStatement,
  type TenantDataValue,
  connectionCounters,
  sqlStatements,
} from "./tenant-data-object.js";

/** The single well-known address of the platform object. */
export const PLATFORM_DATA_ADDRESS = "platform";

/** Prefix on every refusal this object raises, so a caller can recognise one. */
const REFUSAL = "platform_data_object";

/**
 * The ledger-vs-reality witness. `guardrail_evaluations` is created by
 * `0001_guardrail_evaluations` and is the table this object exists to serve — a
 * ledger that claims 0001 applied while this table is absent is a corrupt
 * database, and the object refuses every query rather than serving it.
 */
const WITNESS_TABLE = "guardrail_evaluations";

/** Status RPC result — see {@link PlatformDataObject.schemaStatus}. */
export interface PlatformSchemaStatus {
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

export class PlatformDataObject extends DurableObject {
  readonly #state: DurableObjectState;
  #appliedThisWake: string[] = [];
  #failure: string | null = null;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx as never, env as never);
    this.#state = ctx;
    // Same lock discipline as the control/tenant objects: no RPC is delivered
    // until this settles, and a failure is RECORDED, not swallowed — every
    // later RPC refuses with the message instead of the object aborting
    // opaquely.
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
  protected migrations(): readonly PlatformMigration[] {
    return PLATFORM_MIGRATIONS;
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
   * Run N statements as ONE transaction — the property the parent/check
   * evidence pair relies on, and the property the D1 facade's `batch()`
   * promises. Exactly one result per submitted statement, in order.
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
   * Schema/health probe for deploy verification and cutover checks.
   *
   * Deliberately NOT gated on the recorded failure — this is the one RPC that
   * stays answerable on a broken object, so the operator reads which file the
   * apply stopped at instead of only the refusal. The address check still
   * applies: a mis-addressed probe is a caller bug even when broken.
   */
  async schemaStatus(request: { readonly tenantId: string }): Promise<PlatformSchemaStatus> {
    await this.#admitAddress(request.tenantId);
    let appliedCount = 0;
    try {
      const applied = this.#state.storage.sql
        .exec<{ n: number }>("SELECT COUNT(*) AS n FROM platform_schema_applied")
        .toArray();
      appliedCount = applied[0]?.n ?? 0;
    } catch {
      // A failure so early the ledger table never existed; 0 is the honest count.
    }
    return {
      address: PLATFORM_DATA_ADDRESS,
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
   * The correct address is knowable at compile time, so anything else is a
   * caller bug — most plausibly a seam that passed a TENANT id, which must
   * never be answered with platform data. The `typeof` check is not redundant
   * with the declared type: the value arrived over an RPC boundary as a
   * structured clone, and a guard does not take the caller's word for its input.
   *
   * `async` although nothing inside awaits: an RPC method that throws BEFORE
   * its first `await` throws synchronously into the RPC plumbing, which workerd
   * additionally reports as an uncaught exception in the object's context.
   * Refusing from inside the async machinery keeps a refusal a single, ordinary
   * rejection.
   */
  async #admit(address: string): Promise<void> {
    if (this.#failure !== null) {
      throw new Error(`${REFUSAL}: ${this.#failure}`);
    }
    await this.#admitAddress(address);
  }

  /** Same `async`-for-rejection-shape rationale as {@link #admit}. */
  async #admitAddress(address: string): Promise<void> {
    if (typeof address !== "string" || address !== PLATFORM_DATA_ADDRESS) {
      throw new Error(
        `${REFUSAL}: this object is the platform evidence store and answers only address "${PLATFORM_DATA_ADDRESS}"; it was addressed as "${String(address)}". A tenant id here means a routing seam leaked tenant traffic to platform storage.`,
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
   * discipline to `ControlDataObject.#exec` / `TenantDataObject.#exec`.
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
   * One transaction per FILE: the file's DDL and its `platform_schema_applied`
   * row commit or roll back together. The ledger table itself is created
   * OUTSIDE the gate and is idempotent; it exists before the first file runs so
   * the applied-set read below never races its own bootstrap.
   */
  #migrate(): void {
    this.#state.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS platform_schema_applied (" +
        "name TEXT PRIMARY KEY, " +
        "ordinal INTEGER NOT NULL, " +
        "applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch()))",
    );
    const applied = new Set(
      this.#state.storage.sql
        .exec<{ name: string }>("SELECT name FROM platform_schema_applied")
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
          this.#state.storage.sql.exec(
            "INSERT INTO platform_schema_applied (name, ordinal) VALUES (?, ?)",
            migration.name,
            migration.ordinal,
          );
        });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
          `platform schema migration stopped at ${migration.name} (ordinal ` +
            `${migration.ordinal} of ${this.migrations().length}); the platform database is ` +
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
          `platform schema ledger records ${applied.size} applied migrations but table`,
          `${WITNESS_TABLE} is absent; the ledger and the database disagree, so the`,
          "platform object is refusing every query rather than serving an incomplete schema",
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

/** The `[[durable_objects.bindings]]` namespace type for `env.PLATFORM_DATA`. */
export type PlatformDataNamespace = DurableObjectNamespace<PlatformDataObject>;
