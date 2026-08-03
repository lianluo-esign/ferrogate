/**
 * `TenantDataObject` — a SQLite-backed Durable Object that **is** one tenant's
 * database (issue #822, `docs/design/per-tenant-durable-object-storage-2026-08.md`).
 *
 * ## Why this exists instead of one D1 database per tenant
 *
 * The tenant data plane was specified as one D1 database per tenant and has
 * never been turned on. It cannot be: Cloudflare bindings resolve at DEPLOY
 * time, so `native_binding` makes signup a `wrangler deploy` and caps the
 * product at the ~5,000-binding-per-script ceiling, and the REST escape hatch
 * (`tenant-rest.ts`) has no transaction envelope, so it reports
 * `supportsAtomicBatch: false` and `requireAtomicBatch()` refuses all 13
 * money-path call sites. Choosing `rest` was choosing to scale by giving up the
 * ledger.
 *
 * A SQLite-backed Durable Object carries its own embedded database.
 * `env.TENANT_DATA.idFromName(tenantId)` addresses a tenant's database at
 * RUNTIME — unlimited instances, no deploy, 10 GB each — and
 * `ctx.storage.transactionSync()` is a real SQLite transaction that rolls back
 * on throw, which is exactly what the REST path could not offer.
 *
 * ## This is the fleet's FIRST `ctx.storage.sql` user — read this before editing
 *
 * The repo already ships eight `new_sqlite_classes` DO classes, but every one of
 * them uses the KEY-VALUE storage API (`ctx.storage.get/put/list`) on top of the
 * SQLite backend. `new_sqlite_classes` selects the storage BACKEND, not the SQL
 * API. So the wrangler discipline, the `src/worker.ts` re-export rule and the
 * test harness shape are all proven in-repo, and the SQL API is not. The
 * platform rules this file is written against, verified against Cloudflare's
 * docs on 2026-08-04 and re-verified empirically under this repo's workerd:
 *
 *  1. `ctx.storage.sql.exec(query, ...bindings)` is **synchronous** and returns
 *     a cursor. Bindings apply only to the LAST statement of a multi-statement
 *     string — which is why {@link sqlStatements} splits and the applier loops,
 *     rather than handing a whole file to one `exec()`.
 *  2. A cursor held across an `await` has no isolation guarantee: it may observe
 *     rows from a transaction that later rolls back. **Every cursor in this file
 *     is drained with `.toArray()` in the same synchronous stretch that opened
 *     it**, and no `await` appears inside any `transactionSync` callback.
 *  3. `exec()` cannot run `BEGIN`/`SAVEPOINT`. `transactionSync(cb)` is the only
 *     transaction, and `cb` must be non-async and must not return a Promise.
 *  4. `ctx.blockConcurrencyWhile(cb)` delivers no RPC until `cb` settles, which
 *     is how a request is kept from observing a half-migrated database.
 *
 * ## What this object deliberately does NOT do
 *
 * It exposes `query` / `batch` / `schemaVersion` and nothing else. The
 * `D1Database`-shaped facade that lets the 14 modules under `src/d1/` port
 * unchanged (`prepare().bind().first()/all()/run()`, `meta.changes`, the
 * `durable_object` `TenantDatabaseSource`) is a separate slice; this one
 * establishes the object, its schema and its isolation guard.
 *
 * There is no `fetch()` surface: every method is RPC over the binding, so the
 * object is not addressable from the internet.
 */
import { DurableObject } from "cloudflare:workers";
import {
  TENANT_MIGRATIONS,
  TENANT_SCHEMA_VERSION,
  type TenantMigration,
} from "./tenant-schema-sql.js";

/**
 * The value domain SQLite accepts and returns through `sql.exec`.
 *
 * Narrower than it looks and deliberately so: it excludes `boolean`, `bigint`
 * and `undefined`. The repo already normalizes at the edge — `boolToSqlite()`
 * and `bindOptional()` in `src/d1/rows.ts` — and credit columns that can exceed
 * 2^53 cross as decimal STRINGS via `bindCredits()` / `creditsFromText()`
 * (`src/credits.ts`), because `bind(<bigint>)` throws and the `number` form
 * drifts. Widening this type would quietly re-open that decode.
 */
export type TenantDataValue = ArrayBuffer | string | number | null;

/** One statement and its positional bindings, forwarded to `sql.exec` verbatim. */
export interface TenantDataStatement {
  readonly sql: string;
  /**
   * Bindings, forwarded UNCHANGED and in order.
   *
   * Never renumbered and never counted: `apps/gateway/src/assets/d1.ts` alone
   * uses 106 ordinal placeholders with REUSE (`?2` three times, `?9` and `?16`
   * twice in one statement), so any transform that derives arity by counting
   * `?` characters breaks a live money path.
   */
  readonly params?: readonly TenantDataValue[];
}

/** An RPC carrying the caller's tenant id — see {@link TenantDataObject.query}. */
export interface TenantDataQueryRequest extends TenantDataStatement {
  /** The tenant this caller believes it is addressing. Checked, not trusted. */
  readonly tenantId: string;
}

/** An RPC carrying the caller's tenant id — see {@link TenantDataObject.batch}. */
export interface TenantDataBatchRequest {
  readonly tenantId: string;
  readonly statements: readonly TenantDataStatement[];
}

/** One statement's outcome. Every field is structured-cloneable. */
export interface TenantDataResult {
  /**
   * The rows the statement produced, always a real array — `[]` for a write with
   * no `RETURNING`, never `undefined`. Seventeen call sites under `src/d1/`
   * index `.results` with no guard, so `undefined` there is a TypeError on a
   * money path rather than a missing row.
   */
  readonly results: Record<string, TenantDataValue>[];
  /**
   * Rows this statement inserted/updated/deleted — the `D1Result.meta.changes`
   * equivalent, and the ONLY meta field anything in this repo reads.
   *
   * It is measured as a `total_changes()` DELTA around the statement, not read
   * from `SqlStorageCursor`. The cursor exposes `rowsWritten`, which counts
   * INDEX row writes too, so a row touching three indexes reports 4. Five
   * `changes()` helpers in `src/d1/` treat `changes > 0` as "the guarded write
   * fired" — an overreported value publishes an unscanned asset
   * (`assets-d1.ts:418`), skips a schedule fire forever
   * (`agent-schedule-d1.ts:342`) and reports deletions that never happened
   * (`references-d1.ts`). `changes()` alone is also wrong here: it retains the
   * previous write's count across a SELECT, so a read would inherit it. The
   * delta is 0 for a read, which is what D1 reports.
   */
  readonly changes: number;
  /** Rows the statement read; billing-shaped diagnostics, nothing branches on it. */
  readonly rowsRead: number;
}

/** What {@link TenantDataObject.schemaVersion} answers. */
export interface TenantSchemaStatus {
  /** The tenant id this object adopted, or `null` before its first RPC. */
  readonly tenantId: string | null;
  /** Highest version in `storage_schema_migrations`; `0` on a virgin object. */
  readonly version: number;
  /** The version {@link TENANT_MIGRATIONS} would bring it to. */
  readonly latest: number;
  /**
   * Migration NAMES applied during THIS wake — empty on every wake after the
   * first, which is the observable form of "an already-current object does a
   * version read and nothing more". Asserting on this rather than on wall time
   * is what makes the no-rerun claim a real test instead of a timing guess.
   */
  readonly appliedThisWake: readonly string[];
  /** Set when the schema apply failed; every other RPC refuses while it is set. */
  readonly failure: string | null;
}

/** Storage key for the adopted tenant id. See {@link TenantDataObject.query}. */
const TENANT_ID_KEY = "tenant_data:tenant_id";

/**
 * A witness table from `0001_init_tenant.sql`, used to catch a ledger that
 * disagrees with the database it claims to describe. See `#assertLedgerHonest`.
 */
const WITNESS_TABLE = "projects";

/** Prefix on every refusal this object raises, so a caller can recognise one. */
const REFUSAL = "tenant_data_object";

/**
 * Split a migration file into single statements.
 *
 * A near-copy of the splitter in `apps/gateway/test/setup-d1.ts:70` (and its
 * four duplicates); it lives here rather than being imported because that one
 * is under a `test/` tree and this one ships. The reasoning is carried across
 * with it, because it is the only thing standing between this function and a
 * future trigger body:
 *
 *  * **Comment stripping must come first.** `0001_init_tenant.sql` has 18
 *    comment lines containing a `;` mid-prose; splitting before stripping cuts
 *    statements in half at those points.
 *  * The filter is line-granular after `trimStart()`, which is what makes it
 *    lossless over `0005_responses_conversations.sql` — that file indents `--`
 *    comments BETWEEN columns, and a filter anchored at column 0 would corrupt
 *    the table.
 *  * It is safe today because, measured over all seven files, every non-comment
 *    `;` is at end-of-line, there is no `;` inside any string literal in a live
 *    statement, and there are no trailing inline comments. **A migration that
 *    introduces a `CREATE TRIGGER`, or a `;` inside a quoted literal, breaks
 *    this** — such a migration must extend the splitter in the same commit.
 *
 * Splitting is mandatory, not stylistic: `sql.exec` applies bindings only to the
 * LAST statement of a multi-statement string, so handing a whole file to one
 * `exec()` would make the first parameterized backfill migration bind against
 * the wrong statement, silently. Splitting first makes that invariant free.
 */
export function sqlStatements(migration: string): string[] {
  return migration
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

/**
 * One tenant's database. Addressed `env.TENANT_DATA.idFromName(tenantId)`.
 *
 * Reachable only through the binding; there is no `fetch()`.
 */
export class TenantDataObject extends DurableObject {
  /**
   * `this.ctx` is typed as the base class's state; this is the same handle,
   * narrowed once so the SQL API is reachable without a cast at every use.
   */
  readonly #state: DurableObjectState;
  #tenantId: string | null = null;
  #appliedThisWake: string[] = [];
  #failure: string | null = null;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx as never, env as never);
    this.#state = ctx;
    // `blockConcurrencyWhile` is the lock, and it is the whole reason a request
    // cannot observe a half-migrated database: no RPC is delivered until this
    // settles. An EVICTED instance re-runs it on the next wake, so the version
    // gate inside `#migrate` is what keeps that from re-applying 62 statements
    // on every cold start of every tenant.
    ctx.blockConcurrencyWhile(async () => {
      this.#tenantId = (await ctx.storage.get<string>(TENANT_ID_KEY)) ?? null;
      try {
        this.#migrate();
      } catch (error) {
        // Caught, NOT swallowed. Throwing out of `blockConcurrencyWhile` aborts
        // the object, which fails closed but with an opaque error that names
        // neither the tenant nor the version. Recording it here and refusing
        // every RPC with the message below is the same refusal, legibly: the
        // operator is told which version the schema stopped at.
        this.#failure = error instanceof Error ? error.message : String(error);
      }
    });
  }

  /**
   * The migration set. Overridable so a test can drive a schema that FAILS —
   * a method rather than a field because subclass field initializers run after
   * `super()`, i.e. after the constructor has already migrated.
   */
  protected migrations(): readonly TenantMigration[] {
    return TENANT_MIGRATIONS;
  }

  /** The version {@link migrations} brings the database to. */
  protected latestVersion(): number {
    const list = this.migrations();
    return list[list.length - 1]?.version ?? TENANT_SCHEMA_VERSION;
  }

  // -------------------------------------------------------------------------
  // RPC surface
  // -------------------------------------------------------------------------

  /**
   * Run one statement.
   *
   * `tenantId` is the cross-tenant guard, not a routing hint: the object adopts
   * the FIRST id it is addressed with and refuses every later id that differs.
   * `idFromName` is one-way, so an object cannot derive its own tenant from its
   * id; without this, a resolver bug that computed the wrong name would silently
   * read and write another tenant's ledger, and every row would look correct
   * because the physical database really is the one the id named.
   */
  async query(request: TenantDataQueryRequest): Promise<TenantDataResult> {
    await this.#admit(request.tenantId);
    // One statement is still a transaction: `changes` is measured as a
    // `total_changes()` delta, and a delta straddling a commit boundary could
    // be polluted by another statement. `transactionSync` also gives a bare
    // `query()` the same rollback-on-throw semantics `batch()` has.
    return this.#state.storage.transactionSync(() => this.#exec(request));
  }

  /**
   * Run N statements as ONE transaction. This is the entire point of the object.
   *
   * Every statement runs inside a single `transactionSync`, so a throw anywhere
   * rolls back everything before it. That is what restores
   * `supportsAtomicBatch: true` to the 13 `requireAtomicBatch()` money paths
   * that the REST strategy had to refuse — the no-oversell wallet reserve, the
   * workflow-budget debit, the asset quota admission.
   *
   * Exactly one result per submitted statement, in order. `wallet-d1.ts:377`
   * and `billing-d1.ts:182` both check the length and refuse a short response,
   * because a short batch makes every settle look like a replay and nothing is
   * ever billed.
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
   * The schema state. Callable even while the object is refusing, because the
   * version it stopped at is the one thing an operator needs from a broken
   * tenant — and the only way to see it without a query path.
   */
  async schemaVersion(): Promise<TenantSchemaStatus> {
    return {
      tenantId: this.#tenantId,
      version: this.#appliedVersion(),
      latest: this.latestVersion(),
      appliedThisWake: [...this.#appliedThisWake],
      failure: this.#failure,
    };
  }

  // -------------------------------------------------------------------------
  // Admission
  // -------------------------------------------------------------------------

  /** Refuse a failed schema, a blank tenant id, or another tenant's id. */
  async #admit(tenantId: string): Promise<void> {
    if (this.#failure !== null) {
      throw new Error(`${REFUSAL}: ${this.#failure}`);
    }
    // Blank is refused rather than adopted. `middleware.ts:108` returns `""`
    // (never `null`) for an unclassified credential precisely so that it
    // matches nothing; adopting it here would turn the unforgeable id into a
    // shared object every unclassified caller lands in.
    //
    // The `typeof` arm is not redundant with the parameter type: this value
    // arrived over an RPC boundary as a structured clone, so the declared type
    // is the CALLER's promise, not a checked fact. A guard whose whole job is
    // to be unbypassable does not take a caller's word for its own input.
    if (typeof tenantId !== "string" || tenantId.trim() === "") {
      throw new Error(`${REFUSAL}: an RPC arrived with an empty tenant id; refusing`);
    }
    if (this.#tenantId === null) {
      // Adopt, under the lock. `blockConcurrencyWhile` is what stops two
      // concurrent first RPCs from each seeing `null` and adopting different
      // ids — the in-memory assignment alone would be safe only up to the
      // first `await`, and the `put` is one.
      await this.#state.blockConcurrencyWhile(async () => {
        if (this.#tenantId !== null) return;
        await this.#state.storage.put(TENANT_ID_KEY, tenantId);
        this.#tenantId = tenantId;
      });
    }
    if (this.#tenantId !== tenantId) {
      throw new Error(
        `${REFUSAL}: this object holds tenant ${this.#tenantId} and was addressed as ` +
          `${tenantId}; refusing rather than serving one tenant's data to another`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Execution
  // -------------------------------------------------------------------------

  /**
   * Run one statement and materialize its result.
   *
   * SYNCHRONOUS and called only from inside a `transactionSync` callback, which
   * is what makes the cursor drain safe: `.toArray()` happens in the same
   * synchronous stretch as the `exec()`, so no cursor is ever held across an
   * `await` where it could observe rows a rollback later removes.
   */
  #exec(statement: TenantDataStatement): TenantDataResult {
    const sql = this.#state.storage.sql;
    const before = totalChanges(sql);
    const cursor = sql.exec<Record<string, TenantDataValue>>(
      statement.sql,
      ...(statement.params ?? []),
    );
    // Drained BEFORE `rowsRead` is read: the cursor's counters are only final
    // once it has been consumed.
    const results = cursor.toArray();
    const rowsRead = cursor.rowsRead;
    return { results, changes: totalChanges(sql) - before, rowsRead };
  }

  // -------------------------------------------------------------------------
  // Schema migration
  // -------------------------------------------------------------------------

  /**
   * Bring the database to {@link latestVersion}. Synchronous throughout.
   *
   * The version gate is the first thing that happens, because this runs on every
   * cold start of every tenant object: an already-current tenant pays one
   * `sqlite_master` probe and one `MAX(version)` read and returns, instead of
   * re-running 22 `CREATE TABLE IF NOT EXISTS` and 26 `CREATE INDEX`.
   */
  #migrate(): void {
    const applied = this.#appliedVersion();
    this.#assertLedgerHonest(applied);
    const pending = this.migrations().filter((migration) => migration.version > applied);
    if (pending.length === 0) return;

    for (const migration of pending) {
      try {
        // ONE transaction per FILE: the file's DDL and the ledger row that
        // records it commit or roll back together. That is strictly stronger
        // than what `wrangler d1 migrations apply` gives a D1 tenant, and it is
        // what makes the four ALTER-only migrations safe to gate on the version
        // number alone — SQLite has no `ADD COLUMN IF NOT EXISTS`, so a second
        // apply throws `duplicate column name`, and the only way that can
        // happen here is a ledger row that committed without its DDL, which
        // this transaction makes impossible.
        //
        // Note what is deliberately NOT done: `apps/gateway/test/setup-d1.ts`
        // wraps its ALTERs in a catch that swallows `duplicate column name`.
        // Copying that here would be a bug, not a convenience — inside a
        // transaction, catch-and-continue is exactly how a real error becomes a
        // half-applied schema that reports success.
        this.#state.storage.transactionSync(() => {
          for (const statement of sqlStatements(migration.sql)) {
            this.#state.storage.sql.exec(statement);
          }
          // Recorded LAST and inside the same transaction. `0001` already ends
          // with its own `INSERT OR IGNORE … VALUES (1, '0001_init_tenant')`;
          // `INSERT OR IGNORE` here makes this a no-op for that file rather
          // than a PRIMARY KEY conflict, and supplies the rows for 0002..0007,
          // which record nothing of their own. In D1 that ledger is vestigial
          // (only version 1 is ever written, and `wrangler`'s own
          // `d1_migrations` table does the real bookkeeping); inside a DO there
          // is no wrangler and no `d1_migrations`, so this IS the ledger.
          this.#state.storage.sql.exec(
            "INSERT OR IGNORE INTO storage_schema_migrations (version, name) VALUES (?, ?)",
            migration.version,
            migration.name,
          );
        });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
          `schema migration stopped at version ${migration.version} (${migration.name}); ` +
            `the database is still at version ${this.#appliedVersion()} and this tenant is ` +
            `refusing every query. cause: ${detail}`,
        );
      }
      this.#appliedThisWake.push(migration.name);
    }
  }

  /** Highest recorded version; `0` when the ledger table does not exist yet. */
  #appliedVersion(): number {
    if (!this.#tableExists("storage_schema_migrations")) return 0;
    const rows = this.#state.storage.sql
      .exec<{ version: number | null }>(
        "SELECT MAX(version) AS version FROM storage_schema_migrations",
      )
      .toArray();
    const version = rows[0]?.version;
    return typeof version === "number" ? version : 0;
  }

  /**
   * Refuse a ledger that claims a schema the database does not have.
   *
   * The version row says what the applier BELIEVES; `sqlite_master` says what
   * the database IS. They can only disagree if a ledger row committed without
   * its DDL, which the per-file transaction above is designed to prevent — so
   * this check should never fire. It is here because the consequence of
   * proceeding on a disagreement is a tenant serving queries against a schema
   * that is missing tables, and failing closed on an impossible state costs one
   * `sqlite_master` probe per cold start.
   */
  #assertLedgerHonest(applied: number): void {
    if (applied >= 1 && !this.#tableExists(WITNESS_TABLE)) {
      throw new Error(
        [
          `schema ledger claims version ${applied} but table ${WITNESS_TABLE} is absent;`,
          "the migration ledger and the database disagree, so this tenant is refusing",
          "every query rather than serving an incomplete schema",
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

/**
 * `total_changes()` — rows changed on this connection since it opened.
 *
 * A free function so both reads in `#exec` are provably the same query; the
 * cursor is drained immediately, in the caller's synchronous stretch.
 */
function totalChanges(sql: SqlStorage): number {
  const rows = sql.exec<{ n: number }>("SELECT total_changes() AS n").toArray();
  return rows[0]?.n ?? 0;
}

/** The `[[durable_objects.bindings]]` namespace type for `env.TENANT_DATA`. */
export type TenantDataNamespace = DurableObjectNamespace<TenantDataObject>;
