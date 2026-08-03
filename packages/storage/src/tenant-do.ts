/**
 * The **Durable Object** leg of the tenant router — strategy `durable_object` of
 * {@link D1_BINDING_STRATEGIES}, and the one that is both deploy-free and
 * money-safe (issue #823,
 * `docs/design/per-tenant-durable-object-storage-2026-08.md`).
 *
 * ## Why this is a FACADE and not a port
 *
 * There are ~362 `.prepare(` call sites in this repo and eight tenant-plane
 * modules under `./d1/` written against `D1Database`. Every one of them is a
 * money path or feeds one: the wallet no-oversell reserve, the workflow-budget
 * CAS, the asset quota admission, the at-most-once schedule fire. Porting them
 * by hand to a new client would be a rewrite of every guard with no mechanical
 * guarantee that the semantics survived — and the semantics are the product.
 *
 * So `TenantDataObject` is dressed as a `D1Database` instead, and the acceptance
 * test is not "the facade looks right" but "`test/d1/**` passes against it with
 * NO CHANGE to any module under `./d1/`". If a module needs editing, the facade
 * is wrong.
 *
 * ## What "faithful" has to mean, concretely
 *
 * These are not stylistic choices. Each one is a specific silent-corruption bug
 * that the obvious implementation would introduce, with the call site that would
 * suffer it:
 *
 *  1. **`first()` returns `null`, never `undefined`.** `wallet-d1.ts:282` reads
 *     `row === null ? undefined : creditsFromText(row.credits)` — the exact
 *     balance read — and `wallet-d1.ts:753` is `settleWalletBalance`'s replay
 *     guard. `undefined` there does not fall into the ternary's null arm; it
 *     falls through and dereferences `row.credits` on a missing row. Roughly 55
 *     other sites compare `=== null`.
 *  2. **`bind()` returns a NEW statement and mutates nothing.** Five sites
 *     (`requestlog/d1.ts:162`, `requestlog/queue.ts:119`,
 *     `guardrails/evidence-retention.ts:113`, …) hoist ONE `prepare()` and bind
 *     it N times into one `batch()`. A facade that stored params on the
 *     statement would collapse every record in the batch to the last binding —
 *     silent data loss in the request log, with a green test suite.
 *  3. **`meta.changes` is a `total_changes()` DELTA, not `rowsWritten`.** The
 *     cursor's `rowsWritten` counts INDEX writes, so one row in a
 *     three-index table reports 4. Five `changes()` helpers under `./d1/` read
 *     `changes > 0` as "the guarded write fired": overreporting publishes an
 *     unscanned asset (`assets-d1.ts:418`), skips a schedule fire forever
 *     (`agent-schedule-d1.ts:342`) and reports deletions that never happened
 *     (`references-d1.ts`). The delta is computed inside the object; see
 *     `TenantDataResult.changes`.
 *  4. **`meta` is always present.** Six call sites read `result.meta.changes`
 *     with no `?.`.
 *  5. **`batch()` returns exactly one result per submitted statement, in
 *     order.** `wallet-d1.ts:377` and `billing-d1.ts:182` refuse a short array;
 *     seven sites under `./d1/` index it unguarded and would throw a TypeError.
 *  6. **`results` is always a real array**, `[]` for a write with no
 *     `RETURNING`.
 *
 * ## Fields that cannot be produced are THROWN, not zero-filled
 *
 * `D1Meta` declares seven non-optional fields. Six of them have an honest
 * source inside the object ({@link TenantDataResult}); `duration` does not, and
 * reading it throws rather than reporting a fabricated `0`. See
 * {@link toD1Result} for the per-field derivation and why a placeholder there
 * would be worse than an error.
 *
 * ## ONE round trip per `batch()`
 *
 * The whole statement array crosses the stub boundary once and runs inside one
 * `ctx.storage.transactionSync()`. Issuing N sequential stub calls would be the
 * `rest` strategy with extra steps: it would cost N hops AND lose the
 * transaction, which is the single thing this topology exists to restore.
 */
import { StorageError } from "./errors.js";
import type {
  TenantDataBatchRequest,
  TenantDataQueryRequest,
  TenantDataResult,
  TenantDataStatement,
  TenantDataValue,
} from "./tenant-data-object.js";
import {
  ControlDatabaseTenantRegistry,
  type TenantDatabaseHandle,
  type TenantDatabaseRegistration,
  type TenantDatabaseRouter,
} from "./tenant-router.js";

// ---------------------------------------------------------------------------
// The stub seam
// ---------------------------------------------------------------------------

/**
 * The two RPCs this facade calls on a `TenantDataObject` stub.
 *
 * Declared structurally rather than as `DurableObjectStub<TenantDataObject>`
 * because THIS module must stay importable from plain node: `src/index.ts` is
 * pulled in by ten node-only vitest suites and by `apps/cli`, and
 * `tenant-data-object.ts` imports `DurableObject` from `cloudflare:workers`,
 * which resolves in workerd and nowhere else. Every reference to that module
 * here is `import type`, so it is erased at compile time and this file carries
 * no runtime dependency on the Worker runtime.
 */
export interface TenantDataStub {
  query(request: TenantDataQueryRequest): Promise<TenantDataResult>;
  batch(request: TenantDataBatchRequest): Promise<TenantDataResult[]>;
}

/**
 * The `env.TENANT_DATA` namespace, structurally.
 *
 * `idFromName` is the whole addressing story: it is a pure function of the
 * string, so a tenant's object exists the moment it is named — no deploy, no
 * provisioning call, no binding budget. It is also ONE-WAY, which is why
 * {@link TenantDataObject} re-checks the tenant id it is handed rather than
 * deriving it from its own id.
 */
export interface TenantDataNamespaceLike {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): TenantDataStub;
}

// ---------------------------------------------------------------------------
// Parameter marshalling
// ---------------------------------------------------------------------------

/**
 * Coerce one bound value to the SQLite value domain, or refuse it by name.
 *
 * The refusals are the point. Each rejected type has a specific correct
 * spelling already present in this package, and silently coercing it here would
 * hide a bug that D1 currently surfaces:
 *
 *  * **`bigint`** — `bind(<bigint>)` throws `D1_TYPE_ERROR` on D1 too. Credit
 *    columns exceed 2^53 (1 credit = 1 micro-USD, so a $10 B balance is 10^16),
 *    and the repo's answer is `bindCredits()` in `./credits.ts`: a decimal
 *    STRING, range-checked against int64, which SQLite's INTEGER affinity
 *    stores exactly. Accepting a `bigint` here by calling `Number()` on it
 *    would round the balance and the rounding would be invisible.
 *  * **`boolean`** — SQLite has no BOOLEAN; the schema stores `0`/`1` and
 *    `boolToSqlite()` in `./d1/rows.ts` is the writer. Coercing here would let
 *    a column drift between `1` and `true` depending on which path wrote it,
 *    and `boolFromSqlite()` accepts both, so nothing would ever notice.
 *  * **`undefined`** — a nullable column is bound `null` via `bindOptional()`.
 *    An `undefined` reaching a bind is an unset variable, not an intentional
 *    NULL, and turning it into NULL here writes the bug to disk.
 *
 * `ArrayBufferView` IS accepted and unwrapped, because that is what a caller
 * holding a `Uint8Array` has. No column in `sql/d1-ts/tenant/` is a BLOB today
 * (grep: zero hits), so this path is unexercised by the current schema and is
 * carried so that the first BLOB column is not also the first bug.
 */
function toTenantDataValue(value: unknown, index: number, sql: string): TenantDataValue {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
      return value;
    case "number":
      return value;
    case "bigint":
      throw StorageError.runtime(
        [
          `parameter ${index + 1} of [${sql}] is a bigint, which SQLite bindings do not accept`,
          "(D1 throws D1_TYPE_ERROR for the same value). Credit columns cross as decimal",
          "STRINGS via bindCredits() in src/credits.ts, which is exact above 2^53; converting",
          "here would silently round the balance.",
        ].join(" "),
      );
    case "boolean":
      throw StorageError.runtime(
        [
          `parameter ${index + 1} of [${sql}] is a boolean; SQLite has no BOOLEAN type and this`,
          "schema stores 0/1. Use boolToSqlite() from src/d1/rows.ts so one column cannot hold",
          "both spellings depending on which path wrote it.",
        ].join(" "),
      );
    case "undefined":
      throw StorageError.runtime(
        [
          `parameter ${index + 1} of [${sql}] is undefined. A nullable column is bound null via`,
          "bindOptional() from src/d1/rows.ts; an undefined reaching a bind is an unset variable,",
          "and turning it into NULL here would write the bug to disk.",
        ].join(" "),
      );
    default:
      break;
  }
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    // Copy out of the view's window rather than handing over the whole backing
    // buffer: a `Uint8Array` may be a slice, and passing `.buffer` would bind
    // bytes the caller never selected.
    const view = value as ArrayBufferView;
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
  }
  throw StorageError.runtime(
    `parameter ${index + 1} of [${sql}] has unsupported type ${Object.prototype.toString.call(
      value,
    )}; SQLite accepts null, number, string and ArrayBuffer only`,
  );
}

/** Marshal a whole `bind(...)` argument list. Order is never changed. */
function toTenantDataValues(values: readonly unknown[], sql: string): TenantDataValue[] {
  return values.map((value, index) => toTenantDataValue(value, index, sql));
}

// ---------------------------------------------------------------------------
// Result shaping
// ---------------------------------------------------------------------------

/**
 * The `duration` refusal, extracted so the message is identical on every result
 * and so a reader looking for "why did meta.duration throw" finds the reason in
 * one place.
 */
function durationRefusal(): StorageError {
  return StorageError.runtime(
    [
      "D1Result.meta.duration is not available over a tenant Durable Object and this facade",
      "refuses to fabricate it. Inside ctx.storage.transactionSync() the callback is",
      "synchronous and the Durable Object clock does not advance, so every statement would",
      "report 0 ms — a number that looks measured and is not. The honest alternatives are the",
      "stub round-trip time, which is not what D1's duration means, or this error. Nothing in",
      "this repo reads the field (grep: zero non-test hits); if something needs it, measure the",
      "round trip at the call site where the clock is real.",
    ].join(" "),
  );
}

/**
 * Shape one {@link TenantDataResult} as a `D1Result`, field by field.
 *
 * The derivation of every `D1Meta` field, since "walk the inventory and prove
 * each entry" is the acceptance criterion for this function:
 *
 * | field | source | why it is honest |
 * |---|---|---|
 * | `changes` | `total_changes()` delta around the statement | the CAS signal; see the file docblock |
 * | `rows_read` | `cursor.rowsRead` | the cursor's own counter, drained first |
 * | `rows_written` | `cursor.rowsWritten` | includes index writes, as D1's does |
 * | `last_row_id` | `last_insert_rowid()` after the statement | a connection property on both backends |
 * | `size_after` | `ctx.storage.sql.databaseSize` | real bytes; the 10 GB ceiling is per object |
 * | `changed_db` | `changes > 0 \|\| rows_written > 0` | see below |
 * | `duration` | **throws** | {@link durationRefusal} |
 *
 * `changed_db` under-reports exactly one case: pure DDL, which changes the
 * schema while `total_changes()` and `rowsWritten` both stay 0. That case cannot
 * arrive here — the object owns its own schema and applies it in `#migrate`,
 * and everything reaching this facade is DML from `./d1/`. It is stated rather
 * than hidden because the day someone runs DDL through `prepare()` is the day
 * this comment is the bug report.
 *
 * `duration` is defined as a NON-ENUMERABLE getter. That is deliberate: a
 * direct `meta.duration` read — the only way a caller can actually believe the
 * number — throws, while `{...meta}`, `JSON.stringify(result)` and a test's
 * `toEqual` do not detonate on a field nobody asked for. An enumerable throwing
 * getter would turn every incidental log line into an outage.
 */
export function toD1Result<T = Record<string, unknown>>(result: TenantDataResult): D1Result<T> {
  const meta = {
    changes: result.changes,
    rows_read: result.rowsRead,
    rows_written: result.rowsWritten,
    last_row_id: result.lastRowId,
    size_after: result.databaseSize,
    changed_db: result.changes > 0 || result.rowsWritten > 0,
  };
  Object.defineProperty(meta, "duration", {
    enumerable: false,
    configurable: true,
    get(): number {
      throw durationRefusal();
    },
  });
  return {
    // `success` is `true` unconditionally and that is not a shortcut: a
    // statement that failed threw out of `sql.exec` inside the object's
    // `transactionSync`, rolled the transaction back and rejected the RPC, so
    // there is no path that reaches here with a failed statement. D1 reports
    // the same `true`-or-throw shape, which is why nothing in this repo
    // branches on `.success` (grep: all 43 hits are Zod or the CF envelope).
    success: true,
    meta: meta as D1Meta & Record<string, unknown>,
    results: result.results as unknown as T[],
  };
}

// ---------------------------------------------------------------------------
// The prepared statement
// ---------------------------------------------------------------------------

/**
 * One prepared statement over a tenant Durable Object.
 *
 * Deliberately NOT `implements D1PreparedStatement`, for the same reason
 * {@link D1RestPreparedStatement} is not: `D1PreparedStatement` is an ambient
 * ABSTRACT CLASS with overloaded `first`/`raw` signatures only workerd can
 * supply, so a hand-written class cannot satisfy it nominally. The structural
 * cast lives in {@link DurableObjectD1Database.prepare}, once, where it is
 * visible.
 *
 * **Immutable.** `bind()` returns a new instance; `#params` is never
 * reassigned. See point 2 of the file docblock for the five call sites that
 * depend on it and the request-log data loss that would follow.
 */
export class DurableObjectD1PreparedStatement {
  readonly #sql: string;
  readonly #params: readonly TenantDataValue[];
  readonly #database: DurableObjectD1Database;
  readonly #tenantId: string;

  constructor(sql: string, params: readonly TenantDataValue[], database: DurableObjectD1Database) {
    this.#sql = sql;
    this.#params = params;
    this.#database = database;
    // Captured as a VALUE at prepare time rather than read back off
    // `#database` in `batch()`. `test/d1/usage-d1.test.ts` proxies `handle.db`
    // to count the statements in a batch — a legitimate spy that real D1
    // tolerates — and a `Proxy` forwards property reads with itself as the
    // receiver, so anything that reached through the owner would evaluate a
    // private field against the proxy and throw
    // `Cannot read private member from an object whose class did not declare
    // it`. A facade that only works when nobody is watching is not a facade.
    this.#tenantId = database.tenantId;
  }

  /**
   * The statement as the object's RPC wants it. Internal, but public on the
   * class because {@link DurableObjectD1Database.batch} reads it off statements
   * it did not construct.
   */
  plan(): TenantDataStatement {
    return { sql: this.#sql, params: this.#params };
  }

  /** Which tenant's object this statement was prepared against — the batch guard. */
  tenantId(): string {
    return this.#tenantId;
  }

  bind(...values: unknown[]): DurableObjectD1PreparedStatement {
    return new DurableObjectD1PreparedStatement(
      this.#sql,
      // Marshalled at BIND time, not at execution time, so a type error is
      // raised where the bad value was supplied. D1 does the same — its
      // `D1_TYPE_ERROR` comes out of `bind()`.
      toTenantDataValues(values, this.#sql),
      this.#database,
    );
  }

  /**
   * The first row, or `null`.
   *
   * `null` and not `undefined`: point 1 of the file docblock. The `colName`
   * overload exists because `D1PreparedStatement` declares it; nothing in this
   * repo uses it (grep for `.first("` / `.first('`: zero hits), and a missing
   * column throws rather than reporting `null`, because `null` there is
   * indistinguishable from a NULL cell.
   */
  async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
    const result = await this.#database.runStatement(this.plan());
    const row = result.results[0];
    if (row === undefined) return null;
    if (colName === undefined) return row as unknown as T;
    if (!(colName in row)) {
      throw StorageError.runtime(
        `first("${colName}") on [${this.#sql}] but the row has no such column; ` +
          `columns are [${Object.keys(row).join(", ")}]`,
      );
    }
    return row[colName] as unknown as T;
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return toD1Result<T>(await this.#database.runStatement(this.plan()));
  }

  /**
   * Identical to {@link all} — and that is D1's shape too, not a shortcut.
   * `run()` returns a full `D1Result`, so a write with a `RETURNING` clause
   * carries its rows here as well as through `all()`/`first()`. Eighteen sites
   * assign a `run()` result and every one reads only `meta.changes`, but three
   * families of `RETURNING` read (`.first()`, `.all().results`,
   * `batch()[i].results`) all have to surface the same rows or the wallet
   * settle path reads a replay as a fresh claim.
   */
  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.all<T>();
  }

  async raw<T = unknown[]>(options?: { columnNames?: boolean }): Promise<T[] | [string[], ...T[]]> {
    const result = await this.#database.runStatement(this.plan());
    const rows = result.results;
    const columns = rows.length === 0 ? [] : Object.keys(rows[0] as Record<string, unknown>);
    const values = rows.map((row) => columns.map((column) => row[column]) as unknown as T);
    return options?.columnNames === true ? [columns, ...values] : values;
  }
}

// ---------------------------------------------------------------------------
// The database
// ---------------------------------------------------------------------------

/**
 * A `D1Database`-shaped view of ONE tenant's Durable Object.
 *
 * Holds the stub, not the namespace: the object is chosen once, by
 * {@link DurableObjectTenantDatabaseRouter}, and a database handle that could
 * re-address itself would be a database handle that could address the wrong
 * tenant.
 */
export class DurableObjectD1Database {
  readonly #tenantId: string;
  readonly #stub: TenantDataStub;

  /**
   * The tenant whose object this is. Sent with every RPC and re-checked there.
   *
   * A plain readonly DATA property, not a getter: a getter is invoked with
   * whatever receiver read it, so reading it through a `Proxy` wrapper would
   * evaluate `this.#tenantId` against the proxy and throw. See the constructor
   * for the spy this facade has to survive.
   *
   * It duplicates `#tenantId`, and the duplication is load-bearing rather than
   * sloppy. `readonly` is erased at runtime, so this field is the PUBLIC label a
   * statement captures at prepare time, while `#tenantId` is the private
   * authority for what is actually SENT and what `batch()` compares against.
   * Overwriting the public one therefore makes a statement disagree with the
   * database that will submit it, and `batch()` refuses — a fail-closed
   * outcome, rather than a facade that can be talked into addressing another
   * tenant by assigning one field.
   */
  readonly tenantId: string;

  constructor(tenantId: string, stub: TenantDataStub) {
    this.#tenantId = tenantId;
    this.#stub = stub;
    this.tenantId = tenantId;
    // EVERY method is bound to this instance, and that is a correctness
    // requirement rather than a style. `test/d1/usage-d1.test.ts` wraps
    // `handle.db` in a `Proxy` whose `get` trap returns
    // `Reflect.get(target, property, receiver)` — a spy that real D1 tolerates,
    // because a native binding keeps its state in an internal slot addressed by
    // the object it was called on. This class keeps its state in `#`-private
    // fields, which are keyed on the RECEIVER: an unbound method invoked
    // through the proxy would see `this === proxy` and throw
    // `Cannot read private member #stub from an object whose class did not
    // declare it`. Binding here makes the surface behave like a bag of
    // closures, which is what a caller wrapping, destructuring or forwarding
    // this object already assumes.
    this.prepare = this.prepare.bind(this);
    this.batch = this.batch.bind(this);
    this.runStatement = this.runStatement.bind(this);
    this.exec = this.exec.bind(this);
    this.dump = this.dump.bind(this);
    this.withSession = this.withSession.bind(this);
    this.asD1Database = this.asD1Database.bind(this);
  }

  /**
   * The structural cast to `D1Database`. One place, deliberately — see the note
   * on {@link DurableObjectD1PreparedStatement}.
   */
  asD1Database(): D1Database {
    return this as unknown as D1Database;
  }

  prepare(query: string): D1PreparedStatement {
    return new DurableObjectD1PreparedStatement(query, [], this) as unknown as D1PreparedStatement;
  }

  /** One statement, one stub hop. Used by every statement method. */
  async runStatement(statement: TenantDataStatement): Promise<TenantDataResult> {
    // `tenantId` LAST, so no future field on `TenantDataStatement` can shadow
    // the cross-tenant guard by being named `tenantId`. The object re-checks it
    // either way; this keeps the facade from being the thing that lies to it.
    return this.#stub.query({ ...statement, tenantId: this.#tenantId });
  }

  /**
   * N statements, ONE transaction, ONE round trip.
   *
   * The whole array is marshalled and crosses the stub boundary once;
   * `TenantDataObject.batch()` runs it inside a single
   * `ctx.storage.transactionSync()`, so a throw at statement 3 rolls back 1 and
   * 2. That is what restores `supportsAtomicBatch: true` to the 13
   * `requireAtomicBatch()` money paths the REST strategy had to refuse.
   *
   * Two refusals, both fail-closed:
   *
   *  * a statement this database did not prepare — including one prepared
   *    against the CONTROL database or another tenant's object. D1 refuses a
   *    cross-database batch too, and here the consequence is worse: the object
   *    would run another tenant's SQL against this tenant's data with every row
   *    looking correct.
   *  * a short result array. The object promises one result per statement, in
   *    order; `wallet-d1.ts:377` and `billing-d1.ts:182` already check, but
   *    seven sites under `./d1/` index it unguarded, so the check belongs here
   *    where it covers all of them.
   *
   * An EMPTY batch is passed through rather than short-circuited. `batch([])`
   * on D1 is a legal no-op returning `[]`, and short-circuiting would mean the
   * facade answered a question the object never saw — including the tenant
   * admission check.
   */
  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    const plans: TenantDataStatement[] = statements.map((statement, index) => {
      const candidate = statement as unknown;
      if (!(candidate instanceof DurableObjectD1PreparedStatement)) {
        throw StorageError.runtime(
          [
            `batch() statement ${index + 1} for tenant ${this.#tenantId} was not prepared against`,
            "this tenant's Durable Object. A batch is one transaction inside ONE object, so a",
            "statement from another database cannot join it; refusing rather than running one",
            "tenant's SQL against another's data.",
          ].join(" "),
        );
      }
      if (candidate.tenantId() !== this.#tenantId) {
        throw StorageError.runtime(
          [
            `batch() statement ${index + 1} was prepared against tenant`,
            `${candidate.tenantId()}'s Durable Object but submitted to tenant`,
            `${this.#tenantId}'s; refusing.`,
          ].join(" "),
        );
      }
      return candidate.plan();
    });
    const results = await this.#stub.batch({ tenantId: this.#tenantId, statements: plans });
    if (results.length !== plans.length) {
      throw StorageError.runtime(
        [
          `tenant ${this.#tenantId} Durable Object returned ${results.length} results for`,
          `${plans.length} batched statements. Callers index this array positionally, so a`,
          "misaligned batch reads one statement's rows as another's — refusing.",
        ].join(" "),
      );
    }
    return results.map((result) => toD1Result<T>(result));
  }

  /**
   * REFUSED. `D1Database.exec()` splits its argument on NEWLINES and returns
   * only a statement count and a duration — a shape this facade cannot reproduce
   * (it has no duration; see {@link toD1Result}) and one nothing in this repo
   * calls (grep: zero non-test hits, and the sole `D1ExecResult` mention is the
   * matching refusal in `./tenant-rest.ts`). Splitting SQL on newlines is also
   * exactly the mistake `sqlStatements()` in `./tenant-data-object.ts` documents
   * at length, and re-implementing it here would give the repo a second,
   * weaker splitter.
   */
  exec(_query: string): Promise<D1ExecResult> {
    return Promise.reject(
      StorageError.runtime(
        [
          `tenant ${this.#tenantId} Durable Object does not expose exec(): it splits on newlines,`,
          "reports a duration this facade cannot measure, and nothing in this repo calls it.",
          "Use prepare().run(), or batch() if the statements must be one transaction.",
        ].join(" "),
      ),
    );
  }

  /** REFUSED. There is no D1 snapshot of a Durable Object's SQLite file. */
  dump(): Promise<ArrayBuffer> {
    return Promise.reject(
      StorageError.runtime(
        `tenant ${this.#tenantId} Durable Object does not expose dump(); it is not a D1 database`,
      ),
    );
  }

  /**
   * REFUSED. D1 Sessions exist to pin reads to a replica consistent with a
   * bookmark. A Durable Object is a SINGLE instance with single-threaded
   * execution — there is no replica to be inconsistent with, so a session would
   * be a no-op wearing the name of a consistency guarantee.
   */
  withSession(): never {
    throw StorageError.runtime(
      [
        `tenant ${this.#tenantId} Durable Object does not expose D1 Sessions: an object is a`,
        "single instance, so sequential consistency is unconditional rather than something a",
        "session buys.",
      ].join(" "),
    );
  }
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

export interface DurableObjectTenantRouterOptions {
  /**
   * How long a resolved registration is cached in-isolate, in ms. Default
   * 30_000, `0` disables — the same knob and the same default as
   * {@link EnvBindingTenantRouterOptions}, because it answers the same question.
   *
   * What is cached is the control-registry ROW, never the stub: a stub is a
   * cheap local handle to an object addressed by a pure function of the tenant
   * id, so there is nothing stale about it, while a registration can be created
   * or revoked under a live isolate.
   */
  registrationTtlMs?: number;
}

/**
 * Routes tenants to their Durable Objects — the deploy-free, money-safe leg.
 *
 * ## Why a control-registry lookup survives, when `idFromName` needs none
 *
 * `idFromName` resolves EVERY string. That is the feature (no provisioning
 * round trip) and it is also the hazard: a typo, an unauthenticated id, or a
 * caller that lost its tenant would each address a real, empty, valid object
 * and start writing a ledger into it. Nothing would error, and the tenant would
 * exist. So this router keeps the `tenant_databases` row as the EXISTENCE GATE:
 * an unregistered tenant is `StorageError.notFound`, exactly as under
 * {@link EnvBindingTenantDatabaseRouter}, and there is still no default
 * database anywhere in this module.
 *
 * The registry is also the only way to answer {@link provisionedTenants}. A
 * Durable Object namespace CANNOT be enumerated in production —
 * `listDurableObjectIds` is a `cloudflare:test` helper — and
 * `apps/control-plane/src/store/asset_fleet.ts:330` fans out over that list to
 * serve the fleet asset views. Returning `[]` would report an empty fleet:
 * green, and wrong.
 *
 * ## What the registry row means here, and what it no longer means
 *
 * `binding_name` is IGNORED, and a row without one resolves. Under
 * `native_binding` an absent binding is the "provisioned but not yet
 * redeployed" refusal — the tenant's database exists in the account but the
 * Worker has not been redeployed with its stanza. There is no such state here:
 * one `[[durable_objects.bindings]]` entry serves every tenant that will ever
 * exist, so there is nothing to redeploy and nothing to be missing. That
 * difference IS the architectural change; `test/d1/router.test.ts` pins the
 * refusal for the binding router and `test/do/tenant-do-facade.test.ts` pins
 * the acceptance for this one, so neither can drift into the other by accident.
 *
 * `database_uuid` and `schema_version` are likewise not carried onto the
 * handle: there is no D1 database and therefore no uuid, and the schema version
 * lives in the object's own `storage_schema_migrations` ledger, which the
 * object applies for itself on every cold start. A `schemaVersion` copied off a
 * control-plane row would be a second source of truth that no writer updates.
 */
export class DurableObjectTenantDatabaseRouter implements TenantDatabaseRouter {
  readonly #namespace: TenantDataNamespaceLike;
  readonly #controlDb: D1Database;
  readonly #registry: ControlDatabaseTenantRegistry;
  readonly #ttlMs: number;
  readonly #cache = new Map<string, { at: number; value: TenantDatabaseRegistration }>();

  constructor(
    namespace: TenantDataNamespaceLike,
    controlDb: D1Database,
    options: DurableObjectTenantRouterOptions = {},
  ) {
    this.#namespace = namespace;
    this.#controlDb = controlDb;
    this.#registry = new ControlDatabaseTenantRegistry(controlDb);
    this.#ttlMs = options.registrationTtlMs ?? 30_000;
  }

  /** The account-global CONTROL database. Still D1, and deliberately so. */
  control(): D1Database {
    return this.#controlDb;
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    if (tenantId === "") {
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    const registration = await this.#registration(tenantId);
    if (!registration) {
      throw StorageError.notFound(
        `tenant ${tenantId} has no provisioned database in the control registry`,
      );
    }
    return {
      tenantId,
      db: this.databaseFor(tenantId),
      source: "durable_object",
      // THE claim of this slice. It is true because `TenantDataObject.batch()`
      // runs the statement array inside one `ctx.storage.transactionSync()`,
      // and it is proved by a rolled-back mid-batch failure in
      // `test/do/tenant-do-facade.test.ts` — not asserted because the strategy
      // table says so.
      supportsAtomicBatch: true,
    };
  }

  async provisionedTenants(): Promise<readonly string[]> {
    return (await this.#registry.list()).map((row) => row.tenantId);
  }

  /** Drop the in-isolate registration cache (call after a provisioning write). */
  invalidate(tenantId?: string): void {
    if (tenantId === undefined) this.#cache.clear();
    else this.#cache.delete(tenantId);
  }

  /**
   * The `D1Database` view of one tenant's object, WITHOUT the registry gate.
   *
   * Separate from {@link forTenant} because the gate is a policy about which
   * tenants a deployment will serve, while this is the addressing. A test
   * harness and the object's own maintenance paths need the second without the
   * first; a request path must never take this door, which is why it returns a
   * bare database rather than a {@link TenantDatabaseHandle} — there is no
   * `supportsAtomicBatch` on it for `requireAtomicBatch` to read, so it cannot
   * be mistaken for a routed handle.
   */
  databaseFor(tenantId: string): D1Database {
    if (tenantId === "") {
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    const stub = this.#namespace.get(this.#namespace.idFromName(tenantId));
    return new DurableObjectD1Database(tenantId, stub).asD1Database();
  }

  async #registration(tenantId: string): Promise<TenantDatabaseRegistration | undefined> {
    if (this.#ttlMs > 0) {
      const hit = this.#cache.get(tenantId);
      if (hit && Date.now() - hit.at < this.#ttlMs) return hit.value;
    }
    const value = await this.#registry.get(tenantId);
    if (value && this.#ttlMs > 0) this.#cache.set(tenantId, { at: Date.now(), value });
    return value;
  }
}
