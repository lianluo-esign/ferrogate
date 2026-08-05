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
 * It exposes `query` / `batch` / schema and schedule-alarm RPCs. The
 * `D1Database`-shaped facade that lets the 14 modules under `src/d1/` port
 * unchanged (`prepare().bind().first()/all()/run()`, `meta.changes`, the
 * `durable_object` `TenantDatabaseSource`) is a separate slice; this one
 * establishes the object, its schema and its isolation guard.
 *
 * There is no `fetch()` surface: every method is RPC over the binding, so the
 * object is not addressable from the internet.
 */
import { DurableObject } from "cloudflare:workers";
import { AUDIT_CHAIN_GENESIS_HASH, auditChainKey, auditRowHash } from "./audit-chain.js";
import {
  TENANT_MIGRATIONS,
  TENANT_SCHEMA_VERSION,
  type TenantMigration,
} from "./tenant-schema-sql.js";
import {
  decodeTenantScheduleAlarm,
  encodeTenantScheduleAlarm,
  tenantScheduleAlarmMessage,
  type TenantScheduleAlarmMessage,
} from "./tenant-schedule-alarm.js";

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

/** One tenant-authoritative append to the tamper-evident audit chain. */
export interface TenantAuditAppendRequest {
  readonly tenantId: string;
  readonly id: string;
  readonly requestId: string;
  readonly agentRunId: string | null;
  readonly occurredAtUnix: number;
  readonly auditJson: string;
}

/** The complete row returned after the object assigned its chain position. */
export interface TenantAuditAppendResult {
  readonly id: string;
  readonly requestId: string;
  readonly agentRunId: string | null;
  readonly tenant: string;
  readonly occurredAtUnix: number;
  readonly auditJson: string;
  readonly chainKey: string;
  readonly seq: number;
  readonly prevHash: string;
  readonly rowHash: string;
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
  /**
   * Rows WRITTEN, straight off the cursor — the `D1Result.meta.rows_written`
   * equivalent, and deliberately NOT the same number as {@link changes}.
   *
   * The cursor counts INDEX row writes as well as table rows, so a row landing
   * in a table with three indexes reports 4 here and 1 in `changes`. Both are
   * true and neither substitutes for the other: D1 bills on `rows_written` and
   * the guarded-write CAS branches on `changes`. Reporting one under the other's
   * name would either bill wrong or publish an unscanned asset.
   */
  readonly rowsWritten: number;
  /**
   * `last_insert_rowid()` AFTER the statement — `D1Result.meta.last_row_id`.
   *
   * Read from the connection, not from the statement, so a statement that
   * inserted nothing reports whatever the previous INSERT on this object left
   * behind. That is exactly D1's behaviour (its `last_row_id` is a connection
   * property too), and it is why nothing in this repo reads it: grepping
   * `last_row_id|lastRowId|lastInsertRowid` over non-test source returns zero
   * hits. It is carried anyway because `D1Meta.last_row_id` is non-optional, and
   * a synthesized `0` there would be a lie a future caller could believe.
   */
  readonly lastRowId: number;
  /**
   * The object's SQLite database size in bytes after the statement —
   * `D1Result.meta.size_after`. `ctx.storage.sql.databaseSize`, verbatim.
   *
   * Also unread by anything in this repo, and also carried rather than
   * zero-filled: it is the one meta field that maps onto the 10 GB per-object
   * ceiling, so an operator asking "how close is this tenant to the limit"
   * should get a real answer rather than a placeholder.
   */
  readonly databaseSize: number;
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

/** The single durable alarm deadline a tenant object can own. */
export interface TenantScheduleAlarmRequest {
  /** The tenant this object must already hold or adopt. */
  readonly tenantId: string;
  /** Unix seconds; the native Durable Object alarm is armed in milliseconds. */
  readonly scheduledAtUnix: number;
}

/** Clear the current tenant object's schedule alarm. */
export interface TenantScheduleAlarmClearRequest {
  readonly tenantId: string;
}

/** Storage key for the adopted tenant id. See {@link TenantDataObject.query}. */
const TENANT_ID_KEY = "tenant_data:tenant_id";

/** The validated tenant-only payload retained until the native alarm fires. */
const SCHEDULE_ALARM_KEY = "tenant_data:schedule_alarm";

interface TenantScheduleAlarmQueue {
  send(body: unknown): Promise<unknown>;
}

function scheduleAlarmQueueFrom(env: unknown): TenantScheduleAlarmQueue | null {
  if (typeof env !== "object" || env === null) return null;
  const queue = (env as { SCHEDULE_ALARMS?: unknown }).SCHEDULE_ALARMS;
  if (typeof queue !== "object" || queue === null) return null;
  const send = (queue as { send?: unknown }).send;
  return typeof send === "function" ? (queue as TenantScheduleAlarmQueue) : null;
}

/**
 * Symbol-keyed so it is a testable/internal seam without becoming a string RPC
 * method. Cloudflare RPC only addresses string properties; the alarm entrypoint
 * is the only production caller.
 */
export const TENANT_SCHEDULE_ALARM_CALLBACK = Symbol("TenantDataObject.scheduleAlarmCallback");

export type TenantScheduleAlarmCallback = (message: TenantScheduleAlarmMessage) => Promise<void>;

/**
 * A witness table from `0001_init_tenant.sql`, used to catch a ledger that
 * disagrees with the database it claims to describe. See `#assertLedgerHonest`.
 */
const WITNESS_TABLE = "projects";

/** Prefix on every refusal this object raises, so a caller can recognise one. */
const REFUSAL = "tenant_data_object";

/**
 * Role bindings and their local catalog are an operator projection. Letting a
 * tenant-facing SQL caller write either half would allow it to manufacture its
 * own permission grant, so those writes require the separate privileged RPC.
 */
const PRIVILEGED_WRITE_TABLES = ["tenant_role_bindings", "tenant_role_catalog"] as const;

function stripSqlCommentsAndStrings(sql: string): string {
  let output = "";
  let mode: "normal" | "line_comment" | "block_comment" | "string" = "normal";

  for (let index = 0; index < sql.length; index += 1) {
    const current = sql[index];
    const next = sql[index + 1];
    if (mode === "line_comment") {
      if (current === "\n") {
        output += current;
        mode = "normal";
      } else {
        output += " ";
      }
      continue;
    }
    if (mode === "block_comment") {
      if (current === "*" && next === "/") {
        output += "  ";
        index += 1;
        mode = "normal";
      } else {
        output += " ";
      }
      continue;
    }
    if (mode === "string") {
      if (current === "'") {
        if (next === "'") {
          output += "  ";
          index += 1;
        } else {
          output += " ";
          mode = "normal";
        }
      } else {
        output += " ";
      }
      continue;
    }
    if (current === "-" && next === "-") {
      output += "  ";
      index += 1;
      mode = "line_comment";
    } else if (current === "/" && next === "*") {
      output += "  ";
      index += 1;
      mode = "block_comment";
    } else if (current === "'") {
      output += " ";
      mode = "string";
    } else {
      output += current;
    }
  }
  return output;
}

function requiresPrivilegedWrite(sql: string): string | null {
  // This is deliberately conservative. Tokenising after a stateful pass that
  // removes comments and string literals catches CTEs, `UPDATE OR REPLACE`,
  // schema-qualified names, and trigger bodies without trying to implement
  // SQLite's grammar here. The state machine matters: `--` and `/*` inside a
  // legal string must not hide SQL that follows that string.
  const normalized = stripSqlCommentsAndStrings(sql);
  const tokens = new Set(
    (normalized.match(/[A-Za-z_][A-Za-z0-9_$]*/g) ?? []).map((token) => token.toLowerCase()),
  );
  if (
    !["insert", "replace", "update", "delete", "create", "alter", "drop", "truncate"].some((verb) =>
      tokens.has(verb),
    )
  ) {
    return null;
  }
  for (const table of PRIVILEGED_WRITE_TABLES) {
    if (tokens.has(table)) return table;
  }
  return null;
}

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
 *    comment lines containing a `;` mid-prose, and the TWENTY files have 36
 *    between them (18 in 0001, 1 in 0003, 5 in 0005, 3 in 0008, 2 in 0009,
 *    1 in 0011, 1 in 0012, 1 in 0013, 1 in 0015, 1 in 0016 and 2 in 0017) —
 *    36, not 18,
 *    is the number that bounds this function's exposure. Splitting before
 *    stripping cuts statements in half at every one of them.
 *
 *    These numbers are a MEASUREMENT and they have gone stale before: the
 *    census was not always re-run when a migration landed. `test/do/tenant-
 *    data-object.test.ts` now recomputes every count in this docblock from the
 *    real files and asserts them, so the next migration reddens a test instead
 *    of quietly falsifying a safety argument.
 *  * The filter is line-granular after `trimStart()`, which is what makes it
 *    lossless over `0005_responses_conversations.sql` — that file indents `--`
 *    comments BETWEEN columns, and a filter anchored at column 0 would corrupt
 *    the table.
 *  * It is safe today because, measured over all TWENTY files, every non-comment
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
  readonly #scheduleAlarmQueue: TenantScheduleAlarmQueue | null;
  readonly [TENANT_SCHEDULE_ALARM_CALLBACK]: TenantScheduleAlarmCallback = async (message) => {
    if (this.#scheduleAlarmQueue === null) {
      throw new Error(`${REFUSAL}: SCHEDULE_ALARMS is not bound; retaining the alarm for retry`);
    }
    await this.#scheduleAlarmQueue.send(encodeTenantScheduleAlarm(message));
  };

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx as never, env as never);
    this.#state = ctx;
    this.#scheduleAlarmQueue = scheduleAlarmQueueFrom(env);
    // `blockConcurrencyWhile` is the lock, and it is the whole reason a request
    // cannot observe a half-migrated database: no RPC is delivered until this
    // settles. An EVICTED instance re-runs it on the next wake, so the version
    // gate inside `#migrate` is what keeps that from re-applying 183 statements
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
    this.#refuseUnprivilegedWrite(request.sql);
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
    for (const statement of request.statements) this.#refuseUnprivilegedWrite(statement.sql);
    return this.#state.storage.transactionSync(() => {
      const results: TenantDataResult[] = [];
      for (const statement of request.statements) {
        results.push(this.#exec(statement));
      }
      return results;
    });
  }

  /**
   * Internal operator path for projections that must be written atomically.
   * The binding is private to Worker-to-Worker bindings; ordinary tenant
   * callers only receive `query` and `batch` through the D1 facade.
   */
  async privilegedBatch(request: TenantDataBatchRequest): Promise<TenantDataResult[]> {
    await this.#admit(request.tenantId);
    return this.#state.storage.transactionSync(() => {
      const results: TenantDataResult[] = [];
      for (const statement of request.statements) results.push(this.#exec(statement));
      return results;
    });
  }

  /**
   * Append one tenant audit row with its chain position assigned by the object.
   *
   * The hash calculation is asynchronous Web Crypto, while SQLite's
   * `transactionSync()` callback must be synchronous. `blockConcurrencyWhile`
   * closes that gap: it keeps every other RPC out while the head is read, the
   * digest is computed, and the checked insert commits. The transaction still
   * re-reads the head before inserting, so the serialization assumption is
   * explicit rather than hidden in the caller.
   */
  async appendAudit(request: TenantAuditAppendRequest): Promise<TenantAuditAppendResult> {
    await this.#admit(request.tenantId);
    if (request.tenantId.trim() === "" || request.tenantId !== request.tenantId.trim()) {
      throw new Error(`${REFUSAL}: audit append requires a normalized tenant id`);
    }
    if (request.occurredAtUnix < 0 || !Number.isSafeInteger(request.occurredAtUnix)) {
      throw new Error(`${REFUSAL}: audit append requires a non-negative integer timestamp`);
    }
    const tenant = request.tenantId;
    const chainKey = auditChainKey(tenant);

    return this.#state.blockConcurrencyWhile(async () => {
      const existing = this.#state.storage.sql
        .exec<{
          id: string;
          request_id: string;
          agent_run_id: string | null;
          tenant: string;
          occurred_at_unix: number;
          audit_json: string;
          chain_key: string;
          seq: number;
          prev_hash: string;
          row_hash: string;
        }>(
          "SELECT id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json, " +
            "chain_key, seq, prev_hash, row_hash FROM audit_events WHERE id = ?",
          request.id,
        )
        .toArray()[0];
      if (existing !== undefined) {
        if (
          existing.request_id !== request.requestId ||
          existing.agent_run_id !== request.agentRunId ||
          existing.tenant !== tenant ||
          existing.occurred_at_unix !== request.occurredAtUnix ||
          existing.audit_json !== request.auditJson
        ) {
          throw new Error(`${REFUSAL}: audit append idempotency conflict for ${request.id}`);
        }
        return {
          id: existing.id,
          requestId: existing.request_id,
          agentRunId: existing.agent_run_id,
          tenant: existing.tenant,
          occurredAtUnix: existing.occurred_at_unix,
          auditJson: existing.audit_json,
          chainKey: existing.chain_key,
          seq: existing.seq,
          prevHash: existing.prev_hash,
          rowHash: existing.row_hash,
        };
      }
      const head = this.#auditHead(chainKey);
      const seq = head === null ? 1 : head.seq + 1;
      const prevHash = head?.rowHash ?? AUDIT_CHAIN_GENESIS_HASH;
      const rowHash = await auditRowHash({
        chain_key: chainKey,
        seq,
        prev_hash: prevHash,
        id: request.id,
        request_id: request.requestId,
        agent_run_id: request.agentRunId,
        tenant,
        occurred_at_unix: request.occurredAtUnix,
        audit_json: request.auditJson,
      });

      return this.#state.storage.transactionSync(() => {
        const current = this.#auditHead(chainKey);
        if (current?.seq !== head?.seq || current?.rowHash !== head?.rowHash) {
          throw new Error(`${REFUSAL}: audit chain head changed while appending`);
        }
        this.#state.storage.sql
          .exec(
            "INSERT INTO audit_events " +
              "(id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json, " +
              "chain_key, seq, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            request.id,
            request.requestId,
            request.agentRunId,
            tenant,
            request.occurredAtUnix,
            request.auditJson,
            chainKey,
            seq,
            prevHash,
            rowHash,
          )
          .toArray();
        return {
          id: request.id,
          requestId: request.requestId,
          agentRunId: request.agentRunId,
          tenant,
          occurredAtUnix: request.occurredAtUnix,
          auditJson: request.auditJson,
          chainKey,
          seq,
          prevHash,
          rowHash,
        };
      });
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

  /**
   * Arm the one native alarm owned by this tenant object.
   *
   * Cloudflare permits one alarm deadline per object, so callers must pass the
   * earliest tenant schedule deadline. The small validated message is retained
   * beside the native deadline because an alarm callback receives no timestamp.
   */
  async setScheduleAlarm(request: TenantScheduleAlarmRequest): Promise<void> {
    const message = tenantScheduleAlarmMessage(request.tenantId, request.scheduledAtUnix);
    await this.#admit(message.tenant_id);
    await this.#state.blockConcurrencyWhile(async () => {
      // Keep the payload durable before arming the deadline. If the alarm
      // write fails, a retry still has a complete message to deliver.
      await this.#state.storage.put(SCHEDULE_ALARM_KEY, message);
      await this.#state.storage.setAlarm(message.scheduled_at_unix * 1000);
    });
  }

  /** Clear the current schedule alarm and its tenant-local callback payload. */
  async clearScheduleAlarm(request: TenantScheduleAlarmClearRequest): Promise<void> {
    const tenantId = tenantScheduleAlarmMessage(request.tenantId, 0).tenant_id;
    await this.#admit(tenantId);
    await this.#state.blockConcurrencyWhile(async () => {
      await this.#state.storage.deleteAlarm();
      await this.#state.storage.delete(SCHEDULE_ALARM_KEY);
    });
  }

  /**
   * Recompute the deadline from rows in this object, while no other object RPC
   * can interleave. The caller never supplies a schedule snapshot, so a late
   * rearm cannot clear or replace an alarm written by a newer schedule update.
   */
  async rearmScheduleAlarm(request: TenantScheduleAlarmClearRequest): Promise<void> {
    const tenantId = tenantScheduleAlarmMessage(request.tenantId, 0).tenant_id;
    await this.#admit(tenantId);
    await this.#state.blockConcurrencyWhile(async () => {
      let earliest: number | undefined;
      const rows = this.#state.storage.sql
        .exec<{ enabled: number; next_fire_at_unix: number | null }>(
          "SELECT enabled, next_fire_at_unix FROM agent_schedules WHERE enabled = 1 AND next_fire_at_unix IS NOT NULL ORDER BY next_fire_at_unix ASC LIMIT 1",
        )
        .toArray();
      const candidate = rows[0]?.next_fire_at_unix;
      if (typeof candidate === "number" && Number.isSafeInteger(candidate)) {
        earliest = candidate;
      }

      if (earliest === undefined) {
        await this.#state.storage.deleteAlarm();
        await this.#state.storage.delete(SCHEDULE_ALARM_KEY);
        return;
      }

      const message = tenantScheduleAlarmMessage(tenantId, earliest);
      // Retain the payload before arming the native alarm. If setAlarm fails,
      // the caller receives the failure and can retry without losing intent.
      await this.#state.storage.put(SCHEDULE_ALARM_KEY, message);
      await this.#state.storage.setAlarm(earliest * 1000);
    });
  }

  /**
   * Native Durable Object alarm entrypoint.
   *
   * The callback is symbol-keyed rather than a public string method, so a
   * binding caller cannot invoke a queue-like operation with caller-supplied
   * tenant data. Production sends the validated payload to `SCHEDULE_ALARMS`;
   * a missing binding throws and leaves the payload retained for retry.
   */
  override async alarm(): Promise<void> {
    await this.#state.blockConcurrencyWhile(async () => {
      const raw = await this.#state.storage.get<unknown>(SCHEDULE_ALARM_KEY);
      if (raw === undefined) return;
      const message = decodeTenantScheduleAlarm(raw);
      if (this.#tenantId !== message.tenant_id) {
        throw new Error(
          REFUSAL +
            ": schedule alarm names tenant " +
            message.tenant_id +
            ", but this object holds " +
            (this.#tenantId ?? "no tenant") +
            "; refusing",
        );
      }
      await this[TENANT_SCHEDULE_ALARM_CALLBACK](message);
      await this.#state.storage.delete(SCHEDULE_ALARM_KEY);
    });
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

  #refuseUnprivilegedWrite(sql: string): void {
    const table = requiresPrivilegedWrite(sql);
    if (table === null) return;
    throw new Error(
      `${REFUSAL}: writes to ${table} require the privileged operator RPC; refusing ordinary tenant SQL`,
    );
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
    const before = connectionCounters(sql).changes;
    const cursor = sql.exec<Record<string, TenantDataValue>>(
      statement.sql,
      ...(statement.params ?? []),
    );
    // Drained BEFORE `rowsRead`/`rowsWritten` are read: the cursor's counters
    // are only final once it has been consumed.
    const results = cursor.toArray();
    const rowsRead = cursor.rowsRead;
    const rowsWritten = cursor.rowsWritten;
    // ONE trailing read for both connection-level counters. `total_changes()`
    // and `last_insert_rowid()` are both properties of the connection rather
    // than of the cursor, and reading them in a single `exec` keeps them from
    // straddling a statement that a future edit might insert between them.
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
   * Bring the database to {@link latestVersion}. Synchronous throughout.
   *
   * The version gate is the first thing that happens, because this runs on every
   * cold start of every tenant object: an already-current tenant pays one
   * `sqlite_master` probe and one `MAX(version)` read and returns, instead of
   * re-running the 183 statements of the twenty files — 71 `CREATE TABLE IF
   * NOT EXISTS`, 89 `CREATE INDEX`, 6 `CREATE UNIQUE INDEX`, 10 `ALTER TABLE … ADD
   * COLUMN`, 6 ledger `INSERT` statements and one `DROP TABLE`. (Counted,
   * not estimated — and counted by a
   * TEST since #831's review: an earlier draft said "26 `CREATE INDEX`", and the
   * whole census then went stale again the moment `0013_guardrail_evaluations.sql`
   * landed. `test/do/tenant-data-object.test.ts` re-derives these five numbers
   * from `sql/d1-ts/tenant/` and asserts them. The ten ALTERs are the half that
   * matters — the CREATEs are idempotent by construction and the ALTERs are not,
   * so the gate is load-bearing rather than an optimisation.)
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
          // than a PRIMARY KEY conflict, and supplies the rows for 0002..0008,
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

  #auditHead(chainKey: string): { readonly seq: number; readonly rowHash: string } | null {
    const rows = this.#state.storage.sql
      .exec<{ seq: number; row_hash: string }>(
        "SELECT seq, row_hash FROM audit_events WHERE chain_key = ? ORDER BY seq DESC LIMIT 1",
        chainKey,
      )
      .toArray();
    const row = rows[0];
    return row === undefined ? null : { seq: row.seq, rowHash: row.row_hash };
  }
}

/**
 * The two CONNECTION-level counters `#exec` needs: `total_changes()` (rows
 * changed since the connection opened) and `last_insert_rowid()`.
 *
 * A free function so both reads in `#exec` are provably the same query, and one
 * `exec` for the pair so a future edit cannot slip a statement between them and
 * silently attribute one statement's rowid to another's change count. The
 * cursor is drained immediately, in the caller's synchronous stretch.
 *
 * Reading these is itself a `SELECT`, which changes neither counter — that is
 * what makes the before/after delta in `#exec` attributable to the caller's
 * statement alone.
 */
function connectionCounters(sql: SqlStorage): { changes: number; lastRowId: number } {
  const rows = sql
    .exec<{ n: number; r: number }>("SELECT total_changes() AS n, last_insert_rowid() AS r")
    .toArray();
  const row = rows[0];
  return { changes: row?.n ?? 0, lastRowId: row?.r ?? 0 };
}

/** The `[[durable_objects.bindings]]` namespace type for `env.TENANT_DATA`. */
export type TenantDataNamespace = DurableObjectNamespace<TenantDataObject>;
