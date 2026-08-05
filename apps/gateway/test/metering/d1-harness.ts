/**
 * The REAL D1 binding, for the metering suite.
 *
 * `apps/gateway/wrangler.toml` declares `[[d1_databases]] binding = "BILLING_DB"`
 * (the control compatibility database), so `@cloudflare/vitest-pool-workers`
 * provisions a real local SQLite for it and every statement `D1LedgerStore`
 * issues is executed by the same engine production runs. Nothing here doubles
 * the database.
 *
 * The schema applied is the DEPLOYED migration file, read with Vite's `?raw` —
 * never a fixture copy — for the reason `test/setup-d1.ts` gives for the tenant
 * database: a column rename in the migration must break the suite, rather than
 * the suite passing against a private schema the account does not have.
 *
 * What IS wrapped is the binding, not the code under test:
 * {@link RecordingDatabase} is a transparent decorator that records the SQL and
 * bound values on their way through and can be told to fail — the two things a
 * bare binding cannot expose. With `failure` unset every call reaches the real
 * D1 unchanged.
 */
import { env } from "cloudflare:test";
import controlMigrationSql from "../../../../sql/d1-ts/control/0001_init_control.sql?raw";
import type {
  MeteringDatabase,
  MeteringQueryResult,
  MeteringQueue,
  MeteringQueueMessage,
  MeteringStatement,
} from "../../src/metering/index.js";

/** The deployed control migration, as text. */
export const CONTROL_MIGRATION_SQL: string = controlMigrationSql;

/** The three legacy compatibility tables metering owns in the control schema. */
export const METERING_TABLES = [
  "billing_events",
  "billing_ledger",
  "billing_report_outbox",
] as const;

/**
 * Split a `.sql` migration into executable statements.
 *
 * Line comments are stripped first: `0001_init_control.sql` is mostly prose,
 * and a `;` inside a comment would otherwise cut a statement in half — which
 * fails as a `SQLITE_ERROR` on some unrelated word, i.e. the least legible
 * possible failure.
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

/** The live control compatibility `env.BILLING_DB` binding. */
export function billingDb(): D1Database {
  const binding = (env as unknown as { BILLING_DB?: D1Database }).BILLING_DB;
  if (binding === undefined) {
    // Loud, never a silent skip: the binding is declared in `wrangler.toml`, so
    // an absent one means the declaration was removed and the suite is about to
    // prove something other than what it claims.
    throw new Error(
      "metering tests expect the `BILLING_DB` D1 binding (apps/gateway/wrangler.toml). " +
        "See src/metering/runtime.ts for the tenant-authority and compatibility paths.",
    );
  }
  return binding;
}

/** The live `env.BILLING` Queue producer binding. */
export function billingQueue(): Queue {
  const binding = (env as unknown as { BILLING?: Queue }).BILLING;
  if (binding === undefined) {
    throw new Error(
      "metering tests expect the `BILLING` Queue producer binding (apps/gateway/wrangler.toml).",
    );
  }
  return binding;
}

let applied = false;

/** Apply the deployed control migration once per isolate. */
export async function applyControlMigration(): Promise<void> {
  if (applied) {
    return;
  }
  const db = billingDb();
  for (const statement of sqlStatements(CONTROL_MIGRATION_SQL)) {
    await db.prepare(statement).run();
  }
  applied = true;
}

/** Empty the metering tables between tests, so each one starts from zero rows. */
export async function resetMeteringTables(): Promise<void> {
  await applyControlMigration();
  const db = billingDb();
  await db.batch(METERING_TABLES.map((table) => db.prepare(`DELETE FROM ${table}`)));
}

/** `SELECT count(*)` on one of the metering tables. */
export async function rowCount(table: (typeof METERING_TABLES)[number]): Promise<number> {
  const result = await billingDb().prepare(`SELECT count(*) AS n FROM ${table}`).all();
  const row = result.results?.[0] as { n?: unknown } | undefined;
  return Number(row?.n ?? 0);
}

/** The raw `entry_json` of a ledger row, for asserting what really landed. */
export async function ledgerEntryJson(id: string): Promise<string | undefined> {
  const result = await billingDb()
    .prepare("SELECT entry_json FROM billing_ledger WHERE id = ?")
    .bind(id)
    .all();
  const row = result.results?.[0] as { entry_json?: unknown } | undefined;
  return typeof row?.entry_json === "string" ? row.entry_json : undefined;
}

/** Rewrite a stored ledger document, to forge a divergent replay (issue #213). */
export async function overwriteLedgerDocument(
  id: string,
  document: Record<string, unknown>,
): Promise<void> {
  await billingDb()
    .prepare("UPDATE billing_ledger SET entry_json = ? WHERE id = ?")
    .bind(JSON.stringify(document), id)
    .run();
}

/** One executed statement, for asserting the SQL the store actually issues. */
export interface ExecutedStatement {
  readonly sql: string;
  readonly values: readonly unknown[];
}

class RecordingStatement implements MeteringStatement {
  readonly #owner: RecordingDatabase;
  readonly #sql: string;
  readonly #inner: MeteringStatement;
  readonly #values: readonly unknown[];

  constructor(
    owner: RecordingDatabase,
    sql: string,
    inner: MeteringStatement,
    values: readonly unknown[] = [],
  ) {
    this.#owner = owner;
    this.#sql = sql;
    this.#inner = inner;
    this.#values = values;
  }

  /** `D1PreparedStatement.bind` returns a NEW statement; so does this. */
  bind(...values: unknown[]): MeteringStatement {
    return new RecordingStatement(this.#owner, this.#sql, this.#inner.bind(...values), values);
  }

  async run(): Promise<MeteringQueryResult> {
    this.#owner.note(this.#sql, this.#values);
    this.#owner.throwIfFailing();
    return this.#inner.run();
  }

  async all(): Promise<MeteringQueryResult> {
    this.#owner.note(this.#sql, this.#values);
    this.#owner.throwIfFailing();
    return this.#inner.all();
  }

  /** The statement handed to `batch()`. */
  get inner(): MeteringStatement {
    return this.#inner;
  }

  get sql(): string {
    return this.#sql;
  }

  get values(): readonly unknown[] {
    return this.#values;
  }
}

/**
 * A transparent decorator over a live D1 binding.
 *
 * It records what was executed and can be made to reject, which is how the
 * outbox's retry/dead-letter ladder is exercised against a database that is
 * otherwise entirely real.
 */
export class RecordingDatabase implements MeteringDatabase {
  readonly #inner: MeteringDatabase;
  readonly #executed: ExecutedStatement[] = [];

  /** Set to make every subsequent statement reject, as an outage would. */
  failure: Error | undefined;

  /** Replace one statement inside the next batch with invalid SQL. */
  failBatchIndex: number | undefined;

  constructor(inner: MeteringDatabase = billingDb()) {
    this.#inner = inner;
  }

  prepare(sql: string): MeteringStatement {
    return new RecordingStatement(this, sql, this.#inner.prepare(sql));
  }

  async batch(statements: MeteringStatement[]): Promise<MeteringQueryResult[]> {
    for (const statement of statements) {
      if (statement instanceof RecordingStatement) {
        this.note(statement.sql, statement.values);
      }
    }
    this.throwIfFailing();
    return this.#inner.batch(
      statements.map((statement, index) => {
        if (index === this.failBatchIndex) {
          return this.#inner.prepare(
            "SELECT * FROM billing_batch_statement_that_must_not_exist",
          );
        }
        return statement instanceof RecordingStatement ? statement.inner : statement;
      }),
    );
  }

  note(sql: string, values: readonly unknown[]): void {
    this.#executed.push({ sql, values: [...values] });
  }

  throwIfFailing(): void {
    if (this.failure !== undefined) {
      throw this.failure;
    }
  }

  /** Every statement executed, in order. */
  get executed(): readonly ExecutedStatement[] {
    return this.#executed;
  }

  clearExecuted(): void {
    this.#executed.length = 0;
  }
}

/**
 * A transparent decorator over the live `BILLING` Queue producer binding.
 *
 * PLATFORM LIMIT, stated rather than papered over: `wrangler.toml` declares a
 * PRODUCER only — a `[[queues.consumers]]` entry here would make this Worker
 * deliver the billing reports to itself, which is not the deployment shape —
 * and `cloudflare:test` exposes no API for reading messages back out of a
 * queue. So "the message reached the queue" is proved by the REAL binding
 * accepting the `send()` (a malformed, unclonable, or oversized body rejects
 * there, in workerd, exactly as it would in production), while WHAT was sent is
 * captured on its way through. Nothing is substituted for the binding.
 */
export class RecordingQueue implements MeteringQueue {
  readonly #inner: MeteringQueue;
  readonly #sent: MeteringQueueMessage[] = [];

  /** Set to make every subsequent send reject, as an unavailable queue would. */
  failure: Error | undefined;

  constructor(inner: MeteringQueue = billingQueue() as unknown as MeteringQueue) {
    this.#inner = inner;
  }

  async send(message: MeteringQueueMessage): Promise<unknown> {
    this.#sent.push(message);
    if (this.failure !== undefined) {
      throw this.failure;
    }
    return this.#inner.send(message);
  }

  async sendBatch(messages: Iterable<{ body: MeteringQueueMessage }>): Promise<unknown> {
    const batch = [...messages];
    for (const message of batch) {
      this.#sent.push(message.body);
    }
    if (this.failure !== undefined) {
      throw this.failure;
    }
    return this.#inner.sendBatch(batch);
  }

  /** Every message the queue accepted, in order. */
  get sent(): readonly MeteringQueueMessage[] {
    return this.#sent;
  }
}
