/**
 * A `D1Database`-shaped test double.
 *
 * `apps/gateway/wrangler.toml` declares no `[[d1_databases]]` binding (its
 * "NOT DECLARED — and why" block is explicit that a binding lands WITH the code
 * that reads it, and that file belongs to the integrate step), so miniflare
 * cannot hand this suite a real D1. What is doubled here is therefore the
 * BINDING, not the code under test: {@link D1LedgerStore} runs unmodified
 * against it, issuing its real SQL through the real `prepare`/`bind`/`batch`
 * call shape.
 *
 * The double implements exactly the SQL semantics the store depends on:
 * `ON CONFLICT (…) DO NOTHING` (an insert on an existing key is a no-op) and
 * the `RETURNING` clause that makes "recorded" distinguishable from
 * "duplicate" without a second read.
 *
 * `test/metering/d1.test.ts` additionally asserts, at COMPILE time, that a real
 * `D1Database` satisfies the port — which is the half a double cannot prove.
 */
import {
  BILLING_EVENT_INSERT_SQL,
  BILLING_LEDGER_INSERT_SQL,
  BILLING_OUTBOX_INSERT_SQL,
  type MeteringDatabase,
  type MeteringQueryResult,
  type MeteringStatement,
} from "../../src/metering/index.js";

interface Row {
  [column: string]: unknown;
}

/** One executed statement, for asserting the SQL the store actually issues. */
export interface ExecutedStatement {
  readonly sql: string;
  readonly values: readonly unknown[];
}

class FakeStatement implements MeteringStatement {
  readonly #db: FakeD1Database;
  readonly #sql: string;
  #values: unknown[] = [];

  constructor(db: FakeD1Database, sql: string) {
    this.#db = db;
    this.#sql = sql;
  }

  bind(...values: unknown[]): MeteringStatement {
    this.#values = values;
    return this;
  }

  // `execute` is synchronous and throws, so each call produces exactly ONE
  // rejected promise. Returning an inner promise from these async methods
  // instead leaves the inner one transiently unhandled, which V8 reports as an
  // unhandled rejection and vitest fails the run on.
  // eslint-disable-next-line @typescript-eslint/require-await -- the port is async.
  async run(): Promise<MeteringQueryResult> {
    return this.#db.execute(this.#sql, this.#values);
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- the port is async.
  async all(): Promise<MeteringQueryResult> {
    return this.#db.execute(this.#sql, this.#values);
  }
}

/** Minimal SQLite stand-in for the three metering tables. */
export class FakeD1Database implements MeteringDatabase {
  readonly #billingEvents = new Map<string, Row>();
  readonly #billingLedger = new Map<string, Row>();
  readonly #outbox = new Map<string, Row>();
  readonly #executed: ExecutedStatement[] = [];
  /** Set to make every statement reject, simulating an unavailable D1. */
  failure: Error | undefined;

  prepare(sql: string): MeteringStatement {
    return new FakeStatement(this, sql);
  }

  async batch(statements: MeteringStatement[]): Promise<MeteringQueryResult[]> {
    // D1 `batch()` is one implicit transaction. The double runs the statements
    // in order and, on failure, discards them all — which is the property
    // `D1LedgerStore` relies on for the metering + ledger + outbox atomicity.
    const snapshot = {
      events: new Map(this.#billingEvents),
      ledger: new Map(this.#billingLedger),
      outbox: new Map(this.#outbox),
    };
    try {
      const results: MeteringQueryResult[] = [];
      for (const statement of statements) {
        results.push(await statement.run());
      }
      return results;
    } catch (error) {
      this.#restore(snapshot);
      throw error;
    }
  }

  /** Every statement executed, in order. */
  get executed(): readonly ExecutedStatement[] {
    return this.#executed;
  }

  get eventCount(): number {
    return this.#billingEvents.size;
  }

  get ledgerCount(): number {
    return this.#billingLedger.size;
  }

  get outboxCount(): number {
    return this.#outbox.size;
  }

  /** Rewrite a stored ledger row, to forge a divergent replay. */
  overwriteLedger(id: string, patch: Row): void {
    const row = this.#billingLedger.get(id);
    if (row !== undefined) {
      this.#billingLedger.set(id, { ...row, ...patch });
    }
  }

  execute(sql: string, values: readonly unknown[]): MeteringQueryResult {
    this.#executed.push({ sql, values: [...values] });
    if (this.failure !== undefined) {
      throw this.failure;
    }

    if (sql === BILLING_EVENT_INSERT_SQL) {
      const [billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json] =
        values;
      const id = String(billing_event_id);
      if (this.#billingEvents.has(id)) {
        // ON CONFLICT DO NOTHING ⇒ RETURNING yields no row.
        return { results: [], success: true };
      }
      this.#billingEvents.set(id, {
        billing_event_id: id,
        request_id,
        provider_attempt_index,
        occurred_at_unix,
        event_json,
      });
      return { results: [{ billing_event_id: id }], success: true };
    }

    if (sql === BILLING_LEDGER_INSERT_SQL) {
      const [
        id,
        request_id,
        organization_id,
        project_id,
        api_key_id,
        created_at_unix,
        credits,
        total_tokens,
        total_cost_usd,
        entry_json,
      ] = values;
      const key = String(id);
      if (!this.#billingLedger.has(key)) {
        this.#billingLedger.set(key, {
          id: key,
          request_id,
          organization_id,
          project_id,
          api_key_id,
          created_at_unix,
          credits,
          total_tokens,
          total_cost_usd,
          entry_json,
        });
      }
      return { results: [], success: true };
    }

    if (sql === BILLING_OUTBOX_INSERT_SQL) {
      const [id, next_attempt_unix, created_at_unix, updated_at_unix, event_json] = values;
      const key = String(id);
      if (!this.#outbox.has(key)) {
        this.#outbox.set(key, {
          id: key,
          attempts: 0,
          next_attempt_unix,
          dead_lettered_at_unix: null,
          created_at_unix,
          updated_at_unix,
          event_json,
        });
      }
      return { results: [], success: true };
    }

    if (sql.startsWith("SELECT")) {
      const joined: Row[] = [];
      for (const ledger of this.#billingLedger.values()) {
        const event = this.#billingEvents.get(String(ledger.id));
        if (event === undefined) {
          continue;
        }
        joined.push({
          id: ledger.id,
          credits: ledger.credits,
          created_at_unix: ledger.created_at_unix,
          entry_json: ledger.entry_json,
          event_json: event.event_json,
        });
      }

      const byId = values[0];
      const rows =
        byId === undefined ? joined : joined.filter((row) => row.id === String(byId));
      rows.sort(
        (left, right) => Number(left?.created_at_unix) - Number(right?.created_at_unix),
      );
      return { results: rows, success: true };
    }

    throw new Error(`FakeD1Database has no handler for: ${sql}`);
  }

  #restore(snapshot: { events: Map<string, Row>; ledger: Map<string, Row>; outbox: Map<string, Row> }): void {
    this.#billingEvents.clear();
    for (const [key, value] of snapshot.events) {
      this.#billingEvents.set(key, value);
    }
    this.#billingLedger.clear();
    for (const [key, value] of snapshot.ledger) {
      this.#billingLedger.set(key, value);
    }
    this.#outbox.clear();
    for (const [key, value] of snapshot.outbox) {
      this.#outbox.set(key, value);
    }
  }
}
