/**
 * The D1-backed {@link LedgerStore} — port of
 * `control_plane_store_d1/billing.rs::append_billing_event_with_outbox_enqueue_async`.
 *
 * The load-bearing property is that the metering row, the ledger row and the
 * outbox row are written in ONE `batch()`. Rust does this deliberately (issue
 * #150) so a charge and its delivery intent commit together; splitting them
 * reopens the window where a settled request is billed but never reported, or
 * reported but never billed. D1's `batch()` is an implicit transaction, so the
 * guarantee ports directly — and the `d1-proxy` HTTP hop the Rust code needed
 * disappears entirely because this runs INSIDE the Worker.
 *
 * Idempotency comes from the same place it does in Rust: `ON CONFLICT (…) DO
 * NOTHING` plus a `RETURNING` clause on the metering insert, whose presence or
 * absence tells the caller `recorded` from `duplicate` with no extra read. A
 * duplicate is then re-read and structurally compared so a replay carrying
 * DIFFERENT settlement data surfaces as `conflict` rather than being silently
 * absorbed (issue #213).
 *
 * ## Schema — owned by the DEPLOYED migration, mirrored here
 *
 * The three tables are defined by `sql/d1-ts/control/0001_init_control.sql`,
 * which is the D1 reduction the inventory prescribes (§1.4.4) and is itself the
 * verbatim port of the Rust `sql/d1/001_init_d1.sql`: Postgres' wide
 * `billing_ledger` / `billing_metering_events` collapse to the #447 document
 * pattern — a `*_json` TEXT document plus only the projection columns the
 * filter/order/paginate SQL needs.
 *
 * They live in the CONTROL database, not the tenant one — the tenant migration
 * says so in as many words ("billing ledger/outbox/events -> CONTROL") — so the
 * binding this store takes is `env.BILLING_DB` (`wrangler.toml`), never
 * `env.DB`. All three tables being in the SAME database is what makes the
 * single-`batch()` atomicity below real rather than aspirational.
 *
 * {@link METERING_SCHEMA_SQL} is a VERBATIM MIRROR of those statements, kept
 * only so an offline harness can provision the tables without a migration
 * runner; `test/metering/schema.test.ts` diffs it against the deployed file and
 * fails on any drift, so it cannot become a private schema the tests pass
 * against and production does not have. The deploy path is
 * `wrangler d1 migrations apply ferrogate-control`.
 *
 * ### Where the integer credits live, given the schema has no column for them
 *
 * `billing_ledger` has exactly six columns and none of them is `credits`; the
 * Rust Postgres table did have one and it is `DOUBLE PRECISION`, i.e. lossy
 * past 2^53 — the very drift `credits.ts` exists to close. Since the DDL is not
 * this module's to change, the lossless integer travels as the extra
 * `credits_exact` DECIMAL-STRING field inside the `entry_json` document. It is
 * additive: `ledgerEntryWireSchema` is a non-strict `z.object`, so the field is
 * stripped on parse and `LedgerEntry` keeps serde's exact shape, while
 * {@link D1LedgerStore.get} reads the string off the raw document BEFORE that
 * parse. A row written by some other producer with no `credits_exact` falls
 * back to the `f64` `credits` field, rounded — lossy, and marked as such,
 * rather than silently reading zero.
 */
import type { LedgerListFilter } from "@ferrogate/billing";
import { meteredTotals } from "./ledger.js";
import { sameSettlement } from "./ledger.js";
import type {
  DurableOutboxStore,
  LedgerStore,
  LedgerWriteOutcome,
  MeteredCharge,
  MeteredTotals,
  MeteringDatabase,
  OutboxRecord,
} from "./ports.js";
import { creditsFromWire, creditsToWire } from "./wire.js";
import {
  billingEventFromWire,
  billingEventToWire,
  ledgerEntryFromWire,
  ledgerEntryToWireDocument,
} from "./wire.js";

/**
 * The extra `entry_json` field carrying the lossless integer credits.
 *
 * Not a Rust field and not part of `LedgerEntry` — see the "Where the integer
 * credits live" note above for why the DDL leaves no column for it and why an
 * additive document field is the correct place given the schema is owned
 * elsewhere.
 */
export const CREDITS_EXACT_FIELD = "credits_exact";

/**
 * D1 (SQLite) DDL for the three metering tables — a VERBATIM MIRROR of the
 * `billing_events` / `billing_ledger` / `billing_report_outbox` statements in
 * `sql/d1-ts/control/0001_init_control.sql`.
 *
 * The deployed path is `wrangler d1 migrations apply ferrogate-control`; this
 * constant exists only so a harness with no migration runner can provision the
 * tables. `test/metering/schema.test.ts` reads the migration file and asserts
 * every statement here appears in it, so the two cannot diverge — the failure
 * mode this replaces is a private schema that the suite passes against and the
 * account does not have.
 *
 * Split on `;` by the caller; every statement is `IF NOT EXISTS` so
 * re-application is a no-op.
 */
export const METERING_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS billing_ledger (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    created_at_unix INTEGER NOT NULL,
    entry_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_scope
    ON billing_ledger(organization_id, project_id, api_key_id);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_created
    ON billing_ledger(created_at_unix, id);

CREATE TABLE IF NOT EXISTS billing_report_outbox (
    id TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix INTEGER NOT NULL,
    dead_lettered_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_due
    ON billing_report_outbox(next_attempt_unix);

CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_dead
    ON billing_report_outbox(dead_lettered_at_unix);

CREATE TABLE IF NOT EXISTS billing_events (
    billing_event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    provider_attempt_index INTEGER NOT NULL DEFAULT 0,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_events_occurred
    ON billing_events(occurred_at_unix, request_id, provider_attempt_index);
`.trim();

/** `INSERT ... ON CONFLICT DO NOTHING RETURNING` — presence of a row ⇒ recorded. */
export const BILLING_EVENT_INSERT_SQL =
  "INSERT INTO billing_events " +
  "(billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json) " +
  "VALUES (?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (billing_event_id) DO NOTHING " +
  "RETURNING billing_event_id";

export const BILLING_LEDGER_INSERT_SQL =
  "INSERT INTO billing_ledger " +
  "(id, organization_id, project_id, api_key_id, created_at_unix, entry_json) " +
  "VALUES (?, ?, ?, ?, CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (id) DO NOTHING";

export const BILLING_OUTBOX_INSERT_SQL =
  "INSERT INTO billing_report_outbox " +
  "(id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, " +
  "updated_at_unix, event_json) " +
  "VALUES (?, 0, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (id) DO NOTHING";

const BILLING_LEDGER_SELECT_SQL =
  "SELECT billing_ledger.id AS id, entry_json, event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "WHERE billing_ledger.id = ?";

const BILLING_LEDGER_LIST_SQL =
  "SELECT billing_ledger.id AS id, entry_json, event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "ORDER BY created_at_unix ASC, billing_ledger.id ASC";

/** `delete_billing_report` — the report was delivered, drop the intent. */
export const BILLING_OUTBOX_DELETE_SQL = "DELETE FROM billing_report_outbox WHERE id = ?";

/**
 * `list_due_billing_reports`, rehydrating the whole charge from the documents.
 *
 * The JOIN onto `billing_ledger` is not decoration: the outbox row stores only
 * the `BillingEvent`, and a report also carries the priced `LedgerEntry` and the
 * integer credits. It is also the filter that skips an intent whose charge is
 * not (yet) there to re-deliver.
 */
export const BILLING_OUTBOX_LIST_DUE_SQL =
  "SELECT billing_report_outbox.id AS id, billing_report_outbox.attempts AS attempts, " +
  "billing_report_outbox.next_attempt_unix AS next_attempt_unix, " +
  "billing_ledger.entry_json AS entry_json, billing_report_outbox.event_json AS event_json " +
  "FROM billing_report_outbox " +
  "JOIN billing_ledger ON billing_ledger.id = billing_report_outbox.id " +
  "WHERE billing_report_outbox.dead_lettered_at_unix IS NULL " +
  "AND billing_report_outbox.next_attempt_unix <= CAST(? AS INTEGER) " +
  "ORDER BY billing_report_outbox.next_attempt_unix ASC, billing_report_outbox.id ASC " +
  "LIMIT CAST(? AS INTEGER)";

/** `reschedule_billing_report`. */
export const BILLING_OUTBOX_RESCHEDULE_SQL =
  "UPDATE billing_report_outbox SET attempts = CAST(? AS INTEGER), " +
  "next_attempt_unix = CAST(? AS INTEGER), updated_at_unix = CAST(? AS INTEGER) WHERE id = ?";

/** `dead_letter_billing_report` (#143). */
export const BILLING_OUTBOX_DEAD_LETTER_SQL =
  "UPDATE billing_report_outbox SET dead_lettered_at_unix = CAST(? AS INTEGER), " +
  "updated_at_unix = CAST(? AS INTEGER) WHERE id = ?";

/** A row shape the two selects return. */
interface LedgerRow {
  readonly id: string;
  readonly entry_json: string;
  readonly event_json: string;
}

function isLedgerRow(value: unknown): value is LedgerRow {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const row = value as Record<string, unknown>;
  return (
    typeof row.id === "string" &&
    typeof row.entry_json === "string" &&
    typeof row.event_json === "string"
  );
}

/**
 * The `entry_json` document, plus the integer credits the schema has no column
 * for.
 *
 * `ledgerEntryToWire` is `@ferrogate/billing`'s serde-faithful writer and is NOT
 * re-implemented; the one added key is {@link CREDITS_EXACT_FIELD}, a decimal
 * string. A JSON NUMBER here would defeat the whole point — 2^53+1 would come
 * back as 2^53.
 */
export function ledgerDocument(charge: MeteredCharge): Record<string, unknown> {
  return {
    ...ledgerEntryToWireDocument(charge.entry),
    [CREDITS_EXACT_FIELD]: creditsToWire(charge.credits),
  };
}

/**
 * Read the integer credits back out of a stored `entry_json` document.
 *
 * The fallback exists for a row this store did not write (the Rust producer, a
 * migration backfill): those carry only the `f64` `credits` field, so the value
 * is recovered by rounding it. That path is LOSSY past 2^53 — which is exactly
 * why {@link CREDITS_EXACT_FIELD} is written — but a wrong-by-one credit is
 * still a truthful reading of what was stored, whereas defaulting to `0n` would
 * make an old row look free.
 */
function creditsFromDocument(document: unknown): bigint {
  const record =
    typeof document === "object" && document !== null ? (document as Record<string, unknown>) : {};
  const exact = record[CREDITS_EXACT_FIELD];
  if (exact !== undefined) {
    return creditsFromWire(exact);
  }
  const legacy = record.credits;
  if (typeof legacy === "number" && Number.isFinite(legacy)) {
    return BigInt(Math.round(legacy));
  }
  throw new TypeError(
    `billing_ledger.entry_json carries neither ${CREDITS_EXACT_FIELD} nor a numeric credits field`,
  );
}

function rowToCharge(row: LedgerRow): MeteredCharge {
  const document: unknown = JSON.parse(row.entry_json);
  const entry = ledgerEntryFromWire(document);
  const event = billingEventFromWire(JSON.parse(row.event_json));
  return {
    id: row.id,
    requestId: entry.request_id,
    entry,
    event,
    credits: creditsFromDocument(document),
    occurredAtUnix: entry.occurred_at_unix ?? event.occurred_at_unix ?? 0,
  };
}

/** A `billing_report_outbox` row joined to its charge. */
interface OutboxRow {
  readonly id: string;
  readonly attempts: number;
  readonly next_attempt_unix: number;
  readonly entry_json: string;
  readonly event_json: string;
}

function isOutboxRow(value: unknown): value is OutboxRow {
  if (!isLedgerRow(value)) {
    return false;
  }
  const row = value as unknown as Record<string, unknown>;
  return typeof row.attempts === "number" && typeof row.next_attempt_unix === "number";
}

/** {@link LedgerStore} over a native D1 binding. */
export class D1LedgerStore implements LedgerStore {
  readonly #db: MeteringDatabase;
  readonly #outbox: DurableOutboxStore;

  constructor(db: MeteringDatabase) {
    this.#db = db;
    this.#outbox = new D1DurableOutbox(db);
  }

  /**
   * The durable `billing_report_outbox` intent this store commits alongside
   * every charge — see {@link LedgerStore.outbox}.
   */
  get outbox(): DurableOutboxStore {
    return this.#outbox;
  }

  /**
   * Write the metering event, the ledger row and the outbox row in one batch.
   *
   * `nextAttemptUnix` for the outbox row is the charge's own settlement time,
   * i.e. "due immediately" — the same value `settle_request` passes.
   */
  async record(charge: MeteredCharge): Promise<LedgerWriteOutcome> {
    const eventJson = JSON.stringify(billingEventToWire(charge.event));
    const entryJson = JSON.stringify(ledgerDocument(charge));
    const tenant = charge.entry.tenant;
    const occurredAt = charge.occurredAtUnix;

    const results = await this.#db.batch([
      this.#db
        .prepare(BILLING_EVENT_INSERT_SQL)
        .bind(
          charge.id,
          charge.requestId,
          charge.entry.provider_attempt.provider_attempt_index,
          occurredAt,
          eventJson,
        ),
      this.#db
        .prepare(BILLING_LEDGER_INSERT_SQL)
        .bind(
          charge.id,
          tenant.organization_id ?? null,
          tenant.project_id ?? null,
          tenant.api_key_id ?? null,
          occurredAt,
          entryJson,
        ),
      this.#db
        .prepare(BILLING_OUTBOX_INSERT_SQL)
        .bind(charge.id, occurredAt, occurredAt, occurredAt, eventJson),
    ]);

    const metering = results[0];
    if (metering === undefined) {
      // A short batch response is a binding contract violation, not a
      // duplicate. Treating it as one would silently drop the charge.
      throw new Error("d1 batch returned no result for the metering insert");
    }
    if ((metering.results?.length ?? 0) > 0) {
      return { status: "recorded" };
    }

    // `ON CONFLICT DO NOTHING` matched. Re-read and compare so a replay with
    // different settlement data cannot pass as a healthy retry (issue #213).
    const existing = await this.get(charge.id);
    if (existing === undefined) {
      // The row vanished between the insert and the read: report it as newly
      // recorded rather than as a duplicate, so the caller still delivers.
      return { status: "recorded" };
    }
    return sameSettlement(existing, charge)
      ? { status: "duplicate" }
      : { status: "conflict", existing };
  }

  async get(id: string): Promise<MeteredCharge | undefined> {
    const result = await this.#db.prepare(BILLING_LEDGER_SELECT_SQL).bind(id).all();
    const row = result.results?.[0];
    return row !== undefined && isLedgerRow(row) ? rowToCharge(row) : undefined;
  }

  async list(filter: LedgerListFilter, offset: number, limit: number): Promise<MeteredCharge[]> {
    return (await this.#all(filter)).slice(offset, offset + limit);
  }

  /**
   * Aggregate in app code, in `bigint`.
   *
   * A `SUM(credits)` in SQLite would coerce the TEXT column to a REAL and lose
   * exactly the precision the column exists to protect, and the inventory
   * already flags "move filters to app code" for the D1 port. The read is
   * bounded by the caller's filter.
   */
  async totals(filter: LedgerListFilter = {}): Promise<MeteredTotals> {
    return meteredTotals(await this.#all(filter));
  }

  async #all(filter: LedgerListFilter): Promise<MeteredCharge[]> {
    const result = await this.#db.prepare(BILLING_LEDGER_LIST_SQL).all();
    const charges = (result.results ?? []).filter(isLedgerRow).map(rowToCharge);
    return charges.filter((charge) => matchesFilter(filter, charge));
  }
}

/**
 * The durable outbox row's lifecycle on D1.
 *
 * Only the INSERT is part of {@link D1LedgerStore.record}'s batch — it has to
 * be, that is the #150 atomicity. Everything after it is a separate statement
 * because it happens at a different time, potentially in a different isolate:
 * the reap runs when the Queue publish has been acknowledged, the reschedule
 * and the dead-letter when it has not.
 */
class D1DurableOutbox implements DurableOutboxStore {
  readonly #db: MeteringDatabase;

  constructor(db: MeteringDatabase) {
    this.#db = db;
  }

  async reap(id: string): Promise<void> {
    await this.#db.prepare(BILLING_OUTBOX_DELETE_SQL).bind(id).run();
  }

  async listDue(nowUnix: number, limit: number): Promise<OutboxRecord[]> {
    const result = await this.#db.prepare(BILLING_OUTBOX_LIST_DUE_SQL).bind(nowUnix, limit).all();
    return (result.results ?? []).filter(isOutboxRow).map((row) => ({
      id: row.id,
      charge: rowToCharge(row),
      attempts: row.attempts,
      nextAttemptUnix: row.next_attempt_unix,
      // The JOIN matched a `billing_ledger` row, so the charge HAS committed.
      // A sweep that re-ran the ledger write would read `duplicate` and drop the
      // row without ever delivering it — the exact bug `settled` exists to stop.
      settled: true,
    }));
  }

  async reschedule(
    id: string,
    attempts: number,
    nextAttemptUnix: number,
    nowUnix: number,
  ): Promise<void> {
    await this.#db
      .prepare(BILLING_OUTBOX_RESCHEDULE_SQL)
      .bind(attempts, nextAttemptUnix, nowUnix, id)
      .run();
  }

  async deadLetter(id: string, nowUnix: number): Promise<void> {
    await this.#db.prepare(BILLING_OUTBOX_DEAD_LETTER_SQL).bind(nowUnix, nowUnix, id).run();
  }
}

function matchesFilter(filter: LedgerListFilter, charge: MeteredCharge): boolean {
  const tenant = charge.entry.tenant;
  return (
    (filter.organization_id === undefined || tenant.organization_id === filter.organization_id) &&
    (filter.project_id === undefined || tenant.project_id === filter.project_id) &&
    (filter.api_key_id === undefined || tenant.api_key_id === filter.api_key_id)
  );
}
