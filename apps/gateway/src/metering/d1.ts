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
 * ## Schema
 *
 * The three tables below are the D1 reductions the inventory prescribes
 * (`inventory-data-billing.md` §1.4.4): Postgres' wide `billing_metering_events`
 * / `billing_ledger` collapse to a document row plus the columns that are
 * actually queried. Two projection columns are added beyond that list and are
 * marked in the DDL: `credits` (TEXT) and `total_tokens` (INTEGER), because
 * `credits` must be lossless past 2^53 — see `credits.ts` — and neither can be
 * read out of `entry_json` without a JSONB operator D1 does not have.
 *
 * PORT-TODO(inventory-data-billing §2.5 "LedgerSink"): the composition root
 * must declare `[[d1_databases]] binding = "DB"` and apply
 * {@link METERING_SCHEMA_SQL} as a migration before passing `env.DB` here.
 * `wrangler.toml` is owned by the integrate step, so this module ships the DDL
 * as a constant rather than declaring the binding itself.
 */
import type { LedgerListFilter } from "@ferrogate/billing";
import { creditsFromWire, creditsToWire } from "./wire.js";
import {
  billingEventFromWire,
  billingEventToWire,
  ledgerEntryFromWire,
  ledgerEntryToWireDocument,
} from "./wire.js";
import { meteredTotals } from "./ledger.js";
import type {
  LedgerStore,
  LedgerWriteOutcome,
  MeteredCharge,
  MeteredTotals,
  MeteringDatabase,
} from "./ports.js";
import { sameSettlement } from "./ledger.js";

/**
 * D1 (SQLite) DDL for the three metering tables.
 *
 * Split on `;` by the migration runner; every statement is `IF NOT EXISTS` so
 * re-application is a no-op.
 */
export const METERING_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS billing_events (
  billing_event_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  provider_attempt_index INTEGER NOT NULL DEFAULT 0,
  occurred_at_unix INTEGER NOT NULL,
  event_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_billing_events_request
  ON billing_events (request_id);

CREATE TABLE IF NOT EXISTS billing_ledger (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  organization_id TEXT,
  project_id TEXT,
  api_key_id TEXT,
  created_at_unix INTEGER NOT NULL,
  -- projection column: integer credits as a DECIMAL STRING, so a balance past
  -- 2^53 is exact. SQLite INTEGER is i64 and JSON numbers are doubles; TEXT is
  -- the only carrier that cannot lose a credit.
  credits TEXT NOT NULL,
  -- projection column: D1 has no JSONB operators, so anything aggregated has to
  -- be a real column.
  total_tokens INTEGER NOT NULL DEFAULT 0,
  total_cost_usd REAL NOT NULL DEFAULT 0,
  entry_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_billing_ledger_tenant_time
  ON billing_ledger (organization_id, created_at_unix);

CREATE TABLE IF NOT EXISTS billing_report_outbox (
  id TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_unix INTEGER NOT NULL,
  dead_lettered_at_unix INTEGER,
  created_at_unix INTEGER NOT NULL,
  updated_at_unix INTEGER NOT NULL,
  event_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_due
  ON billing_report_outbox (next_attempt_unix)
  WHERE dead_lettered_at_unix IS NULL;
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
  "(id, request_id, organization_id, project_id, api_key_id, created_at_unix, " +
  "credits, total_tokens, total_cost_usd, entry_json) " +
  "VALUES (?, ?, ?, ?, ?, CAST(? AS INTEGER), ?, CAST(? AS INTEGER), ?, ?) " +
  "ON CONFLICT (id) DO NOTHING";

export const BILLING_OUTBOX_INSERT_SQL =
  "INSERT INTO billing_report_outbox " +
  "(id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, " +
  "updated_at_unix, event_json) " +
  "VALUES (?, 0, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (id) DO NOTHING";

const BILLING_LEDGER_SELECT_SQL =
  "SELECT id, credits, entry_json, event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "WHERE billing_ledger.id = ?";

const BILLING_LEDGER_LIST_SQL =
  "SELECT billing_ledger.id AS id, credits, entry_json, event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "ORDER BY created_at_unix ASC, billing_ledger.id ASC";

/** A row shape the two selects return. */
interface LedgerRow {
  readonly id: string;
  readonly credits: unknown;
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

function rowToCharge(row: LedgerRow): MeteredCharge {
  const entry = ledgerEntryFromWire(JSON.parse(row.entry_json));
  const event = billingEventFromWire(JSON.parse(row.event_json));
  return {
    id: row.id,
    requestId: entry.request_id,
    entry,
    event,
    credits: creditsFromWire(row.credits),
    occurredAtUnix: entry.occurred_at_unix ?? event.occurred_at_unix ?? 0,
  };
}

/** {@link LedgerStore} over a native D1 binding. */
export class D1LedgerStore implements LedgerStore {
  readonly #db: MeteringDatabase;

  constructor(db: MeteringDatabase) {
    this.#db = db;
  }

  /**
   * Write the metering event, the ledger row and the outbox row in one batch.
   *
   * `nextAttemptUnix` for the outbox row is the charge's own settlement time,
   * i.e. "due immediately" — the same value `settle_request` passes.
   */
  async record(charge: MeteredCharge): Promise<LedgerWriteOutcome> {
    const eventJson = JSON.stringify(billingEventToWire(charge.event));
    const entryJson = JSON.stringify(ledgerEntryToWireDocument(charge.entry));
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
          charge.requestId,
          tenant.organization_id ?? null,
          tenant.project_id ?? null,
          tenant.api_key_id ?? null,
          occurredAt,
          creditsToWire(charge.credits),
          charge.entry.usage.total_tokens,
          charge.entry.cost.total_cost,
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

  async list(
    filter: LedgerListFilter,
    offset: number,
    limit: number,
  ): Promise<MeteredCharge[]> {
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

function matchesFilter(filter: LedgerListFilter, charge: MeteredCharge): boolean {
  const tenant = charge.entry.tenant;
  return (
    (filter.organization_id === undefined ||
      tenant.organization_id === filter.organization_id) &&
    (filter.project_id === undefined || tenant.project_id === filter.project_id) &&
    (filter.api_key_id === undefined || tenant.api_key_id === filter.api_key_id)
  );
}
