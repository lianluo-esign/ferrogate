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
 * ## Schema — owned by the DEPLOYED migration, mirrored for compatibility here
 *
 * The compatibility constructor uses the three tables defined by
 * `sql/d1-ts/control/0001_init_control.sql`, which is the D1 reduction the
 * inventory prescribes (§1.4.4) and is itself the verbatim port of the Rust
 * `sql/d1/001_init_d1.sql`: Postgres' wide `billing_ledger` /
 * `billing_metering_events` collapse to the #447 document pattern — a `*_json`
 * TEXT document plus only the projection columns the filter/order/paginate SQL
 * needs. The tenant constructor uses the explicit-column copies added by
 * `sql/d1-ts/tenant/0020_billing_wallet_consistency.sql`.
 *
 * The default constructor remains CONTROL-compatible and uses
 * `env.BILLING_DB`. A tenant-mounted constructor uses the same store contract
 * against the tenant Durable Object's D1-shaped facade. In that mode the
 * billing tables and wallet tables share one database, so the single
 * `batch()` atomicity below covers the full money movement rather than only the
 * report intent.
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
import type { BillingEvent, LedgerListFilter } from "@ferrogate/billing";
import { meteredTotals } from "./ledger.js";
import { sameSettlement } from "./ledger.js";
import type {
  DurableOutboxStore,
  LedgerStore,
  LedgerWriteOutcome,
  MeteredCharge,
  MeteredTotals,
  MeteringDatabase,
  MeteringStatement,
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

const SQLITE_INT64_MIN = -(1n << 63n);
const SQLITE_INT64_MAX = (1n << 63n) - 1n;

/** SQLite INTEGER is signed int64; never let a wallet delta saturate silently. */
function sqliteIntegerString(value: bigint): string {
  if (value < SQLITE_INT64_MIN || value > SQLITE_INT64_MAX) {
    throw new RangeError(`wallet settlement credits exceed SQLite int64: ${value.toString()}`);
  }
  return value.toString();
}

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

/** The same three writes, addressed inside one tenant Durable Object. */
const TENANT_BILLING_EVENT_INSERT_SQL =
  "INSERT INTO billing_events " +
  "(billing_event_id, tenant_id, request_id, provider_attempt_index, occurred_at_unix, event_json) " +
  "VALUES (?, ?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (billing_event_id) DO NOTHING " +
  "RETURNING billing_event_id";

const TENANT_BILLING_LEDGER_INSERT_SQL =
  "INSERT INTO billing_ledger " +
  "(id, tenant_id, organization_id, project_id, api_key_id, created_at_unix, entry_json) " +
  "VALUES (?, ?, ?, ?, ?, CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (id) DO NOTHING";

const TENANT_BILLING_OUTBOX_INSERT_SQL =
  "INSERT INTO billing_report_outbox " +
  "(id, tenant_id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, " +
  "updated_at_unix, event_json) " +
  "VALUES (?, ?, 0, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER), ?) " +
  "ON CONFLICT (id) DO NOTHING";

const TENANT_WALLET_SETTLEMENT_CLAIM_SQL =
  "INSERT INTO wallet_settlements " +
  "(id, tenant_id, delta_credits, balance_after_credits, created_at_unix) " +
  "SELECT ?, ?, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER) " +
  "WHERE changes() > 0 " +
  "AND EXISTS (SELECT 1 FROM wallets WHERE id = ? AND tenant_id = ?) " +
  "ON CONFLICT (id) DO NOTHING";

const TENANT_WALLET_SETTLEMENT_APPLY_SQL =
  "UPDATE wallets SET balance_credits = balance_credits + CAST(? AS INTEGER), " +
  "updated_at_unix = CAST(? AS INTEGER) " +
  "WHERE id = ? AND tenant_id = ? " +
  "AND changes() > 0 " +
  "AND EXISTS (SELECT 1 FROM wallet_settlements " +
  "WHERE id = ? AND tenant_id = ? AND balance_after_credits IS NULL)";

const TENANT_WALLET_SETTLEMENT_FINALIZE_SQL =
  "UPDATE wallet_settlements SET balance_after_credits = " +
  "(SELECT balance_credits FROM wallets WHERE id = ? AND tenant_id = ?) " +
  "WHERE id = ? AND tenant_id = ? AND changes() > 0 AND balance_after_credits IS NULL";

const BILLING_LEDGER_SELECT_SQL =
  "SELECT billing_ledger.id AS id, entry_json, event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "WHERE billing_ledger.id = ?";

const BILLING_LEDGER_LIST_SQL =
  "SELECT billing_ledger.id AS id, entry_json, event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "ORDER BY created_at_unix ASC, billing_ledger.id ASC";

const TENANT_BILLING_LEDGER_SELECT_SQL =
  "SELECT billing_ledger.id AS id, billing_ledger.entry_json AS entry_json, " +
  "billing_events.event_json AS event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "AND billing_events.tenant_id = billing_ledger.tenant_id " +
  "WHERE billing_ledger.id = ? AND billing_ledger.tenant_id = ?";

const TENANT_BILLING_LEDGER_LIST_SQL =
  "SELECT billing_ledger.id AS id, billing_ledger.entry_json AS entry_json, " +
  "billing_events.event_json AS event_json FROM billing_ledger " +
  "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id " +
  "AND billing_events.tenant_id = billing_ledger.tenant_id " +
  "WHERE billing_ledger.tenant_id = ? " +
  "ORDER BY billing_ledger.created_at_unix ASC, billing_ledger.id ASC";

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

const TENANT_BILLING_OUTBOX_LIST_DUE_SQL =
  "SELECT billing_report_outbox.id AS id, billing_report_outbox.attempts AS attempts, " +
  "billing_report_outbox.next_attempt_unix AS next_attempt_unix, " +
  "billing_ledger.entry_json AS entry_json, billing_report_outbox.event_json AS event_json " +
  "FROM billing_report_outbox " +
  "JOIN billing_ledger ON billing_ledger.id = billing_report_outbox.id " +
  "AND billing_ledger.tenant_id = billing_report_outbox.tenant_id " +
  "WHERE billing_report_outbox.tenant_id = ? " +
  "AND billing_report_outbox.dead_lettered_at_unix IS NULL " +
  "AND billing_report_outbox.next_attempt_unix <= CAST(? AS INTEGER) " +
  "ORDER BY billing_report_outbox.next_attempt_unix ASC, billing_report_outbox.id ASC " +
  "LIMIT CAST(? AS INTEGER)";

const TENANT_BILLING_OUTBOX_DELETE_SQL =
  "DELETE FROM billing_report_outbox WHERE id = ? AND tenant_id = ?";

const TENANT_BILLING_OUTBOX_RESCHEDULE_SQL =
  "UPDATE billing_report_outbox SET attempts = CAST(? AS INTEGER), " +
  "next_attempt_unix = CAST(? AS INTEGER), updated_at_unix = CAST(? AS INTEGER) " +
  "WHERE id = ? AND tenant_id = ?";

const TENANT_BILLING_OUTBOX_DEAD_LETTER_SQL =
  "UPDATE billing_report_outbox SET dead_lettered_at_unix = CAST(? AS INTEGER), " +
  "updated_at_unix = CAST(? AS INTEGER) WHERE id = ? AND tenant_id = ?";

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

/** Options for a control-compatible or tenant-authoritative D1 ledger. */
export interface D1LedgerStoreOptions {
  /** The tenant database this store is mounted on. */
  readonly tenantId?: string | undefined;
  /** Compatibility escape hatch for a read-only tenant adapter. */
  readonly settleWallet?: boolean | undefined;
}

/** {@link LedgerStore} over a native D1 binding. */
export class D1LedgerStore implements LedgerStore {
  readonly #db: MeteringDatabase;
  readonly #outbox: DurableOutboxStore;
  readonly #tenantId: string | undefined;
  readonly #settleWallet: boolean;

  constructor(db: MeteringDatabase, options: D1LedgerStoreOptions = {}) {
    this.#db = db;
    const tenantId = options.tenantId?.trim();
    if (options.tenantId !== undefined && tenantId === "") {
      throw new TypeError("D1LedgerStore tenantId must not be empty");
    }
    this.#tenantId = tenantId;
    this.#settleWallet = this.#tenantId !== undefined && options.settleWallet !== false;
    this.#outbox = new D1DurableOutbox(db, this.#tenantId);
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
    const tenantId = this.#tenantId;
    if (
      tenantId !== undefined &&
      [tenant.organization_id, charge.event.tenant.organization_id].some(
        (candidate) => candidate !== undefined && candidate !== tenantId,
      )
    ) {
      throw new Error(`billing charge ${charge.id} is routed to the wrong tenant`);
    }

    const eventStatement =
      tenantId === undefined
        ? this.#db
            .prepare(BILLING_EVENT_INSERT_SQL)
            .bind(
              charge.id,
              charge.requestId,
              charge.entry.provider_attempt.provider_attempt_index,
              occurredAt,
              eventJson,
            )
        : this.#db
            .prepare(TENANT_BILLING_EVENT_INSERT_SQL)
            .bind(
              charge.id,
              tenantId,
              charge.requestId,
              charge.entry.provider_attempt.provider_attempt_index,
              occurredAt,
              eventJson,
            );
    const ledgerStatement =
      tenantId === undefined
        ? this.#db
            .prepare(BILLING_LEDGER_INSERT_SQL)
            .bind(
              charge.id,
              tenant.organization_id ?? null,
              tenant.project_id ?? null,
              tenant.api_key_id ?? null,
              occurredAt,
              entryJson,
            )
        : this.#db
            .prepare(TENANT_BILLING_LEDGER_INSERT_SQL)
            .bind(
              charge.id,
              tenantId,
              tenant.organization_id ?? null,
              tenant.project_id ?? null,
              tenant.api_key_id ?? null,
              occurredAt,
              entryJson,
            );
    const outboxStatement =
      tenantId === undefined
        ? this.#db
            .prepare(BILLING_OUTBOX_INSERT_SQL)
            .bind(charge.id, occurredAt, occurredAt, occurredAt, eventJson)
        : this.#db
            .prepare(TENANT_BILLING_OUTBOX_INSERT_SQL)
            .bind(charge.id, tenantId, occurredAt, occurredAt, occurredAt, eventJson);

    // The wallet claim follows the event INSERT immediately. `changes() > 0`
    // therefore means this transaction won the billing idempotency race. A
    // divergent replay cannot debit a wallet before the later conflict check,
    // while a successful first write still settles in the same batch.
    const statements: MeteringStatement[] = [eventStatement];
    if (this.#settleWallet && tenantId !== undefined && charge.credits > 0n) {
      const walletDelta = sqliteIntegerString(-charge.credits);
      statements.push(
        this.#db
          .prepare(TENANT_WALLET_SETTLEMENT_CLAIM_SQL)
          .bind(charge.id, tenantId, walletDelta, occurredAt, tenantId, tenantId),
        this.#db
          .prepare(TENANT_WALLET_SETTLEMENT_APPLY_SQL)
          .bind(walletDelta, occurredAt, tenantId, tenantId, charge.id, tenantId),
        this.#db
          .prepare(TENANT_WALLET_SETTLEMENT_FINALIZE_SQL)
          .bind(tenantId, tenantId, charge.id, tenantId),
      );
    }
    statements.push(ledgerStatement, outboxStatement);

    const results = await this.#db.batch(statements);

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

  /**
   * The cost-less metering row for a usage nothing could price (#663) — see
   * {@link LedgerStore.recordEvent}.
   *
   * ONE statement, not a batch, because there is deliberately nothing to commit
   * it with: no ledger row (that would be a $0 bill) and no outbox intent (a
   * report of an unpriced charge has no charge to report, and
   * `BILLING_OUTBOX_LIST_DUE_SQL` joins `billing_ledger`, so such a row could
   * never be swept anyway). The atomicity the #150 batch exists to protect is
   * between a CHARGE and its delivery intent; this row is neither.
   *
   * It reuses `BILLING_EVENT_INSERT_SQL` verbatim, so the id, the conflict
   * behaviour and the column projection are the same ones a priced settlement
   * writes — which is what makes the row indistinguishable from the priced case
   * apart from its `cost_usd`, and therefore re-priceable in place.
   */
  async recordEvent(event: BillingEvent, id: string, occurredAtUnix: number): Promise<void> {
    const eventJson = JSON.stringify(billingEventToWire(event));
    if (this.#tenantId === undefined) {
      await this.#db
        .prepare(BILLING_EVENT_INSERT_SQL)
        .bind(
          id,
          event.request_id,
          event.provider_attempt.provider_attempt_index,
          occurredAtUnix,
          eventJson,
        )
        .all();
      return;
    }
    const eventTenant = event.tenant.organization_id;
    if (eventTenant !== undefined && eventTenant !== this.#tenantId) {
      throw new Error(`billing event ${id} is routed to the wrong tenant`);
    }
    await this.#db
      .prepare(TENANT_BILLING_EVENT_INSERT_SQL)
      .bind(
        id,
        this.#tenantId,
        event.request_id,
        event.provider_attempt.provider_attempt_index,
        occurredAtUnix,
        eventJson,
      )
      .all();
  }

  async get(id: string): Promise<MeteredCharge | undefined> {
    const result =
      this.#tenantId === undefined
        ? await this.#db.prepare(BILLING_LEDGER_SELECT_SQL).bind(id).all()
        : await this.#db.prepare(TENANT_BILLING_LEDGER_SELECT_SQL).bind(id, this.#tenantId).all();
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
    const result =
      this.#tenantId === undefined
        ? await this.#db.prepare(BILLING_LEDGER_LIST_SQL).all()
        : await this.#db.prepare(TENANT_BILLING_LEDGER_LIST_SQL).bind(this.#tenantId).all();
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
  readonly #tenantId: string | undefined;

  constructor(db: MeteringDatabase, tenantId: string | undefined) {
    this.#db = db;
    this.#tenantId = tenantId;
  }

  async reap(id: string): Promise<void> {
    if (this.#tenantId === undefined) {
      await this.#db.prepare(BILLING_OUTBOX_DELETE_SQL).bind(id).run();
      return;
    }
    await this.#db.prepare(TENANT_BILLING_OUTBOX_DELETE_SQL).bind(id, this.#tenantId).run();
  }

  async listDue(nowUnix: number, limit: number): Promise<OutboxRecord[]> {
    const result =
      this.#tenantId === undefined
        ? await this.#db.prepare(BILLING_OUTBOX_LIST_DUE_SQL).bind(nowUnix, limit).all()
        : await this.#db
            .prepare(TENANT_BILLING_OUTBOX_LIST_DUE_SQL)
            .bind(this.#tenantId, nowUnix, limit)
            .all();
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
    if (this.#tenantId === undefined) {
      await this.#db
        .prepare(BILLING_OUTBOX_RESCHEDULE_SQL)
        .bind(attempts, nextAttemptUnix, nowUnix, id)
        .run();
      return;
    }
    await this.#db
      .prepare(TENANT_BILLING_OUTBOX_RESCHEDULE_SQL)
      .bind(attempts, nextAttemptUnix, nowUnix, id, this.#tenantId)
      .run();
  }

  async deadLetter(id: string, nowUnix: number): Promise<void> {
    if (this.#tenantId === undefined) {
      await this.#db.prepare(BILLING_OUTBOX_DEAD_LETTER_SQL).bind(nowUnix, nowUnix, id).run();
      return;
    }
    await this.#db
      .prepare(TENANT_BILLING_OUTBOX_DEAD_LETTER_SQL)
      .bind(nowUnix, nowUnix, id, this.#tenantId)
      .run();
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
