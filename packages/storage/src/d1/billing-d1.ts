/**
 * `D1BillingEventLedger` — the CONTROL-database metering-event claim and its
 * durable billing-report outbox (inventory-data-billing §1.5.8 item 8, issues
 * #137 / #143 / #150 / #151 / #388).
 *
 * ## Why this exists here and not next to `D1UsageLedger`
 *
 * `D1UsageLedger` (`./usage-d1.ts`) accumulates counters on a TENANT database
 * with `existing + excluded`. That is correct for a counter and deliberately
 * NOT idempotent: replaying the same settled request counts it twice. The Rust
 * tree gets exactly-once from the CONTROL-database `billing_events` PRIMARY KEY
 * — `append_billing_event_with_outbox_enqueue` claims `billing_event_id` and
 * enqueues the outbox row in ONE transaction, and only a claim that WON is
 * allowed to go on and move money.
 *
 * Both `billing_events` and `billing_report_outbox` live in the CONTROL
 * database (`sql/d1-ts/control/0001_init_control.sql`), so on D1 the Rust
 * transaction maps exactly onto one `controlDb.batch([claim, enqueue])`. There
 * is no cross-database coordination in this class and none is needed.
 *
 * ## The claim token is the `RETURNING` row, not the row's existence
 *
 * Statement 0 is `INSERT ... ON CONFLICT (billing_event_id) DO NOTHING
 * RETURNING billing_event_id`. On a first write the RETURNING set has one row;
 * on a replay the conflict suppresses the insert and the set is EMPTY. So
 * "did I win the claim?" is `results[0].results.length > 0` — never "does the
 * row exist", which is true on both paths and would hand the claim to every
 * replay.
 *
 * Because the two statements commit together, a metering event can never land
 * without its outbox row: there is no partial-success case to compensate for,
 * which is why {@link BillingEventAppendOutcome} carries no `enqueueError`
 * (the Rust in-memory backend needed one; D1 and Postgres do not).
 *
 * ## Divergent replay is a conflict, not a no-op
 *
 * A replay whose stored document differs from the one presented is NOT the same
 * settled call wearing the same id — it is two different settlements colliding
 * on one idempotency key, and silently accepting it would drop revenue on the
 * floor. The Rust `same_billing_event_settlement` is whole-struct equality
 * (`left == right`), so the faithful comparison here is byte equality of the
 * canonical `eventJson`. CALLERS MUST SERIALIZE CANONICALLY — see
 * {@link BillingEventRecord.eventJson}.
 */
import { StorageError } from "../errors.js";
import { d1Error, optionalNumber } from "./rows.js";

/**
 * One settled metering event as the CONTROL database stores it.
 *
 * This package deliberately does NOT depend on `@ferrogate/billing`: the
 * `BillingEvent` shape, its pricing, and its idempotency-id derivation
 * (`ledgerEntryId`) are that package's contract, and storage's job is only to
 * claim an id atomically and hand the document back. The Rust crate's
 * `ferrogate-storage -> ferrogate-billing` dependency exists because Rust has
 * no structural typing; TS does, so the seam stays a plain record.
 */
export interface BillingEventRecord {
  /** The idempotency key. `@ferrogate/billing`'s `ledgerEntryId(event)`. */
  billingEventId: string;
  requestId: string;
  /** The #135 provider-attempt index, so a retried upstream call cannot double-bill. */
  providerAttemptIndex: number;
  occurredAtUnix: number;
  /**
   * The serialized event document.
   *
   * MUST be canonical (stable key order) for a given logical event: the
   * divergent-replay guard compares this string byte-for-byte against the
   * stored one, mirroring Rust's whole-struct `PartialEq`. Two serializations
   * of the same event that differ only in key order would be reported as a
   * conflict.
   */
  eventJson: string;
}

/**
 * Outcome of {@link D1BillingEventLedger.appendBillingEventWithOutboxEnqueue}.
 *
 * `recorded: true` means THIS call won the claim and is the one — and only one
 * — allowed to move money for this `billingEventId`. `recorded: false` is a
 * verified-identical replay: the caller must NOT re-apply the charge.
 *
 * A divergent replay never reaches here; it throws {@link StorageError} with
 * kind `conflict`.
 */
export interface BillingEventAppendOutcome {
  recorded: boolean;
}

/** One `billing_report_outbox` row. */
export interface StoredBillingReportOutboxEntry {
  /** The ledger-entry id the billing service dedups delivery on. */
  id: string;
  eventJson: string;
  attempts: number;
  nextAttemptUnix: number;
  /** Set when the entry was given up on (issue #143); `undefined` while live. */
  deadLetteredAtUnix?: number;
}

/** Outcome of the dead-letter replay CAS (issue #388). */
export type ReplayDeadLetterOutcome =
  | { kind: "replayed"; entry: StoredBillingReportOutboxEntry }
  /** The row exists but was never dead-lettered — reports its real state. */
  | { kind: "not_dead_lettered"; entry: StoredBillingReportOutboxEntry }
  | { kind: "not_found" };

interface OutboxRow {
  id: string;
  event_json: string;
  attempts: number;
  next_attempt_unix: number;
  dead_lettered_at_unix: number | null;
}

const SELECT_OUTBOX_COLUMNS =
  "SELECT id, event_json, attempts, next_attempt_unix, dead_lettered_at_unix " +
  "FROM billing_report_outbox";

function outboxFromRow(row: OutboxRow): StoredBillingReportOutboxEntry {
  const deadLettered = optionalNumber(row.dead_lettered_at_unix);
  return {
    id: row.id,
    eventJson: row.event_json,
    attempts: Number(row.attempts),
    nextAttemptUnix: Number(row.next_attempt_unix),
    ...(deadLettered !== undefined ? { deadLetteredAtUnix: deadLettered } : {}),
  };
}

export class D1BillingEventLedger {
  constructor(private readonly controlDb: D1Database) {}

  /**
   * Claim `event.billingEventId` and enqueue its outbox row in ONE atomic
   * batch (ports `append_billing_event_with_outbox_enqueue`, issue #150).
   *
   * @returns `{ recorded: true }` when this call won the claim (apply the
   *   charge), `{ recorded: false }` on a verified-identical replay (do not).
   * @throws {@link StorageError} `conflict` when the id was replayed with a
   *   different settlement document.
   */
  async appendBillingEventWithOutboxEnqueue(
    event: BillingEventRecord,
    outboxId: string,
    outboxNextAttemptUnix: number,
  ): Promise<BillingEventAppendOutcome> {
    let results: D1Result<{ billing_event_id: string }>[];
    try {
      results = await this.controlDb.batch<{ billing_event_id: string }>([
        this.controlDb
          .prepare(
            "INSERT INTO billing_events " +
              "(billing_event_id, request_id, provider_attempt_index, occurred_at_unix, " +
              " event_json) " +
              "VALUES (?, ?, ?, ?, ?) " +
              "ON CONFLICT (billing_event_id) DO NOTHING " +
              "RETURNING billing_event_id",
          )
          .bind(
            event.billingEventId,
            event.requestId,
            event.providerAttemptIndex,
            event.occurredAtUnix,
            event.eventJson,
          ),
        this.controlDb
          .prepare(
            "INSERT INTO billing_report_outbox " +
              "(id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, " +
              " updated_at_unix, event_json) " +
              "VALUES (?, 0, ?, NULL, unixepoch(), unixepoch(), ?) " +
              "ON CONFLICT (id) DO NOTHING",
          )
          .bind(outboxId, outboxNextAttemptUnix, event.eventJson),
      ]);
    } catch (error) {
      throw d1Error("append_billing_event_with_outbox_enqueue", error);
    }

    const claim = results[0];
    if (claim === undefined) {
      // A short batch response would make every claim look lost, i.e. every
      // settled call would be treated as a replay and never billed.
      throw StorageError.runtime(
        "cloudflare d1: append_billing_event_with_outbox_enqueue batch returned no " +
          "per-statement results",
      );
    }
    if (claim.results.length > 0) {
      return { recorded: true };
    }

    // Lost the claim: the id already existed. Verify it is the SAME settlement
    // before reporting a benign no-op.
    const existing = await this.getBillingEvent(event.billingEventId);
    if (existing === undefined) {
      throw StorageError.runtime(
        `billing event id ${event.billingEventId} conflicted but could not be reloaded`,
      );
    }
    if (existing.eventJson !== event.eventJson) {
      throw StorageError.conflict(
        `billing event id ${event.billingEventId} was replayed with different ` +
          "provider-attempt settlement data",
      );
    }
    return { recorded: false };
  }

  /** One stored metering event by its idempotency key. */
  async getBillingEvent(billingEventId: string): Promise<BillingEventRecord | undefined> {
    try {
      const row = await this.controlDb
        .prepare(
          "SELECT billing_event_id, request_id, provider_attempt_index, occurred_at_unix, " +
            "event_json FROM billing_events WHERE billing_event_id = ?",
        )
        .bind(billingEventId)
        .first<{
          billing_event_id: string;
          request_id: string;
          provider_attempt_index: number;
          occurred_at_unix: number;
          event_json: string;
        }>();
      if (row === null) return undefined;
      return {
        billingEventId: row.billing_event_id,
        requestId: row.request_id,
        providerAttemptIndex: Number(row.provider_attempt_index),
        occurredAtUnix: Number(row.occurred_at_unix),
        eventJson: row.event_json,
      };
    } catch (error) {
      throw d1Error("billing_event_by_id", error);
    }
  }

  /**
   * Outbox rows due for a delivery attempt, oldest deadline first. Dead-lettered
   * rows are excluded — a permanently undeliverable report must not starve the
   * sweeper batch (`MAX_BILLING_OUTBOX_ATTEMPTS`, issue #143).
   */
  async listDueBillingReports(
    nowUnix: number,
    limit: number,
  ): Promise<StoredBillingReportOutboxEntry[]> {
    try {
      const result = await this.controlDb
        .prepare(
          `${SELECT_OUTBOX_COLUMNS} WHERE next_attempt_unix <= ? AND ` +
            "dead_lettered_at_unix IS NULL ORDER BY next_attempt_unix ASC LIMIT ?",
        )
        .bind(nowUnix, Math.max(0, Math.trunc(limit)))
        .all<OutboxRow>();
      return result.results.map(outboxFromRow);
    } catch (error) {
      throw d1Error("list_due_billing_reports", error);
    }
  }

  /** One outbox row by ledger-entry id. */
  async getBillingReportOutboxEntry(
    id: string,
  ): Promise<StoredBillingReportOutboxEntry | undefined> {
    try {
      const row = await this.controlDb
        .prepare(`${SELECT_OUTBOX_COLUMNS} WHERE id = ?`)
        .bind(id)
        .first<OutboxRow>();
      return row === null ? undefined : outboxFromRow(row);
    } catch (error) {
      throw d1Error("get_billing_report_outbox_entry", error);
    }
  }

  /** A failed delivery: charge one attempt and back the row off. */
  async rescheduleBillingReport(id: string, nextAttemptUnix: number): Promise<void> {
    try {
      await this.controlDb
        .prepare(
          "UPDATE billing_report_outbox SET attempts = attempts + 1, next_attempt_unix = ?, " +
            "updated_at_unix = unixepoch() WHERE id = ?",
        )
        .bind(nextAttemptUnix, id)
        .run();
    } catch (error) {
      throw d1Error("reschedule_billing_report", error);
    }
  }

  /** Give up on a row past `MAX_BILLING_OUTBOX_ATTEMPTS` (issue #143). */
  async deadLetterBillingReport(id: string, deadLetteredAtUnix: number): Promise<void> {
    try {
      await this.controlDb
        .prepare(
          "UPDATE billing_report_outbox SET dead_lettered_at_unix = ?, updated_at_unix = ? " +
            "WHERE id = ?",
        )
        .bind(deadLetteredAtUnix, deadLetteredAtUnix, id)
        .run();
    } catch (error) {
      throw d1Error("dead_letter_billing_report", error);
    }
  }

  /** Dead-lettered rows, most recently given up on first (issue #143). */
  async listDeadLetteredBillingReports(
    limit: number,
  ): Promise<StoredBillingReportOutboxEntry[]> {
    try {
      const result = await this.controlDb
        .prepare(
          `${SELECT_OUTBOX_COLUMNS} WHERE dead_lettered_at_unix IS NOT NULL ` +
            "ORDER BY dead_lettered_at_unix DESC LIMIT ?",
        )
        .bind(Math.max(0, Math.trunc(limit)))
        .all<OutboxRow>();
      return result.results.map(outboxFromRow);
    } catch (error) {
      throw d1Error("list_dead_lettered_billing_reports", error);
    }
  }

  /**
   * Operator-driven replay of a dead-lettered row (issue #388), as a guarded
   * CAS: the UPDATE fires ONLY from the dead-lettered state, so a replay of a
   * still-live row cannot silently reset its attempt schedule. Unlike the Rust
   * REST path (which had no `UPDATE ... RETURNING` and needed a follow-up
   * SELECT), the native binding returns the reloaded row in the same statement.
   */
  async replayDeadLetteredBillingReport(
    id: string,
    nextAttemptUnix: number,
    nowUnix: number,
  ): Promise<ReplayDeadLetterOutcome> {
    try {
      const updated = await this.controlDb
        .prepare(
          "UPDATE billing_report_outbox SET dead_lettered_at_unix = NULL, attempts = 0, " +
            "next_attempt_unix = ?, updated_at_unix = ? " +
            "WHERE id = ? AND dead_lettered_at_unix IS NOT NULL " +
            "RETURNING id, event_json, attempts, next_attempt_unix, dead_lettered_at_unix",
        )
        .bind(nextAttemptUnix, nowUnix, id)
        .all<OutboxRow>();
      const row = updated.results[0];
      if (row !== undefined) {
        return { kind: "replayed", entry: outboxFromRow(row) };
      }
    } catch (error) {
      throw d1Error("replay_dead_lettered_billing_report", error);
    }
    const entry = await this.getBillingReportOutboxEntry(id);
    return entry === undefined
      ? { kind: "not_found" }
      : { kind: "not_dead_lettered", entry };
  }

  /** Delete a delivered row (the sweeper's reap step). */
  async deleteBillingReport(id: string): Promise<void> {
    try {
      await this.controlDb
        .prepare("DELETE FROM billing_report_outbox WHERE id = ?")
        .bind(id)
        .run();
    } catch (error) {
      throw d1Error("delete_billing_report", error);
    }
  }

  /**
   * Enqueue an outbox row on its own — the non-atomic sibling, kept because the
   * Rust crate exposes it and a re-publish path needs it. Prefer
   * {@link appendBillingEventWithOutboxEnqueue}: this one can land an outbox row
   * without a claimed metering event.
   */
  async enqueueBillingReport(
    id: string,
    eventJson: string,
    nextAttemptUnix: number,
  ): Promise<void> {
    try {
      await this.controlDb
        .prepare(
          "INSERT INTO billing_report_outbox " +
            "(id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, " +
            " updated_at_unix, event_json) " +
            "VALUES (?, 0, ?, NULL, unixepoch(), unixepoch(), ?) " +
            "ON CONFLICT (id) DO NOTHING",
        )
        .bind(id, nextAttemptUnix, eventJson)
        .run();
    } catch (error) {
      throw d1Error("enqueue_billing_report", error);
    }
  }
}
