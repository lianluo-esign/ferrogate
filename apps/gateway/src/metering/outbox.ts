/**
 * The durable billing-report outbox — port of the `billing_report_outbox` table
 * and the state moves `sweep_billing_outbox_once` makes on it
 * (`crates/ferrogate-gateway/src/state_billing_metering.rs`, issues
 * #137 / #143 / #150 / #151 / #388).
 *
 * Why an outbox at all, restated from the Rust source comment so it does not
 * get optimised away here: "Rather than a fire-and-forget POST that would be
 * lost if billing is unavailable, the event is written to a persistent outbox
 * and a background sweeper delivers it (idempotent on the ledger entry id), so
 * a charge survives a billing outage or a gateway restart."
 *
 * The three constants and the backoff curve are the Rust ones verbatim; they
 * are load-bearing (20 attempts across that ladder is ≈15 minutes of retries,
 * chosen to ride out a billing restart without letting a permanently
 * undeliverable report starve the sweeper batch).
 */
import type { MeteredCharge, MeteringOutbox, OutboxRecord } from "./ports.js";

/** `BILLING_OUTBOX_BATCH` (`state.rs:7055`). */
export const BILLING_OUTBOX_BATCH = 100;

/** `MAX_BILLING_OUTBOX_ATTEMPTS` (`state.rs:7063`) — dead-letter past this. */
export const MAX_BILLING_OUTBOX_ATTEMPTS = 20;

/**
 * `billing_outbox_backoff_secs` (`state.rs:7067`) — capped exponential backoff
 * by PRIOR attempt count: 1, 2, 4, 8, 16, 32, 60, 60, …
 */
export function billingOutboxBackoffSeconds(attempts: number): number {
  const shift = Math.min(Math.max(Math.trunc(attempts), 0), 6);
  return Math.min(2 ** shift, 60);
}

interface MutableRecord {
  readonly id: string;
  readonly charge: MeteredCharge;
  attempts: number;
  nextAttemptUnix: number;
  deadLetteredAtUnix?: number | undefined;
  settled: boolean;
}

function frozen(record: MutableRecord): OutboxRecord {
  return {
    id: record.id,
    charge: record.charge,
    attempts: record.attempts,
    nextAttemptUnix: record.nextAttemptUnix,
    settled: record.settled,
    ...(record.deadLetteredAtUnix !== undefined
      ? { deadLetteredAtUnix: record.deadLetteredAtUnix }
      : {}),
  };
}

/**
 * In-isolate {@link MeteringOutbox}.
 *
 * Insertion order plus a `Map` keyed on the ledger entry id gives both
 * properties the SQL relies on: `ON CONFLICT (id) DO NOTHING` (the key) and
 * `ORDER BY next_attempt_unix ASC` (the sort in {@link listDue}).
 *
 * PORT-TODO(inventory-data-billing §2.5 "billing_report_outbox"): this survives
 * an isolate, not an isolate EVICTION. The durable row is written by
 * {@link D1LedgerStore} in the same batch as the metering insert (exactly as
 * `append_billing_event_with_outbox_enqueue` does), so once the `[[d1_databases]]`
 * binding is declared a charge that outlives this buffer is still recoverable
 * by a Cron-triggered sweep of `billing_report_outbox`. Until then this buffer
 * is the only retry state, which is why {@link MeteringOutbox.enqueue} is
 * synchronous — see the port doc.
 */
export class InMemoryMeteringOutbox implements MeteringOutbox {
  readonly #rows = new Map<string, MutableRecord>();

  enqueue(charge: MeteredCharge, nextAttemptUnix: number): boolean {
    if (this.#rows.has(charge.id)) {
      return false;
    }
    this.#rows.set(charge.id, {
      id: charge.id,
      charge,
      attempts: 0,
      nextAttemptUnix,
      deadLetteredAtUnix: undefined,
      settled: false,
    });
    return true;
  }

  markSettled(id: string): void {
    const row = this.#rows.get(id);
    if (row !== undefined) {
      row.settled = true;
    }
  }

  listDue(nowUnix: number, limit: number): OutboxRecord[] {
    return [...this.#rows.values()]
      .filter((row) => row.deadLetteredAtUnix === undefined && row.nextAttemptUnix <= nowUnix)
      .sort((left, right) => left.nextAttemptUnix - right.nextAttemptUnix)
      .slice(0, limit)
      .map(frozen);
  }

  delete(id: string): void {
    this.#rows.delete(id);
  }

  reschedule(id: string, nextAttemptUnix: number): void {
    const row = this.#rows.get(id);
    if (row === undefined) {
      return;
    }
    row.attempts += 1;
    row.nextAttemptUnix = nextAttemptUnix;
  }

  deadLetter(id: string, nowUnix: number): void {
    const row = this.#rows.get(id);
    if (row === undefined) {
      return;
    }
    row.attempts += 1;
    row.deadLetteredAtUnix = nowUnix;
  }

  deadLetters(): OutboxRecord[] {
    return [...this.#rows.values()]
      .filter((row) => row.deadLetteredAtUnix !== undefined)
      .map(frozen);
  }

  replayDeadLetter(id: string, nextAttemptUnix: number): boolean {
    const row = this.#rows.get(id);
    if (row === undefined || row.deadLetteredAtUnix === undefined) {
      return false;
    }
    row.deadLetteredAtUnix = undefined;
    row.attempts = 0;
    row.nextAttemptUnix = nextAttemptUnix;
    return true;
  }

  get(id: string): OutboxRecord | undefined {
    const row = this.#rows.get(id);
    return row === undefined ? undefined : frozen(row);
  }

  get size(): number {
    return this.#rows.size;
  }

  /** Every row, dead-lettered included — for assertions and admin listings. */
  all(): OutboxRecord[] {
    return [...this.#rows.values()].map(frozen);
  }
}
