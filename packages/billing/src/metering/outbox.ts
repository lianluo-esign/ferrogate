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
 * ## This buffer survives an isolate, not an isolate EVICTION — and that is fine
 *
 * It is deliberately only HALF the outbox, and no longer the half that carries
 * the durability guarantee. The DURABLE row is written by `D1LedgerStore.record`
 * into `billing_report_outbox` in the same `batch()` as the metering insert
 * (exactly as `append_billing_event_with_outbox_enqueue` does), and its whole
 * lifecycle now lives on the storage binding: `DurableOutboxStore.reap` on a
 * successful publish, `reschedule` on a failed one, `deadLetter` past
 * `MAX_BILLING_OUTBOX_ATTEMPTS`, and `listDue` for recovery. A charge whose
 * isolate was evicted between the ledger commit and the Queue publish is
 * re-published by `MeteringUsageSink.sweep`, which the `[triggers] crons` entry
 * in `wrangler.toml` calls once a minute through `scheduled` on
 * `src/worker.ts`'s default export.
 *
 * So this class is the FAST path — a per-isolate buffer that lets `enqueue` be
 * synchronous, which it has to be: `UsageSink.record` is a `void` method called
 * from a stream tap that may already be running after the response was flushed,
 * and an `async` capture would drop the charge on an isolate teardown between
 * `await` points. The durable row is what makes losing this buffer survivable.
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
