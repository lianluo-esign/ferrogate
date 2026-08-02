/**
 * The in-memory {@link LedgerStore} — the shipped default, and the reference
 * semantics the D1 implementation has to reproduce.
 *
 * Port of `ferrogate_billing::InMemoryLedgerSink` (whose TS form lives in
 * `@ferrogate/billing`) lifted to the async, `bigint`-credit, outcome-typed
 * shape the Cloudflare port needs:
 *
 *  - `record` is idempotent on the ledger entry id, which for a settled request
 *    is `ferrogate:provider-attempt:{request_id}:provider-attempt:{n}`. A
 *    byte-equal replay returns `duplicate` (Rust `Ok(false)`); a replay with
 *    DIFFERENT settlement data returns `conflict` (Rust
 *    `BillingError("billing_idempotency_conflict")`, HTTP 409). The distinction
 *    matters: the first is a healthy retry, the second is data corruption and
 *    must never be quietly absorbed.
 *  - credits accumulate in `bigint`. `LedgerTotals.total_credits` is an `f64`
 *    in Rust and in `@ferrogate/billing`; a running total of micro-USD across a
 *    month passes 2^53 at ~$9e9 of traffic, and after that an `f64` accumulator
 *    stops counting whole credits. {@link MeteredTotals.credits} cannot.
 */
import {
  type LedgerListFilter,
  ledgerFilterMatches,
  sameProviderAttemptSettlement,
} from "@ferrogate/billing";
import type { LedgerStore, LedgerWriteOutcome, MeteredCharge, MeteredTotals } from "./ports.js";

/**
 * Whether two charges for the same id are the SAME settlement.
 *
 * The entry comparison is `@ferrogate/billing`'s structural equality (the port
 * of Rust's `PartialEq` on `LedgerEntry`, i.e. `same_provider_attempt_
 * settlement`); the credit comparison is added because the integer-credit
 * figure is authoritative here and a divergence in it is a divergence in the
 * charge even when the `f64` fields happen to agree.
 */
export function sameSettlement(left: MeteredCharge, right: MeteredCharge): boolean {
  return left.credits === right.credits && sameProviderAttemptSettlement(left.entry, right.entry);
}

/** Aggregate charges in the integer domain. */
export function meteredTotals(charges: Iterable<MeteredCharge>): MeteredTotals {
  let entries = 0;
  let credits = 0n;
  let totalTokens = 0n;
  let costUsd = 0;
  for (const charge of charges) {
    entries += 1;
    credits += charge.credits;
    totalTokens += BigInt(charge.entry.usage.total_tokens);
    costUsd += charge.entry.cost.total_cost;
  }
  return { entries, credits, totalTokens, costUsd };
}

/** In-memory, idempotent {@link LedgerStore}. */
export class InMemoryLedgerStore implements LedgerStore {
  readonly #rows = new Map<string, MeteredCharge>();

  // eslint-disable-next-line @typescript-eslint/require-await -- the port is async because D1 is.
  async record(charge: MeteredCharge): Promise<LedgerWriteOutcome> {
    const existing = this.#rows.get(charge.id);
    if (existing !== undefined) {
      return sameSettlement(existing, charge)
        ? { status: "duplicate" }
        : { status: "conflict", existing };
    }
    this.#rows.set(charge.id, charge);
    return { status: "recorded" };
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- see `record`.
  async get(id: string): Promise<MeteredCharge | undefined> {
    return this.#rows.get(id);
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- see `record`.
  async list(filter: LedgerListFilter, offset: number, limit: number): Promise<MeteredCharge[]> {
    return this.#matching(filter).slice(offset, offset + limit);
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- see `record`.
  async totals(filter: LedgerListFilter = {}): Promise<MeteredTotals> {
    return meteredTotals(this.#matching(filter));
  }

  /** Every stored charge, insertion-ordered. Test/admin affordance. */
  get charges(): readonly MeteredCharge[] {
    return [...this.#rows.values()];
  }

  get size(): number {
    return this.#rows.size;
  }

  #matching(filter: LedgerListFilter): MeteredCharge[] {
    return [...this.#rows.values()].filter((charge) =>
      ledgerFilterMatches(filter, charge.entry.tenant),
    );
  }
}
