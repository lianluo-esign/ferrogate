import type {
  BillingReportPublisher,
  MeteredCharge,
  MeteringQueue,
  MeteringQueueMessage,
} from "./ports.js";
/**
 * Downstream delivery of a settled charge — port of
 * `ferrogate-gateway/src/billing_client.rs`'s `BillingReporter::deliver_once`,
 * whose contract is "fail loudly so the outbox sweeper can retry with backoff;
 * idempotent on the billing side, so replay never double-bills".
 *
 * `inventory-data-billing.md` §2.5 names Cloudflare Queues as the natural
 * replacement for the DB-polled sweeper, so {@link QueueBillingReportPublisher}
 * is the production implementation: a Queue `send` that rejects arms the same
 * retry ladder the Rust HTTP POST did, and a Queue consumer with a dead-letter
 * queue replaces the sweeper loop.
 */
import { billingEventToWire, creditsToWire, ledgerEntryToWireDocument } from "./wire.js";

/** The Queue body for one settled charge. */
export function meteringQueueMessage(charge: MeteredCharge): MeteringQueueMessage {
  return {
    id: charge.id,
    request_id: charge.requestId,
    // Decimal string, never a JSON number — see `credits.ts`.
    credits: creditsToWire(charge.credits),
    occurred_at_unix: charge.occurredAtUnix,
    event: billingEventToWire(charge.event),
    entry: ledgerEntryToWireDocument(charge.entry),
  };
}

/**
 * Deliver onto a Cloudflare Queue.
 *
 * The message id IS the ledger entry id, so a consumer that has already applied
 * a message can drop the redelivery — which is what makes Queues' at-least-once
 * semantics safe for money here.
 */
export class QueueBillingReportPublisher implements BillingReportPublisher {
  readonly #queue: MeteringQueue;

  constructor(queue: MeteringQueue) {
    this.#queue = queue;
  }

  async deliver(charge: MeteredCharge): Promise<void> {
    await this.#queue.send(meteringQueueMessage(charge));
  }
}

/**
 * The default publisher: keeps deliveries in the isolate.
 *
 * This is NOT a no-op stand-in that hides an outage — `fail()` makes it reject
 * exactly like an unavailable downstream, which is how the outbox's retry and
 * dead-letter ladder is exercised for real rather than asserted about.
 */
export class InMemoryBillingReportPublisher implements BillingReportPublisher {
  readonly #delivered: MeteredCharge[] = [];
  #failure: Error | undefined;

  // eslint-disable-next-line @typescript-eslint/require-await -- the port is async.
  async deliver(charge: MeteredCharge): Promise<void> {
    if (this.#failure !== undefined) {
      throw this.#failure;
    }
    this.#delivered.push(charge);
  }

  /** Every charge accepted downstream, in order. */
  get delivered(): readonly MeteredCharge[] {
    return this.#delivered;
  }

  /** Simulate an unavailable downstream: every `deliver` rejects. */
  fail(reason = "billing downstream unavailable"): void {
    this.#failure = new Error(reason);
  }

  /** Downstream recovered. */
  recover(): void {
    this.#failure = undefined;
  }
}
