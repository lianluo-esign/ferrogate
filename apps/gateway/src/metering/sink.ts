/**
 * `MeteringUsageSink` — the durable `UsageSink` the inference data plane's
 * `deps.usage` slot takes.
 *
 * It is the Cloudflare shape of `state_billing_metering.rs::settle_request`:
 *
 *   Usage (observed)                                   this module
 *     → BillingEvent                                   `event.ts`
 *     → charge(PriceBook, event)                       `@ferrogate/billing`
 *         · gateway-settled cost is AUTHORITATIVE       (#135)
 *         · >5% divergence is warned, never overridden  (#152)
 *         · no cost + no rule ⇒ price_not_found, FAIL CLOSED (#129)
 *     → integer credits (bigint)                       `credits.ts`
 *     → outbox.enqueue  (SYNCHRONOUS, id-keyed)        `outbox.ts`
 *     → scheduler.waitUntil(flush())                   `ctx.waitUntil`
 *         → ledger.record  (idempotent)                `ledger.ts` / `d1.ts`
 *         → publisher.deliver → outbox.delete          `publisher.ts`
 *         → on failure: backoff, then dead-letter      (#143)
 *
 * ## The two timing shapes, and why the split is where it is
 *
 * `UsageSink.record` is `void` and must never throw, because the request path
 * calls it from two very different places:
 *
 *  - **Non-streaming.** `handlers.ts` calls it after buffering the provider
 *    body, BEFORE returning the `Response`. Doing durable I/O inline here would
 *    add a storage round-trip to every request's latency.
 *  - **Streaming.** The `sseUsageTap` calls it from the transform's `flush()`
 *    — or from its `cancel()` when the client hangs up mid-stream. By then the
 *    response headers and most of the body are long gone to the client; there
 *    is no request left to delay, and equally no request left to block on.
 *
 * So `record` does only the CPU-bound half (build event → price → convert to
 * integer credits → capture in the outbox) synchronously, and hands the I/O
 * half to {@link MeteringScheduler}. In production that scheduler is
 * `ctx.waitUntil`, which is what keeps the isolate alive past the flushed
 * response without the client waiting on it. A client disconnect changes
 * nothing about this path: the tap still reports whatever usage it scraped, and
 * whatever it scraped is what gets charged.
 *
 * ## Fail-closed
 *
 * If the rate card has no rule for `(provider, provider_model)` and the request
 * path settled no cost, `charge()` throws `price_not_found` and this sink
 * records NOTHING — no ledger row, no outbox row, no delivery. That is the
 * point of the Rust behaviour (#129): the alternative to refusing is billing
 * zero, and a model that silently bills zero is a free-inference bug, not a
 * degraded-metering one. The refusal is counted and surfaced through
 * {@link MeteringDiagnostics.onPriceNotFound} and {@link MeteringUsageSink.unpriced}.
 */
import {
  BillingError,
  PriceBook,
  charge as chargeEvent,
  ledgerEntryId,
  type BillingEvent,
  type LedgerEntry,
} from "@ferrogate/billing";
import type { Usage, UsageSink } from "../inference/ports.js";
import { usdToCredits } from "./credits.js";
import { billingEventFromUsage } from "./event.js";
import { InMemoryLedgerStore } from "./ledger.js";
import {
  BILLING_OUTBOX_BATCH,
  InMemoryMeteringOutbox,
  MAX_BILLING_OUTBOX_ATTEMPTS,
  billingOutboxBackoffSeconds,
} from "./outbox.js";
import { InMemoryBillingReportPublisher } from "./publisher.js";
import {
  TrackingScheduler,
  emptyMeteringStats,
  systemClock,
  type BillingReportPublisher,
  type LedgerStore,
  type MeteredCharge,
  type MeteringClock,
  type MeteringDiagnostics,
  type MeteringOutbox,
  type MeteringScheduler,
  type MeteringStats,
  type OutboxRecord,
} from "./ports.js";

/** A charge that could not be priced — kept for operator inspection. */
export interface UnpricedUsage {
  readonly id: string;
  readonly requestId: string;
  readonly provider: string;
  readonly providerModel: string;
  readonly message: string;
  readonly event: BillingEvent;
}

/** Construction options. Every one has a runnable default. */
export interface MeteringSinkOptions {
  /**
   * The rate card. Defaults to `PriceBook.withDefaultRateCard()` — the seeded
   * per-vendor card, which is what makes the fail-closed path a real signal
   * (an UNKNOWN model, not "nothing is configured yet").
   */
  readonly priceBook?: PriceBook;
  readonly ledger?: LedgerStore;
  readonly outbox?: MeteringOutbox;
  readonly publisher?: BillingReportPublisher;
  /** `ctx.waitUntil` in production; see {@link executionContextScheduler}. */
  readonly scheduler?: MeteringScheduler;
  readonly clock?: MeteringClock;
  readonly diagnostics?: MeteringDiagnostics;
  /** Worker deployment identity, stamped onto every event. */
  readonly clusterId?: string;
  readonly nodeId?: string;
  /**
   * The gateway-settled cost for a request, when the data plane priced it
   * itself.
   *
   * PORT-TODO(inventory-data-billing §2.3 "source-of-truth rule", issue #135):
   * the Rust gateway settles `cost_usd` BEFORE dispatch because it enforces the
   * tenant budget against that figure, and `charge()` then treats it as
   * authoritative. `apps/gateway` has no budget enforcement yet (that arrives
   * with `@ferrogate/policy`), so nothing supplies one and the rate card is the
   * source. The seam is here — and exercised — so the authoritative branch and
   * its divergence warning are live the moment budgets land, rather than being
   * retro-fitted onto a path that never had them.
   */
  readonly settledCostUsd?: (usage: Usage) => number | undefined;
}

/**
 * Durable metering for the inference data plane.
 *
 * Structurally an `UsageSink`, so the wiring is literally
 * `inferenceRouteModule({ usage: sink })` — see `index.ts`.
 */
export class MeteringUsageSink implements UsageSink {
  readonly #priceBook: PriceBook;
  readonly #ledger: LedgerStore;
  readonly #outbox: MeteringOutbox;
  readonly #publisher: BillingReportPublisher;
  readonly #scheduler: MeteringScheduler;
  readonly #clock: MeteringClock;
  readonly #diagnostics: MeteringDiagnostics;
  readonly #clusterId: string | undefined;
  readonly #nodeId: string | undefined;
  readonly #settledCostUsd: ((usage: Usage) => number | undefined) | undefined;
  readonly #stats: MeteringStats = emptyMeteringStats();
  readonly #unpriced: UnpricedUsage[] = [];
  #draining: Promise<void> | undefined;

  constructor(options: MeteringSinkOptions = {}) {
    this.#priceBook = options.priceBook ?? PriceBook.withDefaultRateCard();
    this.#ledger = options.ledger ?? new InMemoryLedgerStore();
    this.#outbox = options.outbox ?? new InMemoryMeteringOutbox();
    this.#publisher = options.publisher ?? new InMemoryBillingReportPublisher();
    this.#scheduler = options.scheduler ?? new TrackingScheduler();
    this.#clock = options.clock ?? systemClock;
    this.#diagnostics = options.diagnostics ?? {};
    this.#clusterId = options.clusterId;
    this.#nodeId = options.nodeId;
    this.#settledCostUsd = options.settledCostUsd;
  }

  // -------------------------------------------------------------------------
  // UsageSink
  // -------------------------------------------------------------------------

  /**
   * `UsageSink.record` — synchronous, never throws.
   *
   * Every failure mode below is caught: the request has already been served (or
   * is being served) by the time this runs, and a metering error must not
   * become a client-visible one. The Rust sink had the same contract — a
   * poisoned-lock error went to the log, never to the caller.
   */
  record(usage: Usage): void {
    try {
      this.#settle(usage);
    } catch (error) {
      this.#report("record", error);
      this.#diagnostics.onEnqueueFailure?.({ requestId: usage.requestId, error });
    }
  }

  // -------------------------------------------------------------------------
  // Draining
  // -------------------------------------------------------------------------

  /**
   * Drain the outbox now.
   *
   * Drains are SERIALIZED, not deduplicated: each call appends a drain behind
   * whatever is already running. Overlapping drains would each pull the same
   * due batch and attempt the same delivery twice — harmless for the charge
   * (the ledger is idempotent) but a real duplicate report downstream, which is
   * the thing this whole module exists to prevent. Never rejects.
   */
  async flush(): Promise<void> {
    const chained = (this.#draining ?? Promise.resolve()).then(
      () => this.#drain(),
      () => this.#drain(),
    );
    this.#draining = chained;
    try {
      await chained;
    } finally {
      if (this.#draining === chained) {
        this.#draining = undefined;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Observability
  // -------------------------------------------------------------------------

  /** Counters, mirroring the Rust `billing_*_total` metrics. */
  get stats(): Readonly<MeteringStats> {
    return { ...this.#stats };
  }

  /** Charges refused for want of a price (#129). Never billed, never lost. */
  get unpriced(): readonly UnpricedUsage[] {
    return this.#unpriced;
  }

  /** The durable store, for the admin/read surface. */
  get ledger(): LedgerStore {
    return this.#ledger;
  }

  /** The outbox, for the admin dead-letter surface (#143/#388). */
  get outbox(): MeteringOutbox {
    return this.#outbox;
  }

  get priceBook(): PriceBook {
    return this.#priceBook;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  #settle(usage: Usage): void {
    const now = this.#clock.nowUnixSeconds();
    const settledCostUsd = this.#settledCostUsd?.(usage);
    const event = billingEventFromUsage(usage, {
      nowUnixSeconds: now,
      ...(settledCostUsd !== undefined ? { settledCostUsd } : {}),
      ...(this.#clusterId !== undefined ? { clusterId: this.#clusterId } : {}),
      ...(this.#nodeId !== undefined ? { nodeId: this.#nodeId } : {}),
      diagnostics: this.#diagnostics,
    });
    const id = ledgerEntryId(event);

    const entry = this.#price(event, id);
    if (entry === undefined) {
      return; // fail-closed; already counted and reported
    }

    const charge: MeteredCharge = {
      id,
      requestId: event.request_id,
      event,
      entry,
      credits: usdToCredits(entry.cost.total_cost, this.#priceBook.credits_per_usd),
      occurredAtUnix: event.occurred_at_unix ?? now,
    };

    this.#stats.charged += 1;
    if (!this.#outbox.enqueue(charge, now)) {
      // `ON CONFLICT (id) DO NOTHING`: the id is already queued, so this replay
      // must not produce a second delivery.
      this.#stats.outboxDuplicates += 1;
    }
    this.#scheduler.waitUntil(this.flush());
  }

  /** `charge()`, with the fail-closed branch made explicit. */
  #price(event: BillingEvent, id: string): LedgerEntry | undefined {
    try {
      return chargeEvent(this.#priceBook, event, (divergence) => {
        this.#stats.divergences += 1;
        this.#guard(() => this.#diagnostics.onDivergence?.(divergence), "divergence");
      });
    } catch (error) {
      if (error instanceof BillingError && error.code === "price_not_found") {
        this.#stats.priceNotFound += 1;
        this.#unpriced.push({
          id,
          requestId: event.request_id,
          provider: event.provider,
          providerModel: event.provider_model,
          message: error.message,
          event,
        });
        this.#guard(
          () =>
            this.#diagnostics.onPriceNotFound?.({
              requestId: event.request_id,
              provider: event.provider,
              providerModel: event.provider_model,
              message: error.message,
            }),
          "price_not_found",
        );
        return undefined;
      }
      throw error;
    }
  }

  /**
   * One sweeper pass — `sweep_billing_outbox_once`, looped so a charge enqueued
   * WHILE the pass is running is picked up instead of waiting for the next
   * request.
   *
   * Each id is attempted at most once per drain. Without that guard a
   * rescheduled record whose backoff (1s) elapses mid-drain would be retried
   * inside the same pass, and a permanently-failing downstream would spin
   * through all 20 attempts in one `waitUntil` — the exact starvation
   * `MAX_BILLING_OUTBOX_ATTEMPTS` exists to bound.
   */
  async #drain(): Promise<void> {
    const attempted = new Set<string>();
    try {
      for (;;) {
        const now = this.#clock.nowUnixSeconds();
        const due = this.#outbox
          .listDue(now, BILLING_OUTBOX_BATCH)
          .filter((record) => !attempted.has(record.id));
        if (due.length === 0) {
          return;
        }
        for (const record of due) {
          attempted.add(record.id);
          await this.#deliverOnce(record, now);
        }
      }
    } catch (error) {
      // `listDue` itself failing must not reject into `waitUntil`; the rows are
      // still queued and the next request drains them.
      this.#report("drain", error);
    }
  }

  /**
   * One outbox row, one pass: settle it if it has not been settled, then
   * deliver it.
   *
   * The `settled` bit is what keeps the two halves distinguishable on a retry —
   * see {@link OutboxRecord.settled}. A row that has already settled skips
   * straight to delivery, which is exactly what `sweep_billing_outbox_once`
   * does (it only ever calls `deliver_once`).
   */
  async #deliverOnce(record: OutboxRecord, now: number): Promise<void> {
    const { id, charge, attempts } = record;
    try {
      if (!record.settled) {
        const outcome = await this.#ledger.record(charge);
        if (outcome.status === "conflict") {
          // Same idempotency key, different settlement (#213). Retrying cannot
          // fix it and delivering it would corrupt the downstream, so it stops
          // here and stays visible as a dead letter.
          this.#stats.conflicts += 1;
          this.#guard(
            () => this.#diagnostics.onIdempotencyConflict?.({ id, requestId: charge.requestId }),
            "conflict",
          );
          this.#outbox.deadLetter(id, now);
          return;
        }
        if (outcome.status === "duplicate") {
          // Rust: `if !recorded { return Ok(()); }` — a replay skips the
          // metrics, the counters and the downstream report entirely. Dropping
          // the row is what stops a replay from producing a second report; the
          // ORIGINAL row already delivered (or is still queued to).
          this.#stats.duplicates += 1;
          this.#outbox.delete(id);
          return;
        }
        this.#stats.recorded += 1;
        this.#outbox.markSettled(id);
      }
      await this.#publisher.deliver(charge);
      this.#stats.delivered += 1;
      this.#outbox.delete(id);
    } catch (error) {
      this.#stats.deliveryFailures += 1;
      this.#guard(
        () => this.#diagnostics.onDeliveryFailure?.({ id, attempts, error }),
        "delivery_failure",
      );
      const attemptsAfter = attempts + 1;
      if (attemptsAfter >= MAX_BILLING_OUTBOX_ATTEMPTS) {
        this.#outbox.deadLetter(id, now);
        this.#stats.deadLettered += 1;
        this.#guard(
          () => this.#diagnostics.onDeadLetter?.({ id, attempts: attemptsAfter }),
          "dead_letter",
        );
        return;
      }
      this.#outbox.reschedule(id, now + billingOutboxBackoffSeconds(attempts));
    }
  }

  /** Run an observability hook without letting it become a billing failure. */
  #guard(hook: () => void, stage: string): void {
    try {
      hook();
    } catch (error) {
      this.#report(stage, error);
    }
  }

  #report(stage: string, error: unknown): void {
    try {
      this.#diagnostics.onError?.(stage, error);
    } catch {
      // An `onError` that throws is the end of the line.
    }
  }
}

/** Convenience constructor mirroring the other `defaults.ts`-style factories. */
export function createMeteringUsageSink(options: MeteringSinkOptions = {}): MeteringUsageSink {
  return new MeteringUsageSink(options);
}
