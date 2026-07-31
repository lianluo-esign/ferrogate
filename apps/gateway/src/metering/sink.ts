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
 *     → ctx.waitUntil(flush(rc))                       `middleware.ts`
 *         → ledger.record  (idempotent)                `d1.ts` (env.BILLING_DB)
 *         → publisher.deliver → outbox.delete          `publisher.ts` (env.BILLING)
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
 * half to `ctx.waitUntil` — the only thing on Workers that keeps an isolate's
 * I/O alive past a flushed response. A client disconnect changes nothing about
 * this path: the tap still reports whatever usage it scraped, and whatever it
 * scraped is what gets charged.
 *
 * ## Where the `ExecutionContext` comes from
 *
 * `record(u, rc?)` accepts it, and the durable drain runs on `rc.ctx` against
 * `rc.env` when it is supplied. When it is not, {@link MeteringUsageSink} that
 * was built with a {@link MeteringSinkOptions.bindings} resolver deliberately
 * does NOT drain itself — `meteringDrain()` in `./middleware.ts` owns the drain
 * from the middleware chain, where both `c.env` and `c.executionCtx` are in
 * scope, and it delays that drain until an SSE body has finished or been
 * abandoned. See that file for why a module-scoped "current ctx" is not an
 * option on workerd.
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
  type BillingEvent,
  type LedgerEntry,
  PriceBook,
  charge as chargeEvent,
  ledgerEntryId,
} from "@ferrogate/billing";
import type { Usage, UsageRecordContext, UsageSink } from "../inference/ports.js";
import { usdToCredits } from "./credits.js";
import { D1LedgerStore } from "./d1.js";
import { billingEventFromUsage } from "./event.js";
import { InMemoryLedgerStore } from "./ledger.js";
import {
  BILLING_OUTBOX_BATCH,
  InMemoryMeteringOutbox,
  MAX_BILLING_OUTBOX_ATTEMPTS,
  billingOutboxBackoffSeconds,
} from "./outbox.js";
import {
  type BillingReportPublisher,
  type DurableOutboxStore,
  type LedgerStore,
  type MeteredCharge,
  type MeteringClock,
  type MeteringDiagnostics,
  type MeteringOutbox,
  type MeteringScheduler,
  type MeteringStats,
  type OutboxRecord,
  TrackingScheduler,
  emptyMeteringStats,
  executionContextScheduler,
  systemClock,
} from "./ports.js";
import { InMemoryBillingReportPublisher, QueueBillingReportPublisher } from "./publisher.js";
import type { MeteringBindingResolver } from "./runtime.js";

/**
 * The two durable seams a drain writes through, resolved together.
 *
 * They are a pair because the outbox row's lifecycle spans both: it is deleted
 * only after the ledger write AND the downstream delivery have succeeded, so a
 * drain that mixed one request's D1 with another's Queue would delete a row on
 * the strength of a write that landed somewhere else.
 */
interface MeteringBackend {
  readonly ledger: LedgerStore;
  readonly publisher: BillingReportPublisher;
}

/**
 * How old a durable outbox intent must be before a sweep will touch it.
 *
 * A row younger than this is still inside the `waitUntil` of the request that
 * created it, and re-publishing it there would be a duplicate report bought for
 * nothing. 60s is the Rust sweeper's own cadence and comfortably longer than a
 * Worker's 30s CPU/wall budget for the deferred drain.
 */
export const OUTBOX_SWEEP_GRACE_SECONDS = 60;

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
  /**
   * The ledger used when no {@link MeteringSinkOptions.bindings} resolver
   * produces a durable one. Defaults to {@link InMemoryLedgerStore}.
   */
  readonly ledger?: LedgerStore;
  readonly outbox?: MeteringOutbox;
  /** Fallback publisher; see {@link MeteringSinkOptions.ledger}. */
  readonly publisher?: BillingReportPublisher;
  /**
   * Resolve the DURABLE backend from a request's Worker bindings.
   *
   * Supplying this (`meteringBindingsFromEnv`) changes one behaviour beyond
   * "write to D1 instead of memory", and it is the load-bearing one: a
   * `record()` that carries no {@link UsageRecordContext} NO LONGER SCHEDULES
   * ITS OWN DRAIN. It cannot — draining without an `env` would settle the
   * charge into the in-isolate fallback ledger and then DELETE the outbox row,
   * destroying the very charge the D1 write was supposed to persist. With a
   * resolver configured the drain belongs exclusively to whoever holds the
   * request context, i.e. `meteringDrain()` (`./middleware.ts`).
   *
   * Without it the sink behaves exactly as before: isolate-local ledger,
   * isolate-local outbox, drain scheduled from `record()`.
   */
  readonly bindings?: MeteringBindingResolver;
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
   * PORT-TODO(inventory-data-billing §2.3 "source-of-truth rule", issue #135) —
   * a missing upstream feature, not a platform limit. The Rust gateway settles
   * `cost_usd` BEFORE dispatch because it enforces the tenant budget against
   * that figure, and `charge()` then treats it as authoritative. Nothing in
   * `apps/gateway` does budget enforcement yet — that arrives with
   * `@ferrogate/policy`, in the request path, which this module does not own —
   * so nothing supplies a settled cost and the rate card is the source.
   *
   * The seam is here and it is EXERCISED (`test/metering/sink.test.ts`: the
   * authoritative branch records the supplied cost verbatim, and a >5%
   * divergence from the card is warned, never overridden). So the day budgets
   * land the change is `settledCostUsd: (u) => budget.settled(u)` at the
   * composition root, not a retro-fit onto a path that never had the branch.
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
  readonly #bindings: MeteringBindingResolver | undefined;
  /**
   * Durable backends, memoized ON THE ENV OBJECT.
   *
   * A `WeakMap` keyed by `env` — never a plain field — is what keeps this
   * concurrency-safe: two in-flight requests each resolve through their OWN
   * bindings and neither can observe the other's, while the `D1LedgerStore` /
   * `QueueBillingReportPublisher` wrappers are still built once per isolate
   * instead of once per request. It is the same device `modelsFromEnv` uses.
   */
  readonly #backends = new WeakMap<object, MeteringBackend>();
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
    this.#bindings = options.bindings;
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
   *
   * `rc` carries the request's bindings + `ExecutionContext`. When it is
   * present the durable drain is scheduled on `rc.ctx.waitUntil` against
   * `rc.env`; when it is absent see {@link MeteringSinkOptions.bindings} for
   * why the drain is then deliberately deferred to `meteringDrain()`.
   */
  record(usage: Usage, rc?: UsageRecordContext): void {
    try {
      this.#settle(usage, rc);
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
   *
   * `rc` selects the backend: with {@link MeteringSinkOptions.bindings}
   * configured and `rc.env` carrying a live `BILLING_DB` / `BILLING`, the drain
   * settles into D1 and publishes onto the Queue; otherwise it settles into the
   * construction-time fallbacks.
   */
  async flush(rc?: UsageRecordContext): Promise<void> {
    const chained = (this.#draining ?? Promise.resolve()).then(
      () => this.#drain(rc),
      () => this.#drain(rc),
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

  /**
   * The FALLBACK store, for the admin/read surface and for tests.
   *
   * With {@link MeteringSinkOptions.bindings} configured the durable store is
   * resolved per request from `env.BILLING_DB` and is NOT this object; use
   * {@link ledgerFor} when an `env` is in hand.
   */
  get ledger(): LedgerStore {
    return this.#ledger;
  }

  /** The store a request with these bindings settles into. */
  ledgerFor(env: unknown): LedgerStore {
    return this.#backend(env).ledger;
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

  /**
   * The durable backend for one request's bindings, memoized on the env object.
   *
   * Falls back per-binding, not all-or-nothing: a deployment with `BILLING_DB`
   * but no `BILLING` queue still persists the ledger, it just cannot report
   * downstream. Silently substituting a working half for a missing one is how a
   * partial misconfiguration turns into invisible data loss, so each half is
   * decided on its own.
   */
  #backend(env: unknown): MeteringBackend {
    const fallback: MeteringBackend = { ledger: this.#ledger, publisher: this.#publisher };
    if (this.#bindings === undefined || typeof env !== "object" || env === null) {
      return fallback;
    }
    const cached = this.#backends.get(env);
    if (cached !== undefined) {
      return cached;
    }
    const database = this.#bindings.database(env);
    const queue = this.#bindings.queue(env);
    const resolved: MeteringBackend = {
      ledger: database === undefined ? fallback.ledger : new D1LedgerStore(database),
      publisher: queue === undefined ? fallback.publisher : new QueueBillingReportPublisher(queue),
    };
    this.#backends.set(env, resolved);
    return resolved;
  }

  /** `ctx.waitUntil` when the request context is in hand, else the default. */
  #schedule(work: Promise<unknown>, rc: UsageRecordContext | undefined): void {
    const ctx = rc?.ctx;
    if (ctx !== undefined) {
      executionContextScheduler(ctx).waitUntil(work);
      return;
    }
    this.#scheduler.waitUntil(work);
  }

  #settle(usage: Usage, rc: UsageRecordContext | undefined): void {
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

    // With a binding resolver but no request context, the drain is NOT ours:
    // see `MeteringSinkOptions.bindings`. Draining here would settle the charge
    // into the fallback ledger and then delete the outbox row, which is a lost
    // charge dressed up as a successful one.
    if (this.#bindings === undefined || rc !== undefined) {
      this.#schedule(this.flush(rc), rc);
    }
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
  async #drain(rc: UsageRecordContext | undefined): Promise<void> {
    const attempted = new Set<string>();
    const backend = this.#backend(rc?.env);
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
          await this.#deliverOnce(record, now, backend);
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
  async #deliverOnce(record: OutboxRecord, now: number, backend: MeteringBackend): Promise<void> {
    const { id, charge, attempts } = record;
    try {
      if (!record.settled) {
        const outcome = await backend.ledger.record(charge);
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
      await backend.publisher.deliver(charge);
      this.#stats.delivered += 1;
      this.#outbox.delete(id);
      await this.#reap(backend, id);
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
        await this.#durable(backend, (outbox) => outbox.deadLetter(id, now), "dead_letter");
        return;
      }
      const nextAttemptUnix = now + billingOutboxBackoffSeconds(attempts);
      this.#outbox.reschedule(id, nextAttemptUnix);
      await this.#durable(
        backend,
        (outbox) => outbox.reschedule(id, attemptsAfter, nextAttemptUnix, now),
        "reschedule",
      );
    }
  }

  /**
   * Drop the DURABLE outbox intent once the report has been acknowledged.
   *
   * Best-effort by construction — the failure is reported, never rethrown.
   * Rethrowing would run the caller's `catch`, which counts a delivery failure
   * and arms a retry, i.e. a failure to delete would become a SECOND report of a
   * charge that was already delivered. Leaving the row instead is the safe
   * direction: a later sweep re-publishes it, and the Queue message id is the
   * ledger entry id, so a consumer that already applied it drops the redelivery.
   */
  async #reap(backend: MeteringBackend, id: string): Promise<void> {
    await this.#durable(backend, (outbox) => outbox.reap(id), "reap");
  }

  /** Run one durable-outbox state move, if this backend keeps one. */
  async #durable(
    backend: MeteringBackend,
    move: (outbox: DurableOutboxStore) => Promise<void>,
    stage: string,
  ): Promise<void> {
    const outbox = backend.ledger.outbox;
    if (outbox === undefined) {
      return; // an in-memory ledger writes no durable intent
    }
    try {
      await move(outbox);
    } catch (error) {
      this.#report(stage, error);
    }
  }

  /**
   * Recover charges stranded by an isolate that died between the ledger commit
   * and the Queue publish — `sweep_billing_outbox_once`, driven by a Cron
   * trigger instead of by a background thread (a Worker has none).
   *
   * A stranded row is money: the ledger says the tenant was charged and nothing
   * downstream was ever told. The in-isolate {@link MeteringOutbox} cannot find
   * it — that buffer died with the isolate — so the recovery reads the durable
   * `billing_report_outbox` table directly and re-publishes.
   *
   * Rows younger than {@link OUTBOX_SWEEP_GRACE_SECONDS} are skipped: they are
   * still owned by the `waitUntil` of the request that created them, and racing
   * that would produce a duplicate report for no benefit. Never rejects.
   */
  async sweep(rc: UsageRecordContext, nowUnixSeconds?: number): Promise<void> {
    const backend = this.#backend(rc.env);
    const outbox = backend.ledger.outbox;
    if (outbox === undefined) {
      return;
    }
    const now = nowUnixSeconds ?? this.#clock.nowUnixSeconds();
    try {
      const due = await outbox.listDue(now - OUTBOX_SWEEP_GRACE_SECONDS, BILLING_OUTBOX_BATCH);
      for (const record of due) {
        try {
          await backend.publisher.deliver(record.charge);
          this.#stats.delivered += 1;
          await outbox.reap(record.id);
          // The in-isolate row, if this isolate happens to be the one that
          // created it, must go too — otherwise the next request-time drain
          // delivers the same charge again.
          this.#outbox.delete(record.id);
        } catch (error) {
          this.#stats.deliveryFailures += 1;
          this.#guard(
            () =>
              this.#diagnostics.onDeliveryFailure?.({
                id: record.id,
                attempts: record.attempts,
                error,
              }),
            "delivery_failure",
          );
          const attemptsAfter = record.attempts + 1;
          if (attemptsAfter >= MAX_BILLING_OUTBOX_ATTEMPTS) {
            this.#stats.deadLettered += 1;
            this.#guard(
              () => this.#diagnostics.onDeadLetter?.({ id: record.id, attempts: attemptsAfter }),
              "dead_letter",
            );
            await this.#durable(backend, (o) => o.deadLetter(record.id, now), "dead_letter");
          } else {
            await this.#durable(
              backend,
              (o) =>
                o.reschedule(
                  record.id,
                  attemptsAfter,
                  now + billingOutboxBackoffSeconds(record.attempts),
                  now,
                ),
              "reschedule",
            );
          }
        }
      }
    } catch (error) {
      this.#report("sweep", error);
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
