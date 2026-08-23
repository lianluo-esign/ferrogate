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
 *         → ledger.record  (idempotent)                `d1.ts` (tenant DO; control compatibility fallback)
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
 * ## Fail-closed — on the CHARGE, not on the RECORD (#129 + #663)
 *
 * If the rate card has no rule for `(provider, provider_model)` and the request
 * path settled no cost, `charge()` throws `price_not_found` and this sink
 * writes NO ledger row, NO outbox row and makes NO delivery. That is the point
 * of the Rust behaviour (#129): the alternative to refusing is billing zero,
 * and a model that silently bills zero is a free-inference bug, not a
 * degraded-metering one. The refusal is counted and surfaced through
 * {@link MeteringDiagnostics.onPriceNotFound} and {@link MeteringUsageSink.unpriced}.
 *
 * What it does NOT do — and, before #663, wrongly did — is forget the request.
 * The early return sat upstream of every durable write, so a live 200 against a
 * model outside the 11-entry default rate card left `billing_ledger`,
 * `billing_events` and `billing_report_outbox` all at zero rows and printed
 * nothing. Rust never behaved that way: `state_billing_metering.rs` skipped only
 * the WALLET DEBIT for a `cost_usd: None` and called
 * `append_billing_event_with_outbox_enqueue` regardless. So the refusal now also
 * queues a cost-less `billing_events` row (`#persistUnpriced` →
 * {@link LedgerStore.recordEvent}), which carries the token counts and is
 * therefore re-priceable once the operator adds the rule.
 *
 * The other half of #663 is upstream of here: `src/index.ts` passes
 * `settledCostUsd: routePriceSettledCostUsd` (`./route-price.ts`), so a model
 * priced on its own `[[models]]` row settles at those prices and never reaches
 * the refusal at all.
 */
import {
  BillingError,
  type BillingEvent,
  type LedgerEntry,
  PriceBook,
  charge as chargeEvent,
  ledgerEntryId,
} from "@ferrogate/billing";
import type { Usage, UsageSink } from "../inference/ports.js";
import { chargeWithAgentRun } from "./agent-run.js";
import { billingAnalyticsFromEnv, writeBillingAnalyticsForEvent } from "./billing-analytics.js";
import {
  type BudgetAlertPorts,
  budgetAlertPortsFrom,
  budgetAlertScopesFor,
  dispatchBudgetThresholdAlerts,
} from "./budget-alerts.js";
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
import {
  type MeteringAttribution,
  type MeteringDrainContext,
  chargeWithTenantAttribution,
  d1UsageAggregateSink,
  eventWithTenantAttribution,
  usageWriteFor,
  withUsageDerivedRollups,
  withUsageProjectionRetry,
} from "./usage-ledger.js";
import {
  clearUsageProjectionRetry,
  deferUsageProjectionRetry,
  listUsageProjectionRetries,
  projectUsageProjectionRetry,
  projectUsageRollups,
  usageProjectionRequestFor,
} from "./usage-projection.js";

async function projectWithRetry(work: () => Promise<void>): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await work();
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

/** Resolve the billing authority from the charge, never from the draining request. */
function tenantIdForCharge(
  charge: MeteredCharge,
  attribution: MeteringAttribution | undefined,
): string | undefined {
  const attributed = chargeWithTenantAttribution(charge, attribution);
  const tenantId =
    attributed.event.tenant.organization_id ?? attributed.entry.tenant.organization_id;
  return tenantId === undefined || tenantId.trim() === "" ? undefined : tenantId;
}

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
  /**
   * The tenant database the usage aggregates accumulate into, when one is
   * bound. A separate seam, deliberately not folded into `ledger`: billing
   * settlement and usage aggregation have different idempotency claims even
   * when both are backed by the same tenant Durable Object.
   */
  readonly usageDatabase?: D1Database | undefined;
  /** Control-D1 destination for replace-style tenant-derived usage views. */
  readonly usageProjectionDatabase?: D1Database | undefined;
  /**
   * The proactive budget-threshold alerter (#170/#228), when this deployment
   * configures one — see `./budget-alerts.ts`.
   *
   * A FOURTH seam, resolved with the other three so it is memoized on the same
   * env object: it reads the CONTROL database's `quota_policies` and the TENANT
   * database's `usage_monthly_rollups`, and writes the TENANT database's
   * `budget_alert_notifications` claim. `undefined` whenever no webhook URL is
   * configured or no control database is bound — never a degraded in-isolate
   * substitute, because an alerter without a durable arbiter re-fires the same
   * webhook on every request past the crossing.
   */
  readonly budgetAlerts?: BudgetAlertPorts | undefined;
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

/**
 * How many unwritten unpriced events one isolate will hold (#663).
 *
 * The queue drains on the very next request's `waitUntil`, so it is normally
 * 0–1 deep; a non-trivial depth means the durable write itself is failing. The
 * cap exists so that failure degrades into "the oldest traces are dropped, and
 * `priceNotFound` vs `unpricedRecorded` shows by how much" rather than into an
 * isolate that grows until workerd evicts it — which would lose the whole queue
 * anyway, plus everything else in the isolate.
 */
export const MAX_PENDING_UNPRICED_EVENTS = 256;

/** Which source is allowed to settle an inference usage event. */
export type MeteringSettlementMode = "rate_card" | "serving_offering";

/** A charge that could not be priced — kept for operator inspection. */
export interface UnpricedUsage {
  readonly id: string;
  readonly requestId: string;
  readonly provider: string;
  readonly providerModel: string;
  readonly message: string;
  readonly event: BillingEvent;
}

/** A settled offering price is valid only when it is finite and non-negative. */
function usableSettledCostUsd(value: number | undefined): number | undefined {
  return value !== undefined && Number.isFinite(value) && value >= 0 ? value : undefined;
}

/**
 * Apply the billing-group multiplier (#945) to a settled cost.
 *
 * The multiplier is a POST-PRICE scalar: `cost × multiplier`. An ABSENT cost
 * stays absent (the rate-card / unpriced paths are untouched — there is nothing
 * to scale). An absent, non-finite, or negative multiplier FAILS OPEN to `1.0`,
 * i.e. the official price, so a corrupted or unresolved group can never move an
 * invoice. `0` is a legitimate multiplier (a comp) and scales to `$0`.
 */
function applyBillingMultiplier(
  cost: number | undefined,
  multiplier: number | undefined,
): number | undefined {
  if (cost === undefined) return undefined;
  const factor =
    multiplier !== undefined && Number.isFinite(multiplier) && multiplier >= 0 ? multiplier : 1;
  return cost * factor;
}

/** Construction options. Every one has a runnable default. */
export interface MeteringSinkOptions {
  /**
   * The legacy rate card. Defaults to `PriceBook.withDefaultRateCard()` for
   * `rate_card` mode. `serving_offering` mode keeps only its credit conversion
   * and never reads its model entries.
   */
  readonly priceBook?: PriceBook;
  /**
   * Settlement source for inference events. `rate_card` preserves the generic
   * legacy sink behavior. `serving_offering` is the production inference mode:
   * the route that answered must provide a usable settled cost, and the sink
   * never consults a wildcard card when it does not.
   */
  readonly settlementMode?: MeteringSettlementMode;
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
   * PORT-TODO(P: inventory-data-billing §2.3 "source-of-truth rule", issue #135) —
   * a missing upstream feature, not a platform limit. The Rust gateway settles
   * `cost_usd` BEFORE dispatch because it enforces the tenant budget against
   * that figure, and `charge()` then treats it as authoritative.
   *
   * The REASON this marker used to give is now out of date and is corrected
   * here rather than left to mislead: it said "nothing in `apps/gateway` does
   * budget enforcement yet". It does — `src/ratelimit/middleware.ts` runs the
   * Rust admission ladder, including `monthly_budget_usd` (step 2), the wallet
   * balance (step 3) and the no-oversell reservation (step 3b), through
   * `@ferrogate/policy` and `@ferrogate/storage`.
   *
   * What is still missing is narrower and is the actual gap: that ladder
   * enforces against ACCUMULATED spend (a rollup read and a wallet balance), it
   * does not PRICE THIS REQUEST before dispatch. So no call site has a
   * per-request settled figure to hand this hook, and the rate card remains the
   * source. Closing it means pricing the estimate at admission — the same place
   * the token estimate is already computed for TPM — and carrying that number
   * forward to settlement.
   *
   * The seam is here and it is EXERCISED (`test/metering/sink.test.ts`: the
   * authoritative branch records the supplied cost verbatim). In legacy
   * `rate_card` mode a >5% card divergence is still warned, never overridden.
   * Production inference uses `serving_offering`, where a missing result is
   * recorded as unpriced rather than delegated to a card.
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
  readonly #settlementMode: MeteringSettlementMode;
  readonly #stats: MeteringStats = emptyMeteringStats();
  readonly #unpriced: UnpricedUsage[] = [];
  /**
   * Unpriced usages whose durable trace has not been written yet (#663).
   *
   * A SECOND list rather than a flag on {@link #unpriced}, because the two have
   * different lifetimes: `#unpriced` is the operator's read surface and keeps
   * everything the isolate refused, while this one is a work queue that empties
   * as the rows land. Bounded by {@link MAX_PENDING_UNPRICED_EVENTS}.
   */
  readonly #pendingUnpriced: UnpricedUsage[] = [];
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
  readonly #backends = new WeakMap<object, Map<string, MeteringBackend>>();
  #draining: Promise<void> | undefined;

  constructor(options: MeteringSinkOptions = {}) {
    this.#settlementMode = options.settlementMode ?? "rate_card";
    const configuredPriceBook = options.priceBook ?? PriceBook.withDefaultRateCard();
    // A serving offering is the only inference price source in production.
    // Keep the configured credit conversion, but remove every model entry so a
    // wildcard card cannot participate in either settlement or divergence.
    this.#priceBook =
      this.#settlementMode === "serving_offering"
        ? PriceBook.default().withCreditsPerUsd(configuredPriceBook.credits_per_usd)
        : configuredPriceBook;
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
  record(usage: Usage, rc?: MeteringDrainContext): void {
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
   * configured and `rc.env` carrying tenant storage plus `BILLING`, the drain
   * settles into the tenant object and publishes onto the Queue; unscoped
   * compatibility traffic may use `BILLING_DB`, otherwise it uses fallbacks.
   */
  async flush(rc?: MeteringDrainContext): Promise<void> {
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
   * resolved per request from the charge's tenant authority (or
   * `env.BILLING_DB` for compatibility traffic) and is NOT this object; use
   * {@link ledgerFor} when an `env` is in hand.
   */
  get ledger(): LedgerStore {
    return this.#ledger;
  }

  /** The store a request with these bindings settles into. */
  ledgerFor(env: unknown, tenantId?: string): LedgerStore {
    return this.#backend(env, tenantId).ledger;
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
   * Falls back per-binding, not all-or-nothing: a deployment with tenant
   * storage but no `BILLING` queue still persists the tenant ledger, it just
   * cannot report downstream. Silently substituting a working half for a
   * missing one is how a partial misconfiguration turns into invisible data
   * loss, so each half is decided on its own.
   */
  #backend(env: unknown, tenantId?: string): MeteringBackend {
    const fallback: MeteringBackend = { ledger: this.#ledger, publisher: this.#publisher };
    if (this.#bindings === undefined || typeof env !== "object" || env === null) {
      return fallback;
    }
    const key = tenantId === undefined || tenantId === "" ? "__control__" : tenantId;
    let byTenant = this.#backends.get(env);
    if (byTenant === undefined) {
      byTenant = new Map<string, MeteringBackend>();
      this.#backends.set(env, byTenant);
    }
    const cached = byTenant.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const database = this.#bindings.database(env, tenantId);
    const queue = this.#bindings.queue(env);
    const usageDatabase = this.#bindings.usageDatabase?.(env, tenantId);
    const usageProjectionDatabase = this.#bindings.usageProjectionDatabase?.(env);
    const budgetAlerts = budgetAlertPortsFrom(env);
    const resolved: MeteringBackend = {
      ledger:
        database === undefined
          ? fallback.ledger
          : new D1LedgerStore(database, tenantId === undefined ? {} : { tenantId }),
      publisher: queue === undefined ? fallback.publisher : new QueueBillingReportPublisher(queue),
      ...(usageDatabase === undefined ? {} : { usageDatabase }),
      ...(usageProjectionDatabase === undefined ? {} : { usageProjectionDatabase }),
      ...(budgetAlerts === undefined ? {} : { budgetAlerts }),
    };
    byTenant.set(key, resolved);
    return resolved;
  }

  /** `ctx.waitUntil` when the request context is in hand, else the default. */
  #schedule(work: Promise<unknown>, rc: MeteringDrainContext | undefined): void {
    const ctx = rc?.ctx;
    if (ctx !== undefined) {
      executionContextScheduler(ctx).waitUntil(work);
      return;
    }
    this.#scheduler.waitUntil(work);
  }

  #settle(usage: Usage, rc: MeteringDrainContext | undefined): void {
    const now = this.#clock.nowUnixSeconds();
    // #945 — the billing-group multiplier, applied HERE as a post-price scalar,
    // exactly as `batch/provider-native.ts` scales the settled cost. It arrives
    // PRE-RESOLVED on the row (`Usage.billingMultiplier`) because this settle
    // path is synchronous and the multiplier is a per-`env` control-object read:
    // the inference handler resolves it during the request's async phase and
    // bakes it on. Absent/invalid ⇒ `1.0`, the official price (fail open). A
    // `0` multiplier is honoured — an enabled comp group settles at $0 — while
    // an absent settled cost stays absent so the rate-card path is unchanged.
    const offerCostUsd = this.#settledCostUsd?.(usage);
    const candidateSettledCostUsd = applyBillingMultiplier(offerCostUsd, usage.billingMultiplier);
    const providerCostUsd =
      usage.providerCostMultiplier === undefined
        ? undefined
        : applyBillingMultiplier(offerCostUsd, usage.providerCostMultiplier);
    const settledCostUsd =
      this.#settlementMode === "serving_offering"
        ? usableSettledCostUsd(candidateSettledCostUsd)
        : candidateSettledCostUsd;

    // #956 — the OFFER price (pre-multiplier) is stamped onto the event so the
    // Analytics Engine fleet mirror can report offer vs final even for a 0×
    // comp; the mirror WRITE itself happens in `#deliverOnce`, the only stage
    // that holds the request env carrying the `BILLING_ANALYTICS` binding.
    const event = billingEventFromUsage(usage, {
      nowUnixSeconds: now,
      ...(settledCostUsd !== undefined ? { settledCostUsd } : {}),
      ...(offerCostUsd !== undefined ? { offerCostUsd } : {}),
      ...(providerCostUsd !== undefined ? { providerCostUsd } : {}),
      ...(this.#clusterId !== undefined ? { clusterId: this.#clusterId } : {}),
      ...(this.#nodeId !== undefined ? { nodeId: this.#nodeId } : {}),
      diagnostics: this.#diagnostics,
    });
    const id = ledgerEntryId(event);

    if (this.#settlementMode === "serving_offering" && settledCostUsd === undefined) {
      this.#recordUnpriced(
        event,
        id,
        `serving offering for provider '${event.provider}' model '${event.provider_model}' did not provide a usable settled cost; wildcard rate-card settlement is disabled`,
      );
      this.#scheduleDrain(rc);
      return;
    }

    const entry = this.#price(event, id);
    if (entry === undefined) {
      // FAIL CLOSED ON THE CHARGE, NOT ON THE RECORD (#663).
      //
      // Nothing is billed and nothing is billed at zero — that is #129 and it
      // is unchanged. What changed is that the request no longer disappears:
      // `#price` has queued the event, and the drain scheduled below persists
      // it as a cost-less `billing_events` row, exactly as Rust's
      // `append_billing_event_with_outbox_enqueue` did for a `cost_usd: None`.
      // Returning here without scheduling is what made an unpriced model
      // produce no ledger row, no event row, no outbox row and no log line.
      this.#scheduleDrain(rc);
      return;
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

    this.#scheduleDrain(rc);
  }

  /**
   * Schedule the durable half, if it is ours to schedule.
   *
   * With a binding resolver but no request context, the drain is NOT ours: see
   * {@link MeteringSinkOptions.bindings}. Draining here would settle the charge
   * into the fallback ledger and then delete the outbox row, which is a lost
   * charge dressed up as a successful one. `meteringDrain()` owns it then.
   */
  #scheduleDrain(rc: MeteringDrainContext | undefined): void {
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
        return this.#recordUnpriced(event, id, error.message);
      }
      throw error;
    }
  }

  /** Record a charge refusal without ever collapsing NULL into a zero charge. */
  #recordUnpriced(event: BillingEvent, id: string, message: string): undefined {
    this.#stats.priceNotFound += 1;
    const refused: UnpricedUsage = {
      id,
      requestId: event.request_id,
      provider: event.provider,
      providerModel: event.provider_model,
      message,
      event,
    };
    this.#unpriced.push(refused);
    // #663 — queue the DURABLE trace. `#unpriced` above is isolate-local and dies
    // with the isolate; this list is what `#drain` writes out.
    this.#queueUnpricedEvent(refused);
    this.#guard(
      () =>
        this.#diagnostics.onPriceNotFound?.({
          requestId: event.request_id,
          provider: event.provider,
          providerModel: event.provider_model,
          message,
        }),
      "price_not_found",
    );
    return undefined;
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
  async #drain(rc: MeteringDrainContext | undefined): Promise<void> {
    const attempted = new Set<string>();
    const attribution = rc?.attribution;
    // #663 — FIRST, and outside the outbox loop, because an unpriced usage
    // produces no outbox row at all: it is not a charge and there is nothing to
    // deliver. A drain that only walked the outbox would return immediately on
    // `due.length === 0` and the trace would never be written.
    await this.#persistUnpriced(rc);
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
          const backend = this.#backend(rc?.env, tenantIdForCharge(record.charge, attribution));
          await this.#deliverOnce(record, now, backend, attribution, rc);
        }
      }
    } catch (error) {
      // `listDue` itself failing must not reject into `waitUntil`; the rows are
      // still queued and the next request drains them.
      this.#report("drain", error);
    }
  }

  /**
   * Queue an unpriced usage for its durable, cost-less trace (#663).
   *
   * Oldest-first eviction at the cap: a burst of refusals against ONE
   * misconfigured model is the expected shape, so the newest entries are the
   * ones an operator is most likely to still be able to act on, and the
   * `priceNotFound` counter still records that the older ones happened.
   */
  #queueUnpricedEvent(refused: UnpricedUsage): void {
    if (this.#pendingUnpriced.length >= MAX_PENDING_UNPRICED_EVENTS) {
      this.#pendingUnpriced.shift();
      this.#guard(
        () =>
          this.#diagnostics.onError?.(
            "unpriced_event_dropped",
            new Error(
              `pending unpriced metering events exceeded ${MAX_PENDING_UNPRICED_EVENTS}; the durable write is failing and the oldest trace was discarded`,
            ),
          ),
        "unpriced_event_dropped",
      );
    }
    this.#pendingUnpriced.push(refused);
  }

  /**
   * Write the queued unpriced usages as cost-less `billing_events` rows (#663) —
   * the Rust behaviour `append_billing_event_with_outbox_enqueue` had, where an
   * absent `cost_usd` skipped only the wallet debit.
   *
   * A store with no {@link LedgerStore.recordEvent} (the in-isolate fallback in
   * a deployment with no `BILLING_DB`) leaves the queue ALONE rather than
   * clearing it: the very next drain may resolve a durable backend from a
   * request that does carry bindings, and dropping the entries here would throw
   * away the only record that the usage happened. The cap bounds that.
   *
   * Best-effort and never rethrows, for the same reason every other drain step
   * is: this runs inside `waitUntil` and a bookkeeping failure must not surface
   * on the request path. A failed write goes back on the queue.
   */
  async #persistUnpriced(rc: MeteringDrainContext | undefined): Promise<void> {
    if (this.#pendingUnpriced.length === 0) {
      return;
    }
    const now = this.#clock.nowUnixSeconds();
    const pending = this.#pendingUnpriced.splice(0, this.#pendingUnpriced.length);
    for (const refused of pending) {
      try {
        // Unpriced events do not have a MeteredCharge wrapper, so apply the
        // same request-id guarded attribution directly before choosing the
        // tenant backend. A public route can produce an event without a tenant
        // field even though the authenticated request is tenant-scoped.
        const event = eventWithTenantAttribution(refused.event, rc?.attribution);
        const tenantId = event.tenant.organization_id;
        const backend = this.#backend(
          rc?.env,
          tenantId === undefined || tenantId.trim() === "" ? undefined : tenantId,
        );
        const ledger = backend.ledger;
        if (ledger.recordEvent === undefined) {
          this.#queueUnpricedEvent(refused);
          continue;
        }
        await ledger.recordEvent(event, refused.id, event.occurred_at_unix ?? now);
        this.#stats.unpricedRecorded += 1;
      } catch (error) {
        this.#queueUnpricedEvent(refused);
        this.#report("unpriced_event", error);
      }
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
  async #deliverOnce(
    record: OutboxRecord,
    now: number,
    backend: MeteringBackend,
    attribution: MeteringAttribution | undefined,
    rc: MeteringDrainContext | undefined,
  ): Promise<void> {
    const { id, attempts } = record;
    // #305/#522 — stamp the agent run that caused this spend, when the drain's
    // attribution belongs to THIS charge's request. A no-op otherwise, and
    // never a change to `id`: see `./agent-run.ts`. Applied before BOTH the
    // durable write and the downstream report, so the ledger row and the
    // published event agree.
    const charge = chargeWithTenantAttribution(
      chargeWithAgentRun(record.charge, attribution),
      attribution,
    );
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
          // The billing claim may have won before usage accumulation became
          // available. Re-run the idempotent tenant usage batch so this retry
          // can repair that gap, but never publish a second report for a
          // verified replay.
          this.#stats.duplicates += 1;
          await this.#accumulate(backend, charge, attribution, rc, false);
          this.#outbox.delete(id);
          return;
        }
        if (outcome.status === "recorded") this.#stats.recorded += 1;
        // Billing settlement and tenant usage accumulation are separate
        // batches. The usage batch has its own source-id claim and is safe to
        // retry after billing settlement has already won.
        await this.#accumulate(backend, charge, attribution, rc);
        this.#outbox.markSettled(id);
      }
      await backend.publisher.deliver(charge);
      this.#stats.delivered += 1;
      // #956 — mirror the delivered charge to Analytics Engine for the
      // CROSS-TENANT fleet view (offer + final price + dimensions). Here, not in
      // `#settle`, because only the drain holds the request env that carries the
      // `BILLING_ANALYTICS` binding. Best-effort: the tenant object's
      // `billing_events` row this same drain wrote is the invoicing authority,
      // and a mirror write can never fail a settled, delivered charge.
      if (rc?.env !== undefined) {
        const analytics = billingAnalyticsFromEnv(rc.env);
        if (analytics !== null) writeBillingAnalyticsForEvent(analytics, charge.event);
      }
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

  /**
   * The committed-token / monthly-spend FEEDBACK LOOP: accumulate this charge
   * into the tenant database's `tenant_contexts` + `usage_aggregate_rollups` +
   * `usage_monthly_rollups`, through `@ferrogate/storage`'s `D1UsageLedger`.
   *
   * Those three tables are the inputs of two admission gates that, before this
   * call existed, read a table nothing ever wrote:
   * `ratelimit/quota.ts::d1SpendSource` (the monthly USD budget) and
   * `ratelimit/token-budget.ts` (`api_keys.monthly_token_budget`).
   *
   * The tenant batch is authoritative and therefore fail-closed: a missing or
   * unavailable tenant object leaves the billing outbox unsettled so a later
   * drain can repair the under-count. The control projection is best-effort
   * after that object commit because its durable tenant-local retry intent can
   * rebuild the replace-style view without replaying additive usage.
   */
  async #accumulate(
    backend: MeteringBackend,
    charge: MeteredCharge,
    attribution: MeteringAttribution | undefined,
    rc: MeteringDrainContext | undefined,
    countStats = true,
  ): Promise<void> {
    const hasRequestDatabase =
      rc !== undefined && Object.prototype.hasOwnProperty.call(rc, "usageDatabase");
    const tenantId =
      (attribution?.requestId === charge.requestId ? attribution.tenantId : undefined) ??
      charge.event.tenant.organization_id ??
      "";
    const hasTenantResolver = tenantId !== "" && rc !== undefined && this.#bindings?.usageDatabase;
    const tenantDatabase = hasTenantResolver
      ? this.#bindings?.usageDatabase?.(rc.env, tenantId)
      : undefined;
    // A request context's database is only a convenience for the request that
    // created it. The durable outbox can be drained by a different tenant's
    // request, so once the resolver is available the charge's own tenant is the
    // only admissible routing key. Falling back to `rc.usageDatabase` here would
    // let a tenant-B replay write into tenant A's object.
    if (rc !== undefined && this.#bindings?.usageDatabase !== undefined && tenantId === "") {
      // Reject only the tenant rollup leg. The central billing ledger/report is
      // still authoritative for an unscoped platform charge and must not be
      // lost just because there is no object it can be routed to.
      this.#report("usage_tenant", new Error(`usage charge ${charge.id} has no tenant authority`));
      return;
    }
    const db = hasTenantResolver
      ? tenantDatabase
      : hasRequestDatabase
        ? (rc?.usageDatabase ?? undefined)
        : backend.usageDatabase;
    if (db === undefined && this.#bindings === undefined && !hasRequestDatabase) {
      return; // legacy in-memory/shared-D1 mode has no tenant authority to write
    }
    if (db === undefined && tenantId !== "") {
      throw new Error(`tenant usage database is unavailable for ${tenantId}`);
    }
    if (db === undefined) return;
    const projectionDatabase = backend.usageProjectionDatabase;
    const baseWrite = usageWriteFor(charge, attribution);
    if (baseWrite === null) {
      // No scope at all: `persistUsageAggregate` would refuse this, and rightly
      // — "a call folded into no scope is spend that no budget check can ever
      // see". Counted so an attribution regression is visible rather than
      // showing up months later as a budget that never trips.
      this.#stats.unattributed += 1;
      this.#guard(
        () => this.#diagnostics.onError?.("usage_unattributed", new Error(charge.requestId)),
        "usage_unattributed",
      );
      throw new Error(`usage charge ${charge.id} has no tenant/project scope`);
    }
    const derivedWrite = withUsageDerivedRollups(baseWrite, charge, attribution);
    const write =
      projectionDatabase === undefined
        ? derivedWrite
        : withUsageProjectionRetry(derivedWrite, charge.id);
    try {
      await d1UsageAggregateSink(db, tenantId).accumulate(write);
      if (countStats) this.#stats.aggregated += 1;
    } catch (error) {
      this.#report("usage_aggregate", error);
      // The outbox remains unsettled and is rescheduled by the caller. The
      // tenant claim makes the next attempt safe even if the control claim won.
      throw error;
    }
    if (projectionDatabase !== undefined) {
      try {
        await projectWithRetry(() =>
          projectUsageRollups(db, projectionDatabase, usageProjectionRequestFor(write)),
        );
        await clearUsageProjectionRetry(db, write.projectionRetry?.sourceId ?? charge.id);
      } catch (error) {
        // Object state is authoritative. The durable intent remains for the
        // scheduled repair and must not hold billing delivery hostage.
        this.#report("usage_projection", error);
      }
    }
    await this.#budgetAlerts(backend, charge, attribution);
  }

  /** Repair tenant-local control projection intents without replaying usage. */
  async sweepUsageProjections(
    rc: MeteringDrainContext,
    tenantIds: readonly string[],
    nowUnixSeconds?: number,
    batchSize = BILLING_OUTBOX_BATCH,
  ): Promise<void> {
    const backend = this.#backend(rc.env);
    const projectionDatabase = backend.usageProjectionDatabase;
    const bindings = this.#bindings;
    const resolveTenantDatabase = bindings?.usageDatabase;
    if (projectionDatabase === undefined || resolveTenantDatabase === undefined) return;
    const now = nowUnixSeconds ?? this.#clock.nowUnixSeconds();
    const pageSize = Math.max(1, Math.trunc(batchSize));
    for (const tenantId of tenantIds) {
      if (tenantId.trim() === "") continue;
      const tenantDatabase = resolveTenantDatabase(rc.env, tenantId);
      if (tenantDatabase === undefined) continue;
      try {
        for (;;) {
          const rows = await listUsageProjectionRetries(tenantDatabase, now, pageSize);
          if (rows.length === 0) break;
          let stateWriteFailed = false;
          for (const row of rows) {
            try {
              if (row.tenantId.trim() !== tenantId) {
                throw new Error(
                  `usage projection retry ${row.sourceId} belongs to ${row.tenantId}, not ${tenantId}`,
                );
              }
              await projectWithRetry(() =>
                projectUsageProjectionRetry(tenantDatabase, projectionDatabase, row),
              );
              await clearUsageProjectionRetry(tenantDatabase, row.sourceId);
            } catch (error) {
              try {
                await deferUsageProjectionRetry(tenantDatabase, row, now);
              } catch (deferError) {
                stateWriteFailed = true;
                this.#report("usage_projection_retry_defer", deferError);
              }
              this.#report("usage_projection_retry", error);
            }
          }
          // A due row whose retry-state update also failed would be returned
          // forever by the same page. Leave it for the next scheduled pass.
          if (stateWriteFailed) break;
        }
      } catch (error) {
        this.#report("usage_projection_list", error);
      }
    }
  }

  /**
   * A1 (#170/#228) — proactive budget-threshold alerting, fired from the same
   * position Rust fires it: `state_billing_metering.rs` calls
   * `dispatch_budget_threshold_alerts` after every settlement, and it reads the
   * rollup the settlement just moved.
   *
   * MOUNT GATE. Delete this call and `test/metering/budget-alerts.test.ts` goes
   * red on eight assertions — the whole point of the file, because before this
   * slice an operator who configured a budget alert was never notified of
   * anything.
   *
   * BEST-EFFORT, and it never rejects: `dispatchBudgetThresholdAlerts` swallows
   * and reports every failure itself, and the `try` here is belt-and-braces
   * against a future change to that contract. Rethrowing would run
   * `#deliverOnce`'s `catch`, which counts a DELIVERY failure and arms the
   * billing outbox's retry ladder — i.e. a webhook outage would become duplicate
   * downstream reports of charges that already settled.
   *
   * The whole drain runs on `ctx.waitUntil` (`./middleware.ts`), so the outbound
   * POST — bounded by `BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS`, default 5s —
   * cannot delay or fail the customer request.
   */
  async #budgetAlerts(
    backend: MeteringBackend,
    charge: MeteredCharge,
    attribution: MeteringAttribution | undefined,
  ): Promise<void> {
    const ports = backend.budgetAlerts;
    if (ports === undefined) {
      return; // no webhook configured, or no control database bound
    }
    // Attribution belongs to ONE request — the same guard `usageWriteFor`
    // applies. A drain pass can settle an earlier request's outbox row, and
    // evaluating THIS request's tenant against THAT charge's spend would alert
    // the wrong operator.
    const owned = attribution !== undefined && attribution.requestId === charge.requestId;
    const scopes = budgetAlertScopesFor(owned ? attribution : undefined, charge.event.tenant);
    const tenantId =
      charge.event.tenant.organization_id ?? (owned ? attribution?.tenantId : undefined) ?? "";
    if (tenantId.trim() === "") {
      this.#report("budget_alert_tenant", new Error(charge.requestId));
      return;
    }
    try {
      await dispatchBudgetThresholdAlerts(ports, {
        tenantId,
        scopes,
        nowUnixSeconds: this.#clock.nowUnixSeconds(),
        diagnostics: this.#diagnostics,
      });
    } catch (error) {
      this.#report("budget_alert", error);
    }
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
  async sweep(
    rc: MeteringDrainContext,
    nowUnixSeconds?: number,
    tenantIds?: readonly string[],
  ): Promise<void> {
    const now = nowUnixSeconds ?? this.#clock.nowUnixSeconds();
    const scopedTenants = tenantIds?.filter((tenantId) => tenantId.trim() !== "") ?? [];
    if (scopedTenants.length > 0) {
      for (const tenantId of scopedTenants) {
        await this.#sweepBackend(rc, now, tenantId);
      }
      return;
    }
    await this.#sweepBackend(rc, now, undefined);
  }

  async #sweepBackend(
    rc: MeteringDrainContext,
    now: number,
    tenantId: string | undefined,
  ): Promise<void> {
    const backend = this.#backend(rc.env, tenantId);
    const outbox = backend.ledger.outbox;
    if (outbox === undefined) {
      return;
    }
    try {
      const due = await outbox.listDue(now - OUTBOX_SWEEP_GRACE_SECONDS, BILLING_OUTBOX_BATCH);
      for (const record of due) {
        try {
          if (this.#bindings !== undefined) {
            await this.#accumulate(backend, record.charge, undefined, rc);
          }
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
