/**
 * `apps/gateway/src/metering` — durable metering for the inference data plane.
 *
 * The main path already CAPTURES usage: `src/inference/ports.ts` declares
 * `UsageSink` and the streaming layer taps the trailing usage frame. Until this
 * module existed the default sink was `InMemoryUsageSink`, i.e. that usage went
 * nowhere. This module turns a captured `Usage` into a priced, idempotent,
 * durably-queued charge, reusing `@ferrogate/billing` for every pricing rule
 * rather than restating any of them.
 *
 * ============================================================================
 * WIRING — for the integrate step that owns `src/index.ts` + `wrangler.toml`
 * ============================================================================
 *
 * `MeteringUsageSink` implements `UsageSink` exactly, so the composition root
 * needs ONE new argument:
 *
 * ```ts
 * // apps/gateway/src/index.ts
 * import { createMeteringUsageSink } from "./metering/index.js";
 *
 * const usage = createMeteringUsageSink();          // in-memory ledger + outbox
 *
 * export const GATEWAY_ROUTE_MODULES: readonly RouteModule[] = [
 *   inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher, usage }),
 *   //                                                                       ^^^^^
 *   assetRouteModule(),
 * ];
 * ```
 *
 * That single line is the whole integration; nothing in `inference/` changes.
 *
 * ### Backing it with real Cloudflare storage
 *
 * `MeteringDatabase` is `D1Database`-shaped and `MeteringQueue` is `Queue`-shaped,
 * so live bindings satisfy them with no adapter (the same structural trick
 * `src/assets/ports.ts` plays with `R2Bucket`). Because the sink is built once
 * at module scope and Worker bindings are per request, back it the way
 * `models: ModelResolverFactory` already handles that — or, simplest, build the
 * sink inside the module's `env`-aware factory:
 *
 * ```ts
 * const usage = createMeteringUsageSink({
 *   ledger: new D1LedgerStore(env.DB),                       // [[d1_databases]] binding = "DB"
 *   publisher: new QueueBillingReportPublisher(env.BILLING), // [[queues]] binding = "BILLING"
 *   priceBook: PriceBook.fromJson(env.GATEWAY_PRICE_BOOK ?? "[]"),
 * });
 * ```
 *
 * and apply {@link METERING_SCHEMA_SQL} as the D1 migration first. Neither
 * binding is declared in `wrangler.toml` today (that file's "NOT DECLARED —
 * and why" block already names `[[queues]]` for "metering / ledger fan-out"
 * with this exact PORT-TODO), and declaring a binding nothing reads is the
 * mistake that block exists to prevent — so both land WITH this wiring, not
 * before it.
 *
 * ### `ctx.waitUntil`
 *
 * `record()` never does I/O inline; it hands the durable half to a
 * {@link MeteringScheduler}. The default {@link TrackingScheduler} keeps the
 * promise alive within the isolate and is what the tests await, but the
 * PRODUCTION scheduler must be `ctx.waitUntil`, or workerd may tear down the
 * request's `IoContext` mid-write:
 *
 * ```ts
 * const usage = createMeteringUsageSink({ scheduler: executionContextScheduler(ctx) });
 * ```
 *
 * PORT-TODO(inventory-data-billing §2.5): `UsageSink.record(u: Usage): void`
 * carries no `ExecutionContext`, and the sink is constructed ONCE while `ctx` is
 * per request, so the scheduler cannot be bound at construction time in the
 * deployed Worker. Binding a module-scoped "current ctx" is NOT a fix —
 * workerd refuses I/O started on behalf of a different request, so a
 * last-write-wins slot would break under concurrency. The correct fix is a
 * one-line widening the integrate step owns, threading the context the inner
 * router already receives:
 *
 * ```ts
 * // src/inference/ports.ts
 * export interface UsageSink { record(u: Usage, ctx?: { waitUntil(p: Promise<unknown>): void }): void }
 * // src/inference/handlers.ts — recordUsage(): deps.usage.record({...}, c.executionCtx)
 * ```
 *
 * `MeteringUsageSink.record` already ignores extra arguments, and
 * {@link MeteringUsageSink.flush} is public and idempotent, so a Cron Trigger
 * (`scheduled()` → `sink.flush()`) covers the gap in the meantime: nothing is
 * lost, delivery is merely deferred to the next drain.
 *
 * ============================================================================
 * Ported semantics (see each module for the Rust citation)
 * ============================================================================
 *  - gateway-settled cost is AUTHORITATIVE; the ledger records it verbatim and
 *    only splits the breakdown (#135)                       — `@ferrogate/billing`
 *  - >5% divergence (abs floor $0.0001) is WARNED, never overridden (#152)
 *  - no settled cost + no rate-card rule ⇒ `price_not_found`, FAIL CLOSED,
 *    never billed at zero (#129)                            — `sink.ts`
 *  - integer credits, 1 USD = 1e6, `bigint` end to end      — `credits.ts`
 *  - idempotent on `ledger_entry_id(event)`; replay is a no-op, replay with
 *    different data is a conflict (#213)                    — `ledger.ts`/`d1.ts`
 *  - durable outbox committed in the SAME batch as the metering row (#150),
 *    capped exponential backoff 1,2,4,8,16,32,60…, dead-letter after 20
 *    attempts (#137/#143/#151/#388)                         — `outbox.ts`
 */
export {
  DEFAULT_CREDITS_PER_USD,
  creditsToUsd,
  sumCredits,
  usdToCredits,
  walletDeltaCredits,
} from "./credits.js";

export {
  SINGLE_PROVIDER_ATTEMPT_INDEX,
  billingEventFromUsage,
  usageSourceFor,
} from "./event.js";
export type { BillingEventContext } from "./event.js";

export { InMemoryLedgerStore, meteredTotals, sameSettlement } from "./ledger.js";

export {
  BILLING_OUTBOX_BATCH,
  InMemoryMeteringOutbox,
  MAX_BILLING_OUTBOX_ATTEMPTS,
  billingOutboxBackoffSeconds,
} from "./outbox.js";

export {
  InMemoryBillingReportPublisher,
  QueueBillingReportPublisher,
  meteringQueueMessage,
} from "./publisher.js";

export {
  BILLING_EVENT_INSERT_SQL,
  BILLING_LEDGER_INSERT_SQL,
  BILLING_OUTBOX_INSERT_SQL,
  D1LedgerStore,
  METERING_SCHEMA_SQL,
} from "./d1.js";

export {
  ManualClock,
  TrackingScheduler,
  emptyMeteringStats,
  executionContextScheduler,
  systemClock,
} from "./ports.js";
export type {
  BillingReportPublisher,
  CostDivergence,
  LedgerStore,
  LedgerWriteOutcome,
  MeteredCharge,
  MeteredTotals,
  MeteringClock,
  MeteringDatabase,
  MeteringDiagnostics,
  MeteringOutbox,
  MeteringQueryResult,
  MeteringQueue,
  MeteringQueueMessage,
  MeteringScheduler,
  MeteringStatement,
  MeteringStats,
  OutboxRecord,
} from "./ports.js";

export { MeteringUsageSink, createMeteringUsageSink } from "./sink.js";
export type { MeteringSinkOptions, UnpricedUsage } from "./sink.js";

export {
  billingEventFromWire,
  billingEventToWire,
  creditsFromWire,
  creditsToWire,
  ledgerEntryFromWire,
  ledgerEntryToWireDocument,
} from "./wire.js";
