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
 * WIRING — LIVE. `src/index.ts` builds the sink like this:
 * ============================================================================
 *
 * ```ts
 * const usage = createMeteringUsageSink({ bindings: meteringBindingsFromEnv });
 *
 * export const GATEWAY_ROUTE_MODULES: readonly RouteModule[] = [
 *   inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher, usage }),
 *   assetRouteModule(),
 * ];
 * export const GATEWAY_MIDDLEWARE = [meteringDrain(usage), rateLimit(), guardrails(...)];
 * ```
 *
 * and `wrangler.toml` declares the two bindings that resolver reads:
 * `[[d1_databases]] binding = "BILLING_DB"` (the CONTROL database — the tenant
 * migration explicitly excludes the billing tables) and
 * `[[queues.producers]] binding = "BILLING"`.
 *
 * ### How the per-request `env` and `ExecutionContext` reach a module-scoped sink
 *
 * They are arguments, never ambient state. `UsageSink.record` was widened to
 * `record(u: Usage, rc?: { env, ctx })` (`src/inference/ports.ts`), everything
 * derived from `env` is memoized on the env object in a `WeakMap`
 * (`runtime.ts`), and the drain itself runs from `meteringDrain()`
 * (`middleware.ts`), which is the one place in the request path holding both
 * `c.env` and `c.executionCtx`. A module-scoped "current ctx" slot was rejected
 * outright: workerd refuses I/O started on behalf of a different request, so a
 * last-write-wins slot is a billing corruption that only appears under load.
 *
 * ### Remaining call-site gap — ONE LINE, in a file this module does not own
 *
 * PORT-TODO(P: inventory-data-billing §2.5) — NOT a platform limit, a SCOPE
 * boundary: the line below belongs to `src/inference/handlers.ts`, which this
 * module does not own and must not edit.
 *
 * `recordUsage` still calls `deps.usage.record({...})` with no second argument,
 * so the sink is driven entirely through `meteringDrain()`. That is CORRECT and
 * durable — the middleware supplies `{ env, ctx }` to `flush()` and defers it
 * until an SSE body ends or is abandoned, and every persistence test in
 * `test/metering/durable.test.ts` runs through exactly that path. What it costs
 * is that the drain is scheduled once per REQUEST rather than once per RECORDED
 * USAGE, so a route that meters more than once per request (provider failover,
 * #135's `provider_attempt_index > 0`) would settle every attempt on the same
 * post-response drain instead of overlapping them. Closing it is:
 *
 * ```ts
 * // src/inference/handlers.ts — recordUsage()
 * deps.usage.record({ ... }, { env: c.env, ctx: executionContextOf(c) });
 * ```
 *
 * `MeteringUsageSink.record` already accepts and prefers that argument, and
 * `test/metering/durable.test.ts` ("both shapes of the widened seam") pins BOTH
 * — `record(u, rc)` drains itself onto the request's own `waitUntil` and
 * persists to D1; `record(u)` captures and waits for `meteringDrain()` — so the
 * change is additive and already covered on the day it lands.
 *
 * ### Durable outbox recovery — `[triggers] crons`
 *
 * The request-time drain cannot cover an isolate evicted between the D1 ledger
 * commit and the Queue publish: the tenant is charged and nothing downstream was
 * told. `wrangler.toml` therefore declares a one-minute Cron, `src/worker.ts`
 * exposes `scheduled`, and `MeteringUsageSink.sweep` re-publishes stranded
 * `billing_report_outbox` rows older than `OUTBOX_SWEEP_GRACE_SECONDS`.
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
  providerAttemptIndexFor,
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
  BILLING_OUTBOX_DEAD_LETTER_SQL,
  BILLING_OUTBOX_DELETE_SQL,
  BILLING_OUTBOX_INSERT_SQL,
  BILLING_OUTBOX_LIST_DUE_SQL,
  BILLING_OUTBOX_RESCHEDULE_SQL,
  CREDITS_EXACT_FIELD,
  D1LedgerStore,
  METERING_SCHEMA_SQL,
  ledgerDocument,
} from "./d1.js";

export { attributionFrom, meteringDrain } from "./middleware.js";

export {
  type MeteringAttribution,
  type MeteringDrainContext,
  type UsageAggregateSink,
  type UsageLedgerBindings,
  d1UsageAggregateSink,
  usageContextId,
  usageDatabaseFrom,
  usageScopesFor,
  usageWriteFor,
} from "./usage-ledger.js";

export {
  executionContextOf,
  meteringBindingsFromEnv,
  meteringDatabaseFrom,
  meteringQueueFrom,
} from "./runtime.js";
export type { MeteringBindingResolver, MeteringBindings } from "./runtime.js";

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
  DurableOutboxStore,
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

export {
  OUTBOX_SWEEP_GRACE_SECONDS,
  MeteringUsageSink,
  createMeteringUsageSink,
} from "./sink.js";
export type { MeteringSinkOptions, UnpricedUsage } from "./sink.js";

export {
  billingEventFromWire,
  billingEventToWire,
  creditsFromWire,
  creditsToWire,
  ledgerEntryFromWire,
  ledgerEntryToWireDocument,
} from "./wire.js";
