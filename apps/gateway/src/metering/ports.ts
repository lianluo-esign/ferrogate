/**
 * Narrow ports for durable metering.
 *
 * The pricing logic is NOT re-implemented here — `@ferrogate/billing` already
 * ports `PriceBook` / `charge()` / `ledgerEntryId()` / `BillingEvent` with 59
 * passing tests, and this module depends on it. What lives here is everything
 * that package deliberately does not own: it is "storage-free: the durable
 * `LedgerSink`/`BillingEventRepository` live in `ferrogate-storage`"
 * (`docs/legacy/inventory-data-billing.md` §2.1). These are the Cloudflare
 * shapes of exactly those durable seams.
 *
 * | this module              | Rust                                                            |
 * |--------------------------|-----------------------------------------------------------------|
 * | `MeteredCharge`          | the `(BillingEvent, LedgerEntry)` pair `charge()` settles        |
 * | `LedgerStore`            | `append_billing_event_with_outbox_enqueue` + `trait LedgerSink`  |
 * | `MeteringOutbox`         | the `billing_report_outbox` table + its sweeper's state moves    |
 * | `BillingReportPublisher` | `BillingReporter::deliver_once` (`gateway/billing_client.rs`)    |
 * | `MeteringDatabase`       | `ControlPlaneStoreD1` / the `d1-proxy`, now a native binding     |
 * | `MeteringScheduler`      | the tokio sweeper task — on Workers, `ctx.waitUntil`             |
 * | `MeteringDiagnostics`    | the `tracing::warn!` sites + `billing_*_total` metric counters   |
 *
 * Every port is deliberately shaped so a REAL Cloudflare binding satisfies it
 * structurally, the same trick `src/assets/ports.ts` plays with `R2Bucket`:
 * a live `D1Database` is a {@link MeteringDatabase} and a live `Queue` is a
 * {@link MeteringQueue}, with no adapter and no `as` cast.
 * `test/metering/d1.test.ts` holds that with a compile-time assignment
 * (`_bindingsSatisfyThePorts`) and exercises both bindings for real.
 */
import type { BillingEvent, LedgerEntry, LedgerListFilter } from "@ferrogate/billing";

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/**
 * `now_unix_seconds()`.
 *
 * A port rather than a direct `Date.now()` because the outbox's whole contract
 * is expressed in "due at", and a test that cannot move time can only ever
 * assert the happy path — the retry ladder and the dead-letter cutoff would be
 * unreachable, which is precisely the shape of a vacuous suite.
 */
export interface MeteringClock {
  nowUnixSeconds(): number;
}

/** Wall-clock implementation. */
export const systemClock: MeteringClock = {
  nowUnixSeconds: (): number => Math.floor(Date.now() / 1000),
};

/** A clock a test drives by hand. */
export class ManualClock implements MeteringClock {
  #now: number;

  constructor(startUnixSeconds = 1_700_000_000) {
    this.#now = startUnixSeconds;
  }

  nowUnixSeconds(): number {
    return this.#now;
  }

  advance(seconds: number): void {
    this.#now += seconds;
  }
}

// ---------------------------------------------------------------------------
// Scheduling — `ctx.waitUntil`
// ---------------------------------------------------------------------------

/**
 * Where post-response work is parked.
 *
 * On Workers the only correct answer is `ctx.waitUntil`: a promise left
 * floating after the response is flushed may have its I/O cancelled when the
 * request's `IoContext` is torn down, which is exactly how a metering write
 * gets silently lost. {@link executionContextScheduler} is the production
 * implementation; {@link TrackingScheduler} is the one tests await on.
 *
 * `waitUntil` MUST NOT throw and MUST NOT be awaited by the caller — metering
 * never delays the client.
 */
export interface MeteringScheduler {
  waitUntil(work: Promise<unknown>): void;
}

/** Adapt a Workers `ExecutionContext` (or Hono's `c.executionCtx`). */
export function executionContextScheduler(ctx: {
  waitUntil(work: Promise<unknown>): void;
}): MeteringScheduler {
  return {
    waitUntil(work: Promise<unknown>): void {
      try {
        ctx.waitUntil(work.catch(() => undefined));
      } catch {
        // A context that has already completed rejects `waitUntil`. The work is
        // still in flight and still retried from the outbox; swallowing here
        // keeps a metering detail from surfacing on the request path.
      }
    },
  };
}

/**
 * Keeps every scheduled promise so a test can await quiescence.
 *
 * This is NOT a mock: it is the shipped default, used whenever no
 * `ExecutionContext` has been threaded in. It never lets a rejection escape
 * (an unhandled rejection would fail the isolate, and a metering failure must
 * never do that) while still recording it for {@link errors}.
 */
export class TrackingScheduler implements MeteringScheduler {
  readonly #inFlight = new Set<Promise<unknown>>();
  readonly #errors: unknown[] = [];

  waitUntil(work: Promise<unknown>): void {
    const tracked = work
      .catch((error: unknown) => {
        this.#errors.push(error);
      })
      .finally(() => {
        this.#inFlight.delete(tracked);
      });
    this.#inFlight.add(tracked);
  }

  /** Resolve once nothing is outstanding, including work scheduled meanwhile. */
  async idle(): Promise<void> {
    while (this.#inFlight.size > 0) {
      await Promise.all([...this.#inFlight]);
    }
  }

  /** Rejections swallowed on the way through. */
  get errors(): readonly unknown[] {
    return this.#errors;
  }

  get pending(): number {
    return this.#inFlight.size;
  }
}

// ---------------------------------------------------------------------------
// The settled unit of work
// ---------------------------------------------------------------------------

/**
 * One priced, idempotency-keyed charge — the atom the outbox moves and the
 * ledger stores.
 *
 * `entry.credits` is the `f64` field the Rust `LedgerEntry` carries and is kept
 * verbatim for wire fidelity; {@link MeteredCharge.credits} is the
 * AUTHORITATIVE integer-credit figure and is the only one any balance,
 * total, or wallet movement may use (`inventory-data-billing.md` §2.5).
 */
export interface MeteredCharge {
  /** `ledger_entry_id(event)` — the idempotency key, PK of both tables. */
  readonly id: string;
  readonly requestId: string;
  readonly event: BillingEvent;
  readonly entry: LedgerEntry;
  /** Integer credits (1 USD = 1e6). Never a `number`. */
  readonly credits: bigint;
  readonly occurredAtUnix: number;
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/**
 * What an idempotent write did.
 *
 * Port of the three outcomes the Rust path distinguishes:
 *  - `recorded`  — `append_billing_event*` returned `recorded = true`;
 *  - `duplicate` — `ON CONFLICT (billing_event_id) DO NOTHING` matched and the
 *    stored settlement is byte-equal, i.e. `LedgerSink::record -> Ok(false)`.
 *    The Rust caller then `return`s, skipping metrics, counters and the
 *    downstream report entirely — a replay is a NO-OP, not a re-charge;
 *  - `conflict`  — the id was replayed with DIFFERENT settlement data, i.e.
 *    `BillingError("billing_idempotency_conflict")` / HTTP 409.
 */
export type LedgerWriteOutcome =
  | { readonly status: "recorded" }
  | { readonly status: "duplicate" }
  | { readonly status: "conflict"; readonly existing: MeteredCharge };

/** Aggregates, in the integer domain. */
export interface MeteredTotals {
  readonly entries: number;
  readonly credits: bigint;
  readonly totalTokens: bigint;
  readonly costUsd: number;
}

/**
 * Durable, idempotent settlement store — `trait LedgerSink` plus the metering
 * append, async because every Cloudflare storage binding is.
 *
 * `record` MUST be idempotent on {@link MeteredCharge.id}. That is the single
 * guarantee standing between a retried outbox delivery and a double charge, so
 * an implementation that loses it is a billing defect, not a performance one.
 */
export interface LedgerStore {
  record(charge: MeteredCharge): Promise<LedgerWriteOutcome>;
  get(id: string): Promise<MeteredCharge | undefined>;
  list(filter: LedgerListFilter, offset: number, limit: number): Promise<MeteredCharge[]>;
  totals(filter?: LedgerListFilter): Promise<MeteredTotals>;
  /**
   * The DURABLE half of the outbox, when this store has one.
   *
   * `record` commits a `billing_report_outbox` row in the SAME batch as the
   * charge (#150), so that row's whole lifecycle belongs to the same store —
   * which is why these live here and not on {@link MeteringOutbox} (that port is
   * the in-isolate buffer, and it has no `env` to write through).
   *
   * Every member is OPTIONAL because {@link LedgerStore} also has an in-memory
   * implementation that writes no such row; a caller must treat absence as "this
   * store keeps no durable intent", never as an error.
   */
  readonly outbox?: DurableOutboxStore | undefined;
  /**
   * Persist the metering EVENT alone — no ledger row, no outbox intent, no
   * downstream report (#663).
   *
   * The one caller is the fail-closed path: a request that was served and
   * cannot be priced. Rust did exactly this —
   * `state_billing_metering.rs::settle_request` skipped only the WALLET DEBIT
   * when `cost_usd` was `None` and called
   * `append_billing_event_with_outbox_enqueue` regardless — and the TS port
   * dropped it, so a served, billable request against a model outside the rate
   * card was recorded nowhere at all.
   *
   * Deliberately NOT `record()` with a zero-cost entry: a `billing_ledger` row
   * saying $0 is a BILL, and billing zero for a real call is the
   * free-inference bug #129 exists to prevent. An event row with a null
   * `cost_usd` is a different statement — "this happened, nobody could price
   * it" — and it carries the token counts, so the operator can add the rule and
   * re-price it.
   *
   * Idempotent on `id` (the same `ledgerEntryId` a charge would use), so a
   * replayed drain writes one row. OPTIONAL for the same reason
   * {@link LedgerStore.outbox} is: a store may keep no such table, and absence
   * must read as "nowhere to write", never as an error.
   */
  recordEvent?(event: BillingEvent, id: string, occurredAtUnix: number): Promise<void>;
}

/**
 * The durable `billing_report_outbox` row's lifecycle — the state moves
 * `sweep_billing_outbox_once` makes, expressed against the storage binding
 * rather than against an in-isolate `Map`.
 *
 * Why it exists at all, given {@link MeteringOutbox} already implements the same
 * moves: the in-isolate buffer dies with the isolate. A charge whose ledger row
 * committed but whose Queue publish had not yet succeeded when the isolate was
 * evicted is billed and never reported — real money, silently un-invoiced — and
 * the durable row is the ONLY record that it happened. {@link listDue} is what
 * a Cron-triggered sweep reads to recover it.
 */
export interface DurableOutboxStore {
  /** Drop the intent — the report was delivered. `delete_billing_report`. */
  reap(id: string): Promise<void>;
  /**
   * Stranded intents a sweep should re-deliver: due, not dead-lettered, oldest
   * deadline first, and only those whose ledger row exists (an intent with no
   * charge behind it cannot be rehydrated).
   *
   * Every record comes back `settled: true` — the ledger row is what the join
   * matched on, so by construction the charge has already committed and the
   * sweep's only remaining job is delivery.
   */
  listDue(nowUnix: number, limit: number): Promise<OutboxRecord[]>;
  /** `reschedule_billing_report` — `attempts += 1`, push the deadline out. */
  reschedule(id: string, attempts: number, nextAttemptUnix: number, nowUnix: number): Promise<void>;
  /** `dead_letter_billing_report` — stop retrying, keep for inspection (#143). */
  deadLetter(id: string, nowUnix: number): Promise<void>;
}

// ---------------------------------------------------------------------------
// Outbox
// ---------------------------------------------------------------------------

/** One `billing_report_outbox` row. */
export interface OutboxRecord {
  /** `= ledger entry id`. */
  readonly id: string;
  readonly charge: MeteredCharge;
  readonly attempts: number;
  readonly nextAttemptUnix: number;
  readonly deadLetteredAtUnix?: number | undefined;
  /**
   * Whether the LEDGER write for this row has already committed.
   *
   * Rust does not need this bit: `settle_request` writes the metering row and
   * the outbox row in one transaction on the request path, so by the time the
   * sweeper ever sees a row the charge is, by construction, already settled and
   * the sweeper's only job is delivery. On Workers the ledger write is deferred
   * with the delivery (see `sink.ts` — `UsageSink.record` may not do I/O), so
   * "settled" and "delivered" become two steps of one deferred pass and the row
   * has to remember which of them it has passed. Without it a retry after a
   * FAILED DELIVERY is indistinguishable from a REPLAY of an already-delivered
   * charge: the first must re-deliver, the second must not.
   */
  readonly settled: boolean;
}

/**
 * The durable delivery queue between "we settled a charge" and "the billing
 * side acknowledged it" (issues #137/#143/#150/#151).
 *
 * `enqueue` is SYNCHRONOUS on purpose. `UsageSink.record` is a `void` method
 * called from a stream tap that may be running after the response has been
 * flushed; if capturing the charge were `async`, an isolate teardown between
 * the `await` points would drop it on the floor and nothing would ever know.
 * A synchronous capture followed by an asynchronous, retried drain is the same
 * ordering the Rust path gets from committing the outbox row inside the
 * request's transaction and letting a separate sweeper deliver it.
 */
export interface MeteringOutbox {
  /**
   * `INSERT ... ON CONFLICT (id) DO NOTHING`. Returns `false` when the id was
   * already queued — a replay must not produce a second delivery.
   */
  enqueue(charge: MeteredCharge, nextAttemptUnix: number): boolean;
  /** `list_due_billing_reports` — due, not dead-lettered, oldest deadline first. */
  listDue(nowUnix: number, limit: number): OutboxRecord[];
  /** Record that the ledger write committed — see {@link OutboxRecord.settled}. */
  markSettled(id: string): void;
  /** `delete_billing_report` — delivered, drop the row. */
  delete(id: string): void;
  /** `reschedule_billing_report` — `attempts += 1`, push the deadline out. */
  reschedule(id: string, nextAttemptUnix: number): void;
  /** `dead_letter_billing_report` — stop retrying, keep for inspection (#143). */
  deadLetter(id: string, nowUnix: number): void;
  /** `list_dead_lettered_billing_reports` (#143). */
  deadLetters(): OutboxRecord[];
  /** `replay_dead_lettered_billing_report` (#388) — clears the flag, resets attempts. */
  replayDeadLetter(id: string, nextAttemptUnix: number): boolean;
  /** `get_billing_report_outbox_entry` (#388). */
  get(id: string): OutboxRecord | undefined;
  /** Rows still queued, dead-lettered included. */
  readonly size: number;
}

// ---------------------------------------------------------------------------
// Downstream delivery
// ---------------------------------------------------------------------------

/**
 * `BillingReporter::deliver_once` — hand a settled charge to whatever consumes
 * billing downstream. MUST reject (not swallow) on failure, because rejecting
 * is what arms the outbox's retry ladder.
 */
export interface BillingReportPublisher {
  deliver(charge: MeteredCharge): Promise<void>;
}

/**
 * The subset of a Cloudflare `Queue` this module uses — a live
 * `Queue<MeteringQueueMessage>` binding satisfies it structurally.
 *
 * `inventory-data-billing.md` §2.5: "**Cloudflare Queues** is the natural fit
 * (replace the DB-polled sweeper with a Queue consumer + dead-letter queue)".
 */
export interface MeteringQueue {
  /**
   * Return types are `unknown` because a live `Queue` resolves to
   * `QueueSendResponse`/`QueueSendBatchResponse`, not `void`; narrowing them
   * here would make the real binding fail to satisfy the port, which is the one
   * mistake a structurally-shaped port must not make. Nothing reads the value.
   */
  send(message: MeteringQueueMessage): Promise<unknown>;
  sendBatch(messages: Iterable<{ body: MeteringQueueMessage }>): Promise<unknown>;
}

/**
 * The JSON body put on the Queue.
 *
 * `credits` is a DECIMAL STRING, not a number: Queue bodies are structured-clone
 * / JSON encoded, and a `bigint` past 2^53 would round-trip as a wrong `Number`.
 * The string is the only lossless carrier, and it matches how the D1 column is
 * read back (`CAST(? AS INTEGER)` on the way in, string on the way out).
 */
export interface MeteringQueueMessage {
  readonly id: string;
  readonly request_id: string;
  readonly credits: string;
  readonly occurred_at_unix: number;
  readonly event: Record<string, unknown>;
  readonly entry: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// D1
// ---------------------------------------------------------------------------

/** One prepared statement — `D1PreparedStatement`-shaped. */
export interface MeteringStatement {
  bind(...values: unknown[]): MeteringStatement;
  run(): Promise<MeteringQueryResult>;
  all(): Promise<MeteringQueryResult>;
}

/** `D1Result`-shaped. */
export interface MeteringQueryResult {
  readonly results?: unknown[] | undefined;
  readonly success?: boolean | undefined;
}

/**
 * `D1Database`-shaped. A live `env.BILLING_DB` satisfies this with no adapter —
 * `wrangler.toml` declares that binding (the CONTROL database), and
 * `meteringBindingsFromEnv` resolves it per request.
 */
export interface MeteringDatabase {
  prepare(sql: string): MeteringStatement;
  batch(statements: MeteringStatement[]): Promise<MeteringQueryResult[]>;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/** `charge()`'s divergence callback payload (issue #152). */
export interface CostDivergence {
  readonly request_id: string;
  readonly provider: string;
  readonly provider_model: string;
  readonly gateway_settled_cost_usd: number;
  readonly price_book_estimate_usd: number;
}

/**
 * The observable side of metering — the Rust `tracing::warn!` sites and the
 * `billing_event_total` / `billing_report_enqueue_failure_total` counters.
 *
 * Every hook is optional and every call site guards against a throwing hook,
 * so an observability bug can never become a billing bug.
 *
 * PORT-TODO(P: inventory-data-billing §"Observability/worker/audit analytics
 * families"): these become Analytics Engine `writeDataPoint` calls.
 *
 * NOT a platform limit — the opposite, and it was checked rather than assumed:
 * `[[analytics_engine_datasets]]` is emulated by miniflare and a
 * `writeDataPoint({ blobs, doubles, indexes })` call is accepted for real under
 * `@cloudflare/vitest-pool-workers`. What is missing is a local READ-BACK: the
 * only query interface is the account-scoped SQL API over HTTP, so a test can
 * prove the call was made (through a recording decorator over the live binding)
 * but not that the row is queryable — the same shape as the `BILLING` Queue
 * producer, which this module already handles that way.
 *
 * The reason it is deferred is OWNERSHIP, not capability. `TELEMETRY` is ONE
 * dataset binding, and `apps/gateway/wrangler.toml`'s "NOT DECLARED" block
 * reserves it jointly for the asset audit sink (`src/assets`, a different
 * owner) and `apps/telemetry`, whose `AnalyticsEngineSink` already defines the
 * blob/double/index column contract. Declaring it from the metering slice alone
 * would fork that contract on a dataset whose schema is positional and cannot be
 * migrated. Closing it is: declare
 * `[[analytics_engine_datasets]] binding = "TELEMETRY"`, add a
 * `analyticsEngineDiagnostics(env): MeteringDiagnostics` beside
 * `meteringBindingsFromEnv` in `runtime.ts` mapping each hook below to one data
 * point (index = tenant, blobs = request/provider/model, doubles = credits), and
 * pass it as `MeteringSinkOptions.diagnostics` from `src/index.ts`.
 */
export interface MeteringDiagnostics {
  /** A gateway-settled cost drifted >5% from the rate card. Signal only (#152). */
  onDivergence?(divergence: CostDivergence): void;
  /**
   * No settled cost AND no matching rate-card rule. The charge was REFUSED —
   * nothing was billed, and nothing was billed at zero either (#129).
   */
  onPriceNotFound?(info: {
    readonly requestId: string;
    readonly provider: string;
    readonly providerModel: string;
    readonly message: string;
  }): void;
  /** An id was replayed with different settlement data (#213) — HTTP 409 class. */
  onIdempotencyConflict?(info: { readonly id: string; readonly requestId: string }): void;
  /** One delivery attempt failed; the outbox will retry. */
  onDeliveryFailure?(info: {
    readonly id: string;
    readonly attempts: number;
    readonly error: unknown;
  }): void;
  /** Retries exhausted (#143) — kept for operator inspection, never retried again. */
  onDeadLetter?(info: { readonly id: string; readonly attempts: number }): void;
  /** The narrow window where a charge could be lost (#151). Alert on this. */
  onEnqueueFailure?(info: { readonly requestId: string; readonly error: unknown }): void;
  /** Anything else that would otherwise escape `record()`. */
  onError?(stage: string, error: unknown): void;
}

/** Counters the sink keeps, mirroring the Rust metrics family. */
export interface MeteringStats {
  /** `record()` calls that produced a priced charge. */
  charged: number;
  /** Charges newly written to the ledger. */
  recorded: number;
  /** Replays the ledger absorbed — the double-charge guard firing. */
  duplicates: number;
  /** Replays the OUTBOX absorbed before a write was even attempted. */
  outboxDuplicates: number;
  /** Same id, different settlement (#213). */
  conflicts: number;
  /** Fail-closed refusals (#129). */
  priceNotFound: number;
  /** >5% gateway-vs-rate-card gaps (#152). */
  divergences: number;
  /** Successful downstream deliveries. */
  delivered: number;
  /** Failed delivery attempts (each one arms a retry). */
  deliveryFailures: number;
  /** Reports abandoned after `MAX_BILLING_OUTBOX_ATTEMPTS` (#143). */
  deadLettered: number;
  /**
   * Charges accumulated into the TENANT database's usage rollups — the input
   * of both budget gates (`./usage-ledger.ts`). Distinct from `recorded`, which
   * counts the CONTROL database's billing ledger: the two are separate
   * databases and D1 cannot commit them together, so a gap between these two
   * counters is the visible size of that window.
   */
  aggregated: number;
  /**
   * Charges that named NO attribution scope and so could not be rolled up. A
   * non-zero value here means spend exists that no budget check can ever see.
   */
  unattributed: number;
  /**
   * Unpriced usages whose cost-less `billing_events` row was persisted (#663) —
   * the durable trace that keeps an unbilled request RECOVERABLE.
   *
   * Read against `priceNotFound`: those two being equal means every refusal
   * left a re-priceable record, and a gap between them is usage that the
   * gateway served and then forgot.
   */
  unpricedRecorded: number;
}

/** A zeroed {@link MeteringStats}. */
export function emptyMeteringStats(): MeteringStats {
  return {
    charged: 0,
    recorded: 0,
    duplicates: 0,
    outboxDuplicates: 0,
    conflicts: 0,
    priceNotFound: 0,
    divergences: 0,
    delivered: 0,
    deliveryFailures: 0,
    deadLettered: 0,
    aggregated: 0,
    unattributed: 0,
    unpricedRecorded: 0,
  };
}
