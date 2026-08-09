/**
 * Billing ledger — clean-room port of `ferrogate-billing`'s `ledger.rs`.
 *
 * Turns a token-usage {@link BillingEvent} into a priced {@link LedgerEntry}
 * ({@link charge}), and persists the flow of charges behind the idempotent
 * {@link LedgerSink} seam. Core invariants preserved:
 *  - source-of-truth rule (#135): a finite `cost_usd >= 0` on the event is
 *    authoritative; the ledger records it verbatim and only splits the
 *    breakdown by the rate card's ratio (or token counts).
 *  - divergence detection (#152): a >5% gap (abs floor $0.0001) is a signal
 *    only — never overrides the gateway-settled figure.
 *  - fail-closed (#129): no settled cost + no matching rule ⇒ `price_not_found`.
 *  - idempotency (#213): replay with byte-equal settlement is a no-op; replay
 *    with different data ⇒ `billing_idempotency_conflict`.
 */
import { type TenantContext, tenantContextSchema } from "@ferrogate/core";
import { z } from "zod";
import { BillingError, type BillingEvent } from "./event.js";
import type { PriceBook } from "./pricing.js";
import {
  type AudioQuantity,
  type BillingUsageSource,
  type CostEstimate,
  type ModelPrice,
  type ProviderAttempt,
  type TokenUsage,
  audioQuantityUnpriced,
  billingUsageSourceSchema,
  costEstimateSchema,
  estimateCost,
  modelPriceSchema,
  modelPriceUsd,
  providerAttemptIsLegacy,
  reconcileSplit,
  tokenUsageSchema,
  u16,
  u32,
  u64,
} from "./usage.js";

// ---------------------------------------------------------------------------
// CostSource
// ---------------------------------------------------------------------------

/** Where the settled cost on a {@link LedgerEntry} came from (serde snake_case). */
export type CostSource = "gateway_settled" | "billing_price_book";

export const CostSource = {
  GatewaySettled: "gateway_settled",
  BillingPriceBook: "billing_price_book",
} as const;

/** Mirrors `CostSource::as_str` (identity — the wire tag is the string). */
export function costSourceAsStr(source: CostSource): string {
  return source;
}

// ---------------------------------------------------------------------------
// LedgerEntry
// ---------------------------------------------------------------------------

export interface LedgerEntry {
  id: string;
  request_id: string;
  trace_id?: string;
  provider_attempt: ProviderAttempt;
  tenant: TenantContext;
  logical_model: string;
  provider: string;
  provider_model: string;
  usage: TokenUsage;
  usage_source: BillingUsageSource;
  status_code: number;
  cost: CostEstimate;
  credits: number;
  unit_price: ModelPrice;
  cost_source: CostSource;
  occurred_at_unix?: number;
  wallet_delta_credits?: bigint;
  wallet_balance_after_credits?: bigint;
}

const optI64 = z
  .union([z.bigint(), z.number().int()])
  .nullish()
  .transform((v) => (v == null ? undefined : BigInt(v)));

/** Wire schema for a flattened-provider-attempt {@link LedgerEntry}. */
export const ledgerEntryWireSchema = z
  .object({
    id: z.string(),
    request_id: z.string(),
    trace_id: z
      .string()
      .nullish()
      .transform((v) => v ?? undefined),
    provider_attempt_id: z.string().default(""),
    provider_attempt_index: u32.default(0),
    tenant: tenantContextSchema,
    logical_model: z.string(),
    provider: z.string(),
    provider_model: z.string(),
    usage: tokenUsageSchema,
    usage_source: billingUsageSourceSchema.default("provider_usage"),
    status_code: u16,
    cost: costEstimateSchema,
    credits: z.number(),
    unit_price: modelPriceSchema,
    cost_source: z.enum(["gateway_settled", "billing_price_book"]).default("billing_price_book"),
    occurred_at_unix: u64.nullish().transform((v) => v ?? undefined),
    wallet_delta_credits: optI64,
    wallet_balance_after_credits: optI64,
  })
  .transform(
    (w): LedgerEntry => ({
      id: w.id,
      request_id: w.request_id,
      trace_id: w.trace_id,
      provider_attempt: {
        provider_attempt_id: w.provider_attempt_id,
        provider_attempt_index: w.provider_attempt_index,
      },
      tenant: w.tenant,
      logical_model: w.logical_model,
      provider: w.provider,
      provider_model: w.provider_model,
      usage: w.usage,
      usage_source: w.usage_source,
      status_code: w.status_code,
      cost: w.cost,
      credits: w.credits,
      unit_price: w.unit_price,
      cost_source: w.cost_source,
      occurred_at_unix: w.occurred_at_unix,
      wallet_delta_credits: w.wallet_delta_credits,
      wallet_balance_after_credits: w.wallet_balance_after_credits,
    }),
  );

/**
 * The largest/smallest `i64` a JSON number can carry WITHOUT losing a unit.
 * IEEE-754 doubles are exact on integers up to 2^53 - 1; past that, adjacent
 * integers collapse onto the same double.
 */
const MAX_EXACT_WALLET_CREDITS = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_EXACT_WALLET_CREDITS = BigInt(Number.MIN_SAFE_INTEGER);

/**
 * Render one `i64` wallet field as a JSON number — Rust serde's shape — or
 * REFUSE.
 *
 * Money is integer credits end to end and the wallet fields are `bigint`
 * precisely so no arithmetic on them can drift. JSON has no integer type, so
 * the wire hop is the one place that property could be dropped, and it was
 * being dropped SILENTLY: a bare `Number(entry.wallet_balance_after_credits)`
 * rounds anything past 2^53 to the nearest representable double and returns a
 * number that looks perfectly ordinary.
 *
 * That is not merely a display defect, which is why this refuses instead of
 * rounding. `ledgerEntryWireSchema` reads the field back with `BigInt(v)`, so a
 * rounded value re-enters the domain as a WRONG balance; and
 * {@link sameProviderAttemptSettlement} — the idempotency arbiter — compares
 * bigint against number by widening both with `BigInt`. Two DIFFERENT balances that
 * round to the same double therefore compare EQUAL, and a divergent replay is
 * accepted as a no-op instead of raising `billing_idempotency_conflict`. A
 * money field that quietly disagrees with itself across a serialize/parse hop
 * is the worst available outcome; a loud `wallet_credits_unrepresentable` is
 * the least bad one.
 *
 * The bound is not reachable by ordinary traffic — 2^53 credits is ~$9.0e9 at
 * `credits_per_usd = 1e6` — so this is a guard, not a limit anyone will meet.
 * The INBOUND direction cannot be guarded here and is not pretended to be:
 * `JSON.parse` has already collapsed an over-large literal to a double before
 * any schema sees it, so `ledgerEntryWireSchema` receives a number that is
 * indistinguishable from an exactly-representable one. Rust's serde reads the
 * `i64` from the JSON TEXT and has no such hop.
 */
function walletCreditsToWire(field: string, value: bigint): number {
  if (value > MAX_EXACT_WALLET_CREDITS || value < MIN_EXACT_WALLET_CREDITS) {
    throw new BillingError(
      "wallet_credits_unrepresentable",
      `${field} = ${value} cannot be rendered as a JSON number without losing precision (|value| > ${Number.MAX_SAFE_INTEGER}); refusing rather than silently rounding a money field`,
    );
  }
  return Number(value);
}

/**
 * Serialize a {@link LedgerEntry} to a plain JSON-safe object with the
 * provider-attempt flattened and the `i64` wallet fields rendered as JSON
 * numbers (matching Rust serde), omitting `None`/`undefined` fields.
 *
 * @throws {BillingError} `wallet_credits_unrepresentable` when a wallet field
 *   cannot survive the JSON-number hop — see {@link walletCreditsToWire}.
 */
export function ledgerEntryToWire(entry: LedgerEntry): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: entry.id,
    request_id: entry.request_id,
    provider_attempt_id: entry.provider_attempt.provider_attempt_id,
    provider_attempt_index: entry.provider_attempt.provider_attempt_index,
    tenant: entry.tenant,
    logical_model: entry.logical_model,
    provider: entry.provider,
    provider_model: entry.provider_model,
    usage: entry.usage,
    usage_source: entry.usage_source,
    status_code: entry.status_code,
    cost: entry.cost,
    credits: entry.credits,
    unit_price: entry.unit_price,
    cost_source: entry.cost_source,
  };
  if (entry.trace_id !== undefined) out.trace_id = entry.trace_id;
  if (entry.occurred_at_unix !== undefined) out.occurred_at_unix = entry.occurred_at_unix;
  if (entry.wallet_delta_credits !== undefined)
    out.wallet_delta_credits = walletCreditsToWire(
      "wallet_delta_credits",
      entry.wallet_delta_credits,
    );
  if (entry.wallet_balance_after_credits !== undefined)
    out.wallet_balance_after_credits = walletCreditsToWire(
      "wallet_balance_after_credits",
      entry.wallet_balance_after_credits,
    );
  return out;
}

// ---------------------------------------------------------------------------
// Structural equality (replaces Rust `PartialEq` on the entry struct).
// ---------------------------------------------------------------------------

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a === "bigint" || typeof b === "bigint") {
    // Compare across bigint/number so a reloaded (number) entry still equals one.
    if (
      (typeof a === "bigint" || typeof a === "number") &&
      (typeof b === "bigint" || typeof b === "number")
    ) {
      return BigInt(a as never) === BigInt(b as never);
    }
    return false;
  }
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (typeof a !== "object") return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const keys = new Set([...Object.keys(ao), ...Object.keys(bo)]);
  for (const k of keys) {
    // Treat an absent key and an explicit `undefined` as equal (serde `None`).
    if (ao[k] === undefined && bo[k] === undefined) continue;
    if (!deepEqual(ao[k], bo[k])) return false;
  }
  return true;
}

/**
 * Whether two entries are an exact replay of one immutable provider-attempt
 * settlement (port of `same_provider_attempt_settlement` == full struct eq).
 *
 * The `usage` counters are normalized on both sides first (#667), and that is a
 * correctness requirement rather than a convenience. Rust's `TokenUsage` has
 * plain `u64` fields, so an event that omitted a counter and one that reported
 * `0` are the SAME VALUE there. TypeScript's optionality reintroduces a
 * distinction Rust does not have: an entry built in memory can carry
 * `cached_input_tokens: undefined` while the very same entry, reloaded from
 * `entry_json` through `tokenUsageSchema` (`.default(0)`), carries `0`.
 *
 * Compared naively, those differ — and this function is the IDEMPOTENCY
 * ARBITER. A difference here turns an at-least-once outbox redelivery of one
 * settled request into `billing_idempotency_conflict`, i.e. a stuck outbox row
 * and a 409 for a replay that was in fact identical. Erasing the distinction
 * restores the Rust semantic exactly; nothing else about the comparison is
 * loosened.
 */
export function sameProviderAttemptSettlement(left: LedgerEntry, right: LedgerEntry): boolean {
  return deepEqual(withNormalizedUsage(left), withNormalizedUsage(right));
}

/** An entry whose optional token counters are concrete zeros (see above). */
function withNormalizedUsage(entry: LedgerEntry): LedgerEntry {
  return {
    ...entry,
    usage: {
      ...entry.usage,
      cached_input_tokens: entry.usage.cached_input_tokens ?? 0,
      cache_write_tokens: entry.usage.cache_write_tokens ?? 0,
      reasoning_tokens: entry.usage.reasoning_tokens ?? 0,
    },
  };
}

// ---------------------------------------------------------------------------
// Idempotency key + charge().
// ---------------------------------------------------------------------------

/**
 * Deterministic idempotency key for a usage event (port of `ledger_entry_id`).
 * New provider-dispatch events → `ferrogate:provider-attempt:{attempt_id}`;
 * legacy events → `ferrogate:{trace_id}:{request_id}` or `ferrogate:{request_id}`.
 */
export function ledgerEntryId(event: BillingEvent): string {
  if (!providerAttemptIsLegacy(event.provider_attempt)) {
    return `ferrogate:provider-attempt:${event.provider_attempt.provider_attempt_id}`;
  }
  const trace = event.trace_id?.trim();
  if (trace) {
    return `ferrogate:${event.trace_id}:${event.request_id}`;
  }
  return `ferrogate:${event.request_id}`;
}

/** Relative tolerance (#152): flag divergence beyond 5% of the expected cost. */
const COST_DIVERGENCE_RELATIVE_TOLERANCE = 0.05;
/** Absolute floor (#152): below this, near-zero relative noise is not worth a warning. */
const COST_DIVERGENCE_ABSOLUTE_FLOOR_USD = 0.0001;

/**
 * Whether a gateway-settled cost materially diverges from the rate-card figure
 * for the same usage. Pure — the tolerance logic is independently testable.
 */
export function costDiverges(settled: number, expected: number): boolean {
  const diff = Math.abs(settled - expected);
  if (diff < COST_DIVERGENCE_ABSOLUTE_FLOOR_USD) return false;
  const relativeBase = Math.max(Math.abs(expected), COST_DIVERGENCE_ABSOLUTE_FLOOR_USD);
  return diff / relativeBase > COST_DIVERGENCE_RELATIVE_TOLERANCE;
}

/** The gateway-settled cost, if the event carries a usable (finite, ≥0) one. */
function authoritativeCost(event: BillingEvent): number | undefined {
  const cost = event.cost_usd;
  if (cost !== undefined && Number.isFinite(cost) && cost >= 0.0) return cost;
  return undefined;
}

/**
 * Break a gateway-settled total into input/output components for reporting:
 * by the rate card's ratio when a price is known, else by token counts. Either
 * way `total_cost` equals the settled figure.
 */
function settledBreakdown(
  total: number,
  usage: TokenUsage,
  price: ModelPrice | undefined,
  audio?: AudioQuantity,
): CostEstimate {
  if (price) {
    const est = estimateCost(price, usage, audio);
    if (est.total_cost > 0.0) {
      const scale = total / est.total_cost;
      return {
        input_cost: est.input_cost * scale,
        output_cost: est.output_cost * scale,
        total_cost: total,
        currency: price.currency,
      };
    }
  }
  // #703. With no token counts at all — an audio row — the ratio split has
  // nothing to divide by, and the fallback below would put the WHOLE settled
  // cost on the output side. For both audio operations the billable quantity is
  // the input, so the fallback is stated here rather than reached by accident.
  const audioOnly =
    usage.prompt_tokens === 0 &&
    usage.completion_tokens === 0 &&
    audio !== undefined &&
    ((audio.audio_seconds ?? 0) > 0 || (audio.audio_characters ?? 0) > 0);
  if (audioOnly) {
    return { input_cost: total, output_cost: 0.0, total_cost: total, currency: "USD" };
  }
  const denominator = usage.prompt_tokens + usage.completion_tokens;
  const input_cost = denominator > 0 ? (total * usage.prompt_tokens) / denominator : 0.0;
  return {
    input_cost,
    output_cost: total - input_cost,
    total_cost: total,
    currency: "USD",
  };
}

/**
 * Price a usage event into a {@link LedgerEntry} (port of `charge`). Throws a
 * {@link BillingError} `price_not_found` when there is neither a settled cost
 * nor a matching rate-card rule.
 *
 * `onDivergence` is the port seam for the `tracing::warn!` in the Rust source
 * (#152): called (never throws / overrides) when a gateway-settled cost drifts
 * beyond tolerance from the rate card.
 */
export function charge(
  book: PriceBook,
  event: BillingEvent,
  onDivergence?: (info: {
    request_id: string;
    provider: string;
    provider_model: string;
    gateway_settled_cost_usd: number;
    price_book_estimate_usd: number;
  }) => void,
): LedgerEntry {
  const usage = reconcileSplit(event.usage);
  const priceOpt = book.priceFor(event.provider, event.provider_model);

  let cost: CostEstimate;
  let unit_price: ModelPrice;
  let cost_source: CostSource;

  // #703. The audio quantities travel on the EVENT, not inside `usage`; see
  // `BillingEvent.audio_seconds`. Passing them through here is what arms the
  // divergence check for a transcription — before it, `expected` was $0 for
  // every audio row, so the check was either disarmed (no card entry) or
  // permanently firing (a card entry with no quantity to price).
  const audio: AudioQuantity = {
    ...(event.audio_seconds !== undefined ? { audio_seconds: event.audio_seconds } : {}),
    ...(event.audio_characters !== undefined ? { audio_characters: event.audio_characters } : {}),
  };

  const settled = authoritativeCost(event);
  if (settled !== undefined) {
    if (priceOpt) {
      const expected = estimateCost(priceOpt, usage, audio).total_cost;
      if (costDiverges(settled, expected)) {
        onDivergence?.({
          request_id: event.request_id,
          provider: event.provider,
          provider_model: event.provider_model,
          gateway_settled_cost_usd: settled,
          price_book_estimate_usd: expected,
        });
      }
    }
    cost = settledBreakdown(settled, usage, priceOpt, audio);
    unit_price = priceOpt ?? modelPriceUsd(0.0, 0.0);
    cost_source = CostSource.GatewaySettled;
  } else {
    if (!priceOpt) {
      throw new BillingError(
        "price_not_found",
        `no rate-card price for provider '${event.provider}' model '${event.provider_model}' and the event carried no settled cost`,
      );
    }
    // #703. A card that matches the model but states no rate for the UNIT this
    // row is measured in cannot price it, and the token arithmetic below would
    // quietly answer $0 — the free-inference bug #129 named, one unit over. So
    // it is the same refusal as no entry at all.
    if (audioQuantityUnpriced(priceOpt, audio)) {
      throw new BillingError(
        "price_not_found",
        `rate-card entry for provider '${event.provider}' model '${event.provider_model}' states no audio rate for this row, and the event carried no settled cost`,
      );
    }
    cost = estimateCost(priceOpt, usage, audio);
    unit_price = priceOpt;
    cost_source = CostSource.BillingPriceBook;
  }

  const credits = book.creditsForUsd(cost.total_cost);

  return {
    id: ledgerEntryId(event),
    request_id: event.request_id,
    trace_id: event.trace_id,
    provider_attempt: { ...event.provider_attempt },
    tenant: { ...event.tenant },
    logical_model: event.logical_model,
    provider: event.provider,
    provider_model: event.provider_model,
    usage,
    usage_source: event.usage_source,
    status_code: event.status_code,
    cost,
    credits,
    unit_price,
    cost_source,
    occurred_at_unix: event.occurred_at_unix,
    wallet_delta_credits: event.wallet_delta_credits,
    wallet_balance_after_credits: event.wallet_balance_after_credits,
  };
}

// ---------------------------------------------------------------------------
// LedgerListFilter (issue #149)
// ---------------------------------------------------------------------------

export interface LedgerListFilter {
  organization_id?: string;
  project_id?: string;
  api_key_id?: string;
}

/** Mirrors `LedgerListFilter::is_empty`. */
export function ledgerFilterIsEmpty(filter: LedgerListFilter): boolean {
  return (
    filter.organization_id === undefined &&
    filter.project_id === undefined &&
    filter.api_key_id === undefined
  );
}

function fieldMatches(filter: string | undefined, actual: string | undefined): boolean {
  return filter === undefined ? true : actual === filter;
}

/** Mirrors `LedgerListFilter::matches` — whether a tenant satisfies the filter. */
export function ledgerFilterMatches(filter: LedgerListFilter, tenant: TenantContext): boolean {
  return (
    fieldMatches(filter.organization_id, tenant.organization_id) &&
    fieldMatches(filter.project_id, tenant.project_id) &&
    fieldMatches(filter.api_key_id, tenant.api_key_id)
  );
}

// ---------------------------------------------------------------------------
// LedgerSink + totals + in-memory implementation.
// ---------------------------------------------------------------------------

export interface LedgerTotals {
  entries: number;
  total_cost_usd: number;
  total_credits: number;
  total_tokens: number;
}

export function emptyLedgerTotals(): LedgerTotals {
  return { entries: 0, total_cost_usd: 0, total_credits: 0, total_tokens: 0 };
}

/** A value an implementation may return either directly or as a promise. */
export type MaybePromise<T> = T | Promise<T>;

/**
 * Persistence seam for settled entries (port of `trait LedgerSink`).
 * Implementations must be idempotent on {@link LedgerEntry.id}.
 *
 * Every method is `MaybePromise`-valued, and that is load-bearing rather than
 * cosmetic. The Rust trait is synchronous because its durable implementation is
 * a blocking Postgres/D1-proxy call on a thread that can block; on Workers there
 * is no such thread and **every** durable store — D1, KV, R2, Queues, a Durable
 * Object stub — is `Promise`-returning. A strictly-synchronous seam would
 * therefore be implementable ONLY by {@link InMemoryLedgerSink}: a D1-backed
 * sink would have to return an unawaited promise, the service would answer 200
 * before the row was written, and an idempotency conflict (which must surface as
 * HTTP 409) would become an unhandled rejection after the response had shipped.
 *
 * So the seam accepts both, {@link InMemoryLedgerSink} stays synchronous, and
 * `createBillingService` awaits — which is a no-op for the sync implementation
 * and correct for a durable one. `test/platform-limits.test.ts` pins it.
 */
export interface LedgerSink {
  /** Persist an entry; `true` if newly recorded, `false` on an idempotent replay. */
  record(entry: LedgerEntry): MaybePromise<boolean>;
  /** List recorded entries matching `filter`, newest last, paginated. */
  list(filter: LedgerListFilter, offset: number, limit: number): MaybePromise<LedgerEntry[]>;
  /** Fetch a single entry by its idempotency id. */
  get(id: string): MaybePromise<LedgerEntry | undefined>;
}

/** In-memory, idempotent {@link LedgerSink} with an optional retention bound. */
export class InMemoryLedgerSink implements LedgerSink {
  private entries: LedgerEntry[] = [];
  private retentionLimit: number | undefined;
  private recordedTotalCount = 0;

  constructor(retentionLimit?: number) {
    this.retentionLimit = retentionLimit;
  }

  static withRetentionLimit(retentionLimit: number): InMemoryLedgerSink {
    return new InMemoryLedgerSink(retentionLimit);
  }

  record(entry: LedgerEntry): boolean {
    const existing = this.entries.find((e) => e.id === entry.id);
    if (existing) {
      if (sameProviderAttemptSettlement(existing, entry)) {
        return false;
      }
      throw new BillingError(
        "billing_idempotency_conflict",
        `ledger id ${entry.id} was replayed with different provider-attempt settlement data`,
      );
    }
    this.entries.push({ ...entry });
    this.recordedTotalCount += 1;
    if (this.retentionLimit !== undefined) {
      while (this.entries.length > this.retentionLimit) {
        this.entries.shift();
      }
    }
    return true;
  }

  list(filter: LedgerListFilter, offset: number, limit: number): LedgerEntry[] {
    return this.entries
      .filter((entry) => ledgerFilterMatches(filter, entry.tenant))
      .slice(offset, offset + limit)
      .map((e) => ({ ...e }));
  }

  get(id: string): LedgerEntry | undefined {
    const found = this.entries.find((entry) => entry.id === id);
    return found ? { ...found } : undefined;
  }

  get length(): number {
    return this.entries.length;
  }

  isEmpty(): boolean {
    return this.entries.length === 0;
  }

  recordedTotal(): number {
    return this.recordedTotalCount;
  }

  totals(): LedgerTotals {
    const totals = emptyLedgerTotals();
    totals.entries = this.entries.length;
    for (const entry of this.entries) {
      totals.total_cost_usd += entry.cost.total_cost;
      totals.total_credits += entry.credits;
      totals.total_tokens += entry.usage.total_tokens;
    }
    return totals;
  }
}

/** Aggregate a page of entries into {@link LedgerTotals} (shared by the service). */
export function ledgerTotals(entries: LedgerEntry[]): LedgerTotals {
  const totals = emptyLedgerTotals();
  totals.entries = entries.length;
  for (const entry of entries) {
    totals.total_cost_usd += entry.cost.total_cost;
    totals.total_credits += entry.credits;
    totals.total_tokens += entry.usage.total_tokens;
  }
  return totals;
}
