/**
 * Token-usage metering primitives — clean-room port of the value types in
 * `ferrogate-billing`'s `lib.rs` (`TokenUsage`, `ModelPrice`, `CostEstimate`,
 * `BillingUsageSource`, `ProviderAttempt`).
 *
 * Pure arithmetic, no I/O. All money is USD `number` (Rust `f64`); the
 * integer-credit / wallet domain lives on {@link ../event.ts} and is `bigint`
 * per the inventory's no-drift directive (§2.5).
 */
import { z } from "zod";

/** Non-negative integer (`u64`) guard for token/counter fields. */
export const u64 = z.number().int().min(0);
/** `u32` guard (Rust `u32` for provider-attempt / workflow versions). */
export const u32 = z.number().int().min(0).max(4_294_967_295);
/** `u16` guard (HTTP status codes on the wire event). */
export const u16 = z.number().int().min(0).max(65_535);

// ---------------------------------------------------------------------------
// TokenUsage
// ---------------------------------------------------------------------------

/**
 * Token counts for one settled call.
 *
 * ## The subset invariant (issue #667)
 *
 * The three cached/reasoning counters are SUBSETS of the two headline counts,
 * never additions to them:
 *
 *     cached_input_tokens ⊆ prompt_tokens
 *     cache_write_tokens  ⊆ prompt_tokens   (disjoint from cached_input_tokens)
 *     reasoning_tokens    ⊆ completion_tokens
 *
 * so `prompt_tokens` is always the WHOLE billable input and `total_tokens` never
 * needs adjusting. That is a normalization, and the gateway's capture layer
 * (`apps/gateway/src/inference/usage.ts`) is where each vendor is converted onto
 * it — because the vendors disagree about it and this package must not:
 *
 *  - **OpenAI / Gemini** already report `cached_tokens` /
 *    `cachedContentTokenCount` as a subset of the prompt count.
 *  - **Anthropic** reports `input_tokens` EXCLUDING both cache counters, so the
 *    capture layer adds them in.
 *  - **Gemini** reports `candidatesTokenCount` EXCLUDING `thoughtsTokenCount`,
 *    so the capture layer adds thoughts into the completion count (which is
 *    what `totalTokenCount` already assumed).
 *
 * Doing it the other way — an `additive` flag on the usage record, or a
 * per-vendor branch in {@link estimateCost} — would put provider vocabulary
 * into the money path, where every new family is a new chance to bill wrong.
 *
 * All three default to `0`, so a pre-#667 event on the wire parses unchanged and
 * prices to the figure it always priced to.
 */
export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  /** Prompt tokens served from a prompt cache — a SUBSET of `prompt_tokens`. */
  cached_input_tokens?: number;
  /** Prompt tokens written INTO a prompt cache — a SUBSET of `prompt_tokens`. */
  cache_write_tokens?: number;
  /** Reasoning/thinking tokens — a SUBSET of `completion_tokens`. */
  reasoning_tokens?: number;
}

export const tokenUsageSchema = z.object({
  prompt_tokens: u64.default(0),
  completion_tokens: u64.default(0),
  total_tokens: u64.default(0),
  // `.default(0)`, not `.optional()`: an event minted before #667 must parse,
  // and "the provider reported no cached tokens" and "this event predates the
  // counter" price identically, so distinguishing them buys nothing and would
  // leak `undefined` into arithmetic.
  cached_input_tokens: u64.default(0),
  cache_write_tokens: u64.default(0),
  reasoning_tokens: u64.default(0),
});

/**
 * Mirrors `TokenUsage::new`.
 *
 * The #667 counters are emitted as concrete zeros rather than left off, so a
 * value built here is byte-identical to the same value parsed from the wire
 * (where they are `.default(0)`) and to the same value run through
 * {@link reconcileSplit}. Rust has no `Option` here at all — the asymmetry is a
 * TypeScript artifact, and every place it can leak is closed the same way.
 */
export function newTokenUsage(
  prompt_tokens: number,
  completion_tokens: number,
  total_tokens: number,
): TokenUsage {
  return {
    prompt_tokens,
    completion_tokens,
    total_tokens,
    cached_input_tokens: 0,
    cache_write_tokens: 0,
    reasoning_tokens: 0,
  };
}

/** Mirrors `TokenUsage::estimate_missing_total`. */
export function estimateMissingTotal(usage: TokenUsage): TokenUsage {
  const out = { ...usage };
  if (out.total_tokens === 0) {
    out.total_tokens = out.prompt_tokens + out.completion_tokens;
  }
  return out;
}

/**
 * Reconcile the prompt/completion split with `total_tokens` before pricing
 * (issue #140): a provider-omitted side must not be billed at $0.
 *
 * - `total == 0`            → `total = prompt + completion`
 * - `completion == 0 && total > prompt`     → `completion = total - prompt`
 * - `prompt == 0 && total > completion`     → `prompt = total - completion`
 */
export function reconcileSplit(usage: TokenUsage): TokenUsage {
  const out = {
    ...usage,
    // #667 — NORMALIZE the three optional counters to concrete zeros, and do it
    // here because `charge()` runs every event through this function on the way
    // into a `LedgerEntry`.
    //
    // This is not tidiness. `sameProviderAttemptSettlement` is the idempotency
    // arbiter, and it compares a freshly-charged entry against one RELOADED
    // from `entry_json` — which came back through `tokenUsageSchema`, where
    // these fields are `.default(0)`. Leave them `undefined` on the fresh side
    // and `undefined !== 0` makes an honest replay of the SAME settlement look
    // like divergent data, so an at-least-once outbox delivery raises
    // `billing_idempotency_conflict` instead of being absorbed as the no-op it
    // is. Observed as a real failure in `apps/gateway/test/metering/d1.test.ts`
    // ("absorbs a replay as a duplicate") the moment the fields were added.
    cached_input_tokens: usage.cached_input_tokens ?? 0,
    cache_write_tokens: usage.cache_write_tokens ?? 0,
    reasoning_tokens: usage.reasoning_tokens ?? 0,
  };
  if (out.total_tokens === 0) {
    out.total_tokens = out.prompt_tokens + out.completion_tokens;
  } else {
    if (out.completion_tokens === 0 && out.total_tokens > out.prompt_tokens) {
      out.completion_tokens = out.total_tokens - out.prompt_tokens;
    }
    if (out.prompt_tokens === 0 && out.total_tokens > out.completion_tokens) {
      out.prompt_tokens = out.total_tokens - out.completion_tokens;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// ModelPrice / CostEstimate
// ---------------------------------------------------------------------------

export interface CostEstimate {
  input_cost: number;
  output_cost: number;
  total_cost: number;
  currency: string;
}

export const costEstimateSchema = z.object({
  input_cost: z.number().default(0),
  output_cost: z.number().default(0),
  total_cost: z.number().default(0),
  currency: z.string().default("USD"),
});

/**
 * A rate-card rule.
 *
 * The three cached/reasoning rates (issue #667) are OPTIONAL, and their absence
 * means "price these tokens at the ordinary rate" rather than "price them at
 * zero". That is the backward-compatibility contract stated as behaviour: a
 * rate card written before #667 keeps loading and keeps producing exactly the
 * figures it produced before, and the only way to opt into a cached discount is
 * to state one. The alternative — defaulting a discount an operator never
 * configured — would silently reduce every cached invoice by a number nobody
 * chose.
 */
export interface ModelPrice {
  input_price_per_1m: number;
  output_price_per_1m: number;
  /** USD per 1M CACHE-READ prompt tokens (#667). Absent ⇒ `input_price_per_1m`. */
  cached_input_price_per_1m?: number;
  /** USD per 1M CACHE-WRITE prompt tokens (#667). Absent ⇒ `input_price_per_1m`. */
  cache_write_price_per_1m?: number;
  /** USD per 1M reasoning/thinking tokens (#667). Absent ⇒ `output_price_per_1m`. */
  reasoning_price_per_1m?: number;
  currency: string;
}

const optRate = z
  .number()
  .nullish()
  .transform((v) => v ?? undefined);

export const modelPriceSchema = z.object({
  input_price_per_1m: z.number(),
  output_price_per_1m: z.number(),
  cached_input_price_per_1m: optRate,
  cache_write_price_per_1m: optRate,
  reasoning_price_per_1m: optRate,
  currency: z.string(),
});

/** Mirrors `ModelPrice::usd`. */
export function modelPriceUsd(
  input_price_per_1m: number,
  output_price_per_1m: number,
): ModelPrice {
  return { input_price_per_1m, output_price_per_1m, currency: "USD" };
}

/**
 * A price with cache rates expressed as MULTIPLES of its own input rate (#667).
 *
 * Vendors publish cache pricing as a ratio of the base input rate — Anthropic's
 * cache read is 0.1x and its 5-minute cache write 1.25x of whatever the model's
 * input price is — so a rate card that already states the base rate can carry
 * the cache rates as that ratio instead of as a second, independently-rottable
 * number. Change the base price and the cache prices follow.
 */
export function withCacheMultipliers(
  price: ModelPrice,
  readMultiplier: number,
  writeMultiplier?: number,
): ModelPrice {
  return {
    ...price,
    cached_input_price_per_1m: price.input_price_per_1m * readMultiplier,
    ...(writeMultiplier === undefined
      ? {}
      : { cache_write_price_per_1m: price.input_price_per_1m * writeMultiplier }),
  };
}

/** A non-negative integer count, defaulting to 0 (a counter the event omitted). */
function count(value: number | undefined): number {
  return value !== undefined && Number.isFinite(value) && value > 0 ? Math.trunc(value) : 0;
}

/**
 * The prompt-token split a call is priced on: cache reads, cache writes, and the
 * fresh remainder, in that precedence order.
 *
 * CLAMPED, because the subset invariant is asserted by this package and produced
 * by another. A provider (or an adapter bug) reporting more cached tokens than
 * prompt tokens would otherwise drive the fresh remainder NEGATIVE, and a
 * negative token count multiplied by a positive rate is a CREDIT to the customer
 * conjured out of a malformed usage frame. Clamping bills at most the prompt
 * tokens that were actually reported, which is the conservative direction and
 * the only one that cannot invent money.
 *
 * Exported so the gateway's model-registry settlement leg
 * (`apps/gateway/src/metering/route-price.ts`) splits identically — two
 * settlement paths that disagreed on the split would make the same request cost
 * different amounts depending on where its price was configured.
 */
export function inputTokenSplit(usage: TokenUsage): {
  cachedRead: number;
  cacheWrite: number;
  fresh: number;
} {
  const prompt = count(usage.prompt_tokens);
  const cachedRead = Math.min(count(usage.cached_input_tokens), prompt);
  const cacheWrite = Math.min(count(usage.cache_write_tokens), prompt - cachedRead);
  return { cachedRead, cacheWrite, fresh: prompt - cachedRead - cacheWrite };
}

/** The completion-token split: reasoning tokens and the visible remainder. */
export function outputTokenSplit(usage: TokenUsage): {
  reasoning: number;
  visible: number;
} {
  const completion = count(usage.completion_tokens);
  const reasoning = Math.min(count(usage.reasoning_tokens), completion);
  return { reasoning, visible: completion - reasoning };
}

/**
 * Mirrors `ModelPrice::estimate` — price token usage into a {@link CostEstimate}.
 *
 * Cached/cache-write tokens are billed out of the input side and reasoning
 * tokens out of the output side (issue #667), each at its own rate when the card
 * states one. With all three counters at zero — every pre-#667 event — the
 * arithmetic collapses to `prompt * input + completion * output`, which is
 * exactly what it was.
 */
export function estimateCost(price: ModelPrice, usage: TokenUsage): CostEstimate {
  const { cachedRead, cacheWrite, fresh } = inputTokenSplit(usage);
  const { reasoning, visible } = outputTokenSplit(usage);

  const cachedRate = price.cached_input_price_per_1m ?? price.input_price_per_1m;
  const writeRate = price.cache_write_price_per_1m ?? price.input_price_per_1m;
  const reasoningRate = price.reasoning_price_per_1m ?? price.output_price_per_1m;

  const input_cost =
    (fresh * price.input_price_per_1m +
      cachedRead * cachedRate +
      cacheWrite * writeRate) /
    1_000_000.0;
  const output_cost =
    (visible * price.output_price_per_1m + reasoning * reasoningRate) / 1_000_000.0;
  return {
    input_cost,
    output_cost,
    total_cost: input_cost + output_cost,
    currency: price.currency,
  };
}

// ---------------------------------------------------------------------------
// BillingUsageSource
// ---------------------------------------------------------------------------

/** `enum BillingUsageSource` — serde `rename_all = "snake_case"`. */
export type BillingUsageSource = "provider_usage" | "gateway_estimate";

export const BillingUsageSource = {
  ProviderUsage: "provider_usage",
  GatewayEstimate: "gateway_estimate",
} as const;

export const billingUsageSourceSchema = z.enum([
  "provider_usage",
  "gateway_estimate",
]);

/** Mirrors `BillingUsageSource::as_str` (identity — the wire tag is the string). */
export function billingUsageSourceAsStr(source: BillingUsageSource): string {
  return source;
}

// ---------------------------------------------------------------------------
// ProviderAttempt
// ---------------------------------------------------------------------------

/**
 * Stable identity for one concrete provider dispatch within a logical AI
 * request (issue #213). Serialized flat (`#[serde(flatten)]`) onto the
 * billing event / ledger entry.
 */
export interface ProviderAttempt {
  provider_attempt_id: string;
  provider_attempt_index: number;
}

export const providerAttemptSchema = z.object({
  provider_attempt_id: z.string().default(""),
  provider_attempt_index: u32.default(0),
});

/** Mirrors `ProviderAttempt::for_request`. */
export function providerAttemptForRequest(
  request_id: string,
  provider_attempt_index: number,
): ProviderAttempt {
  return {
    provider_attempt_id: `${request_id}:provider-attempt:${provider_attempt_index}`,
    provider_attempt_index,
  };
}

/** Mirrors `ProviderAttempt::is_legacy` — empty/blank id ⇒ pre-#213 event. */
export function providerAttemptIsLegacy(attempt: ProviderAttempt): boolean {
  return attempt.provider_attempt_id.trim().length === 0;
}

/** Default provider attempt (legacy sentinel). */
export function defaultProviderAttempt(): ProviderAttempt {
  return { provider_attempt_id: "", provider_attempt_index: 0 };
}
