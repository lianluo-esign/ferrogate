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

export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export const tokenUsageSchema = z.object({
  prompt_tokens: u64.default(0),
  completion_tokens: u64.default(0),
  total_tokens: u64.default(0),
});

/** Mirrors `TokenUsage::new`. */
export function newTokenUsage(
  prompt_tokens: number,
  completion_tokens: number,
  total_tokens: number,
): TokenUsage {
  return { prompt_tokens, completion_tokens, total_tokens };
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
  const out = { ...usage };
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

export interface ModelPrice {
  input_price_per_1m: number;
  output_price_per_1m: number;
  currency: string;
}

export const modelPriceSchema = z.object({
  input_price_per_1m: z.number(),
  output_price_per_1m: z.number(),
  currency: z.string(),
});

/** Mirrors `ModelPrice::usd`. */
export function modelPriceUsd(
  input_price_per_1m: number,
  output_price_per_1m: number,
): ModelPrice {
  return { input_price_per_1m, output_price_per_1m, currency: "USD" };
}

/** Mirrors `ModelPrice::estimate` — price token usage into a {@link CostEstimate}. */
export function estimateCost(price: ModelPrice, usage: TokenUsage): CostEstimate {
  const input_cost = (usage.prompt_tokens * price.input_price_per_1m) / 1_000_000.0;
  const output_cost = (usage.completion_tokens * price.output_price_per_1m) / 1_000_000.0;
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
