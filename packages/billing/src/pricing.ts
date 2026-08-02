/**
 * Model pricing registry (rate card) — clean-room port of
 * `ferrogate-billing`'s `pricing.rs`.
 *
 * Wildcard-aware, fail-closed lookup: a `(provider, model)` matching no rule
 * (including the `("*","*")` catch-all, if configured) yields `undefined`, so
 * the caller fails closed rather than billing zero. Includes the asset-egress
 * ($/GB) dimension (issue #262).
 */
import { z } from "zod";
import {
  modelPriceSchema,
  modelPriceUsd,
  withCacheMultipliers,
  type ModelPrice,
} from "./usage.js";

/** 1 USD == 1_000_000 credits (1 credit == 1 micro-USD). */
export const DEFAULT_CREDITS_PER_USD = 1_000_000.0;
/** Bytes in one billed gigabyte for egress metering — decimal GB (10^9, #262). */
export const BYTES_PER_BILLED_GB = 1_000_000_000.0;
/** Conservative default asset-egress rate ($/GB) seeded into the rate card (#262). */
export const DEFAULT_EGRESS_PRICE_PER_GB = 0.09;

const WILDCARD = "*";

/**
 * Settled USD cost of transferring `bytes` at `price_per_gb` (#262). Shared so
 * the rate card and per-download metering can never drift on the GB divisor.
 */
export function egressCostUsd(price_per_gb: number, bytes: number): number {
  return (bytes / BYTES_PER_BILLED_GB) * price_per_gb;
}

// ---------------------------------------------------------------------------
// PriceEntry
// ---------------------------------------------------------------------------

export interface PriceEntry {
  provider: string;
  model: string;
  price: ModelPrice;
}

export const priceEntrySchema = z.object({
  provider: z.string(),
  model: z.string(),
  price: modelPriceSchema,
});

/** Mirrors `PriceEntry::new`. */
export function priceEntry(provider: string, model: string, price: ModelPrice): PriceEntry {
  return { provider, model, price };
}

// ---------------------------------------------------------------------------
// PriceBook
// ---------------------------------------------------------------------------

/** The full-object JSON form of a rate card (`{ entries, credits_per_usd, egress_price_per_gb? }`). */
const priceBookObjectSchema = z.object({
  entries: z.array(priceEntrySchema).default([]),
  credits_per_usd: z.number().default(DEFAULT_CREDITS_PER_USD),
  egress_price_per_gb: z.number().nullish().transform((v) => v ?? undefined),
});

export class PriceBook {
  entries: PriceEntry[];
  credits_per_usd: number;
  egress_price_per_gb?: number;

  constructor(
    entries: PriceEntry[] = [],
    credits_per_usd: number = DEFAULT_CREDITS_PER_USD,
    egress_price_per_gb?: number,
  ) {
    this.entries = entries;
    this.credits_per_usd = credits_per_usd;
    this.egress_price_per_gb = egress_price_per_gb;
  }

  /** Mirrors `PriceBook::default`. */
  static default(): PriceBook {
    return new PriceBook([], DEFAULT_CREDITS_PER_USD, undefined);
  }

  /** Mirrors `PriceBook::new` (entries only; default credits, unpriced egress). */
  static new(entries: PriceEntry[]): PriceBook {
    return new PriceBook(entries, DEFAULT_CREDITS_PER_USD, undefined);
  }

  /** Mirrors `PriceBook::with_egress_price_per_gb` (builder). */
  withEgressPricePerGb(egress_price_per_gb: number): this {
    this.egress_price_per_gb = egress_price_per_gb;
    return this;
  }

  /** Mirrors `PriceBook::with_credits_per_usd` (builder). */
  withCreditsPerUsd(credits_per_usd: number): this {
    this.credits_per_usd = credits_per_usd;
    return this;
  }

  /**
   * Settled USD cost of `bytes` of asset egress under this rate card (#262),
   * or `undefined` when egress is unpriced so the caller can fail closed.
   */
  egressCostUsd(bytes: number): number | undefined {
    if (this.egress_price_per_gb === undefined) return undefined;
    return egressCostUsd(this.egress_price_per_gb, bytes);
  }

  get length(): number {
    return this.entries.length;
  }

  isEmpty(): boolean {
    return this.entries.length === 0;
  }

  /**
   * Resolve the price for a `(provider, model)` pair, most specific first:
   * exact → `(provider,"*")` → `("*",model)` → `("*","*")`. `undefined` when
   * nothing matches (fail-closed).
   */
  priceFor(provider: string, model: string): ModelPrice | undefined {
    return (
      this.find(provider, model) ??
      this.find(provider, WILDCARD) ??
      this.find(WILDCARD, model) ??
      this.find(WILDCARD, WILDCARD)
    );
  }

  private find(provider: string, model: string): ModelPrice | undefined {
    const entry = this.entries.find((e) => e.provider === provider && e.model === model);
    return entry?.price;
  }

  /** Mirrors `PriceBook::credits_for_usd`. */
  creditsForUsd(total_cost_usd: number): number {
    return total_cost_usd * this.credits_per_usd;
  }

  /**
   * Parse a rate card from JSON — accepts either a bare `PriceEntry[]` array or
   * a full `{ entries, credits_per_usd, egress_price_per_gb? }` object (mirrors
   * `PriceBook::from_json_slice`). Throws on malformed input.
   */
  static fromJson(input: string | Uint8Array | unknown): PriceBook {
    let value: unknown = input;
    if (typeof input === "string") {
      value = JSON.parse(input);
    } else if (input instanceof Uint8Array) {
      value = JSON.parse(new TextDecoder().decode(input));
    }
    // Try the full-object form first, then fall back to a bare array.
    const asObject = priceBookObjectSchema.safeParse(value);
    if (asObject.success && !Array.isArray(value)) {
      const o = asObject.data;
      return new PriceBook(o.entries, o.credits_per_usd, o.egress_price_per_gb);
    }
    const asArray = z.array(priceEntrySchema).safeParse(value);
    if (asArray.success) {
      return PriceBook.new(asArray.data);
    }
    throw new Error(
      `failed to parse price book: ${asObject.success ? "not an array" : asObject.error.message}`,
    );
  }

  /** Serialize back to the wire object form (for config round-trips). */
  toJSON(): {
    entries: PriceEntry[];
    credits_per_usd: number;
    egress_price_per_gb: number | null;
  } {
    return {
      entries: this.entries,
      credits_per_usd: this.credits_per_usd,
      egress_price_per_gb: this.egress_price_per_gb ?? null,
    };
  }

  /**
   * A conservative default rate card covering the major vendors FerroGate
   * proxies (per-1M-token USD), keyed on the wildcard provider `"*"` and the
   * concrete model id, plus a seeded egress rate (#262). Mirrors
   * `PriceBook::with_default_rate_card`.
   *
   * ## Cache rates as MULTIPLIERS (issue #667)
   *
   * Each family's cache rates are stated as a ratio of the base input rate the
   * entry already carries, using each vendor's own published cache structure:
   *
   *  - **Anthropic** — cache read 0.1x input, 5-minute cache write 1.25x. The
   *    ratio is model-independent, which is why it can be stated once here.
   *  - **OpenAI** — automatic prompt caching discounts cached input and charges
   *    nothing to write, so only a read multiplier is given (0.5x on the 4o
   *    family, 0.1x on the 5 family).
   *  - **Gemini** — context caching bills cached tokens at 0.25x input. The
   *    storage-hour component of explicit caching is a different meter entirely
   *    and is deliberately not modelled as a token rate.
   *  - **DeepSeek** — publishes a cache-hit input price directly rather than a
   *    ratio; the multiplier below reproduces it (0.07/0.27, 0.14/0.55).
   *
   * These are DEFAULTS for a card an operator is expected to replace, exactly
   * like the base rates beside them. A model whose entry states no cache rate
   * prices cached tokens at its ordinary input rate — never at zero — so the
   * failure direction of a missing multiplier is a slightly high bill, not a
   * free one.
   */
  static withDefaultRateCard(): PriceBook {
    const entries: PriceEntry[] = [
      priceEntry("*", "gpt-5.5", withCacheMultipliers(modelPriceUsd(5.0, 15.0), 0.1)),
      priceEntry("*", "gpt-5", withCacheMultipliers(modelPriceUsd(5.0, 15.0), 0.1)),
      priceEntry("*", "gpt-4o", withCacheMultipliers(modelPriceUsd(2.5, 10.0), 0.5)),
      priceEntry("*", "gpt-4o-mini", withCacheMultipliers(modelPriceUsd(0.15, 0.6), 0.5)),
      priceEntry(
        "*",
        "claude-sonnet-4",
        withCacheMultipliers(modelPriceUsd(3.0, 15.0), 0.1, 1.25),
      ),
      priceEntry(
        "*",
        "claude-opus-4",
        withCacheMultipliers(modelPriceUsd(15.0, 75.0), 0.1, 1.25),
      ),
      priceEntry("*", "gemini-2.5-pro", withCacheMultipliers(modelPriceUsd(1.25, 10.0), 0.25)),
      priceEntry("*", "gemini-2.5-flash", withCacheMultipliers(modelPriceUsd(0.3, 2.5), 0.25)),
      priceEntry("*", "grok-4", withCacheMultipliers(modelPriceUsd(3.0, 15.0), 0.25)),
      priceEntry(
        "*",
        "deepseek-chat",
        withCacheMultipliers(modelPriceUsd(0.27, 1.1), 0.07 / 0.27),
      ),
      priceEntry(
        "*",
        "deepseek-reasoner",
        withCacheMultipliers(modelPriceUsd(0.55, 2.19), 0.14 / 0.55),
      ),
    ];
    return PriceBook.new(entries).withEgressPricePerGb(DEFAULT_EGRESS_PRICE_PER_GB);
  }
}
