/**
 * Integer credits — the money domain, as `bigint`, with no float anywhere in
 * the conversion.
 *
 * `docs/legacy/inventory-data-billing.md` §2.5 is explicit about this: the
 * `f64` USD math ports to JS `number` fine, **except** the integer-credit
 * domain (`DEFAULT_CREDITS_PER_USD = 1e6`, `wallets.balance_credits BIGINT`,
 * `wallet_reservations.amount_credits BIGINT`, `wallet_settlements.
 * delta_credits BIGINT`) — "keep credits as `bigint` in TS to preserve the
 * no-drift property; only USD is `number`".
 *
 * Two drift sources exist and both are closed here:
 *
 *  1. **The multiply.** Rust computes the wallet debit as
 *     `-((cost_usd * DEFAULT_CREDITS_PER_USD).round() as i64)`
 *     (`state_wallets.rs::debit_wallet_for_settled_cost`). `cost_usd * 1e6` is
 *     an `f64` product, so it is already rounded to 53 bits BEFORE `.round()`
 *     sees it. {@link usdToCredits} instead expands the double to its EXACT
 *     decimal rational and does the multiply in `bigint`, so the only rounding
 *     is the single, explicit half-away-from-zero step that `f64::round`
 *     specifies. Same result for every value a rate card produces; exact for
 *     the ones where the `f64` product would have drifted.
 *  2. **The accumulate.** A running credit total is the thing that actually
 *     breaks: `Number` loses integers past 2^53, so a tenant balance in the
 *     quadrillions silently stops counting. {@link sumCredits} is `bigint`
 *     addition and cannot.
 *
 * Nothing in this module allocates a `number` for a credit value at any point.
 */

/** 1 USD == 1_000_000 credits (1 credit == 1 micro-USD). Rust `DEFAULT_CREDITS_PER_USD`. */
export const DEFAULT_CREDITS_PER_USD = 1_000_000;

/** A finite decimal as an exact rational `numerator / denominator`. */
interface ExactDecimal {
  readonly numerator: bigint;
  /** Always a positive power of ten. */
  readonly denominator: bigint;
}

const DECIMAL = /^([+-]?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/;

function pow10(exponent: number): bigint {
  return 10n ** BigInt(exponent);
}

/**
 * Expand a finite JS `number` to the EXACT decimal it prints as.
 *
 * `Number.prototype.toString` emits the shortest decimal that round-trips to
 * the same double, which is the value every other part of the system (JSON on
 * the wire, a rate card in KV, an operator reading a log line) agrees the
 * number is. Parsing that string is therefore both exact with respect to the
 * observable value and free of the binary artefacts `toFixed`-style scaling
 * would reintroduce.
 */
function exactDecimal(value: number): ExactDecimal {
  if (!Number.isFinite(value)) {
    throw new RangeError(`cannot convert non-finite value ${value} to credits`);
  }
  const match = DECIMAL.exec(value.toString());
  if (match === null) {
    // Unreachable for a finite double, but a silent 0 here would bill nothing.
    throw new RangeError(`unparsable numeric literal ${value.toString()}`);
  }
  const [, sign = "", whole = "0", fraction = "", exponent = "0"] = match;
  const digits = BigInt(whole + fraction);
  const scale = Number(exponent) - fraction.length;
  const signed = sign === "-" ? -digits : digits;
  return scale >= 0
    ? { numerator: signed * pow10(scale), denominator: 1n }
    : { numerator: signed, denominator: pow10(-scale) };
}

/** Divide exactly, rounding half AWAY from zero — Rust `f64::round`'s rule. */
function divideRoundHalfAwayFromZero(numerator: bigint, denominator: bigint): bigint {
  const negative = numerator < 0n;
  const magnitude = negative ? -numerator : numerator;
  const quotient = magnitude / denominator;
  const remainder = magnitude % denominator;
  const rounded = remainder * 2n >= denominator ? quotient + 1n : quotient;
  return negative ? -rounded : rounded;
}

/**
 * Settled USD → integer credits.
 *
 * Port of `PriceBook::credits_for_usd` + the `.round() as i64` in
 * `debit_wallet_for_settled_cost`, fused into one exact step. `creditsPerUsd`
 * is the rate card's (a `PriceBook` may configure any rate, and the Rust tests
 * use 1_000).
 *
 * @throws RangeError when either input is not finite — a NaN cost must never
 * degrade into a 0-credit charge.
 */
export function usdToCredits(usd: number, creditsPerUsd: number = DEFAULT_CREDITS_PER_USD): bigint {
  const cost = exactDecimal(usd);
  const rate = exactDecimal(creditsPerUsd);
  return divideRoundHalfAwayFromZero(
    cost.numerator * rate.numerator,
    cost.denominator * rate.denominator,
  );
}

/**
 * Integer credits → USD, for DISPLAY ONLY.
 *
 * The result is a `number` and therefore lossy past 2^53 credits; never feed it
 * back into a balance. It exists so a log line or an admin listing can show
 * dollars without every caller re-deriving the divisor.
 */
export function creditsToUsd(
  credits: bigint,
  creditsPerUsd: number = DEFAULT_CREDITS_PER_USD,
): number {
  return Number(credits) / creditsPerUsd;
}

/** Exact `bigint` sum — the accumulator a `number` running total would lose. */
export function sumCredits(values: Iterable<bigint>): bigint {
  let total = 0n;
  for (const value of values) {
    total += value;
  }
  return total;
}

/**
 * The wallet debit for a settled charge: negative credits, or `undefined` when
 * nothing is owed.
 *
 * Mirrors `debit_wallet_for_settled_cost`'s two early returns verbatim —
 * `cost_usd <= 0.0` and a debit that rounds to zero credits both produce NO
 * wallet movement, which is what keeps "no wallet" distinguishable from
 * "debited zero credits" on the ledger entry (`ledger_test.rs:203`).
 */
export function walletDeltaCredits(
  costUsd: number,
  creditsPerUsd: number = DEFAULT_CREDITS_PER_USD,
): bigint | undefined {
  if (!(costUsd > 0)) {
    return undefined;
  }
  const credits = usdToCredits(costUsd, creditsPerUsd);
  return credits === 0n ? undefined : -credits;
}
