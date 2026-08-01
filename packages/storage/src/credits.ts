/**
 * The credit unit domain — ONE place where cents become credits, and one place
 * where a credit crosses the D1 parameter boundary.
 *
 * ## Why this module exists at all
 *
 * The admin surface talks in **cents** (`amount_cents`, `balance_cents`); every
 * table in `sql/d1-ts/tenant/` that holds money holds **integer credits**
 * (`wallets.balance_credits`, `wallet_reservations.amount_credits`,
 * `wallet_settlements.delta_credits`), where 1 credit == 1 micro-USD. Those two
 * halves were unconnected — `apps/control-plane` wrote a `balance_cents`
 * document in the CONTROL database and `apps/gateway` admitted requests against
 * `balance_credits` in the TENANT database — and the conversion between them
 * had never been written down anywhere. A conversion that gets re-derived at
 * each call site is a conversion that will eventually be re-derived wrongly, in
 * the money path, so it is derived here exactly once.
 *
 * ## Everything is `bigint`, and that is not fussiness
 *
 * `docs/legacy/inventory-data-billing.md` §2.5 requires credits to stay
 * `bigint` in TS ("only USD is `number`"). The reason is arithmetic, not
 * typing: `100_000_000_000_001` cents is an exactly-representable `number`, but
 * `100_000_000_000_001 * 10_000` is **not** — the nearest double is
 * `1_000_000_000_000_009_984`, sixteen credits short of the true product. Worse,
 * `Number.prototype.toString` prints the SHORTEST decimal that round-trips, so
 * that wrong value prints as `1000000000000010000` and looks correct in every
 * log line and every JSON body. Only an exact reader catches it.
 *
 * So {@link centsToCredits} takes a `number` (the JSON wire type the admin API
 * accepts) and returns a `bigint`, and refuses anything that is not an exact
 * integer rather than silently truncating a fractional cent into money.
 *
 * ## `bindCredits` — the D1 boundary
 *
 * **D1 cannot bind a `bigint`.** `stmt.bind(1_000_000_000_000_010_000n)` throws
 * `D1_TYPE_ERROR: Type 'bigint' not supported`, and binding the equivalent
 * `number` re-introduces exactly the drift above. The marshalling that IS exact
 * is the decimal string: SQLite applies INTEGER affinity to a text literal
 * bound into an INTEGER column, and to a text operand of `+`, converting it
 * losslessly for any value inside the int64 range. {@link bindCredits} is that
 * conversion, and it range-checks first — a credit total past int64 would be
 * stored by SQLite as a REAL and start drifting inside the database, which is
 * the one failure no reader could later detect.
 *
 * Reading back has the mirror problem: D1 decodes an INTEGER column into a JS
 * `number`, which is lossy past 2^53. {@link creditsFromText} is the exact
 * reader, and it is why the queries that need exactness select
 * `CAST(<column> AS TEXT)`.
 */
import { StorageError } from "./errors.js";

/**
 * 1 USD == 1_000_000 credits (1 credit == 1 micro-USD).
 *
 * The `number` twins of this constant are `@ferrogate/billing`'s
 * `DEFAULT_CREDITS_PER_USD` (a rate-card default an operator may override) and
 * `apps/gateway/src/metering/credits.ts`'s (the USD→credits settlement path).
 * This one is the `bigint` form used for the cents↔credits conversion, which
 * neither of those performs.
 */
export const CREDITS_PER_USD = 1_000_000n;

/** 1 USD == 100 cents. */
export const CENTS_PER_USD = 100n;

/**
 * 1 cent == 10_000 credits.
 *
 * Exact by construction: 1_000_000 is divisible by 100, so no cent value ever
 * needs rounding on the way IN. (The way OUT does — see {@link creditsToCents}.)
 */
export const CREDITS_PER_CENT = CREDITS_PER_USD / CENTS_PER_USD;

/** SQLite's INTEGER range. Past this a value is stored as REAL and starts drifting. */
const INT64_MAX = 9_223_372_036_854_775_807n;
const INT64_MIN = -9_223_372_036_854_775_808n;

/**
 * Convert a signed cent amount to credits, exactly.
 *
 * Takes a `number` because that is what a JSON body carries, and refuses a
 * non-integer or non-safe one: `1.5` cents is not money this system can
 * represent, and a value past 2^53 has already lost digits before this function
 * could see them — accepting either would launder an unrepresentable amount
 * into an exact-looking credit total.
 */
export function centsToCredits(cents: number): bigint {
  if (!Number.isSafeInteger(cents)) {
    throw StorageError.conflict(
      `wallet amount ${cents} is not an exact integer number of cents (safe-integer range)`,
    );
  }
  return BigInt(cents) * CREDITS_PER_CENT;
}

/**
 * Convert credits back to cents for DISPLAY, rounding toward negative infinity.
 *
 * The direction is deliberate. Credits are 10_000× finer than cents, so a
 * balance the gateway has been spending against is almost never a whole number
 * of cents, and the remainder has to go somewhere. Flooring means the reported
 * balance is never MORE than the customer actually has — an operator reading it
 * can under-promise but cannot over-promise. Rounding half-up, or truncating
 * toward zero (which rounds a NEGATIVE balance up), would both report money
 * that is not there.
 *
 * This is the only lossy direction in the module, and nothing decides anything
 * on its result: every arithmetic decision is taken in credits.
 */
export function creditsToCents(credits: bigint): bigint {
  const quotient = credits / CREDITS_PER_CENT;
  const remainder = credits % CREDITS_PER_CENT;
  return remainder < 0n ? quotient - 1n : quotient;
}

/**
 * Marshal a credit amount into a D1 bind parameter.
 *
 * A decimal STRING, because D1 rejects `bigint` outright and a `number` is
 * lossy past 2^53. See the module docblock for why this is exact.
 */
export function bindCredits(credits: bigint): string {
  if (credits > INT64_MAX || credits < INT64_MIN) {
    throw StorageError.conflict(
      `wallet amount ${credits} is outside the int64 range SQLite stores exactly`,
    );
  }
  return credits.toString();
}

/**
 * Decode a credit column selected as `CAST(<column> AS TEXT)`.
 *
 * `null` (an absent row, or a NULL column) is `undefined` rather than `0n`:
 * "no wallet" and "a wallet at zero" are different facts everywhere in this
 * package, and collapsing them here would push the wrong one up to the
 * admission gate.
 */
export function creditsFromText(value: unknown): bigint | undefined {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw StorageError.runtime(
        `credit column decoded as a lossy double (${value}); select CAST(... AS TEXT)`,
      );
    }
    return BigInt(value);
  }
  if (typeof value !== "string" || value.trim() === "") return undefined;
  try {
    return BigInt(value.trim());
  } catch {
    throw StorageError.runtime(`credit column is not an integer literal: ${value}`);
  }
}
