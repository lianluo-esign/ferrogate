/**
 * Port of the x402 wallet-hold money-safety floor from
 * `ferrogate-config`'s `config/types.rs` (issues #400/#401): the single
 * definition of the smallest hold TTL that strictly outlives the settlement
 * confirmation window. Shared by the load-time `validate_x402_reconciler`
 * check and the runtime clamp in `X402SettlementLoop::open`, so the two can
 * never drift.
 *
 * Arithmetic is saturating: an operator-supplied tick larger than i64::MAX (or
 * component sums that overflow) must produce an absurdly LARGE window — which
 * rejects/clamps conservatively — never a wrapped small one.
 */

const I64_MAX = (1n << 63n) - 1n;

/** The reconciler fields the hold-TTL floor arithmetic reads. */
export interface X402ReconcilerLike {
  tick_interval_secs: number | bigint;
  confirmation_deadline_secs: number | bigint;
  reconcile_check_delay_secs: number | bigint;
}

function saturatingAdd(a: bigint, b: bigint): bigint {
  const sum = a + b;
  return sum > I64_MAX ? I64_MAX : sum;
}

function toI64Saturating(value: number | bigint): bigint {
  const v = typeof value === "bigint" ? value : BigInt(Math.trunc(value));
  return v > I64_MAX ? I64_MAX : v;
}

/**
 * The settlement confirmation window (seconds) a wallet hold must survive:
 * `confirmation_deadline_secs + reconcile_check_delay_secs + one reconciler
 * tick of slack`.
 */
export function x402ConfirmationWindowSecs(reconciler: X402ReconcilerLike): bigint {
  const slack = toI64Saturating(reconciler.tick_interval_secs);
  return saturatingAdd(
    saturatingAdd(
      toI64Saturating(reconciler.confirmation_deadline_secs),
      toI64Saturating(reconciler.reconcile_check_delay_secs),
    ),
    slack,
  );
}

/**
 * THE money-safety floor for an x402 wallet hold TTL: the smallest TTL that
 * STRICTLY outlives {@link x402ConfirmationWindowSecs}, i.e. `window + 1`.
 */
export function x402HoldTtlFloorSecs(reconciler: X402ReconcilerLike): bigint {
  return saturatingAdd(x402ConfirmationWindowSecs(reconciler), 1n);
}
