/**
 * Payment-attempt state alphabet (issue #352).
 *
 * Faithful port of the Rust `PaymentAttemptState` enum: the eight states, their
 * terminal / pre-submission / reconcilable / initial classification, and the
 * durable string spellings the `payment_attempts.state` CHECK constraint uses.
 * Pure types — no storage, no SQL, no I/O.
 *
 * # The one semantic that may not change
 *
 * `outcome_unknown` is NON-TERMINAL and RETAINS the wallet hold. After proof
 * submission, a timeout or RPC ambiguity is not proof the money did not move —
 * releasing the hold there could spend stablecoin without ever charging the
 * internal wallet. `isPreSubmission` (the TTL sweeper) and `isReconcilable`
 * (the settlement reconciler) are kept on disjoint sides of that line.
 *
 * The state value IS its durable spelling, so the string and the enum can never
 * drift apart.
 */

/**
 * Every state, in the order the durable `state` CHECK constraint lists them.
 * Mirrors `PaymentAttemptState::ALL`.
 */
export const PAYMENT_ATTEMPT_STATES = [
  "challenged",
  "authorized",
  "submitted",
  "settled",
  "denied",
  "released",
  "failed",
  "outcome_unknown",
] as const;

/** One state of the durable x402 payment attempt. */
export type PaymentAttemptState = (typeof PAYMENT_ATTEMPT_STATES)[number];

const STATE_SET: ReadonlySet<string> = new Set(PAYMENT_ATTEMPT_STATES);

/**
 * Parse a durable spelling. Returns `undefined` for anything outside the
 * alphabet — an unknown state is never coerced to a default, because guessing
 * here would mean guessing whether a hold is live.
 */
export function parsePaymentAttemptState(value: string): PaymentAttemptState | undefined {
  return STATE_SET.has(value) ? (value as PaymentAttemptState) : undefined;
}

/** True for the four states no transition may leave. */
export function isTerminal(state: PaymentAttemptState): boolean {
  return (
    state === "settled" || state === "denied" || state === "released" || state === "failed"
  );
}

/**
 * True for the states a TTL sweep may expire by RELEASING the hold: the payment
 * proof has not gone on-chain, so no stablecoin can have moved. `submitted` and
 * `outcome_unknown` are deliberately excluded.
 */
export function isPreSubmission(state: PaymentAttemptState): boolean {
  return state === "authorized" || state === "challenged";
}

/**
 * True for the non-terminal post-submission states the on-chain settlement
 * reconciler drives to a definite terminal. Deliberately DISJOINT from
 * {@link isPreSubmission} so the TTL sweeper and the reconciler can never both
 * act on one attempt.
 */
export function isReconcilable(state: PaymentAttemptState): boolean {
  return state === "submitted" || state === "outcome_unknown";
}

/** True for the states an attempt may be CREATED in — the machine's entry points. */
export function isInitial(state: PaymentAttemptState): boolean {
  return state === "challenged" || state === "authorized" || state === "denied";
}

/**
 * True iff this state RETAINS its wallet hold while non-terminal. Exactly
 * `outcome_unknown`: post-submission ambiguity is not proof the money did not
 * move.
 */
export function retainsHoldWhenUnresolved(state: PaymentAttemptState): boolean {
  return state === "outcome_unknown";
}
