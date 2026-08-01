/**
 * x402 payment-attempt state alphabet + the single CAS transition seam
 * (ports the state machine from `ferrogate-storage::payment_attempt`).
 *
 * PORT-TODO(D: §1.4.5 / §1.5.4): x402/Solana payments are DEPRIORITIZED and the D1
 * backend defers `transition_payment_attempt` + payment methods. In the Rust
 * tree the state alphabet proper lives in `ferrogate-payments`
 * (`PaymentAttemptState`), which maps to `@ferrogate/payments`; this module keeps
 * only the storage-side string constants and the pure CAS decision so the
 * generation-guarded transition seam is expressible when payments are resumed.
 *
 * State machine:
 *   challenged --authorize--> authorized --submit--> submitted --settle--> settled (terminal)
 *       |            |                        +--outcome_unknown--> outcome_unknown
 *       |            +--release--> released (terminal)   +--settle--> settled
 *       |            +--fail-----> failed   (terminal)   +--fail----> failed
 *       +--deny----> denied (terminal)
 *       +--release-> released (terminal)
 */

export const PAYMENT_ATTEMPT_CHALLENGED = "challenged";
export const PAYMENT_ATTEMPT_AUTHORIZED = "authorized";
export const PAYMENT_ATTEMPT_SUBMITTED = "submitted";
export const PAYMENT_ATTEMPT_SETTLED = "settled";
export const PAYMENT_ATTEMPT_DENIED = "denied";
export const PAYMENT_ATTEMPT_RELEASED = "released";
export const PAYMENT_ATTEMPT_FAILED = "failed";
export const PAYMENT_ATTEMPT_OUTCOME_UNKNOWN = "outcome_unknown";

export type PaymentAttemptState =
  | "challenged"
  | "authorized"
  | "submitted"
  | "settled"
  | "denied"
  | "released"
  | "failed"
  | "outcome_unknown";

const TERMINAL_STATES: ReadonlySet<string> = new Set([
  PAYMENT_ATTEMPT_SETTLED,
  PAYMENT_ATTEMPT_DENIED,
  PAYMENT_ATTEMPT_RELEASED,
  PAYMENT_ATTEMPT_FAILED,
]);

/** Whether a state string is terminal. An unknown spelling is NOT terminal. */
export function isPaymentAttemptStateTerminal(state: string): boolean {
  return TERMINAL_STATES.has(state);
}

/** Outcome of {@link transitionPaymentAttempt}. */
export type PaymentAttemptTransition =
  | { kind: "applied"; toState: PaymentAttemptState; generation: number }
  | { kind: "idempotent"; state: PaymentAttemptState; generation: number }
  | { kind: "conflict"; currentState: string; currentGeneration: number };

/**
 * The single CAS transition seam (ports `transition_payment_attempt`): a short
 * conditional gated on the current state + `generation` operation token. Pure —
 * decides the outcome given the observed current row and the requested edge:
 *  - already `toState`      ⇒ idempotent (no write);
 *  - current ∈ `allowedFrom` and generation matches ⇒ applied (generation + 1);
 *  - else                   ⇒ conflict (lost update / illegal edge).
 */
export function transitionPaymentAttempt(
  currentState: string,
  currentGeneration: number,
  allowedFrom: readonly PaymentAttemptState[],
  toState: PaymentAttemptState,
  expectedGeneration: number,
): PaymentAttemptTransition {
  if (currentState === toState) {
    return { kind: "idempotent", state: toState, generation: currentGeneration };
  }
  if (
    (allowedFrom as readonly string[]).includes(currentState) &&
    currentGeneration === expectedGeneration
  ) {
    return { kind: "applied", toState, generation: currentGeneration + 1 };
  }
  return { kind: "conflict", currentState, currentGeneration };
}
