/**
 * `@ferrogate/payments` — x402 / non-custodial payment authorization.
 *
 * Replaces the Rust crate `ferrogate-payments`. DEPRIORITIZED: this is a
 * stub-only surface (x402/Solana work is deferred per project directive). It
 * never holds keys and never self-authorizes spend.
 */
import type { Scope } from "@ferrogate/core";
import type { ErrorEnvelope } from "@ferrogate/schemas";

/** A challenge presented by an upstream on HTTP 402. */
export interface PaymentChallenge {
  scope: Scope;
  amountUsd: number;
  evidence: string;
}

/** The result of presenting spend evidence to the external authority. */
export interface PaymentAuthorization {
  authorized: boolean;
  reason?: string;
}

/** Failure shape surfaced by the payment path. */
export type PaymentError = ErrorEnvelope;

/** Stub authorizer — deferred; always declines until x402 is reprioritized. */
export const stubPaymentAuthorizer = {
  authorize(_challenge: PaymentChallenge): PaymentAuthorization {
    return { authorized: false, reason: "x402 payments deprioritized (stub)" };
  },
};
