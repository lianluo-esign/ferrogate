/**
 * `@ferrogate/billing` — price book and usage ledger.
 *
 * Replaces the Rust crate `ferrogate-billing`. On Cloudflare, counters live in
 * Durable Objects, the ledger fans out through Queues, and totals persist to D1.
 */
import type { Scope } from "@ferrogate/core";
import type { ErrorEnvelope } from "@ferrogate/schemas";

/** Per-unit prices for a metered dimension (input/output tokens, requests). */
export interface PriceBook {
  currency: string;
  inputPerMTokUsd: number;
  outputPerMTokUsd: number;
}

/** A single metered usage event to be recorded. */
export interface UsageEvent {
  scope: Scope;
  model: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

/** Sink that durably records usage events (Queue → D1 ledger). */
export interface LedgerSink {
  record(event: UsageEvent): Promise<void>;
}

/** Failure shape surfaced by the ledger, reusing the shared error envelope. */
export type BillingError = ErrorEnvelope;
