/**
 * Inbound (merchant-side) fixed-price x402 monetization — partial clean-room
 * port of `ferrogate-billing`'s `x402_inbound.rs` (issue #356).
 *
 * PORT-TODO(D: §2.2 / §3 — x402 DEPRIORITIZED): the challenge-construction,
 * `expected_payment`, and settlement legs depend on the frozen #350 x402 wire
 * contract from `ferrogate-payments` (`parse_payment_required`,
 * `select_requirement`, `SolanaNetwork`, `SettlementEvidence`,
 * `validate_solana_address`, the challenge hash). Per the project directive and
 * inventory §3, all x402/Solana payment work is deferred and `@ferrogate/payments`
 * is a stub only — so those legs are captured as shapes + throwing stubs here,
 * NOT silently dropped. The **revenue persistence seam** ({@link RevenueSink} /
 * {@link InMemoryRevenueSink}) has no payments dependency and IS ported in full,
 * so the storage/idempotency half of the loop is exercisable today.
 */
import type { TenantContext } from "@ferrogate/core";
import { BillingError } from "./event.js";

/** HTTP status an unpaid call to the priced endpoint receives. */
export const PAYMENT_REQUIRED_STATUS = 402;

// ---------------------------------------------------------------------------
// Revenue provenance + records (self-contained — fully ported).
// ---------------------------------------------------------------------------

/** Port of `enum RevenueSource` — this crate only mints `X402Inbound`. */
export type RevenueSource = "x402_inbound";
export const RevenueSource = { X402Inbound: "x402_inbound" } as const;

/** Immutable, self-describing evidence of one settled inbound paid call. */
export interface InboundX402RevenueRecord {
  /** `x402-inbound:<challenge_hash_hex>:<transaction_signature>`. */
  id: string;
  revenue_source: RevenueSource;
  request_id: string;
  trace_id?: string;
  method: string;
  tenant: TenantContext;
  resource_url: string;
  network_caip2: string;
  mint: string;
  recipient: string;
  /** Settled revenue in atomic token units — ALWAYS the endpoint's fixed price. */
  atomic_amount: bigint;
  challenge_hash_hex: string;
  transaction_signature: string;
  /** Payer wallet (attribution ONLY; never the FerroGate tenant). */
  payer?: string;
  occurred_at_unix?: number;
}

/** Per-call attribution the gateway resolves for an inbound paid request. */
export interface InboundX402CallContext {
  request_id: string;
  trace_id?: string;
  method: string;
  /** FerroGate tenant the priced endpoint is attributed to — never a caller header. */
  tenant: TenantContext;
  occurred_at_unix?: number;
}

/** Aggregate inbound-revenue totals (`total_atomic_amount` cannot overflow — `bigint`). */
export interface RevenueTotals {
  records: number;
  total_atomic_amount: bigint;
}

function recordsEqual(a: InboundX402RevenueRecord, b: InboundX402RevenueRecord): boolean {
  return JSON.stringify(toComparable(a)) === JSON.stringify(toComparable(b));
}
function toComparable(r: InboundX402RevenueRecord): Record<string, unknown> {
  return { ...r, atomic_amount: r.atomic_amount.toString() };
}

/**
 * Persistence seam for settled inbound revenue records (port of `trait
 * RevenueSink`) — deliberately distinct from the token-usage ledger so
 * stablecoin revenue is never conflated with it. Idempotent on the record id.
 */
export interface RevenueSink {
  record(record: InboundX402RevenueRecord): boolean;
  list(offset: number, limit: number): InboundX402RevenueRecord[];
  get(id: string): InboundX402RevenueRecord | undefined;
}

/** In-memory, idempotent {@link RevenueSink} with an optional retention bound. */
export class InMemoryRevenueSink implements RevenueSink {
  private records: InboundX402RevenueRecord[] = [];
  private retentionLimit: number | undefined;
  private recordedTotalCount = 0;

  constructor(retentionLimit?: number) {
    this.retentionLimit = retentionLimit;
  }

  static withRetentionLimit(retentionLimit: number): InMemoryRevenueSink {
    return new InMemoryRevenueSink(retentionLimit);
  }

  record(record: InboundX402RevenueRecord): boolean {
    const existing = this.records.find((r) => r.id === record.id);
    if (existing) {
      if (recordsEqual(existing, record)) return false;
      throw new BillingError(
        "billing_revenue_idempotency_conflict",
        `inbound revenue id ${record.id} was replayed with different settlement data`,
      );
    }
    this.records.push({ ...record });
    this.recordedTotalCount += 1;
    if (this.retentionLimit !== undefined) {
      while (this.records.length > this.retentionLimit) {
        this.records.shift();
      }
    }
    return true;
  }

  list(offset: number, limit: number): InboundX402RevenueRecord[] {
    return this.records.slice(offset, offset + limit).map((r) => ({ ...r }));
  }

  get(id: string): InboundX402RevenueRecord | undefined {
    const found = this.records.find((r) => r.id === id);
    return found ? { ...found } : undefined;
  }

  get length(): number {
    return this.records.length;
  }

  isEmpty(): boolean {
    return this.records.length === 0;
  }

  recordedTotal(): number {
    return this.recordedTotalCount;
  }

  totals(): RevenueTotals {
    let total = 0n;
    for (const r of this.records) total += r.atomic_amount;
    return { records: this.records.length, total_atomic_amount: total };
  }
}

// ---------------------------------------------------------------------------
// Fixed-price endpoint config + settlement (DEFERRED — see module PORT-TODO).
// ---------------------------------------------------------------------------

/** The operator-authored fixed-price monetization config for ONE inbound endpoint. */
export interface InboundX402Endpoint {
  resource_url: string;
  resource_description?: string;
  resource_mime_type?: string;
  network_caip2: string;
  mint: string;
  recipient: string;
  fee_payer: string;
  price_atomic_amount: bigint;
  max_timeout_seconds: number;
  memo?: string;
  challenge_error?: string;
}

/**
 * PORT-TODO(D: §3 — x402 DEPRIORITIZED): validate a fixed-price endpoint. Needs
 * `ferrogate-payments`' `SolanaNetwork::from_caip2`, `validate_solana_address`,
 * `MAX_TIMEOUT_SECONDS`, and `MAX_MEMO_BYTES`, which are stub-only in
 * `@ferrogate/payments`. Reinstate the field-by-field fail-closed checks when
 * x402 is reprioritized (see the Rust `InboundX402Endpoint::validate`).
 */
export function validateInboundX402Endpoint(_endpoint: InboundX402Endpoint): never {
  throw new BillingError(
    "x402_deprioritized",
    "inbound x402 endpoint validation is deferred (x402/Solana work deprioritized; @ferrogate/payments is a stub)",
  );
}

/**
 * PORT-TODO(D: §3 — x402 DEPRIORITIZED): couple a paid call's settlement evidence
 * to a fixed-price endpoint. Needs the frozen #350 wire parser + challenge hash
 * from `ferrogate-payments`. Reinstate the fail-closed success/network/
 * signature/amount checks (see the Rust `settle_inbound_payment`) when revived.
 */
export function settleInboundPayment(
  _endpoint: InboundX402Endpoint,
  _ctx: InboundX402CallContext,
  _evidence: unknown,
): never {
  throw new BillingError(
    "x402_deprioritized",
    "inbound x402 settlement is deferred (x402/Solana work deprioritized; @ferrogate/payments is a stub)",
  );
}
