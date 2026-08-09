import { describe, expect, it } from "vitest";
import {
  BillingError,
  InMemoryRevenueSink,
  type InboundX402Endpoint,
  type InboundX402RevenueRecord,
  PAYMENT_REQUIRED_STATUS,
  RevenueSource,
  settleInboundPayment,
  validateInboundX402Endpoint,
} from "../src/index.js";
const nn = <T>(v: T): NonNullable<T> => v as NonNullable<T>;

/** Assert `fn` throws a {@link BillingError} carrying `code`. */
function expectBillingCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(BillingError);
    expect((error as BillingError).code).toBe(code);
    return;
  }
  throw new Error("expected a BillingError to be thrown");
}

function record(id: string, amount: bigint): InboundX402RevenueRecord {
  return {
    id,
    revenue_source: RevenueSource.X402Inbound,
    request_id: "req",
    method: "POST",
    tenant: { organization_id: "org" },
    resource_url: "https://api.test/priced",
    network_caip2: "solana:devnet",
    mint: "mint",
    recipient: "recipient",
    atomic_amount: amount,
    challenge_hash_hex: "abcd",
    transaction_signature: "sig",
  };
}

describe("InMemoryRevenueSink (fully ported — issue #356)", () => {
  it("exposes the 402 status constant", () => {
    expect(PAYMENT_REQUIRED_STATUS).toBe(402);
  });

  it("records idempotently and sums totals as bigint", () => {
    const sink = new InMemoryRevenueSink();
    expect(sink.record(record("a", 100n))).toBe(true);
    expect(sink.record(record("a", 100n))).toBe(false); // byte-equal replay is a no-op
    expect(sink.record(record("b", 250n))).toBe(true);
    const totals = sink.totals();
    expect(totals.records).toBe(2);
    expect(totals.total_atomic_amount).toBe(350n);
    expect(nn(sink.get("a")).atomic_amount).toBe(100n);
    expect(sink.list(0, 10)).toHaveLength(2);
  });

  it("fails closed on a same-id replay with different settlement data", () => {
    const sink = new InMemoryRevenueSink();
    sink.record(record("a", 100n));
    expectBillingCode(() => sink.record(record("a", 999n)), "billing_revenue_idempotency_conflict");
  });

  it("enforces a FIFO retention bound", () => {
    const sink = InMemoryRevenueSink.withRetentionLimit(1);
    sink.record(record("a", 100n));
    sink.record(record("b", 200n));
    expect(sink.length).toBe(1);
    expect(sink.recordedTotal()).toBe(2);
    expect(sink.get("a")).toBeUndefined();
    expect(nn(sink.get("b")).atomic_amount).toBe(200n);
  });
});

describe("x402 payment legs — DEPRIORITIZED (deferred per §3)", () => {
  const endpoint: InboundX402Endpoint = {
    resource_url: "https://api.test/priced",
    network_caip2: "solana:devnet",
    mint: "mint",
    recipient: "recipient",
    fee_payer: "fee",
    price_atomic_amount: 100n,
    max_timeout_seconds: 60,
  };

  it("validate throws x402_deprioritized until payments is reprioritized", () => {
    expectBillingCode(() => validateInboundX402Endpoint(endpoint), "x402_deprioritized");
  });

  it("settle throws x402_deprioritized until payments is reprioritized", () => {
    expectBillingCode(
      () => settleInboundPayment(endpoint, { request_id: "r", method: "POST", tenant: {} }, {}),
      "x402_deprioritized",
    );
  });

  // Reinstate when @ferrogate/payments ships the real #350 wire contract.
  it.todo("builds a #350-compatible PAYMENT-REQUIRED challenge and round-trips expected_payment");
  it.todo("couples a matching settlement into an immutable revenue record");
  it.todo("fails closed on network / amount / signature mismatch");
});
