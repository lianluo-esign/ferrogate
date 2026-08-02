/**
 * The x402 wire contract `@ferrogate/policy` binds against has exactly ONE
 * definition, and it lives in `@ferrogate/payments`.
 *
 * Rust makes this structural: `crates/ferrogate-policy/Cargo.toml` depends on
 * `ferrogate-payments`, and `x402_spend.rs` opens with
 * `use ferrogate_payments::{validate_solana_address, PaymentIntent,
 * SelectedPayment, SolanaNetwork};`. There is one `PaymentIntent` and one
 * `intent_hash_hex` in the whole workspace.
 *
 * The danger of a second TS copy is not cosmetic. `authorizeX402Payment` seals
 * its decision to `intent.intentHashHex()`; the proof builder in
 * `@ferrogate/payments` signs against the same seal. Two independent
 * implementations of that hash can drift by one NUL byte and the gateway would
 * authorize one payment while signing another — with both packages' suites
 * green, because each tests its own copy.
 *
 * These tests fail if `packages/policy/src/x402/wire.ts` ever goes back to
 * declaring its own types.
 */
import { describe, expect, test } from "vitest";
import {
  PaymentIntent as PaymentsPaymentIntent,
  PaymentIntentError as PaymentsPaymentIntentError,
  RequestBodyHash as PaymentsRequestBodyHash,
  caip2ForNetwork,
  challengeHashHex as paymentsChallengeHashHex,
  solanaNetworkFromCaip2,
  validateSolanaAddress,
  type SelectedPayment as PaymentsSelectedPayment,
} from "@ferrogate/payments";
import {
  CAIP2_SOLANA_DEVNET,
  CAIP2_SOLANA_MAINNET,
  MAX_TIMEOUT_SECONDS,
  PAYMENT_INTENT_HASH_DOMAIN,
  PaymentIntent,
  PaymentIntentError,
  RequestBodyHash,
  SCHEME_EXACT,
  X402_VERSION,
  challengeHashHex,
  hexLower,
  isValidSolanaAddress,
  networkCaip2,
  networkFromCaip2,
  requestBodyHashHex,
  sha256,
  timeoutInRange,
  type PaymentIntentIdentity,
  type SelectedPayment,
} from "../src/index.js";

const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT_A = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER = "So11111111111111111111111111111111111111112";
const RESOURCE_URL = "https://api.example.com/paid/report";

function selected(overrides: Partial<SelectedPayment> = {}): SelectedPayment {
  return {
    network: "devnet",
    mint: USDC_DEVNET,
    atomicAmount: 100_000n,
    recipient: RECIPIENT_A,
    resourceUrl: RESOURCE_URL,
    maxTimeoutSeconds: 300,
    challengeHash: new Uint8Array(32).fill(0xab),
    feePayer: FEE_PAYER,
    memo: null,
    recentBlockhash: null,
    lastValidBlockHeight: null,
    extensions: null,
    rawRequirement: null,
    ...overrides,
  };
}

const IDENTITY: PaymentIntentIdentity = {
  tenantId: "tenant-1",
  projectId: "proj-1",
  keyId: "key-1",
  runId: "run-1",
  workerId: "worker-1",
  requestId: "req-1",
};

describe("x402 wire contract is sourced from @ferrogate/payments", () => {
  test("the exported PaymentIntent is literally the payments class, not a copy", () => {
    // Object identity: a re-declared local class would be a different object
    // even if every method body matched.
    expect(PaymentIntent).toBe(PaymentsPaymentIntent);
    expect(PaymentIntentError).toBe(PaymentsPaymentIntentError);
    expect(RequestBodyHash).toBe(PaymentsRequestBodyHash);
    const intent = PaymentIntent.fromSelected(selected(), "GET", RESOURCE_URL, new Uint8Array(0), IDENTITY);
    expect(intent).toBeInstanceOf(PaymentsPaymentIntent);
  });

  test("the helper functions are the payments functions (aliased, not re-implemented)", () => {
    expect(networkFromCaip2).toBe(solanaNetworkFromCaip2);
    expect(networkCaip2).toBe(caip2ForNetwork);
    expect(challengeHashHex).toBe(paymentsChallengeHashHex);
  });

  test("the constants are the payments constants, value for value", () => {
    expect(X402_VERSION).toBe(2);
    expect(SCHEME_EXACT).toBe("exact");
    expect(MAX_TIMEOUT_SECONDS).toBe(86_400);
    expect(PAYMENT_INTENT_HASH_DOMAIN).toBe("ferrogate.x402.payment-intent.v1");
    expect(networkFromCaip2(CAIP2_SOLANA_MAINNET)).toBe("mainnet");
    expect(networkFromCaip2(CAIP2_SOLANA_DEVNET)).toBe("devnet");
    expect(networkCaip2("devnet")).toBe(CAIP2_SOLANA_DEVNET);
  });

  test("the intent seal is byte-frozen — a drift in either package breaks this", () => {
    const intent = PaymentIntent.fromSelected(selected(), "get", RESOURCE_URL, new Uint8Array(0), IDENTITY);
    // Frozen vector. Domain-tagged, NUL-separated, presence-flagged optional
    // identity components; `get` is normalised to `GET` before hashing.
    expect(intent.intentHashHex()).toBe(
      "896b7494f2ccc26d6f5e735796b0637d6d18d234a0e86bbfe369fe431fd67192",
    );
  });

  test("an optional identity component is bound to its SLOT, not just its content", () => {
    // Same string, different identity slot. A hash that concatenated only the
    // present values would collide these two into one seal, letting a project
    // id stand in for a workspace id.
    const asProject = PaymentIntent.fromSelected(selected(), "GET", RESOURCE_URL, new Uint8Array(0), {
      tenantId: "t",
      requestId: "r",
      projectId: "a",
    });
    const asWorkspace = PaymentIntent.fromSelected(selected(), "GET", RESOURCE_URL, new Uint8Array(0), {
      tenantId: "t",
      requestId: "r",
      workspaceId: "a",
    });
    const neither = PaymentIntent.fromSelected(selected(), "GET", RESOURCE_URL, new Uint8Array(0), {
      tenantId: "t",
      requestId: "r",
    });
    expect(asProject.intentHashHex()).not.toBe(asWorkspace.intentHashHex());
    expect(asProject.intentHashHex()).not.toBe(neither.intentHashHex());
    expect(asWorkspace.intentHashHex()).not.toBe(neither.intentHashHex());
  });

  test("an empty-string identity component is refused rather than hashed as absent", () => {
    try {
      PaymentIntent.fromSelected(selected(), "GET", RESOURCE_URL, new Uint8Array(0), {
        tenantId: "t",
        requestId: "r",
        runId: "",
      });
      throw new Error("expected a PaymentIntentError");
    } catch (err) {
      expect((err as PaymentIntentError).kind).toBe("invalid_identity");
      expect((err as PaymentIntentError).field).toBe("run_id");
    }
  });
});

describe("the payments draft-validation taxonomy now reaches the policy layer", () => {
  // This is what the closed PORT-TODO bought: the policy layer's own
  // `PaymentIntent` copied wire terms verbatim with no validation, so a
  // malformed intent reached `authorizeX402Payment` and was hashed as if sound.
  test("a non-base58 recipient is rejected at construction", () => {
    expect(() =>
      PaymentIntent.fromSelected(
        selected({ recipient: "merchant@example.com" }),
        "GET",
        RESOURCE_URL,
        new Uint8Array(0),
        IDENTITY,
      ),
    ).toThrowError(PaymentIntentError);
    try {
      PaymentIntent.fromSelected(
        selected({ recipient: "merchant@example.com" }),
        "GET",
        RESOURCE_URL,
        new Uint8Array(0),
        IDENTITY,
      );
      throw new Error("expected a PaymentIntentError");
    } catch (err) {
      expect((err as PaymentIntentError).kind).toBe("invalid_address");
    }
  });

  test("a zero atomic amount is rejected", () => {
    try {
      PaymentIntent.fromSelected(selected({ atomicAmount: 0n }), "GET", RESOURCE_URL, new Uint8Array(0), IDENTITY);
      throw new Error("expected a PaymentIntentError");
    } catch (err) {
      expect((err as PaymentIntentError).kind).toBe("zero_amount");
    }
  });

  test("a non-token HTTP method is rejected", () => {
    try {
      PaymentIntent.fromSelected(selected(), "GET /x", RESOURCE_URL, new Uint8Array(0), IDENTITY);
      throw new Error("expected a PaymentIntentError");
    } catch (err) {
      expect((err as PaymentIntentError).kind).toBe("invalid_http_method");
    }
  });

  test("a non-absolute authorized resource URL is rejected", () => {
    try {
      PaymentIntent.fromSelected(selected(), "GET", "/paid/report", new Uint8Array(0), IDENTITY);
      throw new Error("expected a PaymentIntentError");
    } catch (err) {
      expect((err as PaymentIntentError).kind).toBe("invalid_resource_url");
    }
  });

  test("an out-of-range merchant timeout is rejected", () => {
    try {
      PaymentIntent.fromSelected(
        selected({ maxTimeoutSeconds: MAX_TIMEOUT_SECONDS + 1 }),
        "GET",
        RESOURCE_URL,
        new Uint8Array(0),
        IDENTITY,
      );
      throw new Error("expected a PaymentIntentError");
    } catch (err) {
      expect((err as PaymentIntentError).kind).toBe("timeout_out_of_range");
    }
  });
});

describe("the two policy-local adapters match the Rust call shape", () => {
  test("isValidSolanaAddress is the boolean form of validate_solana_address", () => {
    for (const candidate of [USDC_DEVNET, RECIPIENT_A, FEE_PAYER, "USDC", "", "0OIl", "merchant@example.com"]) {
      let ok = true;
      try {
        validateSolanaAddress("probe", candidate);
      } catch {
        ok = false;
      }
      expect(isValidSolanaAddress(candidate)).toBe(ok);
    }
  });

  test("requestBodyHashHex is RequestBodyHash::of(body).as_hex()", () => {
    const body = new TextEncoder().encode('{"q":"report"}');
    expect(requestBodyHashHex(body)).toBe(RequestBodyHash.of(body).asHex());
    // ...and a plain, untagged SHA-256, interoperable with every other
    // request-body hash in the codebase.
    expect(requestBodyHashHex(body)).toBe(hexLower(sha256(body)));
    expect(requestBodyHashHex(new Uint8Array(0))).toBe(RequestBodyHash.empty().asHex());
  });

  test("timeoutInRange brackets 1..=MAX_TIMEOUT_SECONDS on the contract's number domain", () => {
    expect(timeoutInRange(1)).toBe(true);
    expect(timeoutInRange(MAX_TIMEOUT_SECONDS)).toBe(true);
    expect(timeoutInRange(0)).toBe(false);
    expect(timeoutInRange(MAX_TIMEOUT_SECONDS + 1)).toBe(false);
    expect(timeoutInRange(1.5)).toBe(false);
  });
});

describe("the wire type the policy layer accepts IS the wire type", () => {
  test("a SelectedPayment built as the payments type is accepted unchanged", () => {
    // A structural regression (policy re-declaring a narrower SelectedPayment)
    // would make this assignment a type error at `bun run typecheck`.
    const fromWire: PaymentsSelectedPayment = selected();
    const asPolicy: SelectedPayment = fromWire;
    expect(asPolicy.challengeHash).toHaveLength(32);
    expect(challengeHashHex(asPolicy)).toBe("ab".repeat(32));
  });
});
