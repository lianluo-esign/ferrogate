import { describe, expect, test } from "vitest";

import {
  PaymentError,
  SDK_EVIDENCE,
  SDK_NAME,
  SDK_VERDICT,
  SDK_VERSION,
  SdkVerdict,
  isPaymentError,
  sdkUnavailable,
} from "../src/index.js";

describe("PaymentError failure contract", () => {
  test("every variant renders a distinct, non-empty Display string", () => {
    const all = [
      PaymentError.malformedHeader("PAYMENT-REQUIRED", "r"),
      PaymentError.oversizedHeader("PAYMENT-REQUIRED", 1, 2),
      PaymentError.unsupportedVersion("1"),
      PaymentError.noAcceptableRequirement(),
      PaymentError.unsupportedNetwork("eip155:1"),
      PaymentError.unsupportedScheme("upto"),
      PaymentError.unsupportedMint("m"),
      PaymentError.invalidAmount("0", "zero"),
      PaymentError.invalidRecipient("payTo", "x"),
      PaymentError.invalidTimeout("zero"),
      PaymentError.signerRejected("denied"),
      PaymentError.proofBuildFailed("empty"),
      PaymentError.malformedSettlement("bad"),
      PaymentError.sdkIncompatible("msrv"),
    ];
    const rendered = new Set(all.map((e) => e.message));
    expect(rendered.size).toBe(all.length);
    for (const e of all) {
      expect(e.message.length).toBeGreaterThan(0);
      expect(isPaymentError(e)).toBe(true);
    }
    // Kinds are all distinct too.
    expect(new Set(all.map((e) => e.kind)).size).toBe(all.length);
  });

  test("is a real Error subclass with a stable kind discriminant", () => {
    const e = PaymentError.invalidAmount("0", "zero amount");
    expect(e).toBeInstanceOf(Error);
    expect(e.kind).toBe("invalid_amount");
    expect(e.data.amount).toBe("0");
    expect(e.message).toBe('invalid atomic amount "0": zero amount');
  });
});

describe("SDK qualification record (#350)", () => {
  test("is frozen NotUsableYet with the MSRV evidence", () => {
    expect(SDK_NAME).toBe("solana-pay-kit");
    expect(SDK_VERSION).toBe("0.2.0");
    expect(SDK_VERDICT).toBe(SdkVerdict.NotUsableYet);
    expect(SDK_EVIDENCE).toContain("rustc >= 1.89");
    const err = sdkUnavailable();
    expect(err.kind).toBe("sdk_incompatible");
  });
});
