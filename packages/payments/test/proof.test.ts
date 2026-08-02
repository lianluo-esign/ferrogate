import { describe, expect, test } from "vitest";

import {
  base58Decode,
  buildPaymentSignature,
  decodeBase64Std,
  parsePaymentRequired,
  type PaymentError,
  type SelectedPayment,
  SecretBytes,
  selectRequirement,
  type SvmTransferIntent,
  type SvmTransferSigner,
} from "../src/index.js";
import {
  FEE_PAYER,
  PAY_TO,
  paymentRequiredDevnet,
  paymentRequiredMainnet,
  paymentRequiredSponsored,
  toHeader,
} from "./fixtures.js";

function kindOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return (e as PaymentError).kind;
  }
  throw new Error("expected a PaymentError");
}

function decodePayload(header: string): Record<string, unknown> {
  const bytes = decodeBase64Std(header);
  if (bytes === null) throw new Error("header not base64");
  return JSON.parse(new TextDecoder().decode(bytes));
}

class FixedSigner implements SvmTransferSigner {
  constructor(private readonly tx: Uint8Array) {}
  payerAddress(): string {
    return PAY_TO;
  }
  signTransfer(_intent: SvmTransferIntent): Uint8Array {
    return this.tx;
  }
}

class RefusingSigner implements SvmTransferSigner {
  payerAddress(): string {
    return PAY_TO;
  }
  signTransfer(_intent: SvmTransferIntent): Uint8Array {
    throw new Error("user denied payment");
  }
}

function selectedMainnet(): SelectedPayment {
  return selectRequirement(parsePaymentRequired(toHeader(paymentRequiredMainnet())));
}

describe("SecretBytes redaction", () => {
  test("never leaks bytes through toString / inspect / JSON", () => {
    const raw = Uint8Array.from(new Array(32).fill(0xab));
    const secret = new SecretBytes(raw);
    const str = secret.toString();
    expect(str).toContain("REDACTED");
    expect(str.toLowerCase()).not.toContain("ab, ab");
    expect(str).not.toContain("171");
    expect(JSON.stringify(secret)).toBe('"[REDACTED]"');
    expect(secret.len()).toBe(32);
    expect(secret.isEmpty()).toBe(false);
    expect(secret.expose()).toEqual(raw);
  });

  /**
   * PLATFORM LIMIT PIN — kept as a PORT-TODO in `src/proof.ts`.
   *
   * Rust's `SecretBytes` zeroes its buffer in `Drop`. JS has no deterministic
   * destructor, so the timed erasure is unreproducible. These assertions pin
   * the containment that IS implemented, so nobody later "closes" the marker
   * with a `FinalizationRegistry` scrub that runs at an unspecified time or
   * never, and so the copy-in guarantee cannot be optimised away.
   */
  test("the bytes are copied in, not aliased to the caller's buffer", () => {
    const raw = Uint8Array.from([1, 2, 3, 4]);
    const secret = new SecretBytes(raw);
    // A caller zeroing its own buffer (the closest thing to Rust's scrub that
    // JS offers) must not empty the secret out from under the signer...
    raw.fill(0);
    expect(secret.expose()).toEqual(Uint8Array.from([1, 2, 3, 4]));
    // ...nor may a later write to the caller's buffer inject bytes into it.
    raw.set([9, 9, 9, 9]);
    expect(secret.expose()).toEqual(Uint8Array.from([1, 2, 3, 4]));
  });

  test("the buffer is unreachable by enumeration, spread, or property access", () => {
    const secret = new SecretBytes(Uint8Array.from([7, 7, 7, 7]));
    expect(Object.keys(secret)).toEqual([]);
    expect(Object.values(secret)).toEqual([]);
    expect(JSON.stringify({ ...secret })).toBe("{}");
    expect((secret as unknown as Record<string, unknown>)["bytes"]).toBeUndefined();
    expect(JSON.stringify({ wallet: secret })).toBe('{"wallet":"[REDACTED]"}');
  });

  test("no encoding of the bytes leaks (hex/base64/decimal)", () => {
    const raw = Uint8Array.from([1, 22, 240, 15, 200, 3, 99, 128]);
    const secret = new SecretBytes(raw);
    const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
    const decimals = [...raw].map((b) => b.toString()).join(", ");
    for (const sink of [secret.toString(), JSON.stringify(secret)]) {
      expect(sink).not.toContain(hex);
      expect(sink).not.toContain(decimals);
    }
  });
});

describe("buildPaymentSignature", () => {
  test("produces a PaymentPayload echoing the accepted requirement + signed tx", () => {
    const selected = selectedMainnet();
    const header = buildPaymentSignature(selected, new FixedSigner(new Uint8Array(96).fill(7)));
    const payload = decodePayload(header);
    expect(payload.x402Version).toBe(2);
    expect((payload.resource as any).url).toBe("https://pay.example.com/premium-data");
    expect((payload.accepted as any).amount).toBe("1000");
    const tx = decodeBase64Std((payload.payload as any).transaction as string);
    expect(tx).toEqual(new Uint8Array(96).fill(7));
    // No extensions on this challenge → no invented empty object.
    expect("extensions" in payload).toBe(false);
  });

  test("echoes server extensions verbatim when present, absent otherwise", () => {
    const sponsored = selectRequirement(parsePaymentRequired(toHeader(paymentRequiredSponsored())));
    const header = buildPaymentSignature(sponsored, new FixedSigner(new Uint8Array(128).fill(9)));
    const payload = decodePayload(header);
    expect(payload.extensions).toEqual({
      bazaar: { info: { category: "market-data" }, schema: { type: "object" } },
    });

    const plain = selectRequirement(parsePaymentRequired(toHeader(paymentRequiredDevnet())));
    const plainPayload = decodePayload(
      buildPaymentSignature(plain, new FixedSigner(new Uint8Array(64).fill(1))),
    );
    expect("extensions" in plainPayload).toBe(false);
  });

  test("the injected intent carries the validated terms", () => {
    const selected = selectedMainnet();
    let seen: SvmTransferIntent | undefined;
    const signer: SvmTransferSigner = {
      payerAddress: () => PAY_TO,
      signTransfer: (intent) => {
        seen = intent;
        return new Uint8Array(96).fill(7);
      },
    };
    buildPaymentSignature(selected, signer);
    expect(seen?.feePayer).toBe(FEE_PAYER);
    expect(seen?.atomicAmount).toBe(1000n);
    expect(base58Decode(seen?.mint as string)?.length).toBe(32);
  });

  test("signer refusal and bad output map to typed errors", () => {
    const selected = selectedMainnet();
    expect(kindOf(() => buildPaymentSignature(selected, new RefusingSigner()))).toBe(
      "signer_rejected",
    );
    expect(kindOf(() => buildPaymentSignature(selected, new FixedSigner(new Uint8Array(0))))).toBe(
      "proof_build_failed",
    );
    expect(
      kindOf(() => buildPaymentSignature(selected, new FixedSigner(new Uint8Array(2000)))),
    ).toBe("proof_build_failed");
  });
});
