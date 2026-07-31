import { describe, expect, test } from "vitest";

import {
  base58Decode,
  CAIP2_SOLANA_DEVNET,
  CAIP2_SOLANA_MAINNET,
  CHALLENGE_HASH_DOMAIN,
  challengeHashHex,
  decodeBase64Std,
  encodeBase64Std,
  parseAtomicAmount,
  parsePaymentRequired,
  parsePaymentResponse,
  type PaymentError,
  selectRequirement,
  SolanaNetwork,
  solanaNetworkFromCaip2,
} from "../src/index.js";
import {
  CAIP2_DEVNET,
  clone,
  FEE_PAYER,
  PAY_TO,
  paymentRequiredDevnet,
  paymentRequiredMainnet,
  paymentRequiredSponsored,
  paymentResponseFailure,
  paymentResponseSuccess,
  toHeader,
  USDC_DEVNET,
  USDC_MAINNET,
} from "./fixtures.js";

function kindOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return (e as PaymentError).kind;
  }
  throw new Error("expected a PaymentError to be thrown");
}

describe("CAIP-2 network recognition", () => {
  test("is local and exact", () => {
    expect(solanaNetworkFromCaip2(CAIP2_SOLANA_MAINNET)).toBe(SolanaNetwork.Mainnet);
    expect(solanaNetworkFromCaip2(CAIP2_SOLANA_DEVNET)).toBe(SolanaNetwork.Devnet);
    expect(CAIP2_SOLANA_MAINNET).toBe("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
    for (const bogus of [
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp ",
      "solana:mainnet",
      "solana:",
      "eip155:84532",
      "SOLANA:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ]) {
      expect(solanaNetworkFromCaip2(bogus)).toBeUndefined();
    }
  });
});

describe("parse + select golden challenges", () => {
  test("mainnet challenge selects the SVM entry, skipping eip155", () => {
    const required = parsePaymentRequired(toHeader(paymentRequiredMainnet()));
    expect(required.resourceUrl).toBe("https://pay.example.com/premium-data");
    expect(required.accepts.length).toBe(2);
    const s = selectRequirement(required);
    expect(s.network).toBe(SolanaNetwork.Mainnet);
    expect(s.mint).toBe(USDC_MAINNET);
    expect(s.atomicAmount).toBe(1000n);
    expect(s.recipient).toBe(PAY_TO);
    expect(s.feePayer).toBe(FEE_PAYER);
    expect(s.memo).toBe("pi_3abc123def456");
    expect(s.maxTimeoutSeconds).toBe(60);
  });

  test("devnet challenge selects the devnet entry", () => {
    const s = selectRequirement(parsePaymentRequired(toHeader(paymentRequiredDevnet())));
    expect(s.network).toBe(SolanaNetwork.Devnet);
    expect(s.mint).toBe(USDC_DEVNET);
    expect(s.atomicAmount).toBe(2500n);
    expect(s.memo).toBeNull();
    expect(s.maxTimeoutSeconds).toBe(120);
  });
});

describe("challenge hash", () => {
  test("is deterministic, input-sensitive, and matches the pinned golden", () => {
    const required = parsePaymentRequired(toHeader(paymentRequiredMainnet()));
    const a = selectRequirement(required);
    const b = selectRequirement(required);
    expect(challengeHashHex(a)).toBe(challengeHashHex(b));
    expect(challengeHashHex(a).length).toBe(64);

    const c = selectRequirement(parsePaymentRequired(toHeader(paymentRequiredDevnet())));
    expect(challengeHashHex(a)).not.toBe(challengeHashHex(c));

    expect(CHALLENGE_HASH_DOMAIN).toBe("ferrogate-x402-challenge-v1");
    // Cross-checked against the frozen Rust golden (issue #350).
    expect(challengeHashHex(a)).toBe(
      "68dfeb509749893767994aa9bb578fa1b8a74eb7882d0507c04fb3e0ec87f777",
    );
  });

  test("separates memo and fee payer; an absent memo differs from an empty one", () => {
    const base = paymentRequiredDevnet();
    const hashOf = (doc: unknown) =>
      challengeHashHex(selectRequirement(parsePaymentRequired(toHeader(doc))));

    const noMemo = hashOf(base);
    const emptyMemo = clone(base);
    (emptyMemo.accepts as any[])[0].extra.memo = "";
    const invoiceA = clone(base);
    (invoiceA.accepts as any[])[0].extra.memo = "inv_a";
    const invoiceB = clone(base);
    (invoiceB.accepts as any[])[0].extra.memo = "inv_b";
    const otherSponsor = clone(base);
    (otherSponsor.accepts as any[])[0].extra.feePayer = USDC_MAINNET;

    expect(noMemo).not.toBe(hashOf(emptyMemo));
    expect(hashOf(invoiceA)).not.toBe(hashOf(invoiceB));
    expect(noMemo).not.toBe(hashOf(otherSponsor));
  });

  test("ignores transient blockhash hints (idempotency across retries)", () => {
    const base = paymentRequiredSponsored();
    const hashOf = (doc: unknown) =>
      challengeHashHex(selectRequirement(parsePaymentRequired(toHeader(doc))));

    const refreshed = clone(base);
    (refreshed.accepts as any[])[0].extra.recentBlockhash = USDC_MAINNET;
    (refreshed.accepts as any[])[0].extra.lastValidBlockHeight = "291470999";
    expect(hashOf(base)).toBe(hashOf(refreshed));

    const noHints = clone(base);
    delete (noHints.accepts as any[])[0].extra.recentBlockhash;
    delete (noHints.accepts as any[])[0].extra.lastValidBlockHeight;
    expect(hashOf(base)).toBe(hashOf(noHints));
  });
});

describe("blockhash hints", () => {
  test("sponsored challenge carries hints into the selection", () => {
    const s = selectRequirement(parsePaymentRequired(toHeader(paymentRequiredSponsored())));
    expect(s.network).toBe(SolanaNetwork.Devnet);
    expect(s.atomicAmount).toBe(750n);
    expect(s.memo).toBe("inv_2026_07_0001");
    expect(s.recentBlockhash).toBe("EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k");
    expect(s.lastValidBlockHeight).toBe(291470237n);

    const plain = selectRequirement(parsePaymentRequired(toHeader(paymentRequiredDevnet())));
    expect(plain.recentBlockhash).toBeNull();
    expect(plain.lastValidBlockHeight).toBeNull();
  });

  test("an orphan lastValidBlockHeight is ignored", () => {
    const doc = paymentRequiredSponsored();
    delete (doc.accepts as any[])[0].extra.recentBlockhash;
    (doc.accepts as any[])[0].extra.lastValidBlockHeight = "not-a-number";
    const s = selectRequirement(parsePaymentRequired(toHeader(doc)));
    expect(s.recentBlockhash).toBeNull();
    expect(s.lastValidBlockHeight).toBeNull();
  });
});

describe("selection filters", () => {
  test("honours network and mint filters", () => {
    const required = parsePaymentRequired(toHeader(paymentRequiredMainnet()));
    expect(kindOf(() => selectRequirement(required, { networks: [SolanaNetwork.Devnet] }))).toBe(
      "no_acceptable_requirement",
    );
    expect(kindOf(() => selectRequirement(required, { allowedMints: [USDC_DEVNET] }))).toBe(
      "unsupported_mint",
    );
    expect(() =>
      selectRequirement(required, {
        networks: [SolanaNetwork.Mainnet],
        allowedMints: [USDC_MAINNET],
      }),
    ).not.toThrow();
  });

  test("unsupported scheme/network/mint each surface their own variant", () => {
    const scheme = paymentRequiredDevnet();
    (scheme.accepts as any[])[0].scheme = "upto";
    expect(kindOf(() => selectRequirement(parsePaymentRequired(toHeader(scheme))))).toBe(
      "unsupported_scheme",
    );

    for (const badNetwork of [
      "eip155:1",
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvd",
      "SOLANA:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ]) {
      const doc = paymentRequiredDevnet();
      (doc.accepts as any[])[0].network = badNetwork;
      expect(kindOf(() => selectRequirement(parsePaymentRequired(toHeader(doc))))).toBe(
        "unsupported_network",
      );
    }
  });

  test("several unsupported entries fall back to no_acceptable_requirement", () => {
    const doc = paymentRequiredDevnet();
    const other = clone((doc.accepts as any[])[0]);
    other.scheme = "upto";
    (doc.accepts as any[])[0].network = "eip155:1";
    (doc.accepts as any[]).push(other);
    expect(kindOf(() => selectRequirement(parsePaymentRequired(toHeader(doc))))).toBe(
      "no_acceptable_requirement",
    );
  });
});

describe("negative corpus (typed rejection, never a panic, never coerced)", () => {
  const H = (doc: unknown) => toHeader(doc);
  const mut = (fn: (d: Record<string, unknown>) => void) => {
    const d = paymentRequiredDevnet();
    fn(d);
    return d;
  };

  test("malformed / oversized headers", () => {
    expect(kindOf(() => parsePaymentRequired("!!!not base64!!!"))).toBe("malformed_header");
    expect(kindOf(() => parsePaymentRequired(encodeBase64Std(new TextEncoder().encode("not json")))),
    ).toBe("malformed_header");
    expect(kindOf(() => parsePaymentRequired(encodeBase64Std(new TextEncoder().encode("123"))))).toBe(
      "malformed_header",
    ); // not an object
    expect(kindOf(() => parsePaymentRequired("A".repeat(17 * 1024)))).toBe("oversized_header");
  });

  test("version, accepts, resource, extensions", () => {
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => (d.x402Version = 1)))))).toBe(
      "unsupported_version",
    );
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => (d.x402Version = "2")))))).toBe(
      "unsupported_version",
    );
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => delete d.x402Version)))).valueOf()).toBe(
      "malformed_header",
    );
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => (d.accepts = [])))))).toBe(
      "malformed_header",
    );
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => (d.accepts = [1, 2])))))).toBe(
      "malformed_header",
    );
    expect(
      kindOf(() =>
        parsePaymentRequired(H(mut((d) => (d.accepts = new Array(17).fill((d.accepts as any[])[0]))))),
      ),
    ).toBe("malformed_header");
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => delete (d as any).resource)))).valueOf()).toBe(
      "malformed_header",
    );
    expect(kindOf(() => parsePaymentRequired(H(mut((d) => (d.extensions = 7)))))).toBe(
      "malformed_header",
    );
  });

  test("duplicate/conflicting accepts entries", () => {
    const dup = paymentRequiredMainnet();
    (dup.accepts as any[])[0] = clone((dup.accepts as any[])[1]);
    expect(kindOf(() => selectRequirement(parsePaymentRequired(toHeader(dup))))).toBe(
      "malformed_header",
    );
  });

  test("amounts are hard errors, never coerced to zero", () => {
    const amount = (v: unknown) => {
      const d = paymentRequiredDevnet();
      (d.accepts as any[])[0].amount = v;
      return () => selectRequirement(parsePaymentRequired(toHeader(d)));
    };
    expect(kindOf(amount("0"))).toBe("invalid_amount");
    expect(kindOf(amount("01"))).toBe("invalid_amount");
    expect(kindOf(amount("-1"))).toBe("invalid_amount");
    expect(kindOf(amount("1.0"))).toBe("invalid_amount");
    expect(kindOf(amount("1e3"))).toBe("invalid_amount");
    expect(kindOf(amount("18446744073709551616"))).toBe("invalid_amount"); // u64 max + 1
    expect(kindOf(amount(1000))).toBe("malformed_header"); // JSON number, not string
  });

  test("timeout, recipient, mint, fee payer, memo, blockhash", () => {
    const withEntry = (fn: (e: Record<string, unknown>) => void) => {
      const d = paymentRequiredDevnet();
      fn((d.accepts as any[])[0]);
      return () => selectRequirement(parsePaymentRequired(toHeader(d)));
    };
    expect(kindOf(withEntry((e) => (e.maxTimeoutSeconds = 0)))).toBe("invalid_timeout");
    expect(kindOf(withEntry((e) => (e.maxTimeoutSeconds = -5)))).toBe("invalid_timeout");
    expect(kindOf(withEntry((e) => (e.maxTimeoutSeconds = 1.5)))).toBe("invalid_timeout");
    expect(kindOf(withEntry((e) => (e.maxTimeoutSeconds = 999999)))).toBe("invalid_timeout");
    expect(kindOf(withEntry((e) => (e.payTo = "not-base58!")))).toBe("invalid_recipient");
    expect(kindOf(withEntry((e) => (e.asset = "USDC")))).toBe("invalid_recipient");
    expect(kindOf(withEntry((e) => delete (e.extra as any).feePayer))).toBe("malformed_header");
    expect(kindOf(withEntry((e) => ((e.extra as any).memo = "x".repeat(257))))).toBe(
      "malformed_header",
    );
    expect(
      kindOf(
        withEntry((e) => {
          (e.extra as any).recentBlockhash = "tooShort";
        }),
      ),
    ).toBe("malformed_header");
  });
});

describe("standalone parsers", () => {
  test("parseAtomicAmount matches the strict reference model", () => {
    expect(parseAtomicAmount("1")).toBe(1n);
    expect(parseAtomicAmount("18446744073709551615")).toBe(18446744073709551615n);
    for (const bad of ["", "0", "00", "01", "-1", "+1", " 1", "1 ", "1.0", "0x10", "1_000", "1e3"]) {
      expect(() => parseAtomicAmount(bad)).toThrow();
    }
  });

  test("base58Decode matches known vectors", () => {
    expect(base58Decode("11111111111111111111111111111111")).toEqual(new Uint8Array(32));
    expect(base58Decode(USDC_MAINNET)?.length).toBe(32);
    for (const bad of ["0", "O", "I", "l", "", "with space"]) {
      expect(base58Decode(bad)).toBeUndefined();
    }
  });

  test("base64 round-trips and rejects invalid input", () => {
    const bytes = Uint8Array.from([0, 1, 2, 250, 255, 128]);
    expect(decodeBase64Std(encodeBase64Std(bytes))).toEqual(bytes);
    expect(decodeBase64Std("abc")).toBeNull(); // length not a multiple of 4
    expect(decodeBase64Std("!!!!")).toBeNull();
  });
});

describe("settlement evidence", () => {
  test("success and failure decode", () => {
    const ok = parsePaymentResponse(toHeader(paymentResponseSuccess()), SolanaNetwork.Mainnet);
    expect(ok.success).toBe(true);
    expect(ok.settledAmount).toBe(1000n);
    expect(ok.payer).toBe(FEE_PAYER);
    expect(base58Decode(ok.transactionSignature as string)?.length).toBe(64);

    const fail = parsePaymentResponse(toHeader(paymentResponseFailure()), SolanaNetwork.Mainnet);
    expect(fail.success).toBe(false);
    expect(fail.transactionSignature).toBeNull();
    expect(fail.errorReason).toBe("insufficient_funds");
  });

  test("network must match the expected network", () => {
    expect(kindOf(() => parsePaymentResponse(toHeader(paymentResponseSuccess()), SolanaNetwork.Devnet))).toBe(
      "malformed_settlement",
    );
  });

  test("an unrecognised settlement network is the precise unsupported_network variant", () => {
    const doc = paymentResponseSuccess();
    doc.network = "eip155:1";
    expect(kindOf(() => parsePaymentResponse(toHeader(doc), SolanaNetwork.Mainnet))).toBe(
      "unsupported_network",
    );
  });

  test("a zero settled amount is rejected, not coerced", () => {
    const doc = paymentResponseSuccess();
    doc.amount = "0";
    expect(kindOf(() => parsePaymentResponse(toHeader(doc), SolanaNetwork.Mainnet))).toBe(
      "invalid_amount",
    );
  });
});

describe("fuzz-ish: arbitrary input never panics and never yields a zero amount", () => {
  test("random bytes as header", () => {
    for (let i = 0; i < 200; i++) {
      const len = Math.floor(Math.random() * 64);
      const bytes = new Uint8Array(len);
      for (let j = 0; j < len; j++) bytes[j] = Math.floor(Math.random() * 256);
      const header = encodeBase64Std(bytes);
      try {
        const req = parsePaymentRequired(header);
        const s = selectRequirement(req);
        expect(s.atomicAmount > 0n).toBe(true);
      } catch {
        /* typed rejection is fine */
      }
      expect(() => {
        try {
          parsePaymentResponse(header, SolanaNetwork.Devnet);
        } catch {
          /* ok */
        }
      }).not.toThrow();
    }
  });
});
