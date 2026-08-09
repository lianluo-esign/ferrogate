import { describe, expect, test } from "vitest";
import {
  POLICY_NETWORK_DEVNET,
  POLICY_NETWORK_MAINNET,
  type PaymentAuthorizationRequest,
  PaymentIntent,
  REASON_ALLOWED,
  REASON_AMOUNT_BELOW_MIN,
  REASON_APPROVAL_REQUIRED,
  REASON_ATOMIC_CAP_EXCEEDED,
  REASON_CONVERSION_EXPIRED,
  REASON_CONVERSION_UNAVAILABLE,
  REASON_DISABLED,
  REASON_INTENT_MISMATCH,
  REASON_MINT_NOT_ALLOWED,
  REASON_NETWORK_NOT_ALLOWED,
  REASON_OVER_PER_PAYMENT_CAP,
  REASON_OVER_RUN_CAP,
  REASON_OVER_WINDOW_CAP,
  REASON_RECIPIENT_NOT_ALLOWED,
  REASON_RESOURCE_MISMATCH,
  REASON_RESOURCE_NOT_ALLOWED,
  type SelectedPayment,
  type SolanaNetwork,
  type SpendSnapshot,
  U64_MAX,
  type ValidatedX402SpendPolicy,
  type X402SpendPolicy,
  authorizeX402Payment,
  canonicalUrl,
  convert,
  disabledX402SpendPolicy,
  emptySpendSnapshot,
  hexLower,
  isValidSolanaAddress,
  resourceRuleMatches,
  sha256,
  validateX402SpendPolicy,
} from "../src/index.js";

const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIPIENT_A = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const RECIPIENT_B = "GDDMwNyyx8uB6zrqwBFHjLLG3TBYk2F8Az4yrQC5RzMp";
const FEE_PAYER = "So11111111111111111111111111111111111111112";
const RESOURCE_URL = "https://api.example.com/paid/report";

function selected(
  network: SolanaNetwork,
  mint: string,
  atomicAmount: bigint,
  recipient: string,
  resourceUrl: string,
): SelectedPayment {
  return {
    network,
    mint,
    atomicAmount,
    recipient,
    resourceUrl,
    maxTimeoutSeconds: 300,
    challengeHash: new Uint8Array(32).fill(0xab),
    // The remaining fields of the frozen `@ferrogate/payments` wire contract —
    // the policy layer does not read them, but the type is the wire type, not a
    // policy-local subset.
    feePayer: FEE_PAYER,
    memo: null,
    recentBlockhash: null,
    lastValidBlockHeight: null,
    extensions: null,
    rawRequirement: null,
  };
}

function devnetPayment(atomic: bigint): SelectedPayment {
  return selected("devnet", USDC_DEVNET, atomic, RECIPIENT_A, RESOURCE_URL);
}

function basePolicy(): X402SpendPolicy {
  return {
    enabled: true,
    revision: 7n,
    allowedNetworks: [POLICY_NETWORK_DEVNET],
    allowedAssets: [{ network: POLICY_NETWORK_DEVNET, mint: USDC_DEVNET }],
    allowedRecipients: [RECIPIENT_A],
    allowedResources: [{ origin: "https://api.example.com", pathPrefix: "/paid" }],
    caps: {
      maxCreditsPerPayment: 1_000n,
      maxCreditsPerRun: 5_000n,
      maxCreditsPerWindow: 10_000n,
      windowSeconds: 3_600n,
      maxAtomicPerPayment: 2_000_000n,
      minAtomicPerPayment: 10n,
    },
    conversion: { numerator: 1n, denominator: 1_000n, rounding: "up", version: "usdc-devnet-v1" },
    approval: { thresholdCredits: 500n },
    allowInsecureLocalResources: false,
  };
}

function validated(policy: X402SpendPolicy): ValidatedX402SpendPolicy {
  const r = validateX402SpendPolicy(policy);
  if (!r.ok) throw new Error(`policy should validate: ${JSON.stringify(r.error)}`);
  return r.value;
}

function intentFor(payment: SelectedPayment, authorized: string): PaymentIntent {
  return PaymentIntent.fromSelected(payment, "GET", authorized, new Uint8Array(0), {
    tenantId: "tenant-1",
    projectId: "proj-1",
    keyId: "key-1",
    runId: "run-1",
    workerId: "worker-1",
    requestId: "req-1",
  });
}

function req(payment: SelectedPayment, intent: PaymentIntent): PaymentAuthorizationRequest {
  return {
    selected: payment,
    intent,
    scope: { tenantId: "tenant-1", projectId: "proj-1", keyId: "key-1", runId: "run-1" },
  };
}

function decide(
  policy: ValidatedX402SpendPolicy,
  payment: SelectedPayment,
  authorized: string,
  spent: SpendSnapshot,
) {
  return authorizeX402Payment(policy, req(payment, intentFor(payment, authorized)), spent);
}

describe("sha256 (portable sync)", () => {
  test("matches the known empty-string digest", () => {
    expect(hexLower(sha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
  test("matches the known 'abc' digest", () => {
    expect(hexLower(sha256(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("base58 address validation", () => {
  test("accepts canonical 32-byte addresses, rejects symbols and emails", () => {
    expect(isValidSolanaAddress(USDC_DEVNET)).toBe(true);
    expect(isValidSolanaAddress(RECIPIENT_A)).toBe(true);
    expect(isValidSolanaAddress("USDC")).toBe(false);
    expect(isValidSolanaAddress("merchant@example.com")).toBe(false);
  });
});

describe("ConversionRule.convert", () => {
  test("rounding up and down", () => {
    expect(
      convert({ numerator: 1n, denominator: 1_000n, rounding: "up", version: "v" }, 100_001n),
    ).toBe(101n);
    expect(
      convert({ numerator: 1n, denominator: 1_000n, rounding: "down", version: "v" }, 100_999n),
    ).toBe(100n);
  });
  test("overflow yields undefined, never a coerced zero", () => {
    expect(
      convert({ numerator: 1_000n, denominator: 1n, rounding: "up", version: "v" }, U64_MAX),
    ).toBeUndefined();
  });
  test("is monotone non-decreasing in the atomic amount", () => {
    const rule = { numerator: 3n, denominator: 7n, rounding: "up" as const, version: "p" };
    const pairs: [bigint, bigint][] = [
      [10n, 999n],
      [0n, 1n],
      [500n, 500n],
    ];
    for (const [a, b] of pairs) {
      expect(convert(rule, a)! <= convert(rule, b)!).toBe(true);
    }
  });
});

describe("authorizeX402Payment — decision paths", () => {
  test("allows a payment within every cap and populates evidence", () => {
    const auth = decide(
      validated(basePolicy()),
      devnetPayment(100_000n),
      RESOURCE_URL,
      emptySpendSnapshot(),
    );
    expect(auth.decision().kind).toBe("allow");
    expect(auth.reasonCode()).toBe(REASON_ALLOWED);
    expect(auth.policyRevision()).toBe(7n);
    expect(auth.computedCredits()).toBe(100n);
    expect(auth.challengeHashHex()).toBe("ab".repeat(32));
    expect(auth.matchedResource()).toBeDefined();
  });

  test("disabled policy denies every payment", () => {
    const auth = decide(
      validated(disabledX402SpendPolicy()),
      devnetPayment(100_000n),
      RESOURCE_URL,
      emptySpendSnapshot(),
    );
    expect(auth.decision().kind).toBe("deny");
    expect(auth.reasonCode()).toBe(REASON_DISABLED);
  });

  test("denies a non-allowlisted network / mint / recipient", () => {
    const p = validated(basePolicy());
    expect(
      decide(
        p,
        selected("mainnet", USDC_MAINNET, 100_000n, RECIPIENT_A, RESOURCE_URL),
        RESOURCE_URL,
        emptySpendSnapshot(),
      ).reasonCode(),
    ).toBe(REASON_NETWORK_NOT_ALLOWED);
    expect(
      decide(
        p,
        selected("devnet", FEE_PAYER, 100_000n, RECIPIENT_A, RESOURCE_URL),
        RESOURCE_URL,
        emptySpendSnapshot(),
      ).reasonCode(),
    ).toBe(REASON_MINT_NOT_ALLOWED);
    expect(
      decide(
        p,
        selected("devnet", USDC_DEVNET, 100_000n, RECIPIENT_B, RESOURCE_URL),
        RESOURCE_URL,
        emptySpendSnapshot(),
      ).reasonCode(),
    ).toBe(REASON_RECIPIENT_NOT_ALLOWED);
  });

  test("denies a challenge that redirects to a different resource", () => {
    const auth = decide(
      validated(basePolicy()),
      devnetPayment(100_000n),
      "https://evil.example.net/paid/report",
      emptySpendSnapshot(),
    );
    expect(auth.reasonCode()).toBe(REASON_RESOURCE_MISMATCH);
  });

  test("denies a resource not covered by any rule", () => {
    const url = "https://api.example.com/free/report";
    const payment = selected("devnet", USDC_DEVNET, 100_000n, RECIPIENT_A, url);
    expect(decide(validated(basePolicy()), payment, url, emptySpendSnapshot()).reasonCode()).toBe(
      REASON_RESOURCE_NOT_ALLOWED,
    );
  });

  test("binding ignores query and trailing slash but not path", () => {
    const payment = selected(
      "devnet",
      USDC_DEVNET,
      100_000n,
      RECIPIENT_A,
      "https://api.example.com/paid/report/?ref=1",
    );
    const auth = decide(
      validated(basePolicy()),
      payment,
      "https://api.example.com/paid/report#frag",
      emptySpendSnapshot(),
    );
    expect(auth.decision().kind).toBe("allow");
  });

  test("atomic bounds: below min and over the hard cap", () => {
    const p = validated(basePolicy());
    expect(decide(p, devnetPayment(5n), RESOURCE_URL, emptySpendSnapshot()).reasonCode()).toBe(
      REASON_AMOUNT_BELOW_MIN,
    );
    expect(
      decide(p, devnetPayment(2_000_001n), RESOURCE_URL, emptySpendSnapshot()).reasonCode(),
    ).toBe(REASON_ATOMIC_CAP_EXCEEDED);
  });

  test("per-payment credit cap is a boundary at the cap value", () => {
    const raw = basePolicy();
    raw.approval = {};
    raw.caps.minAtomicPerPayment = undefined;
    raw.caps.maxAtomicPerPayment = undefined;
    const p = validated(raw);
    expect(
      decide(p, devnetPayment(1_000_000n), RESOURCE_URL, emptySpendSnapshot()).decision().kind,
    ).toBe("allow");
    expect(
      decide(p, devnetPayment(1_000_001n), RESOURCE_URL, emptySpendSnapshot()).reasonCode(),
    ).toBe(REASON_OVER_PER_PAYMENT_CAP);
  });

  test("per-run and per-window caps count already-spent credits", () => {
    const p = validated(basePolicy());
    expect(
      decide(p, devnetPayment(100_000n), RESOURCE_URL, {
        runSpentCredits: 4_900n,
        windowSpentCredits: 0n,
      }).decision().kind,
    ).toBe("allow");
    expect(
      decide(p, devnetPayment(100_000n), RESOURCE_URL, {
        runSpentCredits: 4_901n,
        windowSpentCredits: 0n,
      }).reasonCode(),
    ).toBe(REASON_OVER_RUN_CAP);
    expect(
      decide(p, devnetPayment(100_000n), RESOURCE_URL, {
        runSpentCredits: 0n,
        windowSpentCredits: 9_950n,
      }).reasonCode(),
    ).toBe(REASON_OVER_WINDOW_CAP);
  });

  test("a checked-add overflow on a cap denies rather than wrapping", () => {
    const auth = decide(validated(basePolicy()), devnetPayment(100_000n), RESOURCE_URL, {
      runSpentCredits: U64_MAX,
      windowSpentCredits: 0n,
    });
    expect(auth.reasonCode()).toBe(REASON_CONVERSION_UNAVAILABLE);
  });

  test("a payment above the approval threshold but within caps needs approval", () => {
    const auth = decide(
      validated(basePolicy()),
      devnetPayment(600_000n),
      RESOURCE_URL,
      emptySpendSnapshot(),
    );
    expect(auth.decision()).toEqual({ kind: "approval_required", thresholdCredits: 500n });
    expect(auth.reasonCode()).toBe(REASON_APPROVAL_REQUIRED);
    expect(auth.computedCredits()).toBe(600n);
  });
});

describe("payment-intent binding", () => {
  test("a decision names the method and body it authorized; requests are distinguishable", () => {
    const policy = validated(basePolicy());
    const payment = devnetPayment(100_000n);
    const read = authorizeX402Payment(
      policy,
      req(
        payment,
        PaymentIntent.fromSelected(payment, "GET", RESOURCE_URL, new Uint8Array(0), {
          tenantId: "tenant-1",
          requestId: "req-1",
        }),
      ),
      emptySpendSnapshot(),
    );
    const write = authorizeX402Payment(
      policy,
      req(
        payment,
        PaymentIntent.fromSelected(
          payment,
          "POST",
          RESOURCE_URL,
          new TextEncoder().encode('{"drain":true}'),
          {
            tenantId: "tenant-1",
            requestId: "req-1",
          },
        ),
      ),
      emptySpendSnapshot(),
    );
    expect(read.decision().kind).toBe("allow");
    expect(write.decision().kind).toBe("allow");
    expect(read.httpMethod()).toBe("GET");
    expect(write.httpMethod()).toBe("POST");
    expect(read.requestBodyHashHex()).not.toBe(write.requestBodyHashHex());
    expect(read.intentHashHex()).not.toBe(write.intentHashHex());
    expect(read.decisionHashHex()).not.toBe(write.decisionHashHex());
  });

  test("an intent built for another payment denies before allowlists are consulted", () => {
    const policy = validated(basePolicy());
    const allowed = devnetPayment(100_000n);
    const mismatched = intentFor(devnetPayment(200_000n), RESOURCE_URL);
    const auth = authorizeX402Payment(policy, req(allowed, mismatched), emptySpendSnapshot());
    expect(auth.reasonCode()).toBe(REASON_INTENT_MISMATCH);
    expect(auth.matchedResource()).toBeUndefined();
  });

  test("the decision seal is deterministic and ignores only the message", () => {
    const policy = validated(basePolicy());
    const payment = devnetPayment(100_000n);
    const intent = intentFor(payment, RESOURCE_URL);
    const first = authorizeX402Payment(policy, req(payment, intent), emptySpendSnapshot());
    const second = authorizeX402Payment(policy, req(payment, intent), emptySpendSnapshot());
    expect(first.decisionHashHex()).toBe(second.decisionHashHex());
    expect(first.decisionHashHex()).toHaveLength(64);
  });

  test("a decision carries the scope it was evaluated at", () => {
    const auth = decide(
      validated(basePolicy()),
      devnetPayment(100_000n),
      RESOURCE_URL,
      emptySpendSnapshot(),
    );
    expect(auth.scope()).toEqual({
      tenantId: "tenant-1",
      projectId: "proj-1",
      workspaceId: undefined,
      keyId: "key-1",
      runId: "run-1",
    });
  });
});

describe("conversion staleness", () => {
  test("an expired conversion rule denies; a fresh one allows", () => {
    const raw = basePolicy();
    raw.conversion.expiresAtUnix = 1_800_000_000;
    const policy = validated(raw);
    expect(
      decide(policy, devnetPayment(100_000n), RESOURCE_URL, {
        runSpentCredits: 0n,
        windowSpentCredits: 0n,
        nowUnix: 1_799_999_999,
      }).decision().kind,
    ).toBe("allow");
    for (const now of [1_800_000_000, 1_900_000_000]) {
      const stale = decide(policy, devnetPayment(100_000n), RESOURCE_URL, {
        runSpentCredits: 0n,
        windowSpentCredits: 0n,
        nowUnix: now,
      });
      expect(stale.reasonCode()).toBe(REASON_CONVERSION_EXPIRED);
    }
  });

  test("a window without a clock denies rather than assuming freshness", () => {
    const raw = basePolicy();
    raw.conversion.expiresAtUnix = 1_800_000_000;
    const policy = validated(raw);
    expect(
      decide(policy, devnetPayment(100_000n), RESOURCE_URL, emptySpendSnapshot()).reasonCode(),
    ).toBe(REASON_CONVERSION_EXPIRED);
    // A policy with NO declared window is unaffected by a missing clock.
    expect(
      decide(
        validated(basePolicy()),
        devnetPayment(100_000n),
        RESOURCE_URL,
        emptySpendSnapshot(),
      ).decision().kind,
    ).toBe("allow");
  });
});

describe("config validation", () => {
  test("wildcard mainnet without an explicit mint is rejected", () => {
    const p = basePolicy();
    p.allowedNetworks = [POLICY_NETWORK_MAINNET, POLICY_NETWORK_DEVNET];
    p.allowedAssets = [{ network: POLICY_NETWORK_DEVNET, mint: USDC_DEVNET }];
    const r = validateX402SpendPolicy(p);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("wildcard_mainnet");
  });

  test("a token symbol used as a mint is rejected", () => {
    const p = basePolicy();
    p.allowedAssets = [{ network: POLICY_NETWORK_DEVNET, mint: "USDC" }];
    const r = validateX402SpendPolicy(p);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toEqual({ kind: "token_symbol_mint", value: "USDC" });
  });

  test("an http resource is rejected unless local test mode is enabled", () => {
    const p = basePolicy();
    p.allowedResources = [{ origin: "http://api.example.com", pathPrefix: "/paid" }];
    const rejected = validateX402SpendPolicy(p);
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.error.kind).toBe("insecure_resource");
    p.allowInsecureLocalResources = true;
    expect(validateX402SpendPolicy(p).ok).toBe(true);
  });

  test("zero caps, zero approval threshold, and inverted atomic band are rejected", () => {
    const zeroCap = basePolicy();
    zeroCap.caps.maxCreditsPerPayment = 0n;
    expect(validateX402SpendPolicy(zeroCap)).toMatchObject({
      ok: false,
      error: { kind: "zero_cap" },
    });

    const zeroApproval = basePolicy();
    zeroApproval.approval.thresholdCredits = 0n;
    expect(validateX402SpendPolicy(zeroApproval)).toMatchObject({
      ok: false,
      error: { field: "approval.threshold_credits" },
    });

    const inverted = basePolicy();
    inverted.caps.minAtomicPerPayment = 100n;
    inverted.caps.maxAtomicPerPayment = 10n;
    expect(validateX402SpendPolicy(inverted)).toMatchObject({
      ok: false,
      error: { kind: "inverted_atomic_band" },
    });
  });

  test("duplicate recipient/asset rules and non-base58 recipients are rejected", () => {
    const dupRecip = basePolicy();
    dupRecip.allowedRecipients = [RECIPIENT_A, RECIPIENT_A];
    expect(validateX402SpendPolicy(dupRecip)).toMatchObject({
      ok: false,
      error: { kind: "duplicate_rule", ruleKind: "recipient" },
    });

    const badRecip = basePolicy();
    badRecip.allowedRecipients = ["merchant@example.com"];
    expect(validateX402SpendPolicy(badRecip)).toMatchObject({
      ok: false,
      error: { kind: "invalid_recipient" },
    });
  });

  test("an impossible conversion ratio is rejected even when disabled", () => {
    const p = disabledX402SpendPolicy();
    p.conversion.denominator = 0n;
    expect(validateX402SpendPolicy(p)).toMatchObject({
      ok: false,
      error: { kind: "impossible_conversion" },
    });
    const p2 = disabledX402SpendPolicy();
    p2.conversion.numerator = 0n;
    expect(validateX402SpendPolicy(p2)).toMatchObject({
      ok: false,
      error: { reason: "conversion numerator is zero" },
    });
  });

  test("a disabled policy with empty allowlists still validates", () => {
    expect(validateX402SpendPolicy(disabledX402SpendPolicy()).ok).toBe(true);
  });

  test("resource rules identical after canonicalisation are duplicates", () => {
    const pairs: [string, string][] = [
      ["https://api.example.com", "https://API.example.com"],
      ["https://api.example.com", "https://api.example.com:443"],
    ];
    for (const [first, second] of pairs) {
      const p = basePolicy();
      p.allowedResources = [
        { origin: first, pathPrefix: "/paid" },
        { origin: second, pathPrefix: "/paid/" },
      ];
      expect(validateX402SpendPolicy(p)).toMatchObject({
        ok: false,
        error: { kind: "duplicate_rule", ruleKind: "resource" },
      });
    }
  });
});

describe("URL canonicalisation (security-load-bearing)", () => {
  test("path-prefix matching respects segment boundaries", () => {
    const url = canonicalUrl("https://api.example.com/payment")!;
    expect(
      resourceRuleMatches({ origin: "https://api.example.com", pathPrefix: "/pay" }, url),
    ).toBe(false);
    expect(
      resourceRuleMatches({ origin: "https://api.example.com", pathPrefix: "/payment" }, url),
    ).toBe(true);
  });

  test("default https port and host case are canonicalised away", () => {
    expect(canonicalUrl("https://api.example.com:443/paid")).toEqual(
      canonicalUrl("https://API.example.com/paid"),
    );
  });
});
