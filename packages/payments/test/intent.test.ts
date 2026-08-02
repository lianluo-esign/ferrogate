import { describe, expect, test } from "vitest";

import {
  challengeHashHex,
  parsePaymentRequired,
  PaymentIntent,
  PaymentIntentError,
  type PaymentIntentIdentity,
  RequestBodyHash,
  type SelectedPayment,
  selectRequirement,
} from "../src/index.js";
import { CAIP2_DEVNET, FEE_PAYER, OTHER_MERCHANT, PAY_TO, RESOURCE, USDC_DEVNET, toHeader } from "./fixtures.js";

const enc = new TextEncoder();

function selected(atomic: number, recipient: string): SelectedPayment {
  return selectedBig(BigInt(atomic), recipient);
}

/**
 * The same builder over a `bigint`, so a `u64` amount past 2^53 can be
 * constructed at all: `selected(Number(...))` would have rounded the amount in
 * the TEST before the code under test ever saw it, which is exactly the vacuity
 * the outbound guard exists to prevent. The amount travels through the
 * `PAYMENT-REQUIRED` header as a DECIMAL STRING, so nothing here loses digits.
 */
function selectedBig(atomic: bigint, recipient: string): SelectedPayment {
  const doc = {
    x402Version: 2,
    resource: { url: RESOURCE, mimeType: "application/json" },
    accepts: [
      {
        scheme: "exact",
        network: CAIP2_DEVNET,
        amount: atomic.toString(),
        asset: USDC_DEVNET,
        payTo: recipient,
        maxTimeoutSeconds: 120,
        extra: { feePayer: FEE_PAYER },
      },
    ],
  };
  return selectRequirement(parsePaymentRequired(toHeader(doc)));
}

function identity(): PaymentIntentIdentity {
  return {
    tenantId: "tenant-1",
    projectId: "project-1",
    workspaceId: "workspace-1",
    keyId: "key-1",
    runId: "run-1",
    workerId: "worker-1",
    requestId: "req-1",
  };
}

function intent(method: string, body: Uint8Array): PaymentIntent {
  return PaymentIntent.fromSelected(selected(2500, PAY_TO), method, RESOURCE, body, identity());
}

/**
 * LANGUAGE LIMIT PIN — kept as a PORT-TODO on `atomic_amount` in `src/intent.ts`.
 *
 * `u64` money survives as `bigint` everywhere in the in-memory domain; only the
 * serde hop is number-domain, because `JSON.parse` has already flattened the
 * integer to a double before `fromWire` is handed the value. These assertions
 * hold the boundary exactly where the marker says it is: if someone "fixes" the
 * marker by turning the domain type into `number`, the money path silently
 * becomes float and this fails.
 */
describe("PORT-TODO PIN — the money domain is bigint, the serde hop is not", () => {
  test("every in-memory atomic amount is a bigint, never a number", () => {
    const sel = selected(2500, PAY_TO);
    expect(typeof sel.atomicAmount).toBe("bigint");
    const built = PaymentIntent.fromSelected(sel, "GET", RESOURCE, new Uint8Array(0), identity());
    expect(typeof built.atomicAmount()).toBe("bigint");
    expect(built.atomicAmount()).toBe(2500n);
    // …and it survives a wire round trip as a bigint, not as whatever
    // `JSON.parse` handed back.
    const round = PaymentIntent.fromWire(JSON.parse(JSON.stringify(built.toWire())));
    expect(typeof round.atomicAmount()).toBe("bigint");
    expect(round.atomicAmount()).toBe(2500n);
    expect(round.intentHashHex()).toBe(built.intentHashHex());
  });

  /**
   * OUTBOUND HALF — CLOSED. `toWire()` used to write `Number(#atomicAmount)`
   * and round in silence past 2^53. These fail if that bare cast comes back.
   *
   * The third assertion is why this is a correctness gate and not cosmetics:
   * `intentHashHex()` digests the EXACT bigint, so a rounded wire amount makes
   * a verifier that re-derives the hash from the wire form disagree with the
   * signer, and `equals()` (JSON of `toWire()`) reports two DIFFERENT amounts
   * as one intent.
   */
  test("toWire REFUSES an amount past 2^53 instead of rounding it", () => {
    const over = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    const built = PaymentIntent.fromSelected(
      selectedBig(over, PAY_TO),
      "GET",
      RESOURCE,
      new Uint8Array(0),
      identity(),
    );
    // The domain accepted it — a u64 amount is legal on chain…
    expect(built.atomicAmount()).toBe(over);
    // …the WIRE render is what refuses.
    try {
      built.toWire();
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(PaymentIntentError);
      expect((error as PaymentIntentError).kind).toBe("amount_unrepresentable");
      expect((error as PaymentIntentError).field).toBe("atomic_amount");
    }
    // The exact boundary itself must still render.
    const edge = PaymentIntent.fromSelected(
      selectedBig(BigInt(Number.MAX_SAFE_INTEGER), PAY_TO),
      "GET",
      RESOURCE,
      new Uint8Array(0),
      identity(),
    );
    expect(edge.toWire().atomic_amount).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("the refusal is what stops a rounded wire amount from breaking the hash binding", () => {
    const a = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    const b = BigInt(Number.MAX_SAFE_INTEGER) + 2n;
    // Two DIFFERENT on-chain amounts collapse onto ONE double…
    expect(a).not.toBe(b);
    expect(Number(a)).toBe(Number(b));
    const mk = (amount: bigint) =>
      PaymentIntent.fromSelected(
        selectedBig(amount, PAY_TO),
        "GET",
        RESOURCE,
        new Uint8Array(0),
        identity(),
      );
    // …but the intent hash, digested from the exact bigint, does NOT.
    expect(mk(a).intentHashHex()).not.toBe(mk(b).intentHashHex());
    // So emitting the collapsed number would sign one amount and publish
    // another. Both renders refuse.
    for (const amount of [a, b]) {
      expect(() => mk(amount).toWire()).toThrow(/amount_unrepresentable|losing precision/);
    }
    // …and `equals()`, which compares JSON of `toWire()`, cannot report them
    // as the same intent, because it cannot produce that JSON at all.
    expect(() => mk(a).equals(mk(b))).toThrow();
  });

  test("the number-domain hop is exactly the serde field, and it is exact below 2^53", () => {
    const wire = PaymentIntent.fromSelected(
      selected(2500, PAY_TO),
      "GET",
      RESOURCE,
      new Uint8Array(0),
      identity(),
    ).toWire();
    expect(typeof wire.atomic_amount).toBe("number");
    expect(wire.atomic_amount).toBe(2500);
    expect(Number.isSafeInteger(wire.atomic_amount)).toBe(true);
  });
});

describe("method + body binding (#351)", () => {
  test("a GET and a POST of a different body to the same URL are distinguishable", () => {
    const read = intent("GET", new Uint8Array(0));
    const write = intent("POST", enc.encode('{"drain":"everything"}'));
    expect(read.challengeHashHex()).toBe(write.challengeHashHex());
    expect(read.authorizedResourceUrl()).toBe(write.authorizedResourceUrl());
    expect(read.atomicAmount()).toBe(write.atomicAmount());
    expect(read.httpMethod()).not.toBe(write.httpMethod());
    expect(read.requestBodyHash().equals(write.requestBodyHash())).toBe(false);
    expect(read.intentHashHex()).not.toBe(write.intentHashHex());
  });

  test("the same request always produces the same intent hash (method normalized)", () => {
    const first = intent("POST", enc.encode("body"));
    const second = intent("post", enc.encode("body"));
    expect(second.httpMethod()).toBe("POST");
    expect(first.intentHashHex()).toBe(second.intentHashHex());
    expect(first.intentHashHex().length).toBe(64);
    expect(/^[0-9a-f]{64}$/.test(first.intentHashHex())).toBe(true);
  });

  test("changing any bound field changes the intent hash", () => {
    const baseline = intent("GET", new Uint8Array(0)).intentHashHex();
    const otherAmount = PaymentIntent.fromSelected(
      selected(2501, PAY_TO),
      "GET",
      RESOURCE,
      new Uint8Array(0),
      identity(),
    );
    const otherRecipient = PaymentIntent.fromSelected(
      selected(2500, OTHER_MERCHANT),
      "GET",
      RESOURCE,
      new Uint8Array(0),
      identity(),
    );
    const otherUrl = PaymentIntent.fromSelected(
      selected(2500, PAY_TO),
      "GET",
      "https://pay.example.com/other",
      new Uint8Array(0),
      identity(),
    );
    const otherRun = PaymentIntent.fromSelected(selected(2500, PAY_TO), "GET", RESOURCE, new Uint8Array(0), {
      ...identity(),
      runId: "run-2",
    });
    for (const other of [otherAmount, otherRecipient, otherUrl, otherRun]) {
      expect(baseline).not.toBe(other.intentHashHex());
    }
  });

  test("an absent optional id differs from a blank one (which is rejected)", () => {
    const withoutRun = PaymentIntent.fromSelected(
      selected(2500, PAY_TO),
      "GET",
      RESOURCE,
      new Uint8Array(0),
      { ...identity(), runId: null },
    );
    expect(withoutRun.identity().runId).toBeNull();
    expect(withoutRun.intentHashHex()).not.toBe(intent("GET", new Uint8Array(0)).intentHashHex());

    let err: unknown;
    try {
      PaymentIntent.fromSelected(selected(2500, PAY_TO), "GET", RESOURCE, new Uint8Array(0), {
        ...identity(),
        runId: "   ",
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(PaymentIntentError);
    expect((err as PaymentIntentError).kind).toBe("invalid_identity");
    expect((err as PaymentIntentError).field).toBe("run_id");
  });
});

describe("binding check", () => {
  test("an intent binds to exactly one challenge", () => {
    const bound = intent("GET", new Uint8Array(0));
    expect(bound.bindingMismatch(selected(2500, PAY_TO))).toBeNull();
    expect(bound.bindingMismatch(selected(9999, PAY_TO))).toBe("challenge_hash");
    expect(bound.bindingMismatch(selected(2500, OTHER_MERCHANT))).toBe("challenge_hash");
  });

  test("a tampered payment term is caught even when the challenge hash matches", () => {
    const bound = intent("GET", new Uint8Array(0));
    const tamperedAmount = { ...selected(2500, PAY_TO), atomicAmount: 2500000n };
    expect(bound.bindingMismatch(tamperedAmount)).toBe("atomic_amount");
    const tamperedRecipient = { ...selected(2500, PAY_TO), recipient: OTHER_MERCHANT };
    expect(bound.bindingMismatch(tamperedRecipient)).toBe("recipient");
    const tamperedMint = { ...selected(2500, PAY_TO), mint: OTHER_MERCHANT };
    expect(bound.bindingMismatch(tamperedMint)).toBe("mint");
  });
});

describe("RequestBodyHash", () => {
  test("a bodyless request has a concrete hash, not an absence", () => {
    expect(RequestBodyHash.empty().equals(RequestBodyHash.of(new Uint8Array(0)))).toBe(true);
    expect(RequestBodyHash.empty().equals(RequestBodyHash.of(enc.encode("{}")))).toBe(false);
    expect(RequestBodyHash.empty().asHex().length).toBe(64);
    const hash = RequestBodyHash.of(enc.encode("payload"));
    expect(RequestBodyHash.fromHex(hash.asHex()).equals(hash)).toBe(true);
    expect(() => RequestBodyHash.fromHex("deadbeef")).toThrow();
    expect(() => RequestBodyHash.fromHex(hash.asHex().toUpperCase())).toThrow();
  });
});

describe("construction and validation", () => {
  const baseDraft = () => ({
    x402Version: 2,
    scheme: "exact",
    networkCaip2: CAIP2_DEVNET,
    mint: USDC_DEVNET,
    atomicAmount: 2500n,
    recipient: PAY_TO,
    authorizedResourceUrl: RESOURCE,
    httpMethod: "GET",
    requestBodyHash: RequestBodyHash.empty(),
    challengeHashHex: challengeHashHex(selected(2500, PAY_TO)),
    maxTimeoutSeconds: 120,
    identity: identity(),
  });

  test("the base draft is valid", () => {
    expect(() => PaymentIntent.new_(baseDraft())).not.toThrow();
  });

  test("rejects every field a decision would later depend on", () => {
    const cases: Array<Partial<ReturnType<typeof baseDraft>>> = [
      { x402Version: 1 },
      { scheme: "upto" },
      { networkCaip2: "solana:whatever" },
      { mint: "USDC" },
      { recipient: "not-base58!" },
      { atomicAmount: 0n },
      { authorizedResourceUrl: "/weather" },
      { authorizedResourceUrl: "file:///etc/passwd" },
      { httpMethod: "  " },
      { httpMethod: "GET /other HTTP/1.1" },
      { challengeHashHex: "abc" },
      { maxTimeoutSeconds: 0 },
      { maxTimeoutSeconds: 86401 },
      { identity: { ...identity(), tenantId: " " } },
      { identity: { ...identity(), requestId: "" } },
    ];
    for (const patch of cases) {
      expect(() => PaymentIntent.new_({ ...baseDraft(), ...patch })).toThrow();
    }
  });
});

describe("wire (de)serialization cannot bypass validation", () => {
  test("round-trips and rejects tampered payloads", () => {
    const original = intent("POST", enc.encode("payload"));
    const wire = original.toWire();
    expect(wire.atomic_amount).toBe(2500);
    const decoded = PaymentIntent.fromWire(JSON.parse(JSON.stringify(wire)));
    expect(decoded.equals(original)).toBe(true);
    expect(decoded.intentHashHex()).toBe(original.intentHashHex());

    const tamperedScheme = { ...wire, scheme: "upto" };
    expect(() => PaymentIntent.fromWire(tamperedScheme)).toThrow();
    const tamperedAmount = { ...wire, atomic_amount: 0 };
    expect(() => PaymentIntent.fromWire(tamperedAmount)).toThrow();
  });
});
