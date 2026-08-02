/**
 * The Durable Object exercised through a **REAL `RATE_LIMIT` binding** in
 * `workerd` — no mock namespace, no in-memory stand-in.
 *
 * What only this file can prove:
 *
 *  - the DO class actually RESOLVES from the entry module's export (the harness
 *    Worker would not boot otherwise, so every test here failing to run at all
 *    is the signal that the `export { RateLimiterDurableObject }` line is
 *    missing);
 *  - `idFromName(counterKey)` really does give one instance per counter key, so
 *    the namespacing in `keys.ts` is an isolation boundary in the runtime and
 *    not just in a pure function;
 *  - window state survives across separate stub acquisitions (the property a
 *    module-scope `Map` cannot provide across isolates).
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, test } from "vitest";
import { DurableObjectRateLimiter } from "../../src/ratelimit/index.js";

const limiter = () => new DurableObjectRateLimiter(env.RATE_LIMIT);

/** Pin the DO's clock, the way Rust threaded `now_unix_seconds` into a window. */
async function pinClock(counterKey: string, now: () => number): Promise<void> {
  const stub = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(counterKey));
  await runInDurableObject(stub, (instance) => {
    instance.clock = now;
  });
}

/** A counter key nobody else in this file uses, so tests never share a window. */
let unique = 0;
const freshKey = (prefix = "tenant") => `${prefix}:do_spec_${unique++}`;

describe("RateLimiterDurableObject — RPM over a real binding", () => {
  test("under limit passes; over limit denies", async () => {
    const key = freshKey();
    const windows = [{ counterKey: key, limit: 3 }];
    const rl = limiter();
    expect(await rl.consumeRequest(windows)).toEqual({ allowed: true });
    expect(await rl.consumeRequest(windows)).toEqual({ allowed: true });
    expect(await rl.consumeRequest(windows)).toEqual({ allowed: true });
    const denied = await rl.consumeRequest(windows);
    expect(denied.allowed).toBe(false);
    expect(denied).toMatchObject({ counterKey: key, limit: 3 });
  });

  test("the count survives a fresh stub — the state is in the DO, not the isolate", async () => {
    const key = freshKey();
    const windows = [{ counterKey: key, limit: 1 }];
    expect((await limiter().consumeRequest(windows)).allowed).toBe(true);
    // A brand-new limiter object, a brand-new stub, the SAME durable window.
    expect((await limiter().consumeRequest(windows)).allowed).toBe(false);
  });

  test("window rollover admits traffic again after 60s", async () => {
    const key = freshKey();
    const clock = { now: 1_700_000_000 };
    await pinClock(key, () => clock.now);
    const rl = limiter();
    const windows = [{ counterKey: key, limit: 2 }];

    expect((await rl.consumeRequest(windows)).allowed).toBe(true);
    expect((await rl.consumeRequest(windows)).allowed).toBe(true);
    const denied = await rl.consumeRequest(windows);
    expect(denied.allowed).toBe(false);
    expect(denied.allowed === false && denied.retryAfterSeconds).toBe(60);

    // One second short of the boundary: still denied.
    clock.now += 59;
    expect((await rl.consumeRequest(windows)).allowed).toBe(false);

    // On the boundary: the window rolls and the budget is whole again.
    clock.now += 1;
    expect((await rl.consumeRequest(windows)).allowed).toBe(true);
    expect((await rl.consumeRequest(windows)).allowed).toBe(true);
    expect((await rl.consumeRequest(windows)).allowed).toBe(false);
  });

  test("retryAfterSeconds counts down within the window", async () => {
    const key = freshKey();
    const clock = { now: 1_700_000_000 };
    await pinClock(key, () => clock.now);
    const rl = limiter();
    const windows = [{ counterKey: key, limit: 1 }];
    expect((await rl.consumeRequest(windows)).allowed).toBe(true);
    clock.now += 25;
    const denied = await rl.consumeRequest(windows);
    expect(denied.allowed === false && denied.retryAfterSeconds).toBe(35);
  });

  test("two counter keys are two INSTANCES, not two entries in one map", async () => {
    const a = freshKey("tenant");
    const b = freshKey("key");
    const rl = limiter();
    expect((await rl.consumeRequest([{ counterKey: a, limit: 1 }])).allowed).toBe(true);
    expect((await rl.consumeRequest([{ counterKey: b, limit: 1 }])).allowed).toBe(true);
    expect((await rl.consumeRequest([{ counterKey: a, limit: 1 }])).allowed).toBe(false);
    expect((await rl.consumeRequest([{ counterKey: b, limit: 1 }])).allowed).toBe(false);

    // …and their state really is separate storage.
    const stubA = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(a));
    const stubB = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(b));
    expect((await stubA.snapshot()).rpm.used).toBe(1);
    expect((await stubB.snapshot()).rpm.used).toBe(1);
  });

  test("an unnamespaced counter key never reaches idFromName", async () => {
    await expect(
      limiter().consumeRequest([{ counterKey: "raw_key_id", limit: 5 }]),
    ).rejects.toThrow(/not scope-namespaced/);
  });
});

describe("RateLimiterDurableObject — TPM reservation / settlement", () => {
  test("charges the ESTIMATE at admission, then reconciles to the ACTUAL", async () => {
    const key = freshKey("project");
    const rl = limiter();
    const window = { counterKey: key, limit: 1000 };

    const admission = await rl.consumeTokens(window, 800);
    expect(admission.allowed).toBe(true);

    const stub = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(key));
    expect((await stub.snapshot()).tpm.used).toBe(800);

    // Second 800-token request cannot fit while the first estimate is charged —
    // this is the whole point of charging BEFORE the response is known.
    expect((await rl.consumeTokens(window, 800)).allowed).toBe(false);

    // The response really used 100 tokens. Settling frees the difference.
    await rl.settleTokens(admission, 100);
    expect((await stub.snapshot()).tpm.used).toBe(100);
    expect((await rl.consumeTokens(window, 800)).allowed).toBe(true);
  });

  test("a settlement arriving after the window rolled is dropped", async () => {
    const key = freshKey("project");
    const clock = { now: 1_700_000_000 };
    await pinClock(key, () => clock.now);
    const rl = limiter();
    const window = { counterKey: key, limit: 1000 };

    const admission = await rl.consumeTokens(window, 900);
    expect(admission.allowed).toBe(true);

    clock.now += 60; // new minute
    expect((await rl.consumeTokens(window, 50)).allowed).toBe(true);

    // The late settlement belongs to the PREVIOUS window and must not credit
    // (or debit) this one.
    await rl.settleTokens(admission, 10);
    const stub = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(key));
    expect((await stub.snapshot()).tpm.used).toBe(50);
  });

  test("TPM and RPM are separate dimensions of the same instance", async () => {
    const key = freshKey("tenant");
    const rl = limiter();
    // Exhaust TPM…
    expect((await rl.consumeTokens({ counterKey: key, limit: 10 }, 10)).allowed).toBe(true);
    expect((await rl.consumeTokens({ counterKey: key, limit: 10 }, 1)).allowed).toBe(false);
    // …RPM on the same key is untouched.
    expect((await rl.consumeRequest([{ counterKey: key, limit: 1 }])).allowed).toBe(true);
  });
});

describe("RateLimiterDurableObject — budget + wallet reservations", () => {
  test("concurrent token-budget holds cannot jointly exceed the budget", async () => {
    const key = freshKey("key");
    const rl = limiter();
    // Fired concurrently: the DO serializes them, so exactly two of the four
    // 400-token holds fit inside a 1000-token budget.
    const outcomes = await Promise.all([
      rl.reserveTokenBudget(key, 0, 1000, 400),
      rl.reserveTokenBudget(key, 0, 1000, 400),
      rl.reserveTokenBudget(key, 0, 1000, 400),
      rl.reserveTokenBudget(key, 0, 1000, 400),
    ]);
    expect(outcomes.filter((o) => o.outcome === "reserved")).toHaveLength(2);
    expect(outcomes.filter((o) => o.outcome === "insufficient")).toHaveLength(2);
  });

  test("releasing a hold frees the budget again", async () => {
    const key = freshKey("key");
    const rl = limiter();
    const held = await rl.reserveTokenBudget(key, 0, 100, 100);
    expect(held.outcome).toBe("reserved");
    expect((await rl.reserveTokenBudget(key, 0, 100, 1)).outcome).toBe("insufficient");
    if (held.outcome !== "reserved") throw new Error("unreachable");
    await held.reservation.release();
    expect((await rl.reserveTokenBudget(key, 0, 100, 100)).outcome).toBe("reserved");
  });

  test("wallet holds serialize against the funded balance (#169 overdraft)", async () => {
    const key = freshKey("tenant");
    const rl = limiter();
    const outcomes = await Promise.all([
      rl.reserveWalletCredits(key, 100, 60),
      rl.reserveWalletCredits(key, 100, 60),
      rl.reserveWalletCredits(key, 100, 60),
    ]);
    expect(outcomes.filter((o) => o.outcome === "reserved")).toHaveLength(1);
    expect(outcomes.filter((o) => o.outcome === "insufficient")).toHaveLength(2);
  });

  test("an unpriced route takes no wallet hold (Rust NotApplicable)", async () => {
    const rl = limiter();
    expect(await rl.reserveWalletCredits(freshKey("tenant"), 0, 0)).toEqual({
      outcome: "not_applicable",
    });
  });
});
