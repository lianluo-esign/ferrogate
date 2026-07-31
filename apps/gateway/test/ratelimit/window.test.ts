/**
 * The pure counter arithmetic — the fixed 60s windows and the two reservation
 * ledgers, checked against the Rust originals in
 * `crates/ferrogate-gateway/src/state.rs`.
 *
 * Time is a parameter here exactly as it is in Rust
 * (`try_consume(limit, now_unix_seconds)`), so rollover is asserted without
 * sleeping. The same arithmetic runs inside the Durable Object — see
 * `harness/durable-object.spec.ts` for it exercised through a REAL DO binding.
 */
import { describe, expect, test } from "vitest";
import {
  InMemoryRateLimiter,
  RequestWindow,
  TokenBudgetLedger,
  TokenWindow,
  WINDOW_SECONDS,
  WalletLedger,
  secondsUntilWindowReset,
} from "../../src/ratelimit/index.js";

describe("RequestWindow (RPM) — Rust ApiKeyRequestWindow", () => {
  test("admits exactly `limit` requests, then denies", () => {
    const w = new RequestWindow();
    expect(w.tryConsume(3, 1000)).toBe(true);
    expect(w.tryConsume(3, 1000)).toBe(true);
    expect(w.tryConsume(3, 1000)).toBe(true);
    expect(w.tryConsume(3, 1000)).toBe(false);
    expect(w.state.used).toBe(3);
  });

  test("a denied request is NOT charged (the window stays at the limit)", () => {
    const w = new RequestWindow();
    w.tryConsume(1, 1000);
    w.tryConsume(1, 1000);
    w.tryConsume(1, 1000);
    expect(w.state.used).toBe(1);
  });

  test("limit 0 denies every request — Rust `count >= limit`", () => {
    expect(new RequestWindow().tryConsume(0, 1000)).toBe(false);
  });

  test("rolls over at exactly 60s, not 59", () => {
    const w = new RequestWindow();
    expect(w.tryConsume(1, 1000)).toBe(true);
    expect(w.tryConsume(1, 1000 + WINDOW_SECONDS - 1)).toBe(false);
    expect(w.tryConsume(1, 1000 + WINDOW_SECONDS)).toBe(true);
    // The new window is anchored at `now`, not at the old start + 60 — the Rust
    // window is fixed-from-first-use, not minute-aligned.
    expect(w.state.windowStartedAt).toBe(1000 + WINDOW_SECONDS);
  });

  test("a long gap resets rather than accumulating credit", () => {
    const w = new RequestWindow();
    w.tryConsume(2, 1000);
    w.tryConsume(2, 1000);
    expect(w.tryConsume(2, 100_000)).toBe(true);
    expect(w.state.used).toBe(1);
  });

  test("clock going backwards does not roll the window (Rust saturating_sub)", () => {
    const w = new RequestWindow();
    expect(w.tryConsume(1, 1000)).toBe(true);
    expect(w.tryConsume(1, 900)).toBe(false);
  });

  test("secondsUntilWindowReset counts down to the rollover", () => {
    const w = new RequestWindow();
    w.tryConsume(1, 1000);
    expect(secondsUntilWindowReset(w.state, 1000)).toBe(60);
    expect(secondsUntilWindowReset(w.state, 1045)).toBe(15);
    expect(secondsUntilWindowReset(w.state, 1060)).toBe(0);
    expect(secondsUntilWindowReset(w.state, 9999)).toBe(0);
  });
});

describe("TokenWindow (TPM) — Rust ApiKeyTokenWindow", () => {
  test("sums tokens and denies the request that would exceed the limit", () => {
    const w = new TokenWindow();
    expect(w.tryConsume(1000, 600, 1000)).toBe(true);
    expect(w.tryConsume(1000, 300, 1000)).toBe(true);
    expect(w.tryConsume(1000, 200, 1000)).toBe(false);
    expect(w.state.used).toBe(900);
  });

  test("admits a request landing EXACTLY on the limit — Rust `used + t > limit`", () => {
    const w = new TokenWindow();
    expect(w.tryConsume(1000, 1000, 1000)).toBe(true);
    expect(w.tryConsume(1000, 1, 1000)).toBe(false);
  });

  test("rolls over at 60s", () => {
    const w = new TokenWindow();
    w.tryConsume(100, 100, 1000);
    expect(w.tryConsume(100, 100, 1059)).toBe(false);
    expect(w.tryConsume(100, 100, 1060)).toBe(true);
  });

  test("settlement swaps the estimate for the actual usage", () => {
    const w = new TokenWindow();
    expect(w.tryConsume(1000, 800, 1000)).toBe(true);
    // The response really used 100 tokens, not the 800 estimated.
    w.settle(w.state.windowStartedAt, 800, 100);
    expect(w.state.used).toBe(100);
    // …so the freed budget is usable again inside the same minute.
    expect(w.tryConsume(1000, 800, 1000)).toBe(true);
  });

  test("settlement of an over-run charges the difference", () => {
    const w = new TokenWindow();
    w.tryConsume(1000, 100, 1000);
    w.settle(1000, 100, 950);
    expect(w.state.used).toBe(950);
  });

  test("a settlement for a window that already rolled is DROPPED", () => {
    const w = new TokenWindow();
    w.tryConsume(1000, 800, 1000);
    const admitted = w.state.windowStartedAt;
    // New minute, fresh charge.
    expect(w.tryConsume(1000, 50, 1100)).toBe(true);
    expect(w.state.used).toBe(50);
    // The late settlement of the PREVIOUS window must not touch this one.
    w.settle(admitted, 800, 10);
    expect(w.state.used).toBe(50);
  });

  test("settlement never drives the window negative", () => {
    const w = new TokenWindow();
    w.tryConsume(1000, 10, 1000);
    w.settle(1000, 900, 0);
    expect(w.state.used).toBe(0);
  });
});

describe("TokenBudgetLedger — Rust try_reserve_tokens / release_tokens", () => {
  test("reserves against committed + in-flight", () => {
    const l = new TokenBudgetLedger();
    expect(l.tryReserve(400, 1000, 300)).toBe(true);
    expect(l.reserved).toBe(300);
    // 400 committed + 300 held + 400 = 1100 > 1000.
    expect(l.tryReserve(400, 1000, 400)).toBe(false);
    expect(l.reserved).toBe(300);
    expect(l.tryReserve(400, 1000, 300)).toBe(true);
    expect(l.reserved).toBe(600);
  });

  test("concurrent holds cannot jointly exceed the budget", () => {
    // The overdraft this guards: N requests each reading `committed` alone
    // would all pass; the in-flight sum is what serializes them.
    const l = new TokenBudgetLedger();
    const granted = [1, 2, 3, 4, 5].filter(() => l.tryReserve(0, 1000, 400));
    expect(granted).toHaveLength(2);
    expect(l.reserved).toBe(800);
  });

  test("a hold landing exactly on the budget is allowed", () => {
    expect(new TokenBudgetLedger().tryReserve(600, 1000, 400)).toBe(true);
  });

  test("release frees the hold and never goes negative", () => {
    const l = new TokenBudgetLedger();
    l.tryReserve(0, 1000, 400);
    l.release(400);
    expect(l.reserved).toBe(0);
    l.release(400);
    expect(l.reserved).toBe(0);
  });
});

describe("WalletLedger — Rust try_reserve_wallet_credits (#169 overdraft)", () => {
  test("in-flight holds cannot jointly overdraw the funded balance", () => {
    const l = new WalletLedger();
    const granted = [1, 2, 3].filter(() => l.tryReserve(100, 40));
    expect(granted).toHaveLength(2);
    expect(l.reserved).toBe(80);
    expect(l.tryReserve(100, 40)).toBe(false);
  });

  test("release frees the hold", () => {
    const l = new WalletLedger();
    l.tryReserve(100, 100);
    expect(l.tryReserve(100, 1)).toBe(false);
    l.release(100);
    expect(l.tryReserve(100, 1)).toBe(true);
  });
});

describe("InMemoryRateLimiter — the RateLimiter port over the same arithmetic", () => {
  const at = (t: { now: number }) => new InMemoryRateLimiter({ clock: () => t.now });

  test("under limit passes, over limit denies with the denying window named", async () => {
    const t = { now: 1000 };
    const limiter = at(t);
    const windows = [{ counterKey: "tenant:t1", limit: 2 }];
    expect(await limiter.consumeRequest(windows)).toEqual({ allowed: true });
    expect(await limiter.consumeRequest(windows)).toEqual({ allowed: true });
    expect(await limiter.consumeRequest(windows)).toEqual({
      allowed: false,
      counterKey: "tenant:t1",
      limit: 2,
      retryAfterSeconds: 60,
    });
  });

  test("window rollover lets traffic through again", async () => {
    const t = { now: 1000 };
    const limiter = at(t);
    const windows = [{ counterKey: "key:k1", limit: 1 }];
    expect(await limiter.consumeRequest(windows)).toEqual({ allowed: true });
    expect((await limiter.consumeRequest(windows)).allowed).toBe(false);
    t.now = 1060;
    expect(await limiter.consumeRequest(windows)).toEqual({ allowed: true });
  });

  test("distinct counter keys are independent budgets", async () => {
    const t = { now: 1000 };
    const limiter = at(t);
    expect(
      (await limiter.consumeRequest([{ counterKey: "tenant:victim", limit: 1 }])).allowed,
    ).toBe(true);
    // The attacker's namespaced key is a DIFFERENT window, so the victim's
    // budget is untouched by it.
    expect(
      (await limiter.consumeRequest([{ counterKey: "key:tenant:victim", limit: 1 }])).allowed,
    ).toBe(true);
    expect(
      (await limiter.consumeRequest([{ counterKey: "tenant:victim", limit: 1 }])).allowed,
    ).toBe(false);
  });

  test("multiple windows: the first denial short-circuits, earlier ones stay charged", async () => {
    const t = { now: 1000 };
    const limiter = at(t);
    const windows = [
      { counterKey: "key:k1", limit: 5 },
      { counterKey: "tenant:t1", limit: 1 },
    ];
    expect((await limiter.consumeRequest(windows)).allowed).toBe(true);
    const denied = await limiter.consumeRequest(windows);
    expect(denied.allowed).toBe(false);
    expect(denied.allowed === false && denied.counterKey).toBe("tenant:t1");
    // The per-key window was charged twice (Rust charges in order and returns
    // on the first denial), so only 3 of its 5 remain.
    for (const _ of [1, 2, 3]) {
      expect((await limiter.consumeRequest([{ counterKey: "key:k1", limit: 5 }])).allowed).toBe(
        true,
      );
    }
    expect((await limiter.consumeRequest([{ counterKey: "key:k1", limit: 5 }])).allowed).toBe(
      false,
    );
  });

  test("an unnamespaced counter key is refused outright", async () => {
    const limiter = new InMemoryRateLimiter();
    await expect(limiter.consumeRequest([{ counterKey: "k1", limit: 5 }])).rejects.toThrow(
      /not scope-namespaced/,
    );
  });

  test("TPM admission + settlement round trip", async () => {
    const t = { now: 1000 };
    const limiter = at(t);
    const window = { counterKey: "project:p1", limit: 1000 };
    const admission = await limiter.consumeTokens(window, 800);
    expect(admission.allowed).toBe(true);
    // The estimate is charged, so a second 800-token request is refused…
    expect((await limiter.consumeTokens(window, 800)).allowed).toBe(false);
    // …until the first one settles at its real, much smaller usage.
    await limiter.settleTokens(admission, 50);
    expect((await limiter.consumeTokens(window, 800)).allowed).toBe(true);
  });

  test("wallet: a zero-cost (unpriced) request takes no hold — Rust NotApplicable", async () => {
    const limiter = new InMemoryRateLimiter();
    expect(await limiter.reserveWalletCredits("tenant:t1", 0, 0)).toEqual({
      outcome: "not_applicable",
    });
  });

  test("reservations release exactly once", async () => {
    const limiter = new InMemoryRateLimiter();
    const first = await limiter.reserveTokenBudget("key:k1", 0, 100, 100);
    expect(first.outcome).toBe("reserved");
    expect((await limiter.reserveTokenBudget("key:k1", 0, 100, 1)).outcome).toBe("insufficient");
    if (first.outcome !== "reserved") throw new Error("unreachable");
    await first.reservation.release();
    await first.reservation.release(); // idempotent — Rust `released: bool`
    expect((await limiter.reserveTokenBudget("key:k1", 0, 100, 100)).outcome).toBe("reserved");
  });
});
