/**
 * The cross-isolate shadow-mirror budget, against a REAL Durable Object in
 * `workerd`.
 *
 * The claim being tested is the one the in-isolate `ShadowBudgetLedger` cannot
 * make: that a cap of N holds no matter how many isolates, requests, or
 * concurrent calls there are, and that eviction does not silently reset it.
 * Over-counting a shadow budget spends real money on mirrored inference the
 * operator asked not to spend.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import {
  DurableObjectShadowBudgetLedger,
  type ShadowBudgetDurableObject,
  type ShadowBudgetNamespace,
} from "../../src/shadow-budget-do.js";
import { ShadowBudgetLedger } from "../../src/index.js";

declare global {
  namespace Cloudflare {
    interface Env {
      SHADOW_BUDGET: ShadowBudgetNamespace;
    }
  }
}

let ledger: DurableObjectShadowBudgetLedger;

beforeEach(async () => {
  ledger = new DurableObjectShadowBudgetLedger(env.SHADOW_BUDGET);
  for (const key of ["gpt-4o", "claude", "shared"]) await ledger.reset(key);
});

describe("DurableObjectShadowBudgetLedger — the cap", () => {
  test("admits exactly `limit` dispatches, then refuses", async () => {
    const admitted: boolean[] = [];
    for (let i = 0; i < 5; i += 1) admitted.push(await ledger.tryConsume("gpt-4o", 3));
    expect(admitted).toEqual([true, true, true, false, false]);
    expect(await ledger.consumed("gpt-4o")).toBe(3);
  });

  test("a refused dispatch does NOT charge the budget", async () => {
    for (let i = 0; i < 10; i += 1) await ledger.tryConsume("gpt-4o", 2);
    expect(await ledger.consumed("gpt-4o")).toBe(2);
  });

  test("limit 0 is UNCAPPED and records nothing", async () => {
    for (let i = 0; i < 4; i += 1) expect(await ledger.tryConsume("gpt-4o", 0)).toBe(true);
    // Not merely "always true": an uncapped rollout must also pay no DO round
    // trip and store no counter, so a later capped call starts from zero.
    expect(await ledger.consumed("gpt-4o")).toBe(0);
    expect(await ledger.tryConsume("gpt-4o", 1)).toBe(true);
  });

  test("budgets are keyed per scope and do not bleed", async () => {
    expect(await ledger.tryConsume("gpt-4o", 1)).toBe(true);
    expect(await ledger.tryConsume("gpt-4o", 1)).toBe(false);
    // A different logical model has its own instance and its own full budget.
    expect(await ledger.tryConsume("claude", 1)).toBe(true);
    expect(await ledger.consumed("gpt-4o")).toBe(1);
    expect(await ledger.consumed("claude")).toBe(1);
  });

  test("CONCURRENT admissions cannot oversell the cap", async () => {
    // This is the whole reason the DO exists. Fired together, an unsynchronized
    // read-modify-write would admit far more than 3.
    const results = await Promise.all(
      Array.from({ length: 20 }, () => ledger.tryConsume("shared", 3)),
    );
    expect(results.filter(Boolean).length).toBe(3);
    expect(await ledger.consumed("shared")).toBe(3);
  });

  test("TWO ledger instances (standing in for two isolates) share ONE counter", async () => {
    const isolateA = new DurableObjectShadowBudgetLedger(env.SHADOW_BUDGET);
    const isolateB = new DurableObjectShadowBudgetLedger(env.SHADOW_BUDGET);
    expect(await isolateA.tryConsume("gpt-4o", 2)).toBe(true);
    expect(await isolateB.tryConsume("gpt-4o", 2)).toBe(true);
    // If the counter were per-isolate, this third call (the second on B) would
    // be admitted and the cap of 2 would have become a cap of 4.
    expect(await isolateB.tryConsume("gpt-4o", 2)).toBe(false);
    expect(await isolateA.consumed("gpt-4o")).toBe(2);
  });
});

describe("DurableObjectShadowBudgetLedger — durability", () => {
  test("the count is written THROUGH to storage, so eviction cannot reset it", async () => {
    await ledger.tryConsume("gpt-4o", 5);
    await ledger.tryConsume("gpt-4o", 5);
    const id = env.SHADOW_BUDGET.idFromName("gpt-4o");
    const stub = env.SHADOW_BUDGET.get(id);
    await runInDurableObject(stub, async (_instance: ShadowBudgetDurableObject, state) => {
      // Reading the RAW storage key, not the in-memory field: an implementation
      // that only kept the count in memory would pass every test above and fail
      // here — and would lose the cap on the first eviction.
      expect(await state.storage.get<number>("shadow:used")).toBe(2);
    });
  });

  test("reset clears both the field and the stored key", async () => {
    await ledger.tryConsume("gpt-4o", 5);
    await ledger.reset("gpt-4o");
    expect(await ledger.consumed("gpt-4o")).toBe(0);
    const stub = env.SHADOW_BUDGET.get(env.SHADOW_BUDGET.idFromName("gpt-4o"));
    await runInDurableObject(stub, async (_instance: ShadowBudgetDurableObject, state) => {
      expect(await state.storage.get<number>("shadow:used")).toBeUndefined();
    });
  });
});

describe("the DO ledger agrees with the in-isolate reference ledger", () => {
  /**
   * `ShadowBudgetLedger` remains the executable specification of the Rust
   * semantics; the DO must produce the SAME admission sequence, or one of the
   * two has drifted.
   */
  test("identical admission sequence for the same inputs", async () => {
    const reference = new ShadowBudgetLedger();
    const referenceSeq: boolean[] = [];
    const durableSeq: boolean[] = [];
    for (const limit of [3, 3, 3, 3, 0, 3]) {
      referenceSeq.push(reference.tryConsume("gpt-4o", limit));
      durableSeq.push(await ledger.tryConsume("gpt-4o", limit));
    }
    expect(durableSeq).toEqual(referenceSeq);
    expect(await ledger.consumed("gpt-4o")).toBe(reference.consumed("gpt-4o"));
  });
});
