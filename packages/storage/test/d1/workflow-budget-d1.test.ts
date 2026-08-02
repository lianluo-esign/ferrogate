/**
 * The workflow-budget optimistic-CAS proof, against a REAL D1 database
 * (inventory §1.5.3, issue #279).
 *
 * The claim under test is no-OVERSPEND: N concurrent steps against a cap of K
 * let exactly K through, and a breach applies no spend. Like the wallet suite,
 * this only means anything against real SQLite — the guard's whole mechanism is
 * that an `UPDATE ... WHERE <snapshot> RETURNING` returns nothing when somebody
 * else committed first.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1WorkflowBudgetStore,
  MemoryWorkflowBudgetStore,
  type TenantDatabaseHandle,
  workflowRunBudgetId,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, resetTenantData, setupDatabases } from "./harness.js";

const NOW = 1_700_000_000;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupDatabases();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
});

beforeEach(async () => {
  await resetTenantData(env.TENANT_DB_A);
  await resetTenantData(env.TENANT_DB_B);
});

const ID = workflowRunBudgetId("wf", 1, "run");

describe("D1WorkflowBudgetStore — open", () => {
  test("is idempotent and does NOT widen the caps on re-open", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    const first = await store.openWorkflowRunBudget(
      "wf",
      1,
      "run",
      TENANT_A,
      { tokenBudget: 100 },
      NOW,
    );
    expect(first.tokenBudget).toBe(100);
    expect(first.status).toBe("active");

    // A second open asking for MORE must be ignored — caps are fixed at the
    // first step, or a runaway step could re-open its way past its envelope.
    const second = await store.openWorkflowRunBudget(
      "wf",
      1,
      "run",
      TENANT_A,
      { tokenBudget: 10_000 },
      NOW + 5,
    );
    expect(second.tokenBudget).toBe(100);
    expect(second.createdAtUnix).toBe(NOW);
  });

  test("an absent cap is unbounded, not zero", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    const opened = await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, {}, NOW);
    expect(opened.costBudgetCredits).toBeUndefined();
    expect(opened.tokenBudget).toBeUndefined();
    // A large debit against an all-unbounded envelope is applied.
    const debit = await store.debitWorkflowRunBudget(ID, 1_000_000, 1_000_000, 1_000_000, NOW);
    expect(debit.kind).toBe("applied");
  });

  test("re-opening under a different tenant is a conflict", async () => {
    const storeA = new D1WorkflowBudgetStore(handleA);
    await storeA.openWorkflowRunBudget("wf", 1, "run", TENANT_A, {}, NOW);
    // Same physical database, a different tenant id claiming the same run id.
    const rogue = new D1WorkflowBudgetStore({ ...handleA, tenantId: "tenant_x" });
    await expect(
      rogue.openWorkflowRunBudget("wf", 1, "run", "tenant_x", {}, NOW),
    ).rejects.toMatchObject({ kind: "conflict" });
  });
});

describe("D1WorkflowBudgetStore — no-overspend under concurrency", () => {
  test("CONCURRENT: 10 parallel single-tool-call debits against a cap of 4 apply exactly 4", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { toolCallBudget: 4 }, NOW);

    const outcomes = await Promise.all(
      Array.from({ length: 10 }, () => store.debitWorkflowRunBudget(ID, 0, 0, 1, NOW)),
    );

    expect(outcomes.filter((o) => o.kind === "applied")).toHaveLength(4);
    const exceeded = outcomes.filter((o) => o.kind === "exceeded");
    expect(exceeded).toHaveLength(6);
    for (const o of exceeded) {
      expect(o.kind === "exceeded" && o.dimension).toBe("tool_calls");
    }

    const final = await store.getWorkflowRunBudget(ID);
    // The durable counter matches what callers were told: never more than the cap.
    expect(final?.spentToolCalls).toBe(4);
    expect(final?.spentToolCalls).toBeLessThanOrEqual(4);
    expect(final?.status).toBe("exhausted");
  });

  test("CONCURRENT: 12 parallel cost debits of 10 against a cost cap of 55 apply exactly 5", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { costBudgetCredits: 55 }, NOW);

    const outcomes = await Promise.all(
      Array.from({ length: 12 }, () => store.debitWorkflowRunBudget(ID, 10, 0, 0, NOW)),
    );
    expect(outcomes.filter((o) => o.kind === "applied")).toHaveLength(5);
    const final = await store.getWorkflowRunBudget(ID);
    expect(final?.spentCredits).toBe(50);
    expect(final?.spentCredits).toBeLessThanOrEqual(55);
  });
});

describe("D1WorkflowBudgetStore — fail-closed breach semantics", () => {
  test("a breach applies NO spend and flips the run to exhausted", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 100 }, NOW);
    await store.debitWorkflowRunBudget(ID, 0, 60, 0, NOW);

    const breach = await store.debitWorkflowRunBudget(ID, 0, 60, 0, NOW);
    expect(breach.kind).toBe("exceeded");
    expect(breach.kind === "exceeded" && breach.dimension).toBe("tokens");

    const after = await store.getWorkflowRunBudget(ID);
    // 60, not 120 — the refused step's spend was NOT applied.
    expect(after?.spentTokens).toBe(60);
    expect(after?.status).toBe("exhausted");
  });

  test("an exhausted run rejects every subsequent debit, even one that would fit", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 100 }, NOW);
    await store.debitWorkflowRunBudget(ID, 0, 200, 0, NOW); // breach -> exhausted

    const tiny = await store.debitWorkflowRunBudget(ID, 0, 1, 0, NOW);
    expect(tiny.kind).toBe("exceeded");
    expect((await store.getWorkflowRunBudget(ID))?.spentTokens).toBe(0);
  });

  test("dimension precedence is wall_clock, then cost, then tokens, then tool_calls", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget(
      "wf",
      1,
      "run",
      TENANT_A,
      { costBudgetCredits: 1, tokenBudget: 1, toolCallBudget: 1, wallClockDeadlineUnix: NOW + 10 },
      NOW,
    );
    // Everything breaches at once; `cost` is reported because the deadline has
    // not passed yet.
    const breach = await store.debitWorkflowRunBudget(ID, 5, 5, 5, NOW);
    expect(breach.kind === "exceeded" && breach.dimension).toBe("cost");

    // Past the deadline, wall_clock wins over every numeric dimension.
    await store.topupWorkflowRunBudget(ID, 100, 100, 100, undefined, NOW);
    const late = await store.debitWorkflowRunBudget(ID, 0, 0, 0, NOW + 999);
    expect(late.kind === "exceeded" && late.dimension).toBe("wall_clock");
  });

  test("a negative debit amount is a conflict, not a credit", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 100 }, NOW);
    await expect(store.debitWorkflowRunBudget(ID, 0, -50, 0, NOW)).rejects.toMatchObject({
      kind: "conflict",
    });
    expect((await store.getWorkflowRunBudget(ID))?.spentTokens).toBe(0);
  });

  test("debiting an unknown run is not_found", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await expect(store.debitWorkflowRunBudget("nope", 0, 1, 0, NOW)).rejects.toMatchObject({
      kind: "not_found",
    });
  });
});

describe("D1WorkflowBudgetStore — top-up", () => {
  test("raises caps, reactivates, and preserves already-applied spend", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 100 }, NOW);
    await store.debitWorkflowRunBudget(ID, 0, 80, 0, NOW);
    await store.debitWorkflowRunBudget(ID, 0, 80, 0, NOW); // breach -> exhausted

    const topped = await store.topupWorkflowRunBudget(ID, 0, 100, 0, undefined, NOW + 1);
    expect(topped.tokenBudget).toBe(200);
    expect(topped.status).toBe("active");
    expect(topped.spentTokens).toBe(80);

    const next = await store.debitWorkflowRunBudget(ID, 0, 80, 0, NOW + 2);
    expect(next.kind).toBe("applied");
  });

  test("an unbounded dimension STAYS unbounded across a top-up", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 10 }, NOW);
    const topped = await store.topupWorkflowRunBudget(ID, 500, 10, 500, undefined, NOW + 1);
    // Adding to an absent cap must not CREATE one — that would silently narrow
    // an unbounded dimension to the delta.
    expect(topped.costBudgetCredits).toBeUndefined();
    expect(topped.toolCallBudget).toBeUndefined();
    expect(topped.tokenBudget).toBe(20);
  });

  test("the deadline extends to the LATER of current and requested", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget(
      "wf",
      1,
      "run",
      TENANT_A,
      { wallClockDeadlineUnix: NOW + 1_000 },
      NOW,
    );
    const shrunk = await store.topupWorkflowRunBudget(ID, 0, 0, 0, NOW + 10, NOW);
    expect(shrunk.wallClockDeadlineUnix).toBe(NOW + 1_000);
    const grown = await store.topupWorkflowRunBudget(ID, 0, 0, 0, NOW + 5_000, NOW);
    expect(grown.wallClockDeadlineUnix).toBe(NOW + 5_000);
  });

  test("CONCURRENT top-ups COMPOSE rather than one overwriting the other", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 0 }, NOW);

    await Promise.all(
      Array.from({ length: 6 }, () => store.topupWorkflowRunBudget(ID, 0, 10, 0, undefined, NOW)),
    );
    // 6 x 10 — a lost update would show 10. This is what the caps-in-the-guard
    // CAS buys: each raise is applied to the value it was computed from.
    expect((await store.getWorkflowRunBudget(ID))?.tokenBudget).toBe(60);
  });

  test("a concurrent top-up forces an in-flight debit to re-decide against the NEW cap", async () => {
    const store = new D1WorkflowBudgetStore(handleA);
    await store.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 10 }, NOW);

    // Race one debit that does not fit the old cap against a top-up that makes
    // it fit. Whichever order the CAS resolves in, the outcome must be
    // consistent with the FINAL cap: applied+120 spent, or exceeded+0 spent.
    const [debit] = await Promise.all([
      store.debitWorkflowRunBudget(ID, 0, 120, 0, NOW),
      store.topupWorkflowRunBudget(ID, 0, 500, 0, undefined, NOW),
    ]);
    const final = await store.getWorkflowRunBudget(ID);
    if (debit.kind === "applied") {
      expect(final?.spentTokens).toBe(120);
      expect(final?.tokenBudget).toBe(510);
    } else {
      // Refused against the old cap: no spend, and the top-up still landed.
      expect(final?.spentTokens).toBe(0);
      expect(final?.tokenBudget).toBe(510);
    }
  });
});

describe("D1WorkflowBudgetStore — parity with the in-memory reference backend", () => {
  test("the same sequence produces the same observable outcomes in both backends", async () => {
    const d1 = new D1WorkflowBudgetStore(handleA);
    const mem = new MemoryWorkflowBudgetStore();
    const caps = { costBudgetCredits: 100, tokenBudget: 50, toolCallBudget: 3 };

    await d1.openWorkflowRunBudget("wf", 1, "run", TENANT_A, caps, NOW);
    mem.openWorkflowRunBudget("wf", 1, "run", TENANT_A, caps, NOW);

    const steps: [number, number, number][] = [
      [10, 10, 1],
      [10, 10, 1],
      [10, 10, 1],
      [10, 10, 1], // breaches tool_calls
    ];
    for (const [cost, tokens, tools] of steps) {
      const a = await d1.debitWorkflowRunBudget(ID, cost, tokens, tools, NOW);
      const b = mem.debitWorkflowRunBudget(ID, cost, tokens, tools, NOW);
      expect(a.kind).toBe(b.kind);
      if (a.kind === "exceeded" && b.kind === "exceeded") {
        expect(a.dimension).toBe(b.dimension);
      }
      expect(a.budget.spentCredits).toBe(b.budget.spentCredits);
      expect(a.budget.spentTokens).toBe(b.budget.spentTokens);
      expect(a.budget.spentToolCalls).toBe(b.budget.spentToolCalls);
      expect(a.budget.status).toBe(b.budget.status);
    }
  });
});

describe("D1WorkflowBudgetStore — isolation", () => {
  test("a run opened for tenant A is absent from tenant B's database", async () => {
    const storeA = new D1WorkflowBudgetStore(handleA);
    const storeB = new D1WorkflowBudgetStore(handleB);
    await storeA.openWorkflowRunBudget("wf", 1, "run", TENANT_A, { tokenBudget: 10 }, NOW);
    expect(await storeB.getWorkflowRunBudget(ID)).toBeUndefined();
    expect(await storeB.listWorkflowRunBudgets(TENANT_A)).toEqual([]);
  });

  test("opening tenant B's run through tenant A's handle is refused", async () => {
    const storeA = new D1WorkflowBudgetStore(handleA);
    await expect(storeA.openWorkflowRunBudget("wf", 1, "run", TENANT_B, {}, NOW)).rejects.toThrow(
      /refusing to cross tenant isolation/,
    );
  });
});
