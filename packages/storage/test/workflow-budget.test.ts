import { beforeEach, describe, expect, test } from "vitest";
import {
  MemoryWorkflowBudgetStore,
  StorageError,
  dimensionExceededBy,
  workflowBudgetDenialCode,
  type StoredWorkflowRunBudget,
} from "../src/index.js";

describe("dimensionExceededBy — first-breached precedence (§1.5.3)", () => {
  const base: StoredWorkflowRunBudget = {
    id: "w:1:r",
    workflowId: "w",
    workflowVersion: 1,
    runId: "r",
    tenantId: "t1",
    costBudgetCredits: 100,
    tokenBudget: 100,
    toolCallBudget: 5,
    wallClockDeadlineUnix: 1000,
    spentCredits: 0,
    spentTokens: 0,
    spentToolCalls: 0,
    status: "active",
    createdAtUnix: 0,
    updatedAtUnix: 0,
  };

  test("wall-clock is checked first, then cost, tokens, tool_calls", () => {
    expect(dimensionExceededBy(base, 200, 200, 10, 2000)).toBe("wall_clock");
    expect(dimensionExceededBy(base, 200, 200, 10, 0)).toBe("cost");
    expect(dimensionExceededBy(base, 0, 200, 10, 0)).toBe("tokens");
    expect(dimensionExceededBy(base, 0, 0, 10, 0)).toBe("tool_calls");
    expect(dimensionExceededBy(base, 1, 1, 1, 0)).toBeUndefined();
  });

  test("an unbounded (undefined) dimension never breaches", () => {
    const unbounded = { ...base, costBudgetCredits: undefined };
    expect(dimensionExceededBy(unbounded, 1_000_000, 0, 0, 0)).toBeUndefined();
  });

  test("denial code is the dimension-qualified family", () => {
    expect(workflowBudgetDenialCode("cost")).toBe("workflow_budget_exceeded:cost");
  });
});

describe("MemoryWorkflowBudgetStore", () => {
  let store: MemoryWorkflowBudgetStore;
  beforeEach(() => {
    store = new MemoryWorkflowBudgetStore();
  });

  test("open is idempotent — caps are fixed at first step", () => {
    const first = store.openWorkflowRunBudget("w", 1, "r", "t1", { toolCallBudget: 3 }, 0);
    const again = store.openWorkflowRunBudget("w", 1, "r", "t1", { toolCallBudget: 999 }, 5);
    expect(again.toolCallBudget).toBe(3);
    expect(again).toEqual(first);
  });

  test("re-opening for another tenant is a conflict", () => {
    store.openWorkflowRunBudget("w", 1, "r", "t1", {}, 0);
    expect(() => store.openWorkflowRunBudget("w", 1, "r", "t2", {}, 0)).toThrowError(StorageError);
  });

  test("no-overspend: N debits against a tool-call budget of K let exactly K through", () => {
    const b = store.openWorkflowRunBudget("w", 1, "r", "t1", { toolCallBudget: 3 }, 0);
    let applied = 0;
    for (let i = 0; i < 5; i++) {
      const d = store.debitWorkflowRunBudget(b.id, 0, 0, 1, 0);
      if (d.kind === "applied") applied++;
    }
    expect(applied).toBe(3);
    expect(store.getWorkflowRunBudget(b.id)?.status).toBe("exhausted");
  });

  test("a breaching debit applies NO spend and flips to exhausted (fail-closed)", () => {
    const b = store.openWorkflowRunBudget("w", 1, "r", "t1", { costBudgetCredits: 10 }, 0);
    const d = store.debitWorkflowRunBudget(b.id, 50, 0, 0, 0);
    expect(d.kind).toBe("exceeded");
    if (d.kind === "exceeded") {
      expect(d.dimension).toBe("cost");
      expect(d.budget.spentCredits).toBe(0);
      expect(d.budget.status).toBe("exhausted");
    }
  });

  test("an exhausted run rejects every further debit until top-up reactivates it", () => {
    const b = store.openWorkflowRunBudget("w", 1, "r", "t1", { costBudgetCredits: 10 }, 0);
    store.debitWorkflowRunBudget(b.id, 50, 0, 0, 0); // exhaust
    expect(store.debitWorkflowRunBudget(b.id, 1, 0, 0, 0).kind).toBe("exceeded");
    const topped = store.topupWorkflowRunBudget(b.id, 100, 0, 0, undefined, 1);
    expect(topped.status).toBe("active");
    expect(topped.costBudgetCredits).toBe(110);
    expect(store.debitWorkflowRunBudget(b.id, 5, 0, 0, 1).kind).toBe("applied");
  });

  test("a negative debit amount is a conflict", () => {
    const b = store.openWorkflowRunBudget("w", 1, "r", "t1", {}, 0);
    expect(() => store.debitWorkflowRunBudget(b.id, -1, 0, 0, 0)).toThrowError(StorageError);
  });

  test("debiting an unknown run is not_found", () => {
    expect(() => store.debitWorkflowRunBudget("missing", 1, 0, 0, 0)).toThrowError(StorageError);
  });
});
