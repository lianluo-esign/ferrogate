import { describe, expect, test } from "vitest";
import {
  type StoredWorkflowRunBudget,
  WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE,
  WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE,
  WORKFLOW_RUN_BUDGET_ACTIVE,
  WORKFLOW_RUN_BUDGET_EXHAUSTED,
  type WorkflowBudgetCaps,
  deadlineUnix,
  evaluateNodeDispatch,
  isUnbounded,
  preflightWorkflowBudget,
  resolveWorkflowBudgetEnvelope,
} from "../src/index.js";

function caps(cost?: number, tokens?: number, tools?: number, wall?: number): WorkflowBudgetCaps {
  return {
    costBudgetCredits: cost,
    tokenBudget: tokens,
    toolCallBudget: tools,
    wallClockMillis: wall,
  };
}

function budget(c: WorkflowBudgetCaps, spent: [number, number, number]): StoredWorkflowRunBudget {
  return {
    id: "wf:1:run-1",
    workflowId: "wf",
    workflowVersion: 1,
    runId: "run-1",
    tenantId: "tenant-1",
    costBudgetCredits: c.costBudgetCredits,
    tokenBudget: c.tokenBudget,
    toolCallBudget: c.toolCallBudget,
    wallClockDeadlineUnix: deadlineUnix(c, 0),
    spentCredits: spent[0],
    spentTokens: spent[1],
    spentToolCalls: spent[2],
    status: WORKFLOW_RUN_BUDGET_ACTIVE,
    createdAtUnix: 0,
    updatedAtUnix: 0,
  };
}

describe("resolveWorkflowBudgetEnvelope", () => {
  test("takes the min and a node can only tighten", () => {
    const envelope = resolveWorkflowBudgetEnvelope(
      caps(1_000, 10_000, 20, 60_000),
      caps(250, 999_999, 5, undefined),
    );
    expect(envelope.costBudgetCredits).toBe(250);
    expect(envelope.tokenBudget).toBe(10_000);
    expect(envelope.toolCallBudget).toBe(5);
    expect(envelope.wallClockMillis).toBe(60_000);
  });

  test("treats undefined as unbounded", () => {
    const e = resolveWorkflowBudgetEnvelope(caps(), caps(7));
    expect(e.costBudgetCredits).toBe(7);
    expect(e.tokenBudget).toBeUndefined();
    expect(isUnbounded(resolveWorkflowBudgetEnvelope(caps(), caps()))).toBe(true);
  });
});

describe("deadlineUnix", () => {
  test("rounds millis up to whole seconds", () => {
    expect(deadlineUnix(caps(undefined, undefined, undefined, 1), 100)).toBe(101);
    expect(deadlineUnix(caps(undefined, undefined, undefined, 1_000), 100)).toBe(101);
    expect(deadlineUnix(caps(undefined, undefined, undefined, 1_001), 100)).toBe(102);
    expect(deadlineUnix(caps(), 100)).toBeUndefined();
  });
});

describe("preflightWorkflowBudget", () => {
  test("allows a step that fits every dimension", () => {
    const b = budget(caps(100, 1_000, 10), [10, 100, 1]);
    expect(preflightWorkflowBudget(b, 5, 50, 1, 0)).toEqual({ ok: true });
  });

  test("denies on the first breached dimension with a distinct code", () => {
    const costB = budget(caps(100), [95, 0, 0]);
    const costDenial = preflightWorkflowBudget(costB, 10, 0, 0, 0);
    expect(costDenial.ok).toBe(false);
    if (!costDenial.ok) {
      expect(costDenial.denial.dimension).toBe("cost");
      expect(costDenial.denial.code).toBe("workflow_budget_exceeded:cost");
    }

    const toolB = budget(caps(undefined, undefined, 3), [0, 0, 3]);
    const toolDenial = preflightWorkflowBudget(toolB, 0, 0, 1, 0);
    expect(toolDenial.ok).toBe(false);
    if (!toolDenial.ok) {
      expect(toolDenial.denial.dimension).toBe("tool_calls");
      expect(toolDenial.denial.code).toBe("workflow_budget_exceeded:tool_calls");
    }
  });

  test("denies at or after the wall-clock deadline", () => {
    const b = budget(caps(undefined, undefined, undefined, 5_000), [0, 0, 0]);
    expect(preflightWorkflowBudget(b, 0, 0, 0, 4)).toEqual({ ok: true });
    const denial = preflightWorkflowBudget(b, 0, 0, 0, 5);
    expect(denial.ok).toBe(false);
    if (!denial.ok) {
      expect(denial.denial.dimension).toBe("wall_clock");
      expect(denial.denial.code).toBe("workflow_budget_exceeded:wall_clock");
    }
  });

  test("an exhausted run denies every step, even a zero-spend one", () => {
    const b = budget(caps(100), [100, 0, 0]);
    b.status = WORKFLOW_RUN_BUDGET_EXHAUSTED;
    expect(preflightWorkflowBudget(b, 0, 0, 0, 0).ok).toBe(false);
  });
});

describe("evaluateNodeDispatch", () => {
  test("model allowlist fails closed at dispatch", () => {
    const node = { nodeId: "n1", model: "fast-chat", providers: [] as string[] };
    expect(evaluateNodeDispatch(node, "fast-chat", undefined)).toEqual({ ok: true });
    const denial = evaluateNodeDispatch(node, "smart-chat", undefined);
    expect(denial.ok).toBe(false);
    if (!denial.ok) {
      expect(denial.denial.code).toBe(WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE);
      expect(denial.denial.message).toContain("fast-chat");
      expect(denial.denial.message).toContain("smart-chat");
    }
  });

  test("provider allowlist fails closed; an unrestricted node allows any dispatch", () => {
    const node = { nodeId: "n2", providers: ["openai", "anthropic"] };
    expect(evaluateNodeDispatch(node, undefined, "anthropic")).toEqual({ ok: true });
    const denial = evaluateNodeDispatch(node, undefined, "cohere");
    expect(denial.ok).toBe(false);
    if (!denial.ok) expect(denial.denial.code).toBe(WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE);

    const open = { nodeId: "n3", providers: [] as string[] };
    expect(evaluateNodeDispatch(open, "anything", "anywhere")).toEqual({ ok: true });
  });

  test("edge: an undefined requested facet is not gated", () => {
    const node = { nodeId: "n4", model: "fast-chat", providers: ["openai"] };
    // No model and no provider requested (tool-only node) ⇒ allowed.
    expect(evaluateNodeDispatch(node, undefined, undefined)).toEqual({ ok: true });
  });
});
