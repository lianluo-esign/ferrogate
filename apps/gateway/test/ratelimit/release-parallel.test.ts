import { Hono } from "hono";
import { expect, it } from "vitest";
import type { GatewayEnv } from "../../src/ports.js";
import { InMemoryRateLimiter } from "../../src/ratelimit/memory.js";
import { rateLimit } from "../../src/ratelimit/middleware.js";
import { NO_POLICY_RULES } from "../../src/ratelimit/policy.js";
import { quotaPolicySourceFromEnv } from "../../src/ratelimit/quota.js";
import { NO_TOKEN_BUDGET } from "../../src/ratelimit/token-budget.js";
import { NO_WORKFLOW_BUDGETS } from "../../src/ratelimit/workflow.js";

it("starts every independent release before waiting, but waits for all before returning", async () => {
  const started: string[] = [];
  const complete: (() => void)[] = [];
  let allStarted!: () => void;
  const barrier = new Promise<void>((resolve) => {
    allStarted = resolve;
  });
  const release = (name: string) => async () => {
    started.push(name);
    const pending = new Promise<void>((resolve) => {
      complete.push(resolve);
    });
    if (started.length === 2) allStarted();
    await pending;
  };
  const limiter = new InMemoryRateLimiter();
  limiter.reserveMonthlyBudget = async () => ({
    outcome: "reserved",
    reservation: { amount: 1, release: release("budget") },
  });
  const app = new Hono<GatewayEnv>();
  app.use("*", async (c, next) => {
    c.set("auth", {
      subject: "key",
      tenancy: { tenantId: "tenant" },
      scopes: [],
      platformOperator: false,
      source: "static_config",
    });
    await next();
  });
  app.use(
    "*",
    rateLimit({
      limiter,
      quotas: quotaPolicySourceFromEnv({
        GATEWAY_QUOTA_POLICIES: JSON.stringify([
          {
            id: "q",
            scope_type: "tenant",
            scope_id: "tenant",
            monthly_budget_usd: 100,
            enabled: true,
          },
        ]),
      }),
      spend: {
        committedSpendUsd: async () => ({ ok: true, committedSpendUsd: 0 }),
        walletBalanceCredits: async () => ({ ok: true, availableCredits: null }),
      },
      wallet: {
        reserve: async () => ({
          kind: "admitted",
          hold: { id: "hold", amountCredits: 1, release: release("wallet") },
        }),
      },
      tokenBudget: NO_TOKEN_BUDGET,
      workflowBudgets: NO_WORKFLOW_BUDGETS,
      policies: NO_POLICY_RULES,
    }),
  );
  app.get("/", (c) => c.text("ok"));
  let returned = false;
  const response = Promise.resolve(app.request("/", undefined, {})).then((value) => {
    returned = true;
    return value;
  });
  await barrier;
  expect(started).toEqual(["budget", "wallet"]);
  expect(returned).toBe(false);
  complete[0]?.();
  await Promise.resolve();
  expect(returned).toBe(false);
  complete[1]?.();
  expect((await response).status).toBe(200);
});
