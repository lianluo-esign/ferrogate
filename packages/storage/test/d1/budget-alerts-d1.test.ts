/**
 * `D1BudgetAlertStore` against the REAL control database in `workerd`.
 *
 * The invariant under test is the one a Worker cannot hold in memory: a budget
 * threshold fires its webhook EXACTLY ONCE per `(scope, period, threshold)`,
 * however many isolates cross it. Every assertion below is about the durable
 * claim, so a fake store could not satisfy them — the arbiter is SQLite's own
 * conflict handling, evaluated inside the INSERT's implicit transaction.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  D1BudgetAlertStore,
  MemoryBudgetAlertStore,
  budgetAlertNotificationId,
} from "../../src/index.js";

const PERIOD = "2026-07";
const SCOPE = "org-1";

function claim(thresholdPct: number, notifiedAtUnix = 1_700_000_000) {
  return {
    scopeType: "tenant" as const,
    scopeId: SCOPE,
    periodMonth: PERIOD,
    thresholdPct,
    notifiedAtUnix,
  };
}

let store: D1BudgetAlertStore;

beforeEach(async () => {
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
  await env.CONTROL_DB.prepare("DELETE FROM budget_alert_notifications").run();
  store = new D1BudgetAlertStore(env.CONTROL_DB);
});

describe("D1BudgetAlertStore — the once-per-period claim", () => {
  it("grants the first caller and refuses every repeat of the same threshold", async () => {
    expect(await store.claimBudgetAlertNotification(claim(80))).toBe(true);
    expect(await store.claimBudgetAlertNotification(claim(80))).toBe(false);
    expect(await store.claimBudgetAlertNotification(claim(80))).toBe(false);
  });

  it("refuses a repeat even when the caller reports a different timestamp", async () => {
    expect(await store.claimBudgetAlertNotification(claim(90, 1_700_000_000))).toBe(true);
    // A later request in the same period is a DUPLICATE, not a new event. If
    // the id or the conflict target ever stopped covering the four natural-key
    // columns, this would flip to `true` and the tenant would be re-notified.
    expect(await store.claimBudgetAlertNotification(claim(90, 1_799_999_999))).toBe(false);
  });

  it("does not let one threshold suppress another in the same period", async () => {
    expect(await store.claimBudgetAlertNotification(claim(80))).toBe(true);
    expect(await store.claimBudgetAlertNotification(claim(90))).toBe(true);
    expect(await store.claimBudgetAlertNotification(claim(100))).toBe(true);
  });

  it("does not let one period suppress the next", async () => {
    expect(await store.claimBudgetAlertNotification(claim(80))).toBe(true);
    expect(await store.claimBudgetAlertNotification({ ...claim(80), periodMonth: "2026-08" })).toBe(
      true,
    );
  });

  it("does not let one tenant suppress another", async () => {
    expect(await store.claimBudgetAlertNotification(claim(80))).toBe(true);
    expect(await store.claimBudgetAlertNotification({ ...claim(80), scopeId: "org-2" })).toBe(true);
  });

  it("gives exactly ONE winner when concurrent callers race the same threshold", async () => {
    // Eight overlapping claims for one threshold — the shape of eight isolates
    // crossing 80% within the same second.
    const outcomes = await Promise.all(
      Array.from({ length: 8 }, () => store.claimBudgetAlertNotification(claim(80))),
    );
    expect(outcomes.filter((won) => won)).toHaveLength(1);
    const rows = await store.listBudgetAlertNotifications("tenant", SCOPE, PERIOD);
    expect(rows).toHaveLength(1);
  });

  it("persists the claim so a LATER isolate reads it as already notified", async () => {
    const id = budgetAlertNotificationId("tenant", SCOPE, PERIOD, 100);
    expect(await store.budgetAlertAlreadyNotified(id)).toBe(false);
    await store.claimBudgetAlertNotification(claim(100));
    // A brand-new store instance models the next isolate: the in-memory ledger
    // answers `false` here forever, which is the whole reason this class exists.
    expect(await new D1BudgetAlertStore(env.CONTROL_DB).budgetAlertAlreadyNotified(id)).toBe(true);
  });

  it("lists a period's notifications ascending by threshold, like the memory twin", async () => {
    for (const pct of [100, 80, 90]) await store.claimBudgetAlertNotification(claim(pct));

    const durable = await store.listBudgetAlertNotifications("tenant", SCOPE, PERIOD);
    expect(durable.map((row) => row.thresholdPct)).toEqual([80, 90, 100]);

    // The in-memory store is the executable specification; the two backends
    // must agree on the observable outcome or one of them is wrong.
    const memory = new MemoryBudgetAlertStore();
    for (const pct of [100, 80, 90]) {
      memory.recordBudgetAlertNotification({
        id: budgetAlertNotificationId("tenant", SCOPE, PERIOD, pct),
        scopeType: "tenant",
        scopeId: SCOPE,
        periodMonth: PERIOD,
        thresholdPct: pct,
        notifiedAtUnix: 1_700_000_000,
      });
    }
    expect(durable).toEqual(memory.listBudgetAlertNotifications("tenant", SCOPE, PERIOD));
  });

  it("scopes the list to the asked-for period and scope", async () => {
    await store.claimBudgetAlertNotification(claim(80));
    await store.claimBudgetAlertNotification({ ...claim(90), periodMonth: "2026-08" });
    await store.claimBudgetAlertNotification({ ...claim(100), scopeId: "org-2" });

    const rows = await store.listBudgetAlertNotifications("tenant", SCOPE, PERIOD);
    expect(rows.map((row) => row.thresholdPct)).toEqual([80]);
  });
});
