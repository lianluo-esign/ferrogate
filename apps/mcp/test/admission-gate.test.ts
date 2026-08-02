/**
 * The arms of the admission gate a live, healthy binding cannot express — the
 * FAIL-CLOSED postures, the counter-key namespacing attack, and the ordering
 * that makes the ladder a control rather than a list.
 *
 * `test/admission.test.ts` is the mount proof: it drives the REAL Worker over
 * `SELF` with real D1 rows. This file is its complement. Every case here needs
 * a dependency that FAILS, and a healthy `env.DB` never does.
 */
import { describe, expect, it } from "vitest";

import {
  ADMIT_ALL,
  type AdmissionIdentity,
  type CounterWindow,
  CounterKeyNamespaceError,
  InMemoryMcpRateLimiter,
  type McpRateLimiter,
  McpAdmissionGate,
  type MonthlySpendReading,
  NO_SPEND_SOURCE,
  type QuotaPolicySnapshot,
  type QuotaPolicySource,
  type RateLimitOutcome,
  type SpendSource,
  type WalletBalanceReading,
  type WalletReserveOutcome,
  assertNamespacedCounterKey,
  d1QuotaPolicySource,
  perKeyCounterKey,
  requestWindows,
} from "../src/admission/index.js";

const IDENTITY: AdmissionIdentity = {
  apiKeyId: "key-1",
  organizationId: "tenant-1",
  projectId: "proj-1",
  workspaceId: "ws-1",
};

/** A policy source that answers one fixed snapshot. */
function quotas(snapshot: QuotaPolicySnapshot): QuotaPolicySource {
  return { policiesFor: async (): Promise<QuotaPolicySnapshot> => snapshot };
}

const NO_POLICIES = quotas({ ok: true, lookup: () => undefined });

/** A limiter that answers one fixed outcome and records what it was asked. */
function limiter(outcome: RateLimitOutcome = { allowed: true }): McpRateLimiter & {
  charged: CounterWindow[][];
} {
  const charged: CounterWindow[][] = [];
  return {
    charged,
    async consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome> {
      charged.push([...windows]);
      return outcome;
    },
  };
}

function spend(overrides: Partial<SpendSource> = {}): SpendSource {
  return { ...NO_SPEND_SOURCE, ...overrides };
}

function spendFor(source: SpendSource) {
  return async (): Promise<{ ok: true; source: SpendSource }> => ({ ok: true, source });
}

// ---------------------------------------------------------------------------

describe("every lookup failure is 503 — an outage never admits and never 429s", () => {
  it("a quota-chain failure is 503 quota_resolution_unavailable", async () => {
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: quotas({ ok: false, detail: "d1 down" }),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 503, code: "quota_resolution_unavailable" });
    expect(outcome.error.message).toContain("d1 down");
  });

  it("a monthly-spend read failure is 503, NOT a 429 — the outage proved nothing", async () => {
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      // A budget must exist or the spend leg is never reached.
      quotas: quotas({
        ok: true,
        lookup: (kind) =>
          kind === "tenant"
            ? {
                id: "p",
                scopeType: "tenant",
                scopeId: "tenant-1",
                modelAllowlist: [],
                monthlyBudgetUsd: 10,
                alertThresholdPcts: [],
                enabled: true,
                createdAtUnix: 0,
                updatedAtUnix: 0,
              }
            : undefined,
      }),
      spendFor: spendFor(
        spend({
          async committedSpendUsd(): Promise<MonthlySpendReading> {
            return { ok: false, detail: "rollup read failed" };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.status).toBe(503);
    expect(outcome.error.code).toBe("quota_resolution_unavailable");
  });

  it("a wallet-balance read failure is 503", async () => {
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: NO_POLICIES,
      spendFor: spendFor(
        spend({
          async walletBalanceCredits(): Promise<WalletBalanceReading> {
            return { ok: false, detail: "wallet read failed" };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 503, code: "quota_resolution_unavailable" });
  });

  it("a wallet RESERVE failure is 503, and is never reported as insufficient", async () => {
    // The split matters: `unavailable` (503) says the storage is broken;
    // `insufficient` (429) says the caller is overdrawn. Collapsing them would
    // tell an operator their tenants are out of credit during an outage.
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: NO_POLICIES,
      spendFor: spendFor(
        spend({
          async walletBalanceCredits(): Promise<WalletBalanceReading> {
            return { ok: true, availableCredits: 100 };
          },
          async reserveWallet(): Promise<WalletReserveOutcome> {
            return { kind: "unavailable", detail: "batch rejected" };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.status).toBe(503);
    expect(outcome.error.code).toBe("quota_resolution_unavailable");
  });

  it("a spend-store routing failure is 503", async () => {
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: NO_POLICIES,
      spendFor: async () => ({ ok: false, detail: "binding missing" }),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.status).toBe(503);
  });

  it("a COUNTER-backend failure is 503 governance_counter_unavailable, not 429", async () => {
    const gate = new McpAdmissionGate({
      limiter: limiter({ allowed: "unavailable", detail: "do dispatch failed" }),
      quotas: NO_POLICIES,
      spendFor: spendFor(NO_SPEND_SOURCE),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 503, code: "governance_counter_unavailable" });
  });
});

describe("the wallet no-oversell guard is the gate's decision, not advice", () => {
  it("an INSUFFICIENT atomic reserve is 429 wallet_balance_exhausted", async () => {
    // The balance READ says there is money; only the in-statement guard knows
    // about the concurrent holds. If the gate trusted the read, N parallel
    // requests against a balance affording K would all be admitted.
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: NO_POLICIES,
      spendFor: spendFor(
        spend({
          async walletBalanceCredits(): Promise<WalletBalanceReading> {
            return { ok: true, availableCredits: 500 };
          },
          async reserveWallet(): Promise<WalletReserveOutcome> {
            return { kind: "insufficient" };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 429, code: "wallet_balance_exhausted" });
  });

  it("refuses at the BALANCE READ when available credits reach zero, before the reserve", async () => {
    // The two wallet legs are independent and both must hold. Step 4 bounds
    // CUMULATIVE spend (`available <= 0`, refusing AT zero exactly as Rust
    // does); step 4b bounds CONCURRENT overdraft. This test neutralizes 4b — the
    // reserve is rigged to admit — so a pass can only come from the read.
    let reserved = 0;
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: NO_POLICIES,
      spendFor: spendFor(
        spend({
          async walletBalanceCredits(): Promise<WalletBalanceReading> {
            return { ok: true, availableCredits: 0 };
          },
          async reserveWallet(): Promise<WalletReserveOutcome> {
            reserved += 1;
            return {
              kind: "admitted",
              hold: { id: "h1", amountCredits: 1, release: async () => undefined },
            };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 429, code: "wallet_balance_exhausted" });
    // ...and it refused BEFORE taking a hold it would then have to unwind.
    expect(reserved).toBe(0);
  });

  it("hands the admitted hold back so the caller can release it", async () => {
    let released = 0;
    const gate = new McpAdmissionGate({
      limiter: limiter(),
      quotas: NO_POLICIES,
      spendFor: spendFor(
        spend({
          async walletBalanceCredits(): Promise<WalletBalanceReading> {
            return { ok: true, availableCredits: 5 };
          },
          async reserveWallet(): Promise<WalletReserveOutcome> {
            return {
              kind: "admitted",
              hold: {
                id: "h1",
                amountCredits: 1,
                release: async () => {
                  released += 1;
                },
              },
            };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.holds).toHaveLength(1);
    expect(released).toBe(0);
  });

  it("RELEASES the hold when a later step refuses — a rate-limited client cannot park the wallet", async () => {
    let released = 0;
    const gate = new McpAdmissionGate({
      // RPM denies AFTER the wallet hold was taken.
      limiter: limiter({
        allowed: false,
        counterKey: "key:key-1",
        limit: 1,
        retryAfterSeconds: 30,
      }),
      quotas: NO_POLICIES,
      spendFor: spendFor(
        spend({
          async walletBalanceCredits(): Promise<WalletBalanceReading> {
            return { ok: true, availableCredits: 5 };
          },
          async reserveWallet(): Promise<WalletReserveOutcome> {
            return {
              kind: "admitted",
              hold: {
                id: "h1",
                amountCredits: 1,
                release: async () => {
                  released += 1;
                },
              },
            };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.code).toBe("rate_limit_exceeded");
    expect(released).toBe(1);
  });
});

describe("the ladder runs in Rust's order, and the order is the control", () => {
  it("a HARD DENY never charges the RPM window", async () => {
    // Rust checks `denied_by` before `request_windows()`. If it did not, a
    // caller that is refused anyway would burn the budget of the requests that
    // are still allowed.
    const counter = limiter();
    const gate = new McpAdmissionGate({
      limiter: counter,
      quotas: quotas({
        ok: true,
        lookup: (kind) =>
          kind === "tenant"
            ? {
                id: "p",
                scopeType: "tenant",
                scopeId: "tenant-1",
                modelAllowlist: [],
                rpmLimit: 100,
                alertThresholdPcts: [],
                enabled: false,
                createdAtUnix: 0,
                updatedAtUnix: 0,
              }
            : undefined,
      }),
      spendFor: spendFor(NO_SPEND_SOURCE),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 403, code: "quota_scope_disabled" });
    expect(counter.charged).toHaveLength(0);
  });

  it("an over-BUDGET refusal never charges the RPM window either", async () => {
    const counter = limiter();
    const gate = new McpAdmissionGate({
      limiter: counter,
      quotas: quotas({
        ok: true,
        lookup: (kind) =>
          kind === "tenant"
            ? {
                id: "p",
                scopeType: "tenant",
                scopeId: "tenant-1",
                modelAllowlist: [],
                rpmLimit: 100,
                monthlyBudgetUsd: 10,
                alertThresholdPcts: [],
                enabled: true,
                createdAtUnix: 0,
                updatedAtUnix: 0,
              }
            : undefined,
      }),
      spendFor: spendFor(
        spend({
          async committedSpendUsd(): Promise<MonthlySpendReading> {
            return { ok: true, committedSpendUsd: 10 };
          },
        }),
      ),
    });
    const outcome = await gate.admit(IDENTITY, "req-1");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatchObject({ status: 429, code: "monthly_budget_exceeded" });
    expect(counter.charged).toHaveLength(0);
  });
});

describe("counter keys are scope-namespaced, which is a tenant-isolation boundary", () => {
  it("a key id that LOOKS like a tenant scope cannot collide with that tenant's window", async () => {
    // The attack: a tenant mints a virtual key whose id is literally
    // `tenant:victim`, hoping its per-key window becomes the victim tenant's
    // aggregate window and lets it deny the victim service.
    const hostileKeyId = "tenant:victim";
    expect(perKeyCounterKey(hostileKeyId)).toBe("key:tenant:victim");
    expect(perKeyCounterKey(hostileKeyId)).not.toBe("tenant:victim");

    // ...and the two really are different budgets under a live limiter.
    const shared = new InMemoryMcpRateLimiter(() => 1_000);
    const attacker: CounterWindow = { counterKey: perKeyCounterKey(hostileKeyId), limit: 1 };
    const victim: CounterWindow = { counterKey: "tenant:victim", limit: 1 };
    expect((await shared.consumeRequest([attacker])).allowed).toBe(true);
    expect((await shared.consumeRequest([attacker])).allowed).toBe(false);
    // The victim's own window is untouched.
    expect((await shared.consumeRequest([victim])).allowed).toBe(true);
  });

  it("refuses to address a counter with an un-namespaced key", () => {
    expect(() => assertNamespacedCounterKey("key-1")).toThrow(CounterKeyNamespaceError);
    expect(() => assertNamespacedCounterKey("bogus:x")).toThrow(CounterKeyNamespaceError);
    expect(() => assertNamespacedCounterKey("key:")).toThrow(CounterKeyNamespaceError);
    expect(() => assertNamespacedCounterKey("key:k1")).not.toThrow();
  });

  it("collapses two caps on the same key to the tighter one instead of charging twice", () => {
    // Rust's `add` closure: `existing.1 = existing.1.min(limit)`.
    const windows = requestWindows("k1", { rpmLimit: 10 }, 3);
    expect(windows).toEqual([{ counterKey: "key:k1", limit: 3 }]);
  });

  it("charges a TENANT-scoped cap at the tenant window, shared by every key beneath it", () => {
    const windows = requestWindows("k1", {
      rpmLimit: 10,
      rpmLimitScope: { kind: "tenant", id: "t1", counterKey: () => "tenant:t1" } as never,
    });
    expect(windows).toEqual([{ counterKey: "tenant:t1", limit: 10 }]);
  });
});

describe("a control database with no quota tables is UNPROVISIONED, not an outage", () => {
  /** A D1 stub whose `sqlite_master` probe reports `tables` and whose real reads throw. */
  function stubDb(tables: readonly string[]): D1Database {
    return {
      prepare(sql: string) {
        const statement = {
          bind: () => statement,
          all: async () => {
            if (sql.includes("sqlite_master")) return { results: tables.map((name) => ({ name })) };
            throw new Error("D1_ERROR: network");
          },
          first: async () => {
            throw new Error("D1_ERROR: network");
          },
        };
        return statement;
      },
      batch: async () => {
        throw new Error("D1_ERROR: network");
      },
    } as unknown as D1Database;
  }

  it("admits when `quota_policies` does not exist — no table, no policy to enforce", async () => {
    const snapshot = await d1QuotaPolicySource(stubDb([])).policiesFor({
      apiKeyId: "k1",
      chain: { tenantId: "t1" },
    });
    expect(snapshot.ok).toBe(true);
    if (!snapshot.ok) return;
    expect(snapshot.lookup("tenant", "t1")).toBeUndefined();
  });

  it("503s when the table EXISTS and the read fails — that is an outage, not an absence", async () => {
    // The distinction is the whole point: "no table" cannot drop a limit that
    // was never configurable, but "table present, read broken" absolutely can.
    const snapshot = await d1QuotaPolicySource(stubDb(["quota_policies"])).policiesFor({
      apiKeyId: "k1",
      chain: { tenantId: "t1" },
    });
    expect(snapshot.ok).toBe(false);
  });
});

describe("the no-op gate is honest about being a no-op", () => {
  it("ADMIT_ALL takes no holds", async () => {
    const outcome = await ADMIT_ALL.admit(IDENTITY, "req-1");
    expect(outcome).toEqual({ ok: true, holds: [] });
  });
});
