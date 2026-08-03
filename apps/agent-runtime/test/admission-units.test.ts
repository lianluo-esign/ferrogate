/**
 * FAIL CLOSED, and the counter-key isolation boundary.
 *
 * `admission.test.ts` and `durable/admission.spec.ts` drive the ladder through
 * the real Worker, which is the right way to prove a refusal. Neither can prove
 * what happens when a BACKEND FAILS: a D1 outage cannot be induced through
 * `SELF.fetch`, and a counter RPC cannot be made to throw from the outside.
 *
 * That direction is the one a limiter gets wrong catastrophically. Rust answers
 * an `Err` from any of these lookups with a **503**, never a 429 and never an
 * admission — a storage outage has not proven the caller is over budget, and a
 * limiter that admitted everyone during an outage would be a free-traffic hole
 * rather than graceful degradation. So it is asserted here, against the ports
 * directly.
 *
 * The second half of the file is the counter-key namespacing: which string may
 * become a counter name is an isolation boundary (a colliding name lets one
 * tenant drain another's window), and `@ferrogate/policy`'s
 * `QuotaScopeSelector.counterKey` is the ONE derivation. These assertions pin
 * that this app calls it rather than re-deriving it.
 */
import { describe, expect, it } from "vitest";
import {
  type AdmissionBindings,
  CounterKeyNamespaceError,
  DurableObjectRequestCounter,
  InMemoryRequestCounter,
  type QuotaPolicySource,
  type RateLimiterNamespace,
  type RequestCounter,
  type SpendSource,
  type WalletAdmission,
  admissionPort,
  assertNamespacedCounterKey,
  counterFromEnv,
  d1QuotaPolicySource,
  d1SpendSource,
  perKeyCounterKey,
  requestWindows,
} from "../src/admission/index.js";
import { HttpError } from "../src/middleware/errors.js";
import type { AuthContext } from "../src/ports.js";

const AUTH: AuthContext = {
  subject: "key-unit",
  tenancy: { tenantId: "tenant-unit", workspaceId: "ws-unit", projectId: "proj-unit" },
  scopes: ["agents.invoke"],
  platformOperator: false,
};

/** A quota source that reports a policy with the given fields at tenant scope. */
function quotaSource(policy: Record<string, unknown> | null): QuotaPolicySource {
  return {
    async policiesFor() {
      return {
        ok: true as const,
        lookup: (kind: string, id: string) =>
          kind === "tenant" && id === "tenant-unit" && policy !== null
            ? ({
                id: "p1",
                scopeType: "tenant",
                scopeId: "tenant-unit",
                modelAllowlist: [],
                alertThresholdPcts: [],
                enabled: true,
                createdAtUnix: 0,
                updatedAtUnix: 0,
                ...policy,
                // biome-ignore lint/suspicious/noExplicitAny: narrow test double
              } as any)
            : undefined,
      };
    },
  };
}

const OPEN_SPEND: SpendSource = {
  async committedSpendUsd() {
    return { ok: true, committedSpendUsd: 0 };
  },
  async walletBalanceCredits() {
    return { ok: true, availableCredits: null };
  },
};

const OPEN_WALLET: WalletAdmission = {
  async reserve() {
    return { kind: "not_applicable" };
  },
};

const OPEN_COUNTER: RequestCounter = {
  async consumeRequest() {
    return { allowed: true };
  },
};

const NO_BINDINGS: AdmissionBindings = {};

/** Run `admit` and return the thrown {@link HttpError}, or fail loudly. */
async function refusalOf(port: { admit: (r: never) => Promise<unknown> }): Promise<HttpError> {
  try {
    await port.admit({ auth: AUTH, requestId: "req-1" } as never);
  } catch (error) {
    if (error instanceof HttpError) return error;
    throw error;
  }
  throw new Error("admission ADMITTED the request; expected a refusal");
}

describe("#679 a nested budget binds at EVERY level, not only the tightest number", () => {
  /** A source with a budget at more than one rung of the chain. */
  function nestedBudgets(): QuotaPolicySource {
    const rung = (scopeType: string, scopeId: string, monthlyBudgetUsd: number) => ({
      id: `${scopeType}:${scopeId}`,
      scopeType,
      scopeId,
      modelAllowlist: [],
      alertThresholdPcts: [],
      enabled: true,
      createdAtUnix: 0,
      updatedAtUnix: 0,
      monthlyBudgetUsd,
    });
    return {
      async policiesFor() {
        return {
          ok: true as const,
          lookup: (kind: string) =>
            // biome-ignore lint/suspicious/noExplicitAny: narrow test double
            (kind === "project"
              ? rung("project", "proj-unit", 5_000)
              : kind === "key"
                ? rung("key", "key-unit", 100)
                : undefined) as any,
        };
      },
    };
  }

  it("refuses when the PROJECT is at its cap and this key is not", async () => {
    // The chain mins to $100 at the key scope, whose rollup is empty. Enforcing
    // only that winner admits a request against a project that has already
    // spent its entire $5,000 — its sibling keys got there first.
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: nestedBudgets(),
      spend: {
        async committedSpendUsd(scopeKind: string) {
          return { ok: true, committedSpendUsd: scopeKind === "project" ? 5_000 : 0 };
        },
        async walletBalanceCredits() {
          return { ok: true, availableCredits: null };
        },
      },
      wallet: OPEN_WALLET,
      counter: OPEN_COUNTER,
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(429);
    expect(error.code).toBe("monthly_budget_exceeded");
  });

  it("admits when every rung of the ladder is under its own cap", async () => {
    // The negative control: same policies, same shapes, only the spend differs.
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: nestedBudgets(),
      spend: {
        async committedSpendUsd(scopeKind: string) {
          return { ok: true, committedSpendUsd: scopeKind === "project" ? 4_000 : 10 };
        },
        async walletBalanceCredits() {
          return { ok: true, availableCredits: null };
        },
      },
      wallet: OPEN_WALLET,
      counter: OPEN_COUNTER,
    });
    await expect(
      (port as { admit: (r: never) => Promise<unknown> }).admit({
        auth: AUTH,
        requestId: "req-1",
      } as never),
    ).resolves.toBeDefined();
  });
});

describe("every lookup failure is a 503, never a 429 and never an admission", () => {
  it("a quota-policy lookup failure → 503 quota_resolution_unavailable", async () => {
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: {
        async policiesFor() {
          return { ok: false, detail: "control db down" };
        },
      },
      spend: OPEN_SPEND,
      wallet: OPEN_WALLET,
      counter: OPEN_COUNTER,
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(503);
    expect(error.code).toBe("quota_resolution_unavailable");
    expect(error.message).toContain("control db down");
  });

  it("a monthly-spend read failure → 503, NOT monthly_budget_exceeded", async () => {
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource({ monthlyBudgetUsd: 10 }),
      spend: {
        async committedSpendUsd() {
          return { ok: false, detail: "rollup read failed" };
        },
        async walletBalanceCredits() {
          return { ok: true, availableCredits: null };
        },
      },
      wallet: OPEN_WALLET,
      counter: OPEN_COUNTER,
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(503);
    expect(error.code).toBe("quota_resolution_unavailable");
    expect(error.code).not.toBe("monthly_budget_exceeded");
  });

  it("a wallet-balance read failure → 503, NOT wallet_balance_exhausted", async () => {
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource(null),
      spend: {
        async committedSpendUsd() {
          return { ok: true, committedSpendUsd: 0 };
        },
        async walletBalanceCredits() {
          return { ok: false, detail: "wallet read failed" };
        },
      },
      wallet: OPEN_WALLET,
      counter: OPEN_COUNTER,
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(503);
    expect(error.code).toBe("quota_resolution_unavailable");
  });

  it("a wallet RESERVATION outage → 503, NOT wallet_balance_exhausted", async () => {
    // The split that matters: `insufficient` is the caller's fault (429),
    // `unavailable` is ours (503). Collapsing them would refuse a funded tenant
    // with a message saying their credit ran out.
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource(null),
      spend: OPEN_SPEND,
      wallet: {
        async reserve() {
          return { kind: "unavailable", detail: "d1 batch rejected" };
        },
      },
      counter: OPEN_COUNTER,
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(503);
    expect(error.code).toBe("quota_resolution_unavailable");
  });

  it("a counter-backend outage → 503 governance_counter_unavailable, NOT 429", async () => {
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource({ rpmLimit: 5 }),
      spend: OPEN_SPEND,
      wallet: OPEN_WALLET,
      counter: {
        async consumeRequest() {
          return { allowed: "unavailable", detail: "stub dispatch failed" };
        },
      },
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(503);
    expect(error.code).toBe("governance_counter_unavailable");
    expect(error.message).toContain("stub dispatch failed");
  });
});

describe("the ladder runs in Rust's order", () => {
  it("a disabled scope refuses 403 BEFORE any counter is charged", async () => {
    let charged = 0;
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource({ enabled: false, rpmLimit: 5 }),
      spend: OPEN_SPEND,
      wallet: OPEN_WALLET,
      counter: {
        async consumeRequest() {
          charged += 1;
          return { allowed: true };
        },
      },
    });
    const error = await refusalOf(port);
    expect(error.status).toBe(403);
    expect(error.code).toBe("quota_scope_disabled");
    // A request that is hard-denied must not also burn a slot from the window
    // the still-allowed requests share.
    expect(charged).toBe(0);
  });

  it("an over-budget refusal does not charge the RPM window either", async () => {
    let charged = 0;
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource({ monthlyBudgetUsd: 10, rpmLimit: 5 }),
      spend: {
        async committedSpendUsd() {
          return { ok: true, committedSpendUsd: 10 };
        },
        async walletBalanceCredits() {
          return { ok: true, availableCredits: null };
        },
      },
      wallet: OPEN_WALLET,
      counter: {
        async consumeRequest() {
          charged += 1;
          return { allowed: true };
        },
      },
    });
    const error = await refusalOf(port);
    expect(error.code).toBe("monthly_budget_exceeded");
    expect(error.status).toBe(429);
    expect(charged).toBe(0);
  });

  it("refuses AT the cap (>=), the way Rust does", async () => {
    const under = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource({ monthlyBudgetUsd: 10 }),
      spend: {
        async committedSpendUsd() {
          return { ok: true, committedSpendUsd: 9.999 };
        },
        async walletBalanceCredits() {
          return { ok: true, availableCredits: null };
        },
      },
      wallet: OPEN_WALLET,
      counter: OPEN_COUNTER,
    });
    await expect(under.admit({ auth: AUTH, requestId: "r" })).resolves.toBeDefined();
  });
});

describe("wallet holds are given back", () => {
  it("releases the hold when a LATER step refuses", async () => {
    let released = 0;
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource({ rpmLimit: 1 }),
      spend: OPEN_SPEND,
      wallet: {
        async reserve() {
          return {
            kind: "admitted",
            hold: {
              id: "h1",
              amountCredits: 1,
              async release() {
                released += 1;
              },
            },
          };
        },
      },
      // Refuses AFTER the hold was taken — the exact ordering that strands
      // credits if the ladder does not unwind its own holds.
      counter: {
        async consumeRequest() {
          return {
            allowed: false,
            counterKey: "tenant:tenant-unit",
            limit: 1,
            retryAfterSeconds: 7,
          };
        },
      },
    });
    const error = await refusalOf(port);
    expect(error.code).toBe("rate_limit_exceeded");
    expect(released).toBe(1);
  });

  it("releases exactly once when the caller also releases", async () => {
    let released = 0;
    const port = admissionPort({
      env: NO_BINDINGS,
      quotas: quotaSource(null),
      spend: OPEN_SPEND,
      wallet: {
        async reserve() {
          return {
            kind: "admitted",
            hold: {
              id: "h1",
              amountCredits: 1,
              async release() {
                released += 1;
              },
            },
          };
        },
      },
      counter: OPEN_COUNTER,
    });
    const grant = await port.admit({ auth: AUTH, requestId: "r" });
    await grant.release();
    await grant.release();
    expect(released).toBe(1);
  });
});

describe("counter keys are scope-namespaced — the cross-tenant DoS boundary", () => {
  it("never lets a key id become a bare tenant window", () => {
    // The attack: mint a virtual key whose id IS another tenant's counter name.
    expect(perKeyCounterKey("tenant:victim")).toBe("key:tenant:victim");
    expect(perKeyCounterKey("tenant:victim")).not.toBe("tenant:victim");
  });

  it("refuses to address a counter with an unnamespaced string", () => {
    expect(() => assertNamespacedCounterKey("raw-api-key-id")).toThrow(CounterKeyNamespaceError);
    expect(() => assertNamespacedCounterKey("")).toThrow(CounterKeyNamespaceError);
  });

  it("collapses two caps on the SAME window to the tighter one", () => {
    // Both the per-key cap and a key-scope policy land on `key:{id}`; Rust
    // `min`s them rather than charging the window twice.
    const quota = {
      rpmLimit: 9,
      rpmLimitScope: {
        kind: "key" as const,
        id: "k1",
        counterKey: () => "key:k1",
        equals: () => false,
      },
    };
    // biome-ignore lint/suspicious/noExplicitAny: structural stand-in for QuotaScopeSelector
    const windows = requestWindows("k1", quota as any, 3);
    expect(windows).toEqual([{ counterKey: "key:k1", limit: 3 }]);
  });

  it("keeps a 0 cap as 0 — never upgraded to 'no cap'", () => {
    // biome-ignore lint/suspicious/noExplicitAny: empty EffectiveQuota
    const windows = requestWindows("k1", {} as any, 0);
    expect(windows).toEqual([{ counterKey: "key:k1", limit: 0 }]);
  });
});

describe("the Durable Object counter client", () => {
  function namespaceOver(
    replies: (name: string) => { allowed: boolean; retryAfterSeconds: number },
    seen: string[],
  ): RateLimiterNamespace {
    return {
      idFromName(name: string) {
        seen.push(name);
        return name as unknown as DurableObjectId;
      },
      get(id: DurableObjectId) {
        return {
          async consumeRequest() {
            return replies(id as unknown as string);
          },
        };
      },
    };
  }

  it("addresses ONE instance per counter key, in order, short-circuiting on denial", async () => {
    const seen: string[] = [];
    const counter = new DurableObjectRequestCounter(
      namespaceOver((name) => ({ allowed: name !== "tenant:t1", retryAfterSeconds: 11 }), seen),
    );
    const outcome = await counter.consumeRequest([
      { counterKey: "key:k1", limit: 5 },
      { counterKey: "tenant:t1", limit: 2 },
      { counterKey: "workspace:w1", limit: 9 },
    ]);
    expect(outcome).toEqual({
      allowed: false,
      counterKey: "tenant:t1",
      limit: 2,
      retryAfterSeconds: 11,
    });
    // The third window is never charged.
    expect(seen).toEqual(["key:k1", "tenant:t1"]);
  });

  it("reports an RPC throw as `unavailable` (→503), never as a denial (→429)", async () => {
    const counter = new DurableObjectRequestCounter({
      idFromName: (name: string) => name as unknown as DurableObjectId,
      get: () => ({
        async consumeRequest(): Promise<never> {
          throw new Error("no such durable object namespace");
        },
      }),
    });
    const outcome = await counter.consumeRequest([{ counterKey: "key:k1", limit: 5 }]);
    expect(outcome).toEqual({
      allowed: "unavailable",
      detail: "no such durable object namespace",
    });
  });

  it("lets a namespacing violation PROPAGATE rather than laundering it into 503", async () => {
    const counter = new DurableObjectRequestCounter({
      idFromName: (name: string) => name as unknown as DurableObjectId,
      get: () => ({
        async consumeRequest() {
          return { allowed: true, retryAfterSeconds: 0 };
        },
      }),
    });
    await expect(
      counter.consumeRequest([{ counterKey: "raw-id", limit: 5 }]),
    ).rejects.toBeInstanceOf(CounterKeyNamespaceError);
  });

  it("falls back to the local counter when RATE_LIMIT is absent or is a [vars] string", () => {
    expect(counterFromEnv({})).toBeInstanceOf(InMemoryRequestCounter);
    // A `[vars]` entry named RATE_LIMIT is a STRING; handing it to `idFromName`
    // would 500 every authenticated request.
    expect(counterFromEnv({ RATE_LIMIT: "yes" })).toBeInstanceOf(InMemoryRequestCounter);
  });
});

describe("the D1 sources report an outage rather than 'nothing configured'", () => {
  /** A D1 binding whose every statement rejects. */
  const brokenDb = {
    prepare() {
      return {
        bind() {
          return this;
        },
        async first(): Promise<never> {
          throw new Error("D1_ERROR: no such table");
        },
        async all(): Promise<never> {
          throw new Error("D1_ERROR: no such table");
        },
      };
    },
    async batch(): Promise<never> {
      throw new Error("D1_ERROR: no such table");
    },
    // biome-ignore lint/suspicious/noExplicitAny: minimal D1 stand-in
  } as any;

  it("d1QuotaPolicySource → { ok: false }, never an empty lookup", async () => {
    const snapshot = await d1QuotaPolicySource(brokenDb).policiesFor({
      apiKeyId: "k1",
      chain: { tenantId: "t1", keyId: "k1" },
    });
    expect(snapshot.ok).toBe(false);
    // CHANGED DELIBERATELY (#697). This used to assert the exact string
    // "quota policy lookup failed", which is the detail of the BATCH leg. The
    // auto-throttle overlay probes `sqlite_master` for `spend_throttles`
    // BEFORE the batch, so a database that fails everything now fails at the
    // probe and reports that leg instead.
    //
    // The INVARIANT this test exists for is untouched and is the first
    // assertion above: a broken control database is `{ ok: false }` — a 503 —
    // and never `{ ok: true, lookup: () => undefined }`, which would turn an
    // outage into unlimited traffic. Both legs are named rather than the
    // assertion being dropped to `snapshot.ok === false`, so a future leg that
    // fails with some third message still fails this test.
    if (!snapshot.ok) {
      expect(snapshot.detail).toMatch(/quota policy lookup failed|spend throttle probe failed/);
    }
  });

  it("d1SpendSource → { ok: false } on both legs, never 0 spent / no wallet", async () => {
    const source = d1SpendSource(brokenDb);
    const spend = await source.committedSpendUsd("tenant", "t1", "2026-08");
    expect(spend.ok).toBe(false);
    const wallet = await source.walletBalanceCredits("t1");
    expect(wallet.ok).toBe(false);
  });
});
