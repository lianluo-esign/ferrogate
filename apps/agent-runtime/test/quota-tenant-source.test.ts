/**
 * THE RELOCATED QUOTA READ (Track A red line) — which DATABASE each admission
 * leg reads from, in agent-runtime.
 *
 * `quota_policies` and `spend_throttles` are per-scope TENANT data whose home is
 * the tenant's OWN object, not the shared control. The
 * `AGENT_RUNTIME_QUOTA_POLICY_SOURCE = "tenant_object"` posture routes those two
 * legs to the tenant object while the account-global `plans` floor stays on
 * control. A split like this passes a per-leg suite while pointing a leg at the
 * wrong database, so each case asserts on the DATABASE that received the SQL.
 *
 * The mirror of `apps/gateway`'s quota-tenant-source test — the three admission
 * clones must stay in behavioural lockstep.
 */
import { describe, expect, it } from "vitest";

import { type QuotaSubject, d1QuotaPolicySource } from "../src/admission/quota.js";

function legOf(sql: string): "quota_policies" | "spend_throttles" | "plans" | "probe" | "other" {
  if (sql.includes("sqlite_master")) return "probe";
  if (sql.includes("FROM quota_policies")) return "quota_policies";
  if (sql.includes("FROM spend_throttles")) return "spend_throttles";
  if (sql.includes("FROM plans")) return "plans";
  return "other";
}

interface FakeD1 {
  readonly db: D1Database;
  readonly batches: string[][];
  readonly probes: number;
}

function fakeD1(options: { throttleProvisioned: boolean }): FakeD1 {
  const state = { batches: [] as string[][], probes: 0 };
  const db = {
    prepare(sql: string) {
      return {
        bind(..._values: unknown[]) {
          return {
            sql,
            async first<T = Record<string, unknown>>(): Promise<T | null> {
              state.probes += 1;
              return (options.throttleProvisioned ? { name: "spend_throttles" } : null) as T | null;
            },
          };
        },
      };
    },
    async batch(statements: { sql: string }[]) {
      state.batches.push(statements.map((s) => legOf(s.sql)));
      return statements.map(() => ({ results: [] as unknown[] }));
    },
  };
  return {
    db: db as unknown as D1Database,
    get batches() {
      return state.batches;
    },
    get probes() {
      return state.probes;
    },
  };
}

const NEVER = () => 0;

function subject(chain: QuotaSubject["chain"]): QuotaSubject {
  return { apiKeyId: "ak_test", chain };
}

describe("d1QuotaPolicySource routes each leg to the right database", () => {
  it("OFF (no resolver): every leg reads control in ONE batch", async () => {
    const control = fakeD1({ throttleProvisioned: true });

    const snapshot = await d1QuotaPolicySource(control.db, NEVER).policiesFor(
      subject({ tenantId: "tenant_a", keyId: "key_a" }),
    );

    expect(snapshot.ok).toBe(true);
    expect(control.batches).toEqual([["quota_policies", "spend_throttles", "plans"]]);
    expect(control.probes).toBe(1);
  });

  it("ON (resolver): tenant-scoped legs read the tenant object, plan stays on control", async () => {
    const control = fakeD1({ throttleProvisioned: false });
    const tenant = fakeD1({ throttleProvisioned: true });

    const snapshot = await d1QuotaPolicySource(
      control.db,
      NEVER,
      async () => tenant.db,
    ).policiesFor(subject({ tenantId: "tenant_a", keyId: "key_a" }));

    expect(snapshot.ok).toBe(true);
    expect(tenant.batches).toEqual([["quota_policies", "spend_throttles"]]);
    expect(control.batches).toEqual([["plans"]]);
    expect(tenant.probes).toBe(1);
    expect(control.probes).toBe(0);
  });

  it("ON but ownerless subject (no tenantId): falls back to control", async () => {
    const control = fakeD1({ throttleProvisioned: true });
    let resolverCalled = false;

    const snapshot = await d1QuotaPolicySource(control.db, NEVER, async () => {
      resolverCalled = true;
      return control.db;
    }).policiesFor(subject({ keyId: "key_only" }));

    expect(snapshot.ok).toBe(true);
    expect(resolverCalled).toBe(false);
    expect(control.batches).toEqual([["quota_policies", "spend_throttles"]]);
  });

  it("ON and the tenant handle cannot be resolved: 503, never a control read", async () => {
    const control = fakeD1({ throttleProvisioned: true });

    const snapshot = await d1QuotaPolicySource(control.db, NEVER, async () => {
      throw new Error("tenant object unreachable");
    }).policiesFor(subject({ tenantId: "tenant_a", keyId: "key_a" }));

    expect(snapshot.ok).toBe(false);
    expect(snapshot.ok === false && snapshot.detail).toContain(
      "routed tenant quota database unavailable",
    );
    expect(control.batches).toEqual([]);
    expect(control.probes).toBe(0);
  });
});
