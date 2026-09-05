/**
 * THE RELOCATED QUOTA READ (Track A red line, HARD CUT), MCP clone — which
 * DATABASE each admission leg reads from.
 *
 * `quota_policies` and `spend_throttles` are per-scope TENANT data whose SOLE
 * authoritative home is the tenant's OWN object; the shared control mirror has
 * been removed. The tenant-scoped legs always route to the tenant object while
 * the account-global `plans` floor stays on control.
 *
 * This clone probes with `.all()` (not `apps/gateway`'s `.first()`), so the
 * test's D1 double models that shape and asserts the probe the routed path
 * issues: the policy tables are probed on the tenant handle, the plan tables on
 * the control handle, and the two caches never contaminate each other.
 *
 * A call with no resolver, or an ownerless subject (no tenantId), has no tenant
 * object to read, so the tenant-scoped legs are SKIPPED and the limiter fails
 * OPEN — acceptable because such a subject has no relocated rows to enforce. The
 * control mirror no longer exists to fall through to, so a resolver failure for a
 * tenant-attributed subject is a 503.
 */
import { describe, expect, it } from "vitest";

import { d1QuotaPolicySource } from "../../src/admission/quota.js";
import type { QuotaSubject } from "../../src/admission/quota.js";

/** Which leg a statement is, decided from its SQL text. */
function legOf(sql: string): "quota_policies" | "spend_throttles" | "plans" | "other" {
  if (sql.includes("FROM quota_policies")) return "quota_policies";
  if (sql.includes("FROM spend_throttles")) return "spend_throttles";
  if (sql.includes("FROM plans")) return "plans";
  return "other";
}

interface FakeD1 {
  readonly db: D1Database;
  /** One entry per `batch()`, each the legs it carried, in order. */
  readonly batches: string[][];
  /** The `sqlite_master` probes (`.all()`) issued against this handle. */
  readonly probes: number;
}

/**
 * A recording D1 double sufficient for the MCP {@link d1QuotaPolicySource}: it
 * answers the `sqlite_master` probe (`.all()`) with `tables`, builds statements
 * (`.prepare().bind()`), and runs them (`.batch()`). The probe answer is
 * per-HANDLE in production — the whole point being that control and the tenant
 * object are probed independently.
 */
function fakeD1(tables: readonly string[]): FakeD1 {
  const state = { batches: [] as string[][], probes: 0 };
  const db = {
    prepare(sql: string) {
      const statement = {
        sql,
        bind(..._values: unknown[]) {
          return statement;
        },
        async all<T = { name: string }>(): Promise<{ results: T[] }> {
          // Only the `sqlite_master` probe reaches `.all()`; real reads go
          // through `.batch()`.
          state.probes += 1;
          return { results: tables.map((name) => ({ name })) as unknown as T[] };
        },
      };
      return statement;
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

const NEVER = () => 0; // the injected clock; no throttle rows are seeded

function subject(chain: QuotaSubject["chain"]): QuotaSubject {
  return { apiKeyId: "ak_test", chain };
}

/** Every table the policy chain + plan floor + throttle can read. */
const ALL_QUOTA_TABLES = [
  "quota_policies",
  "plans",
  "tenants",
  "tenant_databases",
  "spend_throttles",
] as const;

describe("MCP d1QuotaPolicySource routes each leg to the right database", () => {
  it("no resolver: tenant-scoped legs are skipped (fail-open), only the plan floor reads control", async () => {
    // Track A hard-cut removed the control mirror. Without a resolver there is no
    // tenant object to read, so quota_policies + spend_throttles are skipped
    // entirely (the limiter fails open) and ONLY the account-global plan floor
    // reaches control — probed once for its tables, then a single batch.
    const control = fakeD1(ALL_QUOTA_TABLES);

    const snapshot = await d1QuotaPolicySource(control.db, NEVER).policiesFor(
      subject({ tenantId: "tenant_a", keyId: "key_a" }),
    );

    expect(snapshot.ok).toBe(true);
    expect(control.batches).toEqual([["plans"]]);
    // The plan-table probe against control; no tenant-scoped probe anywhere.
    expect(control.probes).toBe(1);
  });

  it("resolver present: tenant-scoped legs read the tenant object, plan stays on control", async () => {
    // MUTATION: leave quota_policies on control while claiming to route it and
    // this goes red — the relocation is exactly the tenant-scoped legs moving.
    const control = fakeD1(["plans", "tenants", "tenant_databases"]);
    const tenant = fakeD1(["quota_policies", "spend_throttles"]);

    const snapshot = await d1QuotaPolicySource(
      control.db,
      NEVER,
      async () => tenant.db,
    ).policiesFor(subject({ tenantId: "tenant_a", keyId: "key_a" }));

    expect(snapshot.ok).toBe(true);
    // quota_policies + spend_throttles on the tenant object...
    expect(tenant.batches).toEqual([["quota_policies", "spend_throttles"]]);
    // ...the plan floor alone on control (`plans` has no per-tenant snapshot).
    expect(control.batches).toEqual([["plans"]]);
    // The DOUBLE PROBE: the policy tables were probed on the tenant handle, the
    // plan tables on the control handle — one each, never cross-contaminated.
    expect(tenant.probes).toBe(1);
    expect(control.probes).toBe(1);
  });

  it("ownerless subject (no tenantId): tenant legs skipped, nothing reads (fail-open)", async () => {
    // A platform-operator credential has no single tenant object to resolve, so
    // the tenant-scoped legs are skipped and the limiter fails open. With no
    // tenant there is no plan floor either, so nothing reads or probes anywhere.
    const control = fakeD1(ALL_QUOTA_TABLES);
    let resolverCalled = false;

    const snapshot = await d1QuotaPolicySource(control.db, NEVER, async () => {
      resolverCalled = true;
      return control.db;
    }).policiesFor(subject({ keyId: "key_only" }));

    expect(snapshot.ok).toBe(true);
    expect(resolverCalled).toBe(false);
    expect(control.batches).toEqual([]);
    expect(control.probes).toBe(0);
  });

  it("the tenant handle cannot be resolved: 503, never a control read", async () => {
    // MUTATION: fall through to control on a resolver failure and this goes red.
    // Answering from the wrong authority would apply the wrong caps to live
    // traffic — the failure a limiter must refuse, not paper over. There is no
    // control mirror to fall through to anyway (Track A hard-cut).
    const control = fakeD1(ALL_QUOTA_TABLES);

    const snapshot = await d1QuotaPolicySource(control.db, NEVER, async () => {
      throw new Error("tenant object unreachable");
    }).policiesFor(subject({ tenantId: "tenant_a", keyId: "key_a" }));

    expect(snapshot.ok).toBe(false);
    expect(snapshot.ok === false && snapshot.detail).toContain(
      "routed tenant quota database unavailable",
    );
    // The resolver throws BEFORE any probe or batch — control is never touched.
    expect(control.batches).toEqual([]);
    expect(control.probes).toBe(0);
  });
});
