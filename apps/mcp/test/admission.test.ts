/**
 * The ADMISSION half of Rust's `authenticate()` — `finalize_auth` — driven
 * through the REAL `ferrogate-mcp` Worker.
 *
 * ## The defect this suite exists to hold
 *
 * `crates/ferrogate-gateway/src/auth.rs::finalize_auth` runs on EVERY
 * successfully identified `AuthContext`, whatever handler is being called,
 * because in the Rust tree `POST /v1/mcp` shared a process with
 * `POST /v1/chat/completions`. It enforces, in this order:
 *
 *   1. `denied_by`               → **403** `quota_scope_disabled`
 *   2. `monthly_budget_usd`      → **429** `monthly_budget_exceeded`
 *   3. wallet balance            → **429** `wallet_balance_exhausted`
 *   4. `request_windows()` (RPM) → **429** `rate_limit_exceeded`
 *
 * …and answers **503** `quota_resolution_unavailable` when a lookup fails and
 * **503** `governance_counter_unavailable` when the counter backend does.
 *
 * When the Rust single process was split into five Workers, that half crossed
 * into `apps/gateway` and NOWHERE else. A credential at its RPM ceiling and
 * over its monthly budget was refused on `/v1/chat/completions` and ADMITTED on
 * MCP `tools/call` — which reaches a paid upstream and a paid asset pull. The
 * exploit was "call the other endpoint", and it needed no special knowledge.
 *
 * ## Why every test drives `SELF.fetch`
 *
 * A test that constructs the gate directly proves the CLASS works and proves
 * nothing about the Worker that ships — the "implemented, fully tested, never
 * mounted" defect this project has been bitten by repeatedly. So policies,
 * rollups and wallets are seeded as raw rows into the REAL `env.DB` /
 * `env.TENANT_DB_A` that `@cloudflare/vitest-pool-workers` boots in workerd, and
 * the credential is then presented to the REAL exported app over HTTP.
 *
 * ## Why each test mints its own tenant and api key
 *
 * The RPM counter is keyed on the scope that won the merge, and the pool does
 * not roll back D1 or the counter state between tests. A per-test tenant id
 * makes each test's counter window structurally its own, so an assertion can
 * never be satisfied (or broken) by a neighbour's traffic.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import { hashApiKeySecret } from "../src/auth.js";
import { type Fixture, rpcRequest, seedFixture } from "./fixtures.js";
import { resetTenantObjectState, seedTenantRoleProjection, tenantObjectDb } from "./tenant-object.js";

interface AdmissionBindings {
  readonly DB: D1Database;
  readonly TENANT_DB_A: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

function bindings(): AdmissionBindings {
  return env as unknown as AdmissionBindings;
}

const control = (): D1Database => bindings().DB;
const tenantDb = (tenantId: string): D1Database => tenantObjectDb(tenantId);

interface JsonBody {
  readonly error?: { code: string; message: string };
  readonly result?: unknown;
}

let fixture: Fixture;
let counter = 0;

/** A tenant / key / secret triple nothing else in this run shares. */
interface Caller {
  readonly tenantId: string;
  readonly keyId: string;
  readonly secret: string;
}

function mintCaller(): Caller {
  counter += 1;
  return {
    tenantId: `adm-tenant-${counter}`,
    keyId: `adm-key-${counter}`,
    secret: `fg_admission_secret_${counter}`,
  };
}

beforeAll(async () => {
  const b = bindings();
  // Zero-D1 S5 (#881): the ControlDataObject self-applies its schema on first
  // wake; there is no control D1 to migrate here.
  await applyD1Migrations(b.TENANT_DB_A, b.TEST_TENANT_D1_SCHEMA);
});

beforeEach(async () => {
  // The pool does not roll D1 writes back and the databases persist under
  // `.wrangler/state`, so a passing assertion could otherwise be a leftover row.
  await control().batch([
    control().prepare("DELETE FROM quota_policies"),
    control().prepare("DELETE FROM tenant_databases"),
    control().prepare("DELETE FROM api_key_directory"),
    control().prepare("DELETE FROM static_api_keys"),
    control().prepare("DELETE FROM roles"),
    control().prepare("DELETE FROM tenants"),
    control().prepare("DELETE FROM plans"),
  ]);
  fixture = seedFixture({ tenantId: "tenant-mcp-admission" });
});

// ---------------------------------------------------------------------------
// Seeding — raw SQL, never through the code under test
// ---------------------------------------------------------------------------

/**
 * Provision a virtual credential end to end: the tenant's database registry
 * row, the control-plane directory row, the tenant `api_keys` row that is the
 * AUTHORITY for scopes, and an RBAC role carrying `mcp.execute`.
 */
async function provision(caller: Caller): Promise<void> {
  const keyHash = await hashApiKeySecret(caller.secret);
  const tenant = tenantDb(caller.tenantId);
  await resetTenantObjectState([caller.tenantId]);
  await control().batch([
    control()
      .prepare(
        `INSERT INTO tenant_databases
           (tenant_id, binding_name, schema_version,
            storage_backend, provisioning_status, provisioned_at_unix, updated_at_unix)
         VALUES (?, NULL, 15, 'durable_object', 'ready', 1, 1)`,
      )
      .bind(caller.tenantId),
    control()
      .prepare(
        `INSERT INTO api_key_directory
           (key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4,
            enabled, expires_at_unix, revoked_at_unix)
         VALUES (?, ?, ?, 'proj-1', 'ws-1', 'fg_', 'key1', 1, NULL, NULL)`,
      )
      .bind(keyHash, caller.keyId, caller.tenantId),
    control()
      .prepare(
        `INSERT INTO roles (id, name, slug, description, permission_keys_json)
         VALUES (?, 'MCP', ?, '', ?)`,
      )
      .bind(`role-${caller.tenantId}`, `mcp-${caller.tenantId}`, JSON.stringify(["mcp.execute"])),
  ]);
  await seedTenantRoleProjection(caller.tenantId, `role-${caller.tenantId}`, ["mcp.execute"]);
  await tenant
    .prepare(
      `INSERT INTO api_keys
         (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4,
          enabled, scopes_json, revoked_at_unix)
       VALUES (?, 'ws-1', ?, 'proj-1', 'mcp', 'fg_', ?, 'key1', 1, ?, NULL)`,
    )
    .bind(
      caller.keyId,
      caller.tenantId,
      keyHash,
      JSON.stringify(["tools.read", "tools.execute", "assets.read"]),
    )
    .run();
}

interface PolicySeed {
  readonly scopeType?: "tenant" | "project" | "workspace" | "key";
  readonly scopeId?: string;
  readonly rpmLimit?: number | null;
  readonly monthlyBudgetUsd?: number | null;
  readonly enabled?: 0 | 1;
}

async function seedQuotaPolicy(caller: Caller, seed: PolicySeed = {}): Promise<void> {
  const scopeType = seed.scopeType ?? "tenant";
  const scopeId = seed.scopeId ?? caller.tenantId;
  await control()
    .prepare(
      `INSERT INTO quota_policies
         (id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit,
          monthly_budget_usd, enabled, alert_threshold_pcts_json)
       VALUES (?, ?, ?, '[]', ?, NULL, ?, ?, '[]')`,
    )
    .bind(
      `policy-${scopeType}-${scopeId}`,
      scopeType,
      scopeId,
      seed.rpmLimit ?? null,
      seed.monthlyBudgetUsd ?? null,
      seed.enabled ?? 1,
    )
    .run();
}

/** Committed spend for one scope in the CURRENT calendar month. */
async function seedMonthlySpend(
  scopeType: string,
  scopeId: string,
  costUsd: number,
): Promise<void> {
  const now = new Date();
  const periodMonth = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  await tenantDb(scopeId)
    .prepare(
      `INSERT INTO usage_monthly_rollups
         (id, period_month, scope_type, scope_id, cost_usd, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, 1)`,
    )
    .bind(`roll-${scopeType}-${scopeId}`, periodMonth, scopeType, scopeId, costUsd)
    .run();
}

async function seedWallet(tenantId: string, balanceCredits: number): Promise<void> {
  await tenantDb(tenantId)
    .prepare(
      `INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 0, 1, 1)`,
    )
    .bind(tenantId, tenantId, balanceCredits)
    .run();
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

async function post(
  body: Record<string, unknown>,
  key?: string,
): Promise<{ status: number; body: JsonBody }> {
  const res = await SELF.fetch(rpcRequest(body, key === undefined ? {} : { key }));
  return { status: res.status, body: (await res.json()) as JsonBody };
}

function toolsCall(key: string): Promise<{ status: number; body: JsonBody }> {
  return post(
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "srv-echo", arguments: {} } },
    key,
  );
}

function toolsList(key: string): Promise<{ status: number; body: JsonBody }> {
  return post({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, key);
}

// ---------------------------------------------------------------------------

describe("the admission half of finalize_auth is enforced on MCP tools/call", () => {
  it("REFUSES a credential over its per-key RPM ceiling with 429 rate_limit_exceeded", async () => {
    const caller = mintCaller();
    await provision(caller);
    await seedQuotaPolicy(caller, { rpmLimit: 1 });

    // The window affords exactly one request...
    const first = await toolsCall(caller.secret);
    expect(first.status).toBe(200);
    expect(first.body.error).toBeUndefined();

    // ...and the second is the Rust 429, BEFORE any tool runs.
    const second = await toolsCall(caller.secret);
    expect(second.status).toBe(429);
    expect(second.body.error?.code).toBe("rate_limit_exceeded");
    // The refused call never reached the upstream — this is admission, not a
    // post-hoc accounting entry.
    expect(fixture.calls).toHaveLength(1);
  });

  it("REFUSES a credential over the TOK-12 api_keys.request_limit_per_minute column", async () => {
    // The per-credential cap is carried on the `api_keys` ROW, independently of
    // the quota-policy chain. A deployment with no `quota_policies` at all must
    // still honour it, or the column is inert configuration.
    const caller = mintCaller();
    await provision(caller);
    await tenantDb(caller.tenantId)
      .prepare("UPDATE api_keys SET request_limit_per_minute = 1 WHERE id = ?")
      .bind(caller.keyId)
      .run();

    expect((await toolsCall(caller.secret)).status).toBe(200);
    const second = await toolsCall(caller.secret);
    expect(second.status).toBe(429);
    expect(second.body.error?.code).toBe("rate_limit_exceeded");
  });

  it("REFUSES a credential over its monthly budget with 429 monthly_budget_exceeded", async () => {
    const caller = mintCaller();
    await provision(caller);
    await seedQuotaPolicy(caller, { monthlyBudgetUsd: 5 });
    // Rust refuses AT the cap (`spent >= budget_usd`), not merely above it.
    await seedMonthlySpend("tenant", caller.tenantId, 5);

    const res = await toolsCall(caller.secret);
    expect(res.status).toBe(429);
    expect(res.body.error?.code).toBe("monthly_budget_exceeded");
    expect(fixture.calls).toHaveLength(0);
  });

  it("ADMITS the same credential while it is still under budget", async () => {
    // The control for the test above: the refusal must come from the SPEND, not
    // from the mere presence of a budget.
    const caller = mintCaller();
    await provision(caller);
    await seedQuotaPolicy(caller, { monthlyBudgetUsd: 5 });
    await seedMonthlySpend("tenant", caller.tenantId, 4.99);

    const res = await toolsCall(caller.secret);
    expect(res.status).toBe(200);
    expect(res.body.error).toBeUndefined();
  });

  it("REFUSES a credential whose prepaid wallet is empty with 429 wallet_balance_exhausted", async () => {
    const caller = mintCaller();
    await provision(caller);
    await seedWallet(caller.tenantId, 0);

    const res = await toolsCall(caller.secret);
    expect(res.status).toBe(429);
    expect(res.body.error?.code).toBe("wallet_balance_exhausted");
    expect(fixture.calls).toHaveLength(0);
  });

  it("RELEASES the wallet hold when the request finishes — JS has no Drop", async () => {
    // Rust released the `WalletCreditReservation` when the guard fell out of
    // scope. Here ONE `finally` in `src/routes/index.ts` does it for every
    // registered operation. A wallet funded with exactly one credit therefore
    // serves an unbounded number of SEQUENTIAL requests; if the release were
    // dropped, the second call would see `available = 1 - 1 = 0` and be
    // refused, and the holds would strand for a full TTL.
    const caller = mintCaller();
    await provision(caller);
    await seedWallet(caller.tenantId, 1);

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const res = await toolsCall(caller.secret);
      expect(res.status, `call ${attempt + 1} was refused`).toBe(200);
    }

    // ...and the holds really are gone from the durable table, not merely
    // forgotten in memory.
    const live = await tenantDb(caller.tenantId)
      .prepare(
        "SELECT COUNT(*) AS n FROM wallet_reservations WHERE tenant_id = ? AND status = 'active'",
      )
      .bind(caller.tenantId)
      .first<{ n: number }>();
    expect(live?.n).toBe(0);
  });

  it("never denies a tenant that has NOT adopted prepaid billing", async () => {
    // Opt-in: no `wallets` row must never be read as a zero balance.
    const caller = mintCaller();
    await provision(caller);

    const res = await toolsCall(caller.secret);
    expect(res.status).toBe(200);
    expect(res.body.error).toBeUndefined();
  });

  it("REFUSES a disabled quota scope with 403 quota_scope_disabled — a deny, not a throttle", async () => {
    const caller = mintCaller();
    await provision(caller);
    await seedQuotaPolicy(caller, { enabled: 0 });

    const res = await toolsCall(caller.secret);
    expect(res.status).toBe(403);
    expect(res.body.error?.code).toBe("quota_scope_disabled");
    expect(fixture.calls).toHaveLength(0);
  });
});

describe("the admission ladder covers the read surface too, not just tools/call", () => {
  it("REFUSES tools/list on an exhausted RPM window", async () => {
    // Both MCP transports share one chokepoint in Rust; a limit that only bound
    // the execute verb would be bypassable by listing in a loop.
    const caller = mintCaller();
    await provision(caller);
    await seedQuotaPolicy(caller, { rpmLimit: 1 });

    expect((await toolsList(caller.secret)).status).toBe(200);
    const second = await toolsList(caller.secret);
    expect(second.status).toBe(429);
    expect(second.body.error?.code).toBe("rate_limit_exceeded");
  });
});

describe("the 401 / 403 ladder ABOVE admission is preserved", () => {
  it("no Bearer header is 401 unauthenticated", async () => {
    const res = await post({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("unauthenticated");
  });

  it("an unknown credential is 401 invalid_api_key", async () => {
    const res = await toolsList("fg_no_such_key_at_all");
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("a SUSPENDED (revoked) credential is 401 invalid_api_key — never 403", async () => {
    const caller = mintCaller();
    await provision(caller);
    await control()
      .prepare("UPDATE api_key_directory SET revoked_at_unix = 10 WHERE id = ?")
      .bind(caller.keyId)
      .run();

    const res = await toolsList(caller.secret);
    expect(res.status).toBe(401);
    expect(res.body.error?.code).toBe("invalid_api_key");
  });

  it("an authenticated credential missing the operation scope is 403 insufficient_scope", async () => {
    const caller = mintCaller();
    await provision(caller);
    await tenantDb(caller.tenantId)
      .prepare("UPDATE api_keys SET scopes_json = ? WHERE id = ?")
      .bind(JSON.stringify(["tools.read"]), caller.keyId)
      .run();

    const res = await toolsCall(caller.secret);
    expect(res.status).toBe(403);
    expect(res.body.error?.code).toBe("insufficient_scope");
  });

  it("a scope refusal is decided BEFORE any admission counter is charged", async () => {
    // Ordering matters: if the RPM window were charged first, an under-scoped
    // caller could drain the budget of the calls that ARE allowed.
    const caller = mintCaller();
    await provision(caller);
    await seedQuotaPolicy(caller, { rpmLimit: 1 });
    await tenantDb(caller.tenantId)
      .prepare("UPDATE api_keys SET scopes_json = ? WHERE id = ?")
      .bind(JSON.stringify(["tools.read"]), caller.keyId)
      .run();

    expect((await toolsCall(caller.secret)).status).toBe(403);
    // The one request the window affords is still there.
    expect((await toolsList(caller.secret)).status).toBe(200);
  });
});
