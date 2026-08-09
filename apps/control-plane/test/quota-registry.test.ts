/**
 * The WRITE half of the quota chain — the MOUNT GATE.
 *
 * `apps/gateway/src/ratelimit/quota.ts`'s `d1QuotaPolicySource` is the data
 * plane's admission gate. On every authenticated request it issues ONE
 * `db.batch()` against the CONTROL database:
 *
 * ```sql
 * SELECT <16 columns> FROM quota_policies
 *   WHERE (scope_type = ? AND scope_id = ?) OR …
 * SELECT p.* FROM plans p JOIN tenants t ON t.plan_id = p.id WHERE t.id = ?
 * ```
 *
 * Nothing in this repo wrote `plans`, `quota_policies` or `tenants`. The admin
 * surface stored documents in `control_plane_resources` and stopped, so both
 * legs came back empty on every deployment and `resolveEffectiveQuota` merged an
 * empty chain — which is not "the default limits", it is NO rpm cap, NO tpm
 * cap, NO monthly budget and NO model allowlist, while
 * `GET /admin/v1/tenant-accounts/{id}/resolved-defaults` cheerfully reported the
 * configured numbers back off the documents.
 *
 * These tests drive the DEPLOYED Worker over `SELF` in the `d1` posture (the
 * production default) and read the typed tables with RAW SQL — never through
 * the projection under test — using the gateway's own column list and its own
 * two statements, transcribed verbatim. The decisive assertion is the last one:
 * the effective quota computed from the PROJECTED ROWS, by the same
 * `@ferrogate/policy` merge the data plane runs, must equal the effective quota
 * the admin surface reports from the DOCUMENTS. Delete any projection and the
 * rows disappear, the merge goes unlimited, and the two stop agreeing.
 */
import { SELF, env } from "cloudflare:test";
import {
  type QuotaScopeKind,
  type StoredPlan,
  type StoredQuotaPolicy,
  resolveEffectiveQuota,
} from "@ferrogate/policy";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantStorage } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import {
  NO_PLAN_ID,
  PLANS_TABLE,
  QUOTA_POLICIES_TABLE,
  TENANTS_TABLE,
} from "../src/store/quota_registry.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

const KEY = operatorKey.secret;

/**
 * `apps/gateway/src/ratelimit/quota.ts`'s `QUOTA_POLICY_COLUMNS`, verbatim.
 * If the projection stops writing one of these, the gateway reads a NULL where
 * the operator configured a number.
 */
const GATEWAY_QUOTA_POLICY_COLUMNS =
  "id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit, " +
  "monthly_budget_usd, enabled, created_at_unix, updated_at_unix, " +
  "alert_threshold_pcts_json, asset_storage_quota_bytes, " +
  "monthly_egress_bytes_budget, download_rpm_limit, asset_max_object_bytes, " +
  "agent_cost_budget_usd";

// ---------------------------------------------------------------------------
// The gateway's two reads, transcribed — the test-side reader
// ---------------------------------------------------------------------------

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function jsonArray<T>(value: unknown): T[] {
  if (value === null || value === undefined || value === "") return [];
  const parsed: unknown = JSON.parse(String(value));
  if (!Array.isArray(parsed)) throw new Error(`not a JSON array: ${String(value)}`);
  return parsed as T[];
}

/** The gateway's `rowToStoredPolicy`, transcribed. */
function rowToPolicy(row: Record<string, unknown>): StoredQuotaPolicy {
  return {
    id: String(row.id),
    scopeType: String(row.scope_type) as QuotaScopeKind,
    scopeId: String(row.scope_id),
    modelAllowlist: jsonArray<string>(row.model_allowlist_json),
    rpmLimit: optionalNumber(row.rpm_limit),
    tpmLimit: optionalNumber(row.tpm_limit),
    monthlyBudgetUsd: optionalNumber(row.monthly_budget_usd),
    assetStorageQuotaBytes: optionalNumber(row.asset_storage_quota_bytes),
    assetMaxObjectBytes: optionalNumber(row.asset_max_object_bytes),
    agentCostBudgetUsd: optionalNumber(row.agent_cost_budget_usd),
    alertThresholdPcts: jsonArray<number>(row.alert_threshold_pcts_json),
    enabled: Number(row.enabled) !== 0,
    createdAtUnix: Number(row.created_at_unix ?? 0),
    updatedAtUnix: Number(row.updated_at_unix ?? 0),
    monthlyEgressBytesBudget: optionalNumber(row.monthly_egress_bytes_budget),
    downloadRpmLimit: optionalNumber(row.download_rpm_limit),
  };
}

/** The gateway's `rowToStoredPlan`, transcribed. */
function rowToPlan(row: Record<string, unknown>): StoredPlan {
  return {
    id: String(row.id),
    name: String(row.name ?? ""),
    slug: String(row.slug ?? ""),
    mcpEnabled: Number(row.mcp_enabled) !== 0,
    selfHostedWorkersEnabled: Number(row.self_hosted_workers_enabled) !== 0,
    adminConsoleSeats: optionalNumber(row.admin_console_seats),
    defaultModelAllowlist: jsonArray<string>(row.default_model_allowlist_json),
    defaultRpmLimit: optionalNumber(row.default_rpm_limit),
    defaultTpmLimit: optionalNumber(row.default_tpm_limit),
    defaultMonthlyBudgetUsd: optionalNumber(row.default_monthly_budget_usd),
    createdAtUnix: Number(row.created_at_unix ?? 0),
    updatedAtUnix: Number(row.updated_at_unix ?? 0),
    assetHostingEnabled: Number(row.asset_hosting_enabled) !== 0,
    defaultAssetStorageQuotaBytes: optionalNumber(row.default_asset_storage_quota_bytes),
    defaultAssetMaxObjectBytes: optionalNumber(row.default_asset_max_object_bytes),
    defaultAgentCostBudgetUsd: optionalNumber(row.default_agent_cost_budget_usd),
    defaultMonthlyEgressBytesBudget: optionalNumber(row.default_monthly_egress_bytes_budget),
    defaultDownloadRpmLimit: optionalNumber(row.default_download_rpm_limit),
    extensionToolsEnabled: Number(row.extension_tools_enabled) !== 0,
  };
}

/** The gateway's policy statement, for one `(scope_type, scope_id)` pair. */
async function gatewayPolicyRow(
  scopeType: string,
  scopeId: string,
): Promise<Record<string, unknown> | null> {
  return await db()
    .prepare(
      `SELECT ${GATEWAY_QUOTA_POLICY_COLUMNS} FROM ${QUOTA_POLICIES_TABLE} WHERE (scope_type = ? AND scope_id = ?)`,
    )
    .bind(scopeType, scopeId)
    .first<Record<string, unknown>>();
}

/** The gateway's plan statement — the join is the whole point. */
async function gatewayPlanRow(tenantId: string): Promise<Record<string, unknown> | null> {
  return await db()
    .prepare(
      `SELECT p.* FROM ${PLANS_TABLE} p JOIN ${TENANTS_TABLE} t ON t.plan_id = p.id WHERE t.id = ?`,
    )
    .bind(tenantId)
    .first<Record<string, unknown>>();
}

async function tenantRow(id: string): Promise<Record<string, unknown> | null> {
  return await db()
    .prepare(`SELECT * FROM ${TENANTS_TABLE} WHERE id = ?`)
    .bind(id)
    .first<Record<string, unknown>>();
}

// ---------------------------------------------------------------------------
// Admin-surface drivers
// ---------------------------------------------------------------------------

async function post(path: string, body: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, jsonRequest(KEY, "POST", body));
}

async function send(method: string, path: string, body: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, jsonRequest(KEY, method, body));
}

async function resolvedDefaults(tenantId: string): Promise<Record<string, unknown>> {
  const res = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/${tenantId}/resolved-defaults`, {
    headers: bearer(KEY),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

beforeAll(applySchema);

beforeEach(async () => {
  arm({ store: "d1", staticKeys: [operatorKey] });
  await resetD1();
  await db().batch([
    db().prepare(`DELETE FROM ${QUOTA_POLICIES_TABLE}`),
    db().prepare(`DELETE FROM ${PLANS_TABLE}`),
    db().prepare(`DELETE FROM ${TENANTS_TABLE}`),
  ]);
  await db()
    .prepare(
      `INSERT INTO ${TENANTS_TABLE}
         (id, name, slug, status, plan_id, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 'active', ?, 0, 0)`,
    )
    .bind("acme", "Acme", "acme", NO_PLAN_ID)
    .run();
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, storage_backend, provisioning_status, migration_state,
          location_hint, location_hint_source, location_hint_recorded_at_unix, jurisdiction)
       VALUES (?, 'durable_object', 'ready', 'done', ?, ?, ?, ?)`,
    )
    .bind("acme", "wnam", "test:registered tenant", 0, null)
    .run();
  const tenantHandle = await resolveTenantStorage(env as unknown as ControlPlaneBindings).forTenant(
    "acme",
    { locationHint: "wnam" },
  );
  await tenantHandle.db.batch([
    tenantHandle.db.prepare("DELETE FROM tenant_resources"),
    tenantHandle.db
      .prepare("DELETE FROM tenant_provisioning_marks WHERE mark = ?")
      .bind("control_plane_resource_backfill_v1"),
  ]);
});

describe("MOUNT: a quota policy created through the admin API is enforceable", () => {
  it("writes the typed row the gateway's admission predicate matches", async () => {
    const created = await post("/admin/v1/quota-policies", {
      scope_type: "tenant",
      scope_id: "acme",
      rpm_limit: 60,
      tpm_limit: 9000,
      monthly_budget_usd: 25.5,
      model_allowlist: ["gpt-4o", "claude-3"],
      alert_threshold_pcts: [75, 90],
      asset_storage_quota_bytes: 1024,
      asset_max_object_bytes: 512,
      monthly_egress_bytes_budget: 2048,
      download_rpm_limit: 7,
      agent_cost_budget_usd: 3.25,
      residency_regions: ["global"],
      require_zero_data_retention: true,
      log_residency: "in_region",
    });
    expect(created.status).toBe(201);

    const row = await gatewayPolicyRow("tenant", "acme");
    expect(row).not.toBeNull();
    const policy = rowToPolicy(row as Record<string, unknown>);
    expect(policy).toMatchObject({
      id: "tenant:acme",
      scopeType: "tenant",
      scopeId: "acme",
      rpmLimit: 60,
      tpmLimit: 9000,
      monthlyBudgetUsd: 25.5,
      modelAllowlist: ["gpt-4o", "claude-3"],
      alertThresholdPcts: [75, 90],
      assetStorageQuotaBytes: 1024,
      assetMaxObjectBytes: 512,
      monthlyEgressBytesBudget: 2048,
      downloadRpmLimit: 7,
      agentCostBudgetUsd: 3.25,
      enabled: true,
    });
    expect(
      await db()
        .prepare(
          "SELECT residency_regions_json, require_zero_data_retention, log_residency " +
            "FROM quota_policies WHERE scope_type = 'tenant' AND scope_id = ?",
        )
        .bind("acme")
        .first(),
    ).toEqual({
      residency_regions_json: '["global"]',
      require_zero_data_retention: 1,
      log_residency: "in_region",
    });
  });

  it("refuses to set EU residency when the object is already unrestricted in another jurisdiction", async () => {
    await db()
      .prepare("UPDATE tenant_databases SET jurisdiction = 'us' WHERE tenant_id = ?")
      .bind("acme")
      .run();
    const response = await post("/admin/v1/quota-policies", {
      scope_type: "tenant",
      scope_id: "acme",
      residency_regions: ["eu-west-1"],
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      error: {
        code: "tenant_jurisdiction_migration_required",
        message: expect.stringContaining("requires a data migration"),
      },
    });
  });

  it("an edit follows through to the enforced row (PATCH and PUT)", async () => {
    await post("/admin/v1/quota-policies", {
      scope_type: "tenant",
      scope_id: "acme",
      rpm_limit: 60,
    });

    const patched = await send("PATCH", "/admin/v1/quota-policies/tenant/acme", {
      rpm_limit: 5,
    });
    expect(patched.status).toBe(200);
    expect(rowToPolicy((await gatewayPolicyRow("tenant", "acme")) ?? {}).rpmLimit).toBe(5);

    const replaced = await send("PUT", "/admin/v1/quota-policies/tenant/acme", {
      rpm_limit: 11,
      enabled: false,
    });
    expect(replaced.status).toBe(200);
    const after = rowToPolicy((await gatewayPolicyRow("tenant", "acme")) ?? {});
    expect(after.rpmLimit).toBe(11);
    // A disabled policy is a HARD DENY in the merge — the one value that must
    // never be lost in translation, because losing it admits the traffic the
    // operator switched off.
    expect(after.enabled).toBe(false);
  });

  it("deleting the policy removes the enforcement row, not just the document", async () => {
    await post("/admin/v1/quota-policies", {
      scope_type: "project",
      scope_id: "proj-1",
      tenant_id: "acme",
      rpm_limit: 3,
    });
    expect(await gatewayPolicyRow("project", "proj-1")).not.toBeNull();

    const deleted = await SELF.fetch(`${BASE}/admin/v1/quota-policies/project/proj-1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(deleted.status).toBe(200);
    // A limit that survives its own deletion keeps throttling a tenant nobody
    // can explain it to.
    expect(await gatewayPolicyRow("project", "proj-1")).toBeNull();
  });

  it("refuses a non-tenant scope carrying a tenant-only asset ceiling", async () => {
    // Rust `validate_quota_policy`: stored assets and their usage are
    // tenant-owned. Storing the row with the column silently dropped would
    // persist a WIDER policy than the operator asked for.
    const res = await post("/admin/v1/quota-policies", {
      scope_type: "workspace",
      scope_id: "ws-1",
      tenant_id: "acme",
      asset_storage_quota_bytes: 10,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error?: { message?: string } };
    expect(body.error?.message).toContain("tenant-only");
  });
});

describe("MOUNT: a plan created through the admin API is the gateway's floor", () => {
  it("the plan join resolves only once the tenant is ON the plan", async () => {
    expect(
      (await post("/admin/v1/plans", { id: "pro", name: "Pro", default_rpm_limit: 40 })).status,
    ).toBe(201);
    expect((await post("/admin/v1/tenant-accounts", { id: "acme", name: "Acme" })).status).toBe(
      201,
    );

    // A tenant account with no plan assignment must NOT join to a plan: the
    // document path reports `plan_id: null`, and an invented `'free'` (the
    // column default) would silently apply a floor the operator never chose.
    expect((await tenantRow("acme"))?.plan_id).toBe(NO_PLAN_ID);
    expect(await gatewayPlanRow("acme")).toBeNull();

    const assigned = await send("PUT", "/admin/v1/tenant-accounts/acme/plan", { plan_id: "pro" });
    expect(assigned.status).toBe(200);
    expect((await tenantRow("acme"))?.plan_id).toBe("pro");

    const planRow = await gatewayPlanRow("acme");
    expect(planRow).not.toBeNull();
    expect(rowToPlan(planRow as Record<string, unknown>)).toMatchObject({
      id: "pro",
      name: "Pro",
      defaultRpmLimit: 40,
    });
  });

  it("editing the plan follows through to every field the gateway reads", async () => {
    await post("/admin/v1/plans", { id: "pro", name: "Pro" });
    await post("/admin/v1/tenant-accounts", { id: "acme", plan_id: "pro" });
    // `plan_id` supplied at creation must already join — not only via the
    // dedicated assignment route.
    expect(await gatewayPlanRow("acme")).not.toBeNull();

    const patched = await send("PATCH", "/admin/v1/plans/pro", {
      default_rpm_limit: 12,
      default_tpm_limit: 3400,
      default_monthly_budget_usd: 9.5,
      default_model_allowlist: ["gpt-4o"],
      mcp_enabled: true,
      self_hosted_workers_enabled: true,
      extension_tools_enabled: true,
      asset_hosting_enabled: true,
      admin_console_seats: 4,
      default_asset_storage_quota_bytes: 111,
      default_asset_max_object_bytes: 22,
      default_agent_cost_budget_usd: 1.5,
      default_monthly_egress_bytes_budget: 333,
      default_download_rpm_limit: 9,
    });
    expect(patched.status).toBe(200);

    expect(rowToPlan((await gatewayPlanRow("acme")) ?? {})).toMatchObject({
      defaultRpmLimit: 12,
      defaultTpmLimit: 3400,
      defaultMonthlyBudgetUsd: 9.5,
      defaultModelAllowlist: ["gpt-4o"],
      mcpEnabled: true,
      selfHostedWorkersEnabled: true,
      extensionToolsEnabled: true,
      assetHostingEnabled: true,
      adminConsoleSeats: 4,
      defaultAssetStorageQuotaBytes: 111,
      defaultAssetMaxObjectBytes: 22,
      defaultAgentCostBudgetUsd: 1.5,
      defaultMonthlyEgressBytesBudget: 333,
      defaultDownloadRpmLimit: 9,
    });
  });

  it("moving a tenant BETWEEN plans re-points the join", async () => {
    await post("/admin/v1/plans", { id: "pro", name: "Pro", default_rpm_limit: 40 });
    await post("/admin/v1/plans", { id: "lite", name: "Lite", default_rpm_limit: 5 });
    await post("/admin/v1/tenant-accounts", { id: "acme", plan_id: "pro" });
    expect(rowToPlan((await gatewayPlanRow("acme")) ?? {}).id).toBe("pro");

    await send("PUT", "/admin/v1/tenant-accounts/acme/plan", { plan_id: "lite" });
    // A stale `tenants.plan_id` is how a downgraded tenant keeps the old
    // plan's ceilings.
    expect(rowToPlan((await gatewayPlanRow("acme")) ?? {}).id).toBe("lite");
  });
});

describe("the enforced quota and the reported quota are the SAME quota", () => {
  it("the merge over the PROJECTED rows equals /resolved-defaults", async () => {
    await post("/admin/v1/plans", {
      id: "pro",
      name: "Pro",
      default_rpm_limit: 100,
      default_tpm_limit: 50_000,
      default_monthly_budget_usd: 80,
      default_model_allowlist: ["gpt-4o", "claude-3", "llama-3"],
    });
    await post("/admin/v1/tenant-accounts", { id: "acme", name: "Acme", plan_id: "pro" });
    await post("/admin/v1/projects", { id: "proj-1", name: "P1", tenant_id: "acme" });
    await post("/admin/v1/quota-policies", {
      scope_type: "tenant",
      scope_id: "acme",
      rpm_limit: 60,
      monthly_budget_usd: 25,
      model_allowlist: ["gpt-4o", "claude-3"],
    });
    await post("/admin/v1/quota-policies", {
      scope_type: "project",
      scope_id: "proj-1",
      rpm_limit: 20,
      model_allowlist: ["gpt-4o"],
    });

    // What the gateway would enforce: the rows it actually reads, merged by the
    // function it actually runs.
    const policies = new Map<string, StoredQuotaPolicy>();
    for (const [kind, id] of [
      ["tenant", "acme"],
      ["project", "proj-1"],
    ] as const) {
      const row = await gatewayPolicyRow(kind, id);
      expect(row).not.toBeNull();
      policies.set(`${kind}:${id}`, rowToPolicy(row as Record<string, unknown>));
    }
    const planRow = await gatewayPlanRow("acme");
    expect(planRow).not.toBeNull();
    const enforced = resolveEffectiveQuota(
      { tenantId: "acme", projectId: "proj-1" },
      (kind, id) => policies.get(`${kind}:${id}`),
      rowToPlan(planRow as Record<string, unknown>),
    );

    // The min-across-the-chain answers, taken from the projected rows alone.
    expect(enforced.rpmLimit).toBe(20);
    expect(enforced.monthlyBudgetUsd).toBe(25);
    expect(enforced.tpmLimit).toBe(50_000);
    expect(enforced.modelAllowlist).toEqual(["gpt-4o"]);

    // …and what the operator is TOLD, computed from the documents.
    const reported = await resolvedDefaults("acme");
    const wire = (
      await SELF.fetch(
        `${BASE}/admin/v1/tenant-accounts/acme/resolved-defaults?project_id=proj-1`,
        { headers: bearer(KEY) },
      )
    ).json() as Promise<Record<string, unknown>>;
    const reportedWithProject = (await wire).effective_quota as Record<string, unknown>;

    expect(reportedWithProject.rpm_limit).toBe(enforced.rpmLimit);
    expect(reportedWithProject.tpm_limit).toBe(enforced.tpmLimit);
    expect(reportedWithProject.monthly_budget_usd).toBe(enforced.monthlyBudgetUsd);
    expect(reportedWithProject.model_allowlist).toEqual(enforced.modelAllowlist);
    // The tenant-only view agrees too (the project leg is not folded in
    // unasked): 60 from the tenant policy, not 20 from the project's.
    expect((reported.effective_quota as Record<string, unknown>).rpm_limit).toBe(60);
  });
});
