/**
 * Contract group `tenant_hierarchy` (20 operations) — the biggest group in the
 * app: tenant accounts, projects, workspaces, and the read-only tenant listing.
 *
 * ```
 *   GET/POST                      /admin/v1/projects        + GET/PUT/PATCH/DELETE /{project_id}
 *   GET/POST                      /admin/v1/workspaces      + GET/PUT/PATCH/DELETE /{workspace_id}
 *   GET/POST                      /admin/v1/tenant-accounts + GET/PUT/PATCH /{tenant_id}
 *   PUT                           /admin/v1/tenant-accounts/{tenant_id}/plan
 *   GET                           /admin/v1/tenant-accounts/{tenant_id}/resolved-defaults
 *   GET                           /admin/v1/tenants
 * ```
 *
 * **A tenant account has no DELETE.** The contract declares create/read/replace/
 * patch only, because tenancy teardown is a lifecycle *status* transition
 * (`active` → `suspended` → `deleted`), not a row removal — deleting the row
 * would orphan every project, workspace, key, quota and billing record that
 * references it. That is why `updateTenantAccount` accepts a `status` and why
 * `crudGroup` registers no DELETE here: `DELETE /admin/v1/tenant-accounts/{id}`
 * is a 405, which is the correct answer.
 *
 * Issue #514, finding 5, is why the *recovery* direction matters: a tenant that
 * used its self-service `disabled` switch must still be able to reverse it, so
 * the status PATCH/PUT must not be gated behind a check that the tenancy is
 * currently admitted. On this Worker the lifecycle gate is a port
 * (`TenancyLifecycleGatePort.admit`), which receives the operation and can
 * therefore admit `disabled` for exactly these reversal routes — the narrow
 * carve-out Rust calls `LifecycleSeam::Recovery`.
 */
import {
  type EffectiveQuota,
  type QuotaScopeKind,
  type StoredPlan,
  type StoredQuotaPolicy,
  isDenied,
  resolveEffectiveQuota,
} from "@ferrogate/policy";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";
import { adminItem } from "../responses.js";
import {
  type GroupModule,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

/** Rust `LifecycleStatus`. */
export const LIFECYCLE_STATUSES = ["active", "disabled", "suspended", "deleted"] as const;
export const lifecycleStatusSchema = z.enum(LIFECYCLE_STATUSES);

export const tenantAccountSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  status: lifecycleStatusSchema.optional(),
  plan_id: z.string().trim().min(1).nullish(),
});

export const projectSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  status: lifecycleStatusSchema.optional(),
});

export const workspaceSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  project_id: z.string().trim().min(1).optional(),
  status: lifecycleStatusSchema.optional(),
});

/** Rust: assigning a plan is a PUT of the plan reference, not a tenant patch. */
export const tenantPlanAssignmentSchema = z.object({
  plan_id: z.string().trim().min(1),
  effective_at: z.number().int().min(0).optional(),
});

const TENANT_ACCOUNTS = "tenant-accounts";
const QUOTA_POLICIES = "quota-policies";
const PLANS = "plans";

// ---------------------------------------------------------------------------
// Stored document → `@ferrogate/policy` value types
// ---------------------------------------------------------------------------
//
// The field names below are the COLUMN names of `quota_policies` / `plans` in
// `sql/d1-ts/control/0001_init_control.sql`, not names invented here: the admin
// documents this app stores are the same shape those tables hold, so a document
// written through `POST /admin/v1/quota-policies` and a row projected out of
// `quota_policies` read identically. `@ferrogate/policy` is camelCase (it is the
// Rust value type, not the wire/row shape), so this is the one place the two
// vocabularies meet.

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

/** `quota_policies` row/document → `StoredQuotaPolicy`. */
export function storedQuotaPolicy(
  record: StoreRecord,
  scopeType: QuotaScopeKind,
  scopeId: string,
): StoredQuotaPolicy {
  return {
    id: record.id,
    scopeType,
    scopeId,
    modelAllowlist: stringArray(record.model_allowlist),
    rpmLimit: optionalNumber(record.rpm_limit),
    tpmLimit: optionalNumber(record.tpm_limit),
    monthlyBudgetUsd: optionalNumber(record.monthly_budget_usd),
    assetStorageQuotaBytes: optionalNumber(record.asset_storage_quota_bytes),
    assetMaxObjectBytes: optionalNumber(record.asset_max_object_bytes),
    agentCostBudgetUsd: optionalNumber(record.agent_cost_budget_usd),
    alertThresholdPcts: Array.isArray(record.alert_threshold_pcts)
      ? record.alert_threshold_pcts.filter((pct): pct is number => typeof pct === "number")
      : [],
    // ABSENT means "this scope does not restrict", which is NOT the same as
    // `enabled = false` (a hard deny for the whole chain). Only an explicit
    // `false` disables.
    enabled: record.enabled !== false,
    createdAtUnix: optionalNumber(record.created_at) ?? 0,
    updatedAtUnix: optionalNumber(record.updated_at) ?? 0,
    monthlyEgressBytesBudget: optionalNumber(record.monthly_egress_bytes_budget),
    downloadRpmLimit: optionalNumber(record.download_rpm_limit),
  };
}

/** `plans` row/document → `StoredPlan` (the merge FLOOR, issue #168). */
export function storedPlan(record: StoreRecord): StoredPlan {
  return {
    id: record.id,
    name: typeof record.name === "string" ? record.name : record.id,
    slug: typeof record.slug === "string" ? record.slug : record.id,
    mcpEnabled: record.mcp_enabled === true,
    selfHostedWorkersEnabled: record.self_hosted_workers_enabled === true,
    adminConsoleSeats: optionalNumber(record.admin_console_seats),
    defaultModelAllowlist: stringArray(record.default_model_allowlist),
    defaultRpmLimit: optionalNumber(record.default_rpm_limit),
    defaultTpmLimit: optionalNumber(record.default_tpm_limit),
    defaultMonthlyBudgetUsd: optionalNumber(record.default_monthly_budget_usd),
    createdAtUnix: optionalNumber(record.created_at) ?? 0,
    updatedAtUnix: optionalNumber(record.updated_at) ?? 0,
    assetHostingEnabled: record.asset_hosting_enabled === true,
    defaultAssetStorageQuotaBytes: optionalNumber(record.default_asset_storage_quota_bytes),
    defaultAssetMaxObjectBytes: optionalNumber(record.default_asset_max_object_bytes),
    defaultAgentCostBudgetUsd: optionalNumber(record.default_agent_cost_budget_usd),
    defaultMonthlyEgressBytesBudget: optionalNumber(record.default_monthly_egress_bytes_budget),
    defaultDownloadRpmLimit: optionalNumber(record.default_download_rpm_limit),
    extensionToolsEnabled: record.extension_tools_enabled === true,
  };
}

/**
 * `EffectiveQuota` → the admin wire shape.
 *
 * Every capped dimension reports BOTH the value and the scope that supplied it
 * (`"tenant:acme"`), because "your rpm limit is 60" is not actionable without
 * "…and it comes from the project policy, not your key's". That pairing is the
 * whole reason `resolveEffectiveQuota` tracks a `QuotaScopeSelector` per
 * dimension rather than just min-ing numbers.
 */
function effectiveQuotaWire(quota: EffectiveQuota): Record<string, unknown> {
  const scope = (selector: { kind: string; id: string } | undefined) =>
    selector === undefined ? null : `${selector.kind}:${selector.id}`;
  return {
    // `undefined` (no scope restricts models) is reported as `null`, distinct
    // from `[]` (every scope's intersection is empty ⇒ NO model is allowed).
    model_allowlist: quota.modelAllowlist ?? null,
    rpm_limit: quota.rpmLimit ?? null,
    rpm_limit_scope: scope(quota.rpmLimitScope),
    tpm_limit: quota.tpmLimit ?? null,
    tpm_limit_scope: scope(quota.tpmLimitScope),
    monthly_budget_usd: quota.monthlyBudgetUsd ?? null,
    monthly_budget_scope: scope(quota.monthlyBudgetScope),
    agent_cost_budget_usd: quota.agentCostBudgetUsd ?? null,
    agent_cost_budget_scope: scope(quota.agentCostBudgetScope),
    asset_storage_quota_bytes: quota.assetStorageQuotaBytes ?? null,
    asset_max_object_bytes: quota.assetMaxObjectBytes ?? null,
    monthly_egress_bytes_budget: quota.monthlyEgressBytesBudget ?? null,
    monthly_egress_bytes_scope: scope(quota.monthlyEgressBytesScope),
    download_rpm_limit: quota.downloadRpmLimit ?? null,
    download_rpm_limit_scope: scope(quota.downloadRpmLimitScope),
    // A disabled policy ANYWHERE in the chain is a hard deny; the caller must
    // fail closed, so it is reported as its own field rather than as an absent
    // limit.
    denied: isDenied(quota),
    denied_by: quota.deniedBy ?? null,
  };
}

export const tenantHierarchyRoutes: GroupModule = crudGroup(
  "tenant_hierarchy",
  [
    { segment: "projects", object: "project", body: projectSchema },
    { segment: "workspaces", object: "workspace", body: workspaceSchema },
    { segment: TENANT_ACCOUNTS, object: "tenant_account", body: tenantAccountSchema },
    readOnlyCollection("tenants", "tenant"),
  ],
  {
    assignTenantPlan: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      const body = await readJson(c, tenantPlanAssignmentSchema);

      // The plan must exist: silently attaching a dangling plan reference is
      // how a tenant ends up billed against nothing.
      if ((await deps.store.get("plans", scope, body.plan_id)) === null) {
        throw new HttpError(404, "not_found", `plan ${body.plan_id} not found`);
      }
      const stored = await deps.store.merge(TENANT_ACCOUNTS, scope, tenantId, {
        plan_id: body.plan_id,
        plan_effective_at: body.effective_at ?? Math.floor(Date.now() / 1000),
      });
      if (stored === null) {
        throw new HttpError(404, "not_found", `tenant account ${tenantId} not found`);
      }
      return json(c, 200, adminItem("tenant_account", stored));
    },

    /**
     * The tenant's effective settings after the multi-level resolution chain
     * Rust performs in `finalize_auth`, composed by `@ferrogate/policy`'s
     * `resolveEffectiveQuota` — the SAME function the data plane resolves a
     * live request's quota with, so the number an operator reads here is the
     * number that will actually be enforced. A second implementation of the
     * merge in this handler is how "the console says 60 rpm and the gateway
     * enforces 20" happens.
     *
     * The chain is the tenant by default, and is DEEPENED only by what the
     * caller names: `?project_id=`, `?workspace_id=`, `?key_id=`. Folding in
     * every project the tenant happens to own would be wrong in the direction
     * that matters — the merge is `min`-across-the-chain, so one tight project
     * policy would be reported as the tenant's default and an operator would
     * read a limit no tenant-level request is subject to. What is not named is
     * not resolved.
     *
     * `resolveEffectiveQuota` takes its policies through an injected lookup, so
     * every row is fetched up front through the caller's scope and the merge
     * itself does no I/O — the policy package stays pure and the tenant fence
     * stays in the store. The named project/workspace are read through the
     * CALLER's scope, so a tenant cannot deepen its chain with another tenant's
     * project id: the read returns nothing and the level is reported as
     * unresolved rather than silently applied.
     */
    getTenantResolvedDefaults: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      const tenant = await deps.store.get(TENANT_ACCOUNTS, scope, tenantId);
      if (tenant === null) {
        throw new HttpError(404, "not_found", `tenant account ${tenantId} not found`);
      }
      const planId = typeof tenant.plan_id === "string" ? tenant.plan_id : null;
      const planRecord = planId === null ? null : await deps.store.get(PLANS, scope, planId);

      // The chain the caller asked for. A named level that does not resolve to
      // a row VISIBLE TO THIS CALLER is dropped from the chain and reported as
      // unresolved — never silently treated as "no policy at that level", which
      // would loosen the answer.
      const params = new URL(c.req.url).searchParams;
      const chain: { tenantId: string; projectId?: string; workspaceId?: string; keyId?: string } =
        { tenantId };
      const unresolved: string[] = [];
      for (const [param, collection, field] of [
        ["project_id", "projects", "projectId"],
        ["workspace_id", "workspaces", "workspaceId"],
        ["key_id", "virtual-keys", "keyId"],
      ] as const) {
        const asked = params.get(param)?.trim();
        if (asked === undefined || asked === "") continue;
        if ((await deps.store.get(collection, scope, asked)) === null) {
          unresolved.push(param);
          continue;
        }
        chain[field] = asked;
      }

      const levels: [QuotaScopeKind, string | undefined][] = [
        ["tenant", chain.tenantId],
        ["project", chain.projectId],
        ["workspace", chain.workspaceId],
        ["key", chain.keyId],
      ];
      const policies = new Map<string, StoredQuotaPolicy>();
      for (const [kind, id] of levels) {
        if (id === undefined) continue;
        const record = await deps.store.get(QUOTA_POLICIES, scope, `${kind}:${id}`);
        if (record !== null) policies.set(`${kind}:${id}`, storedQuotaPolicy(record, kind, id));
      }

      const plan = planRecord === null ? undefined : storedPlan(planRecord);
      const effective = resolveEffectiveQuota(
        chain,
        (kind, id) => policies.get(`${kind}:${id}`),
        plan,
      );

      return json(c, 200, {
        object: "resolved_defaults",
        tenant_id: tenantId,
        plan_id: planId,
        resolved_from: [
          "tenant_account",
          ...(planRecord === null ? [] : ["plan"]),
          ...[...policies.keys()].sort().map((key) => `quota_policy:${key}`),
        ],
        /** Levels the caller named that resolved to no visible row. */
        unresolved_scopes: unresolved,
        plan: planRecord,
        // The tenant-scope policy row, unchanged, for callers that were reading
        // it before the merge existed.
        quota_policy: policies.has(`tenant:${tenantId}`)
          ? await deps.store.get(QUOTA_POLICIES, scope, `tenant:${tenantId}`)
          : null,
        effective_quota: effectiveQuotaWire(effective),
        status: tenant.status ?? "active",
      });
    },
  },
);
