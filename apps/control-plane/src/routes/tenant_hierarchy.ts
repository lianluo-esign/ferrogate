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
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { adminItem } from "../responses.js";
import {
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  readOnlyCollection,
  scopeOf,
  type GroupModule,
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
     * (tenant → project → workspace) Rust performs in `finalize_auth`.
     *
     * PORT-TODO(inventory-policy-core §quota resolution): compose the real
     * `EffectiveQuota` via `@ferrogate/policy` once it lands. The chain that IS
     * resolvable here — the tenant row and its plan — is resolved honestly, and
     * the response names the levels it consulted so a caller can tell what was
     * and was not applied.
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
      const plan = planId === null ? null : await deps.store.get("plans", scope, planId);
      const quotaPolicy = await deps.store.get("quota-policies", scope, `tenant:${tenantId}`);

      return json(c, 200, {
        object: "resolved_defaults",
        tenant_id: tenantId,
        plan_id: planId,
        resolved_from: [
          "tenant_account",
          ...(plan === null ? [] : ["plan"]),
          ...(quotaPolicy === null ? [] : ["quota_policy"]),
        ],
        plan,
        quota_policy: quotaPolicy,
        status: tenant.status ?? "active",
      });
    },
  },
);
