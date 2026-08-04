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
import { LIFECYCLE_STATUS_ALL, type LifecycleStatus } from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { StoreConflictError, type StoreRecord } from "../ports.js";
import { adminDeleted, adminItem } from "../responses.js";
import { projectTenantAccount, storedPlan, storedQuotaPolicy } from "../store/quota_registry.js";
import {
  deleteProjectRow,
  deleteWorkspaceRow,
  projectTenantRow,
  referencedConflict,
  tenantDatabaseFor,
  tenantOf,
  workspaceTenantRow,
} from "../store/tenancy.js";
import { provisionTenantStorageFor } from "../store/tenant_storage.js";
import {
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

/**
 * Rust `LifecycleStatus` — the vocabulary itself comes from
 * `@ferrogate/storage`'s `lifecycle-status.ts`, which is the port of
 * `ferrogate-storage::lifecycle_status` and the one place the closed set is
 * defined. It used to be re-spelled here; two copies of a closed vocabulary
 * drift, and the direction that bites is the WRITE side accepting a token the
 * read side does not recognize (which then parses to `active` and silently
 * un-suspends the tenancy).
 */
export const LIFECYCLE_STATUSES = LIFECYCLE_STATUS_ALL;
export const lifecycleStatusSchema = z.enum(
  LIFECYCLE_STATUS_ALL as unknown as [LifecycleStatus, ...LifecycleStatus[]],
);

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
// These two decoders MOVED to `../store/quota_registry.ts` and are re-exported
// here unchanged, so every existing importer keeps working. The move is not
// tidying: that module now also PROJECTS the same documents into the typed
// `plans` / `quota_policies` / `tenants` rows the gateway's admission gate
// reads, and it builds the row from the value these functions return. One
// decode therefore feeds both the admin answer and the enforced row — a second
// document→column mapping is exactly how "the console says 60 rpm and the
// gateway enforces something else" happens.

export { storedPlan, storedQuotaPolicy };

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

// ---------------------------------------------------------------------------
// The per-tenant D1 projection (see `src/store/tenancy.ts`)
// ---------------------------------------------------------------------------

/**
 * Create the admin document, then project it into the owning tenant's database.
 *
 * The document goes FIRST and is the arbiter: its `(kind, id)` primary key is
 * what turns a duplicate into the 409 the surface has always returned, and the
 * tenant row's upsert cannot report one. See `src/store/tenancy.ts` for why
 * this ordering (and not the reverse) is the one whose crash state is benign.
 *
 * A tenant with no provisioned database projects nothing and behaves exactly as
 * before — which is every deployment that has not onboarded a tenant database,
 * so this cannot regress one.
 */
function createHierarchyRow(options: {
  readonly collection: string;
  readonly object: string;
  readonly schema: z.ZodTypeAny;
  readonly project: (
    handle: Awaited<ReturnType<typeof tenantDatabaseFor>> & object,
    record: StoreRecord,
    nowUnix: number,
  ) => Promise<void>;
}): Handler {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const body = (await readJson(c, options.schema)) as Record<string, unknown>;
    const declared = body.id;
    const id =
      typeof declared === "string" && declared.trim() !== ""
        ? declared.trim()
        : crypto.randomUUID();

    let stored: StoreRecord;
    try {
      stored = await deps.store.create(options.collection, scope, { ...body, id });
    } catch (error) {
      if (error instanceof StoreConflictError) {
        throw new HttpError(409, "conflict", `${options.object} ${id} already exists`);
      }
      throw error;
    }

    const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantOf(stored));
    if (handle !== null) {
      await options.project(handle, stored, Math.floor(Date.now() / 1000));
    }
    return json(c, 201, adminItem(options.object, stored));
  };
}

/**
 * Delete through `@ferrogate/storage`'s §1.5.7 reference-guarded delete, then
 * drop the admin document.
 *
 * The guarded tenant-database delete goes FIRST, because it is the one that can
 * REFUSE: removing the document first and then discovering a live workspace
 * would leave the operator with a project they can no longer see and a
 * `projects` row the data plane still reads. A refusal here is a 409 that names
 * the blockers and leaves both rows exactly as they were.
 */
function deleteHierarchyRow(options: {
  readonly collection: string;
  readonly object: string;
  readonly param: string;
  readonly guardedDelete: (
    handle: Awaited<ReturnType<typeof tenantDatabaseFor>> & object,
    id: string,
  ) => Promise<{ readonly kind: string; readonly [field: string]: unknown }>;
}): Handler {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const id = pathParam(c, options.param);

    // Read through the CALLER's scope first, so a tenant-scoped caller cannot
    // reach another tenant's row — and so the tenant we route to is the row's
    // own, never the caller's.
    const existing = await deps.store.get(options.collection, scope, id);
    if (existing === null) {
      throw new HttpError(404, "not_found", `${options.object} ${id} not found`);
    }

    const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantOf(existing));
    if (handle !== null) {
      const outcome = await options.guardedDelete(handle, id);
      if (outcome.kind === "referenced") {
        throw referencedConflict(options.object, id, {
          workspaces: Number(outcome.workspaces ?? 0),
          "virtual keys": Number(outcome.virtualKeys ?? 0),
        });
      }
      // `not_found` in the tenant database is NOT a 404: the admin document
      // exists and is what the operator asked to delete. It means the typed row
      // was never projected (a document predating this seam, or a crash between
      // the two legs), and the document delete below is still owed.
    }

    const removed = await deps.store.remove(options.collection, scope, id);
    if (!removed) throw new HttpError(404, "not_found", `${options.object} ${id} not found`);
    return json(c, 200, adminDeleted(options.object, id));
  };
}

export const tenantHierarchyRoutes: GroupModule = crudGroup(
  "tenant_hierarchy",
  [
    { segment: "projects", object: "project", body: projectSchema },
    { segment: "workspaces", object: "workspace", body: workspaceSchema },
    // The typed `tenants` row is the LEFT side of the gateway's plan join
    // (`JOIN plans p ON t.plan_id = p.id`): without it a tenant resolves to no
    // plan and therefore no floor, whatever `PUT …/plan` recorded in the
    // document. See `store/quota_registry.ts`.
    {
      segment: TENANT_ACCOUNTS,
      object: "tenant_account",
      body: tenantAccountSchema,
      project: projectTenantAccount,
      // #820. A tenant's data plane is its own Durable Object, and the object is
      // created by being addressed — so onboarding is "record the tenant on the
      // roster and seed its model catalog", and nothing did either. Declared on
      // the SPEC so POST, PUT and PATCH all run it: PUT/PATCH cannot create a
      // tenant, but they are the repair points for one whose provisioning failed.
      provision: (deps, record) => provisionTenantStorageFor(deps, String(record.id)),
    },
    /**
     * PORT-TODO(P: cert2-controlplane §CLASS-A tenant_hierarchy GET /tenants) —
     * CLASS A REGRESSION, and the ONE non-equivalent operation in this
     * otherwise-equivalent 20-operation group.
     *
     * This pages a `tenants` DOCUMENT collection that no contract operation
     * writes (tenant ACCOUNTS are the separate `tenant-accounts` collection
     * above, and the typed `tenants` TABLE is written by `projectTenantAccount`,
     * not by this document store). It therefore answers an empty `AdminList` on
     * every deployment.
     *
     * Rust `local.rs::handle_admin_tenants` (9288) answers a DERIVED view:
     * `state.tenant_refs()` (`state_tools.rs:28`) projects every configured api
     * key that carries an `organization_id` / `team_id` / `project_id` /
     * `user_id` into an `AdminTenantRef {organization_id, team_id, project_id,
     * user_id, api_key_id}`, then `filter_by_tenant_scope` fences it to the
     * caller. It is the "which tenancies exist, and through which credential"
     * answer an operator uses to find an unattributed key — a real, complete,
     * non-stub handler.
     *
     * Closing it needs no new binding: the same projection is derivable here
     * from `api_key_directory` ⋈ `static_api_keys` in the CONTROL database,
     * which `store/api_keys.ts` and `store/virtual_keys.ts` already write. Carry
     * the fence: Rust filters by STRICT tenant equality, so an un-attributed
     * platform key must not appear for a tenant-scoped caller.
     */
    readOnlyCollection("tenants", "tenant"),
  ],
  {
    createProject: createHierarchyRow({
      collection: "projects",
      object: "project",
      schema: projectSchema,
      project: projectTenantRow,
    }),
    deleteProject: deleteHierarchyRow({
      collection: "projects",
      object: "project",
      param: "project_id",
      guardedDelete: deleteProjectRow,
    }),
    createWorkspace: createHierarchyRow({
      collection: "workspaces",
      object: "workspace",
      schema: workspaceSchema,
      project: workspaceTenantRow,
    }),
    deleteWorkspace: deleteHierarchyRow({
      collection: "workspaces",
      object: "workspace",
      param: "workspace_id",
      guardedDelete: deleteWorkspaceRow,
    }),

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
      // This route is an OVERRIDE, so the spec's `project` hook does not run for
      // it. Projecting here is not optional: assigning a plan and leaving
      // `tenants.plan_id` stale is the single change most likely to make the
      // console and the gateway disagree, because it is the ONLY route that
      // moves a tenant between plans.
      const db = deps.controlDatabase;
      if (db !== null) {
        await projectTenantAccount(db, stored, Math.floor(Date.now() / 1000));
      }
      // #820, and for the same "this route is an OVERRIDE, so the spec hooks do
      // not run for it" reason as the projection above. This route cannot create
      // a tenant, but it IS the route that retroactively materialises the typed
      // `tenants` row of a self-registered tenant — so it is exactly the moment a
      // tenant whose storage provisioning was refused for want of that row
      // becomes provisionable, and repairing it here costs one idempotent call.
      await provisionTenantStorageFor(deps, tenantId);
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
