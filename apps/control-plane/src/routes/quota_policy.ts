/**
 * Contract group `quota_policy` (6 operations).
 *
 * ```
 *   GET/POST                 /admin/v1/quota-policies
 *   GET/PUT/PATCH/DELETE     /admin/v1/quota-policies/{scope_type}/{scope_id}
 * ```
 *
 * The item path is a **two-segment composite key**, not an opaque id — a quota
 * policy is identified by what it applies to. `scope_type` is the Rust
 * `QuotaScopeKind` (`tenant` | `project` | `workspace` | `key`), and the
 * enum is validated at the route so an unknown scope kind is a 404 rather than
 * a lookup against a collection that cannot exist.
 *
 * ## 0. Reading a quota is one authority; SETTING it is another (#782)
 *
 * The reads and the writes do NOT share a fence. {@link authorizeScopedResource}
 * asks "does this scope resolve to MY tenant?", which is the right question for
 * a read and, for a write, is the escalation itself: the answer being "yes"
 * means the caller is the party the limit is imposed on. A quota the
 * quota-holder can raise is not a quota. Every write leg therefore runs
 * {@link authorizeScopedResourceWrite} — operator only, all four scope kinds,
 * including `DELETE` and including a LOWERING edit; that function states why
 * each of those is deliberate rather than a hammer.
 *
 * ## 1. Resolution failure denies (#185)
 *
 * The read authorization is the one Rust factored into
 * `auth::authorize_scoped_resource`: a scope that is not already a bare tenant
 * id must be RESOLVED to its owning tenant before a tenant-scoped caller may
 * touch it, and **resolution failure denies**. Both "the row is absent" and
 * "the store is unavailable" collapse to `None` in Rust, and `None` can never
 * equal the caller's tenant — so a storage blip denies rather than granting.
 * "Nonexistent means safe to touch" is explicitly the wrong default, and that is
 * reproduced exactly below.
 *
 * ## 2. The sibling fences, swept — where the next reader should look
 *
 * #782 is the SECOND instance of "a read-shaped fence authorising a write"
 * (#743's asset review verb was the first), so the whole family was probed
 * rather than reasoned about. Recorded here because a sweep whose result lives
 * only in a merged PR body is a sweep the next reader repeats:
 *
 *  - `wallets.ts::authorizeWalletTenant` — **the same defect, on money, filed as
 *    #790.** `walletAdjustSchema.amount_cents` is SIGNED and the module calls
 *    `adjust` an "operator movement", but the fence is the read's: a tenant
 *    `admin.write` key `POST`ing `/admin/v1/wallets/{its own id}/adjust` with
 *    `+10_000_000` answered `200` and took `balance_cents` 500 → 10_000_500,
 *    projecting `balance_credits` the gateway spends. Not fixed here: this file
 *    is the quota surface, and whether a NEGATIVE self-adjustment stays open is
 *    a product decision that deserves its own argument. `PATCH /wallets/{id}`
 *    is NOT affected — the balance-move guard already holds it.
 *  - `rbac.ts::authorizeTenantPath` — **same shape, filed as #791.** A tenant
 *    key can `POST /admin/v1/roles` a role with `permissions: ["*"]` (the store
 *    stamps its tenant) and bind it to itself, and `D1RbacAuthorizer` allows on
 *    `granted.has("*")`. Blast radius is that tenant's own RBAC-gated verbs —
 *    today the twelve guardrail operations, `activate` and `archive` among them.
 *    Left open deliberately: tenant self-service RBAC may be intended, which
 *    #782's fence cannot decide for it.
 *  - `billing.ts::authorizeReportTenant` — **correct as-is.** Sharing is fine
 *    here because replay moves nothing the caller can choose: it clears a
 *    dead-letter mark so the gateway's sweeper retries, idempotently on the
 *    report id, which pushes a charge TOWARDS landing. There is no field a
 *    tenant can raise, and it already runs before the CAS.
 *  - `admin_semantic_cache.ts`'s copy of `authorizeScopedResource` — **same
 *    shape, left alone on purpose.** A tenant `PUT`/`DELETE` on its own policy
 *    answers `200`, but every knob there governs only that tenant's own traffic
 *    and its own spend, and caching lowers cost rather than escaping a cap. The
 *    one question that would change this is whether an operator ever sets
 *    `enabled: false` there as a COMPLIANCE decision (no cross-request reuse for
 *    a regulated tenant) — if that is ever true, this becomes the same defect
 *    and needs the same split.
 */

import {
  ControlDatabaseTenantRegistry,
  tenantJurisdictionForResidencyRegions,
} from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import {
  type CallerScope,
  type ControlPlaneStore,
  StoreConflictError,
  type StoreRecord,
} from "../ports.js";
import { adminDeleted, adminItem } from "../responses.js";
import { deleteQuotaPolicyRow, projectQuotaPolicy } from "../store/quota_registry.js";
import {
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

/** Rust `QuotaScopeKind`. */
export const QUOTA_SCOPE_KINDS = ["tenant", "project", "workspace", "key"] as const;
export const quotaScopeKindSchema = z.enum(QUOTA_SCOPE_KINDS);
export type QuotaScopeKind = (typeof QUOTA_SCOPE_KINDS)[number];

/** Collection each scope kind resolves its owning tenant from. */
const SCOPE_COLLECTION: Readonly<Record<QuotaScopeKind, string | null>> = {
  tenant: null, // the scope id IS the tenant id
  project: "projects",
  workspace: "workspaces",
  key: "virtual-keys",
};

export const quotaPolicySchema = adminRecordSchema.extend({
  scope_type: quotaScopeKindSchema.optional(),
  scope_id: z.string().trim().min(1).optional(),
  rpm_limit: z.number().int().min(0).nullish(),
  monthly_token_budget: z.number().int().min(0).nullish(),
  enabled: z.boolean().optional(),
  /**
   * #678 — the `metadata` tag KEYS every request from this scope must carry,
   * and what to do when one is missing. Read by the gateway at the `tenant`
   * scope only (`apps/gateway/src/attribution/source.ts` states why).
   *
   * `on_missing_tags` has no default and is not inferred from
   * `required_tags`: the issue asks for the operator's choice to be EXPLICIT,
   * so a document that lists required tags without naming an action enforces
   * nothing. Both the projection and the gateway reader make that same
   * judgement, from opposite ends.
   */
  required_tags: z.array(z.string().trim().min(1)).optional(),
  on_missing_tags: z.enum(["reject", "default_from_key"]).nullish(),
  residency_regions: z.array(z.string().trim().min(1)).optional(),
  require_zero_data_retention: z.boolean().optional(),
  log_residency: z.enum(["in_region", "unconstrained"]).nullish(),
  /**
   * #697 — the spend burn-rate detector's tuning, at the `tenant` scope only
   * (`apps/control-plane/src/finops/pass.ts` states why a per-key baseline is
   * noise rather than sensitivity).
   *
   * Named here rather than left to `adminRecordSchema`'s `passthrough()`
   * because the passthrough would ACCEPT `spend_anomaly_ratio: "four"` and the
   * projection would then bind `NULL` and fall back to the default — an
   * operator who believes they raised the bar, silently still at 4x, with a
   * 200 in hand. A typed refusal is the only version of that an operator can
   * act on.
   *
   * `.nullish()` throughout: `null` is a real value here and means "back to the
   * documented default", which is the only way to UNDO a tuning through a JSON
   * merge patch.
   */
  spend_anomaly_enabled: z.boolean().optional(),
  spend_anomaly_baseline_windows: z.number().int().min(1).max(168).nullish(),
  spend_anomaly_min_baseline_windows: z.number().int().min(0).nullish(),
  spend_anomaly_min_active_windows: z.number().int().min(0).nullish(),
  spend_anomaly_min_window_usd: z.number().min(0).nullish(),
  spend_anomaly_ratio: z.number().min(1).nullish(),
  spend_anomaly_critical_ratio: z.number().min(1).nullish(),
  spend_anomaly_cooldown_secs: z.number().int().min(60).nullish(),
  spend_anomaly_forecast_min_pct: z.number().min(0).max(100).nullish(),
  spend_anomaly_auto_throttle_rpm: z.number().int().min(1).nullish(),
  spend_anomaly_throttle_ttl_secs: z.number().int().min(60).nullish(),
});

const QUOTA_POLICIES = "quota-policies";

/** Composite `(scope_type, scope_id)` flattened to the store's string id. */
export function quotaPolicyId(scopeType: string, scopeId: string): string {
  return `${scopeType}:${scopeId}`;
}

/**
 * Project the committed policy document into the typed `quota_policies` row.
 *
 * Every leg of this group is an OVERRIDE, so the `CollectionSpec.project` hook
 * the generic handlers run never fires here — the projection has to be called
 * on each write explicitly, and forgetting one leg is a policy the operator
 * edited and the gateway kept enforcing at the old numbers.
 *
 * This is the row `apps/gateway`'s `d1QuotaPolicySource` matches with
 * `(scope_type = ? AND scope_id = ?)` on the admission path of every
 * authenticated request. Until it existed, `resolveEffectiveQuota` merged an
 * empty chain, which is not "the default limits" — it is NO rpm cap, NO tpm
 * cap, NO monthly budget and NO model allowlist.
 */
async function projectPolicy(
  c: Parameters<Handler>[0],
  record: Record<string, unknown>,
  scopeType: QuotaScopeKind,
  scopeId: string,
): Promise<void> {
  const db = depsOf(c).controlDatabase;
  if (db === null) return;
  await projectQuotaPolicy(
    db,
    record as Parameters<typeof projectQuotaPolicy>[1],
    scopeType,
    scopeId,
    Math.floor(Date.now() / 1000),
  );
}

function readScope(c: Parameters<Handler>[0]): { scopeType: QuotaScopeKind; scopeId: string } {
  const parsed = quotaScopeKindSchema.safeParse(pathParam(c, "scope_type"));
  if (!parsed.success) {
    // An unknown scope kind names no resource — 404, like Rust's route miss.
    throw new HttpError(404, "not_found", `no route for ${c.req.method} ${c.req.path}`);
  }
  return { scopeType: parsed.data, scopeId: pathParam(c, "scope_id") };
}

function residencyRegionsOf(record: { readonly residency_regions?: unknown }): string[] {
  return Array.isArray(record.residency_regions)
    ? record.residency_regions.filter((region): region is string => typeof region === "string")
    : [];
}

const QUOTA_SCOPE_OWNER_COLLECTION: Readonly<Record<QuotaScopeKind, string | null>> = {
  tenant: null,
  project: "projects",
  workspace: "workspaces",
  key: "virtual-keys",
};

/** Resolve the tenant object that owns a tenant-private quota document. */
async function quotaPolicyTenantId(
  deps: ReturnType<typeof depsOf>,
  scopeType: QuotaScopeKind,
  scopeId: string,
  record: { readonly tenant_id?: unknown },
): Promise<string> {
  if (scopeType === "tenant") return scopeId;
  if (typeof record.tenant_id === "string" && record.tenant_id.trim() !== "") {
    return record.tenant_id.trim();
  }

  const collection = QUOTA_SCOPE_OWNER_COLLECTION[scopeType];
  if (collection === null) return scopeId;
  const owner = await deps.store.get(collection, { kind: "platform_operator" }, scopeId);
  if (typeof owner?.tenant_id === "string" && owner.tenant_id.trim() !== "") {
    return owner.tenant_id.trim();
  }
  throw new HttpError(
    400,
    "invalid_request_body",
    `quota policy scope ${scopeType}/${scopeId} must name an existing tenant owner`,
  );
}

/** Refuse a policy update that would name a different object namespace. */
async function assertResidencyJurisdiction(
  c: Parameters<Handler>[0],
  scopeType: QuotaScopeKind,
  scopeId: string,
  record: { readonly residency_regions?: unknown },
): Promise<void> {
  if (scopeType !== "tenant") return;
  const db = c.get("deps").controlDatabase;
  if (db === null) return;

  const required = tenantJurisdictionForResidencyRegions(residencyRegionsOf(record));
  const registration = await new ControlDatabaseTenantRegistry(db).get(scopeId);
  if (registration === undefined) return;

  const materialized =
    registration.locationHint !== undefined ||
    registration.status === "ready" ||
    registration.status === "incomplete" ||
    registration.status === "failed";
  const actual = registration.jurisdiction;
  const mismatch =
    required !== undefined && (actual !== undefined ? required !== actual : materialized);
  if (!mismatch) return;

  const actualLabel = actual ?? "unrestricted";
  const requiredLabel = required ?? "unrestricted";
  throw new HttpError(
    409,
    "tenant_jurisdiction_migration_required",
    `tenant ${scopeId} already has a Durable Object addressed in jurisdiction ${actualLabel}, but this residency policy requires ${requiredLabel}; changing the jurisdiction is part of the object address and requires a data migration`,
  );
}

/**
 * Rust `authorize_scoped_resource`, and the fence for the READ leg only.
 *
 * Fails closed: a tenant-scoped caller is denied both when the resolved tenant
 * differs from its own AND when resolution fails entirely.
 *
 * It is deliberately NOT the fence for a write — see
 * {@link authorizeScopedResourceWrite} and decision 0 in the module header.
 * The question it asks is "is this row MINE?", and for a write the answer being
 * "yes" is precisely the escalation.
 */
async function authorizeScopedResource(
  store: ControlPlaneStore,
  scope: CallerScope,
  scopeType: QuotaScopeKind,
  scopeId: string,
): Promise<void> {
  if (scope.kind === "platform_operator") return;

  let resolvedTenantId: string | null = null;
  const collection = SCOPE_COLLECTION[scopeType];
  if (collection === null) {
    resolvedTenantId = scopeId;
  } else {
    // Deliberately a platform-scoped read: the point is to learn who OWNS the
    // referenced row, which a tenant-filtered read could not tell us apart from
    // "absent". The answer is then compared to the caller's tenant below.
    const owner = await store
      .get(collection, { kind: "platform_operator" }, scopeId)
      .catch(() => null);
    const tenantId = owner?.tenant_id;
    resolvedTenantId = typeof tenantId === "string" ? tenantId : null;
  }

  if (resolvedTenantId !== scope.tenantId) {
    throw new HttpError(
      403,
      "tenant_scope_denied",
      "API key is not authorized to access this tenant's resources",
    );
  }
}

/**
 * The fence for every WRITE leg of this group: **operator only** (#782).
 *
 * A tenant-scoped credential is refused outright, at every scope kind, before
 * any resolution happens. The reasoning, since "all writes are operator-only"
 * is a big hammer and an unnecessary fence is its own cost:
 *
 *  - **Raising is the whole defect.** For `scope_type=tenant` the read fence
 *    resolves the owner as the scope id ITSELF, so a tenant-scoped `admin.write`
 *    key passed it for its own row and could `PUT` itself a new `rpm_limit`,
 *    `monthly_token_budget` or `asset_storage_quota_bytes`. The last is the
 *    ceiling #736's bundle expansion and #737's egress accounting enforce
 *    against, and `packages/policy/src/quota.ts` gives a tenant-scope policy
 *    value PRECEDENCE over the plan default rather than a minimum with it — so
 *    the tenant's own number simply replaced the plan's.
 *  - **The other scope kinds are the same defect**, not a lesser one. The merge
 *    is min-across-the-chain, so an inner rung only tightens *when an outer rung
 *    exists*; against a plan-only tenant (no `tenant` policy row at all), a
 *    `project`/`workspace`/`key` policy the tenant wrote for a scope it owns is
 *    the only rung, and it overrides the plan default outright.
 *  - **Deleting is the largest raise available**, not a self-imposed zero:
 *    `resolveEffectiveQuota` over an empty chain is not "the defaults", it is no
 *    rpm cap, no budget and no allowlist.
 *  - **Lowering is refused too, and that is the judgement call.** "A tenant may
 *    tighten its own limits" is only safe if tightening is DECIDABLE, and on
 *    this document it is not. The same credential that lowered `rpm_limit` can
 *    raise it back a request later, so a value-comparing fence would have to
 *    re-derive the operator's intent on every field, forever: the schema already
 *    carries fields with no monotone direction (`required_tags`,
 *    `on_missing_tags`) and fields where LARGER is looser in the opposite
 *    direction from `rpm_limit` (`spend_anomaly_ratio`,
 *    `spend_anomaly_cooldown_secs`, `spend_anomaly_enabled: false`), and it
 *    grew twelve of them in one slice (#697). A monotonicity table that a newly
 *    added field defaults into the WRONG half of is a silent hole; refusing the
 *    verb has no such failure mode. A tenant that wants to be held to less
 *    belongs on its own self-service budget document the merge takes the
 *    minimum with — a separate row, not the operator's ceiling.
 *
 * Refusing BEFORE resolution is also deliberate: the read fence's cross-scope
 * lookup is a platform-scoped read, so answering `tenant_scope_denied` only for
 * scopes the caller does not own would make the write leg an existence oracle
 * for other tenants' projects and keys. One refusal, one code, no probe.
 *
 * A tenant may still READ its own policy — that read is how it tells a `429`
 * from a bug, and {@link authorizeScopedResource} is unchanged for it.
 */
function authorizeScopedResourceWrite(scope: CallerScope, verb: string): void {
  if (scope.kind === "platform_operator") return;
  throw new HttpError(
    403,
    "quota_policy_write_operator_only",
    `${verb} a quota policy is an operator action: this credential is scoped to tenant ${scope.tenantId}, which may read its own quota policy but may not change the limits it is held to`,
  );
}

export const quotaPolicyRoutes: GroupModule = crudGroup(
  "quota_policy",
  [{ segment: QUOTA_POLICIES, object: "quota_policy", body: quotaPolicySchema }],
  {
    createQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      // Ahead of the body, on purpose: a caller this verb will never admit must
      // not be told which fields its request was missing.
      authorizeScopedResourceWrite(scope, "Creating");
      const body = await readJson(c, quotaPolicySchema);
      const parsedType = quotaScopeKindSchema.safeParse(body.scope_type);
      if (!parsedType.success || body.scope_id === undefined) {
        throw new HttpError(
          400,
          "invalid_request_body",
          "scope_type (tenant|project|workspace|key) and scope_id are required",
        );
      }

      const id = quotaPolicyId(parsedType.data, body.scope_id);
      await assertResidencyJurisdiction(c, parsedType.data, body.scope_id, body);
      try {
        const tenantId = await quotaPolicyTenantId(deps, parsedType.data, body.scope_id, body);
        const stored = await deps.store.create(QUOTA_POLICIES, scope, {
          ...body,
          id,
          tenant_id: tenantId,
        });
        await projectPolicy(c, stored, parsedType.data, body.scope_id);
        return json(c, 201, adminItem("quota_policy", stored));
      } catch (error) {
        if (error instanceof StoreConflictError) {
          throw new HttpError(409, "conflict", `quota policy ${id} already exists`);
        }
        throw error;
      }
    },

    getQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const id = quotaPolicyId(scopeType, scopeId);
      const record = await deps.store.get(QUOTA_POLICIES, scope, id);
      if (record === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      return json(c, 200, adminItem("quota_policy", record));
    },

    replaceQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      authorizeScopedResourceWrite(scope, "Replacing");
      const body = await readJson(c, quotaPolicySchema);
      const id = quotaPolicyId(scopeType, scopeId);
      await assertResidencyJurisdiction(c, scopeType, scopeId, body);
      const stored = await deps.store.replace(QUOTA_POLICIES, scope, id, {
        ...body,
        scope_type: scopeType,
        scope_id: scopeId,
      });
      if (stored === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      await projectPolicy(c, stored, scopeType, scopeId);
      return json(c, 200, adminItem("quota_policy", stored));
    },

    updateQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      authorizeScopedResourceWrite(scope, "Updating");
      const body = await readJson(c, quotaPolicySchema);
      const id = quotaPolicyId(scopeType, scopeId);
      const existing = await deps.store.get(QUOTA_POLICIES, scope, id);
      if (existing === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      await assertResidencyJurisdiction(c, scopeType, scopeId, { ...existing, ...body });
      const stored = await deps.store.merge(QUOTA_POLICIES, scope, id, body);
      if (stored === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      await projectPolicy(c, stored, scopeType, scopeId);
      return json(c, 200, adminItem("quota_policy", stored));
    },

    deleteQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      authorizeScopedResourceWrite(scope, "Deleting");
      const id = quotaPolicyId(scopeType, scopeId);
      const existing = await deps.store.get(QUOTA_POLICIES, scope, id);
      if (existing === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      await assertResidencyJurisdiction(c, scopeType, scopeId, {});
      if (!(await deps.store.remove(QUOTA_POLICIES, scope, id))) {
        throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      }
      // Document first, enforcement row second — see the ordering table in
      // `store/quota_registry.ts`. A crash between them leaves a limit that
      // still bites and that the operator can no longer see, which is the
      // direction a limiter must fail in; the inverse leaves a policy the
      // console lists and the gateway no longer applies.
      const db = deps.controlDatabase;
      if (db !== null) await deleteQuotaPolicyRow(db, scopeType, scopeId);
      return json(c, 200, adminDeleted("quota_policy", id));
    },
  },
);
