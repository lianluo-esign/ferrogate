/**
 * The PLAN-and-RBAC tool-entitlement ladder, over the CONTROL D1 — the durable
 * half of {@link EntitlementPort}.
 *
 * Clean-room port of two Rust functions, both of which are about to be deleted
 * with `crates/**` and neither of which is specified anywhere else
 * (`docs/rewrite/CUTOVER-READINESS.md` §3, cluster **S5**; finding **A3/R1**):
 *
 *  * `crates/ferrogate-gateway/src/server/local.rs:137
 *    tool_execution_entitlement_denial` — the per-backend taxonomy (which plan
 *    column, which permission key, which error code, which message), the
 *    built-in exemption, and the platform-operator exemption;
 *  * `crates/ferrogate-gateway/src/server/state_rbac.rs:11
 *    tenant_tool_entitlement_denied` — the durable walk itself.
 *
 * Rust, transcribed in full so the semantics survive the delete:
 *
 * ```rust
 * let account = self.repositories.get_tenant_account(&tenant_id).await.ok().flatten();
 * let tenant_account_exists = account.is_some();
 * let plan_grants_access = match account {
 *     Some(account) => self.repositories.get_plan(&account.plan_id).await
 *         .ok().flatten().is_some_and(|plan| plan_enabled(&plan)),
 *     None => false,
 * };
 * let permission_exists = self.repositories.list_permissions().await.ok()
 *     .is_some_and(|permissions| permissions.iter().any(|p| p.key == permission_key));
 * let mut role_grants_access = false;
 * if permission_exists {
 *     if let Ok(bindings) = self.repositories.list_tenant_role_bindings(&tenant_id).await {
 *         for binding in bindings {
 *             if let Ok(Some(role)) = self.repositories.get_role(&binding.role_id).await {
 *                 if role.permission_keys.iter().any(|key| key == &permission_key) {
 *                     role_grants_access = true;
 *                     break;
 *                 }
 *             }
 *         }
 *     }
 * }
 * tenant_account_exists && !plan_grants_access && !role_grants_access
 * ```
 *
 * ## Four properties that are easy to lose and are all load-bearing
 *
 * 1. **Denial requires a REGISTERED tenant.** `tenant_account_exists &&` is the
 *    first conjunct. Pre-#515 credentials, keys declared in `ferrogate.toml`
 *    (whose `Config::validate` is storage-free and so cannot look a tenant up)
 *    and most fixtures carry an `organization_id` that was never registered
 *    through `/admin/v1/tenant-accounts`. These flags were dead until #182, so
 *    reading "no tenant record" as an implicit denial is a silent breaking
 *    change for exactly that population. It is NOT a statement about
 *    `organization_id` being weak — it is a foreign key and the authorization
 *    identity of every isolation check (#515).
 * 2. **Plan OR role.** Either grants. Implementing only the plan half
 *    un-grants every #182 per-tenant override; only the role half un-grants
 *    every paying tenant.
 * 3. **An UNDECLARED permission grants nothing.** `permission_exists` is
 *    checked before any binding is read, so a role naming `mcp.execute` at a
 *    deployment that never declared that permission is a typo, not a grant.
 *    (`src/auth.ts`'s `#permissions` — which feeds
 *    {@link AuthContext.permissions} — deliberately does NOT do this check, so
 *    this walk cannot be replaced by reading that field. Rust re-walks here too
 *    rather than trusting the `AuthContext`.)
 * 4. **Every lookup swallows its error into "no grant".** Rust is
 *    `.ok().flatten()` / `if let Ok(..)` on all four reads, and because the
 *    verdict is `tenant_account_exists && …`, an unreadable control plane
 *    produces NO denial rather than a 503. That is reproduced verbatim: it
 *    means a control-plane outage cannot lock every tenant out of tool
 *    execution, and it is why this port never throws. Tightening it to a 503
 *    would be "more honest" in the abstract and a worse outage in practice —
 *    and it would differ from the Rust.
 *
 * ## Precedence against the in-memory dev table
 *
 * A tenant with a row in `tenants` is decided ENTIRELY by the durable graph:
 * the dev bundle cannot re-grant what a plan withdrew. The fallback answers
 * only for a tenant the control plane has never heard of — which is the same
 * population property 1 describes, and the same precedence
 * `apps/gateway/src/assets/entitlements.ts` uses for `ASSET_ENTITLEMENTS`.
 *
 * ## The `extension` backend is transcribed and NOT wired, on purpose
 *
 * Rust's third arm (`ToolExecuteBackend::Extension`, #183) gates
 * `POST /v1/tools/execute` on `plans.extension_tools_enabled` /
 * `extensions.execute` / `extension_tools_disabled`. That endpoint answers
 * **501** in this tree (`CUTOVER-READINESS.md` §2.1 **A2**, cluster **S2**),
 * so wiring the arm would be a gate on a door that does not exist. The four
 * values are carried in {@link TOOL_ENTITLEMENTS} anyway — that is the whole
 * of the specification, it costs one table row, it is pinned by
 * `test/entitlements.test.ts`, and it stops S2 from having to re-derive the
 * taxonomy from a deleted file. `toolExecutionDenial` accepts only the
 * backends this Worker can actually reach.
 */
import { backfillTenantConfigurationPolicy, type TenantDatabaseRouter } from "@ferrogate/storage";
import type { AuthContext, EntitlementPort, ToolExecuteBackend } from "./ports.js";

/** Rust permission key for the MCP arm (`local.rs:155`). */
export const MCP_EXECUTE_PERMISSION = "mcp.execute";

/**
 * Rust `UNSCOPED_TENANT_ID` (`auth.rs:329`) — the id `caller_scope()` pins a
 * credential to when it declares neither a tenant nor platform root. It matches
 * no `tenants.id`, so such a credential is never denied here, exactly as in
 * Rust. It is a sentinel, not an exemption: it also filters every listing to
 * nothing everywhere else it is used.
 */
const UNSCOPED_TENANT_ID = "";

/** One backend's entitlement: which column, which permission, which refusal. */
export interface ToolEntitlementSpec {
  /** Column on `plans`. A fixed literal union — never interpolated user input. */
  readonly planColumn: "mcp_enabled" | "extension_tools_enabled";
  readonly permissionKey: string;
  readonly errorCode: string;
  readonly errorMessage: string;
}

/**
 * The taxonomy of `local.rs:143-168`, verbatim. `builtin` is absent because
 * Rust returns `None` for it before reaching this table (see
 * {@link D1ToolEntitlements.toolExecutionDenial}).
 */
export const TOOL_ENTITLEMENTS: Readonly<Record<"mcp" | "extension", ToolEntitlementSpec>> =
  Object.freeze({
    mcp: Object.freeze({
      planColumn: "mcp_enabled",
      permissionKey: MCP_EXECUTE_PERMISSION,
      errorCode: "mcp_tools_disabled",
      errorMessage:
        "the tenant's plan does not enable MCP tool execution and no bound role " +
        "grants the mcp.execute permission",
    }),
    // NOT WIRED — the spec carrier for cluster S2. See the module header.
    extension: Object.freeze({
      planColumn: "extension_tools_enabled",
      permissionKey: "extensions.execute",
      errorCode: "extension_tools_disabled",
      errorMessage:
        "the tenant's plan does not enable extension tool execution and no bound role " +
        "grants the extensions.execute permission",
    }),
  });

/**
 * `get_tenant_account` + `get_plan` in ONE statement.
 *
 * The join is a LEFT join and that is not cosmetic: Rust reads the tenant
 * account and the plan SEPARATELY, so a `tenants` row whose `plan_id` names no
 * `plans` row still counts as an EXISTING tenant account with a plan that does
 * not grant — i.e. DENIED unless a role lifts it. An INNER join would return no
 * row for that tenant and silently turn a dangling `plan_id` into "not
 * registered", which ADMITS. Absence of the row here therefore means exactly
 * what `account.is_none()` means in Rust, and nothing else.
 */
export function tenantPlanSql(column: ToolEntitlementSpec["planColumn"]): string {
  return `SELECT plans.${column} AS enabled FROM tenants LEFT JOIN plans ON plans.id = tenants.plan_id WHERE tenants.id = ?1`;
}

/** Step 1 of the role half: `list_permissions().any(|p| p.key == key)`. */
export const PERMISSION_DECLARED_SQL = "SELECT 1 AS present FROM permissions WHERE key = ?1";

/** Steps 2+3: `list_tenant_role_bindings(tenant)` × `get_role(binding.role_id)`. */
export const ROLE_GRANTS_SQL =
  "SELECT roles.permission_keys_json AS permission_keys_json " +
  "FROM tenant_role_bindings " +
  "JOIN roles ON roles.id = tenant_role_bindings.role_id " +
  "WHERE tenant_role_bindings.tenant_id = ?1";

/** SQLite has no boolean: the plan columns are `INTEGER NOT NULL DEFAULT 0`. */
function truthy(value: unknown): boolean {
  return value === 1 || value === true;
}

interface PlanRow {
  readonly enabled?: unknown;
}

/**
 * `tool_execution_entitlement_denial` + `tenant_tool_entitlement_denied`, over
 * the CONTROL database.
 *
 * `fallback` answers for a tenant with NO `tenants` row — see the precedence
 * note in the module header. Production binds none.
 */
export class D1ToolEntitlements implements EntitlementPort {
  readonly #db: D1Database;
  readonly #fallback: EntitlementPort | undefined;
  readonly #tenantDatabases: TenantDatabaseRouter | undefined;

  constructor(
    db: D1Database,
    options: {
      fallback?: EntitlementPort | undefined;
      tenantDatabases?: TenantDatabaseRouter | undefined;
    } = {},
  ) {
    this.#db = db;
    this.#fallback = options.fallback;
    this.#tenantDatabases = options.tenantDatabases;
  }

  async toolExecutionDenial(
    auth: AuthContext,
    backend: ToolExecuteBackend,
  ): Promise<{ code: string; message: string } | undefined> {
    // `ToolExecuteBackend::Builtin => return None`. Built-in tools carry no
    // `StoredPlan` feature flag: `fetch_asset` reuses the asset-read authz
    // (scope `assets.read` + tenant scoping) enforced INSIDE the tool, exactly
    // as `handle_asset_pull` does, so there is no entitlement to deny here.
    if (backend === "builtin") return undefined;
    // #515: only a DECLARED platform operator is exempt. A credential that
    // merely omitted its tenant is not — it is pinned to `UNSCOPED_TENANT_ID`,
    // which matches no row, and is therefore allowed for the reason in
    // property 1 rather than by an exemption.
    if (auth.platformOperator) return undefined;
    const tenantId = auth.organizationId ?? UNSCOPED_TENANT_ID;

    const spec = TOOL_ENTITLEMENTS[backend];

    let plan: PlanRow | null;
    try {
      plan = await this.#db.prepare(tenantPlanSql(spec.planColumn)).bind(tenantId).first<PlanRow>();
    } catch {
      // `.ok().flatten()` — an unreadable control plane is "no account", and
      // `tenant_account_exists && …` then denies nobody.
      plan = null;
    }

    if (plan === null) {
      // No `tenants` row: `account.is_none()` ⇒ `tenant_account_exists` is
      // false ⇒ the verdict is false whatever the roles say. The dev bundle,
      // when one is bound, is the only thing that may speak for this tenant.
      return this.#fallback === undefined
        ? undefined
        : this.#fallback.toolExecutionDenial(auth, backend);
    }

    // The tenant IS registered. From here the durable graph decides alone.
    if (truthy(plan.enabled)) return undefined;
    if (await this.#roleGrants(tenantId, spec.permissionKey)) return undefined;
    return { code: spec.errorCode, message: spec.errorMessage };
  }

  /** The Permission → Role → TenantRoleBinding walk. Errors are "no grant". */
  async #roleGrants(tenantId: string, permissionKey: string): Promise<boolean> {
    try {
      const declared = await this.#db
        .prepare(PERMISSION_DECLARED_SQL)
        .bind(permissionKey)
        .first<{ present: number }>();
      // Property 3: an undeclared permission grants nothing, however many roles
      // happen to name it.
      if (declared === null) return false;

      const bound =
        this.#tenantDatabases === undefined
          ? await this.#db
              .prepare(ROLE_GRANTS_SQL)
              .bind(tenantId)
              .all<{ permission_keys_json: string | null }>()
          : await this.#tenantRoleGrants(tenantId);
      for (const row of bound.results) {
        const raw = row.permission_keys_json;
        if (typeof raw !== "string") continue;
        let keys: unknown;
        try {
          keys = JSON.parse(raw);
        } catch {
          // A corrupt `permission_keys_json` is one unreadable ROLE, not an
          // unreadable walk: Rust's `get_role` failing skips that binding and
          // keeps looping. Breaking out here would let one bad row withdraw a
          // grant held by a different, valid role.
          continue;
        }
        if (Array.isArray(keys) && keys.some((key) => key === permissionKey)) return true;
      }
      return false;
    } catch {
      // `if let Ok(bindings)` / `if let Ok(Some(role))` — both are "no grant".
      return false;
    }
  }

  async #tenantRoleGrants(
    tenantId: string,
  ): Promise<{ results: { permission_keys_json: string | null }[] }> {
    const router = this.#tenantDatabases;
    if (router === undefined) throw new Error("tenant object router is not configured");
    await backfillTenantConfigurationPolicy(this.#db, router, tenantId);
    const handle = await router.forTenant(tenantId);
    const local = await handle.db
      .prepare(
        `SELECT b.role_id
           FROM tenant_role_bindings AS b
          WHERE b.tenant_id = ?1`,
      )
      .bind(tenantId)
      .all<{ role_id: string }>();
    const valid: { permission_keys_json: string | null }[] = [];
    for (const row of local.results) {
      const shared = await this.#db
        .prepare("SELECT permission_keys_json FROM roles WHERE id = ?1")
        .bind(row.role_id)
        .all<{ permission_keys_json: string | null }>();
      const role = shared.results[0];
      if (role !== undefined) valid.push(role);
    }
    return { results: valid };
  }
}
