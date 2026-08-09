/**
 * Asset entitlements out of the CONTROL D1 — the durable half of
 * `AssetEntitlementsPort`.
 *
 * Port of the Rust `assets.rs::tenant_can_host` plus the `EffectiveQuota`
 * fields the asset handlers read off `StoredPlan`:
 *
 * ```rust
 * async fn tenant_can_host(&self, state: &AppState, tenant_id: &str) -> bool {
 *     let plan = state.resolve_tenant_plan(tenant_id).await.ok().flatten();
 *     let plan_grants = plan.as_ref().is_some_and(|plan| plan.asset_hosting_enabled);
 *     let role_grants = state.tenant_has_permission(tenant_id, "assets.host").await;
 *     plan_grants || role_grants
 * }
 * ```
 *
 * Both halves are reproduced, and BOTH are needed: hosting from a PLAN is the
 * common case, hosting from a bound ROLE is issue #182's per-tenant override,
 * and implementing only one would silently un-host every tenant on the other.
 * The role half reuses the very same Permission → Role → TenantRoleBinding walk
 * `D1RbacAuthorizer` performs for `rbac_action`s, against the permission key
 * `assets.host`.
 *
 * ## Fail-closed, and NOT a 503
 *
 * Every Rust lookup here swallows its error into "no grant"
 * (`.ok().flatten()`, and `tenant_has_permission` is
 * `tenant_has_permission_result(..).unwrap_or(false)`). That is deliberate and
 * it is reproduced verbatim: a control-plane outage stops new PUBLISHES
 * (`403`, `NO_ASSET_HOSTING`) and leaves every already-published asset
 * READABLE, because the read surfaces do not require hosting. Turning it into
 * a 503 would be "more honest" in the abstract and a worse outage in practice —
 * and it would differ from the Rust.
 *
 * ## Precedence against the `ASSET_ENTITLEMENTS` var
 *
 * A tenant with a row in `tenants` is decided ENTIRELY by the durable graph:
 * the var cannot re-grant what a plan withdrew. The var answers only for a
 * tenant the control plane has never heard of, which is the bootstrap case it
 * exists for (same shape as the API-key tables — durable first, config second,
 * and the config leg never widens a durable decision).
 */

import {
  DurableObjectTenantDatabaseRouter,
  type TenantDatabaseRouter,
  backfillTenantConfigurationPolicy,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { controlDatabaseFrom } from "../control-data.js";
import type { AssetEntitlements, AssetEntitlementsPort } from "./handlers.js";

/** Rust permission key for the role half of `tenant_can_host` (issue #182). */
export const ASSET_HOST_PERMISSION = "assets.host";

/** The subset of `D1Database` this port reads; a live binding satisfies it. */
export interface EntitlementsDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { all(): Promise<{ results?: unknown[] | null }> };
  };
}

/** Exported so a test pins the statements rather than restating them. */
export const TENANT_PLAN_SQL =
  "SELECT plans.asset_hosting_enabled AS asset_hosting_enabled, " +
  "plans.default_asset_storage_quota_bytes AS quota_bytes, " +
  "plans.default_asset_max_object_bytes AS max_object_bytes " +
  "FROM tenants JOIN plans ON plans.id = tenants.plan_id WHERE tenants.id = ?1";

/** The role half: is `assets.host` declared, and does a bound role hold it? */
export const ASSET_HOST_ROLE_SQL =
  "SELECT roles.permission_keys_json AS permission_keys_json " +
  "FROM tenant_role_bindings " +
  "JOIN roles ON roles.id = tenant_role_bindings.role_id " +
  "WHERE tenant_role_bindings.tenant_id = ?1";

export const ASSET_HOST_PERMISSION_SQL = "SELECT 1 AS present FROM permissions WHERE key = ?1";

function isEntitlementsDatabase(value: unknown): value is EntitlementsDatabase {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as EntitlementsDatabase).prepare === "function"
  );
}

/** SQLite has no boolean: the column is `INTEGER NOT NULL DEFAULT 0`. */
function truthy(value: unknown): boolean {
  return value === 1 || value === true;
}

/** `NULL` means unbounded, which is `undefined` on {@link AssetEntitlements}. */
function optionalBytes(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

interface PlanRow {
  readonly asset_hosting_enabled?: unknown;
  readonly quota_bytes?: unknown;
  readonly max_object_bytes?: unknown;
}

/**
 * `resolve_tenant_plan` + `tenant_has_permission("assets.host")`, over D1.
 *
 * `fallback` answers for a tenant with no `tenants` row — see the precedence
 * note in the module header.
 */
export class D1AssetEntitlements implements AssetEntitlementsPort {
  readonly #db: EntitlementsDatabase;
  readonly #fallback: AssetEntitlementsPort | undefined;
  readonly #tenantDatabases: TenantDatabaseRouter | undefined;

  constructor(
    db: EntitlementsDatabase,
    options: {
      fallback?: AssetEntitlementsPort | undefined;
      tenantDatabases?: TenantDatabaseRouter | undefined;
    } = {},
  ) {
    this.#db = db;
    this.#fallback = options.fallback;
    this.#tenantDatabases = options.tenantDatabases;
  }

  /** `null` when `CONTROL_DB` is unbound, so the caller keeps its var path. */
  static fromEnv(
    env: Record<string, unknown>,
    options: {
      fallback?: AssetEntitlementsPort | undefined;
      tenantDatabases?: TenantDatabaseRouter | undefined;
    } = {},
  ): D1AssetEntitlements | null {
    const binding = controlDatabaseFrom(env);
    if (!isEntitlementsDatabase(binding)) return null;
    const namespace = env.TENANT_DATA as TenantDataNamespace | undefined;
    const tenantDatabases =
      options.tenantDatabases ??
      (namespace === undefined
        ? undefined
        : new DurableObjectTenantDatabaseRouter(namespace, binding as D1Database));
    return new D1AssetEntitlements(binding, { ...options, tenantDatabases });
  }

  async resolve(tenantId: string): Promise<AssetEntitlements> {
    let plan: PlanRow | undefined;
    try {
      const rows = await this.#db.prepare(TENANT_PLAN_SQL).bind(tenantId).all();
      plan = (rows.results ?? [])[0] as PlanRow | undefined;
    } catch {
      // Rust `.ok().flatten()`: an unreadable control plane is "no plan".
      plan = undefined;
    }

    if (plan === undefined && this.#fallback !== undefined) {
      // No durable row at all — the bootstrap case. A tenant the control plane
      // HAS heard of never reaches here, so the var cannot re-grant hosting a
      // plan withdrew.
      const bootstrap = await this.#fallback.resolve(tenantId);
      if (bootstrap.assetHostingEnabled) {
        return bootstrap;
      }
      // …but a bootstrap "no" must still let the ROLE half speak, exactly as it
      // does for a tenant with a plan.
      return {
        ...bootstrap,
        assetHostingEnabled: await this.#roleGrantsHosting(tenantId),
      };
    }

    const planGrants = truthy(plan?.asset_hosting_enabled);
    return {
      // `plan_grants || role_grants` — either is sufficient (#176/#177/#182).
      // The role query is skipped entirely when the plan already granted:
      // it cannot change the answer, and the asset path runs on every push.
      assetHostingEnabled: planGrants || (await this.#roleGrantsHosting(tenantId)),
      assetStorageQuotaBytes: optionalBytes(plan?.quota_bytes),
      assetMaxObjectBytes: optionalBytes(plan?.max_object_bytes),
    };
  }

  /** `tenant_has_permission(tenant, "assets.host")` — errors are "no grant". */
  async #roleGrantsHosting(tenantId: string): Promise<boolean> {
    try {
      const declared = await this.#db
        .prepare(ASSET_HOST_PERMISSION_SQL)
        .bind(ASSET_HOST_PERMISSION)
        .all();
      if ((declared.results ?? []).length === 0) {
        // Step 1 of the Rust walk: an undeclared permission grants nothing,
        // however many roles happen to name it.
        return false;
      }
      const grants =
        this.#tenantDatabases === undefined
          ? await this.#db.prepare(ASSET_HOST_ROLE_SQL).bind(tenantId).all()
          : await this.#tenantRoleGrantsHosting(tenantId);
      for (const row of grants.results ?? []) {
        const raw = (row as { permission_keys_json?: unknown }).permission_keys_json;
        if (typeof raw !== "string") continue;
        let keys: unknown;
        try {
          keys = JSON.parse(raw);
        } catch {
          continue;
        }
        if (Array.isArray(keys) && keys.some((key) => key === ASSET_HOST_PERMISSION)) {
          return true;
        }
      }
      return false;
    } catch {
      // `tenant_has_permission` is `…_result(..).unwrap_or(false)`.
      return false;
    }
  }

  async #tenantRoleGrantsHosting(
    tenantId: string,
  ): Promise<{ results: { role_id: string; permission_keys_json: string | null }[] }> {
    const router = this.#tenantDatabases;
    if (router === undefined) throw new Error("tenant object router is not configured");
    await backfillTenantConfigurationPolicy(this.#db as unknown as D1Database, router, tenantId);
    const handle = await router.forTenant(tenantId);
    const local = await handle.db
      .prepare(
        `SELECT b.role_id
           FROM tenant_role_bindings AS b
          WHERE b.tenant_id = ?1`,
      )
      .bind(tenantId)
      .all<{ role_id: string }>();
    const valid: { role_id: string; permission_keys_json: string | null }[] = [];
    for (const row of local.results) {
      const shared = await this.#db
        .prepare("SELECT permission_keys_json FROM roles WHERE id = ?1")
        .bind(row.role_id)
        .all();
      const role = (shared.results ?? [])[0] as { permission_keys_json?: unknown } | undefined;
      if (role !== undefined) {
        valid.push({
          role_id: row.role_id,
          permission_keys_json:
            typeof role.permission_keys_json === "string" ? role.permission_keys_json : null,
        });
      }
    }
    return { results: valid };
  }
}
