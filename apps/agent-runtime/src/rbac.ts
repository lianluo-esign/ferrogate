/**
 * THE RBAC GATE — an operation's `rbac_action`, decided here exactly as
 * `apps/gateway` decides it. (`docs/rewrite/FLEET-CONSISTENCY.md` finding
 * **FC-7**.)
 *
 * ## What FC-7 was
 *
 * `src/contract.ts:328` parsed `rbac_action` off the shared contract table into
 * every `ApiOperation` this Worker serves — and **nothing ever read it**.
 * `apps/mcp` had the identical hole. So a role that denies an action was
 * enforced on `apps/gateway` and `apps/control-plane` and silently ignored on
 * the other two: "call the other endpoint", which is the shape both of this
 * project's shipped fleet defects had.
 *
 * Its blast radius was ZERO on the day it was found and only on that day: all
 * 12 operations in `docs/openapi/runtime-api-contract.json` carrying an
 * `rbac_action` are `/admin/v1/guardrail-*` or `/admin/v1/investigations`
 * paths, which this Worker does not serve. It was a control PRE-ARMED to fail —
 * the first `rbac_action` on a data-plane operation would have been unenforced
 * on two of five Workers with every per-Worker suite green.
 *
 * That is why the fix is STRUCTURAL rather than a gate on a named route:
 * `src/middleware/auth.ts::bearerAuth` consults this port for whatever the
 * MATCHED contract operation declares, so the day an `rbac_action` lands on
 * `POST /v1/agent-runs` the enforcement is already here.
 *
 * ## The walk is `apps/gateway/src/adapters.ts::D1RbacAuthorizer`, step for step
 *
 * Both are ports of `crates/ferrogate-gateway/src/server/state_rbac.rs::
 * tenant_has_permission_result`, and each step is load-bearing:
 *
 *  1. **The permission must EXIST** (`permissions.key`). An action nobody
 *     declared is denied even if a role happens to name it — which is what
 *     stops a typo in a role's `permission_keys` from minting an entitlement.
 *  2. **The tenant's bindings are walked**, and a binding whose `roles` row is
 *     missing is SKIPPED rather than treated as a grant (Rust's
 *     `let Some(role) = … else { continue }`, which the `JOIN` reproduces).
 *  3. **A role grants when its `permission_keys` CONTAINS the action.** No
 *     wildcard: Rust compares `key == permission_key`, so `"*"` in a role is a
 *     permission literally named `*` and nothing else.
 *
 * Two departures, both narrowing and both matching `apps/gateway`: a
 * **platform operator** is waved through before any query, and a **storage
 * failure** answers `allowed: "unavailable"` → 503 `rbac_unavailable` rather
 * than a decision. Fail-open there would make "flap the control plane" an
 * authorization bypass.
 *
 * ## What this file deliberately does NOT do
 *
 * `apps/gateway` carries a second, VAR-backed authorizer over
 * `TENANT_RBAC_ACTIONS` as an additive bootstrap in front of the durable graph.
 * It is not ported here: Rust has no config-file RBAC, the var is declared only
 * in `apps/gateway/wrangler.toml`, and reading a var this Worker's deploy
 * config does not declare would fail `test/env-var-drift.test.ts` for a value
 * no operator could set. The consequence, stated rather than hidden: a grant
 * that exists ONLY in the gateway's var table is honoured there and denied
 * here. The asymmetry is in the DENY direction on this Worker, and the
 * authority the fleet shares — the durable graph — decides identically.
 *
 * ## No control database ⇒ 503, never an open door
 *
 * With no `CONTROL_DB` there is no grant graph, and an operation that DECLARES
 * an `rbac_action` cannot be authorized without one — so
 * {@link UnboundRbacAuthorizer} answers `unavailable` (503), the same posture
 * `resolveDeps` takes when a credential authority is missing. An operation with
 * no `rbac_action` never reaches this port, so an unbound deployment serves
 * exactly what it served before.
 */
import {
  DurableObjectTenantDatabaseRouter,
  type TenantDatabaseRouter,
  backfillTenantConfigurationPolicy,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { controlDatabaseFrom } from "./control-data.js";
import type { AuthContext } from "./ports.js";

/**
 * The decision, spelled the same way as `apps/gateway`'s and
 * `apps/control-plane`'s so the three call sites read alike — including the
 * `"unavailable"` third arm, which exists precisely so an outage cannot
 * collapse into "denied" (a policy answer) or "allowed" (a hole).
 */
export type RbacDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly code: string; readonly message: string }
  | { readonly allowed: "unavailable"; readonly detail: string };

/** Evaluates an operation's `rbac_action` for the caller. */
export interface RbacAuthorizerPort {
  authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision>;
}

/** Step 1 of the walk — byte-identical to the gateway's statement. */
export const RBAC_PERMISSION_EXISTS_SQL = "SELECT 1 AS present FROM permissions WHERE key = ?1";

/**
 * Steps 2+3 — `list_tenant_role_bindings(tenant)` × `get_role(binding.role_id)`.
 *
 * ONE template literal rather than a `"SELECT …" + "FROM …"` concatenation, and
 * that is not a style choice: `apps/gateway/test/fleet-control-matrix.test.ts`
 * derives which durable authority each Worker reads by scanning SQL string
 * literals that carry both the verb and the table, so a statement split across
 * fragments is INVISIBLE to it and the Worker scores as reading nowhere. A
 * consistency gate that cannot see a table cannot hold a control that lives in
 * it. `src/guardrails.ts` carries the same note for the same reason.
 */
export const RBAC_TENANT_ROLE_GRANTS_SQL = `SELECT roles.permission_keys_json AS permission_keys_json
     FROM tenant_role_bindings
     JOIN roles ON roles.id = tenant_role_bindings.role_id
    WHERE tenant_role_bindings.tenant_id = ?1`;

/**
 * Rust names the denial after the action's own domain — `guardrail_rbac_denied`
 * is the only domain-specific one that exists today
 * (`guardrail_policies.rs:959`, `local.rs:236`). Same function, same answer, on
 * every Worker that enforces the control.
 */
export function rbacDenialCode(rbacAction: string): string {
  return rbacAction.startsWith("guardrails.") ? "guardrail_rbac_denied" : "rbac_denied";
}

/** The Rust denial message, verbatim. */
export function rbacDenialMessage(rbacAction: string): string {
  return `tenant roles do not grant required action ${rbacAction}`;
}

/**
 * The subset of `D1Database` this authorizer reads. A live binding satisfies it
 * structurally, so nothing is cast and nothing is wrapped — and a test can
 * supply a THROWING database, which is the one thing a healthy binding cannot
 * be asked to do.
 */
export interface RbacDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { all(): Promise<{ results?: unknown[] | null }> };
  };
}

function isRbacDatabase(value: unknown): value is RbacDatabase {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as RbacDatabase).prepare === "function"
  );
}

/** The durable Permission → Role → TenantRoleBinding walk, over the CONTROL D1. */
export class D1RbacAuthorizer implements RbacAuthorizerPort {
  readonly #db: RbacDatabase;
  readonly #tenantDatabases: TenantDatabaseRouter | undefined;

  constructor(db: RbacDatabase, options: { tenantDatabases?: TenantDatabaseRouter } = {}) {
    this.#db = db;
    this.#tenantDatabases = options.tenantDatabases;
  }

  async authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision> {
    // #515: only a DECLARED platform operator is exempt. A credential that
    // merely omitted its tenant is pinned to the empty-string tenant id, which
    // is unforgeable as a real `tenants.id` and therefore matches no binding —
    // so it is DENIED here rather than waved through.
    if (auth.platformOperator) return { allowed: true };
    const tenantId = auth.tenancy.tenantId ?? "";

    let granted: boolean;
    try {
      granted = await this.#durablyGrants(tenantId, rbacAction);
    } catch (error) {
      return {
        allowed: "unavailable",
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    if (granted) return { allowed: true };
    return {
      allowed: false,
      code: rbacDenialCode(rbacAction),
      message: rbacDenialMessage(rbacAction),
    };
  }

  async #durablyGrants(tenantId: string, rbacAction: string): Promise<boolean> {
    const declared = await this.#db.prepare(RBAC_PERMISSION_EXISTS_SQL).bind(rbacAction).all();
    if ((declared.results ?? []).length === 0) return false;

    const grants =
      this.#tenantDatabases === undefined
        ? await this.#db.prepare(RBAC_TENANT_ROLE_GRANTS_SQL).bind(tenantId).all()
        : await this.#tenantRoleGrants(tenantId);
    for (const row of grants.results ?? []) {
      const raw = (row as { permission_keys_json?: unknown }).permission_keys_json;
      if (typeof raw !== "string") continue;
      let keys: unknown;
      try {
        keys = JSON.parse(raw);
      } catch {
        // A corrupt role document grants nothing — and must not deny the whole
        // lookup either, or one bad row would revoke every other role the
        // tenant holds.
        continue;
      }
      if (Array.isArray(keys) && keys.some((key) => key === rbacAction)) return true;
    }
    return false;
  }

  /** Read the tenant-local binding and validate its projected role in CONTROL. */
  async #tenantRoleGrants(tenantId: string): Promise<{ results: unknown[] }> {
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
    const valid: unknown[] = [];
    for (const row of local.results) {
      const shared = await this.#db
        .prepare("SELECT permission_keys_json FROM roles WHERE id = ?1")
        .bind(row.role_id)
        .all();
      const role = (shared.results ?? [])[0] as { permission_keys_json?: unknown } | undefined;
      if (role !== undefined) {
        valid.push({
          permission_keys_json:
            typeof role.permission_keys_json === "string" ? role.permission_keys_json : null,
        });
      }
    }
    return { results: valid };
  }
}

/** No control database bound: 503 `rbac_unavailable`, never an implicit grant. */
export class UnboundRbacAuthorizer implements RbacAuthorizerPort {
  authorize(): Promise<RbacDecision> {
    return Promise.resolve({
      allowed: "unavailable",
      detail: "no control database is bound, so role permissions cannot be resolved",
    });
  }
}

/**
 * Choose the authorizer for this env — the composition-root half.
 *
 * `CONTROL_DB` bound ⇒ the durable walk over the SAME `permissions` / `roles` /
 * `tenant_role_bindings` rows `apps/control-plane`'s RBAC routes write and
 * `apps/gateway` reads. Absent ⇒ {@link UnboundRbacAuthorizer}.
 */
export function rbacAuthorizerFromEnv(env: {
  CONTROL_DATA?: unknown;
  TENANT_DATA?: unknown;
}): RbacAuthorizerPort {
  const controlDb = controlDatabaseFrom(env);
  if (!isRbacDatabase(controlDb)) return new UnboundRbacAuthorizer();
  const namespace = env.TENANT_DATA as TenantDataNamespace | undefined;
  const tenantDatabases =
    namespace === undefined
      ? undefined
      : new DurableObjectTenantDatabaseRouter(namespace, controlDb as unknown as D1Database);
  return new D1RbacAuthorizer(controlDb, { tenantDatabases });
}
