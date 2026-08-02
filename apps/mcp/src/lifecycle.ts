/**
 * THE TENANCY LIFECYCLE GATE — the control an operator applies once and every
 * spending Worker must honour.
 *
 * ## What this closes
 *
 * `docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-2**. Before this module
 * `apps/mcp` had **no lifecycle check in any posture**: `src/auth.ts` documents
 * its whole 401-vs-403 taxonomy and tenancy suspension was not a row in it. A
 * tenant suspended in the control plane was refused `403 tenancy_suspended` on
 * `/v1/chat/completions` by `apps/gateway` and ADMITTED here on `tools/call`,
 * which spends real provider money against a quota and a wallet nobody zeroed.
 *
 * The exploit is the wave-16 admission bypass wearing a second control: **call
 * the other endpoint.** Suspending a TENANCY does not revoke its KEY, so the
 * credential still resolves — only the gate that should refuse it was missing.
 *
 * ## The authority, and why it is not a new one
 *
 * `tenants.status` in the CONTROL database — the exact column
 * `apps/gateway/src/adapters.ts::D1TenancyLifecycleGate` reads and
 * `apps/control-plane`'s lifecycle routes write. This Worker already binds that
 * database as `env.DB` (`wrangler.toml`, `database_name = "ferrogate-control"`),
 * so no new binding is introduced; what was missing was the reader.
 *
 * `projects` and `workspaces` are TENANT data (the split rule in `sql/d1-ts/`),
 * so the two deeper tiers are read through the SAME
 * `EnvBindingTenantDatabaseRouter` the NATIVE credential leg already uses. One
 * credential, one tenant database, one lifecycle answer.
 *
 * ## The walk, not the declaration
 *
 * Clean-room port of Rust `resolve_lifecycle_chain` + `check_lifecycle_chain`.
 * The subtlety Rust's second landing fixed is reproduced rather than
 * re-derived: three independent lookups that check only the ids the CALLER
 * declared mean a credential carrying just a `project_id` yields the chain
 * `[project(active)]` and the suspended TENANT above it is never read. So the
 * workspace row backfills its `project_id`/`tenant_id`, each project row
 * backfills its `tenant_id`, and declared ids are UNIONed with derived ones —
 * never substituted. There is no ordering in which a suspended ancestor is
 * skipped.
 *
 * The chain is evaluated SHALLOWEST FIRST so the refusal names the ROOT cause:
 * when suspending a tenant cascades onto its project and workspace, the caller
 * is told the TENANT is suspended rather than being sent chasing the workspace.
 *
 * ## Three postures that are decided here, not discovered later
 *
 *  1. **A row that is absent is not a denial.** A dangling id resolves to
 *     nothing, exactly as the api-key tenancy rules already treat one. Inventing
 *     a refusal there would make a typo indistinguishable from a suspension.
 *  2. **A LOOKUP FAILURE is 503, never an admission.** Rust
 *     `LifecycleGateError::Unavailable`, and it states the reason: fail-open
 *     here would hand every suspended tenant a trivial bypass — make the control
 *     plane flap and keep serving. `src/admission/quota.ts` argues the identical
 *     posture for spend; this file matches it.
 *  3. **A platform operator is waved through before any query.** An operator
 *     credential carries no tenancy chain, so there is nothing to walk; every
 *     Rust call site does the same.
 *
 * ## Where it runs, and why the position is the control
 *
 * `src/http.ts::authenticateRequest`, AFTER the credential resolves and BEFORE
 * `src/admission/`. That is `finalize_auth`'s order and it is not cosmetic: the
 * lifecycle gate runs ahead of quota/wallet resolution precisely so a suspended
 * tenant never reaches the step that authorizes spend.
 *
 * ## The status codes are the gateway's, not new ones
 *
 * `403 tenancy_suspended` / `tenancy_disabled` / `tenancy_deleted` for a
 * refusal; `503 lifecycle_status_unavailable` for an unreadable authority.
 * A suspended **KEY** stays `401 invalid_api_key` (`src/auth.ts`) — that
 * distinction is a defect class this project has shipped, and this module must
 * not blur it: 403 here is only ever reached by a caller who IS authenticated.
 */
import {
  type LifecycleStatus,
  StorageError,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  lifecycleStatusAllowsRequests,
  parseLifecycleStatus,
} from "@ferrogate/storage";

import type { AuthContext, AuthError } from "./ports.js";

// ---------------------------------------------------------------------------
// The three statements, exported so a test can pin them
// ---------------------------------------------------------------------------

/** CONTROL database (`env.DB` on this Worker). */
export const LIFECYCLE_TENANT_SQL = "SELECT id, status FROM tenants WHERE id = ?1";
/** TENANT database, reached through the router. */
export const LIFECYCLE_PROJECT_SQL = "SELECT id, status, tenant_id FROM projects WHERE id = ?1";
/** TENANT database, reached through the router. */
export const LIFECYCLE_WORKSPACE_SQL =
  "SELECT id, status, tenant_id, project_id FROM workspaces WHERE id = ?1";

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/**
 * Rust `LifecycleGate` outcome, spelled exactly as
 * `apps/gateway/src/ports.ts::LifecycleDecision` so the two Workers cannot
 * drift in what they can even express.
 */
export type LifecycleDecision =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly code: string; readonly message: string }
  | { readonly admitted: "unavailable"; readonly detail: string };

export interface TenancyLifecycleGatePort {
  admit(auth: AuthContext): Promise<LifecycleDecision>;
}

/** One resolved ancestor — Rust `LifecycleRef`. */
export interface LifecycleRef {
  /** Used verbatim in the message, so the operator is told WHICH tier is off. */
  readonly kind: "tenant" | "project" | "workspace";
  readonly id: string;
  readonly status: LifecycleStatus;
}

/**
 * Rust `LifecycleRejection::code`, byte-identical to
 * `apps/gateway/src/adapters.ts::lifecycleRejectionCode`.
 *
 * Distinguishable per state so a client can tell "your account is suspended,
 * pay the bill" from "this project is switched off".
 */
export function lifecycleRejectionCode(status: LifecycleStatus): string {
  switch (status) {
    case "suspended":
      return "tenancy_suspended";
    case "disabled":
      return "tenancy_disabled";
    case "deleted":
      return "tenancy_deleted";
    default:
      // Unreachable: an active status never produces a rejection. Total rather
      // than thrown, so a future variant cannot turn this into a 500.
      return "tenancy_inactive";
  }
}

/** Rust `LifecycleRejection::message` for the Request seam. */
export function lifecycleRejectionMessage(reference: LifecycleRef): string {
  return (
    `${reference.kind} ${reference.id} is ${reference.status}; ` +
    "requests authenticated against this tenancy chain are refused"
  );
}

/**
 * Rust `check_lifecycle_chain`.
 *
 * `chain` MUST be ordered shallowest-first — {@link resolveLifecycleChain} is
 * the only supported way to build one.
 *
 * This Worker serves no lifecycle RECOVERY route (those are `apps/control-plane`
 * operations), so only the REQUEST seam exists here and `disabled` denies. The
 * recovery carve-out that keeps a tenant's own off switch reversible lives with
 * the routes that undo it.
 */
export function checkLifecycleChain(chain: readonly LifecycleRef[]): LifecycleDecision {
  for (const reference of chain) {
    if (!lifecycleStatusAllowsRequests(reference.status)) {
      return {
        admitted: false,
        code: lifecycleRejectionCode(reference.status),
        message: lifecycleRejectionMessage(reference),
      };
    }
  }
  return { admitted: true };
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/** A `tenants` / `projects` / `workspaces` row, narrowed to what the gate reads. */
export interface LifecycleRow {
  readonly id: string;
  readonly status: string;
  readonly tenant_id?: string | null;
  readonly project_id?: string | null;
}

/**
 * The three row reads the walk needs — a seam for the same reason Rust makes it
 * a trait: a test can implement a THROWING source and hold the fail-closed
 * claim, which is the one property a live binding cannot express.
 */
export interface LifecycleRowSource {
  tenantRow(id: string): Promise<LifecycleRow | null>;
  projectRow(id: string): Promise<LifecycleRow | null>;
  workspaceRow(id: string): Promise<LifecycleRow | null>;
}

function asLifecycleRow(value: unknown): LifecycleRow | null {
  if (typeof value !== "object" || value === null) return null;
  const row = value as Record<string, unknown>;
  if (typeof row.id !== "string") return null;
  return {
    id: row.id,
    // A NULL/absent `status` is not a decision — `parseLifecycleStatus` reads it
    // as `active` (the fail-OPEN READ default #514 chose deliberately, so the
    // decorative pre-#514 rows do not revoke every existing tenant).
    status: typeof row.status === "string" ? row.status : "",
    tenant_id: typeof row.tenant_id === "string" ? row.tenant_id : null,
    project_id: typeof row.project_id === "string" ? row.project_id : null,
  };
}

/**
 * The two-database row source: `tenants` lives in CONTROL, `projects` and
 * `workspaces` are TENANT data reached through the router.
 *
 * The router split mirrors `src/auth.ts`'s NATIVE leg exactly: a tenant with NO
 * registry row cannot have project/workspace rows either, so that case resolves
 * to NOTHING (the tiers are skipped) rather than to a refusal — a tenant the
 * deployment cannot route is the same "resolves to nothing" the credential path
 * already answers. A registry row this Worker cannot REACH is a different
 * thing: it is a deployment fault, it propagates, and the gate answers 503.
 */
export class D1McpLifecycleRowSource implements LifecycleRowSource {
  readonly #control: D1Database;
  readonly #router: TenantDatabaseRouter | undefined;
  /** Memoized per REQUEST-SCOPED instance only — never across requests. */
  #tenantHandle: Promise<TenantDatabaseHandle | null> | undefined;
  readonly #tenantId: string | undefined;

  constructor(control: D1Database, tenantId: string | undefined, router?: TenantDatabaseRouter) {
    this.#control = control;
    this.#tenantId = tenantId;
    this.#router = router;
  }

  async tenantRow(id: string): Promise<LifecycleRow | null> {
    return asLifecycleRow(await this.#control.prepare(LIFECYCLE_TENANT_SQL).bind(id).first());
  }

  async projectRow(id: string): Promise<LifecycleRow | null> {
    const db = await this.#tenantDb();
    if (db === null) return null;
    return asLifecycleRow(await db.prepare(LIFECYCLE_PROJECT_SQL).bind(id).first());
  }

  async workspaceRow(id: string): Promise<LifecycleRow | null> {
    const db = await this.#tenantDb();
    if (db === null) return null;
    return asLifecycleRow(await db.prepare(LIFECYCLE_WORKSPACE_SQL).bind(id).first());
  }

  /** `null` ⇒ this deployment has no tenant database for the caller. */
  async #tenantDb(): Promise<D1Database | null> {
    if (this.#router === undefined || this.#tenantId === undefined) return null;
    this.#tenantHandle ??= this.#router.forTenant(this.#tenantId).catch((error: unknown) => {
      // NOT registered ⇒ no rows to read (skip the tier). Registered but
      // unreachable ⇒ a real outage, and it must propagate to the 503 arm.
      if (error instanceof StorageError && error.kind === "not_found") return null;
      throw error;
    });
    const handle = await this.#tenantHandle;
    return handle === null ? null : handle.db;
  }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/** The `tenant → project → workspace` ids a caller declares (Rust `TenancyRefs`). */
export interface TenancyRefs {
  readonly tenantId?: string | null | undefined;
  readonly projectId?: string | null | undefined;
  readonly workspaceId?: string | null | undefined;
}

/** Rust `present`: trim, and treat blank as absent. */
function presentId(value: string | null | undefined): string | undefined {
  const trimmed = (value ?? "").trim();
  return trimmed === "" ? undefined : trimmed;
}

function pushUnique(ids: string[], candidate: string | null | undefined): void {
  const value = presentId(candidate);
  if (value === undefined || ids.includes(value)) return;
  ids.push(value);
}

/**
 * Rust `resolve_lifecycle_chain` — walk the HIERARCHY, not the caller's
 * declaration, and return the chain shallowest-first.
 */
export async function resolveLifecycleChain(
  source: LifecycleRowSource,
  refs: TenancyRefs,
): Promise<LifecycleRef[]> {
  const tenantIds: string[] = [];
  const projectIds: string[] = [];
  const workspaceRows: LifecycleRow[] = [];

  pushUnique(tenantIds, refs.tenantId);
  pushUnique(projectIds, refs.projectId);

  const workspaceId = presentId(refs.workspaceId);
  if (workspaceId !== undefined) {
    const workspace = await source.workspaceRow(workspaceId);
    if (workspace !== null) {
      // Backfill from the row itself: this is what makes the walk a walk.
      pushUnique(projectIds, workspace.project_id);
      pushUnique(tenantIds, workspace.tenant_id);
      workspaceRows.push(workspace);
    }
  }

  const projectRows: LifecycleRow[] = [];
  // Indexed, not `for…of`: a project may be reached only via the workspace
  // above, and each project row appends tenant ids the caller never named.
  for (let index = 0; index < projectIds.length; index += 1) {
    const project = await source.projectRow(projectIds[index] as string);
    if (project !== null) {
      pushUnique(tenantIds, project.tenant_id);
      projectRows.push(project);
    }
  }

  const chain: LifecycleRef[] = [];
  for (const tenantId of tenantIds) {
    const tenant = await source.tenantRow(tenantId);
    if (tenant !== null) {
      chain.push({ kind: "tenant", id: tenant.id, status: parseLifecycleStatus(tenant.status) });
    }
  }
  for (const project of projectRows) {
    chain.push({ kind: "project", id: project.id, status: parseLifecycleStatus(project.status) });
  }
  for (const workspace of workspaceRows) {
    chain.push({
      kind: "workspace",
      id: workspace.id,
      status: parseLifecycleStatus(workspace.status),
    });
  }
  return chain;
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/** Rust `check_usable_tenancy` at the request seam, over D1. */
export class D1McpTenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #control: D1Database;
  readonly #router: TenantDatabaseRouter | undefined;

  constructor(control: D1Database, router?: TenantDatabaseRouter) {
    this.#control = control;
    this.#router = router;
  }

  async admit(auth: AuthContext): Promise<LifecycleDecision> {
    // An operator credential carries no tenancy chain; Rust never gates it.
    if (auth.platformOperator) return { admitted: true };

    let chain: readonly LifecycleRef[];
    try {
      chain = await resolveLifecycleChain(
        new D1McpLifecycleRowSource(this.#control, auth.organizationId, this.#router),
        {
          tenantId: auth.organizationId,
          projectId: auth.projectId,
          workspaceId: auth.workspaceId,
        },
      );
    } catch (error) {
      return {
        admitted: "unavailable",
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    return checkLifecycleChain(chain);
  }
}

/**
 * The posture for a deployment with NO control database bound.
 *
 * It is an OUTAGE, not an admission. `resolvePorts` binds {@link UnboundAuth}
 * in the same posture, so no caller can reach this gate anyway — but a gate
 * whose "not configured" answer were `admitted: true` would become a live
 * suspension bypass the day someone made the auth port more permissive. The
 * fail-closed default is written here so that cannot happen at a distance.
 */
export class UnboundLifecycleGate implements TenancyLifecycleGatePort {
  // eslint-disable-next-line @typescript-eslint/require-await
  async admit(): Promise<LifecycleDecision> {
    return {
      admitted: "unavailable",
      detail: "no control database is bound to this Worker",
    };
  }
}

/**
 * Render a decision as the wire refusal, or `null` when the caller is admitted.
 *
 * The status/code pairs are `apps/gateway/src/middleware/auth.ts`'s, verbatim:
 * a suspended tenancy is authenticated-but-forbidden (403, naming the tier),
 * and an unreadable authority is 503 `lifecycle_status_unavailable`.
 */
export function lifecycleRefusal(decision: LifecycleDecision): AuthError | null {
  if (decision.admitted === true) return null;
  if (decision.admitted === "unavailable") {
    return {
      status: 503,
      code: "lifecycle_status_unavailable",
      message: `tenancy lifecycle lookup failed: ${decision.detail}`,
    };
  }
  return { status: 403, code: decision.code, message: decision.message };
}
