/**
 * The DURABLE tenancy lifecycle gate — issue #514's `status` column, read from
 * the control database instead of a Worker var.
 *
 * ## What this closes
 *
 * `adapters.ts` resolved the whole gate from `TENANCY_LIFECYCLE`, a JSON map of
 * `tenant_id → status` baked into `wrangler.toml`. That had two defects against
 * the Rust original, and they compound:
 *
 *  1. **It was not the row the admin API writes.** `PATCH
 *     /admin/v1/tenant-accounts/{id} {"status":"suspended"}` persists into
 *     `control_plane_resources` and the gate never looked there, so the one
 *     control this app exposes for stopping a tenant had no effect on that
 *     tenant's traffic until somebody redeployed a var. That is precisely the
 *     "decorative `status` column" #514 exists to kill, reproduced in the port.
 *  2. **It checked only the TENANT.** Rust's `resolve_lifecycle_chain` WALKS the
 *     `tenant → project → workspace` hierarchy, and its docblock records the
 *     bypass that motivated the walk: a credential that declares only a
 *     `project_id` (entirely legal — a native key's tenant is optional)
 *     produced the chain `[project(active)]`, so the suspended TENANT above it
 *     was never read and suspending a tenant did not stop its projects' keys.
 *
 * Both are closed here, off the SAME rows the admin surface mutates.
 *
 * ## Reads run as PLATFORM OPERATOR, deliberately
 *
 * {@link StoreTenancyLifecycleGate} resolves the chain with
 * `{ kind: "platform_operator" }` rather than with the caller's own scope. This
 * is a deny-side read and it can only ever RESTRICT, so widening it is safe;
 * narrowing it is not. Two concrete rows the caller's own scope would hide:
 *
 *  - a workspace's parent tenant account, when the credential declares a
 *    workspace but carries no tenant (the walk's whole point); and
 *  - a tenant's own `tenant-accounts` document, if it were ever written
 *    un-attributed or under a different `tenant_id` — under a tenant-scoped
 *    read that row would be invisible and the suspension would silently not
 *    apply, which is a gate that fails OPEN on exactly the input it exists for.
 *
 * ## Absence is not suspension; a storage failure is not "active"
 *
 * An id that names no row is skipped (Rust `LifecycleRef`: "inventing a denial
 * here would make a typo indistinguishable from a suspension"), and an
 * unrecognized/blank `status` parses to `active` (Rust `LifecycleStatus::parse`
 * — rows predating #514 carry arbitrary values and failing closed on them would
 * revoke every existing tenant). The WRITE side is strict instead:
 * `routes/tenant_hierarchy.ts` validates `status` against
 * `lifecycleStatusSchema`, so `{"status":"suspend"}` is a 400 rather than a
 * green confirmation for a control that was never applied.
 *
 * A store read that THROWS is `unavailable` → **503**, never an implicit allow.
 * Rust: "fail-open here would hand every suspended tenant a trivial bypass
 * (make the control plane flap and keep serving)."
 */
import type { ApiOperation } from "../contract.js";
import type {
  AuthContext,
  CallerScope,
  ControlPlaneStore,
  LifecycleDecision,
  StoreRecord,
  TenancyLifecycleGatePort,
} from "../ports.js";

/** Rust `LifecycleStatus`. */
export type LifecycleStatus = "active" | "disabled" | "suspended" | "deleted";

/** The collections the hierarchy rows live in (`routes/tenant_hierarchy.ts`). */
export const TENANT_ACCOUNTS_COLLECTION = "tenant-accounts";
export const PROJECTS_COLLECTION = "projects";
export const WORKSPACES_COLLECTION = "workspaces";

/** The gate reads to DENY, so it reads everything. See the module docblock. */
const GATE_SCOPE: CallerScope = { kind: "platform_operator" };

/**
 * The operations that exist to turn an off hierarchy back ON — Rust
 * `LifecycleSeam::Recovery` (#514, finding 5).
 *
 * `disabled` is the TENANT's own self-service switch, so gating its reversal on
 * it would make the switch a one-way door: a console key scoped to the project
 * it just disabled could never reach the PUT that undoes it. `suspended` and
 * `deleted` are platform actions and still deny here.
 */
export const RECOVERY_OPERATION_IDS: ReadonlySet<string> = new Set([
  "updateTenantAccount",
  "replaceTenantAccount",
  "updateProject",
  "replaceProject",
  "updateWorkspace",
  "replaceWorkspace",
]);

/**
 * Rust `LifecycleStatus::parse` — case- and whitespace-insensitive, and
 * anything outside the closed vocabulary (including absent and `""`) is
 * `active`. See the module docblock for why that default is load-bearing.
 */
export function parseLifecycleStatus(raw: unknown): LifecycleStatus {
  if (typeof raw !== "string") return "active";
  switch (raw.trim().toLowerCase()) {
    case "suspended":
      return "suspended";
    case "disabled":
      return "disabled";
    case "deleted":
      return "deleted";
    default:
      return "active";
  }
}

/** One resolved ancestor in the chain. Rust `LifecycleRef`. */
export interface LifecycleRef {
  readonly kind: "tenant" | "project" | "workspace";
  readonly id: string;
  readonly status: LifecycleStatus;
}

/** Rust `LifecycleRejection::code`, for the request/recovery seams. */
export function lifecycleCode(status: LifecycleStatus): string {
  switch (status) {
    case "suspended":
      return "tenancy_suspended";
    case "disabled":
      return "tenancy_disabled";
    case "deleted":
      return "tenancy_deleted";
    // Unreachable: an active row never produces a rejection. Kept total rather
    // than thrown so a future status can never turn this seam into a crash.
    default:
      return "tenancy_inactive";
  }
}

/** Rust `LifecycleRejection::message` for `Request`/`Recovery`, verbatim. */
export function lifecycleMessage(reference: LifecycleRef): string {
  return `${reference.kind} ${reference.id} is ${reference.status}; requests authenticated against this tenancy chain are refused`;
}

/**
 * THE pure decision, shared by the durable gate and the declarative one so the
 * two cannot answer differently for the same chain.
 *
 * `chain` must be ordered shallowest-first so the rejection names the ROOT
 * cause: when suspending a tenant cascades onto its project and workspace, the
 * caller is told the TENANT is suspended rather than being sent chasing the
 * workspace.
 */
export function decideLifecycleChain(
  chain: readonly LifecycleRef[],
  operation: { readonly operationId: string },
): LifecycleDecision {
  const recovery = RECOVERY_OPERATION_IDS.has(operation.operationId);
  for (const reference of chain) {
    if (reference.status === "active") continue;
    if (reference.status === "disabled" && recovery) continue;
    return {
      admitted: false,
      code: lifecycleCode(reference.status),
      message: lifecycleMessage(reference),
    };
  }
  return { admitted: true };
}

function trimmed(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const candidate = value.trim();
  return candidate === "" ? null : candidate;
}

/** Rust `push_unique`: blank and duplicate ids never cost a second read. */
function pushUnique(ids: string[], candidate: unknown): void {
  const id = trimmed(candidate);
  if (id === null || ids.includes(id)) return;
  ids.push(id);
}

/**
 * The durable gate: {@link TenancyLifecycleGatePort} over the hierarchy rows the
 * admin surface writes, with a declarative fallback.
 *
 * **The fallback rule is the one the sibling adapters use** (`D1RbacAuthorizer`,
 * `D1ApiKeyAuthenticator`): when the caller's declared chain resolves to NO
 * hierarchy rows at all, the deployment has not moved its tenancy into the
 * database and the declarative `TENANCY_LIFECYCLE` gate decides. A chain that
 * DOES resolve rows is decided by those rows alone, so provisioning a
 * `tenant-accounts` document can never be second-guessed by a stale var — and,
 * in the direction that matters, a `status: "suspended"` written through the
 * admin API takes effect on the very next request with no redeploy.
 */
export class StoreTenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #store: ControlPlaneStore;
  readonly #fallback: TenancyLifecycleGatePort;

  constructor(store: ControlPlaneStore, fallback: TenancyLifecycleGatePort) {
    this.#store = store;
    this.#fallback = fallback;
  }

  async admit(auth: AuthContext, operation: ApiOperation): Promise<LifecycleDecision> {
    const declaredTenant = trimmed(auth.tenancy.tenantId);
    const declaredProject = trimmed(auth.tenancy.projectId);
    const declaredWorkspace = trimmed(auth.tenancy.workspaceId);
    // Rust `TenancyRefs::is_empty`: a credential that declares no chain at all
    // (a platform operator key) is not gated, and costs no reads.
    if (declaredTenant === null && declaredProject === null && declaredWorkspace === null) {
      return { admitted: true };
    }

    let chain: readonly LifecycleRef[];
    try {
      chain = await this.#resolveChain(declaredTenant, declaredProject, declaredWorkspace);
    } catch (error) {
      // Never "active". Rust `LifecycleGateError::Unavailable` → 503.
      return {
        admitted: "unavailable",
        detail: `tenancy lifecycle lookup failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    if (chain.length === 0) return this.#fallback.admit(auth, operation);
    return decideLifecycleChain(chain, operation);
  }

  /**
   * Rust `resolve_lifecycle_chain`, walking the hierarchy rather than the
   * caller's declaration:
   *
   *  1. resolve the declared workspace — its row carries `project_id` and
   *     `tenant_id`, so its ancestors join the chain even when the caller named
   *     neither;
   *  2. resolve every candidate project — declared AND the workspace's parent —
   *     each of which carries `tenant_id`;
   *  3. resolve every candidate tenant — declared AND every ancestor discovered
   *     above.
   *
   * Declared and derived ids are UNIONed, never substituted: when a caller names
   * a tenant that disagrees with the row's own parent, both are checked and
   * either one being inactive denies. There is no ordering in which a suspended
   * ancestor is skipped.
   */
  async #resolveChain(
    declaredTenant: string | null,
    declaredProject: string | null,
    declaredWorkspace: string | null,
  ): Promise<readonly LifecycleRef[]> {
    const tenantIds: string[] = [];
    const projectIds: string[] = [];
    const workspaces: StoreRecord[] = [];

    pushUnique(tenantIds, declaredTenant);
    pushUnique(projectIds, declaredProject);

    if (declaredWorkspace !== null) {
      const workspace = await this.#store.get(WORKSPACES_COLLECTION, GATE_SCOPE, declaredWorkspace);
      if (workspace !== null) {
        pushUnique(projectIds, workspace.project_id);
        pushUnique(tenantIds, workspace.tenant_id);
        workspaces.push(workspace);
      }
    }

    const projects: StoreRecord[] = [];
    for (const projectId of projectIds) {
      const project = await this.#store.get(PROJECTS_COLLECTION, GATE_SCOPE, projectId);
      if (project === null) continue;
      pushUnique(tenantIds, project.tenant_id);
      projects.push(project);
    }

    // Shallowest-first: every tenant, then every project, then every workspace.
    const chain: LifecycleRef[] = [];
    for (const tenantId of tenantIds) {
      const account = await this.#store.get(TENANT_ACCOUNTS_COLLECTION, GATE_SCOPE, tenantId);
      if (account === null) continue;
      chain.push({
        kind: "tenant",
        id: String(account.id),
        status: parseLifecycleStatus(account.status),
      });
    }
    for (const project of projects) {
      chain.push({
        kind: "project",
        id: String(project.id),
        status: parseLifecycleStatus(project.status),
      });
    }
    for (const workspace of workspaces) {
      chain.push({
        kind: "workspace",
        id: String(workspace.id),
        status: parseLifecycleStatus(workspace.status),
      });
    }
    return chain;
  }
}
