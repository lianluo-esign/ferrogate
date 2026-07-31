/**
 * Request identity & tenant attribution — port of `ferrogate-core`'s
 * `TenantContext`, `RequestContext`, and `WorkspaceScope`.
 *
 * Load-bearing semantics preserved from the crate:
 *  - `organization_id` IS the tenant id (`tenants.id`) and is used for
 *    authorization, not merely attribution. `undefined` means "names no
 *    tenant" — legitimate only for a declared platform operator (issue #515).
 *  - `TenantContext.workspace_id` is additive and `#[serde(default)]`: legacy
 *    payloads that predate the multi-tenant hierarchy omit it and must still
 *    deserialize (all fields `.optional()`).
 *  - `WorkspaceScope::apply_to` overlays the scope onto a `TenantContext`,
 *    mapping `tenant_id → organization_id` and filling `project_id` /
 *    `workspace_id`.
 *
 * Wire keys are snake_case to match serde. serde treats every `Option<T>` field
 * as missing-⇒-None (no `deny_unknown_fields` on these structs), so the schemas
 * are non-strict (unknown keys are ignored) and optional fields may be absent.
 */
import { z } from "zod";

/** `u32` range guard (Rust `Option<u32>` for `workflow_version`). */
const u32 = z.number().int().min(0).max(4_294_967_295);

/**
 * Tenant fields resolved from a virtual API key. Every field is optional; an
 * absent `organization_id` means the identity names no tenant.
 */
export const tenantContextSchema = z.object({
  organization_id: z.string().optional(),
  team_id: z.string().optional(),
  project_id: z.string().optional(),
  workspace_id: z.string().optional(),
  user_id: z.string().optional(),
  api_key_id: z.string().optional(),
});
export type TenantContext = z.infer<typeof tenantContextSchema>;

/**
 * Request identity threaded across runtime, auth, routing, and logs. `request_id`
 * and `tenant` are required (Rust: non-`Option`, no `#[serde(default)]`); every
 * other field is optional.
 */
export const requestContextSchema = z.object({
  request_id: z.string(),
  trace_id: z.string().optional(),
  agent_run_id: z.string().optional(),
  workflow_id: z.string().optional(),
  workflow_version: u32.optional(),
  workflow_node_id: z.string().optional(),
  route: z.string().optional(),
  upstream: z.string().optional(),
  tenant: tenantContextSchema,
});
export type RequestContext = z.infer<typeof requestContextSchema>;

/**
 * Fully resolved attribution chain for a workspace: the workspace itself plus
 * the project and tenant it rolls up to. All three ids are required.
 */
export const workspaceScopeSchema = z.object({
  tenant_id: z.string(),
  project_id: z.string(),
  workspace_id: z.string(),
});
export type WorkspaceScope = z.infer<typeof workspaceScopeSchema>;

/** Construct a {@link WorkspaceScope} (mirrors Rust `WorkspaceScope::new`). */
export function newWorkspaceScope(
  tenantId: string,
  projectId: string,
  workspaceId: string,
): WorkspaceScope {
  return { tenant_id: tenantId, project_id: projectId, workspace_id: workspaceId };
}

/**
 * Overlay `scope` onto `tenant`, mapping `tenant_id → organization_id` and
 * filling `project_id` / `workspace_id` (mirrors Rust `apply_to(&mut ...)`).
 * Mutates `tenant` in place — as the `&mut` signature does — and returns the
 * same reference for convenience.
 */
export function applyWorkspaceScope(scope: WorkspaceScope, tenant: TenantContext): TenantContext {
  tenant.organization_id = scope.tenant_id;
  tenant.project_id = scope.project_id;
  tenant.workspace_id = scope.workspace_id;
  return tenant;
}
