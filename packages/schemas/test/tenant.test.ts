import { describe, expect, test } from "vitest";
import {
  applyWorkspaceScope,
  newWorkspaceScope,
  requestContextSchema,
  type TenantContext,
  tenantContextSchema,
  workspaceScopeSchema,
} from "@ferrogate/schemas";

// These exercise the ferrogate-core wire schemas as surfaced by the schemas
// façade. Core uses `.optional()` for every serde `Option<T>` field, so the
// TS twin of `None` is an absent key / `undefined` (JSON.stringify drops it).

describe("tenantContextSchema", () => {
  // Mirrors Rust `tenant_context_deserializes_legacy_payload_without_workspace_id`.
  test("deserializes legacy payload without workspace_id", () => {
    const legacy = {
      organization_id: "org-1",
      team_id: "team-1",
      project_id: "proj-1",
      user_id: "user-1",
      api_key_id: "key-1",
    };
    const tenant = tenantContextSchema.parse(legacy);
    expect(tenant.organization_id).toBe("org-1");
    expect(tenant.project_id).toBe("proj-1");
    expect(tenant.workspace_id).toBeUndefined();
  });

  // Mirrors Rust `tenant_context_roundtrips_with_workspace_id` (None → absent key).
  test("roundtrips with workspace_id", () => {
    const tenant: TenantContext = {
      organization_id: "org-1",
      project_id: "proj-1",
      workspace_id: "ws-1",
      api_key_id: "key-1",
    };
    const decoded = tenantContextSchema.parse(JSON.parse(JSON.stringify(tenant)));
    expect(decoded).toEqual(tenant);
    expect(decoded.workspace_id).toBe("ws-1");
  });

  test("accepts the empty object (all fields absent)", () => {
    expect(tenantContextSchema.parse({})).toEqual({});
  });

  // Edge: a wrong-typed field is rejected.
  test("rejects a non-string tenant field", () => {
    expect(tenantContextSchema.safeParse({ organization_id: 42 }).success).toBe(false);
  });
});

describe("workspaceScope", () => {
  test("newWorkspaceScope builds the attribution triple", () => {
    expect(newWorkspaceScope("t", "p", "w")).toEqual({
      tenant_id: "t",
      project_id: "p",
      workspace_id: "w",
    });
  });

  test("schema requires all three fields", () => {
    expect(workspaceScopeSchema.safeParse({ tenant_id: "t", project_id: "p" }).success).toBe(
      false,
    );
  });

  // Mirrors Rust `workspace_scope_applies_attribution_chain`.
  test("applyWorkspaceScope overlays org/project/workspace onto a default tenant", () => {
    const scope = newWorkspaceScope("tenant-1", "project-1", "workspace-1");
    const tenant: TenantContext = {};
    const returned = applyWorkspaceScope(scope, tenant);
    expect(returned).toBe(tenant); // mutates and returns the same reference
    expect(tenant.organization_id).toBe("tenant-1");
    expect(tenant.project_id).toBe("project-1");
    expect(tenant.workspace_id).toBe("workspace-1");
  });

  // Edge: apply_to deliberately leaves team_id/user_id/api_key_id untouched.
  test("applyWorkspaceScope leaves team_id/user_id/api_key_id untouched", () => {
    const tenant: TenantContext = {
      team_id: "team-x",
      user_id: "user-x",
      api_key_id: "key-x",
      organization_id: "stale-org",
    };
    applyWorkspaceScope(newWorkspaceScope("t", "p", "w"), tenant);
    expect(tenant.organization_id).toBe("t"); // overwritten
    expect(tenant.team_id).toBe("team-x");
    expect(tenant.user_id).toBe("user-x");
    expect(tenant.api_key_id).toBe("key-x");
  });
});

describe("requestContextSchema", () => {
  test("requires request_id and tenant, allows everything else absent", () => {
    const parsed = requestContextSchema.parse({ request_id: "r1", tenant: {} });
    expect(parsed.request_id).toBe("r1");
    expect(parsed.trace_id).toBeUndefined();
    expect(parsed.tenant).toEqual({});
  });

  test("rejects a payload missing tenant", () => {
    expect(requestContextSchema.safeParse({ request_id: "r1" }).success).toBe(false);
  });

  test("rejects a payload missing request_id", () => {
    expect(requestContextSchema.safeParse({ tenant: {} }).success).toBe(false);
  });

  // Edge: workflow_version is a Rust u32 → non-negative integer within u32 range.
  test("workflow_version honors the u32 bound", () => {
    const base = { request_id: "r", tenant: {} };
    expect(requestContextSchema.safeParse({ ...base, workflow_version: 7 }).success).toBe(true);
    expect(requestContextSchema.safeParse({ ...base, workflow_version: -1 }).success).toBe(false);
    expect(requestContextSchema.safeParse({ ...base, workflow_version: 1.5 }).success).toBe(false);
    expect(
      requestContextSchema.safeParse({ ...base, workflow_version: 4_294_967_296 }).success,
    ).toBe(false);
  });
});
