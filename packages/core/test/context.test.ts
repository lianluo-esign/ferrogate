import { describe, expect, it } from "vitest";

import {
  type TenantContext,
  applyWorkspaceScope,
  newWorkspaceScope,
  requestContextSchema,
  tenantContextSchema,
  workspaceScopeSchema,
} from "../src/index";

describe("TenantContext", () => {
  // Mirrors Rust `tenant_context_deserializes_legacy_payload_without_workspace_id`.
  it("deserializes a legacy payload that omits workspace_id", () => {
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

  // Mirrors Rust `tenant_context_roundtrips_with_workspace_id`.
  it("round-trips through JSON with workspace_id", () => {
    const tenant = {
      organization_id: "org-1",
      project_id: "proj-1",
      workspace_id: "ws-1",
      api_key_id: "key-1",
    } satisfies TenantContext;
    const decoded = tenantContextSchema.parse(JSON.parse(JSON.stringify(tenant)));
    expect(decoded).toEqual(tenant);
    expect(decoded.workspace_id).toBe("ws-1");
  });

  it("accepts an empty object (every field optional) and ignores unknown keys", () => {
    expect(tenantContextSchema.parse({})).toEqual({});
    const parsed = tenantContextSchema.parse({ organization_id: "o", surprise: "x" });
    expect(parsed.organization_id).toBe("o");
    expect("surprise" in parsed).toBe(false);
  });
});

describe("RequestContext", () => {
  it("requires request_id and tenant", () => {
    expect(requestContextSchema.safeParse({ request_id: "r1" }).success).toBe(false);
    expect(requestContextSchema.safeParse({ tenant: {} }).success).toBe(false);
    const ctx = requestContextSchema.parse({ request_id: "r1", tenant: {} });
    expect(ctx.request_id).toBe("r1");
    expect(ctx.tenant).toEqual({});
  });

  it("treats optional identity fields as absent-⇒-undefined", () => {
    const ctx = requestContextSchema.parse({ request_id: "r1", tenant: { organization_id: "o" } });
    expect(ctx.agent_run_id).toBeUndefined();
    expect(ctx.workflow_id).toBeUndefined();
    expect(ctx.trace_id).toBeUndefined();
  });

  it("bounds workflow_version to a u32 (edge case)", () => {
    expect(
      requestContextSchema.safeParse({ request_id: "r", tenant: {}, workflow_version: -1 }).success,
    ).toBe(false);
    expect(
      requestContextSchema.safeParse({ request_id: "r", tenant: {}, workflow_version: 1.5 })
        .success,
    ).toBe(false);
    expect(
      requestContextSchema.safeParse({
        request_id: "r",
        tenant: {},
        workflow_version: 4_294_967_296,
      }).success,
    ).toBe(false);
    const ok = requestContextSchema.parse({ request_id: "r", tenant: {}, workflow_version: 7 });
    expect(ok.workflow_version).toBe(7);
  });
});

describe("WorkspaceScope", () => {
  it("newWorkspaceScope builds the attribution chain", () => {
    const scope = newWorkspaceScope("tenant-1", "project-1", "workspace-1");
    expect(scope).toEqual({
      tenant_id: "tenant-1",
      project_id: "project-1",
      workspace_id: "workspace-1",
    });
    expect(workspaceScopeSchema.parse(scope)).toEqual(scope);
  });

  // Mirrors Rust `workspace_scope_applies_attribution_chain`.
  it("applyWorkspaceScope overlays tenant_id → organization_id (mutates in place)", () => {
    const scope = newWorkspaceScope("tenant-1", "project-1", "workspace-1");
    const tenant: TenantContext = {};
    const returned = applyWorkspaceScope(scope, tenant);
    expect(tenant.organization_id).toBe("tenant-1");
    expect(tenant.project_id).toBe("project-1");
    expect(tenant.workspace_id).toBe("workspace-1");
    expect(returned).toBe(tenant);
  });

  it("requires all three ids (edge case)", () => {
    expect(workspaceScopeSchema.safeParse({ tenant_id: "t", project_id: "p" }).success).toBe(false);
  });
});
