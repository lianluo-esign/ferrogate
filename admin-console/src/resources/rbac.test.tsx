import { ResourcePage } from "@/components/resource/resource-page";
import { type AdminApiKey, apiKeysConfig } from "@/resources/api-keys";
import { permissionsConfig } from "@/resources/permissions";
import { policiesConfig } from "@/resources/policies";
import { type AdminRole, rolesConfig } from "@/resources/roles";
import { gatewayUrl, mockAdminError, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
// IAM completion (#321): generic-resource RBAC surfaces (roles, permissions,
// policies) and native api-keys, exercised through ResourcePage + MSW.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

function role(overrides: Partial<AdminRole> = {}): AdminRole {
  return {
    id: "role-admin",
    name: "Administrator",
    slug: "administrator",
    description: "Full access",
    permission_keys: ["admin.read", "admin.write"],
    created_at_unix: 1,
    updated_at_unix: 1,
    ...overrides,
  };
}

function apiKey(overrides: Partial<AdminApiKey> = {}): AdminApiKey {
  return {
    id: "key-1",
    name: "CI key",
    enabled: true,
    key_source: "env",
    scopes: ["admin.read"],
    allowed_models: [],
    denied_models: [],
    allowed_providers: [],
    denied_providers: [],
    organization_id: null,
    team_id: null,
    project_id: null,
    workspace_id: null,
    user_id: null,
    monthly_token_budget: null,
    request_limit_per_minute: null,
    expires_at_unix: null,
    log_bodies: false,
    cache_enabled: null,
    ...overrides,
  } as AdminApiKey;
}

beforeEach(() => {
  seedSession();
});

describe("RBAC roles resource", () => {
  it("lists roles with their permission keys", async () => {
    mockAdminList("/admin/v1/roles", [role()]);
    renderWithProviders(<ResourcePage config={rolesConfig} />);

    expect(await screen.findByText("Administrator")).toBeInTheDocument();
    expect(screen.getByText("admin.read, admin.write")).toBeInTheDocument();
  });

  it("creates a role (tenant-scoped POST) from the New form", async () => {
    const user = userEvent.setup();
    let createdBody: Record<string, unknown> | null = null;
    mockAdminList("/admin/v1/roles", [role()]);
    server.use(
      http.post(gatewayUrl("/admin/v1/roles"), async ({ request }) => {
        createdBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ object: "role", role: role() }, { status: 201 });
      }),
    );

    renderWithProviders(<ResourcePage config={rolesConfig} />);
    await screen.findByText("Administrator");

    await user.click(screen.getByRole("button", { name: "New" }));
    await user.type(await screen.findByLabelText("Name *"), "Auditor");
    await user.type(screen.getByLabelText("Slug *"), "auditor");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(createdBody).toMatchObject({ name: "Auditor", slug: "auditor" }));
  });

  it("offers delete but not edit (roles have no update endpoint)", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/roles", [role()]);
    renderWithProviders(<ResourcePage config={rolesConfig} />);

    await screen.findByText("Administrator");
    await user.click(screen.getByRole("button", { name: "Actions for Administrator" }));
    expect(await screen.findByRole("menuitem", { name: "Delete" })).toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "Edit" })).not.toBeInTheDocument();
  });

  it("surfaces a 403 from the roles list (tenant-scope denial)", async () => {
    mockAdminError("get", "/admin/v1/roles", 403, "forbidden", "missing rbac.read");
    renderWithProviders(<ResourcePage config={rolesConfig} />);

    expect(await screen.findByText(/Failed to load roles: missing rbac.read/)).toBeInTheDocument();
  });
});

describe("RBAC permissions resource", () => {
  it("lists permissions", async () => {
    mockAdminList("/admin/v1/permissions", [
      {
        id: "perm-1",
        key: "admin.read",
        name: "Admin read",
        description: "Read admin resources",
        created_at_unix: 1,
        updated_at_unix: 1,
      },
    ]);
    renderWithProviders(<ResourcePage config={permissionsConfig} />);

    expect(await screen.findByText("admin.read")).toBeInTheDocument();
    expect(screen.getByText("Admin read")).toBeInTheDocument();
  });
});

describe("RBAC policies resource", () => {
  it("lists policy rules with their effect", async () => {
    mockAdminList("/admin/v1/policies", [
      {
        name: "block-o1",
        effect: "deny",
        organization_ids: [],
        project_ids: [],
        api_key_ids: [],
        models: ["o1"],
        providers: [],
        code: "policy_denied",
        message: "denied",
        enabled: true,
      },
    ]);
    renderWithProviders(<ResourcePage config={policiesConfig} />);

    expect(await screen.findByText("block-o1")).toBeInTheDocument();
    expect(screen.getByText("deny")).toBeInTheDocument();
  });
});

describe("native api-keys resource", () => {
  it("lists api keys", async () => {
    mockAdminList("/admin/v1/api-keys", [apiKey()]);
    renderWithProviders(<ResourcePage config={apiKeysConfig} />);

    expect(await screen.findByText("CI key")).toBeInTheDocument();
  });

  it("edits an api key (PUT round-trip)", async () => {
    const user = userEvent.setup();
    let putBody: Record<string, unknown> | null = null;
    mockAdminList("/admin/v1/api-keys", [apiKey()]);
    server.use(
      http.put(gatewayUrl("/admin/v1/api-keys/key-1"), async ({ request }) => {
        putBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ object: "api_key", key: apiKey() });
      }),
    );

    renderWithProviders(<ResourcePage config={apiKeysConfig} />);
    await screen.findByText("CI key");
    await user.click(screen.getByRole("button", { name: "Actions for CI key" }));
    await user.click(await screen.findByRole("menuitem", { name: "Edit" }));

    const nameInput = await screen.findByLabelText("Name *");
    await user.clear(nameInput);
    await user.type(nameInput, "Renamed key");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(putBody).toMatchObject({ name: "Renamed key" }));
  });

  it("deletes an api key (DELETE round-trip)", async () => {
    const user = userEvent.setup();
    let deleted = false;
    mockAdminList("/admin/v1/api-keys", [apiKey()]);
    server.use(
      http.delete(gatewayUrl("/admin/v1/api-keys/key-1"), () => {
        deleted = true;
        return HttpResponse.json({ object: "deleted", id: "key-1" });
      }),
    );

    renderWithProviders(<ResourcePage config={apiKeysConfig} />);
    await screen.findByText("CI key");
    await user.click(screen.getByRole("button", { name: "Actions for CI key" }));
    await user.click(await screen.findByRole("menuitem", { name: "Delete" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Delete",
      }),
    );

    await waitFor(() => expect(deleted).toBe(true));
  });
});
