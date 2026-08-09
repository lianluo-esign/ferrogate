import TenantRolesPage from "@/pages/tenant-roles";
import { gatewayUrl, mockAdminError, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
// Tenant role bindings page (#321 / #232): assign + remove role bindings for the
// signed-in tenant, and surface a 403 when a tenant-scoped caller is denied.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

function binding(role_id: string) {
  return { id: `bind-${role_id}`, tenant_id: "tenant-1", role_id, created_at_unix: 1 };
}

// #340: the tenant + role fields are shared #337 entity pickers now, so every
// render hydrates the default tenant and (when opened) lists roles. Install the
// catalog handlers these pickers hit; onUnhandledRequest is "error", so an
// un-mocked picker call would fail the test rather than silently pass.
function installPickerHandlers() {
  server.use(
    http.get(gatewayUrl("/admin/v1/tenant-accounts/tenant-1"), () =>
      HttpResponse.json({
        object: "tenant",
        tenant: { id: "tenant-1", name: "Acme", slug: "acme" },
      }),
    ),
    http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
      HttpResponse.json({ object: "list", data: [{ id: "tenant-1", name: "Acme", slug: "acme" }] }),
    ),
    http.get(gatewayUrl("/admin/v1/roles"), () =>
      HttpResponse.json({
        object: "list",
        data: [
          { id: "role-admin", name: "Admin", slug: "admin" },
          { id: "role-auditor", name: "Auditor", slug: "auditor" },
        ],
      }),
    ),
  );
}

beforeEach(() => {
  // Default tenant is the signed-in tenant ("tenant-1").
  seedSession();
  installPickerHandlers();
});

describe("TenantRolesPage", () => {
  it("lists bindings for the signed-in tenant and assigns a role", async () => {
    const user = userEvent.setup();
    let posted: Record<string, unknown> | null = null;
    mockAdminList("/admin/v1/tenant-roles/tenant-1", [binding("role-admin")]);
    server.use(
      http.post(gatewayUrl("/admin/v1/tenant-roles/tenant-1"), async ({ request }) => {
        posted = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(binding("role-auditor"), { status: 201 });
      }),
    );

    renderWithProviders(<TenantRolesPage />);
    expect(await screen.findByText("role-admin")).toBeInTheDocument();

    // #340: the role is chosen from the roles catalog picker, not typed. The
    // binding still submits the role's canonical id.
    await user.click(screen.getByRole("combobox", { name: "Role" }));
    await user.click(await screen.findByRole("option", { name: /Auditor/ }));
    await user.click(screen.getByRole("button", { name: "Assign role" }));

    await waitFor(() => expect(posted).toEqual({ role_id: "role-auditor" }));
  });

  it("hydrates the default tenant picker to its human label", async () => {
    mockAdminList("/admin/v1/tenant-roles/tenant-1", []);
    renderWithProviders(<TenantRolesPage />);

    // The tenant field is a picker (combobox), not a free-text id input.
    const tenantPicker = screen.getByRole("combobox", { name: "Tenant" });
    expect(tenantPicker).toBeInTheDocument();
    // The signed-in tenant id hydrates to its display name.
    await waitFor(() => expect(tenantPicker).toHaveTextContent("Acme"));
    // No raw id textboxes remain for tenant or role.
    expect(screen.queryByRole("textbox", { name: /Tenant ID/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /Role ID/ })).not.toBeInTheDocument();
  });

  it("removes a binding after confirmation", async () => {
    const user = userEvent.setup();
    let deleted = false;
    mockAdminList("/admin/v1/tenant-roles/tenant-1", [binding("role-admin")]);
    server.use(
      http.delete(gatewayUrl("/admin/v1/tenant-roles/tenant-1/role-admin"), () => {
        deleted = true;
        return HttpResponse.json({ object: "deleted" });
      }),
    );

    renderWithProviders(<TenantRolesPage />);
    await screen.findByText("role-admin");

    await user.click(screen.getByRole("button", { name: "Remove" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Remove",
      }),
    );

    await waitFor(() => expect(deleted).toBe(true));
  });

  it("surfaces a 403 when the caller may not manage this tenant", async () => {
    mockAdminError(
      "get",
      "/admin/v1/tenant-roles/tenant-1",
      403,
      "forbidden",
      "tenant scope mismatch",
    );
    renderWithProviders(<TenantRolesPage />);

    expect(
      await screen.findByText(/Failed to load tenant roles: tenant scope mismatch/),
    ).toBeInTheDocument();
  });
});
