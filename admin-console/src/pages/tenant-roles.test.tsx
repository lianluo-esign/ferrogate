// Tenant role bindings page (#321 / #232): assign + remove role bindings for the
// signed-in tenant, and surface a 403 when a tenant-scoped caller is denied.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import TenantRolesPage from "@/pages/tenant-roles";
import { gatewayUrl, mockAdminError, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

function binding(role_id: string) {
  return { id: `bind-${role_id}`, tenant_id: "tenant-1", role_id, created_at_unix: 1 };
}

beforeEach(() => {
  // Default tenant is the signed-in tenant ("tenant-1").
  seedSession();
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

    await user.type(screen.getByLabelText("Role ID to assign"), "role-auditor");
    await user.click(screen.getByRole("button", { name: "Assign role" }));

    await waitFor(() => expect(posted).toEqual({ role_id: "role-auditor" }));
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
