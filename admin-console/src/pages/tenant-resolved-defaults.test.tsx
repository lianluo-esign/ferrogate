// #340 acceptance box 7: the tenancy module's resolved-defaults lookup was the
// last entity-backed field still asking an operator to paste a raw tenant id
// (`<Input id="tenant-id" placeholder="tenant-abc123">`). It now uses the same
// shared #337 tenant-accounts picker as tenant-roles and payment-methods, and
// the canonical `id` still drives
// `/admin/v1/tenant-accounts/{id}/resolved-defaults`.
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, expect, it } from "vitest";
import TenantResolvedDefaultsPage from "@/pages/tenant-resolved-defaults";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

const tenant = {
  id: "tenant-acme-01",
  name: "Acme operations",
  slug: "acme-ops",
  status: "active",
  plan_id: "enterprise",
  created_at_unix: 1_720_000_000,
  updated_at_unix: 1_720_086_400,
};

beforeEach(() => {
  seedSession();
  server.use(
    http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
      HttpResponse.json({ object: "list", data: [tenant], total: 1, offset: 0, limit: 20 }),
    ),
    http.get(gatewayUrl(`/admin/v1/tenant-accounts/${tenant.id}`), () =>
      HttpResponse.json({ object: "tenant", tenant }),
    ),
  );
});

it("looks a tenant up by picking it, never by typing an id", async () => {
  let requestedPath: string | null = null;
  server.use(
    http.get(
      gatewayUrl(`/admin/v1/tenant-accounts/${tenant.id}/resolved-defaults`),
      ({ request }) => {
        requestedPath = new URL(request.url).pathname;
        return HttpResponse.json({
          tenant_id: tenant.id,
          plan_id: "enterprise",
          model_allowlist: ["fast-chat"],
          rpm_limit: 600,
          tpm_limit: null,
          monthly_budget_usd: 250,
          mcp_enabled: true,
          extension_tools_enabled: false,
          self_hosted_workers_enabled: true,
          asset_hosting_enabled: true,
          default_asset_storage_quota_bytes: null,
        });
      },
    ),
  );
  const user = userEvent.setup();
  renderWithProviders(<TenantResolvedDefaultsPage />);

  // No free-text id entry survives on this form.
  expect(screen.queryByRole("textbox", { name: /tenant/i })).not.toBeInTheDocument();

  const picker = screen.getByRole("combobox", { name: "Tenant ID" });
  await user.click(picker);
  // The option is labelled by the tenant's NAME while the canonical id is what
  // the lookup path carries.
  await user.click(await screen.findByRole("option", { name: /Acme operations/ }));
  await user.click(screen.getByRole("button", { name: "Look up" }));

  expect(await screen.findByText("Plan: enterprise")).toBeVisible();
  await waitFor(() =>
    expect(requestedPath).toBe(`/admin/v1/tenant-accounts/${tenant.id}/resolved-defaults`),
  );
});
