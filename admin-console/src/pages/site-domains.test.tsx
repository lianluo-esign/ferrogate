import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import SiteDomainsPage from "@/pages/site-domains";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type SiteDomain = AdminSchema<"AdminSiteDomain">;

function domain(overrides: Partial<SiteDomain> = {}): SiteDomain {
  return {
    object: "site_domain",
    hostname: "app.example.com",
    tenant_id: "org-acme",
    site: "marketing",
    serve_path: "/sites/org-acme/marketing/",
    created_at_unix: 1000,
    updated_at_unix: 1000,
    ...overrides,
  };
}

/** One `/v1/assets` summary row for the published-site enumeration. */
function assetRow(name: string, version: string): AdminSchema<"AssetSummary"> {
  return {
    id: `tenant-1:static_site:${name}:${version}`,
    asset_type: "static_site",
    name,
    version,
    content_type: "application/zip",
    content_hash: "a".repeat(64),
    size_bytes: 100,
    storage_backed: false,
    created_at_unix: 1000,
    updated_at_unix: 1000,
  };
}

function mockList(domains: SiteDomain[]): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/site-domains"), () =>
      HttpResponse.json({ object: "list", data: domains }),
    ),
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <I18nProvider>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <SiteDomainsPage />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("SiteDomainsPage", () => {
  it("lists bound hostnames with their tenant and site", async () => {
    mockList([domain(), domain({ hostname: "docs.example.com", site: "docs" })]);
    renderPage();

    expect(await screen.findByTestId("site-domain-app.example.com")).toBeInTheDocument();
    const row = screen.getByTestId("site-domain-app.example.com");
    expect(within(row).getByText("org-acme")).toBeInTheDocument();
    expect(within(row).getByText("marketing")).toBeInTheDocument();
    expect(screen.getByTestId("site-domain-docs.example.com")).toBeInTheDocument();
  });

  it("binds a valid hostname and reports ACME posture", async () => {
    mockList([]);
    // #342: the Tenant field is the shared entity picker; it hydrates a human
    // display name from the tenant-accounts catalog and submits the canonical id.
    server.use(
      http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
        HttpResponse.json({
          object: "list",
          data: [{ id: "org-acme", name: "Acme", slug: "acme" }],
          total: 1,
          offset: 0,
          limit: 20,
        }),
      ),
      http.get(gatewayUrl("/admin/v1/tenant-accounts/org-acme"), () =>
        HttpResponse.json({
          object: "tenant",
          tenant: { id: "org-acme", name: "Acme", slug: "acme" },
        }),
      ),
    );
    let bound: unknown = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/site-domains"), async ({ request }) => {
        bound = await request.json();
        return HttpResponse.json(
          {
            object: "site_domain",
            site_domain: domain({ hostname: "new.example.com", site: "docs" }),
            acme: { enabled: true, reload_triggered: true },
          },
          { status: 201 },
        );
      }),
    );
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("No bound hostnames.");

    const hostnameInput = screen.getByLabelText("Hostname (FQDN)");
    await user.type(hostnameInput, "new.example.com");
    // Select the tenant by its display name; the picker submits the id.
    await user.click(screen.getByRole("combobox", { name: "Tenant" }));
    await user.click(await screen.findByRole("option", { name: /Acme/ }));
    await user.type(screen.getByLabelText("Site"), "docs");
    await user.click(screen.getByRole("button", { name: "Bind hostname" }));

    await waitFor(() =>
      expect(bound).toEqual({
        hostname: "new.example.com",
        tenant_id: "org-acme",
        site: "docs",
      }),
    );
    // onSuccess clears the form once the bind (and its ACME posture) is accepted.
    await waitFor(() => expect(hostnameInput).toHaveValue(""));
  });

  it("backs the site field with the session tenant's published site slugs", async () => {
    mockList([]);
    // A bind must name an ALREADY-PUBLISHED site (the gateway 404s otherwise),
    // and those slugs are enumerable — the distinct `name`s of the tenant's
    // static_site asset rows — so the field is backed by that enumeration
    // instead of being blind free text.
    server.use(
      http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
        HttpResponse.json({
          object: "list",
          data: [{ id: "tenant-1", name: "Acme", slug: "acme" }],
          total: 1,
          offset: 0,
          limit: 20,
        }),
      ),
      http.get(gatewayUrl("/admin/v1/tenant-accounts/tenant-1"), () =>
        HttpResponse.json({
          object: "tenant",
          tenant: { id: "tenant-1", name: "Acme", slug: "acme" },
        }),
      ),
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            // The #397 row set: bundle-manifest rows, per-file rows and the
            // reserved marker all share the site's `name`, so the distinct
            // names are exactly the published slugs.
            assetRow("marketing", "2.1.0"),
            assetRow("marketing", "__site_file__:2.1.0:index.html"),
            assetRow("marketing", "__site_manifest__"),
            assetRow("docs", "1.0.0"),
            // A non-site asset must not leak into the suggestions.
            { ...assetRow("prompt-pack", "1.0.0"), asset_type: "prompt" },
          ],
        }),
      ),
    );
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("No bound hostnames.");

    const siteInput = screen.getByLabelText("Site");
    expect(siteInput).toHaveAttribute("list", "bind-site-options");
    // Suggestions appear only once the form targets the SESSION tenant, because
    // GET /v1/assets is scoped to the caller's own tenant.
    expect(
      document.getElementById("bind-site-options")!.querySelectorAll("option"),
    ).toHaveLength(0);

    await user.click(screen.getByRole("combobox", { name: "Tenant" }));
    await user.click(await screen.findByRole("option", { name: /Acme/ }));

    await waitFor(() =>
      expect(
        [
          ...document
            .getElementById("bind-site-options")!
            .querySelectorAll("option"),
        ].map((option) => option.getAttribute("value")),
      ).toEqual(["docs", "marketing"]),
    );
  });

  it("blocks an invalid hostname client-side without POSTing", async () => {
    mockList([]);
    let posted = false;
    server.use(
      http.post(gatewayUrl("/admin/v1/site-domains"), () => {
        posted = true;
        return HttpResponse.json({}, { status: 201 });
      }),
    );
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("No bound hostnames.");

    // Wildcard is rejected by the mirrored client-side rules.
    await user.type(screen.getByLabelText("Hostname (FQDN)"), "*.example.com");
    expect(
      await screen.findByText("wildcard hostnames cannot be bound to a site"),
    ).toBeInTheDocument();

    // Bind button is disabled while the hostname is invalid.
    expect(screen.getByRole("button", { name: "Bind hostname" })).toBeDisabled();
    expect(posted).toBe(false);
  });

  it("rejects a single-label (non-FQDN) hostname", async () => {
    mockList([]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("No bound hostnames.");

    await user.type(screen.getByLabelText("Hostname (FQDN)"), "localhost");
    expect(
      await screen.findByText(/must be a fully qualified domain name/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Bind hostname" })).toBeDisabled();
  });

  it("unbinds a hostname after confirmation", async () => {
    mockList([domain()]);
    let deleted = false;
    server.use(
      http.delete(gatewayUrl("/admin/v1/site-domains/app.example.com"), () => {
        deleted = true;
        return HttpResponse.json({
          object: "site_domain",
          id: "app.example.com",
          deleted: true,
        });
      }),
    );
    const user = userEvent.setup();
    renderPage();

    await screen.findByTestId("site-domain-app.example.com");
    await user.click(screen.getByRole("button", { name: "Unbind" }));

    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/Unbind app.example.com/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Unbind" }));

    await waitFor(() => expect(deleted).toBe(true));
  });
});
