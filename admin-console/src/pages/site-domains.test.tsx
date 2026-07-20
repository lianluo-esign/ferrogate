import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
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
      <AuthProvider>
        <QueryClientProvider client={createTestQueryClient()}>
          <SiteDomainsPage />
        </QueryClientProvider>
      </AuthProvider>
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
    await user.type(screen.getByLabelText("Tenant"), "org-acme");
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
