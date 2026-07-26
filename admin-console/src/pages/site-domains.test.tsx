import { render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { toast } from "sonner";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, type Locale } from "@/i18n";
import SiteDomainsPage from "@/pages/site-domains";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type SiteDomain = AdminSchema<"AdminSiteDomain">;

/**
 * The shape the gateway ACTUALLY serializes for a bound hostname: #488 added
 * `verification_state` + `serving` to `admin_site_domain()` with no
 * `skip_serializing_if`, so the listing carries both on every row — while the
 * generated client declares them optional, which is what let fixtures omit them
 * and hide the fact that a bound hostname may not be serving at all. Typing the
 * base fixture `Required` makes dropping either a compile error.
 */
type WireSiteDomain = SiteDomain &
  Required<Pick<SiteDomain, "verification_state" | "serving">>;

const BOUND_DOMAIN: WireSiteDomain = {
  object: "site_domain",
  hostname: "app.example.com",
  tenant_id: "org-acme",
  site: "marketing",
  serve_path: "/sites/org-acme/marketing/",
  verification_state: "verified",
  serving: true,
  created_at_unix: 1000,
  updated_at_unix: 1000,
};

function domain(overrides: Partial<SiteDomain> = {}): SiteDomain {
  return { ...BOUND_DOMAIN, ...overrides };
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

function renderPage(locale?: Locale) {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale={locale}>
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

  it("reports each hostname's liveness, and the DNS record a pending one still needs", async () => {
    // Post-#488 a bound hostname does not serve until its DNS ownership proof
    // resolves, and the listing says so per row. A page that shows only the
    // bound timestamp presents a hostname the gateway REFUSES exactly like a
    // live one.
    mockList([
      domain(),
      domain({
        hostname: "pending.example.com",
        verification_state: "pending_verification",
        serving: false,
      }),
    ]);
    server.use(
      http.get(gatewayUrl("/admin/v1/site-domains/pending.example.com"), () =>
        HttpResponse.json({
          object: "site_domain",
          site_domain: domain({
            hostname: "pending.example.com",
            verification_state: "pending_verification",
            serving: false,
          }),
          acme: { enabled: true, reload_triggered: false },
          verification: {
            object: "site_domain_verification",
            state: "pending_verification",
            serves: false,
            tenant_id: "org-acme",
            hostname: "pending.example.com",
            site: "marketing",
            challenge_record_name: "_ferrogate-challenge.pending.example.com",
            challenge_record_type: "TXT",
            challenge_record_value: "ferrogate-site-verify=deadbeef",
            issued_at_unix: 1000,
            token_expires_at_unix: 1_700_003_600,
            attempt_count: 0,
          } satisfies AdminSchema<"AdminSiteDomainVerification">,
        }),
      ),
    );
    renderPage();

    const live = await screen.findByTestId("site-domain-app.example.com");
    expect(within(live).getByText("Serving")).toBeInTheDocument();
    expect(within(live).getByText("Ownership verified")).toBeInTheDocument();

    const pending = screen.getByTestId("site-domain-pending.example.com");
    expect(within(pending).getByText("Not serving")).toBeInTheDocument();
    expect(within(pending).getByText("Pending DNS verification")).toBeInTheDocument();
    expect(within(pending).queryByText("Serving")).toBeNull();

    // The remedy is offered for the pending hostname only.
    const challenge = await screen.findByTestId(
      "site-domain-challenge-pending.example.com",
    );
    expect(challenge).toHaveTextContent("_ferrogate-challenge.pending.example.com");
    expect(challenge).toHaveTextContent("ferrogate-site-verify=deadbeef");
    expect(
      screen.queryByTestId("site-domain-challenge-app.example.com"),
    ).toBeNull();
  });

  it("says Unknown for a hostname whose liveness the gateway does not report", async () => {
    mockList([domain({ verification_state: undefined, serving: undefined })]);
    renderPage();

    const row = await screen.findByTestId("site-domain-app.example.com");
    // Two Unknowns — the serving badge and the verification state — and no
    // guessed posture in either.
    expect(within(row).getAllByText("Unknown")).toHaveLength(2);
    expect(within(row).queryByText("Serving")).toBeNull();
    expect(within(row).queryByText("Not serving")).toBeNull();
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

  // Same finding as the drawer's: the gateway answers 202 for an UNPROVEN
  // binding and keeps that hostname out of the ACME order set, while
  // `acme.enabled` keeps reporting the gateway-wide flag. The toast must not
  // announce an enrolment that did not happen.
  it("does not claim ACME enrolment for an UNPROVEN (202) binding", async () => {
    mockList([]);
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
      http.post(gatewayUrl("/admin/v1/site-domains"), () =>
        HttpResponse.json(
          {
            object: "site_domain",
            site_domain: domain({
              hostname: "new.example.com",
              site: "docs",
              serving: false,
              verification_state: "pending_verification",
            }),
            acme: { enabled: true, reload_triggered: true },
          },
          { status: 202 },
        ),
      ),
    );
    const success = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderPage();
      await screen.findByText("No bound hostnames.");

      await user.type(screen.getByLabelText("Hostname (FQDN)"), "new.example.com");
      await user.click(screen.getByRole("combobox", { name: "Tenant" }));
      await user.click(await screen.findByRole("option", { name: /Acme/ }));
      await user.type(screen.getByLabelText("Site"), "docs");
      await user.click(screen.getByRole("button", { name: "Bind hostname" }));

      await waitFor(() => expect(success).toHaveBeenCalled());
      const message = success.mock.calls[0][0] as string;
      expect(message).toContain("Not enrolled for ACME");
      expect(message).not.toContain("ACME reload triggered");
      expect(message).not.toContain("ACME enabled");
    } finally {
      success.mockRestore();
    }
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
      await screen.findByText("Wildcard hostnames cannot be bound to a site"),
    ).toBeInTheDocument();

    // Bind button is disabled while the hostname is invalid.
    expect(screen.getByRole("button", { name: "Bind hostname" })).toBeDisabled();
    expect(posted).toBe(false);
  });

  // #348: the rejection reason is `lib/`-owned (src/lib/hostname.ts) and renders
  // in a live role="alert" between a localized label and a localized hint. It
  // returns a TranslationKey, so it must localize with the rest of the form —
  // an English sentence here is a mixed-language field, and the
  // `no-untranslated-literal` lint rule cannot see it (not JSX text, not a
  // toast argument).
  it("localizes the lib-owned hostname validation error in zh-CN", async () => {
    mockList([]);
    const user = userEvent.setup();
    renderPage("zh-CN");
    await screen.findByText("暂无已绑定的主机名。");

    await user.type(screen.getByLabelText("主机名（FQDN）"), "*.example.com");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("通配符主机名无法绑定到站点");
    // No English leaks into the Chinese form.
    expect(
      screen.queryByText("Wildcard hostnames cannot be bound to a site"),
    ).not.toBeInTheDocument();
  });

  // The interpolated variant: the operator's own hostname is echoed back
  // verbatim (an identifier) inside the localized sentence.
  it("interpolates the hostname into the localized non-FQDN error", async () => {
    mockList([]);
    const user = userEvent.setup();
    renderPage("zh-CN");
    await screen.findByText("暂无已绑定的主机名。");

    await user.type(screen.getByLabelText("主机名（FQDN）"), "localhost");
    expect(
      await screen.findByText("主机名 localhost 必须是完全限定域名"),
    ).toBeInTheDocument();
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

  // #348: a failing mutation used to call `toast.error(err.message)`, putting
  // the gateway's English sentence on a Chinese page with no localized headline
  // at all. The page now routes it through `useOperatorError`, so the headline
  // is catalog copy and the server's own words survive as marked technical
  // detail. Proves the adoption at a real call site, not only in the hook.
  it("localizes a failed unbind and keeps the gateway verdict verbatim", async () => {
    mockList([domain()]);
    server.use(
      http.delete(gatewayUrl("/admin/v1/site-domains/app.example.com"), () =>
        HttpResponse.json(
          { error: { code: "unknown_error", message: "certificate store is locked" } },
          { status: 500 },
        ),
      ),
    );
    const errorToast = vi.spyOn(toast, "error");
    const user = userEvent.setup();
    renderPage("zh-CN");

    await screen.findByTestId("site-domain-app.example.com");
    await user.click(screen.getByRole("button", { name: "解绑" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "解绑" }));

    await waitFor(() => expect(errorToast).toHaveBeenCalled());
    expect(errorToast.mock.calls[0][0]).toBe("服务器遇到错误。请稍后重试。");
    expect(errorToast.mock.calls[0][0]).not.toBe("certificate store is locked");
    // The gateway's own wording is retained as the technical detail.
    const options = errorToast.mock.calls[0][1] as { description?: ReactNode };
    const { container } = render(<>{options.description}</>);
    expect(container.textContent).toBe("certificate store is locked");
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
