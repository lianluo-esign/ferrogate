import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { HttpResponse, http } from "msw";
import { MemoryRouter, useLocation } from "react-router-dom";
import { toast } from "sonner";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, type Locale } from "@/i18n";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import type { AdminSchema } from "@/lib/gateway-client";
import StaticSitesPage from "@/pages/static-sites";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, renderWithProviders, seedSession } from "@/test/test-utils";

// Surfaces the live location so URL-state assertions can read the query the
// page writes as the operator picks a tenant/site/version or opens a site.
let currentSearch = "";
function LocationProbe() {
  currentSearch = useLocation().search;
  return null;
}

/** Renders the page at `initialEntry` with a LocationProbe so a test can assert
 * both directions of the URL mirror (deep-link seed + write-through). Mirrors
 * the assets-page URL-state harness. */
function renderAtUrl(initialEntry: string, locale: Locale = "en") {
  currentSearch = "";
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <StaticSitesPage />
            <LocationProbe />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

type AssetSummary = AdminSchema<"AssetSummary">;
type SiteDomain = AdminSchema<"AdminSiteDomain">;

function siteAsset(name: string, version: string): AssetSummary {
  return {
    id: `tenant-1:static_site:${name}:${version}`,
    asset_type: "static_site",
    name,
    version,
    content_type: "text/html",
    content_hash: "a".repeat(64),
    size_bytes: 100,
    storage_backed: false,
    created_at_unix: 1000,
    updated_at_unix: 1000,
  };
}

interface SiteManifestBody {
  site: string;
  bundle_version: string;
  public: boolean;
  spa_fallback: boolean;
  cache_control: string | null;
  files: { path: string; content_type: string; content_hash: string; size_bytes: number }[];
  created_at_unix: number;
  updated_at_unix: number;
}

function manifest(overrides: Partial<SiteManifestBody> = {}): SiteManifestBody {
  return {
    site: "marketing",
    bundle_version: "2.1.0",
    public: true,
    spa_fallback: true,
    cache_control: "public, max-age=600",
    files: [
      { path: "index.html", content_type: "text/html", content_hash: "b".repeat(64), size_bytes: 2048 },
      { path: "app.js", content_type: "text/javascript", content_hash: "c".repeat(64), size_bytes: 4096 },
    ],
    created_at_unix: 1000,
    updated_at_unix: 1_700_000_000,
    ...overrides,
  };
}

function domain(overrides: Partial<SiteDomain> = {}): SiteDomain {
  return {
    object: "site_domain",
    hostname: "app.example.com",
    tenant_id: "tenant-1",
    site: "marketing",
    serve_path: "/sites/tenant-1/marketing/",
    created_at_unix: 1000,
    updated_at_unix: 1000,
    ...overrides,
  };
}

/** Uploads `file` to a file input directly, bypassing the browser-level
 * `accept` filter so the component's own client-side archive validation (the
 * belt-and-suspenders JS check) is exercised. */
function uploadFile(input: HTMLElement, file: File) {
  fireEvent.change(input, { target: { files: [file] } });
}

/** Base handlers: the tenant picker hydrates the seeded tenant, and the two
 * list reads back the page. Individual tests layer manifests / publish. */
function mockBase(options: {
  assets?: AssetSummary[];
  domains?: SiteDomain[];
} = {}) {
  server.use(
    http.get(gatewayUrl("/v1/assets"), () =>
      HttpResponse.json({ object: "list", data: options.assets ?? [] }),
    ),
    http.get(gatewayUrl("/admin/v1/site-domains"), () =>
      HttpResponse.json({ object: "list", data: options.domains ?? [] }),
    ),
    http.get(gatewayUrl("/admin/v1/tenant-accounts/tenant-1"), () =>
      HttpResponse.json({ object: "tenant", tenant: { id: "tenant-1", name: "Acme", slug: "acme" } }),
    ),
    // Default asset registry manifest read (the drawer's version history reads
    // it on open); version-history tests override with a populated manifest.
    http.get(gatewayUrl("/v1/assets/static_site/:site/manifest"), ({ params }) =>
      HttpResponse.json({
        object: "asset_manifest",
        asset_type: "static_site",
        name: params.site as string,
        channels: [],
        versions: [],
      }),
    ),
  );
}

function mockManifest(site: string, body: SiteManifestBody) {
  server.use(
    http.get(gatewayUrl(`/v1/assets/static_site/${site}/__site_manifest__`), () =>
      HttpResponse.json(body),
    ),
  );
}

interface RegistryChannel {
  channel: string;
  version: string;
  updated_at_unix: number;
}
interface RegistryVersion {
  version: string;
  yanked: boolean;
  variants: never[];
}

/** Mocks the asset registry manifest (channels + versions) the drawer reads for
 * version history. `channels`/`versions` mirror gateway #397's keying. */
function mockRegistry(
  site: string,
  channels: RegistryChannel[],
  versions: RegistryVersion[],
) {
  server.use(
    http.get(gatewayUrl(`/v1/assets/static_site/${site}/manifest`), () =>
      HttpResponse.json({
        object: "asset_manifest",
        asset_type: "static_site",
        name: site,
        channels,
        versions,
      }),
    ),
  );
}

/** A retained #397 bundle version: the bare `{version}` manifest row plus a
 * companion `__site_file__:{version}:index.html` file row (the structural mark
 * that distinguishes a real bundle version from a legacy path-keyed file row). */
function bundleVersions(...versions: { version: string; yanked?: boolean }[]): RegistryVersion[] {
  return versions.flatMap(({ version, yanked = false }) => [
    { version, yanked, variants: [] },
    { version: `__site_file__:${version}:index.html`, yanked: false, variants: [] },
  ]);
}

beforeEach(() => {
  seedSession();
});

describe("StaticSitesPage", () => {
  it("lists published sites with policy, serve URL, and bound domains", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [domain()] });
    mockManifest("marketing", manifest());
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    // Bundle version resolves once the manifest read lands.
    expect(await within(row).findByText("2.1.0")).toBeInTheDocument();
    // Public + SPA policy badges from the manifest.
    expect(within(row).getByText("Public")).toBeInTheDocument();
    expect(within(row).getByText("SPA")).toBeInTheDocument();
    // Cache policy + file count + serve URL + bound domain.
    expect(within(row).getByText("public, max-age=600")).toBeInTheDocument();
    expect(within(row).getByText("2")).toBeInTheDocument();
    expect(within(row).getByText("/sites/tenant-1/marketing/")).toBeInTheDocument();
    expect(within(row).getByText("app.example.com")).toBeInTheDocument();
  });

  it("renders the list in Simplified Chinese", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest({ public: false, spa_fallback: false }));
    renderWithProviders(<StaticSitesPage />, { locale: "zh-CN" });

    expect(await screen.findByRole("heading", { name: "静态站点" })).toBeInTheDocument();
    const row = await screen.findByTestId("static-site-marketing");
    // Private site shows the localized access badge once the manifest lands.
    expect(await within(row).findByText("私有")).toBeInTheDocument();
  });

  it("blocks a non-zip archive client-side without publishing", async () => {
    mockBase();
    let putCalled = false;
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/:site/:version"), () => {
        putCalled = true;
        return HttpResponse.json({}, { status: 200 });
      }),
    );
    renderWithProviders(<StaticSitesPage />);
    await screen.findByText("No published static sites.");

    const notZip = new File(["hello"], "notes.txt", { type: "text/plain" });
    uploadFile(screen.getByLabelText("Bundle (ZIP)"), notZip);

    expect(await screen.findByText("The bundle must be a .zip archive.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Publish" })).toBeDisabled();
    expect(putCalled).toBe(false);
  });

  it("publishes a zip bundle with the site policy headers", async () => {
    mockBase();
    let captured: {
      path: string;
      public: string | null;
      spa: string | null;
      cache: string | null;
      visibility: string | null;
    } | null = null;
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/blog/1.4.0"), ({ request }) => {
        const url = new URL(request.url);
        captured = {
          path: url.pathname,
          public: request.headers.get("x-site-public"),
          spa: request.headers.get("x-site-spa-fallback"),
          cache: request.headers.get("x-site-cache-control"),
          visibility: request.headers.get("x-asset-visibility"),
        };
        return HttpResponse.json({
          object: "static_site",
          tenant: "tenant-1",
          site: "blog",
          bundle_version: "1.4.0",
          public: true,
          spa_fallback: true,
          file_count: 3,
          size_bytes: 6144,
          files: ["index.html", "app.js", "style.css"],
        });
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    await screen.findByText("No published static sites.");

    await user.type(screen.getByLabelText("Site"), "blog");
    await user.type(screen.getByLabelText("Version"), "1.4.0");
    await user.type(screen.getByLabelText("Cache-Control"), "public, max-age=60");
    await user.click(screen.getByRole("switch", { name: "Public access" }));
    await user.click(screen.getByRole("switch", { name: "SPA fallback" }));
    const zip = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], "blog.zip", {
      type: "application/zip",
    });
    uploadFile(screen.getByLabelText("Bundle (ZIP)"), zip);

    await user.click(screen.getByRole("button", { name: "Publish" }));

    await waitFor(() => expect(captured).not.toBeNull());
    expect(captured).toEqual({
      path: "/v1/assets/static_site/blog/1.4.0",
      public: "true",
      spa: "true",
      cache: "public, max-age=60",
      visibility: "public",
    });
    // Form resets after a successful publish.
    await waitFor(() => expect(screen.getByLabelText("Site")).toHaveValue(""));
  });

  it("surfaces a gateway rejection verbatim", async () => {
    mockBase();
    const gatewayMessage =
      "index.html: rejected by scan (EICAR test signature detected)";
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/tainted/1.0.0"), () =>
        HttpResponse.json(
          {
            error: {
              type: "ferrogate_error",
              code: "asset_scan_rejected",
              message: gatewayMessage,
              request_id: "req-1",
            },
          },
          { status: 422 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    await screen.findByText("No published static sites.");

    await user.type(screen.getByLabelText("Site"), "tainted");
    await user.type(screen.getByLabelText("Version"), "1.0.0");
    const zip = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], "tainted.zip", {
      type: "application/zip",
    });
    uploadFile(screen.getByLabelText("Bundle (ZIP)"), zip);
    await user.click(screen.getByRole("button", { name: "Publish" }));

    // The exact gateway verdict is shown verbatim in an accessible alert.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(gatewayMessage);
  });
});

describe("StaticSitesPage detail drawer", () => {
  async function openDrawer(user: ReturnType<typeof userEvent.setup>, moreDetails: string) {
    const row = await screen.findByTestId("static-site-marketing");
    // The action arms only once the manifest read lands.
    await within(row).findByText("2.1.0");
    await user.click(within(row).getByRole("button", { name: moreDetails }));
    return screen.findByRole("dialog");
  }

  it("renders the bundle file tree from the manifest", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);

    const drawer = await openDrawer(user, en["resource.table.moreDetails"]);

    // Section heading + bundle summary (2 files, 6 KB) from the manifest.
    expect(within(drawer).getByText(en["page.staticSites.detail.files"])).toBeInTheDocument();
    expect(within(drawer).getByText(/2 files, 6 KB/)).toBeInTheDocument();
    // Every file path, its content type, short hash, and size render.
    expect(within(drawer).getByText("index.html")).toBeInTheDocument();
    expect(within(drawer).getByText("app.js")).toBeInTheDocument();
    expect(within(drawer).getByText("text/javascript")).toBeInTheDocument();
    expect(within(drawer).getByText(`${"b".repeat(12)}…`)).toBeInTheDocument();
    expect(within(drawer).getByText("2 KB")).toBeInTheDocument();
    expect(within(drawer).getByText("4 KB")).toBeInTheDocument();
  });

  it("renders the file tree in Simplified Chinese", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />, { locale: "zh-CN" });

    const drawer = await openDrawer(user, zhCN["resource.table.moreDetails"]);

    expect(within(drawer).getByText(zhCN["page.staticSites.detail.files"])).toBeInTheDocument();
    expect(within(drawer).getByText("index.html")).toBeInTheDocument();
    expect(within(drawer).getByText("app.js")).toBeInTheDocument();
  });
});

describe("StaticSitesPage serve-URL affordance", () => {
  it("links each site's serve URL out to a new tab with a safe rel", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");
    const link = within(row).getByRole("link", {
      name: /\/sites\/tenant-1\/marketing\//,
    });
    expect(link).toHaveAttribute("target", "_blank");
    // rel=noopener severs window.opener; noreferrer drops the Referer header.
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    // href is an absolute, openable URL that ends in the tenant/site serve path.
    expect(link.getAttribute("href")).toMatch(/\/sites\/tenant-1\/marketing\/$/);
  });

  it("offers the same open-serve-URL affordance inside the detail drawer", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");
    await user.click(
      within(row).getByRole("button", { name: en["resource.table.moreDetails"] }),
    );
    const drawer = await screen.findByRole("dialog");
    const openLink = within(drawer).getByRole("link", {
      name: new RegExp(en["page.staticSites.serveUrl.open"]),
    });
    expect(openLink).toHaveAttribute("target", "_blank");
    expect(openLink).toHaveAttribute("rel", "noopener noreferrer");
    expect(openLink.getAttribute("href")).toMatch(/\/sites\/tenant-1\/marketing\/$/);
  });
});

/** Installs jsdom-safe object-URL + anchor-click doubles for the duration of a
 * download test (jsdom implements neither), returning the spies + a restore. */
function stubDownloadPlumbing() {
  const createObjectURL = vi.fn(() => "blob:mock-url");
  const revokeObjectURL = vi.fn();
  const urlWithBlob = URL as unknown as {
    createObjectURL?: (obj: Blob) => string;
    revokeObjectURL?: (url: string) => void;
  };
  const originalCreate = urlWithBlob.createObjectURL;
  const originalRevoke = urlWithBlob.revokeObjectURL;
  urlWithBlob.createObjectURL = createObjectURL;
  urlWithBlob.revokeObjectURL = revokeObjectURL;
  const clickSpy = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  return {
    createObjectURL,
    clickSpy,
    restore() {
      clickSpy.mockRestore();
      urlWithBlob.createObjectURL = originalCreate;
      urlWithBlob.revokeObjectURL = originalRevoke;
    },
  };
}

async function openMarketingDrawer(user: ReturnType<typeof userEvent.setup>) {
  const row = await screen.findByTestId("static-site-marketing");
  await within(row).findByText("2.1.0");
  await user.click(
    within(row).getByRole("button", { name: en["resource.table.moreDetails"] }),
  );
  return screen.findByRole("dialog");
}

describe("StaticSitesPage per-file download", () => {
  it("downloads an individual bundle file via that file's asset-object path", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    let requestedPath: string | null = null;
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/app.js"), ({ request }) => {
        requestedPath = new URL(request.url).pathname;
        return new HttpResponse("console.log(1)", {
          headers: { "Content-Type": "text/javascript" },
        });
      }),
    );
    const plumbing = stubDownloadPlumbing();
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const drawer = await openMarketingDrawer(user);

      // Download the app.js row specifically (index.html is a separate row).
      const appRow = within(drawer).getByText("app.js").closest("tr") as HTMLElement;
      await user.click(
        within(appRow).getByRole("button", {
          name: en["page.staticSites.detail.download"],
        }),
      );

      await waitFor(() =>
        expect(requestedPath).toBe("/v1/assets/static_site/marketing/app.js"),
      );
      // A blob URL was minted and a synthetic anchor click fired the save.
      expect(plumbing.createObjectURL).toHaveBeenCalledTimes(1);
      expect(plumbing.clickSpy).toHaveBeenCalledTimes(1);
    } finally {
      plumbing.restore();
    }
  });

  it("surfaces a download failure verbatim, keyed to the exact file", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/app.js"), () =>
        HttpResponse.json(
          { error: { code: "asset_not_found", message: "no asset resolves" } },
          { status: 404 },
        ),
      ),
    );
    // No Toaster is mounted in the test provider stack, so assert on the sonner
    // call itself: the message must name the file AND carry the gateway verdict.
    const errorToast = vi.spyOn(toast, "error");
    const plumbing = stubDownloadPlumbing();
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const drawer = await openMarketingDrawer(user);
      const appRow = within(drawer).getByText("app.js").closest("tr") as HTMLElement;
      await user.click(
        within(appRow).getByRole("button", {
          name: en["page.staticSites.detail.download"],
        }),
      );

      await waitFor(() => expect(errorToast).toHaveBeenCalled());
      const message = errorToast.mock.calls[0][0] as string;
      expect(message).toContain("app.js");
      expect(message).toContain("no asset resolves");
    } finally {
      errorToast.mockRestore();
      plumbing.restore();
    }
  });

  it("labels the download + serve-URL affordances in Simplified Chinese", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />, { locale: "zh-CN" });

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");
    await user.click(
      within(row).getByRole("button", { name: zhCN["resource.table.moreDetails"] }),
    );
    const drawer = await screen.findByRole("dialog");
    expect(
      within(drawer).getByRole("link", {
        name: new RegExp(zhCN["page.staticSites.serveUrl.open"]),
      }),
    ).toBeInTheDocument();
    expect(
      within(drawer).getAllByRole("button", {
        name: zhCN["page.staticSites.detail.download"],
      }).length,
    ).toBeGreaterThan(0);
  });
});

describe("StaticSitesPage unpublish flow", () => {
  it("requires the exact typed site name before enabling, then deletes files + manifest", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    const deleted = new Set<string>();
    server.use(
      http.delete(
        gatewayUrl("/v1/assets/static_site/marketing/:version"),
        ({ params }) => {
          deleted.add(params.version as string);
          return HttpResponse.json({ object: "asset", deleted: true });
        },
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");
    await user.click(within(row).getByRole("button", { name: en["resource.table.moreDetails"] }));
    const drawer = await screen.findByRole("dialog");
    await user.click(within(drawer).getByRole("button", { name: en["page.staticSites.unpublish.action"] }));

    // The confirm dialog names the site and stays disarmed until it is retyped.
    const confirmDialog = (
      await screen.findByText(
        en["page.staticSites.unpublish.title"].replace("{site}", "marketing"),
      )
    ).closest("[role='dialog']") as HTMLElement;
    const confirmButton = within(confirmDialog).getByRole("button", {
      name: en["page.staticSites.unpublish.action"],
    });
    expect(confirmButton).toBeDisabled();

    const input = within(confirmDialog).getByLabelText(
      en["page.staticSites.unpublish.confirmLabel"].replace("{site}", "marketing"),
    );
    await user.type(input, "blog");
    expect(confirmButton).toBeDisabled();

    await user.clear(input);
    await user.type(input, "marketing");
    expect(confirmButton).toBeEnabled();

    await user.click(confirmButton);

    // Every file version PLUS the reserved manifest row is deleted.
    await waitFor(() =>
      expect(deleted).toEqual(
        new Set(["index.html", "app.js", "__site_manifest__"]),
      ),
    );
  });
});

/**
 * Minimal controllable XHR double: drives `upload.onprogress` with real byte
 * counts and completes on demand so the test can observe an intermediate
 * `role="progressbar"` value before the publish resolves.
 */
class FakeXHR {
  static instances: FakeXHR[] = [];
  upload: { onprogress: ((event: ProgressEvent) => void) | null } = {
    onprogress: null,
  };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  status = 0;
  statusText = "OK";
  responseText = "";
  responseType = "";
  open() {}
  setRequestHeader() {}
  send() {
    FakeXHR.instances.push(this);
  }
  emitProgress(loaded: number, total: number) {
    this.upload.onprogress?.({
      lengthComputable: true,
      loaded,
      total,
    } as ProgressEvent);
  }
  complete(status: number, body: unknown) {
    this.status = status;
    this.responseText = JSON.stringify(body);
    this.onload?.();
  }
}

describe("StaticSitesPage upload progress", () => {
  it("surfaces real byte-level progress from the XHR upload", async () => {
    mockBase();
    FakeXHR.instances = [];
    const original = globalThis.XMLHttpRequest;
    vi.stubGlobal("XMLHttpRequest", FakeXHR as unknown as typeof XMLHttpRequest);
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      await screen.findByText("No published static sites.");

      await user.type(screen.getByLabelText("Site"), "blog");
      await user.type(screen.getByLabelText("Version"), "1.0.0");
      const zip = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], "blog.zip", {
        type: "application/zip",
      });
      uploadFile(screen.getByLabelText("Bundle (ZIP)"), zip);
      await user.click(screen.getByRole("button", { name: "Publish" }));

      await waitFor(() => expect(FakeXHR.instances).toHaveLength(1));
      const xhr = FakeXHR.instances[0];

      // Half the bytes uploaded → a determinate progressbar reads 50.
      act(() => xhr.emitProgress(512, 1024));
      const bar = await screen.findByRole("progressbar");
      expect(bar).toHaveAttribute("aria-valuenow", "50");
      expect(bar).toHaveAttribute("aria-valuetext", "50%");

      // Full upload + gateway ack completes the publish and resets the form.
      act(() => {
        xhr.emitProgress(1024, 1024);
        xhr.complete(200, {
          object: "static_site",
          tenant: "tenant-1",
          site: "blog",
          bundle_version: "1.0.0",
          public: false,
          spa_fallback: false,
          file_count: 1,
          size_bytes: 1024,
          files: ["index.html"],
        });
      });

      await waitFor(() => expect(screen.getByLabelText("Site")).toHaveValue(""));
    } finally {
      vi.stubGlobal("XMLHttpRequest", original);
    }
  });
});

/** Two retained bundle version rows for `marketing`, dated so the newest (the
 * served one) sorts first, plus the reserved manifest marker row the listing
 * also carries. */
function marketingAssets(): AssetSummary[] {
  return [
    { ...siteAsset("marketing", "2.1.0"), created_at_unix: 1_700_000_200 },
    { ...siteAsset("marketing", "2.0.0"), created_at_unix: 1_700_000_100 },
    { ...siteAsset("marketing", "__site_manifest__"), created_at_unix: 1_700_000_200 },
  ];
}

async function openHistoryDrawer(
  user: ReturnType<typeof userEvent.setup>,
  moreDetails: string,
) {
  const row = await screen.findByTestId("static-site-marketing");
  await within(row).findByText("2.1.0");
  await user.click(within(row).getByRole("button", { name: moreDetails }));
  return screen.findByRole("dialog");
}

describe("StaticSitesPage version history", () => {
  it("lists retained bundle versions, marking the served (active) one + publish times", async () => {
    mockBase({ assets: marketingAssets(), domains: [] });
    mockManifest("marketing", manifest());
    // The `serving` channel points at 2.1.0; 2.0.0 is a retained prior bundle.
    mockRegistry(
      "marketing",
      [{ channel: "serving", version: "2.1.0", updated_at_unix: 1_700_000_200 }],
      bundleVersions({ version: "2.1.0" }, { version: "2.0.0" }),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openHistoryDrawer(user, en["resource.table.moreDetails"]);

    expect(
      within(drawer).getByText(en["page.staticSites.history.title"]),
    ).toBeInTheDocument();

    // Both retained bundle versions render as history rows.
    const activeRow = within(drawer).getByTestId("static-site-version-2.1.0");
    const priorRow = within(drawer).getByTestId("static-site-version-2.0.0");
    // The served version carries the Active badge; the prior version does not.
    expect(
      within(activeRow).getByText(en["page.staticSites.history.active"]),
    ).toBeInTheDocument();
    expect(
      within(priorRow).queryByText(en["page.staticSites.history.active"]),
    ).toBeNull();
    // Only the non-active version offers a rollback button.
    expect(
      within(priorRow).getByRole("button", {
        name: en["page.staticSites.rollback.action"],
      }),
    ).toBeInTheDocument();
    expect(
      within(activeRow).queryByRole("button", {
        name: en["page.staticSites.rollback.action"],
      }),
    ).toBeNull();
  });

  it("excludes reserved + legacy-only versions from the bundle history", async () => {
    mockBase({ assets: marketingAssets(), domains: [] });
    mockManifest("marketing", manifest());
    // Registry with: one real #397 bundle (2.1.0, has __site_file__ companion),
    // the reserved manifest marker, and a LEGACY bare file row `index.html`
    // (no companion) — only 2.1.0 is a real rollback target.
    mockRegistry(
      "marketing",
      [{ channel: "serving", version: "2.1.0", updated_at_unix: 1_700_000_200 }],
      [
        ...bundleVersions({ version: "2.1.0" }),
        { version: "__site_manifest__", yanked: false, variants: [] },
        { version: "index.html", yanked: false, variants: [] },
      ],
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openHistoryDrawer(user, en["resource.table.moreDetails"]);

    expect(
      within(drawer).getByTestId("static-site-version-2.1.0"),
    ).toBeInTheDocument();
    // Neither the reserved marker nor the legacy bare file path is a bundle row.
    expect(
      within(drawer).queryByTestId("static-site-version-__site_manifest__"),
    ).toBeNull();
    expect(
      within(drawer).queryByTestId("static-site-version-index.html"),
    ).toBeNull();
  });

  it("renders version history in Simplified Chinese", async () => {
    mockBase({ assets: marketingAssets(), domains: [] });
    mockManifest("marketing", manifest());
    mockRegistry(
      "marketing",
      [{ channel: "serving", version: "2.1.0", updated_at_unix: 1_700_000_200 }],
      bundleVersions({ version: "2.1.0" }, { version: "2.0.0" }),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />, { locale: "zh-CN" });
    const drawer = await openHistoryDrawer(user, zhCN["resource.table.moreDetails"]);

    expect(
      within(drawer).getByText(zhCN["page.staticSites.history.title"]),
    ).toBeInTheDocument();
    const activeRow = within(drawer).getByTestId("static-site-version-2.1.0");
    expect(
      within(activeRow).getByText(zhCN["page.staticSites.history.active"]),
    ).toBeInTheDocument();
  });
});

describe("StaticSitesPage rollback", () => {
  it("moves the serving channel to the selected version behind a confirm, then refreshes", async () => {
    mockBase({ assets: marketingAssets(), domains: [] });
    mockManifest("marketing", manifest());
    let registryReads = 0;
    let channelUrl: string | null = null;
    let channelMethod: string | null = null;
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/manifest"), () => {
        registryReads += 1;
        return HttpResponse.json({
          object: "asset_manifest",
          asset_type: "static_site",
          name: "marketing",
          channels: [
            { channel: "serving", version: "2.1.0", updated_at_unix: 1_700_000_200 },
          ],
          versions: bundleVersions({ version: "2.1.0" }, { version: "2.0.0" }),
        });
      }),
      http.put(
        gatewayUrl("/v1/assets/static_site/marketing/channels/serving"),
        ({ request }) => {
          channelUrl = request.url;
          channelMethod = request.method;
          return HttpResponse.json({
            object: "asset_channel",
            asset_type: "static_site",
            name: "marketing",
            channel: { channel: "serving", version: "2.0.0", updated_at_unix: 3000 },
          });
        },
      ),
    );
    const successToast = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const drawer = await openHistoryDrawer(user, en["resource.table.moreDetails"]);

      await waitFor(() => expect(registryReads).toBeGreaterThanOrEqual(1));
      const readsBefore = registryReads;

      // Arm rollback on the prior version.
      const priorRow = within(drawer).getByTestId("static-site-version-2.0.0");
      await user.click(
        within(priorRow).getByRole("button", {
          name: en["page.staticSites.rollback.action"],
        }),
      );

      // The confirm dialog names the exact target version + consequence.
      const confirmDialog = (
        await screen.findByText(
          en["page.staticSites.rollback.title"].replace("{version}", "2.0.0"),
        )
      ).closest("[role='dialog']") as HTMLElement;
      await user.click(
        within(confirmDialog).getByRole("button", {
          name: en["page.staticSites.rollback.confirm"],
        }),
      );

      // A PUT moved the `serving` channel to 2.0.0 via the version= query.
      await waitFor(() => expect(channelUrl).not.toBeNull());
      expect(channelMethod).toBe("PUT");
      const url = new URL(channelUrl!);
      expect(url.pathname).toBe("/v1/assets/static_site/marketing/channels/serving");
      expect(url.searchParams.get("version")).toBe("2.0.0");
      // Success toast + a re-read of the registry (the served version changed).
      await waitFor(() => expect(successToast).toHaveBeenCalled());
      await waitFor(() => expect(registryReads).toBeGreaterThan(readsBefore));
    } finally {
      successToast.mockRestore();
    }
  });

  it("maps a 409 unresolvable target to a localized message, leaving serving unchanged", async () => {
    mockBase({ assets: marketingAssets(), domains: [] });
    mockManifest("marketing", manifest());
    mockRegistry(
      "marketing",
      [{ channel: "serving", version: "2.1.0", updated_at_unix: 1_700_000_200 }],
      bundleVersions({ version: "2.1.0" }, { version: "2.0.0" }),
    );
    server.use(
      http.put(
        gatewayUrl("/v1/assets/static_site/marketing/channels/serving"),
        () =>
          HttpResponse.json(
            {
              error: {
                type: "ferrogate_error",
                code: "asset_channel_unresolvable",
                message: "target version could not be resolved",
                request_id: "req-9",
              },
            },
            { status: 409 },
          ),
      ),
    );
    const errorToast = vi.spyOn(toast, "error");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const drawer = await openHistoryDrawer(user, en["resource.table.moreDetails"]);

      const priorRow = within(drawer).getByTestId("static-site-version-2.0.0");
      await user.click(
        within(priorRow).getByRole("button", {
          name: en["page.staticSites.rollback.action"],
        }),
      );
      const confirmDialog = (
        await screen.findByText(
          en["page.staticSites.rollback.title"].replace("{version}", "2.0.0"),
        )
      ).closest("[role='dialog']") as HTMLElement;
      await user.click(
        within(confirmDialog).getByRole("button", {
          name: en["page.staticSites.rollback.confirm"],
        }),
      );

      // The 409 maps to the localized unresolvable message naming the version.
      await waitFor(() => expect(errorToast).toHaveBeenCalled());
      const message = errorToast.mock.calls[0][0] as string;
      expect(message).toBe(
        en["page.staticSites.rollback.unresolvable"].replace("{version}", "2.0.0"),
      );
    } finally {
      errorToast.mockRestore();
    }
  });
});

describe("StaticSitesPage URL state", () => {
  it("seeds the publish form's site + version from the query string (direct link)", async () => {
    mockBase();
    renderAtUrl("/?site=blog&version=2.0.0");
    await screen.findByText("No published static sites.");

    // A deep link pre-fills the selection, so a shared URL reopens it as-is.
    expect(screen.getByLabelText("Site")).toHaveValue("blog");
    expect(screen.getByLabelText("Version")).toHaveValue("2.0.0");
  });

  it("mirrors a site edit into the URL as a shareable direct link", async () => {
    mockBase();
    const user = userEvent.setup();
    renderAtUrl("/");
    await screen.findByText("No published static sites.");

    await user.type(screen.getByLabelText("Site"), "blog");

    // The selection is written through to the query string with `replace`.
    await waitFor(() => expect(currentSearch).toContain("site=blog"));
  });

  it("opens a site's detail drawer directly from the detail query param", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    renderAtUrl("/?detail=marketing");

    // The drawer opens on mount for the linked site (no click needed).
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText("marketing")).toBeInTheDocument();
  });
});

describe("StaticSitesPage publish error states", () => {
  async function fillAndPublish(
    user: ReturnType<typeof userEvent.setup>,
    site: string,
    version: string,
  ) {
    await user.type(screen.getByLabelText("Site"), site);
    await user.type(screen.getByLabelText("Version"), version);
    const zip = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], `${site}.zip`, {
      type: "application/zip",
    });
    uploadFile(screen.getByLabelText("Bundle (ZIP)"), zip);
    await user.click(screen.getByRole("button", { name: "Publish" }));
  }

  it("surfaces a quota rejection verbatim and accessibly", async () => {
    mockBase();
    const quotaMessage =
      "asset storage quota exceeded: bundle would use 42 MiB of a 32 MiB tenant quota";
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/1.0.0"), () =>
        HttpResponse.json(
          {
            error: {
              type: "ferrogate_error",
              code: "asset_quota_exceeded",
              message: quotaMessage,
              request_id: "req-q",
            },
          },
          { status: 413 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    await screen.findByText("No published static sites.");
    await fillAndPublish(user, "marketing", "1.0.0");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(quotaMessage);
  });

  it("surfaces a backend-unavailable failure verbatim", async () => {
    mockBase();
    const downMessage = "asset registry is temporarily unavailable";
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/1.0.0"), () =>
        HttpResponse.json(
          {
            error: {
              type: "ferrogate_error",
              code: "backend_unavailable",
              message: downMessage,
              request_id: "req-503",
            },
          },
          { status: 503 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    await screen.findByText("No published static sites.");
    await fillAndPublish(user, "marketing", "1.0.0");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(downMessage);
  });

  it("surfaces a mid-upload network failure (partial upload) verbatim", async () => {
    mockBase();
    FakeXHR.instances = [];
    const original = globalThis.XMLHttpRequest;
    vi.stubGlobal("XMLHttpRequest", FakeXHR as unknown as typeof XMLHttpRequest);
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      await screen.findByText("No published static sites.");
      await fillAndPublish(user, "marketing", "1.0.0");

      await waitFor(() => expect(FakeXHR.instances).toHaveLength(1));
      const xhr = FakeXHR.instances[0];
      // Some bytes went up, then the connection dropped mid-upload.
      act(() => xhr.emitProgress(256, 1024));
      act(() => xhr.onerror?.());

      // The publish reports the network failure verbatim; it never claims success.
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("network request failed");
    } finally {
      vi.stubGlobal("XMLHttpRequest", original);
    }
  });

  it("a failed republish leaves the prior site listed and claims no success", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        HttpResponse.json(
          {
            error: {
              type: "ferrogate_error",
              code: "asset_zip_bomb_rejected",
              message: "bundle expands past the 64 MiB unpacked ceiling",
              request_id: "req-bomb",
            },
          },
          { status: 422 },
        ),
      ),
    );
    const successToast = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      // The already-published site is present before the doomed republish.
      const row = await screen.findByTestId("static-site-marketing");
      await within(row).findByText("2.1.0");

      await fillAndPublish(user, "marketing", "2.2.0");

      // The gateway verdict is surfaced verbatim…
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("64 MiB unpacked ceiling");
      // …no success was ever claimed…
      expect(successToast).not.toHaveBeenCalled();
      // …and the prior bundle stays usable (still listed at its old version).
      const stillThere = screen.getByTestId("static-site-marketing");
      expect(within(stillThere).getByText("2.1.0")).toBeInTheDocument();
      expect(
        within(stillThere).getByRole("link", {
          name: /\/sites\/tenant-1\/marketing\//,
        }),
      ).toBeInTheDocument();
    } finally {
      successToast.mockRestore();
    }
  });
});

/** A POST /admin/v1/site-domains bind response with a chosen ACME posture. */
function bindResponse(
  hostname: string,
  acme: { enabled: boolean; reload_triggered: boolean },
) {
  return {
    object: "site_domain",
    site_domain: domain({ hostname }),
    acme,
  };
}

describe("StaticSitesPage domain binding (site context)", () => {
  it("binds a hostname using the session tenant + site slug, then shows ACME posture", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    let body: { hostname?: string; tenant_id?: string; site?: string } | null = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/site-domains"), async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json(
          bindResponse("app.example.com", { enabled: true, reload_triggered: true }),
        );
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    await user.type(
      within(drawer).getByLabelText("Hostname (FQDN)"),
      "app.example.com",
    );
    await user.click(
      within(drawer).getByRole("button", { name: "Bind hostname" }),
    );

    // The bind is scoped to the site context: tenant_id + site come from the
    // drawer's row, never free input, so it can't cross tenants or target an
    // unpublished site.
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      hostname: "app.example.com",
      tenant_id: "tenant-1",
      site: "marketing",
    });
    // The ACME + reload posture stays visible in the drawer after binding.
    const status = await within(drawer).findByRole("status");
    expect(status).toHaveTextContent(/ACME reload triggered/);
  });

  it("validates the hostname client-side without issuing a bind", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [] });
    mockManifest("marketing", manifest());
    let posted = false;
    server.use(
      http.post(gatewayUrl("/admin/v1/site-domains"), () => {
        posted = true;
        return HttpResponse.json(
          bindResponse("bad", { enabled: false, reload_triggered: false }),
        );
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    // A single-label hostname is rejected by the client mirror of the gateway
    // rule; the Bind button stays disarmed and no POST is issued.
    await user.type(within(drawer).getByLabelText("Hostname (FQDN)"), "localhost");
    expect(
      within(drawer).getByRole("button", { name: "Bind hostname" }),
    ).toBeDisabled();
    expect(
      within(drawer).getByText(/fully qualified domain name/),
    ).toBeInTheDocument();
    expect(posted).toBe(false);
  });

  it("unbinds a domain bound to the site behind a confirm", async () => {
    mockBase({ assets: [siteAsset("marketing", "index.html")], domains: [domain()] });
    mockManifest("marketing", manifest());
    let unbound: string | null = null;
    server.use(
      http.delete(
        gatewayUrl("/admin/v1/site-domains/:hostname"),
        ({ params }) => {
          unbound = params.hostname as string;
          return HttpResponse.json({ object: "site_domain", deleted: true });
        },
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    // The bound hostname is listed in the site context with an Unbind action.
    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    await user.click(within(domainRow).getByRole("button", { name: "Unbind" }));

    // Unbind is confirmed before it fires (an alertdialog).
    const confirm = await screen.findByRole("alertdialog");
    await user.click(within(confirm).getByRole("button", { name: "Unbind" }));

    await waitFor(() => expect(unbound).toBe("app.example.com"));
  });
});
