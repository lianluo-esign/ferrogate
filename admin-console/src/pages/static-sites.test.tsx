import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import type { AdminSchema } from "@/lib/gateway-client";
import StaticSitesPage from "@/pages/static-sites";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

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
  );
}

function mockManifest(site: string, body: SiteManifestBody) {
  server.use(
    http.get(gatewayUrl(`/v1/assets/static_site/${site}/__site_manifest__`), () =>
      HttpResponse.json(body),
    ),
  );
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
