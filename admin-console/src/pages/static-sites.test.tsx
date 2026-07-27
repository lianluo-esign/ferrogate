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

// Reserved `version` keys the gateway writes for a static site (mirrors the
// constants in static-sites.tsx and the gateway's sites.rs).
const SITE_MANIFEST_VERSION = "__site_manifest__";
const SITE_FILE_VERSION_PREFIX = "__site_file__";

function siteFileVersion(bundleVersion: string, path: string): string {
  return `${SITE_FILE_VERSION_PREFIX}:${bundleVersion}:${path}`;
}

function siteAsset(
  name: string,
  version: string,
  createdAtUnix = 1000,
): AssetSummary {
  return {
    id: `tenant-1:static_site:${name}:${version}`,
    asset_type: "static_site",
    name,
    version,
    content_type: "text/html",
    content_hash: "a".repeat(64),
    size_bytes: 100,
    storage_backed: false,
    // #528: a row the consumer listing returns is always `visible`; the
    // withheld ones are on the operator-only listing (#379).
    visibility: "visible",
    created_at_unix: createdAtUnix,
    updated_at_unix: createdAtUnix,
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

/** One RETAINED bundle exactly as gateway #397 stores it: a bare
 * `{version}` bundle-manifest row plus one `__site_file__:{version}:{path}` row
 * per file. */
interface BundleFixture {
  version: string;
  files: string[];
  createdAtUnix: number;
  /** Body served at `/v1/assets/static_site/{site}/{version}` — this bundle's
   * own immutable manifest, which is what the console must display when the
   * `serving` channel points here. */
  manifest: SiteManifestBody;
}

/**
 * A published site's COMPLETE server-side shape, modelled on what
 * `Gateway::commit_site_bundle` (sites.rs) actually writes:
 *   - one bare `{bundle_version}` manifest row per retained bundle,
 *   - one `__site_file__:{bundle_version}:{path}` object row per file of EVERY
 *     retained bundle (prior bundles are retained, not overwritten),
 *   - the single MUTABLE `__site_manifest__` marker, refreshed only on publish,
 *   - a `serving` channel pointing at the active bundle.
 *
 * The previous fixture modelled a single legacy pre-#397 path-keyed asset row,
 * which hid two real behaviours: that a rollback (a channel move) leaves the
 * marker describing a DIFFERENT bundle than the one served, and that retained
 * rows — and the bytes they charge to the tenant asset-storage quota — survive
 * an unpublish that only walks the served bundle's file list.
 */
interface SiteFixture {
  site: string;
  /** Newest first. */
  bundles: BundleFixture[];
  /** Version the `serving` channel points at; `null` models a LEGACY pre-#397
   * site with no channel, which the gateway serves from the marker instead. */
  serving: string | null;
  /** The mutable `__site_manifest__` body. Defaults to the newest bundle's
   * manifest (what a publish writes); a rollback test sets it apart on purpose,
   * because a rollback never rewrites the marker. */
  marker?: SiteManifestBody;
}

/** Every `/v1/assets` summary row the fixture's site owns. */
function assetRowsFor(fixture: SiteFixture): AssetSummary[] {
  const rows = fixture.bundles.flatMap((bundle) => [
    siteAsset(fixture.site, bundle.version, bundle.createdAtUnix),
    ...bundle.files.map((path) =>
      siteAsset(fixture.site, siteFileVersion(bundle.version, path), bundle.createdAtUnix),
    ),
  ]);
  rows.push(
    siteAsset(
      fixture.site,
      SITE_MANIFEST_VERSION,
      fixture.bundles[0]?.createdAtUnix ?? 1000,
    ),
  );
  return rows;
}

/** The asset REGISTRY manifest (channels + version rows) for the fixture. */
function registryFor(fixture: SiteFixture) {
  return {
    object: "asset_manifest",
    asset_type: "static_site",
    name: fixture.site,
    channels:
      fixture.serving === null
        ? []
        : [
            {
              channel: "serving",
              version: fixture.serving,
              updated_at_unix: 1_700_000_200,
            },
          ],
    versions: [
      ...fixture.bundles.flatMap((bundle) => [
        { version: bundle.version, yanked: false, variants: [] },
        ...bundle.files.map((path) => ({
          version: siteFileVersion(bundle.version, path),
          yanked: false,
          variants: [],
        })),
      ]),
      { version: SITE_MANIFEST_VERSION, yanked: false, variants: [] },
    ],
  };
}

/** The default two-bundle `marketing` fixture: 2.1.0 served, 2.0.0 retained. */
function marketingFixture(overrides: Partial<SiteFixture> = {}): SiteFixture {
  return {
    site: "marketing",
    serving: "2.1.0",
    bundles: [
      {
        version: "2.1.0",
        files: ["index.html", "app.js"],
        createdAtUnix: 1_700_000_200,
        manifest: manifest(),
      },
      {
        version: "2.0.0",
        files: ["index.html"],
        createdAtUnix: 1_700_000_100,
        manifest: manifest({
          bundle_version: "2.0.0",
          public: false,
          spa_fallback: false,
          cache_control: "public, max-age=60",
          files: [
            {
              path: "index.html",
              content_type: "text/html",
              content_hash: "d".repeat(64),
              size_bytes: 1024,
            },
          ],
          updated_at_unix: 1_699_000_000,
        }),
      },
    ],
    ...overrides,
  };
}

/**
 * The shape the gateway ACTUALLY serializes for a bound hostname. #488 added
 * `verification_state` and `serving` to `admin_site_domain()` with NO
 * `skip_serializing_if`, so every `AdminSiteDomain` on the wire carries both —
 * yet the generated client declares them optional, so a fixture that omits them
 * still typechecks. That divergence is exactly why the ACME tests below would
 * stay green against a permanently dead hostname. Typing the base fixture as
 * `Required` makes dropping either field a COMPILE error; a test that wants to
 * model a gateway that reports neither still overrides them to `undefined`
 * explicitly, which is a visible choice rather than an omission.
 */
type WireSiteDomain = SiteDomain &
  Required<Pick<SiteDomain, "verification_state" | "serving">>;

const BOUND_DOMAIN: WireSiteDomain = {
  object: "site_domain",
  hostname: "app.example.com",
  tenant_id: "tenant-1",
  site: "marketing",
  serve_path: "/sites/tenant-1/marketing/",
  // A live binding: ownership proven, so the gateway serves it.
  verification_state: "verified",
  serving: true,
  created_at_unix: 1000,
  updated_at_unix: 1000,
};

function domain(overrides: Partial<SiteDomain> = {}): SiteDomain {
  return { ...BOUND_DOMAIN, ...overrides };
}

/** The #488 ownership-proof block `GET /admin/v1/site-domains/{hostname}`
 * returns alongside a binding: the exact `_ferrogate-challenge.{hostname}` TXT
 * record still to be published, plus when its token expires. */
function pendingVerification(
  binding: SiteDomain,
): AdminSchema<"AdminSiteDomainVerification"> {
  return {
    object: "site_domain_verification",
    state: "pending_verification",
    serves: false,
    tenant_id: binding.tenant_id,
    hostname: binding.hostname,
    site: binding.site,
    challenge_record_name: `_ferrogate-challenge.${binding.hostname}`,
    challenge_record_type: "TXT",
    challenge_record_value: "ferrogate-site-verify=cafebabe",
    issued_at_unix: 1000,
    token_expires_at_unix: 1_700_003_600,
    attempt_count: 0,
  };
}

/** Uploads `file` to a file input directly, bypassing the browser-level
 * `accept` filter so the component's own client-side archive validation (the
 * belt-and-suspenders JS check) is exercised. */
function uploadFile(input: HTMLElement, file: File) {
  fireEvent.change(input, { target: { files: [file] } });
}

/**
 * Base handlers backing the page: the tenant asset listing, the site-domains
 * registry (+ the per-hostname detail read the drawer uses for ACME posture),
 * and — for every published site fixture — the three reads the console's
 * active-bundle resolution walks: the asset REGISTRY manifest, each retained
 * bundle's own manifest row, and the mutable `__site_manifest__` marker.
 *
 * Site-specific handlers are listed FIRST so they win over the generic ones.
 */
/**
 * A row of the operator-only withheld listing (`GET /v1/assets/withheld`,
 * #379): the DURABLE record that screening withheld an asset (#366) rather than
 * rejecting it. This is what distinguishes the two ways a publish PUT can
 * answer 200 without publishing anything — screening withheld the bundle, or
 * the body simply was not a ZIP — so the console can name the real reason
 * instead of guessing at one.
 */
function withheldAsset(
  overrides: Partial<AdminSchema<"WithheldAssetSummary">> = {},
): AdminSchema<"WithheldAssetSummary"> {
  return {
    id: "tenant-1:static_site:marketing:2.2.0",
    asset_type: "static_site",
    name: "marketing",
    version: "2.2.0",
    content_type: "application/zip",
    content_hash: "e".repeat(64),
    size_bytes: 400,
    storage_backed: false,
    created_at_unix: 1_700_000_300,
    updated_at_unix: 1_700_000_300,
    visibility: "quarantined",
    ...overrides,
  };
}

function mockBase(options: {
  sites?: SiteFixture[];
  domains?: SiteDomain[];
  /** ACME posture returned by `GET /admin/v1/site-domains/{hostname}`. */
  acmeEnabled?: boolean;
  /** Rows the withheld listing returns. Empty by default — the ordinary case,
   * where nothing the tenant pushed was withheld by screening. */
  withheld?: AdminSchema<"WithheldAssetSummary">[];
} = {}) {
  const sites = options.sites ?? [];
  const siteHandlers = sites.flatMap((fixture) => [
    http.get(gatewayUrl(`/v1/assets/static_site/${fixture.site}/manifest`), () =>
      HttpResponse.json(registryFor(fixture)),
    ),
    http.get(
      gatewayUrl(`/v1/assets/static_site/${fixture.site}/${SITE_MANIFEST_VERSION}`),
      () => HttpResponse.json(fixture.marker ?? fixture.bundles[0].manifest),
    ),
    ...fixture.bundles.map((bundle) =>
      http.get(
        gatewayUrl(`/v1/assets/static_site/${fixture.site}/${bundle.version}`),
        () => HttpResponse.json(bundle.manifest),
      ),
    ),
  ]);
  server.use(
    ...siteHandlers,
    http.get(gatewayUrl("/v1/assets"), () =>
      HttpResponse.json({
        object: "list",
        data: sites.flatMap((fixture) => assetRowsFor(fixture)),
      }),
    ),
    http.get(gatewayUrl("/admin/v1/site-domains"), () =>
      HttpResponse.json({ object: "list", data: options.domains ?? [] }),
    ),
    // The withheld listing the publish path reads back to explain a 200 that
    // committed no bundle. Modelled on every fixture, not just the tests that
    // care, so a publish can never silently fall off the end of the mock.
    http.get(gatewayUrl("/v1/assets/withheld"), () =>
      HttpResponse.json({
        object: "list",
        data: options.withheld ?? [],
        total: (options.withheld ?? []).length,
      }),
    ),
    // Per-hostname detail read: the only endpoint that carries ACME posture and
    // the #488 `verification` block, so the drawer can show both for a binding
    // made long before this session. It echoes the listed binding, so a fixture
    // that says a hostname is pending is not contradicted by its own detail.
    http.get(gatewayUrl("/admin/v1/site-domains/:hostname"), ({ params }) => {
      const hostname = params.hostname as string;
      const binding =
        (options.domains ?? []).find((entry) => entry.hostname === hostname) ??
        domain({ hostname });
      return HttpResponse.json({
        object: "site_domain",
        site_domain: binding,
        acme: {
          enabled: options.acmeEnabled ?? true,
          reload_triggered: false,
        },
        // The gateway omits `verification` only when no proof record exists at
        // all; a pending binding always carries the record to publish.
        ...(binding.verification_state === "pending_verification"
          ? { verification: pendingVerification(binding) }
          : {}),
      });
    }),
    http.get(gatewayUrl("/admin/v1/tenant-accounts/tenant-1"), () =>
      HttpResponse.json({ object: "tenant", tenant: { id: "tenant-1", name: "Acme", slug: "acme" } }),
    ),
  );
}

beforeEach(() => {
  seedSession();
});

describe("StaticSitesPage", () => {
  it("lists published sites with policy, serve URL, and bound domains", async () => {
    mockBase({ sites: [marketingFixture()], domains: [domain()] });
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
    mockBase({
      sites: [
        marketingFixture({
          bundles: [
            {
              version: "2.1.0",
              files: ["index.html", "app.js"],
              createdAtUnix: 1_700_000_200,
              manifest: manifest({ public: false, spa_fallback: false }),
            },
          ],
        }),
      ],
    });
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

  // How D1 became REACHABLE: the client-side gate used to check only the
  // filename and the browser-declared MIME type, so `head -c 400 /dev/urandom >
  // site.zip` passed it, reached the gateway, failed `is_zip_archive`, and came
  // back as a 200 the console read as a publish. The bytes are the fact; the
  // name is only the operator's claim.
  it("blocks a corrupt file NAMED .zip before it is ever uploaded", async () => {
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

    // Correct name, correct MIME type, bytes that are not a ZIP at all.
    const corrupt = new File([new Uint8Array([0x00, 0xff, 0x13, 0x37])], "site.zip", {
      type: "application/zip",
    });
    uploadFile(screen.getByLabelText("Bundle (ZIP)"), corrupt);

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

describe("StaticSitesPage served-bundle fidelity", () => {
  /** The post-rollback state: the `serving` channel has been moved back to
   * 2.0.0, but the mutable `__site_manifest__` marker still describes 2.1.0 —
   * because a rollback is a channel move and never rewrites the marker
   * (sites.rs writes it only on publish). Reading the marker here would
   * describe a bundle nobody is being served. */
  function rolledBackFixture(): SiteFixture {
    const fixture = marketingFixture();
    return { ...fixture, serving: "2.0.0", marker: fixture.bundles[0].manifest };
  }

  it("shows the CHANNEL-RESOLVED bundle's policy after a rollback, not the stale marker", async () => {
    mockBase({ sites: [rolledBackFixture()] });
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    // The served bundle is 2.0.0 — private, no SPA, max-age=60, one file.
    expect(await within(row).findByText("2.0.0")).toBeInTheDocument();
    expect(within(row).queryByText("2.1.0")).toBeNull();
    expect(within(row).getByText("Private")).toBeInTheDocument();
    expect(within(row).queryByText("SPA")).toBeNull();
    expect(within(row).getByText("public, max-age=60")).toBeInTheDocument();
    // …and NOT the marker's 2.1.0 policy (public + SPA + max-age=600).
    expect(within(row).queryByText("public, max-age=600")).toBeNull();
  });

  it("does not contradict itself: the drawer header names the version badged Active", async () => {
    mockBase({ sites: [rolledBackFixture()] });
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.0.0");
    await user.click(
      within(row).getByRole("button", { name: en["resource.table.moreDetails"] }),
    );
    const drawer = await screen.findByRole("dialog");

    // Header describes the SERVED bundle (2.0.0, its single file)…
    expect(within(drawer).getByText(/Bundle 2\.0\.0/)).toBeInTheDocument();
    // …and the history badges that very same version Active.
    const activeRow = within(drawer).getByTestId("static-site-version-2.0.0");
    expect(
      within(activeRow).getByText(en["page.staticSites.history.active"]),
    ).toBeInTheDocument();
    // The file tree is the served bundle's, so a per-file download's bytes match
    // the hash beside it: 2.1.0's app.js is not listed at all.
    expect(within(drawer).getByText("index.html")).toBeInTheDocument();
    expect(within(drawer).queryByText("app.js")).toBeNull();
  });

  it("falls back to the marker for a LEGACY site that has no serving channel", async () => {
    // A pre-#397 site: no `serving` channel, so the gateway itself serves from
    // the mutable marker — and so must the console.
    mockBase({
      sites: [marketingFixture({ serving: null, marker: manifest() })],
    });
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    expect(await within(row).findByText("2.1.0")).toBeInTheDocument();
    expect(within(row).getByText("public, max-age=600")).toBeInTheDocument();
  });

  it("says nothing about the cache policy while the manifest is unavailable", async () => {
    mockBase({ sites: [marketingFixture()] });
    // The served bundle's manifest read fails: the console knows the site
    // exists but knows NOTHING about its policy.
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/2.1.0"), () =>
        HttpResponse.json(
          { error: { code: "asset_not_found", message: "gone" } },
          { status: 404 },
        ),
      ),
    );
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    // Access honestly reports the manifest is unavailable…
    expect(
      await within(row).findByText(en["page.staticSites.manifestError"]),
    ).toBeInTheDocument();
    // …so the Cache cell must NOT assert the `default` policy — it prints the
    // same em dash the files/bytes/published siblings do (#458/#464/#473).
    expect(
      within(row).queryByText(en["page.staticSites.cache.default"]),
    ).toBeNull();
    expect(within(row).getAllByText("—").length).toBeGreaterThanOrEqual(4);
  });

  it("keeps a site whose manifest row is unreadable inspectable and purgeable", async () => {
    mockBase({ sites: [marketingFixture()] });
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/2.1.0"), () =>
        HttpResponse.json(
          { error: { code: "asset_not_found", message: "gone" } },
          { status: 404 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText(en["page.staticSites.manifestError"]);
    // The registry read succeeded, so the site's retained versions ARE known —
    // the drawer must open (a site stranded behind a disabled action could
    // never be purged, which is how retained bytes end up billed forever).
    await user.click(
      within(row).getByRole("button", { name: en["resource.table.moreDetails"] }),
    );
    const drawer = await screen.findByRole("dialog");
    // Version history still renders from the registry…
    expect(
      within(drawer).getByTestId("static-site-version-2.1.0"),
    ).toBeInTheDocument();
    expect(
      within(drawer).queryByText(en["page.staticSites.history.unavailable"]),
    ).toBeNull();
    // …and Unpublish is armed, because the purge walks the registry.
    expect(
      within(drawer).getByRole("button", {
        name: en["page.staticSites.unpublish.action"],
      }),
    ).toBeEnabled();
  });
});

describe("StaticSitesPage publish target", () => {
  it("states the session tenant read-only and previews the serve URL under it", async () => {
    mockBase();
    renderWithProviders(<StaticSitesPage />);
    await screen.findByText("No published static sites.");

    // No tenant PICKER: the publish path carries no tenant (the gateway takes it
    // from the API key), so a selectable control could only mislead — it used to
    // drive the serve-URL preview into naming a tenant the bundle never reaches.
    expect(screen.queryByRole("combobox", { name: "Tenant" })).toBeNull();
    // The tenant that will actually own the bundle is stated instead…
    expect(screen.getByText("Acme")).toBeInTheDocument();
    // …and the serve-URL preview is pinned to it.
    expect(screen.getByText("/sites/tenant-1/{site}/")).toBeInTheDocument();
  });

  it("backs the site field with the tenant's published slugs, deduped and sorted", async () => {
    // THREE published sites, listed out of order, each contributing several
    // `/v1/assets` rows (bundle manifests, `__site_file__:` objects, the marker)
    // under the SAME name. A single-site fixture pinned one option and so could
    // not tell a correct enumeration from one that dropped the sort or emitted a
    // suggestion per asset row.
    mockBase({
      sites: [
        marketingFixture(),
        marketingFixture({ site: "docs", serving: "2.1.0" }),
        marketingFixture({ site: "blog", serving: "2.1.0" }),
      ],
    });
    renderWithProviders(<StaticSitesPage />);
    await screen.findByTestId("static-site-marketing");

    // The published-site selection is no longer blind free text: the input is
    // bound to a datalist enumerating the tenant's own published site slugs
    // (it stays an input so a FIRST publish can still name a new slug).
    const input = screen.getByLabelText("Site");
    expect(input).toHaveAttribute("list", "site-slug-options");
    const options = document
      .getElementById("site-slug-options")!
      .querySelectorAll("option");
    // One option per SITE (not per asset row), alphabetically ordered.
    expect([...options].map((option) => option.getAttribute("value"))).toEqual([
      "blog",
      "docs",
      "marketing",
    ]);
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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

/**
 * A STATEFUL `marketing` server for the unpublish purge, modelling the two
 * gateway behaviours a fire-and-forget mock cannot show:
 *
 *  1. `DELETE` of a version row that a channel still points at is REFUSED —
 *     `delete_asset_variant_if_unreferenced` returns `BlockedByChannel` for the
 *     last resolvable variant of a channel-referenced version, and
 *     `handle_asset_delete` turns that into 409 `asset_version_referenced`
 *     ("…move or delete the channel first"). A handler that 200s every version
 *     DELETE leaves the purge ORDER completely unconstrained, which is how a
 *     purge that deletes versions before channels passed its own test.
 *  2. Deletions are VISIBLE: `/v1/assets` and the registry manifest are rebuilt
 *     from live state, so the test can assert the applied outcome (the site is
 *     gone from a refetched listing) instead of only the requests sent.
 */
function installStatefulMarketing(
  fixture: SiteFixture,
  options: {
    /** Version rows whose DELETE fails with a 503, to model a purge that only
     * partially applies. Keyed by the DECODED registry key, since the reserved
     * `__site_file__:{v}:{path}` keys are percent-encoded on the wire. */
    failVersions?: Record<string, string>;
  } = {},
) {
  const registry = registryFor(fixture);
  const state = {
    versions: registry.versions.map((entry) => entry.version),
    channels: registry.channels.map((entry) => ({ ...entry })),
    /** Every delete, in the order the server received it. */
    order: [] as string[],
  };
  const rowsByVersion = new Map(
    assetRowsFor(fixture).map((row) => [row.version, row]),
  );
  server.use(
    http.get(gatewayUrl("/v1/assets"), () =>
      HttpResponse.json({
        object: "list",
        data: state.versions.flatMap((version) => {
          const row = rowsByVersion.get(version);
          return row ? [row] : [];
        }),
      }),
    ),
    http.get(gatewayUrl(`/v1/assets/static_site/${fixture.site}/manifest`), () =>
      HttpResponse.json({
        ...registry,
        channels: state.channels,
        versions: state.versions.map((version) => ({
          version,
          yanked: false,
          variants: [],
        })),
      }),
    ),
    http.delete(
      gatewayUrl(`/v1/assets/static_site/${fixture.site}/channels/:channel`),
      ({ params }) => {
        const channel = params.channel as string;
        state.order.push(`channel:${channel}`);
        state.channels = state.channels.filter(
          (entry) => entry.channel !== channel,
        );
        return HttpResponse.json({
          object: "asset_channel",
          id: `static_site/${fixture.site}/channels/${channel}`,
          deleted: true,
        });
      },
    ),
    http.delete(
      gatewayUrl(`/v1/assets/static_site/${fixture.site}/:version`),
      ({ params }) => {
        const version = params.version as string;
        state.order.push(`version:${version}`);
        const injected = options.failVersions?.[version];
        if (injected !== undefined) {
          return HttpResponse.json(
            {
              error: {
                type: "ferrogate_error",
                code: "storage_unavailable",
                message: injected,
                request_id: "req-down",
              },
            },
            { status: 503 },
          );
        }
        // The gateway's refusal, verbatim in shape and code.
        if (state.channels.some((entry) => entry.version === version)) {
          return HttpResponse.json(
            {
              error: {
                type: "ferrogate_error",
                code: "asset_version_referenced",
                message: `version ${version} is the last resolvable variant of a channel-referenced version; move or delete the channel first`,
                request_id: "req-ref",
              },
            },
            { status: 409 },
          );
        }
        state.versions = state.versions.filter((entry) => entry !== version);
        return HttpResponse.json({
          object: "asset",
          id: `static_site/${fixture.site}/${version}`,
          deleted: true,
        });
      },
    ),
  );
  return state;
}

describe("StaticSitesPage unpublish flow", () => {
  it("requires the exact typed site name, then purges EVERY retained row and the serving channel", async () => {
    mockBase({ sites: [marketingFixture()] });
    const state = installStatefulMarketing(marketingFixture());
    const successToast = vi.spyOn(toast, "success");
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

    // The APPLIED outcome: the site is gone from a refetched `/v1/assets`.
    // Anything left behind keeps the site listed forever and keeps charging its
    // bytes to the tenant's asset-storage quota, which would make the success
    // toast a lie — and that is precisely what happens when the purge deletes
    // versions before the channel that references them: the served bundle's row
    // 409s and the channel + marker deletes never run.
    await waitFor(() =>
      expect(screen.queryByTestId("static-site-marketing")).toBeNull(),
    );
    expect(await screen.findByText("No published static sites.")).toBeInTheDocument();

    // Nothing survives server-side: no version rows, no channel pointer (a
    // leftover `serving` would be re-adopted by a later publish of the slug).
    expect(state.versions).toEqual([]);
    expect(state.channels).toEqual([]);
    // EVERY retained row was deleted, not just the served bundle's files: both
    // bundle-manifest rows (2.1.0 + the retained 2.0.0), every
    // `__site_file__:{version}:{path}` object of BOTH bundles, and the marker.
    expect(new Set(state.order)).toEqual(
      new Set([
        "channel:serving",
        "version:2.1.0",
        "version:__site_file__:2.1.0:index.html",
        "version:__site_file__:2.1.0:app.js",
        "version:2.0.0",
        "version:__site_file__:2.0.0:index.html",
        "version:__site_manifest__",
      ]),
    );
    // The order the gateway's own 409 message prescribes: channel first, then
    // the version rows, then the reserved marker last.
    expect(state.order[0]).toBe("channel:serving");
    expect(state.order.at(-1)).toBe("version:__site_manifest__");
    await waitFor(() =>
      expect(successToast).toHaveBeenCalledWith(
        en["page.staticSites.unpublish.success"].replace("{site}", "marketing"),
      ),
    );
    successToast.mockRestore();
  });

  it("reports a PARTIAL purge honestly and leaves it re-drivable", async () => {
    mockBase({ sites: [marketingFixture()] });
    // One file object refuses to delete (a storage blip). The purge must not
    // claim success, must not push on to the marker — which would orphan the
    // surviving objects behind a gone manifest — and must say what is left.
    const state = installStatefulMarketing(marketingFixture(), {
      failVersions: {
        "__site_file__:2.0.0:index.html": "object store is unavailable",
      },
    });
    const successToast = vi.spyOn(toast, "success");
    const errorToast = vi.spyOn(toast, "error");
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);

    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");
    await user.click(
      within(row).getByRole("button", { name: en["resource.table.moreDetails"] }),
    );
    const drawer = await screen.findByRole("dialog");
    await user.click(
      within(drawer).getByRole("button", {
        name: en["page.staticSites.unpublish.action"],
      }),
    );
    const confirmDialog = (
      await screen.findByText(
        en["page.staticSites.unpublish.title"].replace("{site}", "marketing"),
      )
    ).closest("[role='dialog']") as HTMLElement;
    await user.type(
      within(confirmDialog).getByLabelText(
        en["page.staticSites.unpublish.confirmLabel"].replace("{site}", "marketing"),
      ),
      "marketing",
    );
    await user.click(
      within(confirmDialog).getByRole("button", {
        name: en["page.staticSites.unpublish.action"],
      }),
    );

    // No success is claimed, and the failure names the row + the gateway verdict.
    await waitFor(() => expect(errorToast).toHaveBeenCalled());
    expect(successToast).not.toHaveBeenCalled();
    const message = errorToast.mock.calls[0][0] as string;
    expect(message).toContain("__site_file__:2.0.0:index.html");
    expect(message).toContain("object store is unavailable");
    expect(message).toContain("marketing");
    // The marker was NOT deleted — the site stays describable, and the surviving
    // object is still reachable for a retry.
    expect(state.versions).toContain("__site_manifest__");
    expect(state.versions).toContain("__site_file__:2.0.0:index.html");
    expect(state.order).not.toContain("version:__site_manifest__");
    successToast.mockRestore();
    errorToast.mockRestore();
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
    mockBase({ sites: [marketingFixture()] });
    // The fixture's `serving` channel points at 2.1.0; 2.0.0 is retained.
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
    mockBase({ sites: [marketingFixture()] });
    // Layer a LEGACY bare file row `index.html` (no `__site_file__:` companion)
    // onto the fixture registry, next to the real #397 bundle rows and the
    // reserved marker — only the bundles are real rollback targets.
    const legacyRegistry = registryFor(marketingFixture());
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/manifest"), () =>
        HttpResponse.json({
          ...legacyRegistry,
          versions: [
            ...legacyRegistry.versions,
            { version: "index.html", yanked: false, variants: [] },
          ],
        }),
      ),
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
    let registryReads = 0;
    let channelUrl: string | null = null;
    let channelMethod: string | null = null;
    const registry = registryFor(marketingFixture());
    server.use(
      http.get(gatewayUrl("/v1/assets/static_site/marketing/manifest"), () => {
        registryReads += 1;
        return HttpResponse.json(registry);
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
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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

  // GATE (#345 box 3, "the UI states the ACTUAL outcome"): the gateway only
  // takes the bundle-publish path when `asset_type == static_site &&
  // is_zip_archive(body) && screening.is_visible()` (assets.rs:653). A body
  // that is NOT a real ZIP -- the console's `looksLikeZip` gate was name/MIME
  // only, so a corrupt file named `site.zip` passed it -- or a bundle whose
  // supply-chain screening came back pending/quarantined falls THROUGH to the
  // ordinary blob store, which answers 200 with the AssetMutationResponse
  // envelope. Observed against a real gateway:
  //   PUT /v1/assets/static_site/mysite/3.0.0  (400 random bytes, .zip)
  //   -> 200 {"object":"asset","asset":{...,"content_type":"application/zip"}}
  //   and /sites/org_a/mysite/ kept serving the PREVIOUS bundle.
  // Nothing was published, so the console must not claim a publish.
  it("does not claim a publish when the gateway stored an opaque blob instead", async () => {
    mockBase({ sites: [marketingFixture()] });
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        // The REAL fallthrough envelope, verbatim from the probe above.
        HttpResponse.json({
          object: "asset",
          asset: {
            id: "tenant-1:static_site:marketing:2.2.0",
            asset_type: "static_site",
            name: "marketing",
            version: "2.2.0",
            content_type: "application/zip",
            content_hash: "0c8c83a298d8cf76f4973c6ed2c09c354b49be64b3f06201aa5e90a1a161be6f",
            size_bytes: 400,
            storage_backed: false,
            created_at_unix: 1785056919,
            updated_at_unix: 1785056919,
          },
        }),
      ),
    );
    const successToast = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const row = await screen.findByTestId("static-site-marketing");
      await within(row).findByText("2.1.0");

      await fillAndPublish(user, "marketing", "2.2.0");

      // No site bundle was committed, so no success may be claimed.
      await waitFor(() => expect(successToast).not.toHaveBeenCalled());
    } finally {
      successToast.mockRestore();
    }
  });

  /** The opaque-blob 200 the gateway answers when it did NOT publish a bundle:
   * `AssetMutationResponse`, carrying no `site`/`file_count`/`size_bytes`. */
  function blobEnvelope(site: string, version: string) {
    return HttpResponse.json({
      object: "asset",
      asset: {
        id: `tenant-1:static_site:${site}:${version}`,
        asset_type: "static_site",
        name: site,
        version,
        content_type: "application/zip",
        content_hash: "0c8c83a298d8cf76f4973c6ed2c09c354b49be64b3f06201aa5e90a1a161be6f",
        size_bytes: 400,
        storage_backed: false,
        created_at_unix: 1785056919,
        updated_at_unix: 1785056919,
      },
    });
  }

  // The other half of D1: the operator must be TOLD what happened, not merely
  // denied a success toast. The withheld listing is empty here, which is how the
  // console knows screening passed and the body was therefore not a ZIP.
  it("states the actual outcome of an opaque-blob 200, with no undefined or NaN", async () => {
    mockBase({ sites: [marketingFixture()] });
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        blobEnvelope("marketing", "2.2.0"),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");

    await fillAndPublish(user, "marketing", "2.2.0");

    const alert = await screen.findByRole("alert");
    // It names the real outcome: stored as an ordinary asset, nothing served.
    expect(alert).toHaveTextContent("Not published");
    expect(alert).toHaveTextContent("not a ZIP archive");
    expect(alert).toHaveTextContent("still serves its previous bundle");
    // The old code rendered the missing bundle fields into operator copy.
    expect(alert.textContent).not.toMatch(/undefined|NaN/);
    // The previously published bundle is untouched and still listed.
    const stillThere = screen.getByTestId("static-site-marketing");
    expect(within(stillThere).getByText("2.1.0")).toBeInTheDocument();
  });

  // Box 6's missing half: the gateway does NOT reject a pending/quarantined
  // bundle (#366 stores it withheld on purpose, so it is never served before it
  // is proven clean) — it answers the same 200 blob envelope. A scan rejection
  // therefore has a 2xx shape as well as the 4xx one already covered.
  it("names the screening verdict when a bundle was stored withheld, not published", async () => {
    mockBase({
      sites: [marketingFixture()],
      withheld: [withheldAsset({ visibility: "quarantined" })],
    });
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        blobEnvelope("marketing", "2.2.0"),
      ),
    );
    const successToast = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const row = await screen.findByTestId("static-site-marketing");
      await within(row).findByText("2.1.0");

      await fillAndPublish(user, "marketing", "2.2.0");

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("screening withheld this bundle");
      // The DURABLE verdict from the withheld row, not a generic guess.
      expect(alert).toHaveTextContent("Quarantined");
      expect(alert).not.toHaveTextContent("not a ZIP archive");
      expect(successToast).not.toHaveBeenCalled();
    } finally {
      successToast.mockRestore();
    }
  });

  it("distinguishes a pending scan from a quarantine", async () => {
    mockBase({
      sites: [marketingFixture()],
      withheld: [withheldAsset({ visibility: "pending_scan" })],
    });
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        blobEnvelope("marketing", "2.2.0"),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const row = await screen.findByTestId("static-site-marketing");
    await within(row).findByText("2.1.0");

    await fillAndPublish(user, "marketing", "2.2.0");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Pending scan");
    expect(alert).not.toHaveTextContent("Quarantined");
  });

  // The "it was not withheld, therefore it was not a ZIP" deduction is only
  // sound if the whole withheld listing was seen. It is PAGINATED (any non-empty
  // query takes the paginated branch at admin_list_default_limit = 100) and
  // sorted by (name, version) — alphabetically, NOT by recency — so a tenant
  // with more withheld static_site rows than one page holds could have this
  // bundle's row sort past the cut. Concluding "not a ZIP archive" from a
  // truncated page is exactly the guess the message claims never to make.
  it("does not deduce 'not a ZIP' from a TRUNCATED withheld listing", async () => {
    mockBase({ sites: [marketingFixture()] });
    let withheldQuery: URLSearchParams | undefined;
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        blobEnvelope("marketing", "2.2.0"),
      ),
      // A page of rows that does NOT include marketing/2.2.0, while `total`
      // reports there are more rows than were returned.
      http.get(gatewayUrl("/v1/assets/withheld"), ({ request }) => {
        withheldQuery = new URL(request.url).searchParams;
        return HttpResponse.json({
          object: "list",
          data: [withheldAsset({ name: "aardvark", version: "2.2.0", id: "a" })],
          total: 4_200,
          offset: 0,
          limit: 1,
        });
      }),
    );
    const successToast = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const row = await screen.findByTestId("static-site-marketing");
      await within(row).findByText("2.1.0");

      await fillAndPublish(user, "marketing", "2.2.0");

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("Not published");
      // The observed outcome is still stated…
      expect(alert).toHaveTextContent("stored the upload as an ordinary asset");
      // …but neither reason is asserted from a partial answer.
      expect(alert).toHaveTextContent("could not be determined");
      expect(alert).not.toHaveTextContent("the upload is not a ZIP archive");
      expect(alert).not.toHaveTextContent("screening withheld");
      expect(successToast).not.toHaveBeenCalled();
      // And the read narrows before it paginates: `search` is matched against
      // id/name/version/asset_type/visibility server-side, and the limit is the
      // largest a single read can be given (clamped by admin_list_max_limit).
      expect(withheldQuery?.get("search")).toBe("2.2.0");
      expect(withheldQuery?.get("asset_type")).toBe("static_site");
      expect(Number(withheldQuery?.get("limit"))).toBeGreaterThanOrEqual(1000);
    } finally {
      successToast.mockRestore();
    }
  });

  // Honesty rule: when the reason cannot be read we report the outcome we DID
  // observe and surface the unread reason — we never pick one of the two.
  it("admits it could not read WHY the publish did not commit", async () => {
    mockBase({ sites: [marketingFixture()] });
    server.use(
      http.put(gatewayUrl("/v1/assets/static_site/marketing/2.2.0"), () =>
        blobEnvelope("marketing", "2.2.0"),
      ),
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json(
          {
            error: {
              type: "ferrogate_error",
              code: "forbidden",
              message: "assets.read permission required",
              request_id: "req-w",
            },
          },
          { status: 403 },
        ),
      ),
    );
    const successToast = vi.spyOn(toast, "success");
    try {
      const user = userEvent.setup();
      renderWithProviders(<StaticSitesPage />);
      const row = await screen.findByTestId("static-site-marketing");
      await within(row).findByText("2.1.0");

      await fillAndPublish(user, "marketing", "2.2.0");

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("Not published");
      expect(alert).toHaveTextContent("the reason could not be read back");
      // The gateway's own words, verbatim — not a substituted guess.
      expect(alert).toHaveTextContent("assets.read permission required");
      // Neither reason is asserted.
      expect(alert).not.toHaveTextContent("not a ZIP archive");
      expect(alert).not.toHaveTextContent("screening withheld");
      expect(successToast).not.toHaveBeenCalled();
    } finally {
      successToast.mockRestore();
    }
  });

  it("a failed republish leaves the prior site listed and claims no success", async () => {
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()] });
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

  // The gateway answers 202 for a binding it recorded but could not prove, and
  // it deliberately keeps that hostname OUT of the ACME order set (`let acme =
  // if proven && holds_binding { refresh… } else { ambient }`, site_domains.rs).
  // `acme.enabled` still reports the gateway-wide flag, so reading it alone
  // announces "ACME reload triggered"/"ACME enabled" for a hostname that was
  // never enrolled. The in-band twin of that 202 is `site_domain.serving`.
  it("does not claim ACME enrolment for an UNPROVEN (202) binding", async () => {
    mockBase({ sites: [marketingFixture()] });
    server.use(
      http.post(gatewayUrl("/admin/v1/site-domains"), () =>
        HttpResponse.json(
          {
            object: "site_domain",
            site_domain: domain({
              hostname: "app.example.com",
              serving: false,
              verification_state: "pending_verification",
            }),
            // ACME is on for the gateway, and reports a reload — but this
            // hostname is not in the set that was reloaded.
            acme: { enabled: true, reload_triggered: true },
          },
          { status: 202 },
        ),
      ),
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

    const status = await within(drawer).findByRole("status");
    expect(status).toHaveTextContent(/Not enrolled for ACME/);
    expect(status).not.toHaveTextContent(/ACME reload triggered/);
    expect(status).not.toHaveTextContent(/ACME enabled/);
  });

  // Absent liveness is not a licence to guess the healthy answer, here either.
  it("says the enrolment is unknown when the bind response omits serving", async () => {
    mockBase({ sites: [marketingFixture()] });
    server.use(
      http.post(gatewayUrl("/admin/v1/site-domains"), () =>
        HttpResponse.json({
          object: "site_domain",
          // A gateway predating #488: no liveness on the wire at all.
          site_domain: domain({
            hostname: "app.example.com",
            serving: undefined,
            verification_state: undefined,
          }),
          acme: { enabled: true, reload_triggered: false },
        }),
      ),
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

    const status = await within(drawer).findByRole("status");
    expect(status).toHaveTextContent(/whether this hostname was enrolled is unknown/);
    expect(status).not.toHaveTextContent(/Not enrolled for ACME/);
  });

  it("validates the hostname client-side without issuing a bind", async () => {
    mockBase({ sites: [marketingFixture()] });
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
    mockBase({ sites: [marketingFixture()], domains: [domain()] });
    let unbound: string | null = null;
    server.use(
      http.delete(
        gatewayUrl("/admin/v1/site-domains/:hostname"),
        ({ params }) => {
          unbound = params.hostname as string;
          // The contract is DeleteResponse: object + id + deleted.
          return HttpResponse.json({
            object: "site_domain",
            id: unbound,
            deleted: true,
          });
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

  it("shows ACME posture for a PRE-EXISTING binding, with no bind in this session", async () => {
    // The binding predates this session, so nothing in the bind response is
    // available; the posture has to come from the per-hostname detail read.
    mockBase({
      sites: [marketingFixture()],
      domains: [domain()],
      acmeEnabled: true,
    });
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    expect(
      await within(domainRow).findByText(en["page.staticSites.acme.enabled"]),
    ).toBeInTheDocument();
  });

  it("reports a disabled-ACME gateway for a pre-existing binding", async () => {
    mockBase({
      sites: [marketingFixture()],
      domains: [domain()],
      acmeEnabled: false,
    });
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    expect(
      await within(domainRow).findByText(en["page.staticSites.acme.disabled"]),
    ).toBeInTheDocument();
  });

  it("reports a live binding as serving, with its ownership verified", async () => {
    mockBase({ sites: [marketingFixture()], domains: [domain()] });
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    expect(
      await within(domainRow).findByText(en["page.siteDomains.serving"]),
    ).toBeInTheDocument();
    expect(
      within(domainRow).getByText(en["page.siteDomains.verification.verified"]),
    ).toBeInTheDocument();
    // A live binding has no outstanding challenge to publish.
    expect(
      within(drawer).queryByTestId(
        "site-domain-challenge-app.example.com",
      ),
    ).toBeNull();
  });

  it("shows a bound hostname the gateway REFUSES as not serving, with the record to publish", async () => {
    // The exact post-bind reality #488 created: the binding is recorded (it has
    // a bound timestamp and ACME is on) but `serving` is false until the DNS
    // proof lands. Showing only "bound" + "ACME enabled" here would render a
    // hostname whose requests are refused exactly like a live one.
    mockBase({
      sites: [marketingFixture()],
      domains: [
        domain({ verification_state: "pending_verification", serving: false }),
      ],
    });
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    expect(
      await within(domainRow).findByText(en["page.siteDomains.notServing"]),
    ).toBeInTheDocument();
    expect(
      within(domainRow).getByText(en["page.siteDomains.verification.pending"]),
    ).toBeInTheDocument();
    expect(
      within(domainRow).queryByText(en["page.siteDomains.serving"]),
    ).toBeNull();
    // …and the remedy: the exact TXT record the gateway is waiting for.
    const challenge = await within(drawer).findByTestId(
      "site-domain-challenge-app.example.com",
    );
    expect(challenge).toHaveTextContent("_ferrogate-challenge.app.example.com");
    expect(challenge).toHaveTextContent("TXT");
    expect(challenge).toHaveTextContent("ferrogate-site-verify=cafebabe");
  });

  it("says Unknown for liveness rather than guessing when nothing reports it", async () => {
    // A gateway that reports neither field (both are optional in the generated
    // client) AND a failed detail read: the console knows nothing about this
    // hostname's liveness and must say exactly that.
    mockBase({
      sites: [marketingFixture()],
      domains: [domain({ verification_state: undefined, serving: undefined })],
    });
    server.use(
      http.get(gatewayUrl("/admin/v1/site-domains/:hostname"), () =>
        HttpResponse.json(
          { error: { code: "backend_unavailable", message: "down" } },
          { status: 503 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    // Serving badge, verification state and ACME all read Unknown — no posture
    // is asserted anywhere in the row.
    await waitFor(() =>
      expect(
        within(domainRow).getAllByText(en["common.unknown"]).length,
      ).toBe(3),
    );
    expect(
      within(domainRow).queryByText(en["page.siteDomains.serving"]),
    ).toBeNull();
    expect(
      within(domainRow).queryByText(en["page.siteDomains.notServing"]),
    ).toBeNull();
  });

  it("says Unknown rather than guessing when the ACME read fails", async () => {
    mockBase({ sites: [marketingFixture()], domains: [domain()] });
    server.use(
      http.get(gatewayUrl("/admin/v1/site-domains/:hostname"), () =>
        HttpResponse.json(
          { error: { code: "backend_unavailable", message: "down" } },
          { status: 503 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderWithProviders(<StaticSitesPage />);
    const drawer = await openMarketingDrawer(user);

    const domainRow = within(drawer).getByTestId(
      "static-site-domain-app.example.com",
    );
    expect(
      await within(domainRow).findByText(en["common.unknown"]),
    ).toBeInTheDocument();
    expect(
      within(domainRow).queryByText(en["page.staticSites.acme.enabled"]),
    ).toBeNull();
  });
});
