// Bespoke browser-contract mocks for the static-site + site-domains GATEWAY
// surface (issue #345). The static-sites page (src/pages/static-sites.tsx) and
// the domain bind/unbind page (src/pages/site-domains.tsx) do NOT talk purely to
// the Admin API shell that installAuthenticatedAdminApi covers:
//
//   * the LIST of sites is derived from the tenant gateway asset listing
//     (GET /v1/assets), one per-site serving-policy manifest read
//     (GET /v1/assets/static_site/{site}/__site_manifest__), and the site-domains
//     registry (GET /admin/v1/site-domains);
//   * PUBLISH/republish is a single raw-bytes PUT
//     (PUT /v1/assets/static_site/{site}/{version}) carrying the serving policy in
//     x-site-* request headers (public / spa-fallback / cache-control);
//   * the detail drawer reads the asset REGISTRY manifest
//     (GET /v1/assets/static_site/{site}/manifest) for its version history and
//     rolls back by moving the well-known `serving` asset channel
//     (PUT /v1/assets/static_site/{site}/channels/serving?version=…);
//   * bind/unbind hit the Admin API site-domains surface
//     (POST /admin/v1/site-domains, DELETE /admin/v1/site-domains/{hostname}).
//
// The shared admin mock returns an EMPTY site-domains list and 501s the gateway
// `/v1/*` + the bind/unbind mutations (the same crux #348 flagged for #344), so
// this module supplies faithful, STATEFUL mocks whose shapes match the generated
// OpenAPI contract (AssetSummary / AssetManifest / StaticSitePublishResponse /
// AdminSiteDomain / AdminSiteDomainResponse). Registered AFTER
// installAuthenticatedAdminApi so these more specific routes win.
//
// State is rebuilt fresh per install() call so each test is isolated. Mutations
// (publish/republish, rollback channel-move, bind, unbind) mutate the in-memory
// state so a subsequent list/manifest refetch — which the pages trigger via
// invalidateQueries — reflects the change: a republished bundle appears in the
// version history and moves the served version, a bound hostname appears in the
// table, an unbound one disappears. That lets the spec assert real
// post-conditions, not just fire-and-forget request sends.
import type { Page, Route } from "@playwright/test";
import type { components } from "../../src/lib/api-types.generated";

type AssetSummary = components["schemas"]["AssetSummary"];
type AssetManifest = components["schemas"]["AssetManifest"];
type AssetManifestVariant = components["schemas"]["AssetManifestVariant"];
type AdminSiteDomain = components["schemas"]["AdminSiteDomain"];

// Reserved `version` keys the gateway writes for a static site (mirrors the
// constants in static-sites.tsx / the gateway's sites.rs).
const STATIC_SITE_TYPE = "static_site";
const SITE_MANIFEST_VERSION = "__site_manifest__";
const SITE_FILE_VERSION_PREFIX = "__site_file__";
const SITE_SERVE_CHANNEL = "serving";

// The session tenant installAuthenticatedAdminApi seeds. The publish form's
// tenant picker pre-selects it and hydrates its label by id, so this module also
// answers that one Admin API detail read (the shared mock only lists tenant-1…24
// and would 404 the session tenant).
const SESSION_TENANT_ID = "tenant-e2e";

const HASH = "a".repeat(64);

/** The per-site serving-policy JSON the gateway stores at the reserved
 * `__site_manifest__` version and serves back verbatim (mirrors the gateway
 * SiteManifest; NOT an OpenAPI component — static-sites.tsx declares it inline). */
interface SiteManifestBody {
  site: string;
  bundle_version: string;
  public: boolean;
  spa_fallback: boolean;
  cache_control: string | null;
  files: {
    path: string;
    content_type: string;
    content_hash: string;
    size_bytes: number;
  }[];
  created_at_unix: number;
  updated_at_unix: number;
}

export interface GatewayStaticSitesOptions {
  /**
   * Hold the publish PUT open this many ms so the "Uploading bundle…" phase +
   * the determinate progressbar are observable by a web-first assertion. Zero
   * (default) fulfills immediately.
   */
  uploadHoldMs?: number;
}

interface StaticSitesState {
  /** Flat per-version summary rows backing GET /v1/assets (dates history rows). */
  summaries: AssetSummary[];
  /** Asset REGISTRY manifests keyed by `${asset_type}/${name}` (channels +
   * versions, incl. the `__site_file__:{v}:{path}` retained-bundle markers). */
  registry: Map<string, AssetManifest>;
  /** Per-site serving-policy manifests keyed by site slug. */
  siteManifests: Map<string, SiteManifestBody>;
  /** Bound custom hostnames backing GET /admin/v1/site-domains. */
  domains: AdminSiteDomain[];
  clock: number;
}

function regKey(assetType: string, name: string): string {
  return `${assetType}/${name}`;
}

function variant(sizeBytes = 2048): AssetManifestVariant {
  return {
    variant: "",
    content_type: "application/zip",
    content_hash: HASH,
    size_bytes: sizeBytes,
    storage_backed: false,
  };
}

function staticSiteSummary(
  name: string,
  version: string,
  createdAtUnix: number,
): AssetSummary {
  return {
    id: `asset_${name}_${version}`.replace(/[^a-z0-9_]/gi, "_"),
    asset_type: STATIC_SITE_TYPE,
    name,
    version,
    content_type: "application/zip",
    content_hash: HASH,
    size_bytes: 2048,
    storage_backed: false,
    created_at_unix: createdAtUnix,
    updated_at_unix: createdAtUnix,
  };
}

/**
 * Fresh fixture per test:
 *   - "marketing" — TWO retained bundle versions (2.0.0 served, 1.0.0 prior),
 *     public + SPA, no bound custom domain (its serve URL is the canonical
 *     tenant path). Backs publish/republish/preview + version-history rollback.
 *   - "docs" — ONE version (1.0.0 served), private, with a bound custom domain
 *     (docs.acme.example) whose serve_path is the site's canonical serve URL.
 * The single bound domain also seeds the site-domains page's list.
 */
function buildState(): StaticSitesState {
  const marketingRegistry: AssetManifest = {
    object: "asset_manifest",
    asset_type: STATIC_SITE_TYPE,
    name: "marketing",
    channels: [{ channel: SITE_SERVE_CHANNEL, version: "2.0.0", updated_at_unix: 1_752_002_000 }],
    versions: [
      { version: "2.0.0", yanked: false, variants: [variant()] },
      { version: "1.0.0", yanked: false, variants: [variant()] },
      {
        version: `${SITE_FILE_VERSION_PREFIX}:2.0.0:index.html`,
        yanked: false,
        variants: [variant()],
      },
      {
        version: `${SITE_FILE_VERSION_PREFIX}:2.0.0:assets/app.js`,
        yanked: false,
        variants: [variant(40_960)],
      },
      {
        version: `${SITE_FILE_VERSION_PREFIX}:1.0.0:index.html`,
        yanked: false,
        variants: [variant()],
      },
      { version: SITE_MANIFEST_VERSION, yanked: false, variants: [variant()] },
    ],
  };

  const docsRegistry: AssetManifest = {
    object: "asset_manifest",
    asset_type: STATIC_SITE_TYPE,
    name: "docs",
    channels: [{ channel: SITE_SERVE_CHANNEL, version: "1.0.0", updated_at_unix: 1_751_900_000 }],
    versions: [
      { version: "1.0.0", yanked: false, variants: [variant()] },
      {
        version: `${SITE_FILE_VERSION_PREFIX}:1.0.0:index.html`,
        yanked: false,
        variants: [variant()],
      },
      { version: SITE_MANIFEST_VERSION, yanked: false, variants: [variant()] },
    ],
  };

  const marketingManifest: SiteManifestBody = {
    site: "marketing",
    bundle_version: "2.0.0",
    public: true,
    spa_fallback: true,
    cache_control: "public, max-age=300",
    files: [
      { path: "index.html", content_type: "text/html", content_hash: HASH, size_bytes: 2048 },
      {
        path: "assets/app.js",
        content_type: "application/javascript",
        content_hash: HASH,
        size_bytes: 40_960,
      },
    ],
    created_at_unix: 1_751_800_000,
    updated_at_unix: 1_752_002_000,
  };

  const docsManifest: SiteManifestBody = {
    site: "docs",
    bundle_version: "1.0.0",
    public: false,
    spa_fallback: false,
    cache_control: null,
    files: [
      { path: "index.html", content_type: "text/html", content_hash: HASH, size_bytes: 1024 },
    ],
    created_at_unix: 1_751_700_000,
    updated_at_unix: 1_751_900_000,
  };

  const domains: AdminSiteDomain[] = [
    {
      object: "site_domain",
      hostname: "docs.acme.example",
      tenant_id: SESSION_TENANT_ID,
      site: "docs",
      serve_path: "/sites/tenant-e2e/docs/",
      created_at_unix: 1_751_950_000,
      updated_at_unix: 1_751_950_000,
    },
  ];

  return {
    summaries: [
      staticSiteSummary("marketing", "2.0.0", 1_752_002_000),
      staticSiteSummary("marketing", "1.0.0", 1_751_800_000),
      staticSiteSummary("docs", "1.0.0", 1_751_900_000),
    ],
    registry: new Map([
      [regKey(STATIC_SITE_TYPE, "marketing"), marketingRegistry],
      [regKey(STATIC_SITE_TYPE, "docs"), docsRegistry],
    ]),
    siteManifests: new Map([
      ["marketing", marketingManifest],
      ["docs", docsManifest],
    ]),
    domains,
    clock: 1_752_100_000,
  };
}

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function notMocked(route: Route, method: string, pathname: string): Promise<void> {
  await fulfillJson(route, 501, {
    error: {
      code: "unmocked_e2e_route",
      message: `${method} ${pathname} is not mocked by the static-sites gateway contract`,
    },
  });
}

/**
 * Publish/republish (PUT /v1/assets/static_site/{site}/{version}): registers the
 * new bundle so a subsequent list/registry/manifest refetch reflects it —
 * a flat summary row (dates the history), a retained bundle version + its
 * `__site_file__:{version}:index.html` companion (so the drawer counts it a real
 * rollback target), and a `serving` channel move to the new version (a publish
 * makes the new bundle the served one, #397). Returns the StaticSitePublishResponse.
 */
async function handlePublish(
  route: Route,
  state: StaticSitesState,
  name: string,
  version: string,
): Promise<void> {
  const headers = route.request().headers();
  const isPublic = headers["x-site-public"] === "true";
  const spaFallback = headers["x-site-spa-fallback"] === "true";
  const cacheHeader = headers["x-site-cache-control"];
  const cacheControl = cacheHeader && cacheHeader !== "" ? cacheHeader : null;
  const now = (state.clock += 1_000);

  state.summaries = [staticSiteSummary(name, version, now), ...state.summaries];

  state.siteManifests.set(name, {
    site: name,
    bundle_version: version,
    public: isPublic,
    spa_fallback: spaFallback,
    cache_control: cacheControl,
    files: [
      { path: "index.html", content_type: "text/html", content_hash: HASH, size_bytes: 2048 },
    ],
    created_at_unix: now,
    updated_at_unix: now,
  });

  let manifest = state.registry.get(regKey(STATIC_SITE_TYPE, name));
  if (!manifest) {
    manifest = {
      object: "asset_manifest",
      asset_type: STATIC_SITE_TYPE,
      name,
      channels: [],
      versions: [{ version: SITE_MANIFEST_VERSION, yanked: false, variants: [variant()] }],
    };
    state.registry.set(regKey(STATIC_SITE_TYPE, name), manifest);
  }
  if (!manifest.versions.some((entry) => entry.version === version)) {
    manifest.versions.unshift({ version, yanked: false, variants: [variant()] });
  }
  const fileKey = `${SITE_FILE_VERSION_PREFIX}:${version}:index.html`;
  if (!manifest.versions.some((entry) => entry.version === fileKey)) {
    manifest.versions.push({ version: fileKey, yanked: false, variants: [variant()] });
  }
  const serving = manifest.channels.find((channel) => channel.channel === SITE_SERVE_CHANNEL);
  if (serving) serving.version = version;
  else manifest.channels.push({ channel: SITE_SERVE_CHANNEL, version, updated_at_unix: now });

  await fulfillJson(route, 200, {
    object: "static_site",
    tenant: SESSION_TENANT_ID,
    site: name,
    bundle_version: version,
    public: isPublic,
    spa_fallback: spaFallback,
    file_count: 1,
    size_bytes: 2048,
    files: ["index.html"],
  });
}

async function handleGatewayRequest(
  route: Route,
  state: StaticSitesState,
  options: GatewayStaticSitesOptions,
): Promise<void> {
  const request = route.request();
  const method = request.method();
  const url = new URL(request.url());
  const pathname = url.pathname;

  // GET /v1/assets — the flat tenant asset listing the site list is derived from.
  if (method === "GET" && pathname === "/v1/assets") {
    await fulfillJson(route, 200, { object: "list", data: state.summaries });
    return;
  }

  const segments = pathname
    .slice("/v1/assets".length)
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => decodeURIComponent(segment));

  // GET /v1/assets/static_site/{name}/manifest — asset REGISTRY manifest (the
  // drawer's version-history source: channels + retained bundle versions).
  if (method === "GET" && segments.length === 3 && segments[2] === "manifest") {
    const [assetType, name] = segments;
    const manifest = state.registry.get(regKey(assetType, name));
    if (!manifest) {
      await fulfillJson(route, 404, {
        error: { code: "asset_not_found", message: "manifest not found" },
      });
      return;
    }
    await fulfillJson(route, 200, manifest);
    return;
  }

  // PUT /v1/assets/static_site/{name}/channels/{channel}?version=… — the truthful
  // rollback: moving the `serving` channel re-points the served bundle (#397/#188).
  if (segments.length === 4 && segments[2] === "channels") {
    const [assetType, name, , channel] = segments;
    const manifest = state.registry.get(regKey(assetType, name));
    if (!manifest) {
      await fulfillJson(route, 404, {
        error: { code: "asset_not_found", message: "asset not found" },
      });
      return;
    }
    if (method === "PUT") {
      const version = url.searchParams.get("version") ?? "";
      const now = (state.clock += 1_000);
      const existing = manifest.channels.find((entry) => entry.channel === channel);
      if (existing) existing.version = version;
      else manifest.channels.push({ channel, version, updated_at_unix: now });
      await fulfillJson(route, 200, {
        object: "asset_channel",
        asset_type: assetType,
        name,
        channel: { channel, version, updated_at_unix: now },
      });
      return;
    }
  }

  // PUT /v1/assets/static_site/{name}/{version} — the publish/republish upload.
  if (method === "PUT" && segments.length === 3 && segments[0] === STATIC_SITE_TYPE) {
    if (options.uploadHoldMs && options.uploadHoldMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, options.uploadHoldMs));
    }
    await handlePublish(route, state, segments[1], segments[2]);
    return;
  }

  // /v1/assets/static_site/{name}/{versionOrPath}
  if (segments.length === 3 && segments[0] === STATIC_SITE_TYPE) {
    const [assetType, name, tail] = segments;

    // GET the reserved manifest version — the per-site serving policy JSON body.
    if (method === "GET" && tail === SITE_MANIFEST_VERSION) {
      const manifest = state.siteManifests.get(name);
      if (!manifest) {
        await fulfillJson(route, 404, {
          error: { code: "asset_not_found", message: "site manifest not found" },
        });
        return;
      }
      await fulfillJson(route, 200, manifest);
      return;
    }

    // GET any other version key — an individual published file's bytes (the
    // drawer's per-file download). Any body suffices; the spec asserts the action.
    if (method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/octet-stream",
        body: Buffer.from(`e2e-site-file:${name}/${tail}`),
      });
      return;
    }

    // DELETE — the unpublish path purges each file object then the manifest.
    // Removing the manifest tears the whole site down so a refetch drops it.
    if (method === "DELETE") {
      state.summaries = state.summaries.filter(
        (row) => !(row.asset_type === assetType && row.name === name && row.version === tail),
      );
      if (tail === SITE_MANIFEST_VERSION) {
        state.siteManifests.delete(name);
        state.registry.delete(regKey(assetType, name));
        state.summaries = state.summaries.filter(
          (row) => !(row.asset_type === assetType && row.name === name),
        );
      }
      await fulfillJson(route, 200, {
        object: "asset",
        id: `${assetType}/${name}/${tail}`,
        deleted: true,
      });
      return;
    }
  }

  await notMocked(route, method, pathname);
}

async function handleSiteDomainsRequest(
  route: Route,
  state: StaticSitesState,
): Promise<void> {
  const request = route.request();
  const method = request.method();
  const url = new URL(request.url());
  const pathname = url.pathname;
  const now = () => (state.clock += 1_000);

  // GET /admin/v1/site-domains — the bound-hostname list (overrides the shared
  // admin mock's empty stub so the fixture domain is present + mutations reflect).
  if (method === "GET" && pathname === "/admin/v1/site-domains") {
    await fulfillJson(route, 200, { object: "list", data: state.domains });
    return;
  }

  // POST /admin/v1/site-domains — bind a custom hostname to a published site.
  if (method === "POST" && pathname === "/admin/v1/site-domains") {
    const body = (request.postDataJSON() ?? {}) as {
      hostname?: string;
      tenant_id?: string;
      site?: string;
    };
    const hostname = (body.hostname ?? "").toLowerCase();
    const tenantId = body.tenant_id ?? "";
    const site = body.site ?? "";
    const created = now();
    const siteDomain: AdminSiteDomain = {
      object: "site_domain",
      hostname,
      tenant_id: tenantId,
      site,
      serve_path: `/sites/${tenantId}/${site}/`,
      created_at_unix: created,
      updated_at_unix: created,
    };
    // Replace any existing binding for this hostname (bind is idempotent-ish).
    state.domains = [
      ...state.domains.filter((domain) => domain.hostname !== hostname),
      siteDomain,
    ];
    await fulfillJson(route, 200, {
      object: "site_domain",
      site_domain: siteDomain,
      acme: { enabled: true, reload_triggered: true },
    });
    return;
  }

  // DELETE /admin/v1/site-domains/{hostname} — unbind a custom hostname.
  if (method === "DELETE" && pathname.startsWith("/admin/v1/site-domains/")) {
    const hostname = decodeURIComponent(
      pathname.slice("/admin/v1/site-domains/".length),
    );
    state.domains = state.domains.filter((domain) => domain.hostname !== hostname);
    await fulfillJson(route, 200, {
      object: "site_domain",
      id: hostname,
      deleted: true,
    });
    return;
  }

  await notMocked(route, method, pathname);
}

/**
 * Installs the static-site + site-domains gateway mocks. Pair with
 * installAuthenticatedAdminApi (which seeds the session + Admin API shell) and
 * call this AFTER it so these more specific routes take precedence. Registers:
 *   - the `/v1/assets*` tenant gateway surface (list / site manifest / registry
 *     manifest / publish PUT / channel-move rollback / file download / unpublish);
 *   - the `/admin/v1/site-domains*` bind/unbind surface + the seeded list;
 *   - the session tenant's `/admin/v1/tenant-accounts/{id}` detail read, so the
 *     publish form's pre-selected tenant picker hydrates cleanly (no 404).
 */
export async function installGatewayStaticSites(
  page: Page,
  options: GatewayStaticSitesOptions = {},
): Promise<void> {
  const state = buildState();

  await page.route(
    (url) => url.pathname === "/v1/assets" || url.pathname.startsWith("/v1/assets/"),
    (route) => handleGatewayRequest(route, state, options),
  );

  await page.route(
    (url) =>
      url.pathname === "/admin/v1/site-domains" ||
      url.pathname.startsWith("/admin/v1/site-domains/"),
    (route) => handleSiteDomainsRequest(route, state),
  );

  // The publish form pre-selects the session tenant; its picker hydrates the
  // label by id. The shared mock only knows tenant-1…24, so answer this one read
  // here to keep the tenant chip resolved (and off the console-error path).
  await page.route(
    (url) => url.pathname === `/admin/v1/tenant-accounts/${SESSION_TENANT_ID}`,
    (route) =>
      fulfillJson(route, 200, {
        object: "tenant",
        tenant: {
          id: SESSION_TENANT_ID,
          name: "Acme Operations",
          slug: "acme-operations",
          status: "active",
          plan_id: "enterprise",
          created_at_unix: 1_720_000_000,
          updated_at_unix: 1_720_086_400,
        },
      }),
  );
}
