/**
 * `/sites/*` — the static-site serve mode (issue #737), driven over real HTTP
 * through the real gateway app.
 *
 * The bundle is a REAL tar built in `../assets/archives.ts` and published
 * through `AssetService.putAsset`, i.e. through #736's expander, so what these
 * cases read back is the same `asset_bundle_files` index a production publish
 * writes. A site fixture assembled by poking rows into the index would prove
 * nothing about the path a browser actually takes.
 *
 * `SELF.fetch` is deliberately not used: the deployed Worker has no R2 binding
 * offline, so the suite assembles the same app the shell assembles
 * (`createGatewayApp({ modules: [siteRouteModule(...)] })`) and drives it with
 * `app.request`. That the SHELL mounts this module is proved separately, over
 * `SELF.fetch`, in `test/contract.test.ts`.
 */
import { describe, expect, test } from "vitest";
import type { AssetCaller, AssetScreener } from "../../src/assets/ports.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { siteRouteModule } from "../../src/sites/index.js";
import type { SiteBinding } from "../../src/sites/registry.js";
import { buildTar } from "../assets/archives.js";
import { CTX, PendingScreener, callerFor, harness } from "../assets/helpers.js";

/**
 * Two tenants. `fg_a` owns `docs`; `fg_b` is the cross-tenant probe that must
 * never reach it. `fg_a_noscope` authenticates but holds no `assets.read`.
 */
const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: ["assets.read"] },
    { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: ["assets.read"] },
    { key: "fg_a_noscope", id: "key_a_ns", tenant_id: "tenant_a", scopes: ["models.read"] },
  ]),
};

const HOME = "<!doctype html><h1>home</h1>";
const DOCS = "<!doctype html><h1>docs</h1>";
const APP_JS = "console.log('this is the fingerprinted bundle')";

function siteTar(): Uint8Array {
  return buildTar([
    { name: "index.html", body: HOME },
    { name: "docs/index.html", body: DOCS },
    { name: "assets/app.4f3a9c21.js", body: APP_JS },
    { name: "assets/app.css", body: "body{color:red}" },
    { name: "404.html", body: "<!doctype html><h1>nope</h1>" },
  ]);
}

interface SiteGatewayOptions {
  readonly bindings?: Record<string, Partial<SiteBinding> & { tenantId: string }>;
  /** Publish under this tenant. Default `tenant_a`. */
  readonly owner?: string;
  /** Asset name to publish as. Default `docs`. */
  readonly name?: string;
  readonly tar?: Uint8Array;
  /** Screener override — `PendingScreener` parks a publish in `pending_scan`. */
  readonly screener?: AssetScreener | undefined;
}

function bindingMap(
  raw: Record<string, Partial<SiteBinding> & { tenantId: string }> | undefined,
): ReadonlyMap<string, SiteBinding> | undefined {
  if (raw === undefined) return undefined;
  const map = new Map<string, SiteBinding>();
  for (const [slug, value] of Object.entries(raw)) {
    map.set(slug, {
      slug,
      assetName: slug,
      channel: "latest",
      anonymous: false,
      spa: false,
      notFoundDocument: "404.html",
      ...value,
    });
  }
  return map;
}

async function siteGateway(options: SiteGatewayOptions = {}) {
  const h = harness(options.screener === undefined ? {} : { screener: options.screener });
  const owner = options.owner ?? "tenant_a";
  const publish = async (name: string, tar: Uint8Array, version = "1.0.0", caller?: AssetCaller) =>
    h.service.putAsset(
      caller ?? callerFor(owner),
      { assetType: "static_site", name, version },
      { content: tar, contentType: "application/x-tar" },
      CTX,
    );
  const published = await publish(options.name ?? "docs", options.tar ?? siteTar());
  const bindings = bindingMap(options.bindings);
  const { app, router } = createGatewayApp({
    modules: [
      siteRouteModule({
        service: h.service,
        ...(bindings !== undefined ? { bindings } : {}),
      }),
    ],
  });
  const call = (
    path: string,
    init: RequestInit & { token?: string | null } = {},
  ): Promise<Response> => {
    const { token = null, headers, ...rest } = init;
    const merged = new Headers(headers);
    if (token !== null) merged.set("authorization", `Bearer ${token}`);
    return Promise.resolve(
      app.request(`https://gw.test${path}`, { ...rest, headers: merged }, ENV),
    );
  };
  return { ...h, app, router, call, publish, published };
}

async function textOf(response: Response): Promise<string> {
  return new TextDecoder().decode(await response.arrayBuffer());
}

async function envelope(response: Response): Promise<{ error: { code: string; message: string } }> {
  return JSON.parse(await textOf(response)) as { error: { code: string; message: string } };
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

describe("#737: a published static_site is served at /sites/*", () => {
  test("GET /sites/{site}/ serves index.html to the owning tenant", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/", { token: "fg_a" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/html");
    expect(res.headers.get("x-ferrogate-site-path")).toBe("index.html");
    expect(await textOf(res)).toBe(HOME);
  });

  test("a nested file is served with the content type the bundle recorded", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/assets/app.4f3a9c21.js", { token: "fg_a" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/javascript");
    expect(await textOf(res)).toBe(APP_JS);
  });

  test("the version came out of the SAME resolution the asset pull uses", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/", { token: "fg_a" });
    // `channel=latest;version=1.0.0` — the header `pullAsset` writes, which
    // only exists because resolution ran. A serve mode with its own lookup
    // would have nothing to put here.
    expect(res.headers.get("x-ferrogate-asset-resolved")).toBe("channel=latest;version=1.0.0");
    expect(res.headers.get("x-ferrogate-asset-version")).toBe("1.0.0");
  });

  test("a channel move is what the site follows", async () => {
    const { call, publish, service } = await siteGateway();
    await publish(
      "docs",
      buildTar([{ name: "index.html", body: "<!doctype html><h1>v2</h1>" }]),
      "2.0.0",
    );
    expect(await textOf(await call("/sites/docs/", { token: "fg_a" }))).toContain("v2");
    // Pin `latest` back at 1.0.0 and the site follows the pointer, not the
    // highest version.
    await service.putChannel(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs" },
      "latest",
      "1.0.0",
      CTX,
    );
    expect(await textOf(await call("/sites/docs/", { token: "fg_a" }))).toBe(HOME);
  });
});

// ---------------------------------------------------------------------------
// Index resolution and trailing slashes
// ---------------------------------------------------------------------------

describe("one document, one URL", () => {
  test("the bare site root redirects to the directory URL", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs", { token: "fg_a" });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe("/sites/docs/");
  });

  test("a directory with an index redirects rather than serving two bodies", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/docs", { token: "fg_a" });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe("/sites/docs/docs/");
    // ...and the canonical URL is the one that has the bytes.
    const followed = await call("/sites/docs/docs/", { token: "fg_a" });
    expect(followed.status).toBe(200);
    expect(await textOf(followed)).toBe(DOCS);
  });

  test("an explicit index.html redirects to its directory", async () => {
    const { call } = await siteGateway();
    for (const [requested, canonical] of [
      ["/sites/docs/index.html", "/sites/docs/"],
      ["/sites/docs/docs/index.html", "/sites/docs/docs/"],
    ]) {
      const res = await call(requested as string, { token: "fg_a" });
      expect(res.status, requested).toBe(308);
      expect(res.headers.get("location"), requested).toBe(canonical);
    }
  });

  test("a redirect carries the query string with it", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/docs?v=2", { token: "fg_a" });
    expect(res.headers.get("location")).toBe("/sites/docs/docs/?v=2");
  });

  test("a directory with no index is a miss, never a listing", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/assets/", { token: "fg_a" });
    expect(res.status).toBe(404);
    const body = await textOf(res);
    // Nothing that names a file inside the directory may appear in the answer.
    expect(body).not.toContain("app.css");
    expect(body).not.toContain("app.4f3a9c21.js");
  });
});

// ---------------------------------------------------------------------------
// Misses
// ---------------------------------------------------------------------------

describe("a miss inside a real site is not the same as an unknown site", () => {
  test("the site's own 404.html is served, with status 404", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/nope.html", { token: "fg_a" });
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toBe("text/html");
    expect(await textOf(res)).toContain("<h1>nope</h1>");
    // A soft-404 — the document with status 200 — is what makes a crawler index
    // every typo, so the status is asserted next to the body.
    expect(res.headers.get("x-ferrogate-site-path")).toBe("404.html");
  });

  test("without a 404 document the answer is the JSON envelope", async () => {
    const { call } = await siteGateway({
      tar: buildTar([{ name: "index.html", body: HOME }]),
    });
    const res = await call("/sites/docs/nope.html", { token: "fg_a" });
    expect(res.status).toBe(404);
    expect((await envelope(res)).error.code).toBe("site_file_not_found");
  });

  test("an unknown site is site_not_found, and says nothing else", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/nosuchsite/", { token: "fg_a" });
    expect(res.status).toBe(404);
    const error = (await envelope(res)).error;
    expect(error.code).toBe("site_not_found");
    expect(error.message).toBe("no site is served at /sites/nosuchsite");
  });

  test("SPA fallback is opt-in and answers 200 with the entry document", async () => {
    const { call } = await siteGateway({
      bindings: { docs: { tenantId: "tenant_a", spa: true } },
    });
    const res = await call("/sites/docs/orders/42", { token: "fg_a" });
    expect(res.status).toBe(200);
    expect(await textOf(res)).toBe(HOME);
    expect(res.headers.get("x-ferrogate-site-path")).toBe("index.html");
  });

  test("without the opt-in the same path is a 404, not the entry document", async () => {
    const { call } = await siteGateway({
      bindings: { docs: { tenantId: "tenant_a", spa: false } },
    });
    const res = await call("/sites/docs/orders/42", { token: "fg_a" });
    expect(res.status).toBe(404);
    expect(await textOf(res)).not.toBe(HOME);
  });
});

// ---------------------------------------------------------------------------
// Unservable versions
// ---------------------------------------------------------------------------

describe("quarantined, withheld and yanked bundles are absent", () => {
  test("a yanked version drops out and the site falls back to what is left", async () => {
    const { call, publish, service } = await siteGateway();
    await publish(
      "docs",
      buildTar([{ name: "index.html", body: "<!doctype html><h1>v2</h1>" }]),
      "2.0.0",
    );
    expect(await textOf(await call("/sites/docs/", { token: "fg_a" }))).toContain("v2");
    await service.setVersionYank(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs", version: "2.0.0" },
      true,
      CTX,
    );
    // 2.0.0 is unservable HERE even though `/v1/assets/.../2.0.0` still serves
    // it by exact pin: `/sites/*` never takes a version from the URL.
    const after = await call("/sites/docs/", { token: "fg_a" });
    expect(after.status).toBe(200);
    expect(await textOf(after)).toBe(HOME);
    expect(after.headers.get("x-ferrogate-asset-version")).toBe("1.0.0");
  });

  test("yanking the only version makes the site indistinguishable from absent", async () => {
    const { call, service } = await siteGateway();
    await service.setVersionYank(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs", version: "1.0.0" },
      true,
      CTX,
    );
    const res = await call("/sites/docs/", { token: "fg_a" });
    expect(res.status).toBe(404);
    const error = (await envelope(res)).error;
    expect(error.code).toBe("site_not_found");
    // Byte for byte the answer an unknown slug gets.
    expect(error.message).toBe("no site is served at /sites/docs");
  });

  test("a WITHHELD version — published but unproven — is never served", async () => {
    // The async-scan posture: the screener defers, so the row is admitted
    // `pending_scan` and `isDownloadable` keeps it out of resolution entirely.
    const { call } = await siteGateway({ screener: new PendingScreener() });
    const res = await call("/sites/docs/", { token: "fg_a" });
    expect(res.status).toBe(404);
    expect((await envelope(res)).error.code).toBe("site_not_found");
  });

  test("a QUARANTINED version is never served", async () => {
    const { call, service } = await siteGateway({ screener: new PendingScreener() });
    const promoted = await service.promoteVisibility(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs", version: "1.0.0", variant: "" },
      { scan_outcome: "infected", evidence: "eicar", scanner: "test" },
      CTX,
    );
    expect(promoted.ok).toBe(true);
    const res = await call("/sites/docs/", { token: "fg_a" });
    expect(res.status).toBe(404);
    expect((await envelope(res)).error.code).toBe("site_not_found");
  });

  test("...and a CLEAN promotion of the same row makes the site appear", async () => {
    // The other half of the pair: without it, the two cases above would still
    // pass if `/sites/*` had simply never worked for this fixture.
    const { call, service } = await siteGateway({ screener: new PendingScreener() });
    await service.promoteVisibility(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs", version: "1.0.0", variant: "" },
      { scan_outcome: "clean", evidence: "scanned", scanner: "test" },
      CTX,
    );
    expect((await call("/sites/docs/", { token: "fg_a" })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Conditional, range, HEAD
// ---------------------------------------------------------------------------

describe("conditional requests, ranges and HEAD reuse the asset pull", () => {
  test("a matching ETag answers 304 with no body", async () => {
    const { call } = await siteGateway();
    const first = await call("/sites/docs/", { token: "fg_a" });
    const etag = first.headers.get("etag");
    expect(etag).toMatch(/^"[0-9a-f]{64}"$/);
    const second = await call("/sites/docs/", {
      token: "fg_a",
      headers: { "if-none-match": etag ?? "" },
    });
    expect(second.status).toBe(304);
    expect(await textOf(second)).toBe("");
  });

  test("if-modified-since is honoured too", async () => {
    const { call } = await siteGateway();
    const first = await call("/sites/docs/", { token: "fg_a" });
    const lastModified = first.headers.get("last-modified");
    expect(lastModified).not.toBeNull();
    const second = await call("/sites/docs/", {
      token: "fg_a",
      headers: { "if-modified-since": lastModified ?? "" },
    });
    expect(second.status).toBe(304);
  });

  test("a byte range answers 206 with the slice and a content-range", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/assets/app.4f3a9c21.js", {
      token: "fg_a",
      headers: { range: "bytes=0-6" },
    });
    expect(res.status).toBe(206);
    expect(res.headers.get("content-range")).toBe(`bytes 0-6/${APP_JS.length}`);
    expect(await textOf(res)).toBe(APP_JS.slice(0, 7));
  });

  test("an unsatisfiable range answers 416", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/assets/app.4f3a9c21.js", {
      token: "fg_a",
      headers: { range: `bytes=${APP_JS.length + 10}-` },
    });
    expect(res.status).toBe(416);
    expect(res.headers.get("content-range")).toBe(`bytes */${APP_JS.length}`);
  });

  test("HEAD answers the GET headers with no body — and is not a 405", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/", { token: "fg_a", method: "HEAD" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-length")).toBe(String(HOME.length));
    expect(res.headers.get("etag")).not.toBeNull();
    expect(await textOf(res)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// Caching
// ---------------------------------------------------------------------------

describe("cache-control is per response, not one constant", () => {
  test("a fingerprinted asset is immutable for a year", async () => {
    const { call } = await siteGateway({
      bindings: { docs: { tenantId: "tenant_a", anonymous: true } },
    });
    const res = await call("/sites/docs/assets/app.4f3a9c21.js");
    expect(res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
  });

  test("an HTML document behind a mutable channel always revalidates", async () => {
    const { call } = await siteGateway({
      bindings: { docs: { tenantId: "tenant_a", anonymous: true } },
    });
    const res = await call("/sites/docs/");
    expect(res.headers.get("cache-control")).toBe("public, max-age=0, must-revalidate");
  });

  test("a non-fingerprinted asset gets a short TTL, never immutable", async () => {
    const { call } = await siteGateway({
      bindings: { docs: { tenantId: "tenant_a", anonymous: true } },
    });
    const res = await call("/sites/docs/assets/app.css");
    expect(res.headers.get("cache-control")).toBe("public, max-age=60, must-revalidate");
  });

  test("a PRIVATE site is never marked public, whatever the file", async () => {
    const { call } = await siteGateway();
    const html = await call("/sites/docs/", { token: "fg_a" });
    const asset = await call("/sites/docs/assets/app.4f3a9c21.js", { token: "fg_a" });
    expect(html.headers.get("cache-control")).toBe("private, max-age=0, must-revalidate");
    expect(asset.headers.get("cache-control")).toBe("private, max-age=31536000, immutable");
    // A shared cache keyed on the URL must never store one tenant's document.
    expect(html.headers.get("vary")).toBe("authorization, x-api-key");
  });

  test("a fallback document is never stored against the URL it answered for", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/nope.html", { token: "fg_a" });
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });
});

// ---------------------------------------------------------------------------
// Paths that are refused
// ---------------------------------------------------------------------------

describe("hostile paths are refused rather than normalised", () => {
  test("encoded traversal, backslash and encoded separators are 400", async () => {
    const { call } = await siteGateway();
    for (const path of [
      // An encoded separator: refused BEFORE decoding, because decoding first
      // would make `a%2f..%2fb` a traversal the segment split never saw. This
      // is the one traversal shape the URL parser does NOT neutralise —
      // `%2e%2e` it collapses itself (see the case below), `%2f` it preserves.
      "/sites/docs/a%2f%2e%2e%2fb",
      "/sites/docs/%2fetc%2fpasswd",
      "/sites/docs/a%5cb",
      // A truncated escape decodes to nothing legal.
      "/sites/docs/a%2",
    ]) {
      const res = await call(path, { token: "fg_a" });
      expect(res.status, path).toBe(400);
      expect((await envelope(res)).error.code, path).toBe("site_path_invalid");
    }
  });

  test("a traversal segment never reaches the gateway AS one — and cannot escape", async () => {
    // `new Request("https://gw.test/sites/docs/../secret")` normalises to
    // `/sites/secret` in the URL parser, before any of our code runs — and so
    // does `%2e%2e`, which the WHATWG URL parser decodes before its own
    // dot-segment collapse. Asserted rather than assumed, because "the platform
    // already handles it" is exactly the belief that leaves a hole when the
    // platform stops doing it. `src/sites/paths.ts` refuses these itself, which
    // `./paths.test.ts` drives directly; here the property is only that no
    // spelling of a traversal serves a byte of `docs`.
    const { call } = await siteGateway();
    for (const path of [
      "/sites/docs/../secret",
      "/sites/docs/%2e%2e/index.html",
      "/sites/docs/a/%2e%2e/%2e%2e/b",
    ]) {
      const res = await call(path, { token: "fg_a" });
      expect([308, 400, 404], path).toContain(res.status);
      expect(await textOf(res), path).not.toContain("<h1>home</h1>");
    }
  });

  test("a percent-encoded space in a real filename still resolves", async () => {
    const { call } = await siteGateway({
      tar: buildTar([{ name: "a b.html", body: "<!doctype html>spaces" }]),
    });
    const res = await call("/sites/docs/a%20b.html", { token: "fg_a" });
    expect(res.status).toBe(200);
    expect(await textOf(res)).toContain("spaces");
  });
});
