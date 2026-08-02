/**
 * Verified custom domains (issue #738) — the half of #737 that is a DNS
 * ownership boundary rather than a URL boundary.
 *
 * Everything here is driven over real HTTP through the real app, against real
 * `site_domains` / `site_domain_verifications` rows in the real `CONTROL_DB`
 * (the `cloudflare:test` D1 binding, migrated by `test/setup-d1.ts` from
 * `sql/d1-ts/control/0001_init_control.sql`). The bundle is a real tar
 * published through `AssetService.putAsset`, i.e. through #736's expander, so
 * what these cases read back is the same `asset_bundle_files` index a
 * production publish writes.
 *
 * The four properties, in the order the issue states them:
 *
 *  1. a hostname with a LIVE proof serves its tenant's bundle at `/`, through
 *     the same serve path and the same resolution as `/sites/{slug}/`;
 *  2. an UNPROVEN, EXPIRED or UNBOUND hostname is refused — never silently
 *     routed as if it had arrived on the API host;
 *  3. **a hostname can never resolve to another tenant's bundle**, proved from
 *     both directions and mutation-pinned;
 *  4. nothing about the #737 access model is bypassed: private is still the
 *     default, anonymous is still an operator opt-in, and a yanked bundle is
 *     still unservable.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { createGatewayApp } from "../../src/routes/index.js";
import {
  SITE_DOMAIN_ROUTE_SQL,
  decideSiteDomain,
  normalizeSiteHostname,
  siteDomainBinding,
} from "../../src/sites/domains.js";
import { siteDomainRouting } from "../../src/sites/host.js";
import { siteRouteModule } from "../../src/sites/index.js";
import { planSiteDomainPath } from "../../src/sites/paths.js";
import type { SiteBinding } from "../../src/sites/registry.js";
import { buildTar } from "../assets/archives.js";
import { CTX, callerFor, harness } from "../assets/helpers.js";

const CONTROL_DB = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;

/** A fixed "now" for the middleware, so verification expiry is deterministic. */
const NOW = 1_800_000_000;
const DAY = 86_400;

const KEYS = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: ["assets.read"] },
    { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: ["assets.read"] },
  ]),
};

const A_HOME = "<!doctype html><h1>tenant a</h1>";
const B_HOME = "<!doctype html><h1>tenant b</h1>";
const A_DOCS = "<!doctype html><h1>tenant a docs</h1>";

function siteTar(home: string): Uint8Array {
  return buildTar([
    { name: "index.html", body: home },
    { name: "docs/index.html", body: A_DOCS },
    { name: "assets/app.4f3a9c21.js", body: "console.log(1)" },
    { name: "404.html", body: "<!doctype html><h1>nope</h1>" },
  ]);
}

// ---------------------------------------------------------------------------
// Control-database fixtures — the REAL tables, not a document store
// ---------------------------------------------------------------------------

async function clearDomains(): Promise<void> {
  await CONTROL_DB.prepare("DELETE FROM site_domains").run();
  await CONTROL_DB.prepare("DELETE FROM site_domain_verifications").run();
}

/** `site_domains` — the tenant's INTENT to serve `site` on `hostname`. */
async function bindDomain(hostname: string, tenantId: string, site: string): Promise<void> {
  await CONTROL_DB.prepare(
    "INSERT OR REPLACE INTO site_domains (hostname, tenant_id, site, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(hostname, tenantId, site, NOW, NOW)
    .run();
}

interface ProofOptions {
  readonly state?: string;
  /** Absolute deadline of a completed verification. Default `NOW + 90 days`. */
  readonly verificationExpiresAtUnix?: number | null;
  /** Challenge-token deadline. Default `NOW + 7 days`. */
  readonly tokenExpiresAtUnix?: number;
}

/** `site_domain_verifications` — the EVIDENCE, keyed `(tenant_id, hostname)`. */
async function proveDomain(
  hostname: string,
  tenantId: string,
  site: string,
  options: ProofOptions = {},
): Promise<void> {
  const state = options.state ?? "verified";
  await CONTROL_DB.prepare(
    "INSERT OR REPLACE INTO site_domain_verifications (tenant_id, hostname, site, state, challenge_token, issued_at_unix, token_expires_at_unix, verified_at_unix, verification_expires_at_unix, last_checked_at_unix, last_failure_reason, attempt_count, updated_at_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      tenantId,
      hostname,
      site,
      state,
      "token-not-readable-from-the-serve-path",
      NOW - DAY,
      options.tokenExpiresAtUnix ?? NOW + 7 * DAY,
      state === "verified" ? NOW - DAY : null,
      options.verificationExpiresAtUnix === null
        ? null
        : (options.verificationExpiresAtUnix ?? NOW + 90 * DAY),
      NOW - DAY,
      null,
      1,
      NOW - DAY,
    )
    .run();
}

// ---------------------------------------------------------------------------
// The app under test — assembled exactly as `src/index.ts` assembles it
// ---------------------------------------------------------------------------

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

interface GatewayOptions {
  readonly bindings?: Record<string, Partial<SiteBinding> & { tenantId: string }>;
  /** Seconds since the epoch the DOMAIN gate reads. Default {@link NOW}. */
  readonly now?: number;
}

/**
 * Two tenants, each publishing a `static_site` called `docs` under the `latest`
 * channel — the collision a hostname namespace has to answer for.
 */
async function twoTenantGateway(options: GatewayOptions = {}) {
  const h = harness();
  await h.service.putAsset(
    callerFor("tenant_a"),
    { assetType: "static_site", name: "docs", version: "1.0.0" },
    { content: siteTar(A_HOME), contentType: "application/x-tar" },
    CTX,
  );
  await h.service.putAsset(
    callerFor("tenant_b"),
    { assetType: "static_site", name: "docs", version: "1.0.0" },
    { content: siteTar(B_HOME), contentType: "application/x-tar" },
    CTX,
  );
  const bindings = bindingMap(options.bindings);
  const shared = { service: h.service, ...(bindings === undefined ? {} : { bindings }) };
  const { app } = createGatewayApp({
    modules: [siteRouteModule(shared)],
    siteDomains: siteDomainRouting({ ...shared, now: () => options.now ?? NOW }),
  });
  const call = (url: string, token?: string): Promise<Response> => {
    const headers = new Headers();
    if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
    return Promise.resolve(app.request(url, { headers }, { ...KEYS, CONTROL_DB }));
  };
  return { ...h, call };
}

async function textOf(response: Response): Promise<string> {
  return new TextDecoder().decode(await response.arrayBuffer());
}

async function errorOf(response: Response): Promise<{ code: string; message: string }> {
  return (JSON.parse(await textOf(response)) as { error: { code: string; message: string } }).error;
}

beforeEach(async () => {
  await clearDomains();
});

// ---------------------------------------------------------------------------

describe("a verified hostname serves the bundle it is bound to", () => {
  test("the site is served at `/` on the custom domain", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });

    const res = await call("https://docs.acme.test/");
    expect(res.status).toBe(200);
    expect(await textOf(res)).toBe(A_HOME);
    // `x-ferrogate-site-path` is the serve path's own header: this response came
    // out of `SiteServer.serve`, not out of some hostname shortcut.
    expect(res.headers.get("x-ferrogate-site-path")).toBe("index.html");
  });

  test("it resolves through the CHANNEL, identically to the slug route", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });

    const viaHost = await call("https://docs.acme.test/");
    const viaSlug = await call("https://gw.test/sites/acme/");
    expect(viaHost.status).toBe(200);
    expect(viaSlug.status).toBe(200);
    // Same resolved version, same strong validator, same bytes — because it is
    // the same `#resolveArtifact` call.
    expect(viaHost.headers.get("x-ferrogate-asset-version")).toBe("1.0.0");
    expect(viaHost.headers.get("x-ferrogate-asset-resolved")).toBe(
      viaSlug.headers.get("x-ferrogate-asset-resolved"),
    );
    expect(viaHost.headers.get("etag")).toBe(viaSlug.headers.get("etag"));
  });

  test("a nested path and its canonical redirect stay on the custom domain", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });

    const redirect = await call("https://docs.acme.test/docs");
    expect(redirect.status).toBe(308);
    // Authority-relative, and with NO `/sites/acme` prefix: the reader asked
    // for a hostname and must never be sent to the internal slug spelling.
    expect(redirect.headers.get("location")).toBe("/docs/");

    const served = await call("https://docs.acme.test/docs/");
    expect(served.status).toBe(200);
    expect(await textOf(served)).toBe(A_DOCS);
  });

  test("a YANKED version is unservable on the custom domain too", async () => {
    // The point of routing through a CHANNEL rather than a hostname-keyed
    // lookup: yank removes the version from `#resolveArtifact`, so it is gone
    // from both entry points at once.
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call, service } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });
    expect((await call("https://docs.acme.test/")).status).toBe(200);

    await service.setVersionYank(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs", version: "1.0.0" },
      true,
      CTX,
    );

    const after = await call("https://docs.acme.test/");
    expect(after.status).toBe(404);
    expect((await errorOf(after)).code).toBe("site_not_found");
    expect((await call("https://gw.test/sites/acme/")).status).toBe(404);
  });
});

describe("an unproven, expired or unbound hostname is REFUSED, never fallen back", () => {
  test("a bound hostname with no verification row at all", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });

    const res = await call("https://docs.acme.test/");
    expect(res.status).toBe(421);
    expect((await errorOf(res)).code).toBe("site_domain_not_active");
  });

  test("a challenge that was issued but never redeemed", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme", { state: "pending_verification" });
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });
    expect((await call("https://docs.acme.test/")).status).toBe(421);
  });

  test("a verification past its 90-day deadline stops serving with NO sweeper", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme", {
      verificationExpiresAtUnix: NOW + 10,
    });
    const bindings = { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } };

    const live = await twoTenantGateway({ bindings });
    expect((await live.call("https://docs.acme.test/")).status).toBe(200);

    // Same rows, one second past the deadline. Nothing wrote anything.
    const lapsed = await twoTenantGateway({ bindings, now: NOW + 11 });
    expect((await lapsed.call("https://docs.acme.test/")).status).toBe(421);
  });

  test("the refusal covers the WHOLE authority, including the gateway's own paths", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });
    // If `/healthz` still answered here, the refusal would not be about the
    // authority — it would be about one path, and the gateway would be
    // advertising itself on a hostname it refuses to serve.
    expect((await call("https://docs.acme.test/healthz")).status).toBe(421);
    expect((await call("https://docs.acme.test/v1/models")).status).toBe(421);
  });

  test("REVOKING the binding stops serving; the site does not reappear at /", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const bindings = { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } };
    const before = await twoTenantGateway({ bindings });
    expect((await before.call("https://docs.acme.test/")).status).toBe(200);

    await CONTROL_DB.prepare("DELETE FROM site_domains WHERE hostname = ?")
      .bind("docs.acme.test")
      .run();

    // A fresh isolate-equivalent (new directory ⇒ new cache), i.e. what every
    // isolate sees once its `SITE_DOMAIN_CACHE_TTL_SECONDS` window has turned
    // over. The hostname is no longer a site domain, so the request routes as
    // any other unknown authority does — and `/` is not a route, so it is a
    // plain `404 not_found` from the router and NOT the tenant's bundle.
    const after = await twoTenantGateway({ bindings });
    const res = await after.call("https://docs.acme.test/");
    expect(res.status).toBe(404);
    expect((await errorOf(res)).code).toBe("not_found");
  });

  test("an unclaimed authority is untouched — the API keeps working", async () => {
    const { call } = await twoTenantGateway();
    expect((await call("https://gw.test/healthz")).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// THE FENCE
// ---------------------------------------------------------------------------

describe("a hostname can never resolve to another tenant's bundle", () => {
  test("tenant A cannot serve on a host only tenant B ever proved", async () => {
    // The fixture the whole join predicate exists for. `site_domains` is keyed
    // on hostname alone, so tenant A holds the binding; `site_domain_verifications`
    // is keyed `(tenant_id, hostname)`, so tenant B's completed proof sits
    // beside it. A has proved NOTHING.
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_b", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });

    const res = await call("https://docs.acme.test/");
    expect(res.status).toBe(421);
    const body = await textOf(res);
    expect(body).not.toContain("tenant a");
    expect(JSON.parse(body).error.code).toBe("site_domain_not_active");
  });

  test("the join predicate that makes that true is in the SQL actually run", () => {
    // A behavioural assertion alone would still pass against a read that joined
    // on hostname and then filtered in TypeScript, which is a different (and
    // scan-shaped) statement. The predicate is pinned where it lives.
    expect(SITE_DOMAIN_ROUTE_SQL).toContain("v.tenant_id = d.tenant_id");
  });

  test("a proven hostname whose slug the operator bound to ANOTHER tenant refuses", async () => {
    // The second direction: the DNS proof is tenant A's, but `GATEWAY_SITES`
    // says the slug `acme` is tenant B's site. Serving either one would put a
    // tenant's bytes on an authority the other owns.
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_b", assetName: "docs", anonymous: true } },
    });

    const res = await call("https://docs.acme.test/");
    expect(res.status).toBe(404);
    const body = await textOf(res);
    expect(body).not.toContain("tenant b");
    expect(JSON.parse(body).error.code).toBe("site_not_found");
  });

  test("an UNBOUND slug is pinned to the domain's tenant, not the caller's", async () => {
    // Without the synthesized binding, #737's rule for an unbound slug is "the
    // caller's own tenant" — so tenant B's credential would read tenant B's
    // `docs` bundle on tenant A's verified hostname.
    await bindDomain("docs.acme.test", "tenant_a", "docs");
    await proveDomain("docs.acme.test", "tenant_a", "docs");
    const { call } = await twoTenantGateway();

    const theirs = await call("https://docs.acme.test/", "fg_b");
    expect(theirs.status).toBe(404);
    expect((await errorOf(theirs)).code).toBe("site_not_found");

    // ...and the owner reads its own, on the same URL with its own credential.
    const mine = await call("https://docs.acme.test/", "fg_a");
    expect(mine.status).toBe(200);
    expect(await textOf(mine)).toBe(A_HOME);
  });

  test("siteDomainBinding is the whole fence, and it is total", () => {
    const route = { hostname: "docs.acme.test", tenantId: "tenant_a", slug: "acme" };
    const owned: SiteBinding = {
      slug: "acme",
      tenantId: "tenant_a",
      assetName: "docs",
      channel: "stable",
      anonymous: true,
      spa: false,
      notFoundDocument: "404.html",
    };
    expect(siteDomainBinding(route, new Map([["acme", owned]]))).toEqual({
      kind: "bound",
      binding: owned,
    });
    expect(
      siteDomainBinding(route, new Map([["acme", { ...owned, tenantId: "tenant_b" }]])),
    ).toEqual({ kind: "tenant_mismatch", boundTenantId: "tenant_b" });

    // No operator entry ⇒ a PRIVATE binding pinned to the domain's own tenant.
    const synthesized = siteDomainBinding(route, new Map());
    expect(synthesized.kind).toBe("bound");
    expect(synthesized.kind === "bound" && synthesized.binding).toEqual({
      slug: "acme",
      tenantId: "tenant_a",
      assetName: "acme",
      channel: "latest",
      anonymous: false,
      spa: false,
      notFoundDocument: "404.html",
    });
  });
});

// ---------------------------------------------------------------------------
// The #737 access model is not bypassed
// ---------------------------------------------------------------------------

describe("a custom domain does not widen access", () => {
  test("without the operator's anonymous opt-in the domain still demands a credential", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs" } },
    });

    const anonymous = await call("https://docs.acme.test/");
    expect(anonymous.status).toBe(401);
    expect((await errorOf(anonymous)).code).toBe("missing_api_key");

    const owner = await call("https://docs.acme.test/", "fg_a");
    expect(owner.status).toBe(200);
  });

  test("the opt-in names ONE channel, and the domain inherits exactly that", async () => {
    await bindDomain("docs.acme.test", "tenant_a", "acme");
    await proveDomain("docs.acme.test", "tenant_a", "acme");
    const { call, service } = await twoTenantGateway({
      bindings: {
        acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true, channel: "staging" },
      },
    });
    // Nothing is on `staging` yet, so the verified domain resolves nothing.
    expect((await call("https://docs.acme.test/")).status).toBe(404);

    await service.putChannel(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs" },
      "staging",
      "1.0.0",
      CTX,
    );
    const after = await call("https://docs.acme.test/");
    expect(after.status).toBe(200);
    expect(after.headers.get("x-ferrogate-asset-resolved")).toBe("channel=staging;version=1.0.0");
  });

  test("a public site's bytes stay cacheable; a private one's stay private", async () => {
    await bindDomain("open.acme.test", "tenant_a", "acme");
    await proveDomain("open.acme.test", "tenant_a", "acme");
    const { call } = await twoTenantGateway({
      bindings: { acme: { tenantId: "tenant_a", assetName: "docs", anonymous: true } },
    });
    const res = await call("https://open.acme.test/");
    expect(res.headers.get("cache-control")).toContain("public");
    expect(res.headers.get("vary")).toContain("authorization");
  });
});

// ---------------------------------------------------------------------------
// Pure units
// ---------------------------------------------------------------------------

describe("decideSiteDomain", () => {
  const record = (
    verification: {
      state: "pending_verification" | "verified" | "grandfathered" | "expired";
      tokenExpiresAtUnix: number;
      verificationExpiresAtUnix: number | undefined;
    } | null,
    site = "acme",
  ) => ({ hostname: "docs.acme.test", tenantId: "tenant_a", site, verification });

  test("no row is `unbound`; a row with no proof is `inactive`", () => {
    expect(decideSiteDomain(null, NOW).kind).toBe("unbound");
    expect(decideSiteDomain(record(null), NOW)).toEqual({
      kind: "inactive",
      hostname: "docs.acme.test",
      reason: "unproven",
    });
  });

  test("only `verified` and `grandfathered` serve, and only before they lapse", () => {
    const live = { tokenExpiresAtUnix: NOW + DAY, verificationExpiresAtUnix: NOW + DAY };
    expect(decideSiteDomain(record({ state: "verified", ...live }), NOW).kind).toBe("route");
    expect(decideSiteDomain(record({ state: "grandfathered", ...live }), NOW).kind).toBe("route");
    expect(decideSiteDomain(record({ state: "pending_verification", ...live }), NOW).kind).toBe(
      "inactive",
    );
    expect(decideSiteDomain(record({ state: "expired", ...live }), NOW).kind).toBe("inactive");
    // Expiry is applied at READ time, from `nowUnix`, with no sweeper.
    expect(decideSiteDomain(record({ state: "verified", ...live }), NOW + DAY)).toEqual({
      kind: "inactive",
      hostname: "docs.acme.test",
      reason: "expired",
    });
    // An unredeemed challenge past its own TTL, likewise.
    expect(
      decideSiteDomain(
        record({
          state: "pending_verification",
          tokenExpiresAtUnix: NOW - 1,
          verificationExpiresAtUnix: undefined,
        }),
        NOW,
      ).kind,
    ).toBe("inactive");
  });

  test("a proven hostname bound to NO site is refused, never routed to the empty slug", () => {
    const proven = {
      state: "verified" as const,
      tokenExpiresAtUnix: NOW + DAY,
      verificationExpiresAtUnix: NOW + DAY,
    };
    expect(decideSiteDomain(record(proven, "   "), NOW).kind).toBe("inactive");
  });
});

describe("normalizeSiteHostname", () => {
  test("case, port and the root dot are not part of the key", () => {
    expect(normalizeSiteHostname("Docs.ACME.test")).toBe("docs.acme.test");
    expect(normalizeSiteHostname("docs.acme.test:8443")).toBe("docs.acme.test");
    expect(normalizeSiteHostname("docs.acme.test.")).toBe("docs.acme.test");
    expect(normalizeSiteHostname("  DOCS.acme.TEST.:443 ")).toBe("docs.acme.test");
    // A legal label keeps its hyphens — the allowlist must not eat them.
    expect(normalizeSiteHostname("my-docs.acme-corp.test")).toBe("my-docs.acme-corp.test");
  });

  test("anything that is not a DNS name matches nothing", () => {
    for (const raw of ["", "   ", "docs.acme.test/../evil", "a b.test", "evil@docs.test", null]) {
      expect(normalizeSiteHostname(raw), String(raw)).toBe("");
    }
    // An IPv6 literal keeps its brackets, so it can never alias a DNS name.
    expect(normalizeSiteHostname("[::1]:8787")).toBe("");
  });
});

describe("planSiteDomainPath", () => {
  test("the root is the index document, with no `/sites/` prefix anywhere", () => {
    expect(planSiteDomainPath("acme", "/")).toEqual({
      kind: "resolve",
      slug: "acme",
      file: "index.html",
      directoryProbe: null,
      directory: true,
    });
  });

  test("the same canonicalisation as the slug route, authority-relative", () => {
    expect(planSiteDomainPath("acme", "/index.html")).toEqual({
      kind: "redirect",
      location: "/",
    });
    expect(planSiteDomainPath("acme", "/docs/index.html", "?v=2")).toEqual({
      kind: "redirect",
      location: "/docs/?v=2",
    });
    const nested = planSiteDomainPath("acme", "/docs");
    expect(nested.kind === "resolve" && nested.directoryProbe).toEqual({
      file: "docs/index.html",
      location: "/docs/",
    });
  });

  test("traversal and encoded separators are refused here too", () => {
    expect(planSiteDomainPath("acme", "/../secrets").kind).toBe("invalid");
    expect(planSiteDomainPath("acme", "/a%2f..%2fb").kind).toBe("invalid");
    expect(planSiteDomainPath("acme", "/a//b").kind).toBe("invalid");
  });
});
