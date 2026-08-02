/**
 * Who may read a site (issue #737) — the half of this feature that is a
 * security boundary rather than a convenience.
 *
 * Four properties, each driven over real HTTP through the real app:
 *
 *  1. a site is PRIVATE by default: no credential, no bytes;
 *  2. the credential must carry `assets.read`, and the ladder that decides it
 *     is the contract middleware's own (`authenticateBearer`), not a copy;
 *  3. **the tenant fence** — one tenant's credential can never read another
 *     tenant's site, and the fence is proved by MUTATION below;
 *  4. anonymous serving happens ONLY where an operator bound the slug and set
 *     `anonymous`, per site and per channel.
 */
import { describe, expect, test } from "vitest";
import { createGatewayApp } from "../../src/routes/index.js";
import { siteRouteModule } from "../../src/sites/index.js";
import {
  type SiteBinding,
  siteAccessFor,
  siteBindingsFromEnv,
  siteTenantForCredential,
} from "../../src/sites/registry.js";
import { buildTar } from "../assets/archives.js";
import { CTX, callerFor, harness } from "../assets/helpers.js";

const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: ["assets.read"] },
    { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: ["assets.read"] },
    { key: "fg_a_noscope", id: "key_a_ns", tenant_id: "tenant_a", scopes: ["models.read"] },
  ]),
};

const A_HOME = "<!doctype html><h1>tenant a</h1>";
const B_HOME = "<!doctype html><h1>tenant b</h1>";

function binding(
  slug: string,
  overrides: Partial<SiteBinding> & { tenantId: string },
): SiteBinding {
  return {
    slug,
    // The fixture below publishes `static_site/docs` inside BOTH tenants, so a
    // bound slug points at that asset under a different public name — which is
    // also the more honest fixture: the slug and the asset name are not the
    // same namespace and a binding is what joins them.
    assetName: "docs",
    channel: "latest",
    anonymous: false,
    spa: false,
    notFoundDocument: "404.html",
    ...overrides,
  };
}

/**
 * Two tenants, each with a `static_site` — and, when asked, a slug bound to
 * one of them. Both sites are named `docs` inside their own tenant, which is
 * the collision a global `/sites/{slug}` namespace has to answer for.
 */
async function twoTenantGateway(bindings?: ReadonlyMap<string, SiteBinding>) {
  const h = harness();
  const publish = (tenant: string, body: string) =>
    h.service.putAsset(
      callerFor(tenant),
      { assetType: "static_site", name: "docs", version: "1.0.0" },
      { content: buildTar([{ name: "index.html", body }]), contentType: "application/x-tar" },
      CTX,
    );
  await publish("tenant_a", A_HOME);
  await publish("tenant_b", B_HOME);
  const { app } = createGatewayApp({
    modules: [
      siteRouteModule({ service: h.service, ...(bindings === undefined ? {} : { bindings }) }),
    ],
  });
  const call = (path: string, token?: string): Promise<Response> => {
    const headers = new Headers();
    if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
    return Promise.resolve(app.request(`https://gw.test${path}`, { headers }, ENV));
  };
  return { ...h, call };
}

async function textOf(response: Response): Promise<string> {
  return new TextDecoder().decode(await response.arrayBuffer());
}

async function errorOf(response: Response): Promise<{ code: string; message: string }> {
  return (JSON.parse(await textOf(response)) as { error: { code: string; message: string } }).error;
}

describe("a site is private by default", () => {
  test("no credential is 401, not a served site", async () => {
    const { call } = await twoTenantGateway();
    const res = await call("/sites/docs/");
    expect(res.status).toBe(401);
    expect((await errorOf(res)).code).toBe("missing_api_key");
  });

  test("a bad credential is 401 — the ladder resolves the key, it does not trust it", async () => {
    const { call } = await twoTenantGateway();
    const res = await call("/sites/docs/", "fg_not_a_key");
    expect(res.status).toBe(401);
    expect((await errorOf(res)).code).toBe("invalid_api_key");
  });

  test("a credential without assets.read is 403 scope_denied", async () => {
    const { call } = await twoTenantGateway();
    const res = await call("/sites/docs/", "fg_a_noscope");
    expect(res.status).toBe(403);
    const error = await errorOf(res);
    expect(error.code).toBe("scope_denied");
    // The message is the middleware's own, which is the point: this refusal
    // came from `authenticateBearer` and not from a second implementation.
    expect(error.message).toContain("assets.read");
  });
});

describe("the tenant fence", () => {
  test("each tenant's credential reads its OWN site at the same URL", async () => {
    const { call } = await twoTenantGateway();
    expect(await textOf(await call("/sites/docs/", "fg_a"))).toBe(A_HOME);
    expect(await textOf(await call("/sites/docs/", "fg_b"))).toBe(B_HOME);
  });

  test("a bound private site refuses every OTHER tenant, indistinguishably", async () => {
    const bindings = new Map([["acme", binding("acme", { tenantId: "tenant_a" })]]);
    const { call } = await twoTenantGateway(bindings);
    const mine = await call("/sites/acme/", "fg_a");
    expect(mine.status).toBe(200);
    expect(await textOf(mine)).toBe(A_HOME);

    const theirs = await call("/sites/acme/", "fg_b");
    expect(theirs.status).toBe(404);
    const error = await errorOf(theirs);
    expect(error.code).toBe("site_not_found");
    // Byte for byte what an unknown slug answers — no "forbidden", which would
    // itself confirm the site exists.
    const unknown = await errorOf(await call("/sites/nosuch/", "fg_b"));
    expect(error.code).toBe(unknown.code);
    expect(error.message).toBe("no site is served at /sites/acme");
    expect(unknown.message).toBe("no site is served at /sites/nosuch");
  });

  /**
   * The fence as a PURE decision, so the mutation proof has a single line to
   * attack. `siteTenantForCredential` is what says "this credential may read
   * this site, as this tenant"; every wire case above is that function plus
   * HTTP.
   */
  test("siteTenantForCredential is the whole fence, and it is total", () => {
    const bound = binding("acme", { tenantId: "tenant_a" });
    expect(siteTenantForCredential(bound, "tenant_a")).toBe("tenant_a");
    expect(siteTenantForCredential(bound, "tenant_b")).toBeNull();
    expect(siteTenantForCredential(bound, "")).toBeNull();
    // Unbound: the caller's own tenant, and a credential with no tenancy at all
    // resolves to nothing rather than to the empty tenant (which would match no
    // row today, but would silently become a shared namespace the day it did).
    expect(siteTenantForCredential(null, "tenant_b")).toBe("tenant_b");
    expect(siteTenantForCredential(null, "")).toBeNull();
    // A PUBLIC site is the owner's for everyone — that is what public means,
    // and it is also who is billed for the egress.
    const open = binding("acme", { tenantId: "tenant_a", anonymous: true });
    expect(siteTenantForCredential(open, "tenant_b")).toBe("tenant_a");
  });
});

describe("anonymous serving is an opt-in, per site and per channel", () => {
  test("a bound site without the opt-in still refuses an anonymous reader", async () => {
    const bindings = new Map([["acme", binding("acme", { tenantId: "tenant_a" })]]);
    const { call } = await twoTenantGateway(bindings);
    const res = await call("/sites/acme/");
    expect(res.status).toBe(401);
  });

  test("with the opt-in the same URL serves with no credential at all", async () => {
    const bindings = new Map([
      ["acme", binding("acme", { tenantId: "tenant_a", anonymous: true })],
    ]);
    const { call } = await twoTenantGateway(bindings);
    const res = await call("/sites/acme/");
    expect(res.status).toBe(200);
    expect(await textOf(res)).toBe(A_HOME);
    // Public content, so a shared cache may hold it — the distinction the
    // private case above must never lose.
    expect(res.headers.get("cache-control")).toContain("public");
  });

  test("the opt-in names ONE channel, so another channel is not exposed by it", async () => {
    // `staging` is public; `latest` is not reachable at that slug at all.
    const bindings = new Map([
      ["acme", binding("acme", { tenantId: "tenant_a", anonymous: true, channel: "staging" })],
    ]);
    const { call, service } = await twoTenantGateway(bindings);
    // No `staging` channel exists yet, so the public slug resolves nothing...
    const before = await call("/sites/acme/");
    expect(before.status).toBe(404);
    // ...and once the tenant points `staging` somewhere, that is what it serves.
    await service.putChannel(
      callerFor("tenant_a"),
      { assetType: "static_site", name: "docs" },
      "staging",
      "1.0.0",
      CTX,
    );
    const after = await call("/sites/acme/");
    expect(after.status).toBe(200);
    expect(after.headers.get("x-ferrogate-asset-resolved")).toBe("channel=staging;version=1.0.0");
  });

  test("a presented credential is ALWAYS authenticated, even for a public site", async () => {
    // Silently ignoring a token because the site happens to be public would
    // serve a caller whose key is revoked as though it were fine.
    const bindings = new Map([
      ["acme", binding("acme", { tenantId: "tenant_a", anonymous: true })],
    ]);
    const { call } = await twoTenantGateway(bindings);
    expect((await call("/sites/acme/", "fg_not_a_key")).status).toBe(401);
    expect((await call("/sites/acme/", "fg_b")).status).toBe(200);
  });

  test("siteAccessFor: only a bound, anonymous slug with no credential skips auth", () => {
    const open = binding("acme", { tenantId: "tenant_a", anonymous: true });
    const shut = binding("acme", { tenantId: "tenant_a" });
    expect(siteAccessFor(open, false).kind).toBe("anonymous");
    expect(siteAccessFor(open, true).kind).toBe("authenticate");
    expect(siteAccessFor(shut, false).kind).toBe("authenticate");
    expect(siteAccessFor(undefined, false).kind).toBe("authenticate");
  });
});

describe("GATEWAY_SITES parses fail-closed", () => {
  test("a full entry becomes a binding", () => {
    const bindings = siteBindingsFromEnv({
      GATEWAY_SITES: JSON.stringify({
        acme: {
          tenant_id: "tenant_a",
          asset_name: "marketing",
          channel: "stable",
          anonymous: true,
          spa: true,
          not_found_document: "missing.html",
        },
      }),
    });
    expect(bindings.get("acme")).toEqual({
      slug: "acme",
      tenantId: "tenant_a",
      assetName: "marketing",
      channel: "stable",
      anonymous: true,
      spa: true,
      notFoundDocument: "missing.html",
    });
  });

  test("defaults are private, `latest`, no SPA, `404.html`", () => {
    const bindings = siteBindingsFromEnv({
      GATEWAY_SITES: JSON.stringify({ acme: { tenant_id: "tenant_a" } }),
    });
    expect(bindings.get("acme")).toEqual({
      slug: "acme",
      tenantId: "tenant_a",
      assetName: "acme",
      channel: "latest",
      anonymous: false,
      spa: false,
      notFoundDocument: "404.html",
    });
  });

  test("malformed input binds NOTHING — never `everything is public`", () => {
    for (const raw of ["", "   ", "not json", "[]", '"acme"', "null"]) {
      expect(siteBindingsFromEnv({ GATEWAY_SITES: raw }).size, raw).toBe(0);
    }
    expect(siteBindingsFromEnv({}).size).toBe(0);
    // An entry with no tenant binds nothing: it could only resolve to the empty
    // tenant id, and `anonymous: true` on it would be a public site belonging
    // to nobody.
    expect(
      siteBindingsFromEnv({ GATEWAY_SITES: JSON.stringify({ acme: { anonymous: true } }) }).size,
    ).toBe(0);
    // Truthiness is not enough for the two flags that open a site up.
    const coerced = siteBindingsFromEnv({
      GATEWAY_SITES: JSON.stringify({ acme: { tenant_id: "t", anonymous: "yes", spa: 1 } }),
    }).get("acme");
    expect(coerced?.anonymous).toBe(false);
    expect(coerced?.spa).toBe(false);
  });
});
