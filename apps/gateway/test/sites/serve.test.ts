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
import { createGatewayApp } from "../../src/routes/index.js";
import { siteRouteModule } from "../../src/sites/index.js";
import { buildTar } from "../assets/archives.js";
import { CTX, callerFor, harness } from "../assets/helpers.js";

/**
 * Two tenants. `fg_a` owns `docs`; `fg_b` is the cross-tenant probe that must
 * never reach it.
 */
const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: ["assets.read"] },
    { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: ["assets.read"] },
    { key: "fg_a_noscope", id: "key_a_ns", tenant_id: "tenant_a", scopes: ["models.read"] },
  ]),
};

const SITE_TAR = () =>
  buildTar([
    { name: "index.html", body: "<!doctype html><h1>home</h1>" },
    { name: "docs/index.html", body: "<!doctype html><h1>docs</h1>" },
    { name: "assets/app.4f3a9c21.js", body: "console.log('app')" },
    { name: "assets/app.css", body: "body{color:red}" },
    { name: "404.html", body: "<!doctype html><h1>nope</h1>" },
  ]);

async function siteGateway(options: { env?: Record<string, string> } = {}) {
  const h = harness();
  await h.service.putAsset(
    callerFor("tenant_a"),
    { assetType: "static_site", name: "docs", version: "1.0.0" },
    { content: SITE_TAR(), contentType: "application/x-tar" },
    CTX,
  );
  const { app, router } = createGatewayApp({ modules: [siteRouteModule({ service: h.service })] });
  const call = (
    path: string,
    init: RequestInit & { token?: string | null } = {},
  ): Promise<Response> => {
    const { token = null, headers, ...rest } = init;
    const merged = new Headers(headers);
    if (token !== null) merged.set("authorization", `Bearer ${token}`);
    return Promise.resolve(
      app.request(`https://gw.test${path}`, { ...rest, headers: merged }, {
        ...ENV,
        ...(options.env ?? {}),
      } as Record<string, string>),
    );
  };
  return { ...h, app, router, call };
}

async function textOf(response: Response): Promise<string> {
  return new TextDecoder().decode(await response.arrayBuffer());
}

describe("#737: a published static_site is served at /sites/*", () => {
  test("GET /sites/{site}/ serves index.html to the owning tenant", async () => {
    const { call } = await siteGateway();
    const res = await call("/sites/docs/", { token: "fg_a" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/html");
    expect(await textOf(res)).toContain("<h1>home</h1>");
  });
});
