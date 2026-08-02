/**
 * `/sites/*` is metered, egress-quota'd and audited — including anonymously
 * (issue #737).
 *
 * The question the issue puts as a decision to record: *is the serve path
 * metered, and is it rate-limited?* An unmetered public serve mode on top of
 * tenant-billed R2 storage is a hole, and #736 makes it a sharper one: a
 * bundle's `size_bytes` counts the ARCHIVE the tenant uploaded ONCE, so nothing
 * in the storage number sees a site being served a million times.
 *
 * The answer, asserted here rather than asserted in prose:
 *
 *  - every site read spends the owner's `monthlyEgressBytesBudget` and is
 *    billed to the owner's meter, whether or not a credential was presented;
 *  - the ANONYMOUS read charges the same counter key as the authenticated one,
 *    so anonymous traffic cannot be used to obtain a second, fresh budget;
 *  - an exhausted budget refuses the site with 429 rather than serving it;
 *  - the pull-side audit row is written for the site read too.
 */
import { describe, expect, test } from "vitest";
import {
  InMemoryAssetEgressCounters,
  InMemoryAssetEgressMeter,
  assetEgressByteCounterKey,
} from "../../src/assets/egress.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { siteRouteModule } from "../../src/sites/index.js";
import type { SiteBinding } from "../../src/sites/registry.js";
import { buildTar } from "../assets/archives.js";
import { CTX, callerFor, harness } from "../assets/helpers.js";

const TENANT = "tenant_a";
const HOME = "<!doctype html><h1>metered</h1>";

const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_a", id: "key_a", tenant_id: TENANT, scopes: ["assets.read"] },
  ]),
};

const PUBLIC_BINDING: SiteBinding = {
  slug: "acme",
  tenantId: TENANT,
  assetName: "docs",
  channel: "latest",
  anonymous: true,
  spa: false,
  notFoundDocument: "404.html",
};

async function meteredGateway(options: { budget?: number; spent?: number } = {}) {
  const counters = new InMemoryAssetEgressCounters();
  const meter = new InMemoryAssetEgressMeter();
  const h = harness({ egress: { counters, meter } });
  await h.service.putAsset(
    callerFor(TENANT),
    { assetType: "static_site", name: "docs", version: "1.0.0" },
    { content: buildTar([{ name: "index.html", body: HOME }]), contentType: "application/x-tar" },
    CTX,
  );
  const { app } = createGatewayApp({
    modules: [
      siteRouteModule({
        service: h.service,
        bindings: new Map([["acme", PUBLIC_BINDING]]),
      }),
    ],
  });
  // The budget is expressed the way the deployment expresses it: a quota policy
  // on the OWNING tenant, read by the handler through the same policy source
  // the inference path uses.
  const env: Record<string, string> = {
    ...ENV,
    ...(options.budget === undefined
      ? {}
      : {
          GATEWAY_QUOTA_POLICIES: JSON.stringify([
            {
              id: "qp_tenant",
              scope_type: "tenant",
              scope_id: TENANT,
              monthly_egress_bytes_budget: options.budget,
              enabled: 1,
            },
          ]),
        }),
  };
  const call = (path: string, token?: string, method = "GET"): Promise<Response> => {
    const headers = new Headers();
    if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
    return Promise.resolve(app.request(`https://gw.test${path}`, { headers, method }, env));
  };
  return { ...h, counters, meter, call };
}

describe("a site read is metered against the owning tenant", () => {
  test("an ANONYMOUS read bills the owner, not nobody", async () => {
    const { call, meter } = await meteredGateway();
    const res = await call("/sites/acme/");
    expect(res.status).toBe(200);
    expect(meter.charges).toHaveLength(1);
    const charge = meter.charges[0];
    expect(charge?.tenantId).toBe(TENANT);
    expect(charge?.bytes).toBe(HOME.length);
  });

  test("an anonymous read and an authenticated one charge the SAME counter", async () => {
    const { call, counters } = await meteredGateway();
    // `egress:tenant:{id}` — the tenant scope. An anonymous reader has no key
    // scope to fall back to, so if this were keyed on the (empty) api key id
    // instead, anonymous traffic would accumulate in a counter of its own and
    // the tenant's budget would never see it.
    const key = assetEgressByteCounterKey({}, "", TENANT);
    expect(key).toBe(`egress:tenant:${TENANT}`);

    expect(counters.bytesUsed(key)).toBe(0);
    await call("/sites/acme/");
    expect(counters.bytesUsed(key)).toBe(HOME.length);
    await call("/sites/acme/", "fg_a");
    expect(counters.bytesUsed(key)).toBe(HOME.length * 2);
  });

  test("a HEAD bills nothing, because nothing was served", async () => {
    const { call, meter, counters } = await meteredGateway();
    const key = assetEgressByteCounterKey({}, "", TENANT);
    const res = await call("/sites/acme/", undefined, "HEAD");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-length")).toBe(String(HOME.length));
    expect(meter.charges).toHaveLength(0);
    expect(counters.bytesUsed(key)).toBe(0);
  });

  test("an exhausted egress budget refuses the SITE with 429", async () => {
    // One byte of budget against a document that is far larger: the gate is
    // fail-closed and charged the resolved object size before anything is read.
    const { call } = await meteredGateway({ budget: 1 });
    const res = await call("/sites/acme/");
    expect(res.status).toBe(429);
    const body = JSON.parse(new TextDecoder().decode(await res.arrayBuffer())) as {
      error: { code: string };
    };
    expect(body.error.code).toBe("asset_egress_quota_exceeded");
  });

  test("the pull-side audit row is written for a site read", async () => {
    const { call, audit } = await meteredGateway();
    await call("/sites/acme/");
    const pulls = audit.events.filter((event) => event.action === "asset.pull");
    expect(pulls).toHaveLength(1);
    expect(pulls[0]?.tenantId).toBe(TENANT);
    expect(pulls[0]?.target).toContain("static_site");
  });
});
