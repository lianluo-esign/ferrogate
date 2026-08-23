/**
 * `static_resource` per-request billing (STATIC_RESOURCES_DESIGN.md §5.3).
 *
 * A pull of the `static_resource` asset type is charged a FLAT price per served
 * gateway GET (design Q-A) and is deliberately kept OUT of the per-GB egress
 * path (Q-E). This suite pins that split at the service seam:
 *
 *  - a `static_resource` pull settles ONE per-request charge and ZERO egress
 *    charges;
 *  - every OTHER asset type still settles through egress, untouched;
 *  - a `HEAD`/`304` that puts no bytes on the wire bills nothing (Q-A).
 */
import { describe, expect, it } from "vitest";
import {
  InMemoryAssetEgressCounters,
  InMemoryAssetEgressMeter,
} from "../../src/assets/egress.js";
import {
  InMemoryStaticResourceMeter,
  STATIC_RESOURCE_PROVIDER,
} from "@ferrogate/billing";
import { CTX, bytes, callerFor, harness } from "./helpers.js";

const TENANT = "tenant-sr";
const KEY = "key_sr";

function callers() {
  return callerFor(TENANT, { apiKeyId: KEY } as never);
}

/** Publish a visible asset of the given type/name and return the harness + meters. */
async function published(
  assetType: string,
  name: string,
  size: number,
  contentType: string,
) {
  const egressMeter = new InMemoryAssetEgressMeter();
  const staticMeter = new InMemoryStaticResourceMeter();
  const h = harness({
    egress: { counters: new InMemoryAssetEgressCounters(), meter: egressMeter, pricePerGb: 0.09 },
    staticResource: { meter: staticMeter, pricePerRequest: 0.001 },
  });
  const put = await h.service.putAsset(
    callerFor(TENANT),
    { assetType, name, version: "1.0.0" },
    { contentType, content: bytes("x".repeat(size)) },
    CTX,
  );
  expect(put.ok).toBe(true);
  return { h, egressMeter, staticMeter };
}

describe("static_resource per-request billing at the service seam", () => {
  it("bills a static_resource pull per-request and NOT through egress", async () => {
    const { h, egressMeter, staticMeter } = await published(
      STATIC_RESOURCE_PROVIDER,
      "docs/guide.md",
      256,
      "text/markdown",
    );

    const result = await h.service.pullAsset(
      callers(),
      { assetType: STATIC_RESOURCE_PROVIDER, name: "docs/guide.md", reference: "1.0.0" },
      { headers: new Headers() },
      CTX,
    );

    expect(result.ok).toBe(true);
    expect(egressMeter.charges).toHaveLength(0);
    expect(staticMeter.charges).toHaveLength(1);
    const charge = staticMeter.charges[0];
    expect(charge?.provider).toBe(STATIC_RESOURCE_PROVIDER);
    expect(charge?.requests).toBe(1);
    expect(charge?.costUsd).toBeCloseTo(0.001, 12);
    expect(charge?.name).toBe("docs/guide.md");
    // The PULL-side audit event is still written.
    expect(h.audit.events.some((event) => event.action === "asset.pull")).toBe(true);
  });

  it("leaves every OTHER asset type on the per-GB egress path", async () => {
    const { h, egressMeter, staticMeter } = await published(
      "cli_tool",
      "installer",
      4_096,
      "application/octet-stream",
    );

    const result = await h.service.pullAsset(
      callers(),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      CTX,
    );

    expect(result.ok).toBe(true);
    expect(staticMeter.charges).toHaveLength(0);
    expect(egressMeter.charges).toHaveLength(1);
    expect(egressMeter.charges[0]?.assetType).toBe("cli_tool");
  });

  it("bills nothing for a HEAD (no bytes served)", async () => {
    const { h, egressMeter, staticMeter } = await published(
      STATIC_RESOURCE_PROVIDER,
      "docs/guide.md",
      256,
      "text/markdown",
    );

    const result = await h.service.pullAsset(
      callers(),
      { assetType: STATIC_RESOURCE_PROVIDER, name: "docs/guide.md", reference: "1.0.0" },
      { headers: new Headers(), method: "HEAD" },
      CTX,
    );

    expect(result.ok).toBe(true);
    expect(staticMeter.charges).toHaveLength(0);
    expect(egressMeter.charges).toHaveLength(0);
  });

  it("serves a script-bearing static_resource as a sandboxed attachment (design §4.3/§9)", async () => {
    const { h } = await published(
      STATIC_RESOURCE_PROVIDER,
      "pages/report.html",
      64,
      "text/html",
    );

    const result = await h.service.pullAsset(
      callers(),
      { assetType: STATIC_RESOURCE_PROVIDER, name: "pages/report.html", reference: "1.0.0" },
      { headers: new Headers() },
      CTX,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    expect(result.headers["content-disposition"]).toBe("attachment");
    expect(result.headers["content-security-policy"]).toBe("sandbox");
    expect(result.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("serves a non-scriptable static_resource inline with only nosniff", async () => {
    const { h } = await published(
      STATIC_RESOURCE_PROVIDER,
      "docs/guide.md",
      64,
      "text/markdown",
    );

    const result = await h.service.pullAsset(
      callers(),
      { assetType: STATIC_RESOURCE_PROVIDER, name: "docs/guide.md", reference: "1.0.0" },
      { headers: new Headers() },
      CTX,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.headers["x-content-type-options"]).toBe("nosniff");
    expect(result.headers["content-disposition"]).toBeUndefined();
  });

  it("bills nothing for a 304 Not Modified", async () => {
    const { h, staticMeter } = await published(
      STATIC_RESOURCE_PROVIDER,
      "docs/guide.md",
      256,
      "text/markdown",
    );
    const ref = { assetType: STATIC_RESOURCE_PROVIDER, name: "docs/guide.md", reference: "1.0.0" };

    const first = await h.service.pullAsset(callers(), ref, { headers: new Headers() }, CTX);
    expect(first.ok).toBe(true);
    const etag = (first.ok && first.headers.etag) || "";
    expect(staticMeter.charges).toHaveLength(1);

    const conditional = await h.service.pullAsset(
      callers(),
      ref,
      { headers: new Headers({ "if-none-match": etag }) },
      CTX,
    );
    expect(conditional.ok && conditional.status).toBe(304);
    // Still one charge — the 304 added nothing.
    expect(staticMeter.charges).toHaveLength(1);
  });
});
