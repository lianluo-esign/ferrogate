// Wire-contract drift alarm for the static-site PUBLISH response (#345),
// the sibling of site-domains.contract.test.ts.
//
// Why this exists: `object === "static_site"` is load-bearing PRODUCT logic.
// `isBundleCommit` in src/pages/static-sites.tsx narrows the publish success
// branch on it, because the same PUT answers 200 with an entirely different
// envelope — the ordinary `AssetMutationResponse` blob receipt — whenever the
// body is not a recognizable archive or screening withheld it. Treating that
// fallthrough as a publish produced the gate's
// `Published undefined (undefined files, NaN)`.
//
// RE-ANCHORED (2026-08): this test used to read the Rust producer
// (`crates/ferrogate-gateway/src/server/sites.rs`, where the body was an ad-hoc
// `serde_json::json!` literal with no struct behind it); the Rust tree was
// deleted on 2026-08-02. The anchors are now:
//
//  * `docs/openapi/admin-api.openapi.json`'s `StaticSitePublishResponse` — the
//    old test's complaint ("appears only in the operation's description prose")
//    is half-resolved: the envelope is now a REAL schema, with the `object`
//    const discriminator, every field required, and
//    `additionalProperties: false`. Pinned field-for-field below.
//  * `apps/gateway/src/assets/bundle.ts` — the TS gateway's archive detection,
//    read from source exactly as the Rust `is_zip_archive` was, so the magic
//    bytes the console predicts client-side (src/lib/zip-archive.ts) cannot
//    silently diverge from the branch the server takes.
//
// Two documented contract facts this file also holds:
//
//  * `putAsset`'s 200 is STILL `AssetMutationResponse` alone — not a `oneOf` —
//    so the runtime discriminator remains the only thing separating the two
//    success envelopes. If the contract ever grows the `oneOf`, this pin fails
//    and `isBundleCommit` should be re-derived from it instead.
//  * KNOWN BACKEND GAP (server↔contract half, not this file's): as of this
//    re-anchor the TS gateway's `putAsset` (apps/gateway/src/assets/service.ts)
//    still answers the `{object: "asset"}` AssetMutationResponse envelope even
//    after committing a bundle — the `StaticSitePublishResponse` envelope is
//    declared by the contract, produced by the e2e gateway harness
//    (e2e/support/gateway-static-sites.ts), and typed into the generated
//    client, but not yet emitted by the ported backend. This test pins the
//    contract shape that backend must converge on; the console's fallthrough
//    branch keeps real publishes from being reported as successes meanwhile.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { contractOperation, contractSchema, fieldShapes, sortedRequired } from "@/lib/contract-pin";
import { ZIP_MAGIC } from "@/lib/zip-archive";
import { describe, expect, it } from "vitest";

// Vitest runs with `admin-console/` as its root, so the TS gateway sources sit
// one directory up. Reading the source (rather than a checked-in copy) is the
// whole point: there is no second artifact to forget to update.
const BUNDLE_SOURCE = resolve(process.cwd(), "../apps/gateway/src/assets/bundle.ts");

describe("static-site publish wire contract", () => {
  const publish = contractSchema("StaticSitePublishResponse");

  it("still discriminates a committed bundle with object: static_site", () => {
    // Anything else and `isBundleCommit` (static-sites.tsx) routes a real,
    // committed publish into the "not published" failure branch.
    expect(publish.properties?.object?.const).toBe("static_site");
    // The discriminator must be REQUIRED, or a serializer could legally omit
    // it and every real publish would read as a fallthrough.
    expect(publish.required).toContain("object");
  });

  it("still carries every field the publish success path reads", () => {
    // `site`/`file_count`/`size_bytes` are read straight into the success
    // toast; the rest are the envelope the generated client declares, so a
    // dropped field is a contract break even where the console does not render
    // it today. `additionalProperties: false` + the full `required` list make
    // this pin exhaustive in both directions.
    expect(fieldShapes(publish)).toEqual({
      object: "const:static_site",
      tenant: "string",
      site: "string",
      bundle_version: "string",
      public: "boolean",
      spa_fallback: "boolean",
      file_count: "integer",
      size_bytes: "integer:int64",
      files: "array<string>",
    });
    expect(sortedRequired(publish)).toEqual([
      "bundle_version",
      "file_count",
      "files",
      "object",
      "public",
      "site",
      "size_bytes",
      "spa_fallback",
      "tenant",
    ]);
    expect(publish.additionalProperties).toBe(false);
  });

  it("putAsset's 200 is still the single AssetMutationResponse (the discriminator stays load-bearing)", () => {
    const put = contractOperation("/v1/assets/{asset_type}/{name}/{version}", "put");
    expect(put.operationId).toBe("putAsset");
    const schema = put.responses?.["200"]?.content?.["application/json"]?.schema;
    expect(schema?.$ref).toBe("#/components/schemas/AssetMutationResponse");
    // The day this becomes a oneOf, the contract finally names both success
    // envelopes and `isBundleCommit` should be derived from it — fail here so
    // that improvement is noticed rather than shadowed.
    expect(schema?.oneOf).toBeUndefined();
  });

  it("still branches into a bundle publish on the same ZIP magic the console checks", () => {
    // src/lib/zip-archive.ts predicts the gateway's branch client-side; if the
    // gateway's magic changed, the console would disable Publish for bundles
    // the gateway would have accepted (or the reverse). The TS gateway
    // (`detectArchiveFormat`, bundle.ts) is deliberately WIDER than the
    // console's check — it also accepts tar / tar.gz and the empty-zip EOCD
    // (PK\x05\x06) — so the console's `PK\x03\x04` local-file-header magic must
    // remain a SUBSET of what the server recognizes as a zip. That containment
    // is what is pinned: the exact four bytes the console requires are the
    // exact four bytes the server's zip branch matches first.
    const source = readFileSync(BUNDLE_SOURCE, "utf8");
    const head =
      /bytes\.length >= 4 && bytes\[0\] === (0x[0-9a-fA-F]+) && bytes\[1\] === (0x[0-9a-fA-F]+)/.exec(
        source,
      );
    expect(head, "the PK signature check was not found in bundle.ts").not.toBeNull();
    const localFileHeader =
      /\(third === (0x[0-9a-fA-F]+) && fourth === (0x[0-9a-fA-F]+)\)[^\n]*return "zip"/.exec(
        source,
      );
    expect(
      localFileHeader,
      'the local-file-header zip branch (`return "zip"`) was not found in bundle.ts',
    ).not.toBeNull();
    const bytes = [
      Number(head?.[1]),
      Number(head?.[2]),
      Number(localFileHeader?.[1]),
      Number(localFileHeader?.[2]),
    ];
    expect(bytes).toEqual(ZIP_MAGIC);
  });

  it("still confines the bundle branch to the static_site asset type", () => {
    // The console only offers the bundle Publish flow for static sites; a
    // server that started expanding archives for other asset types (or stopped
    // doing so for static_site) would invalidate that prediction.
    const source = readFileSync(BUNDLE_SOURCE, "utf8");
    expect(source).toContain('if (assetType !== "static_site") return false;');
  });
});
