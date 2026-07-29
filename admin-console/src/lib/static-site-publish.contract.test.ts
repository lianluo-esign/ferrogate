// Wire-contract drift alarm for the static-site PUBLISH response (#345),
// the sibling of site-domains.contract.test.ts.
//
// Why this exists: `object === "static_site"` is now load-bearing PRODUCT logic.
// `isBundleCommit` in src/pages/static-sites.tsx narrows the publish success
// branch on it, because the same PUT answers 200 with an entirely different
// envelope — the ordinary `AssetMutationResponse` blob receipt — whenever the
// body is not a ZIP or screening withheld it (assets.rs), and treating that as a
// publish produced the gate's `Published undefined (undefined files, NaN)`.
//
// The producer side has no guard of its own: the gateway builds this body as an
// ad-hoc `serde_json::json!` literal with no Rust struct behind it, and the
// OpenAPI `200` for `putAsset` is `AssetMutationResponse` alone —
// `StaticSitePublishResponse` appears only in the operation's description prose,
// not in a `oneOf`. So renaming the discriminator, or any field the console
// reads out of it, would leave every test and fixture green (they hard-code the
// same literal) while the console called every real publish "not published".
// This reads the literal out of the gateway source so that rename fails HERE.
//
// (Correcting the OpenAPI `200` to a `oneOf` is the better long-term fix, but it
// needs a compatibility-baseline revision, which is a separate change.)
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { ZIP_MAGIC } from "@/lib/zip-archive";

// Vitest runs with `admin-console/` as its root, so the gateway sources sit one
// directory up.
const SITES = resolve(process.cwd(), "../crates/ferrogate-gateway/src/server/sites.rs");

/** The `serde_json::json!({ … })` literal the site-publish success path writes,
 * located by the discriminator itself so an unrelated literal cannot match. */
function publishResponseLiteral(source: string): string {
  const match = /serde_json::json!\(\{\s*\n\s*"object": "static_site",([\s\S]*?)\n\s*\}\);/.exec(
    source,
  );
  if (!match) {
    throw new Error(
      'the static-site publish response literal (`"object": "static_site"`) was not found in sites.rs',
    );
  }
  return match[1];
}

describe("static-site publish wire contract", () => {
  const sites = readFileSync(SITES, "utf8");

  it("still discriminates a committed bundle with object: static_site", () => {
    // Anything else and `isBundleCommit` (static-sites.tsx) routes a real,
    // committed publish into the "not published" failure branch.
    expect(sites).toContain('"object": "static_site"');
    expect(() => publishResponseLiteral(sites)).not.toThrow();
  });

  it("still carries every field the publish success path reads", () => {
    const literal = publishResponseLiteral(sites);
    const keys = [...literal.matchAll(/^\s*"(\w+)":/gm)].map((match) => match[1]);
    // `site`/`file_count`/`size_bytes` are read straight into the success toast;
    // the rest are the envelope the generated `StaticSitePublishResponse`
    // declares, so a dropped field is a contract break even where the console
    // does not render it today.
    expect(new Set(keys)).toEqual(
      new Set([
        "tenant",
        "site",
        "bundle_version",
        "public",
        "spa_fallback",
        "file_count",
        "size_bytes",
        "files",
      ]),
    );
  });

  it("still branches into that response on the same ZIP magic the console checks", () => {
    // src/lib/zip-archive.ts predicts the gateway's branch client-side; if the
    // gateway's magic changed, the console would disable Publish for bundles the
    // gateway would have accepted (or the reverse).
    const magic = /fn is_zip_archive\(data: &\[u8\]\) -> bool \{\n\s*data\.starts_with\(&\[([^\]]*)\]\)/.exec(
      sites,
    );
    expect(magic, "is_zip_archive was not found in sites.rs").not.toBeNull();
    const bytes = magic![1]
      .split(",")
      .map((byte) => byte.trim())
      .filter((byte) => byte !== "")
      .map((byte) => Number(byte));
    expect(bytes).toEqual(ZIP_MAGIC);
  });
});
