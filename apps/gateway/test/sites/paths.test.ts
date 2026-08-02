/**
 * The URL rules of the serve mode, driven directly (issue #737).
 *
 * `./serve.test.ts` proves these over HTTP, which is the proof that matters —
 * but the WHATWG URL parser collapses `..` and `%2e%2e` before a request ever
 * reaches the gateway, so the refusals for those shapes are unreachable from
 * there and would look like dead code. They are not dead: they are what holds
 * if this module is ever entered from anything but a parsed `Request` (a
 * service binding, a queue consumer, a future `fetch` on a raw path), and this
 * file is where they are exercised.
 */
import { describe, expect, test } from "vitest";
import { planSitePath } from "../../src/sites/paths.js";
import {
  SITE_DEFAULT_MAX_AGE_SECONDS,
  SITE_IMMUTABLE_MAX_AGE_SECONDS,
  isFingerprintedFilename,
  siteCacheControl,
} from "../../src/sites/policy.js";

describe("planSitePath", () => {
  test("a directory URL resolves that directory's index", () => {
    expect(planSitePath("docs/")).toEqual({
      kind: "resolve",
      slug: "docs",
      file: "index.html",
      directoryProbe: null,
      directory: true,
    });
    expect(planSitePath("docs/guide/")).toMatchObject({
      file: "guide/index.html",
      directory: true,
    });
  });

  test("a file URL resolves the file, and offers the directory as a second guess", () => {
    expect(planSitePath("docs/guide")).toEqual({
      kind: "resolve",
      slug: "docs",
      file: "guide",
      directoryProbe: { file: "guide/index.html", location: "/sites/docs/guide/" },
      directory: false,
    });
  });

  test("the bare site root redirects to its directory URL, query and all", () => {
    expect(planSitePath("docs")).toEqual({ kind: "redirect", location: "/sites/docs/" });
    expect(planSitePath("docs", "?v=2")).toEqual({
      kind: "redirect",
      location: "/sites/docs/?v=2",
    });
  });

  test("an explicit index.html redirects to the directory it belongs to", () => {
    expect(planSitePath("docs/index.html")).toEqual({
      kind: "redirect",
      location: "/sites/docs/",
    });
    expect(planSitePath("docs/a/b/index.html")).toEqual({
      kind: "redirect",
      location: "/sites/docs/a/b/",
    });
  });

  test("traversal, empty segments, backslashes and control characters are refused", () => {
    const refused = [
      "docs/../secret",
      "docs/a/../../b",
      "docs/./a",
      "docs//a",
      "docs/a%2fb",
      "docs/a%5cb",
      `docs/a${String.fromCharCode(0)}b`,
      "docs/a%2",
      "..",
      "",
    ];
    for (const rest of refused) {
      expect(planSitePath(rest).kind, rest).toBe("invalid");
    }
  });

  test("a percent-encoded space is a legal filename, not a refusal", () => {
    expect(planSitePath("docs/a%20b.html")).toMatchObject({ file: "a b.html" });
  });

  test("the slug is decoded once and re-encoded into every redirect", () => {
    // No double-encoding: a slug that arrives as `my%20site` must redirect to
    // `/sites/my%20site/`, not `/sites/my%2520site/`.
    expect(planSitePath("my%20site")).toEqual({
      kind: "redirect",
      location: "/sites/my%20site/",
    });
  });
});

describe("isFingerprintedFilename", () => {
  test("recognises the digests real bundlers emit", () => {
    for (const name of [
      "app.4f3a9c21.js",
      "assets/index-DiwrgTda.js",
      "main.a1b2c3d4e5f6.css",
      "chunk-4F3A9C21.mjs",
    ]) {
      expect(isFingerprintedFilename(name), name).toBe(true);
    }
  });

  test("refuses everything it is not sure about", () => {
    // A false positive pins a MUTABLE file in every browser cache for a year
    // with no way to recall it, so anything word-shaped stays short-lived.
    for (const name of [
      "index.html",
      "app.js",
      "jquery.min.js",
      "styles.mobile.css",
      "bootstrap-reboot.css",
      "assets/photo-of-the-team.jpg",
      "docs/getting-started.html",
    ]) {
      expect(isFingerprintedFilename(name), name).toBe(false);
    }
  });
});

describe("siteCacheControl", () => {
  const base = { publicSite: true, fallback: false };

  test("fingerprinted, non-HTML files are immutable for a year", () => {
    expect(
      siteCacheControl({ ...base, path: "assets/app.4f3a9c21.js", contentType: "text/javascript" }),
    ).toBe(`public, max-age=${SITE_IMMUTABLE_MAX_AGE_SECONDS}, immutable`);
  });

  test("HTML always revalidates, even when its NAME looks fingerprinted", () => {
    // The channel pointer is mutable and the HTML document is what resolves it.
    expect(
      siteCacheControl({ ...base, path: "page.a1b2c3d4.html", contentType: "text/html" }),
    ).toBe("public, max-age=0, must-revalidate");
  });

  test("anything else gets the short TTL", () => {
    expect(siteCacheControl({ ...base, path: "assets/app.css", contentType: "text/css" })).toBe(
      `public, max-age=${SITE_DEFAULT_MAX_AGE_SECONDS}, must-revalidate`,
    );
  });

  test("a private site is never marked public, for any file", () => {
    for (const path of ["index.html", "assets/app.4f3a9c21.js", "assets/app.css"]) {
      const value = siteCacheControl({
        path,
        contentType: path.endsWith(".html") ? "text/html" : "text/javascript",
        publicSite: false,
        fallback: false,
      });
      expect(value.startsWith("private,"), path).toBe(true);
      expect(value, path).not.toContain("public");
    }
  });

  test("a fallback document is never stored, public or private", () => {
    expect(
      siteCacheControl({ ...base, path: "404.html", contentType: "text/html", fallback: true }),
    ).toBe("public, no-store");
    expect(
      siteCacheControl({
        path: "index.html",
        contentType: "text/html",
        publicSite: false,
        fallback: true,
      }),
    ).toBe("private, no-store");
  });
});
