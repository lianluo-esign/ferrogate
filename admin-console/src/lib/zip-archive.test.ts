import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { hasZipMagic, readsAsZipArchive, ZIP_MAGIC } from "@/lib/zip-archive";
import {
  E2E_PUBLISH_BUNDLE,
  E2E_REPUBLISH_BUNDLE,
  zipBundleBytes,
} from "@/test/fixtures/zip-bundle";

// The permanent guard for the #345 fixture break.
//
// `readsAsZipArchive` replaced a filename/MIME check with a magic-byte check.
// That silently invalidated the Playwright publish fixtures — they were
// `Buffer.alloc(4096, 1)` / `Buffer.alloc(2048, 9)`, which the old gate passed
// and the new one rejects, so the Publish button was `disabled` and both publish
// specs would have hung on actionability in every viewport project. Nothing in
// the dev-loop could see it: `playwright --list` still discovered the cases and
// `npm run typecheck:e2e` was still clean, because neither executes a
// validation, and no browser can run here.
//
// So these tests run the PRODUCT's predicate over the EXACT bytes the e2e specs
// upload (the specs import the same constants). Tighten the predicate again —
// require a full local-file header, a central directory, a minimum size — and
// this goes red in vitest instead of in the gate's chromium run.
describe("readsAsZipArchive", () => {
  function fileOf(bytes: Uint8Array, name: string): File {
    // Copy into a fresh buffer so the fixture's own bytes cannot be detached.
    return new File([new Uint8Array(bytes)], name, { type: "application/zip" });
  }

  it("accepts the exact bundle e2e/static-sites.spec.ts publishes", async () => {
    await expect(readsAsZipArchive(fileOf(E2E_PUBLISH_BUNDLE, "landing.zip"))).resolves.toBe(
      true,
    );
  });

  it("accepts the exact bundle e2e/static-sites.spec.ts republishes", async () => {
    await expect(
      readsAsZipArchive(fileOf(E2E_REPUBLISH_BUNDLE, "marketing-v3.zip")),
    ).resolves.toBe(true);
  });

  // Non-vacuity: the buffers the specs used BEFORE the magic-byte gate landed
  // are exactly what this guard has to be able to reject. If this ever passes,
  // the two assertions above prove nothing.
  it("rejects the pre-gate fixtures the specs used to upload", async () => {
    const preGatePublish = new Uint8Array(4096).fill(1);
    const preGateRepublish = new Uint8Array(2048).fill(9);
    await expect(readsAsZipArchive(fileOf(preGatePublish, "landing.zip"))).resolves.toBe(
      false,
    );
    await expect(
      readsAsZipArchive(fileOf(preGateRepublish, "marketing-v3.zip")),
    ).resolves.toBe(false);
  });

  it("rejects a file whose name claims .zip but whose bytes do not", async () => {
    const corrupt = new Uint8Array([0x00, 0xff, 0x13, 0x37, 0x42]);
    await expect(readsAsZipArchive(fileOf(corrupt, "site.zip"))).resolves.toBe(false);
  });

  it("rejects a truncated file that is shorter than the magic", async () => {
    await expect(
      readsAsZipArchive(fileOf(new Uint8Array(ZIP_MAGIC.slice(0, 3)), "site.zip")),
    ).resolves.toBe(false);
  });
});

// The half the assertions above cannot cover: they prove the SHARED constants
// pass the predicate, but not that the spec still uploads those constants. An
// inline `Buffer.alloc(…)` added to a new publish case would be exactly the
// original break again, and again invisible to `--list` and `typecheck:e2e`.
describe("e2e/static-sites.spec.ts bundle fixtures", () => {
  it("uploads only the shared, guarded bundle constants", () => {
    const spec = readFileSync(
      resolve(process.cwd(), "e2e/static-sites.spec.ts"),
      "utf8",
    );
    const buffers = [...spec.matchAll(/^\s*buffer: (.+),$/gm)].map(
      (match) => match[1],
    );
    expect(buffers.length).toBeGreaterThan(0);
    for (const expression of buffers) {
      expect(expression).toMatch(/E2E_\w+_BUNDLE/);
    }
  });
});

describe("zipBundleBytes", () => {
  it("produces bytes the archive predicate accepts, at the requested length", () => {
    const bytes = zipBundleBytes(64, 7);
    expect(bytes).toHaveLength(64);
    expect(hasZipMagic(bytes)).toBe(true);
    expect(bytes[ZIP_MAGIC.length]).toBe(7);
  });

  it("refuses to build a fixture too short to carry the magic", () => {
    expect(() => zipBundleBytes(3)).toThrow(/at least 4 bytes/);
  });
});
