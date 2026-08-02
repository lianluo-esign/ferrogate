/**
 * `src/**` must stay runtime-agnostic.
 *
 * The point of a thin client is that it runs wherever `fetch` does — a Worker,
 * Bun, Node, a browser. One `node:*` import (or a `process.env` read for a
 * default) would quietly make it Node-only, and the failure would surface as a
 * bundling error in a consumer's Worker rather than here.
 */
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

function sourceFiles(): string[] {
  return readdirSync(srcDir)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => path.join(srcDir, name));
}

describe("src hygiene", () => {
  it("imports nothing from node:*", () => {
    const offenders = sourceFiles().filter((file) =>
      /from\s+["']node:|require\(["']node:/.test(readFileSync(file, "utf8")),
    );
    expect(offenders).toEqual([]);
  });

  it("reads no ambient process state", () => {
    // A default pulled from `process.env` would make the SAME code authenticate
    // differently in two runtimes. Credentials are arguments here, always.
    const offenders = sourceFiles().filter((file) =>
      /\bprocess\.env\b/.test(readFileSync(file, "utf8")),
    );
    expect(offenders).toEqual([]);
  });
});
