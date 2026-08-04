import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));

describe("TypeScript admin SDK package", () => {
  it("has an independent build and dist-only public entrypoint", () => {
    expect(packageJson.private).not.toBe(true);
    expect(packageJson.files).toContain("dist");
    expect(packageJson.scripts.build).toBe("tsc -p tsconfig.build.json");
    expect(packageJson.exports["."]).toEqual({
      types: "./dist/index.d.ts",
      import: "./dist/index.js",
    });
    expect(existsSync(path.join(packageRoot, "tsconfig.build.json"))).toBe(true);
  });
});
