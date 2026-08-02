/**
 * The committed generated types MUST match the committed contract.
 *
 * `src/api-types.generated.ts` is produced from
 * `docs/openapi/admin-api.openapi.json`. Stale generated types still COMPILE —
 * they simply describe an older server — so nothing else in this repo would
 * notice a contract change that landed without re-running the generator. The
 * console learned that the expensive way (#379/#392) and guards it the same
 * way; this is that guard for the SDK.
 *
 * It replays the exact `bun run generate` pipeline (openapi-typescript, then
 * the banner stamp) into a THROWAWAY temp file and compares. It never writes to
 * the committed file.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BANNER } from "../scripts/stamp-generated-header.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const specPath = path.join(repoRoot, "docs", "openapi", "admin-api.openapi.json");
const generatedPath = path.join(packageRoot, "src", "api-types.generated.ts");
const cli = path.join(repoRoot, "node_modules", "openapi-typescript", "bin", "cli.js");

describe("generated types", () => {
  it("are in sync with docs/openapi/admin-api.openapi.json", () => {
    const scratch = mkdtempSync(path.join(tmpdir(), "ferrogate-admin-sdk-types-"));
    try {
      const tempOut = path.join(scratch, "api-types.generated.ts");
      execFileSync(process.execPath, [cli, specPath, "-o", tempOut], {
        cwd: packageRoot,
        stdio: ["ignore", "ignore", "inherit"],
      });

      const fresh = BANNER + readFileSync(tempOut, "utf8");
      const committed = readFileSync(generatedPath, "utf8");

      expect(
        fresh === committed,
        "src/api-types.generated.ts is stale vs docs/openapi/admin-api.openapi.json — " +
          "run `bun run generate` from sdks/typescript/ and commit the result",
      ).toBe(true);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});
