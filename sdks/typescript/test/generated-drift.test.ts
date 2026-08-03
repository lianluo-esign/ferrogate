/**
 * The committed generated types MUST match the committed contract.
 *
 * `src/api-types.generated.ts` is produced from
 * `docs/openapi/admin-api.openapi.json`. Stale generated types still COMPILE —
 * they simply describe an older server — so nothing else in this workspace
 * would notice a contract change that landed without re-running the generator.
 *
 * Since #766 the comparison itself lives at `tools/generated-clients/`, shared
 * with every other client generated from the same document, and this test
 * drives it through the very CLI that admin-console's `check:api-types` uses.
 * The duplication it replaces was not harmless: this SDK and admin-console each
 * carried their own copy of the pipeline, which is how one could be regenerated
 * and the other forgotten (#736, #737).
 *
 * Kept in THIS workspace anyway, because `bun run --filter '@ferrogate/admin-sdk'
 * test` has to be able to fail on a stale client without the runner knowing to
 * go look somewhere else.
 */
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const checkCli = path.join(repoRoot, "tools", "generated-clients", "check.mjs");

describe("generated types", () => {
  it("are in sync with docs/openapi/admin-api.openapi.json", () => {
    // The CLI exits 1 and prints the fix instruction on drift, so a failure
    // here reads as the drift report rather than as a diff of two large files.
    let failure: string | null = null;
    try {
      execFileSync(process.execPath, [checkCli, "--only", "sdks/typescript"], {
        cwd: repoRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      const spawned = error as { stdout?: string; stderr?: string; message?: string };
      failure = (spawned.stderr || "") + (spawned.stdout || "") || String(spawned.message);
    }

    expect(failure, failure ?? undefined).toBeNull();
    // 30s is sized against 539ms unloaded and 4.061s under CPU contention;
    // sampling the 2 MiB contract would weaken the drift proof.
  }, 30_000);
});
