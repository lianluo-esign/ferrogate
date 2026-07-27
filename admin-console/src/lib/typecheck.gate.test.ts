// Typecheck regression gate (#527).
//
// `npm run build` already runs `tsc -b` UNPIPED (`tsc -b && vite build && ...`)
// under `set -euo pipefail` in scripts/check-admin-console.sh, so a real type
// error already fails that command's exit code correctly -- there is no
// swallowed-exit-code bug in this repo's scripts to fix (verified: `npm run
// build` on the pre-fix tree exited 2, matching `npx tsc -b`'s own exit code).
// The gotcha #527 called out ($? of `tail` in a piped invocation) is a manual
// measurement mistake, not something any committed script does.
//
// What WAS missing: `npm run build` is a slow, separate step nobody runs on
// every save, so a typecheck regression (exactly what #527 fixed: agent-jobs.tsx
// submitting a body that no longer satisfied `AgentJobSubmitRequest` after
// #474) could land and sit red on main across several commits before anyone
// noticed. This test runs the SAME `tsc -b` project build as part of
// `npm run test` (already invoked by scripts/check-admin-console.sh, and by
// any developer running the ordinary test command), so a type error now fails
// an everyday test run instead of only the separate release-local.sh build.
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const tscBin = path.join(projectRoot, "node_modules", ".bin", "tsc");

describe("admin-console typecheck gate", () => {
  it("`tsc -b` reports zero project-wide type errors", () => {
    let output = "";
    let failed = false;
    try {
      output = execFileSync(tscBin, ["-b"], {
        cwd: projectRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      failed = true;
      const execError = error as { stdout?: string; stderr?: string; message: string };
      output = `${execError.stdout ?? ""}${execError.stderr ?? ""}` || execError.message;
    }
    expect(failed, `tsc -b reported type errors (unpiped exit code was non-zero):\n${output}`).toBe(
      false,
    );
  }, 60_000);
});
