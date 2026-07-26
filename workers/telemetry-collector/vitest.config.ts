// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Worker-side test harness for the telemetry-collector (issue #520). Boots the
//   REAL Worker in workerd via @cloudflare/vitest-pool-workers + miniflare — the same runtime
//   `wrangler dev --local` uses — with NO Docker, NO live Cloudflare account, NO network.
//
//   Config shape targets vitest-pool-workers >= 0.18 (vitest 4): the workers pool is
//   registered as the `cloudflareTest(...)` Vite plugin (the older
//   `defineWorkersConfig`/`poolOptions.workers` form was removed for vitest 4).
//
//   The compatibility date is READ FROM wrangler.toml rather than restated here, so the
//   suite can never drift onto different runtime semantics than the deployment.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

const workerDir = path.dirname(fileURLToPath(import.meta.url));
const wranglerToml = readFileSync(path.join(workerDir, "wrangler.toml"), "utf8");

function requiredMatch(pattern: RegExp, what: string): string {
  const match = pattern.exec(wranglerToml);
  if (!match) throw new Error(`wrangler.toml: could not read ${what}`);
  return match[1];
}

/** The deployed compatibility date, verbatim. */
const compatibilityDate = requiredMatch(
  /^compatibility_date\s*=\s*"([^"]+)"/m,
  "compatibility_date",
);

/** The deployed Analytics Engine dataset name, verbatim. */
const dataset = requiredMatch(/^dataset\s*=\s*"([^"]+)"/m, "the analytics engine dataset");

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate,
        // miniflare implements the Analytics Engine binding locally, so the
        // production code path (`env.TELEMETRY.writeDataPoint`) runs for real in
        // these tests. The writes are not READABLE from inside the Worker — no
        // binding exposes them — so the limit clamps are additionally asserted
        // against an observable stub in test/limits.test.ts.
        analyticsEngineDatasets: { TELEMETRY: { dataset } },
        bindings: {
          COLLECTOR_TOKEN: "test-collector-secret",
          // Small enough that the 413 path is cheap to exercise, large enough
          // that the 251-point over-cap batch still fits.
          MAX_BODY_BYTES: "65536",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
