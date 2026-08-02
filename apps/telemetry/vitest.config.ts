/**
 * Offline, docker-free Worker tests (`docs/rewrite/TESTING.md`).
 *
 * The Worker runs in the real local `workerd`, so `TELEMETRY` is a REAL
 * Analytics Engine binding: `SELF.fetch` exercises the deployed write path, not
 * a mock of it. Exact data-point contents are asserted separately by driving
 * the same exported app with a `RecordingTelemetrySink` — the binding itself
 * cannot be read back, since Analytics Engine's only read API is the
 * off-platform SQL API.
 *
 * `COLLECTOR_TOKEN` lives here rather than in `wrangler.toml` on purpose: it is
 * a SECRET, seeded per environment with `wrangler secret put`. A deploy must
 * never inherit a token from a committed config, so `wrangler.toml` ships none
 * and the Worker fails closed without one.
 */
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/worker.ts",
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          COLLECTOR_TOKEN: "test-collector-token",
          // A deliberately small ceiling so the 413 path is provable with a
          // payload the suite builds inline instead of a 4 MiB fixture.
          MAX_BODY_BYTES: "2048",
        },
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
