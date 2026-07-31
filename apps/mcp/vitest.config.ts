/**
 * Offline, docker-free Worker tests (`docs/rewrite/TESTING.md`).
 *
 * `main` is named EXPLICITLY, mirroring `apps/agent-runtime`. That is what puts
 * the Worker `SELF` drives in the SAME isolate as the test file, which two
 * things in this suite depend on:
 *
 *  - `test/fixtures.ts` seeds the in-memory port singleton and then asserts on
 *    what the Worker recorded there;
 *  - `setMcpEnvVar` overrides an operator `[vars]` value for one test, and the
 *    Worker observes it on its next request. Without an explicit `main` the
 *    pool serves `SELF` from a separate worker whose env is the `wrangler.toml`
 *    vars alone, so an override is visible to the test and NOT to the code
 *    under test — which silently degrades every guardrail assertion in
 *    `test/guardrails.test.ts` into "no detector configured ⇒ allow".
 */
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/worker.ts",
      wrangler: { configPath: "./wrangler.toml" },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
