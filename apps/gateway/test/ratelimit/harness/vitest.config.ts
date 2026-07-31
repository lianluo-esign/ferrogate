import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/** `test/ratelimit/` — where the specs live; this file sits one level below. */
const SUITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Vitest project for the rate-limit suite, pointed at `harness/wrangler.toml`
 * so a REAL `RATE_LIMIT` Durable Object namespace exists in `workerd`.
 *
 * It is a SECOND config rather than a change to `apps/gateway/vitest.config.ts`
 * because that file (like `wrangler.toml` and `src/worker.ts`) belongs to the
 * composition root, which this slice may not edit. The specs here are named
 * `*.spec.ts`, NOT `*.test.ts`, so the app's own config — `include:
 * ["test/**\/*.test.ts"]` — does not pick up DO tests it has no binding for.
 *
 * Run:  bun x vitest run --config test/ratelimit/harness/vitest.config.ts
 *       (from apps/gateway)
 *
 * ONCE THE INTEGRATE STEP LANDS the binding in `apps/gateway/wrangler.toml` and
 * the `export { RateLimiterDurableObject }` in `src/worker.ts`, delete this file
 * plus `harness/worker.ts` + `harness/wrangler.toml`, fold the `[vars]` from
 * that toml into `apps/gateway/vitest.config.ts`'s `miniflare.bindings`, and
 * rename `*.spec.ts` → `*.test.ts` so the specs run in the ONE suite against
 * the app the Worker really exports.
 */
export default defineConfig({
  root: SUITE_ROOT,
  plugins: [cloudflareTest({ wrangler: { configPath: "./harness/wrangler.toml" } })],
  test: { include: ["**/*.spec.ts"] },
});
