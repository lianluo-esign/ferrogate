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
 * ## THIS CONFIG IS CHAINED, AND IT HAS TO BE
 *
 * `apps/gateway/package.json`'s `test` script runs `vitest run` AND THEN this
 * config. That second half is not a convenience: without it these 24 specs —
 * including the cross-tenant counter-collision attack — are dead files. They
 * are `*.spec.ts` under a non-default config, so a bare `vitest run` matches
 * none of them and reports a green suite that never executed a single one. Do
 * not drop the `&&` when editing that script.
 *
 * Run alone:  bun x vitest run --config test/ratelimit/harness/vitest.config.ts
 *             (from apps/gateway)
 *
 * ## Integrate-step status (re-checked)
 *
 * HALF of the precondition this harness was written around has now landed:
 * `apps/gateway/wrangler.toml` carries the `[[durable_objects.bindings]]
 * RATE_LIMIT` + `[[migrations]] new_sqlite_classes` blocks, and
 * `apps/gateway/src/worker.ts` carries `export { RateLimiterDurableObject }`.
 * The deployed Worker therefore has the namespace this harness once existed to
 * supply, and `src/index.ts` mounts `rateLimit()` in `GATEWAY_MIDDLEWARE`.
 *
 * What is still harness-only is the DATA: `harness/wrangler.toml`'s `[vars]`
 * carry the quota policies, plans and eight API keys these specs assert
 * against, and `apps/gateway/wrangler.toml` pins `GATEWAY_QUOTA_POLICIES = "[]"`.
 * `harness/worker.ts` also turns on two options production does not use
 * (`perKeyRequestLimit`, `settleTokens`), so folding the specs into the main
 * suite would change what they test, not just where they run.
 *
 * To finish: fold those `[vars]` into `apps/gateway/vitest.config.ts`'s
 * `miniflare.bindings`, move the two option overrides onto the app's own
 * `rateLimit()` call or drop the specs that need them, rename `*.spec.ts` →
 * `*.test.ts`, and delete this file plus `harness/worker.ts` +
 * `harness/wrangler.toml`.
 */
export default defineConfig({
  root: SUITE_ROOT,
  plugins: [cloudflareTest({ wrangler: { configPath: "./harness/wrangler.toml" } })],
  test: { include: ["**/*.spec.ts"] },
});
