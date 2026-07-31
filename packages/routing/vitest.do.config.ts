import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * The DURABLE-OBJECT suite: `test/do/**` runs inside the REAL local `workerd`
 * (miniflare), against a REAL Durable Object — no fake namespace, no stub stub.
 *
 * This is a SECOND config rather than a replacement for `vitest.config.ts`
 * because the two suites answer different questions:
 *
 *   * `vitest.config.ts` — the pure rollout/hash algorithms. Plain vitest,
 *     milliseconds, no `workerd` boot. `src/index.ts` must stay importable from
 *     node, which is why `shadow-budget-do.ts` is NOT in that barrel.
 *   * this file — the ONLY place the cross-isolate claim is actually exercised.
 *     The whole point of `ShadowBudgetDurableObject` is that it is one instance
 *     globally with single-threaded execution and write-through storage; a fake
 *     namespace would be "single-instance" because the fake was written to
 *     agree, which is exactly the green-but-vacuous test this repo keeps being
 *     bitten by.
 *
 * `bun run test` runs BOTH (see package.json).
 *
 * `test/do/entry.ts` exists because workerd resolves a DO `class_name` against
 * the ENTRY module's exports — the same constraint every `apps/<x>/src/worker.ts` is
 * shaped by. It is a test fixture, not a deployable.
 */
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./test/do/wrangler.toml" },
    }),
  ],
  test: { include: ["test/do/**/*.test.ts"] },
});
