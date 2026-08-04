import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * The DURABLE-OBJECT suite: `test/do/**` runs inside the REAL local `workerd`
 * (miniflare), against a REAL SQLite-backed Durable Object.
 *
 * A THIRD config in this package, for the same reason there is already a
 * second: the three suites answer different questions and have different costs.
 *
 *   * `vitest.config.ts`     — the pure algorithms, plain vitest, no workerd.
 *   * `vitest.d1.config.ts`  — the same algorithms against real D1 bindings.
 *   * this file              — `TenantDataObject`, the tenant's own database.
 *
 * It cannot be folded into the D1 config. That one boots from `d1Databases` +
 * `bindings` with no `wrangler.toml`, and a Durable Object namespace needs a
 * `class_name` resolved against an ENTRY module — the same workerd rule that
 * shapes every `apps/<x>/src/worker.ts`. `test/do/wrangler.toml` +
 * `test/do/entry.ts` are that fixture.
 *
 * Everything this suite asserts is a property of the RUNTIME, not of this
 * package's code: that `transactionSync` really rolls back, that the ALTER-only
 * migrations really are not re-applied on the second wake, that two
 * `idFromName` objects really hold different databases. A fake namespace would
 * agree with all of it because the fake was written to agree — the
 * green-but-vacuous shape this repo keeps being bitten by.
 *
 * `bun run test` in this package runs ALL THREE (see package.json). Dropping
 * this leg from the `&&` chain would leave `src/tenant-data-object.ts` with no
 * gate at all while `bunx vitest run` still reports green.
 */
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./test/do/wrangler.toml" },
    }),
  ],
  test: { include: ["test/do/**/*.test.ts"] },
});
