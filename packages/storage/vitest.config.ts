import { defineConfig } from "vitest/config";

/**
 * The PURE-ALGORITHM suite: every ported algorithm and its synchronous
 * in-memory reference backend. Plain vitest, no Cloudflare binding, no
 * `workerd` boot.
 *
 * `test/d1/**` is EXCLUDED and runs under `vitest.d1.config.ts` instead,
 * because those tests need a real D1 binding to mean anything: the atomicity
 * claims they assert (`batch()` is one transaction, an empty `RETURNING` set is
 * the guard's refusal, SQLite serializes writers per database) are properties
 * of the runtime, not of this package's code. Asserting them against a fake
 * would assert only that the fake was written to agree.
 *
 * `bun run test` runs both suites; see package.json.
 */
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/d1/**"],
  },
});
