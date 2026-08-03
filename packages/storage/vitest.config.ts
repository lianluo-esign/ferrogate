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
 * `test/do/**` is EXCLUDED for the same reason and runs under
 * `vitest.do.config.ts`: `TenantDataObject` extends `DurableObject` from
 * `cloudflare:workers` and its suite imports `cloudflare:test`, neither of
 * which resolves in node — and its claims (`transactionSync` rolls back, the
 * version gate stops the ALTER-only migrations re-running, two `idFromName`
 * objects hold different databases) are runtime properties too.
 *
 * `bun run test` runs all three suites; see package.json.
 *
 * The warning below is not decoration. A gate a developer cannot reach with the
 * obvious command in the obvious directory goes stale — #760 is the proof: the
 * `api_keys` column pin sat red on main because `bunx vitest run` here reports
 * a clean 302/302 while the suite that pins the schema is not collected at all.
 * Silence after an incomplete run reads exactly like silence after a complete
 * one, so the run now says which half it skipped.
 */
console.warn(
  "[@ferrogate/storage] this config EXCLUDES test/d1/** and test/do/** — the D1 " +
    "schema pins, the durable-backend tests and the TenantDataObject suite were " +
    "NOT run. Use `bun run test` to run all three suites.",
);

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/d1/**", "test/do/**"],
  },
});
