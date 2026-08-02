/**
 * Applies the DEPLOYED D1 migrations before every file in this project.
 *
 * `apps/gateway/wrangler.toml` binds `DB` (tenant) and `BILLING_DB` (control),
 * and the gateway makes the durable key/quota/RBAC legs the PRIMARY sources
 * whenever those bindings exist. A bound database whose tables do not exist is
 * a FAILURE, not an empty result, so without this file every request in the
 * suite would answer `503 external_auth_unavailable` and the conformance
 * findings would be about a broken harness rather than about the gateway.
 *
 * With the tables present and empty the durable legs simply find nothing, the
 * config fallbacks in `vitest.config.ts` answer, and the suite exercises the
 * same admission ladder a deployment with no seeded rows would.
 *
 * Same shape and same rationale as `apps/gateway/test/setup-d1.ts`; the
 * migrations are the deployed ones (`sql/d1-ts/**`), never a fixture copy.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll } from "vitest";
import controlMigrationSql from "../../../sql/d1-ts/control/0001_init_control.sql?raw";

interface D1TestBindings {
  readonly DB?: D1Database;
  readonly BILLING_DB?: D1Database;
  readonly TEST_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

/** Split a `.sql` migration into statements, dropping the (heavy) prose first. */
function sqlStatements(migration: string): string[] {
  return migration
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

beforeAll(async () => {
  const { DB, BILLING_DB, TEST_D1_SCHEMA } = env as unknown as D1TestBindings;
  if (DB === undefined || TEST_D1_SCHEMA === undefined) {
    // Loud, never a silent skip: both are supplied by this project's
    // `vitest.config.ts` + `apps/gateway/wrangler.toml`. An absent one means the
    // wiring changed and the suite is about to prove something else.
    throw new Error(
      "sdk-conformance setup: expected the `DB` binding (apps/gateway/wrangler.toml) " +
        "and `TEST_D1_SCHEMA` (tools/sdk-conformance/vitest.config.ts).",
    );
  }
  await applyD1Migrations(DB, TEST_D1_SCHEMA);

  if (BILLING_DB !== undefined) {
    for (const statement of sqlStatements(controlMigrationSql)) {
      await BILLING_DB.prepare(statement).run();
    }
  }
});
