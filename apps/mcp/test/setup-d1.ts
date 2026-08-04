/**
 * Applies the DEPLOYED D1 migrations to `env.DB` (control) and `env.TENANT_DB_A`
 * before every test file in this suite.
 *
 * ## Why the whole suite needs this, not just the D1 files
 *
 * `wrangler.toml` declares `[[d1_databases]] binding = "DB"`, so `resolvePorts`
 * builds the durable auth port, the durable admission ladder AND — since
 * FLEET-CONSISTENCY finding FC-2 — the durable {@link
 * TenancyLifecycleGatePort} for EVERY request in this suite. That wiring is
 * deliberately not test-only.
 *
 * The lifecycle gate FAILS CLOSED: a `tenants` read that raises answers
 * `503 lifecycle_status_unavailable`, never an admission, because fail-open
 * would make "flap the control plane" a suspension bypass. **A missing table is
 * such a failure.** So without this file every authenticated test in the suite
 * would 503, and the "fix" would look like making the gate fail OPEN on a
 * missing table — which is precisely the bypass FC-2 exists to close, reopened
 * on the excuse of a green suite.
 *
 * `apps/gateway/test/setup-d1.ts` is the same file for the same reason, one
 * Worker over, and it is the precedent this follows.
 *
 * With the tables present and EMPTY nothing else changes: the credential legs
 * find no row and fall through to the in-memory dev table exactly as before,
 * and the lifecycle walk finds no `tenants` row, which is ABSENCE — and absence
 * is not suspension, so every pre-existing expectation holds unchanged.
 *
 * The migrations are the deployed ones (`sql/d1-ts/{control,tenant}`, read by
 * `vitest.config.ts` with `readD1Migrations`) rather than a fixture copy, so a
 * column rename breaks these tests instead of them passing against a schema
 * production does not have. `applyD1Migrations` is idempotent and bookkept in
 * `d1_migrations`.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll } from "vitest";

import { forgetControlTableProbe } from "../src/auth.js";

interface McpTestBindings {
  readonly DB?: D1Database;
  readonly BILLING_DB?: D1Database;
  readonly TENANT_DB?: D1Database;
  readonly TENANT_DB_A?: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
  readonly TEST_TENANT_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

beforeAll(async () => {
  const bindings = env as unknown as McpTestBindings;
  const {
    DB,
    BILLING_DB,
    TENANT_DB,
    TENANT_DB_A,
    TEST_CONTROL_D1_SCHEMA,
    TEST_TENANT_D1_SCHEMA,
  } = bindings;
  if (
    DB === undefined ||
    TENANT_DB === undefined ||
    TENANT_DB_A === undefined ||
    TEST_CONTROL_D1_SCHEMA === undefined ||
    TEST_TENANT_D1_SCHEMA === undefined
  ) {
    // Loud, never a silent skip: all five come from `wrangler.toml` +
    // `vitest.config.ts`, so an absent one means the wiring was removed and the
    // suite is about to prove something other than what it claims.
    throw new Error(
      "mcp test setup: expected the `DB`, `TENANT_DB` and `TENANT_DB_A` bindings plus " +
        "`TEST_CONTROL_D1_SCHEMA` / `TEST_TENANT_D1_SCHEMA`. " +
        "See src/lifecycle.ts for why this suite runs against a real, MIGRATED D1.",
    );
  }
  await applyD1Migrations(DB, TEST_CONTROL_D1_SCHEMA);
  if (BILLING_DB !== undefined && BILLING_DB !== DB) {
    await applyD1Migrations(BILLING_DB, TEST_CONTROL_D1_SCHEMA);
  }
  await applyD1Migrations(TENANT_DB, TEST_TENANT_D1_SCHEMA);
  await applyD1Migrations(TENANT_DB_A, TEST_TENANT_D1_SCHEMA);
  // `src/auth.ts` caches its table probe per D1 handle for the life of the
  // isolate. Forgetting it here is what an isolate recycle does after a
  // migration lands, and without it a file whose first request preceded the
  // migration would remember "these tables do not exist" for the whole run.
  forgetControlTableProbe(DB);
});
