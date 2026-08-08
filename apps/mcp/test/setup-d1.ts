/**
 * Applies the DEPLOYED D1 migrations to `env.DB` (control) and the auxiliary
 * test-only native tenant binding `env.TENANT_DB_A` before every test file.
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
 * is not suspension, so every pre-existing expectation holds unchanged. Tenant
 * asset fixtures use the gateway-owned `TENANT_DATA` Durable Object namespace,
 * not a flat D1 binding.
 *
 * The migrations are the deployed ones (`sql/d1-ts/{control,tenant}`, read by
 * `vitest.config.ts` with `readD1Migrations`) rather than a fixture copy, so a
 * column rename breaks these tests instead of them passing against a schema
 * production does not have. `applyD1Migrations` is idempotent and bookkept in
 * `d1_migrations`.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { controlDataObjectDatabase } from "@ferrogate/storage";
import { beforeAll } from "vitest";

import { forgetControlTableProbe } from "../src/auth.js";

interface McpTestBindings {
  DB?: D1Database;
  BILLING_DB?: D1Database;
  CONTROL_DATA?: unknown;
  TENANT_DB_A?: D1Database;
  readonly TEST_TENANT_D1_SCHEMA?: Parameters<typeof applyD1Migrations>[1];
}

const bindings = env as unknown as McpTestBindings;

if (bindings.CONTROL_DATA === undefined) {
  // Loud, never a silent skip: the control object is bound cross-script from
  // the gateway aux worker (`vitest.config.ts`), so an absent one means the
  // wiring was removed and the suite is about to prove something other than
  // what it claims.
  throw new Error(
    "mcp test setup: `CONTROL_DATA` is not bound — vitest.config.ts must bind the " +
      "cross-script ControlDataObject (Zero-D1 S5, #881).",
  );
}

// Zero-D1 S5 (#881): the control database is the singleton ControlDataObject.
// The mcp `[[d1_databases]] DB` / `BILLING_DB` (`ferrogate-control`) stanzas are
// deleted; `src/control-data.ts` reads `CONTROL_DATA`. The legacy binding names
// are aliased AT MODULE LOAD to a fresh-per-call facade over that object so
// fixtures that seed `env.DB` / `env.BILLING_DB` land in the object the code
// reads. A lazy Proxy avoids reusing a request-bound DO stub across requests.
const controlAlias = new Proxy({} as D1Database, {
  get(_target, prop) {
    const db = controlDataObjectDatabase(bindings.CONTROL_DATA as never) as unknown as Record<
      string | symbol,
      unknown
    >;
    if (prop === "exec") {
      return async (sql: string): Promise<{ count: number; duration: number }> => {
        const statements = sql
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line !== "");
        for (const statement of statements) {
          await (db.prepare as (s: string) => { run(): Promise<unknown> })(statement).run();
        }
        return { count: statements.length, duration: 0 };
      };
    }
    const value = db[prop];
    return typeof value === "function" ? value.bind(db) : value;
  },
});
bindings.DB = controlAlias;
bindings.BILLING_DB = controlAlias;

beforeAll(async () => {
  const { TENANT_DB_A, TEST_TENANT_D1_SCHEMA } = bindings;
  if (TENANT_DB_A === undefined || TEST_TENANT_D1_SCHEMA === undefined) {
    throw new Error(
      "mcp test setup: expected the `TENANT_DB_A` binding and `TEST_TENANT_D1_SCHEMA` " +
        "(vitest.config.ts). See src/lifecycle.ts for why this suite runs against real, " +
        "migrated storage.",
    );
  }
  await applyD1Migrations(TENANT_DB_A, TEST_TENANT_D1_SCHEMA);
  // `src/auth.ts` caches its table probe per control handle for the life of the
  // isolate. Forgetting it here is what an isolate recycle does after a schema
  // lands, so a file whose first request preceded the seed does not remember
  // "these tables do not exist" for the whole run.
  forgetControlTableProbe(controlAlias);
});
