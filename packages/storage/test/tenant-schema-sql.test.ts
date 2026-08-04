/**
 * The drift gate on `src/tenant-schema-sql.ts`.
 *
 * That module is GENERATED: it inlines the bytes of `sql/d1-ts/tenant/*.sql` so
 * `TenantDataObject` can apply the tenant schema inside workerd, where there is
 * no filesystem. The obvious alternative — `import sql from "…/0001.sql?raw"` —
 * is a vite transform: it works under vitest and `wrangler deploy`'s esbuild
 * does not understand it. That combination is the worst of the two, because the
 * suite stays green on a Worker that cannot boot, which is precisely the
 * failure shape the `src/worker.ts` re-export comments describe.
 *
 * Inlining trades that for a different risk: the copy can drift from the source
 * of truth. This file removes it, in both directions.
 *
 *  * A migration ADDED to `sql/d1-ts/tenant/` without regenerating → red. That
 *    matters more than it looks: `wrangler d1 migrations apply` would pick the
 *    new file up for every D1 tenant while every DO tenant stayed one version
 *    behind, and nothing else in the repo compares the two.
 *  * A migration EDITED in place → red, byte-for-byte. The tenant schema is
 *    append-only by convention (`test/d1/schema.test.ts` pins column order as
 *    the evidence that `0001` was never edited), and an in-place edit that
 *    reached only one of the two backends is unrecoverable divergence.
 *
 * Plain node fs rather than a `?raw` glob, so the gate reads the same bytes an
 * operator would `cat`.
 */
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { TENANT_MIGRATIONS, TENANT_SCHEMA_VERSION } from "../src/tenant-schema-sql.js";

const sqlDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../sql/d1-ts/tenant",
);

/** `NNNN_*.sql`, sorted by filename — which IS the apply order. */
const FILES = readdirSync(sqlDir)
  .filter((name) => /^\d{4}_.*\.sql$/.test(name))
  .sort();

describe("the generated tenant schema module", () => {
  test("the scan found the real migration directory", () => {
    // An empty scan makes every assertion below vacuously true — the same
    // vacuity `test/mount-inventory.test.ts` and `test/source-hygiene.test.ts`
    // both open with.
    expect(FILES.length).toBeGreaterThanOrEqual(7);
    expect(FILES[0]).toBe("0001_init_tenant.sql");
  });

  test("covers exactly the files on disk, in filename order", () => {
    expect(TENANT_MIGRATIONS.map((migration) => `${migration.name}.sql`)).toEqual(FILES);
  });

  test("carries each file's bytes VERBATIM", () => {
    for (const [index, file] of FILES.entries()) {
      const onDisk = readFileSync(path.join(sqlDir, file), "utf8");
      expect(
        TENANT_MIGRATIONS[index]?.sql,
        `${file} differs from the generated copy — run \`node scripts/generate-tenant-schema-sql.mjs\``,
      ).toBe(onDisk);
    }
  });

  test("derives each version from the NNNN filename prefix", () => {
    for (const migration of TENANT_MIGRATIONS) {
      expect(migration.version).toBe(Number.parseInt(migration.name.slice(0, 4), 10));
    }
    // Ascending and gapless: the applier's version gate is `version > applied`,
    // so a gap would be skipped silently and a duplicate would be applied twice
    // — and four of these files are ALTER-only, which SQLite cannot re-apply.
    expect(TENANT_MIGRATIONS.map((migration) => migration.version)).toEqual(
      TENANT_MIGRATIONS.map((_, index) => index + 1),
    );
  });

  test("reports the last version as the current schema version", () => {
    expect(TENANT_SCHEMA_VERSION).toBe(TENANT_MIGRATIONS[TENANT_MIGRATIONS.length - 1]?.version);
  });
});
