/**
 * The drift gate on `src/platform-schema-sql.ts` — the platform twin of
 * `test/control-schema-sql.test.ts`, and red for the same two drifts:
 *
 *  * A migration ADDED to `sql/d1-ts/platform/` without regenerating → red.
 *  * A migration EDITED in place → red, byte-for-byte.
 *
 * Unlike the control gate there is NO duplicate-prefix invariant and no
 * `>= N files` floor: the platform directory has a single file today with a
 * unique `NNNN` prefix. The applier still gates by NAME (the copied skeleton),
 * so name uniqueness and gapless ordinals are pinned all the same.
 */
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { PLATFORM_MIGRATIONS } from "../src/platform-schema-sql.js";

const sqlDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../sql/d1-ts/platform",
);

/** `NNNN_*.sql`, sorted by filename — which IS the apply order. */
const FILES = readdirSync(sqlDir)
  .filter((name) => /^\d{4}_.*\.sql$/.test(name))
  .sort();

describe("the generated platform schema module", () => {
  test("the scan found the real migration directory", () => {
    // An empty scan makes every assertion below vacuously true.
    expect(FILES.length).toBeGreaterThanOrEqual(1);
    expect(FILES[0]).toBe("0001_guardrail_evaluations.sql");
  });

  test("covers exactly the files on disk, in filename order", () => {
    expect(PLATFORM_MIGRATIONS.map((migration) => `${migration.name}.sql`)).toEqual(FILES);
  });

  test("carries each file's bytes VERBATIM", () => {
    for (const [index, file] of FILES.entries()) {
      const onDisk = readFileSync(path.join(sqlDir, file), "utf8");
      expect(
        PLATFORM_MIGRATIONS[index]?.sql,
        `${file} differs from the generated copy — run \`node scripts/generate-platform-schema-sql.mjs\``,
      ).toBe(onDisk);
    }
  });

  test("ordinals are gapless 1-based positions, and names are unique", () => {
    expect(PLATFORM_MIGRATIONS.map((migration) => migration.ordinal)).toEqual(
      PLATFORM_MIGRATIONS.map((_, index) => index + 1),
    );
    expect(new Set(PLATFORM_MIGRATIONS.map((migration) => migration.name)).size).toBe(
      PLATFORM_MIGRATIONS.length,
    );
  });
});
