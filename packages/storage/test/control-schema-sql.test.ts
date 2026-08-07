/**
 * The drift gate on `src/control-schema-sql.ts` — the control twin of
 * `test/tenant-schema-sql.test.ts`, and red for the same two drifts:
 *
 *  * A migration ADDED to `sql/d1-ts/control/` without regenerating → red.
 *    `wrangler d1 migrations apply` would pick the new file up for a
 *    D1-resident control database while the control object stayed one file
 *    behind, and nothing else in the repo compares the two.
 *  * A migration EDITED in place → red, byte-for-byte.
 *
 * Plus the one control-specific invariant: ordinals are POSITIONS, because
 * the `NNNN` prefixes are non-unique here (three `0003_*` files) and the
 * applier gates by NAME — see the generator's docblock.
 */
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { CONTROL_MIGRATIONS } from "../src/control-schema-sql.js";

const sqlDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../sql/d1-ts/control",
);

/** `NNNN_*.sql`, sorted by filename — which IS the apply order. */
const FILES = readdirSync(sqlDir)
  .filter((name) => /^\d{4}_.*\.sql$/.test(name))
  .sort();

describe("the generated control schema module", () => {
  test("the scan found the real migration directory", () => {
    // An empty scan makes every assertion below vacuously true.
    expect(FILES.length).toBeGreaterThanOrEqual(20);
    expect(FILES[0]).toBe("0001_init_control.sql");
  });

  test("covers exactly the files on disk, in filename order", () => {
    expect(CONTROL_MIGRATIONS.map((migration) => `${migration.name}.sql`)).toEqual(FILES);
  });

  test("carries each file's bytes VERBATIM", () => {
    for (const [index, file] of FILES.entries()) {
      const onDisk = readFileSync(path.join(sqlDir, file), "utf8");
      expect(
        CONTROL_MIGRATIONS[index]?.sql,
        `${file} differs from the generated copy — run \`node scripts/generate-control-schema-sql.mjs\``,
      ).toBe(onDisk);
    }
  });

  test("ordinals are gapless 1-based positions, and names are unique", () => {
    expect(CONTROL_MIGRATIONS.map((migration) => migration.ordinal)).toEqual(
      CONTROL_MIGRATIONS.map((_, index) => index + 1),
    );
    // Name uniqueness is what makes the name-keyed ledger sound. Filenames in
    // one directory are unique by construction; this pins that the generator
    // never starts deriving names some other way.
    expect(new Set(CONTROL_MIGRATIONS.map((migration) => migration.name)).size).toBe(
      CONTROL_MIGRATIONS.length,
    );
  });

  test("the directory really does carry duplicate NNNN prefixes", () => {
    // The reason the applier gates by NAME. If this ever becomes false —
    // the control directory renumbered to unique prefixes — the divergence
    // from the tenant applier stops being load-bearing and should be
    // reconsidered, so the fact is pinned rather than assumed.
    const prefixes = CONTROL_MIGRATIONS.map((migration) => migration.name.slice(0, 4));
    expect(new Set(prefixes).size).toBeLessThan(prefixes.length);
  });
});
