#!/usr/bin/env node
/**
 * Generates `packages/storage/src/tenant-schema-sql.ts` from `sql/d1-ts/tenant/*.sql`.
 *
 * ## Why this file exists at all
 *
 * `TenantDataObject` applies the tenant schema to its OWN embedded SQLite
 * database on first wake. It therefore needs the migration TEXT at runtime,
 * inside workerd, where there is no filesystem — and the two build paths that
 * carry a Worker to workerd disagree about how to get it:
 *
 *   * vitest / vite transforms the sources, so `import sql from "…/0001.sql?raw"`
 *     works (and the test suites here already use `?raw` for exactly this);
 *   * `wrangler deploy` bundles with esbuild, which does NOT understand `?raw`.
 *
 * A construct that works under the test runner and fails at deploy is the worst
 * of the two, because the suite stays green on an unbootable Worker — the same
 * failure shape `apps/gateway/src/worker.ts`'s re-export comments describe. So
 * the bytes are INLINED into a plain TypeScript module that both bundlers
 * handle identically, and `packages/storage/test/tenant-schema-sql.test.ts` is
 * the gate that the inlined bytes still equal the files on disk.
 *
 * Regenerate after adding or editing a tenant migration:
 *
 *     node scripts/generate-tenant-schema-sql.mjs
 *
 * Forgetting to is not a silent drift: the drift test compares byte-for-byte
 * and names the file that disagrees.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sqlDir = path.join(repoRoot, "sql", "d1-ts", "tenant");
const outFile = path.join(repoRoot, "packages", "storage", "src", "tenant-schema-sql.ts");

/**
 * `NNNN_name.sql`, sorted by FILENAME.
 *
 * Filename order is the apply order, and it is not a stylistic choice: four of
 * the seven files are `ALTER TABLE … ADD COLUMN`, and
 * `packages/storage/test/d1/schema.test.ts` pins the resulting column ORDER of
 * `api_keys` / `usage_aggregate_rollups` / `usage_monthly_rollups` with an
 * ordered `toEqual`. Appended position is the evidence that nobody edited
 * `0001` in place, so an applier that reordered — or that folded the ALTERs
 * into the CREATEs — would produce a tenant object whose column order differs
 * from every migrated D1, silently.
 */
export function readTenantMigrations() {
  const files = readdirSync(sqlDir)
    .filter((name) => /^\d{4}_.*\.sql$/.test(name))
    .sort();
  if (files.length === 0) {
    throw new Error(`no NNNN_*.sql migrations found under ${sqlDir}`);
  }
  return files.map((file) => {
    const version = Number.parseInt(file.slice(0, 4), 10);
    if (!Number.isInteger(version) || version < 1) {
      throw new Error(`migration ${file} has no parseable NNNN version prefix`);
    }
    return {
      version,
      name: file.replace(/\.sql$/, ""),
      file,
      sql: readFileSync(path.join(sqlDir, file), "utf8"),
    };
  });
}

function literal(text) {
  // JSON.stringify is the only escaping that is total over arbitrary SQL text:
  // it handles quotes, backslashes, newlines and any stray control byte. A
  // template literal would need `${`/backtick escaping and would still be a
  // trap the day a migration contains one.
  return JSON.stringify(text);
}

function render(migrations) {
  const entries = migrations
    .map(
      (m) =>
        `  {\n    version: ${m.version},\n    name: ${literal(m.name)},\n    sql: ${literal(m.sql)},\n  },`,
    )
    .join("\n");
  return `/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Source: \`sql/d1-ts/tenant/*.sql\` (the same directory \`migrations_dir\` names
 * for every D1 tenant database, so a DO-resident tenant and a D1-resident
 * tenant apply the SAME bytes in the SAME order).
 *
 * Regenerate with:
 *
 *     node scripts/generate-tenant-schema-sql.mjs
 *
 * \`packages/storage/test/tenant-schema-sql.test.ts\` re-reads the directory from
 * disk and compares byte-for-byte, so an edit here that does not correspond to
 * an edit there is red — and so is a migration added to \`sql/d1-ts/tenant/\`
 * without regenerating.
 *
 * The bytes are inlined rather than imported because \`wrangler deploy\`'s
 * esbuild has no \`?raw\` and workerd has no filesystem; see the generator's
 * docblock for why the vite-only form would be green-but-unbootable.
 */

/** One tenant migration file, exactly as it sits in \`sql/d1-ts/tenant/\`. */
export interface TenantMigration {
  /** The \`NNNN\` filename prefix as an integer; the \`storage_schema_migrations.version\` value. */
  readonly version: number;
  /** The filename without \`.sql\`; the \`storage_schema_migrations.name\` value. */
  readonly name: string;
  /** The file's verbatim contents, comments and all. */
  readonly sql: string;
}

/** Every tenant migration, ascending by version. Order IS the contract. */
export const TENANT_MIGRATIONS: readonly TenantMigration[] = [
${entries}
];

/**
 * The version a freshly-migrated tenant database sits at.
 *
 * Derived from the array rather than hard-coded, so adding \`0008_*.sql\` and
 * regenerating is the whole change — there is no second place to forget.
 */
export const TENANT_SCHEMA_VERSION: number =
  TENANT_MIGRATIONS[TENANT_MIGRATIONS.length - 1]?.version ?? 0;
`;
}

const migrations = readTenantMigrations();
mkdirSync(path.dirname(outFile), { recursive: true });
writeFileSync(outFile, render(migrations), "utf8");

/**
 * Hand the result to biome.
 *
 * Not cosmetics: `bun run lint` checks `packages/**` and biome picks the quote
 * style from the string's own contents (single quotes when the SQL contains
 * more `"` than `'`, which varies file by file). A generator that guessed would
 * be red on some migrations and green on others, and the obvious "fix" for that
 * is to add the file to `biome.jsonc`'s ignore list — which would also stop
 * biome noticing a genuinely malformed generated module. Formatting here
 * instead keeps the file inside the same gate as hand-written source.
 */
const biome = path.join(repoRoot, "node_modules", ".bin", "biome");
if (existsSync(biome)) {
  execFileSync(biome, ["format", "--write", outFile], { stdio: "inherit" });
} else {
  process.stderr.write(
    `warning: ${path.relative(repoRoot, biome)} not found; run \`bun run format\` before committing\n`,
  );
}

process.stdout.write(
  `wrote ${path.relative(repoRoot, outFile)} — ${migrations.length} migrations, ` +
    `versions ${migrations[0].version}..${migrations[migrations.length - 1].version}\n`,
);
