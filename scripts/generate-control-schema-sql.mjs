#!/usr/bin/env node
/**
 * Generates `packages/storage/src/control-schema-sql.ts` from
 * `sql/d1-ts/control/*.sql`.
 *
 * The control twin of `generate-tenant-schema-sql.mjs`, for the same reason:
 * `ControlDataObject` applies the control schema to its own embedded SQLite
 * database on first wake, inside workerd, where there is no filesystem — and
 * `wrangler deploy`'s esbuild does not understand `?raw` imports, so a
 * vite-only import would be green under vitest and unbootable in production.
 * The bytes are INLINED, and
 * `packages/storage/test/control-schema-sql.test.ts` gates that the inlined
 * bytes still equal the files on disk.
 *
 * ## Why `ordinal`, not `version` (the one deliberate divergence)
 *
 * The tenant directory's `NNNN` prefixes are unique and gapless, so the tenant
 * applier gates on `MAX(version)`. The control directory's prefixes are NOT
 * unique — `0003_audit_chain`, `0003_request_log_columns` and
 * `0003_tenant_provider_credentials` all carry version 3, because `wrangler d1
 * migrations apply` bookkeeps by FILENAME and never cared. A `MAX(version)`
 * gate over these files would apply one of the three and silently skip the
 * other two. So each entry here carries its 1-based POSITION in filename
 * order (`ordinal`), and `ControlDataObject`'s applier records and gates by
 * NAME. The `NNNN` prefix remains part of the name and still drives the sort.
 *
 * Regenerate after adding or editing a control migration:
 *
 *     node scripts/generate-control-schema-sql.mjs
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sqlDir = path.join(repoRoot, "sql", "d1-ts", "control");
const outFile = path.join(repoRoot, "packages", "storage", "src", "control-schema-sql.ts");

/** `NNNN_name.sql`, sorted by FILENAME — which IS the apply order. */
export function readControlMigrations() {
  const files = readdirSync(sqlDir)
    .filter((name) => /^\d{4}_.*\.sql$/.test(name))
    .sort();
  if (files.length === 0) {
    throw new Error(`no NNNN_*.sql migrations found under ${sqlDir}`);
  }
  return files.map((file, index) => ({
    ordinal: index + 1,
    name: file.replace(/\.sql$/, ""),
    file,
    sql: readFileSync(path.join(sqlDir, file), "utf8"),
  }));
}

function literal(text) {
  // JSON.stringify is the only escaping that is total over arbitrary SQL text:
  // it handles quotes, backslashes, newlines and any stray control byte.
  return JSON.stringify(text);
}

function render(migrations) {
  const entries = migrations
    .map(
      (m) =>
        `  {\n    ordinal: ${m.ordinal},\n    name: ${literal(m.name)},\n    sql: ${literal(m.sql)},\n  },`,
    )
    .join("\n");
  return `/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Source: \`sql/d1-ts/control/*.sql\` (the same directory \`migrations_dir\`
 * names for the CONTROL D1 database, so the control Durable Object and a
 * D1-resident control database apply the SAME bytes in the SAME order).
 *
 * Regenerate with:
 *
 *     node scripts/generate-control-schema-sql.mjs
 *
 * \`packages/storage/test/control-schema-sql.test.ts\` re-reads the directory
 * from disk and compares byte-for-byte, so an edit here that does not
 * correspond to an edit there is red — and so is a migration added to
 * \`sql/d1-ts/control/\` without regenerating.
 *
 * \`ordinal\` is the 1-based position in filename order, NOT the \`NNNN\`
 * prefix: the control prefixes are non-unique (three \`0003_*\` files), so the
 * applier gates by NAME and the ordinal is bookkeeping only. See the
 * generator's docblock.
 */

/** One control migration file, exactly as it sits in \`sql/d1-ts/control/\`. */
export interface ControlMigration {
  /** 1-based position in filename apply order. NOT the (non-unique) NNNN prefix. */
  readonly ordinal: number;
  /** The filename without \`.sql\`; the applier's ledger key. */
  readonly name: string;
  /** The file's verbatim contents, comments and all. */
  readonly sql: string;
}

/** Every control migration, ascending by filename. Order IS the contract. */
export const CONTROL_MIGRATIONS: readonly ControlMigration[] = [
${entries}
];
`;
}

const migrations = readControlMigrations();
mkdirSync(path.dirname(outFile), { recursive: true });
writeFileSync(outFile, render(migrations), "utf8");

// Hand the result to biome, for the same reason the tenant generator does:
// the generated module must stay inside the same lint gate as written source.
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
    `ordinals 1..${migrations.length}\n`,
);
