#!/usr/bin/env node
/**
 * Generates `packages/storage/src/platform-schema-sql.ts` from
 * `sql/d1-ts/platform/*.sql`.
 *
 * The platform twin of `generate-control-schema-sql.mjs`, for the same reason:
 * `PlatformDataObject` applies the platform schema to its own embedded SQLite
 * database on first wake, inside workerd, where there is no filesystem — and
 * `wrangler deploy`'s esbuild does not understand `?raw` imports, so a
 * vite-only import would be green under vitest and unbootable in production.
 * The bytes are INLINED, and
 * `packages/storage/test/platform-schema-sql.test.ts` gates that the inlined
 * bytes still equal the files on disk.
 *
 * ## Why `ordinal`, gated by NAME
 *
 * `PlatformDataObject` copies `ControlDataObject`'s applier, which records and
 * gates by migration NAME (its `platform_schema_applied` ledger). The platform
 * directory's `NNNN` prefixes are unique today, so a `MAX(version)` gate would
 * also work — but the name gate is strictly more general and matches the copied
 * skeleton, so each entry carries its 1-based POSITION in filename order
 * (`ordinal`) as bookkeeping and the applier keys on the name.
 *
 * Regenerate after adding or editing a platform migration:
 *
 *     node scripts/generate-platform-schema-sql.mjs
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sqlDir = path.join(repoRoot, "sql", "d1-ts", "platform");
const outFile = path.join(repoRoot, "packages", "storage", "src", "platform-schema-sql.ts");

/** `NNNN_name.sql`, sorted by FILENAME — which IS the apply order. */
export function readPlatformMigrations() {
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
 * Source: \`sql/d1-ts/platform/*.sql\` — the schema the platform Durable Object
 * (\`PlatformDataObject\`, exactly one instance) applies to its own embedded
 * SQLite database on first wake.
 *
 * Regenerate with:
 *
 *     node scripts/generate-platform-schema-sql.mjs
 *
 * \`packages/storage/test/platform-schema-sql.test.ts\` re-reads the directory
 * from disk and compares byte-for-byte, so an edit here that does not
 * correspond to an edit there is red — and so is a migration added to
 * \`sql/d1-ts/platform/\` without regenerating.
 *
 * \`ordinal\` is the 1-based position in filename order; the applier gates by
 * NAME (see the generator's docblock).
 */

/** One platform migration file, exactly as it sits in \`sql/d1-ts/platform/\`. */
export interface PlatformMigration {
  /** 1-based position in filename apply order. */
  readonly ordinal: number;
  /** The filename without \`.sql\`; the applier's ledger key. */
  readonly name: string;
  /** The file's verbatim contents, comments and all. */
  readonly sql: string;
}

/** Every platform migration, ascending by filename. Order IS the contract. */
export const PLATFORM_MIGRATIONS: readonly PlatformMigration[] = [
${entries}
];
`;
}

const migrations = readPlatformMigrations();
mkdirSync(path.dirname(outFile), { recursive: true });
writeFileSync(outFile, render(migrations), "utf8");

// Hand the result to biome, for the same reason the control generator does:
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
