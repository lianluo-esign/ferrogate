/**
 * D1 test plumbing: a REAL `env.DB` with the REAL control-database migration
 * applied.
 *
 * `TEST_D1_SCHEMA` is bound by `vitest.config.ts`, which reads
 * `sql/d1-ts/control/` — the same directory `wrangler.toml`'s `migrations_dir`
 * points at. Nothing here restates a `CREATE TABLE`; if the migration renames a
 * column, these tests go red, which is the whole point of not keeping a fixture
 * copy of the schema.
 *
 * `applySchema()` belongs in `beforeAll` (the migration is idempotent and
 * bookkept in `d1_migrations`); `resetD1()` belongs in `beforeEach` and is what
 * actually gives each test a clean database — see its docblock for why the pool
 * does not do that for you.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import type { StoreRecord } from "../src/ports.js";
import { AUDIT_TABLE, RESOURCE_TABLE } from "../src/store/d1.js";

interface D1TestBindings {
  readonly DB: D1Database;
  readonly TEST_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

/** The database the Worker under test writes through. */
export function db(): D1Database {
  return (env as unknown as D1TestBindings).DB;
}

/** Apply `sql/d1-ts/control/`. Call once per file, in `beforeAll`. */
export async function applySchema(): Promise<void> {
  const bindings = env as unknown as D1TestBindings;
  await applyD1Migrations(bindings.DB, bindings.TEST_D1_SCHEMA);
}

/**
 * Empty the two tables this app writes. Call in `beforeEach`.
 *
 * The pool does NOT roll a test's D1 writes back (the old `isolatedStorage`
 * switch is gone from `@cloudflare/vitest-pool-workers` 0.18's `cloudflareTest`
 * plugin), and the database is persisted under `.wrangler/state`, so without
 * this a passing assertion could be a previous test's — or a previous RUN's —
 * leftover row. Truncating is also honest about what it does not do: it leaves
 * the schema alone, so the migration still only runs once.
 */
export async function resetD1(): Promise<void> {
  await db().batch([
    db().prepare(`DELETE FROM ${RESOURCE_TABLE}`),
    db().prepare(`DELETE FROM ${AUDIT_TABLE}`),
  ]);
}

/**
 * Insert rows the way the store does, for the read-only collections that have
 * no create route (`models`, `providers`, `metering-events`, …).
 *
 * Deliberately raw SQL rather than a call into `D1ControlPlaneStore`: a fixture
 * built with the code under test cannot show that the code under test reads what
 * is actually in the table.
 */
export async function seedD1(collection: string, records: readonly StoreRecord[]): Promise<void> {
  if (records.length === 0) return;
  await db().batch(
    records.map((record) =>
      db()
        .prepare(
          `INSERT INTO ${RESOURCE_TABLE}
             (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, 1, ?, ?)`,
        )
        .bind(collection, record.id, JSON.stringify(record), 1, 1),
    ),
  );
}

/** The raw stored document, read straight out of the table. */
export async function rawDocument(
  collection: string,
  id: string,
): Promise<Record<string, unknown> | null> {
  const row = await db()
    .prepare(
      `SELECT document_json FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`,
    )
    .bind(collection, id)
    .first<{ document_json: string }>();
  return row === null ? null : (JSON.parse(row.document_json) as Record<string, unknown>);
}

/** The storage revision of a stored row, or `null` when it is gone. */
export async function rawRevision(collection: string, id: string): Promise<number | null> {
  const row = await db()
    .prepare(`SELECT revision FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`)
    .bind(collection, id)
    .first<{ revision: number }>();
  return row === null ? null : row.revision;
}

/** One decoded `audit_events` row. */
export interface AuditRow {
  readonly id: string;
  readonly request_id: string;
  readonly tenant: string | null;
  readonly occurred_at_unix: number;
  readonly audit: Record<string, unknown>;
}

/** Every audit row written so far, oldest first. */
export async function auditRows(): Promise<readonly AuditRow[]> {
  const rows = await db()
    .prepare(`SELECT id, request_id, tenant, occurred_at_unix, audit_json FROM ${AUDIT_TABLE}`)
    .all<{
      id: string;
      request_id: string;
      tenant: string | null;
      occurred_at_unix: number;
      audit_json: string;
    }>();
  return rows.results.map((row) => ({
    id: row.id,
    request_id: row.request_id,
    tenant: row.tenant,
    occurred_at_unix: row.occurred_at_unix,
    audit: JSON.parse(row.audit_json) as Record<string, unknown>,
  }));
}
