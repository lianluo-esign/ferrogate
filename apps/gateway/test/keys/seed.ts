/**
 * Test fixtures: the real `api_keys` DDL, and a seeder that provisions rows the
 * way the control plane would.
 *
 * The schema here is `sql/d1/001_init_d1.sql` verbatim (columns, types,
 * defaults and the three indexes). Keeping the literal SQL rather than an
 * abbreviated table is deliberate: `enabled INTEGER NOT NULL DEFAULT 1` and
 * `scopes_json TEXT NOT NULL DEFAULT '[]'` are precisely the SQLite dialect
 * quirks `storedApiKeyFromRow` has to survive, and a hand-slimmed test table
 * would stop exercising them.
 *
 * Rows are seeded through {@link hashVirtualApiKeySecret} — the SAME function
 * the resolver verifies against — so a test can never accidentally prove the
 * resolver correct against a hash only the test knows how to make. The
 * plaintext secret is returned to the caller and never stored.
 */
import { env } from "cloudflare:test";
import {
  hashVirtualApiKeySecret,
  virtualApiKeyLast4,
  virtualApiKeyPrefix,
} from "../../src/keys/index.js";

/** `sql/d1/001_init_d1.sql`, the `api_keys` stanza. */
export const API_KEYS_DDL = `
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    last4 TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    allowed_models_json TEXT NOT NULL DEFAULT '[]',
    allowed_providers_json TEXT NOT NULL DEFAULT '[]',
    monthly_token_budget INTEGER,
    request_limit_per_minute INTEGER,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    rotated_at_unix INTEGER,
    expires_at_unix INTEGER,
    revoked_at_unix INTEGER
)`;

const API_KEYS_INDEXES = [
  "CREATE INDEX IF NOT EXISTS idx_api_keys_workspace ON api_keys(workspace_id)",
  "CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_project ON api_keys(tenant_id, project_id)",
  "CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)",
];

/**
 * The D1 binding under test.
 *
 * Throws — loudly, never a silent skip — when the binding is absent. A skipped
 * auth test is worse than a failing one: it looks green while proving nothing,
 * which is precisely how this project has shipped unheld invariants before. So
 * an unbound `DB` is a RED suite with a message that names the one-line fix.
 */
export function testDb(): D1Database {
  const db = (env as { DB?: D1Database }).DB;
  if (db === undefined) {
    throw new Error(
      "WIRING TODO — no D1 binding `DB`.\n" +
        "  Fix (one line, owned by the integrate step): add to apps/gateway/wrangler.toml\n" +
        '      [[d1_databases]]\n      binding = "DB"\n' +
        '      database_name = "ferrogate-control"\n      database_id = "replace-at-deploy"\n' +
        "  Until then run this slice with:\n" +
        "      cd apps/gateway && npx vitest run --config test/keys/vitest.config.ts\n" +
        "  These tests refuse to run against a mock — see src/keys/index.ts.",
    );
  }
  return db;
}

/** Create the table (once) and truncate it, so each test starts from a known state. */
export async function resetApiKeysTable(): Promise<D1Database> {
  const db = testDb();
  await db.exec(API_KEYS_DDL.trim().replace(/\n\s*/g, " "));
  for (const statement of API_KEYS_INDEXES) {
    await db.exec(statement);
  }
  await db.exec("DELETE FROM api_keys");
  return db;
}

/** A `fg_<48 hex>`-shaped secret, deterministic per label so failures are readable. */
export function testSecret(label: string): string {
  const body = [...label]
    .map((character) => character.codePointAt(0)?.toString(16).padStart(2, "0") ?? "00")
    .join("")
    .padEnd(48, "0")
    .slice(0, 48);
  return `fg_${body}`;
}

/** Everything a seeded row can override. Anything omitted takes the table default. */
export interface SeedApiKeyOptions {
  readonly id: string;
  readonly secret: string;
  readonly tenantId: string;
  readonly projectId?: string;
  readonly workspaceId?: string;
  readonly name?: string;
  readonly scopes?: readonly string[];
  readonly allowedModels?: readonly string[];
  readonly allowedProviders?: readonly string[];
  readonly enabled?: boolean;
  readonly monthlyTokenBudget?: number | null;
  readonly requestLimitPerMinute?: number | null;
  readonly expiresAtUnix?: number | null;
  readonly revokedAtUnix?: number | null;
  /**
   * Override the stored hash outright — for the `blake2b:` legacy-row case and
   * for the "malformed `key_hash` must never authenticate" case. When absent
   * the row is hashed exactly as the control plane hashes it.
   */
  readonly keyHash?: string;
  /** Override `last4`; `""` exercises Rust's "blank last4 matches anything". */
  readonly last4?: string;
}

/** Insert one `api_keys` row. Returns the plaintext secret for the test to present. */
export async function seedApiKey(options: SeedApiKeyOptions): Promise<string> {
  const db = testDb();
  const keyHash = options.keyHash ?? (await hashVirtualApiKeySecret(options.secret));
  const keyPrefix = virtualApiKeyPrefix(options.secret) ?? "";
  const last4 = options.last4 ?? virtualApiKeyLast4(options.secret);

  await db
    .prepare(
      `INSERT INTO api_keys (
         id, workspace_id, tenant_id, project_id, name,
         key_prefix, key_hash, last4, enabled, scopes_json,
         allowed_models_json, allowed_providers_json,
         monthly_token_budget, request_limit_per_minute,
         expires_at_unix, revoked_at_unix
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      options.id,
      options.workspaceId ?? `${options.tenantId}_workspace`,
      options.tenantId,
      options.projectId ?? `${options.tenantId}_project`,
      options.name ?? options.id,
      keyPrefix,
      keyHash,
      last4,
      options.enabled === false ? 0 : 1,
      JSON.stringify(options.scopes ?? []),
      JSON.stringify(options.allowedModels ?? []),
      JSON.stringify(options.allowedProviders ?? []),
      options.monthlyTokenBudget ?? null,
      options.requestLimitPerMinute ?? null,
      options.expiresAtUnix ?? null,
      options.revokedAtUnix ?? null,
    )
    .run();

  return options.secret;
}

/** Flip `enabled` to 0 — what `DELETE /admin/v1/virtual-keys/{id}` suspension does. */
export async function suspendApiKey(id: string): Promise<void> {
  await testDb().prepare("UPDATE api_keys SET enabled = 0 WHERE id = ?").bind(id).run();
}

/** Remove the row entirely — the hard-delete case. */
export async function deleteApiKey(id: string): Promise<void> {
  await testDb().prepare("DELETE FROM api_keys WHERE id = ?").bind(id).run();
}
