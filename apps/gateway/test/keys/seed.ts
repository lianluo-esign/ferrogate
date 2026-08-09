/**
 * Test fixtures for the TWO-HOP directory credential model (#821).
 *
 * A virtual key now lives in TWO places, exactly as the deployed dual write puts
 * it there:
 *
 *  - a row in `api_key_directory` in the CONTROL database (the `CONTROL_DATA`
 *    singleton object, reached with the app's own `controlDatabaseFrom`), keyed
 *    by `key_hash` and carrying the owning tenant plus the fail-closed lifecycle
 *    columns; and
 *  - the AUTHORITATIVE `api_keys` row in that tenant's OWN database — here a
 *    per-tenant `TenantDataObject`, reached with the same
 *    `DurableObjectTenantDatabaseRouter` the resolver routes through.
 *
 * Both are seeded through {@link hashVirtualApiKeySecret} — the SAME construction
 * the resolver hashes the presented secret with — so a test can never prove the
 * resolver correct against a hash only the test knows how to make. The plaintext
 * secret is returned to the caller and never stored. Nothing here fakes a
 * database, a binding or a router: the two hops run over real `workerd` objects
 * that self-apply their schema on first wake.
 */
import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter, type TenantDatabaseRouter } from "@ferrogate/storage";
import { controlDatabaseFrom } from "../../src/control-data.js";
import {
  hashVirtualApiKeySecret,
  virtualApiKeyLast4,
  virtualApiKeyPrefix,
} from "../../src/keys/index.js";

/** The default tenant every fixture belongs to unless it overrides `tenantId`. */
export const DEFAULT_TENANT = "tenant_a";
/** The tenants whose per-tenant `api_keys` this suite writes and must clear. */
const SEEDED_TENANTS = ["tenant_a", "tenant_b"] as const;

/**
 * The CONTROL database — the `CONTROL_DATA` object facade.
 *
 * Throws — loudly, never a silent skip — when `CONTROL_DATA` is absent. A skipped
 * auth test is worse than a failing one: it looks green while proving nothing.
 */
export function controlDb(): D1Database {
  const db = controlDatabaseFrom(env);
  if (db === undefined) {
    throw new Error(
      "WIRING TODO — no CONTROL_DATA object bound.\n" +
        "  The two-hop directory resolver reads `api_key_directory` from CONTROL_DATA;\n" +
        "  bind the [[durable_objects.bindings]] CONTROL_DATA stanza in apps/gateway/wrangler.toml.",
    );
  }
  return db;
}

/** The tenant router — one `TenantDataObject` per tenant, no registry read. */
export function tenantRouter(): TenantDatabaseRouter {
  const namespace = (
    env as { TENANT_DATA?: ConstructorParameters<typeof DurableObjectTenantDatabaseRouter>[0] }
  ).TENANT_DATA;
  if (namespace === undefined) {
    throw new Error("WIRING TODO — no TENANT_DATA namespace bound; the second hop cannot route.");
  }
  return new DurableObjectTenantDatabaseRouter(namespace, controlDb());
}

/** One tenant's `api_keys` handle, self-migrated on first wake. */
export async function tenantDb(tenantId: string): Promise<D1Database> {
  return (await tenantRouter().forTenant(tenantId)).db;
}

/** Clear both halves of the dual write, so each test starts from a known state. */
export async function resetApiKeysTable(): Promise<void> {
  await controlDb().prepare("DELETE FROM api_key_directory").run();
  for (const tenantId of SEEDED_TENANTS) {
    await (await tenantDb(tenantId)).prepare("DELETE FROM api_keys").run();
  }
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
   * Override the stored hash outright — for the "malformed `key_hash` must never
   * authenticate" cases. When absent the row is hashed exactly as the control
   * plane hashes it. The SAME value is written into BOTH halves of the dual
   * write, because the directory is keyed by `api_keys.key_hash`.
   */
  readonly keyHash?: string;
  /** Override `last4`; only cosmetic under the hash-keyed lookup. */
  readonly last4?: string;
  /**
   * Seed ONLY the tenant `api_keys` row and NOT the directory — the "a directory
   * entry whose tenant row is gone" / "row in another tenant's database" cases.
   */
  readonly skipDirectory?: boolean;
  /**
   * Seed ONLY the directory and NOT the tenant row — the "directory names a key
   * whose tenant row is gone" case (a revoke that landed its second leg).
   */
  readonly skipTenantRow?: boolean;
  /** Write the tenant `api_keys` row into THIS tenant's database instead of `tenantId`. */
  readonly tenantRowIn?: string;
}

/** Insert one virtual key's directory + tenant rows. Returns the plaintext secret. */
export async function seedApiKey(options: SeedApiKeyOptions): Promise<string> {
  const keyHash = options.keyHash ?? (await hashVirtualApiKeySecret(options.secret));
  const keyPrefix = virtualApiKeyPrefix(options.secret) ?? "";
  const last4 = options.last4 ?? virtualApiKeyLast4(options.secret);
  const projectId = options.projectId ?? `${options.tenantId}_project`;
  const workspaceId = options.workspaceId ?? `${options.tenantId}_workspace`;
  const enabled = options.enabled === false ? 0 : 1;

  if (options.skipDirectory !== true) {
    await controlDb()
      .prepare(
        `INSERT OR REPLACE INTO api_key_directory (
           key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4,
           enabled, expires_at_unix, revoked_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        keyHash,
        options.id,
        options.tenantId,
        projectId,
        workspaceId,
        keyPrefix,
        last4,
        enabled,
        options.expiresAtUnix ?? null,
        options.revokedAtUnix ?? null,
      )
      .run();
  }

  if (options.skipTenantRow !== true) {
    const handle = await tenantDb(options.tenantRowIn ?? options.tenantId);
    await handle
      .prepare(
        `INSERT OR REPLACE INTO api_keys (
           id, workspace_id, tenant_id, project_id, name,
           key_prefix, key_hash, last4, enabled, scopes_json,
           allowed_models_json, allowed_providers_json,
           monthly_token_budget, request_limit_per_minute,
           expires_at_unix, revoked_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        options.id,
        workspaceId,
        options.tenantId,
        projectId,
        options.name ?? options.id,
        keyPrefix,
        keyHash,
        last4,
        enabled,
        JSON.stringify(options.scopes ?? []),
        JSON.stringify(options.allowedModels ?? []),
        JSON.stringify(options.allowedProviders ?? []),
        options.monthlyTokenBudget ?? null,
        options.requestLimitPerMinute ?? null,
        options.expiresAtUnix ?? null,
        options.revokedAtUnix ?? null,
      )
      .run();
  }

  return options.secret;
}

/**
 * Flip `enabled` to 0 on BOTH halves — what `DELETE /admin/v1/virtual-keys/{id}`
 * suspension does. The directory is checked first, so this denies immediately.
 */
export async function suspendApiKey(id: string, tenantId: string = DEFAULT_TENANT): Promise<void> {
  await controlDb().prepare("UPDATE api_key_directory SET enabled = 0 WHERE id = ?").bind(id).run();
  await (await tenantDb(tenantId))
    .prepare("UPDATE api_keys SET enabled = 0 WHERE id = ?")
    .bind(id)
    .run();
}

/**
 * Hard-delete the credential — the DIRECTORY row first (the revoke ordering) and
 * the tenant row with it. With no directory row the key is `unknown`, never a
 * lingering `key_suspended`.
 */
export async function deleteApiKey(id: string, tenantId: string = DEFAULT_TENANT): Promise<void> {
  await controlDb().prepare("DELETE FROM api_key_directory WHERE id = ?").bind(id).run();
  await (await tenantDb(tenantId)).prepare("DELETE FROM api_keys WHERE id = ?").bind(id).run();
}
