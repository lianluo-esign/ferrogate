/**
 * The WRITE half of the virtual-key credential — `api_keys` in the TENANT
 * database plus `api_key_directory` in the CONTROL database.
 *
 * ## What this closes
 *
 * `src/store/api_keys.ts`'s `D1NativeApiKeyAuthenticator` — and
 * `apps/gateway`'s and `apps/mcp`'s equivalents — resolve a presented native
 * credential in exactly two hops:
 *
 *  1. `api_key_directory` (CONTROL) maps `key_hash` → the tenancy chain;
 *  2. the routed tenant database's `api_keys` row supplies `scopes_json` and
 *     the budget.
 *
 * **Nothing in this repo wrote either row.** `POST /admin/v1/virtual-keys`
 * minted a secret, hashed it, and stored the whole thing as a
 * `control_plane_resources` DOCUMENT — a table no authenticator reads. So on
 * every deployment a freshly minted virtual key answered `401 invalid_api_key`
 * on the gateway, on the MCP ingress and on this Worker's own native leg, and
 * `disable` / `revoke` / `rotate` changed nothing that any credential check
 * could observe. The admin surface reported a working key that authenticated
 * nowhere.
 *
 * Same defect class as the MCP server catalog, the self-hosted-worker registry
 * and the quota chain: the reader mounted, the data path into it absent, every
 * suite green because both sides were tested against their own fixtures.
 *
 * ## Two databases, no transaction — the ORDER is the security property
 *
 * `packages/storage/README.md` fixes the ordering and
 * `D1NativeApiKeyAuthenticator`'s docblock explains why checking the directory
 * FIRST is what makes it pay off:
 *
 * > **create** writes the tenant row then the directory; **revoke** writes the
 * > directory then the tenant row.
 *
 * {@link VirtualKeyWriteDirection} is that rule, named. A write that LOOSENS
 * (create, enable) writes the tenant row first, so a crash in between leaves a
 * credential that does not yet authenticate. A write that TIGHTENS (disable,
 * revoke, rotate) writes the directory first, so a crash in between leaves a
 * credential that has ALREADY stopped authenticating. Both residual states fail
 * CLOSED; the inverse orderings leave a live credential the operator believes is
 * revoked, which is the one outcome that is not survivable.
 *
 * ## Rotation deletes the old directory row — it cannot upsert over it
 *
 * `api_key_directory`'s PRIMARY KEY is `key_hash`, so an `ON CONFLICT (key_hash)`
 * upsert of a rotated key would INSERT a second row and leave the old hash
 * sitting there, still resolving, forever: rotation would mint a new secret
 * without retiring the old one, which is worse than not rotating at all. The
 * directory leg is therefore a `DELETE … WHERE id = ?` followed by the INSERT,
 * issued as one `db.batch()` so no window exists in which the credential is
 * absent from a directory that still has to answer other requests.
 *
 * ## When nothing is written, NOTHING is written
 *
 * Both rows are required for a resolution, so the projection is all-or-nothing
 * on availability: no control database, or no provisioned tenant database, and
 * neither leg runs. Writing the directory half alone would publish a tenancy
 * routing entry for a credential whose authority row does not exist — the
 * authenticator would find the directory row, miss the tenant row, and answer
 * `401`, which is the same outcome with an extra misleading row in it.
 * `tenantDatabaseFor` still distinguishes "not provisioned" (skip) from
 * "provisioned but unroutable" (503) — see `store/tenancy.ts`.
 */
import type { TenantDatabaseHandle } from "@ferrogate/storage";
import type { StoreRecord } from "../ports.js";
import { API_KEY_DIRECTORY_TABLE, TENANT_API_KEY_TABLE } from "./api_keys.js";

/**
 * Which way a write moves the credential's authority, and therefore which leg
 * goes first. See the module docblock — this is not a style choice.
 */
export type VirtualKeyWriteDirection =
  /** create, enable — tenant row first; a crash leaves a key that cannot yet authenticate. */
  | "loosen"
  /** disable, revoke, rotate — directory first; a crash leaves a key that already cannot. */
  | "tighten";

function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringArrayJson(value: unknown): string {
  return JSON.stringify(
    Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [],
  );
}

/** SQLite has no boolean; the readers compare against 1. */
function bit(value: boolean): number {
  return value ? 1 : 0;
}

/**
 * `revoked_at_unix`, which is a TIMESTAMP and not a flag.
 *
 * The readers treat any non-null value as revoked, so an unrevoked key must
 * write `NULL` and a revoked one must write a time even if the document's
 * `revoked_at` is missing — `revoked: true` with a null timestamp would read as
 * a live key.
 */
function revokedAt(record: StoreRecord, nowUnix: number): number | null {
  if (record.revoked !== true) return null;
  return finite(record.revoked_at) ?? nowUnix;
}

/**
 * Whether a stored virtual-key document can become credential rows at all.
 *
 * `key_hash` is the join between the two tables AND the value a presentation is
 * matched on. A document without one (a row predating the mint, or an operator
 * `PATCH` that dropped it) must not be projected: it would write a directory
 * entry keyed on the empty string, which any second such key would then collide
 * with on the primary key.
 */
export function virtualKeyProjectable(record: StoreRecord): boolean {
  return text(record.key_hash, "") !== "" && text(record.tenant_id, "") !== "";
}

/**
 * Write (or overwrite) the credential's two rows.
 *
 * Both legs are upserts on the row's `id`, so a retried create, a rotation and
 * a lifecycle flip all converge rather than conflicting — the DOCUMENT store is
 * the arbiter of "does this key already exist" (it owns the 409), and these
 * rows follow it.
 */
export async function projectVirtualKey(
  controlDb: D1Database,
  handle: TenantDatabaseHandle,
  record: StoreRecord,
  nowUnix: number,
  direction: VirtualKeyWriteDirection,
): Promise<void> {
  const id = String(record.id);
  const keyHash = text(record.key_hash, "");
  const tenantId = handle.tenantId;
  const projectId = text(record.project_id, "");
  const workspaceId = text(record.workspace_id, "");
  const keyPrefix = text(record.key_prefix, "");
  const last4 = text(record.last4, "");
  const enabled = bit(record.enabled !== false);
  const expiresAt = finite(record.expires_at) ?? finite(record.expires_at_unix);
  const revoked = revokedAt(record, nowUnix);

  const tenantLeg = async (): Promise<void> => {
    await handle.db
      .prepare(
        `INSERT INTO ${TENANT_API_KEY_TABLE} (
           id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4,
           enabled, scopes_json, allowed_models_json, allowed_providers_json,
           monthly_token_budget, request_limit_per_minute,
           created_at_unix, updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           workspace_id = excluded.workspace_id,
           project_id = excluded.project_id,
           name = excluded.name,
           key_prefix = excluded.key_prefix,
           key_hash = excluded.key_hash,
           last4 = excluded.last4,
           enabled = excluded.enabled,
           scopes_json = excluded.scopes_json,
           allowed_models_json = excluded.allowed_models_json,
           allowed_providers_json = excluded.allowed_providers_json,
           monthly_token_budget = excluded.monthly_token_budget,
           request_limit_per_minute = excluded.request_limit_per_minute,
           updated_at_unix = excluded.updated_at_unix,
           rotated_at_unix = excluded.rotated_at_unix,
           expires_at_unix = excluded.expires_at_unix,
           revoked_at_unix = excluded.revoked_at_unix`,
      )
      .bind(
        id,
        workspaceId,
        tenantId,
        projectId,
        text(record.name, id),
        keyPrefix,
        keyHash,
        last4,
        enabled,
        // `parseVirtualKeyScopes` reads an unparseable column as the EMPTY set,
        // never the wildcard, so a malformed array here can only ever narrow.
        stringArrayJson(record.scopes),
        stringArrayJson(record.allowed_models),
        stringArrayJson(record.allowed_providers),
        finite(record.monthly_token_budget),
        finite(record.request_limit_per_minute),
        nowUnix,
        nowUnix,
        finite(record.rotated_at),
        expiresAt,
        revoked,
      )
      .run();
  };

  const directoryLeg = async (): Promise<void> => {
    // DELETE-then-INSERT, in ONE batch: the table is keyed on `key_hash`, so a
    // rotation that only inserted would leave the previous secret resolving.
    // See the module docblock.
    await controlDb.batch([
      controlDb.prepare(`DELETE FROM ${API_KEY_DIRECTORY_TABLE} WHERE id = ?`).bind(id),
      controlDb
        .prepare(
          `INSERT INTO ${API_KEY_DIRECTORY_TABLE} (
             key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4,
             enabled, expires_at_unix, revoked_at_unix, created_at_unix, updated_at_unix
           )
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (key_hash) DO UPDATE SET
             id = excluded.id,
             tenant_id = excluded.tenant_id,
             project_id = excluded.project_id,
             workspace_id = excluded.workspace_id,
             key_prefix = excluded.key_prefix,
             last4 = excluded.last4,
             enabled = excluded.enabled,
             expires_at_unix = excluded.expires_at_unix,
             revoked_at_unix = excluded.revoked_at_unix,
             updated_at_unix = excluded.updated_at_unix`,
        )
        .bind(
          keyHash,
          id,
          tenantId,
          projectId,
          workspaceId,
          keyPrefix,
          last4,
          enabled,
          expiresAt,
          revoked,
          nowUnix,
          nowUnix,
        ),
    ]);
  };

  if (direction === "tighten") {
    await directoryLeg();
    await tenantLeg();
    return;
  }
  await tenantLeg();
  await directoryLeg();
}
