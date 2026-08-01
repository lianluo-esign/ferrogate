/**
 * The WRITE half of `admin_api_key` — `static_api_keys` in the CONTROL
 * database, plus the two rules that keep the mint from becoming an escalation
 * primitive.
 *
 * ## What this closes
 *
 * `store/api_keys.ts::D1ApiKeyAuthenticator` resolves an operator credential in
 * one hop: `SELECT … FROM static_api_keys WHERE key_hash = ?`, probed with the
 * `sha256:`-tagged digest of the presented secret. **Nothing in this repo wrote
 * that table.** All six `admin_api_key` operations stored a
 * `control_plane_resources` DOCUMENT and stopped, and the schema deliberately
 * refuses a client-supplied `secret` while nothing minted one — so the
 * collection had no path to a working credential at all, and `DELETE` answered
 * `200 {"deleted": true}` over a row no authenticator had ever consulted. Rust
 * `handle_admin_api_key_upsert` mutated the config the authenticator read, so
 * the two could not diverge there.
 *
 * Same defect class as the RBAC write half (`store/rbac_registry.ts`), the
 * quota chain and the virtual-key credential.
 *
 * ## Two invariants that are security, not hygiene
 *
 * **1. `platform_operator` is ALWAYS 0.** The column exists because an
 * operator-authored static key MAY declare platform root (#515) — but a key
 * *minted through the admin API* must never, or any credential holding
 * `admin.write` in one tenant could mint itself platform root and read every
 * other tenant. Platform-root static keys are provisioned out of band (the
 * `CONTROL_PLANE_STATIC_API_KEYS` var, or a seeded row), which is a deliberate
 * deployment act rather than an API call. The column is bound to the literal
 * `0` here, and {@link clampMintedScopes} independently strips the field from
 * the document, so neither a passthrough body field nor a later document edit
 * can reach it.
 *
 * **2. A minted key never outranks its minter.** See {@link clampMintedScopes}.
 *
 * ## Ordering
 *
 * `static_api_keys` is a GRANT, so it obeys the same rule as
 * `store/rbac_registry.ts` and the opposite of `store/quota_registry.ts`: the
 * document is written first on create (a crash leaves a credential the operator
 * can see that does not yet authenticate) and the ROW is deleted first on
 * revoke (a crash leaves a credential that has already stopped authenticating).
 * A residual grant is the one residue that is not survivable.
 */
import { WILDCARD_SCOPE, hasScope } from "../ports.js";
import type { AuthContext, StoreRecord } from "../ports.js";

/** The typed table in `sql/d1-ts/control/0001_init_control.sql`. */
export const STATIC_API_KEYS_TABLE = "static_api_keys";

/** Rust `api_key.rs`: `fg_<hex>`. Shared shape with the virtual-key family. */
const SECRET_PREFIX = "fg_";

/** 24 random bytes, hex — the same width `routes/admin_virtual_key.ts` mints. */
export function mintApiKeySecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${SECRET_PREFIX}${hex}`;
}

/**
 * The scopes a credential minted by `auth` may carry.
 *
 * The rule is **a minted key never outranks its minter**, and it is enforced on
 * the DOCUMENT rather than only on the projected row, so the admin surface
 * reports the authority the credential actually has. (Clamping only the row
 * would recreate this whole family of defects one field down: the console would
 * list `["*"]` and the authenticator would grant something narrower.)
 *
 *  - a minter holding the wildcard may mint anything, including the wildcard;
 *  - `["*"]` requested by anyone else EXPANDS to the minter's own set rather
 *    than being dropped — "give it my access" is the common operator intent and
 *    silently minting a scopeless, permanently-403 credential would be a worse
 *    answer than a narrower one;
 *  - every other requested scope must be one the minter holds, or it is dropped;
 *  - requesting nothing at all yields the minter's own set. It must NOT yield
 *    SQL `NULL`, which this table defines as the WILDCARD (see the migration's
 *    comment: a static key with no scopes means ALL access) — "I did not say"
 *    becoming "everything" is exactly the inverted-default the quota chain was
 *    bitten by.
 *
 * `platform_operator` is deleted here as well: `adminRecordSchema` is a
 * passthrough, so an unrecognised body field would otherwise be persisted and
 * read back as though the operator had configured it.
 */
export function clampMintedScopes(
  body: Record<string, unknown>,
  auth: AuthContext,
): Record<string, unknown> {
  const { platform_operator: _refused, ...rest } = body;
  // A platform operator's authority is the wildcard whatever its scope list
  // says — `callerScope` already waves it past every tenant fence.
  const minter = auth.platformOperator ? [WILDCARD_SCOPE] : auth.scopes;
  const requested = Array.isArray(rest.scopes)
    ? rest.scopes.filter((entry): entry is string => typeof entry === "string")
    : null;

  // "I did not say" and "give it my access" are the same request, and both
  // resolve to the minter's own set — never to SQL NULL, which this table reads
  // as the wildcard.
  if (requested === null || requested.includes(WILDCARD_SCOPE)) {
    return { ...rest, scopes: [...minter] };
  }
  if (minter.includes(WILDCARD_SCOPE)) return { ...rest, scopes: requested };
  return { ...rest, scopes: requested.filter((scope) => hasScope(minter, scope)) };
}

/**
 * Whether a stored document can become a `static_api_keys` row.
 *
 * `key_hash` is both the join key and the value a presentation is matched on. A
 * document without one (a row predating the mint, or an edit that dropped it)
 * must not be projected: it would write a row keyed on the empty string, which
 * the next such document would then collide with on the primary key.
 */
export function staticKeyProjectable(record: StoreRecord): boolean {
  return typeof record.key_hash === "string" && record.key_hash.trim() !== "";
}

function scopesJson(value: unknown): string {
  if (!Array.isArray(value)) return "[]";
  return JSON.stringify(value.filter((entry): entry is string => typeof entry === "string"));
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Write (or overwrite) the `static_api_keys` row a document describes.
 *
 * The upsert is on `id` (UNIQUE) rather than on `key_hash` (the PRIMARY KEY)
 * and deliberately does NOT update `key_hash`: the digest is minted once, at
 * create, and a later `PUT`/`PATCH` must not be able to re-point an existing
 * credential id at a different secret. `routes/admin_api_key.ts` carries the
 * minted triple forward across a replace for the same reason.
 */
export async function projectStaticApiKey(
  db: D1Database,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ${STATIC_API_KEYS_TABLE}
         (key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix,
          created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         tenant_id = excluded.tenant_id,
         scopes_json = excluded.scopes_json,
         enabled = excluded.enabled,
         expires_at_unix = excluded.expires_at_unix,
         updated_at_unix = excluded.updated_at_unix`,
    )
    .bind(
      String(record.key_hash),
      String(record.id),
      typeof record.tenant_id === "string" && record.tenant_id !== "" ? record.tenant_id : null,
      // NEVER `null`: this table reads SQL NULL as the wildcard.
      scopesJson(record.scopes),
      record.enabled === false ? 0 : 1,
      finite(record.expires_at),
      nowUnix,
      nowUnix,
    )
    .run();
}

/**
 * Revoke the credential.
 *
 * Runs BEFORE the document is removed (see the module docblock), and is
 * addressed by `id` rather than by `key_hash` so a row whose digest the
 * document no longer agrees with is still revoked — a revocation that missed
 * because two copies of the hash had drifted is the exact failure this module
 * exists to remove.
 */
export async function unprojectStaticApiKey(db: D1Database, id: string): Promise<void> {
  await db.prepare(`DELETE FROM ${STATIC_API_KEYS_TABLE} WHERE id = ?`).bind(id).run();
}
