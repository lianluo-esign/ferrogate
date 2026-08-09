/**
 * The console session's PLATFORM-OPERATOR credential — the one, superadmin-gated
 * writer of `static_api_keys.platform_operator = 1` in the whole tree (#912).
 *
 * ## Why this is a SEPARATE credential from the gateway session key
 *
 * `gateway_key.ts` mints the console's ordinary GATEWAY virtual key — an
 * `{kind:"tenant"}` credential fenced to the caller's own tenant, whatever tier
 * they hold. That is the credential a normal admin drives `/admin/v1/*` with,
 * and it must NEVER become a platform-root key: `store/api_keys.ts`'s
 * `D1NativeApiKeyAuthenticator` hard-writes `platformOperator:false` for exactly
 * that reason, and `store/static_keys.ts` hard-binds `platform_operator = 0` for
 * every key the admin API mints. Neither of those is touched here.
 *
 * A platform OPERATOR — a `superadmin` `admin_users` row — needs a credential
 * that resolves to `platformOperator:true`, and the ONLY authenticator that ever
 * emits that is `D1ApiKeyAuthenticator` reading a `static_api_keys` row whose
 * `platform_operator` column is `1`. So the console mints such a row, gated on
 * `superadmin`, and hands it back as a DISTINCT `platform_operator_api_key`
 * field. The tenant path is left exactly as it was.
 *
 * ## One key per superadmin, rotated by delete-then-insert
 *
 * The id is deterministic — `plat-op-${userId}` — so a superadmin has at most
 * one operator key at a time. Rotation is DELETE-then-INSERT rather than an
 * id-upsert: `key_hash` is the PRIMARY KEY of `static_api_keys`, and an upsert
 * keyed on `id` (the way `store/static_keys.ts::projectStaticApiKey` writes)
 * would collide on the old row's `key_hash` when the new secret hashes
 * differently. Deleting first makes the row's identity the USER, not the secret.
 *
 * ## Least privilege, not the wildcard
 *
 * `platform_operator = 1` already waves the credential past every tenant fence
 * (`callerScope` returns `{kind:"platform_operator"}` and the scope clamp treats
 * it as holding the wildcard). The explicit scope list is therefore the
 * credential's *console* authority, and it is the four concrete scopes a
 * platform console needs — NOT `["*"]`, which would be a strictly wider grant
 * than any operation this credential is minted to perform.
 */
import type { ControlPlaneDeps } from "../ports.js";
import { hashApiKeySecret } from "../store/api_keys.js";
import { STATIC_API_KEYS_TABLE, mintApiKeySecret } from "../store/static_keys.js";
import { ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS } from "./tokens.js";

/**
 * The scopes the operator credential carries on the console surface.
 *
 * Least-privilege: the credential's platform reach comes from
 * `platform_operator = 1`, not from a wildcard scope. These are the concrete
 * read/write scopes the platform console drives, and nothing wider.
 */
const OPERATOR_KEY_SCOPES: readonly string[] = [
  "admin.read",
  "admin.write",
  "assets.read",
  "assets.write",
];

/** The deterministic id of a superadmin's operator key — one per user. */
export function platformOperatorApiKeyId(userId: string): string {
  return `plat-op-${userId}`;
}

/**
 * Mint (or ROTATE) the platform-operator static credential for a superadmin.
 *
 * Returns the plaintext secret, shown once, or `null` when there is no control
 * database to write it to (the console answers 503 elsewhere, but this keeps the
 * mint a no-op rather than a throw when the binding is absent).
 *
 * DELETE-then-INSERT so a re-mint replaces the row keyed on the USER rather than
 * colliding on the previous secret's `key_hash` primary key.
 */
export async function provisionPlatformOperatorApiKey(
  deps: ControlPlaneDeps,
  userId: string,
): Promise<string | null> {
  const db = deps.controlDatabase;
  if (db === null) return null;

  const id = platformOperatorApiKeyId(userId);
  // Rotation: drop the prior row FIRST so the new `key_hash` cannot collide with
  // it on the primary key. The old secret stops authenticating from here.
  await db.prepare(`DELETE FROM ${STATIC_API_KEYS_TABLE} WHERE id = ?`).bind(id).run();

  const secret = mintApiKeySecret();
  const now = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      `INSERT INTO ${STATIC_API_KEYS_TABLE}
         (key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix,
          created_at_unix, updated_at_unix)
       VALUES (?, ?, NULL, 1, ?, 1, ?, ?, ?)`,
    )
    .bind(
      await hashApiKeySecret(secret),
      id,
      JSON.stringify(OPERATOR_KEY_SCOPES),
      now + ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
      now,
      now,
    )
    .run();
  return secret;
}

/**
 * Revoke a superadmin's platform-operator credential — the logout counterpart.
 *
 * Addressed by the deterministic id, so it removes whatever secret is currently
 * live for that user. A no-op when there is no control database, or when the
 * user never held one.
 */
export async function revokePlatformOperatorApiKey(
  deps: ControlPlaneDeps,
  userId: string,
): Promise<void> {
  const db = deps.controlDatabase;
  if (db === null) return;
  await db
    .prepare(`DELETE FROM ${STATIC_API_KEYS_TABLE} WHERE id = ?`)
    .bind(platformOperatorApiKeyId(userId))
    .run();
}
