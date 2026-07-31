/**
 * Durable credential resolution: operator-authored keys read from the control
 * database instead of a Worker var.
 *
 * ## What this closes
 *
 * `adapters.ts` used to resolve EVERY credential from
 * `CONTROL_PLANE_STATIC_API_KEYS` / `CONTROL_PLANE_NATIVE_API_KEYS` — plaintext
 * secrets in a Worker var, rotatable only by a redeploy. The control migration
 * (`sql/d1-ts/control/0001_init_control.sql`) ships `static_api_keys` for exactly
 * this: `key_hash` as the primary key, plus `id`, `tenant_id`,
 * `platform_operator`, `scopes_json`, `enabled` and `expires_at_unix`. Every
 * column the resolution needs is there, so the static/operator leg moves onto the
 * database here and the var becomes the fallback for a deployment that has not
 * provisioned rows yet.
 *
 * **Keys are stored HASHED.** The stored value is `"sha256:" + lowercase hex of
 * SHA-256 over the TRIMMED secret — byte-for-byte the construction Rust's
 * `hash_virtual_api_key_secret` mints and the one `apps/gateway/src/keys/hash.ts`
 * verifies against, so a row provisioned for one is readable by the other. A
 * plaintext secret mistakenly written into `key_hash` authenticates nothing —
 * see "Why there is no separate verify step" below for why that is structural.
 *
 * ## The 401-vs-403 taxonomy is NOT decided here
 *
 * This class only reports an {@link ApiKeyResolution} variant; `middleware/auth.ts`
 * owns the whole status mapping. The variants it can produce are the same ones
 * the var-backed authenticator produces for the same states, which is what keeps
 * "a disabled STATIC key is 403" and "a suspended NATIVE key is 401" from drifting
 * apart when the source of the row changes.
 *
 * ## PLATFORM LIMIT — the durable NATIVE/virtual leg is not resolvable here
 *
 * PORT-TODO(inventory-edge-control §5.2 / inventory-data-billing §1.7) — KEPT,
 * sharpened. Rust's `StorageApiKeyAuthenticator` resolves a durable virtual key
 * off the FULL `api_keys` row: scopes, allow-lists and `monthly_token_budget`.
 * On this platform those columns are in the PER-TENANT database
 * (`sql/d1-ts/tenant/0001_init_tenant.sql`), and a Worker cannot open a D1
 * database by uuid at runtime — `[[d1_databases]]` bindings are resolved at
 * DEPLOY time, and the set of tenant databases is created by the provisioning
 * flow, so they cannot be enumerated in `wrangler.toml`. The control database
 * carries only `api_key_directory`, the narrow credential→tenant routing index,
 * which DELIBERATELY has no `scopes_json` (a key's scopes are that tenant's
 * data and are physically isolated).
 *
 * Resolving a native key off the directory alone would therefore have to invent
 * its scopes. The closest correct behaviour, and the one implemented, is to
 * resolve NOTHING from the directory: a durable tenant key that this Worker
 * cannot authorize is `401 invalid_api_key`, indistinguishable from an unknown
 * key — the same answer Rust gives when `StorageApiKeyAuthenticator` returns
 * `None`, and the direction that discloses no key state. `test/api-keys-d1.test.ts`
 * pins that approximation. It closes the day D1 gains a runtime bind-by-uuid API
 * (the same follow-up `sql/d1-ts/control/0001_init_control.sql` names above
 * `api_key_directory`), or the day a control-plane service binding to a
 * per-tenant Worker is introduced.
 */
import type { ApiKeyAuthenticatorPort, ApiKeyResolution, AuthContext } from "../ports.js";

/** The durable operator-key table (`sql/d1-ts/control/0001_init_control.sql`). */
export const STATIC_API_KEY_TABLE = "static_api_keys";
/** The narrow credential→tenant routing index; read only to prove it is NOT trusted for authz. */
export const API_KEY_DIRECTORY_TABLE = "api_key_directory";

const UTF8 = new TextEncoder();

/** Lowercase, two chars per byte, no separator (Rust `encode_hex`). */
function encodeHex(bytes: Uint8Array): string {
  let encoded = "";
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

/** Lowercase hex SHA-256 of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", UTF8.encode(input));
  return encodeHex(new Uint8Array(digest));
}

/**
 * Rust `hash_virtual_api_key_secret`. The ONE construction FerroGate mints, and
 * the value a `static_api_keys.key_hash` row is expected to hold.
 */
export async function hashApiKeySecret(secret: string): Promise<string> {
  return `sha256:${await sha256Hex(secret.trim())}`;
}

/**
 * ## Why there is no separate "verify the hash" step
 *
 * `static_api_keys.key_hash` is the PRIMARY KEY, and the only value this module
 * ever probes it with is {@link hashApiKeySecret} of the presented secret. The
 * lookup IS the verification: an equality match on the `"sha256:"`-tagged digest.
 *
 * That makes the fail-closed rule structural rather than a code path that could
 * be forgotten — a row whose `key_hash` holds an untagged digest, a different
 * algorithm's digest, or (the accident that matters) the PLAINTEXT secret can
 * never be the row a probe matches, because every probe carries the `sha256:`
 * tag and a full SHA-256 hex digest. There is deliberately no fallback lookup on
 * the raw secret, and adding one would defeat the property.
 *
 * The gateway's resolver (`apps/gateway/src/keys/resolver.ts`) does carry an
 * explicit constant-time verify because it looks rows up by the PUBLIC
 * `key_prefix` index and must then check the candidate set. This table has no
 * prefix column and no candidate set — one row or none.
 */

/** One `static_api_keys` row, as read. */
interface StaticKeyRow {
  readonly key_hash: string;
  readonly id: string;
  readonly tenant_id: string | null;
  readonly platform_operator: number;
  readonly scopes_json: string | null;
  readonly enabled: number;
  readonly expires_at_unix: number | null;
}

const STATIC_KEY_SQL = `SELECT key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix
   FROM ${STATIC_API_KEY_TABLE} WHERE key_hash = ?`;

/**
 * `scopes_json` → the granted scope set.
 *
 * The asymmetry the migration spells out is preserved EXACTLY, because the two
 * values mean opposite things and normalizing them together would silently
 * promote a deliberately powerless key:
 *
 *  - `NULL`  ⇒ the wildcard `["*"]` — "no scopes listed" is operator intent for
 *    "all access", the same normalization the var-backed adapter applies.
 *  - `'[]'`  ⇒ the EMPTY set, which `ports.ts::hasScope` grants data-plane
 *    scopes with and never an `admin.*` one. On this Worker every operation is
 *    `admin.read`/`admin.write`, so such a key reaches nothing.
 *
 * A malformed `scopes_json` is the empty set, not the wildcard: a column this
 * code cannot read must not be the one that hands out platform-wide access.
 */
export function parseScopesJson(raw: string | null): readonly string[] {
  if (raw === null) return ["*"];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((entry): entry is string => typeof entry === "string");
}

export interface D1ApiKeyAuthenticatorOptions {
  /** Injected unix-SECONDS clock, so expiry is deterministic in tests. */
  readonly now?: () => number;
}

/**
 * The `ApiKeyAuthenticatorPort` over the control database, with a fallback.
 *
 * Order: the DURABLE row first, the declarative var second. A deployment that
 * has provisioned `static_api_keys` is decided by it — a stale var can never
 * re-enable a key the database disabled — while a deployment that has not
 * provisioned any rows keeps working exactly as it did.
 */
export class D1ApiKeyAuthenticator implements ApiKeyAuthenticatorPort {
  readonly #db: D1Database;
  readonly #fallback: ApiKeyAuthenticatorPort;
  readonly #now: () => number;

  constructor(
    db: D1Database,
    fallback: ApiKeyAuthenticatorPort,
    options: D1ApiKeyAuthenticatorOptions = {},
  ) {
    this.#db = db;
    this.#fallback = fallback;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async authenticate(presentedKey: string): Promise<ApiKeyResolution> {
    const trimmed = presentedKey.trim();
    if (trimmed === "") return this.#fallback.authenticate(presentedKey);

    let row: StaticKeyRow | null;
    try {
      row = await this.#db
        .prepare(STATIC_KEY_SQL)
        .bind(await hashApiKeySecret(trimmed))
        .first<StaticKeyRow>();
    } catch (error) {
      // 503, never 401: a database outage must not be indistinguishable from a
      // revoked credential, and it must not silently fall through to a var that
      // may still list a key the database revoked.
      return {
        outcome: "unavailable",
        detail: `static api key lookup failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    if (row === null) return this.#fallback.authenticate(presentedKey);

    if (row.enabled === 0) return { outcome: "static_key_disabled" };
    if (row.expires_at_unix !== null && row.expires_at_unix <= this.#now()) {
      return { outcome: "static_key_expired" };
    }

    const auth: AuthContext = {
      subject: row.id,
      tenancy: { tenantId: row.tenant_id },
      scopes: parseScopesJson(row.scopes_json),
      // Unlike a durable VIRTUAL key, an operator-authored static key MAY
      // declare platform root — that is the whole reason the table has the
      // column and the reason it lives in the control database rather than a
      // tenant one (#515).
      platformOperator: row.platform_operator === 1,
      source: "static_config",
    };
    return { outcome: "resolved", auth };
  }
}
