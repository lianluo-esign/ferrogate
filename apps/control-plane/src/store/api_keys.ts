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
 * ## The durable NATIVE/virtual leg — CLOSED, and how
 *
 * This used to carry a `PORT_TODO(inventory-edge-control §5.2 /
 * inventory-data-billing §1.7)` claiming a platform limit: Rust's
 * `StorageApiKeyAuthenticator` resolves a durable virtual key off the FULL
 * `api_keys` row (scopes, allow-lists, `monthly_token_budget`), those columns
 * live in the PER-TENANT database, and "a Worker cannot open a D1 database by
 * uuid at runtime". The premise was right and the conclusion was wrong, and the
 * difference is the whole point of `@ferrogate/storage`'s tenant router:
 *
 * > A Worker cannot open a database by **uuid**. It can absolutely select one by
 * > **binding name** — `env[name]` is an ordinary runtime property lookup over a
 * > deploy-time-declared set. What was missing was not an API; it was the
 * > REGISTRY mapping tenant → binding name, which is the control database's
 * > `tenant_databases` table, read by `EnvBindingTenantDatabaseRouter`.
 *
 * That router had zero importers under any app's `src` when the marker was
 * written (`docs/rewrite/parity-audit-storage.md` §4.1), so the limit was real in
 * practice while being false in principle. It is now mounted
 * (`src/store/tenancy.ts`), and {@link D1NativeApiKeyAuthenticator} resolves the
 * native leg exactly as Rust does — two hops, never a fan-out:
 *
 *  1. `api_key_directory` in the CONTROL database maps the credential's hash to
 *     its tenant. This hop is what makes the whole thing possible: the lookup
 *     that PRODUCES the tenant id cannot itself be tenant-routed.
 *  2. the routed tenant database supplies `scopes_json` and the budget — the
 *     columns that are that tenant's data and are physically isolated from every
 *     other tenant's.
 *
 * The directory deliberately still has no `scopes_json`, and nothing here infers
 * one: a tenant whose database is not provisioned resolves to **nothing**
 * (`401 invalid_api_key`, indistinguishable from an unknown key), which is the
 * same answer Rust gives when `StorageApiKeyAuthenticator` returns `None`.
 *
 * PORT-TODO(L: inventory-data-billing §1.7) — the residual, stated honestly and far
 * narrower than what it replaced: routing a tenant still requires that tenant's
 * `[[d1_databases]]` stanza to have been deployed, so onboarding costs a
 * `wrangler deploy` and the tenant count is bounded by the Worker's binding
 * budget (`D1_BINDING_STRATEGIES.native_binding` in `@ferrogate/storage` states
 * the ceiling as "low hundreds"). Past that it needs a proxy Worker holding the
 * bindings behind a service binding, or sharding. It is a SCALING limit now, not
 * a capability one.
 */
import { StorageError, type TenantDatabaseRouter } from "@ferrogate/storage";
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

// ---------------------------------------------------------------------------
// The durable NATIVE / virtual key leg (two hops, never a fan-out)
// ---------------------------------------------------------------------------

/** One `api_key_directory` row (CONTROL database) — routing plus lifecycle bits. */
interface DirectoryRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly project_id: string;
  readonly workspace_id: string;
  readonly enabled: number;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
}

const DIRECTORY_SQL = `SELECT id, tenant_id, project_id, workspace_id, enabled, expires_at_unix, revoked_at_unix
   FROM ${API_KEY_DIRECTORY_TABLE} WHERE key_hash = ?`;

/** The tenant-database `api_keys` table — the AUTHORITY for a virtual key. */
export const TENANT_API_KEY_TABLE = "api_keys";

/** One `api_keys` row (TENANT database). */
interface TenantKeyRow {
  readonly id: string;
  readonly project_id: string;
  readonly workspace_id: string;
  readonly enabled: number;
  readonly scopes_json: string;
  readonly monthly_token_budget: number | null;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
}

const TENANT_KEY_SQL = `SELECT id, project_id, workspace_id, enabled, scopes_json,
          monthly_token_budget, expires_at_unix, revoked_at_unix
   FROM ${TENANT_API_KEY_TABLE} WHERE key_hash = ?`;

/**
 * `scopes_json` for a VIRTUAL key.
 *
 * Deliberately NOT {@link parseScopesJson}: that one maps `NULL` to the wildcard
 * `["*"]`, which is the right reading of an OPERATOR-authored static key ("no
 * scopes listed" has always meant "all access"). A durable virtual key is minted
 * under a tenant and must never be able to acquire the wildcard by an absent or
 * unreadable column — `ports.ts::hasScope` grants the empty set data-plane scopes
 * only and never an `admin.*` one, and every operation this Worker serves is
 * `admin.*`, so the empty set is the correct fail-closed reading of anything this
 * function cannot parse.
 */
export function parseVirtualKeyScopes(raw: string | null): readonly string[] {
  if (raw === null) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((entry): entry is string => typeof entry === "string");
}

/**
 * Rust `StorageApiKeyAuthenticator`: a durable/virtual key resolved off its own
 * tenant's `api_keys` row, reached through `@ferrogate/storage`'s tenant router.
 *
 * ## Every refusal is `key_suspended` → 401, never 403
 *
 * `middleware/auth.ts` collapses `key_suspended` onto the same
 * `401 invalid_api_key` an unknown key gets, which is the invariant
 * `ROUTE-MAP.md` numbers 6 and the defect the Rust tree was bitten by
 * (inventory-edge-control §5.2). Disabled, revoked, expired and
 * "the directory says this key exists but the tenant row is gone" are therefore
 * ALL indistinguishable from a typo: key state is not disclosed to an
 * unauthenticated caller. A 403 anywhere on this path would confirm that the
 * presented secret is a real credential.
 *
 * ## Both halves of the dual write are checked, and the directory goes first
 *
 * `api_key_directory` duplicates four lifecycle columns across two databases
 * with no transaction spanning them, so `packages/storage/README.md` fixes the
 * ordering: **create** writes the tenant row then the directory; **revoke**
 * writes the directory then the tenant row. Checking the directory first is what
 * makes that ordering pay off — a revoke that crashed after its first leg has
 * already disabled the credential here, and a create that crashed after its
 * first leg has not yet enabled one. Both partial states fail CLOSED.
 *
 * The tenant row is then checked too rather than trusted, because it is the
 * authority for the columns the directory does not carry and because the two can
 * legitimately disagree for a moment.
 *
 * ## An unroutable tenant is 503; an unprovisioned one is 401
 *
 * Same split as `src/store/tenancy.ts`, for the same reason. No registry row
 * means this deployment cannot authorize the key at all, and inventing scopes
 * for it is the one thing that must never happen — so it resolves to nothing and
 * falls through to `401`. A registry row this Worker cannot reach is a
 * deployment fault an operator must see, and `unavailable` (→ 503) says so
 * without disclosing anything about the key.
 */
export class D1NativeApiKeyAuthenticator implements ApiKeyAuthenticatorPort {
  readonly #controlDb: D1Database;
  readonly #router: TenantDatabaseRouter;
  readonly #fallback: ApiKeyAuthenticatorPort;
  readonly #now: () => number;

  constructor(
    controlDb: D1Database,
    router: TenantDatabaseRouter,
    fallback: ApiKeyAuthenticatorPort,
    options: D1ApiKeyAuthenticatorOptions = {},
  ) {
    this.#controlDb = controlDb;
    this.#router = router;
    this.#fallback = fallback;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async authenticate(presentedKey: string): Promise<ApiKeyResolution> {
    const trimmed = presentedKey.trim();
    if (trimmed === "") return this.#fallback.authenticate(presentedKey);
    const keyHash = await hashApiKeySecret(trimmed);

    let directory: DirectoryRow | null;
    try {
      directory = await this.#controlDb.prepare(DIRECTORY_SQL).bind(keyHash).first<DirectoryRow>();
    } catch (error) {
      // 503, never 401: an outage must not be indistinguishable from a revoked
      // credential, and must not fall through to a var that may still list a key
      // the database revoked.
      return {
        outcome: "unavailable",
        detail: `api key directory lookup failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    // Not a durable key. The static/operator leg and the declarative vars are
    // next, preserving Rust's `authenticate_with_admission` source ordering.
    if (directory === null) return this.#fallback.authenticate(presentedKey);

    if (this.#retired(directory))
      return { outcome: "key_suspended", reason: this.#reason(directory) };

    let tenantDb: D1Database;
    try {
      tenantDb = (await this.#router.forTenant(directory.tenant_id)).db;
    } catch (error) {
      if (error instanceof StorageError && error.kind === "not_found") {
        // No provisioned database ⇒ the scopes are unreachable ⇒ resolve
        // NOTHING. Falling back would let a declarative var speak for a durable
        // key the database owns.
        return { outcome: "unknown" };
      }
      return {
        outcome: "unavailable",
        detail: `tenant ${directory.tenant_id} database is unreachable: ${
          error instanceof Error ? error.message : String(error)
        }`,
      };
    }

    let row: TenantKeyRow | null;
    try {
      row = await tenantDb.prepare(TENANT_KEY_SQL).bind(keyHash).first<TenantKeyRow>();
    } catch (error) {
      return {
        outcome: "unavailable",
        detail: `tenant api key lookup failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    // The directory names a key whose tenant row is gone — a revoke that landed
    // its second leg, or a create that never did. Either way the authority for
    // its scopes does not exist, so it authenticates nothing.
    if (row === null) return { outcome: "key_suspended", reason: "revoked" };
    if (this.#retired(row)) return { outcome: "key_suspended", reason: this.#reason(row) };

    // Rust: `monthly_token_budget == 0` is an exhausted budget (429), which is a
    // property of the ACCOUNT rather than of the credential, so it is its own
    // outcome and not a suspension.
    if (row.monthly_token_budget === 0) return { outcome: "token_budget_exhausted" };

    const auth: AuthContext = {
      subject: row.id,
      tenancy: {
        tenantId: directory.tenant_id,
        // The TENANT row's placement wins over the directory's mirror: it is the
        // authority, and a key moved between workspaces must not be gated by a
        // stale copy.
        projectId: row.project_id,
        workspaceId: row.workspace_id,
      },
      scopes: parseVirtualKeyScopes(row.scopes_json),
      // #515: a durable key is minted under a tenant and can NEVER declare
      // platform root over this path, whatever its row says.
      platformOperator: false,
      source: "durable_native",
    };
    return { outcome: "resolved", auth };
  }

  /** Disabled, revoked or past its expiry — the three states that deny. */
  #retired(row: {
    readonly enabled: number;
    readonly expires_at_unix: number | null;
    readonly revoked_at_unix: number | null;
  }): boolean {
    if (row.enabled === 0) return true;
    if (row.revoked_at_unix !== null) return true;
    return row.expires_at_unix !== null && row.expires_at_unix <= this.#now();
  }

  /** Which of the three it was. Reported for logs only — all three are 401. */
  #reason(row: {
    readonly enabled: number;
    readonly expires_at_unix: number | null;
    readonly revoked_at_unix: number | null;
  }): "disabled" | "revoked" | "expired" {
    if (row.revoked_at_unix !== null) return "revoked";
    if (row.enabled === 0) return "disabled";
    return "expired";
  }
}
