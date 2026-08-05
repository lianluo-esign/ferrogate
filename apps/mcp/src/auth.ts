/**
 * The DURABLE {@link AuthPort} — the last port in `src/ports.ts` whose only
 * implementation was an in-memory dev table.
 *
 * ## What this closes
 *
 * `portsBound` used to be `env.FG_DEV_IN_MEMORY_PORTS === "1"` and nothing
 * else, which meant a PRODUCTION deployment of `ferrogate-mcp` — one that
 * correctly refused to set the dev flag — answered `503 mcp_auth_unavailable`
 * on every authenticated surface and `503 not_ready` on `GET /readyz`, forever.
 * The identity, flow and catalog halves were already durable; authenticating a
 * caller is a precondition for all of them, so the Worker was unusable.
 *
 * The marker on `portsBound` said this was "NOT a platform limit — a cross-app
 * wiring deferral", naming two ways out: a `[[services]]` binding to
 * `apps/control-plane`, or a shared D1 read of its key tables. The SECOND one
 * needs no new binding at all: this Worker already binds the CONTROL database
 * as `env.DB` (`wrangler.toml`, `database_name = "ferrogate-control"`), which
 * is the database `sql/d1-ts/control/0001_init_control.sql` creates
 * `static_api_keys` and `api_key_directory` in. So the credential tables were
 * already reachable from here; what was missing was the reader.
 *
 * ## The two legs, in Rust's order
 *
 * Clean-room port of `crates/ferrogate-gateway/src/auth.rs::authenticate`, the
 * same chain `apps/gateway/src/keys/resolver.ts` and
 * `apps/control-plane/src/store/api_keys.ts` implement:
 *
 *  1. **STATIC / operator keys** — `static_api_keys` in the CONTROL database.
 *     Account-global by construction (a platform-operator key has no owning
 *     tenant), so every column it needs is in the one database this Worker
 *     binds. This leg is COMPLETE here.
 *  2. **NATIVE / virtual keys** — `api_key_directory` in the CONTROL database
 *     maps the credential hash to its tenant (the lookup that PRODUCES the
 *     tenant id cannot itself be tenant-routed), then `@ferrogate/storage`'s
 *     `EnvBindingTenantDatabaseRouter` opens that tenant's own database for the
 *     `api_keys` row that is the AUTHORITY for scopes. Two hops, never a
 *     fan-out.
 *  3. **fallback** — an optional {@link AuthPort} consulted only when neither
 *     table knows the credential. `resolvePorts` passes the in-memory dev table
 *     there, so a durable row can never be overruled by a dev key, and a
 *     deployment with no dev flag has no fallback at all.
 *
 * ## The 401-vs-403 taxonomy — the invariant this file exists to hold
 *
 * | presented credential                      | answer                       |
 * |-------------------------------------------|------------------------------|
 * | no/!Bearer `Authorization`                | 401 `unauthenticated`        |
 * | unknown to every leg                      | 401 `invalid_api_key`        |
 * | **disabled** (`enabled = 0`)              | 401 `invalid_api_key`        |
 * | **revoked** (`revoked_at_unix` set)       | 401 `invalid_api_key`        |
 * | **expired** (`expires_at_unix <= now`)    | 401 `invalid_api_key`        |
 * | directory row with no tenant `api_keys` row | 401 `invalid_api_key`      |
 * | tenant with no registry row               | 401 `invalid_api_key`        |
 * | resolved, but missing the operation scope | 403 `insufficient_scope`     |
 * | control D1 read failed                    | 503 `mcp_auth_unavailable`   |
 * | tenant registered but its binding is gone | 503 `mcp_auth_unavailable`   |
 *
 * **A suspended key is 401, NOT 403**, and every refusal above the scope row is
 * the SAME 401 an unknown key gets: key state is never disclosed, so an
 * attacker cannot use the status code to learn that a guessed secret exists.
 * That is the repeat defect this project has been bitten by
 * (`docs/rewrite/PORT-PLAN.md` "parity verification" #4). 403 is reserved for a
 * caller who IS authenticated and merely lacks the scope.
 *
 * ## Cross-tenant isolation
 *
 * {@link virtualKeyContext} writes `platformOperator: false` as a LITERAL and
 * reads no row field to get there, so no value in any tenant database —
 * hostile, corrupted or otherwise — can turn a tenant key into an operator key.
 * Rust's `durable_virtual_key_is_never_platform_root` invariant, structural
 * rather than checked.
 *
 * ## The ADMISSION half lives next door, and is now mounted
 *
 * The ladder above is the CREDENTIAL half of Rust's `authenticate()`. The
 * ADMISSION half — `finalize_auth`: `403 quota_scope_disabled`,
 * `429 monthly_budget_exceeded`, `429 wallet_balance_exhausted`,
 * `429 rate_limit_exceeded`, `503 quota_resolution_unavailable` — used to be
 * absent from this Worker entirely, so a credential refused on
 * `/v1/chat/completions` was ADMITTED on MCP `tools/call`, which spends real
 * provider money (`docs/rewrite/CUTOVER-READINESS.md` finding D1).
 *
 * It is now `src/admission/`, called by `src/http.ts::authenticateRequest`
 * immediately after this file resolves the credential — the same position
 * `finalize_auth` occupies inside Rust's `authenticate()`. The one thing THIS
 * file owes it is {@link AuthContext.requestLimitPerMinute}: the TOK-12 per-key
 * cap lives on the tenant `api_keys` row, so the leg that opens that row is the
 * only place it can be read.
 */
import {
  StorageError,
  backfillTenantConfigurationPolicy,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
} from "@ferrogate/storage";

import type { AuthContext, AuthError, AuthPort } from "./ports.js";
import { hasScope } from "./ports.js";

/** Operator-authored keys (CONTROL database). */
export const STATIC_API_KEY_TABLE = "static_api_keys";
/** The credential→tenant routing index (CONTROL database). Never trusted for authz. */
export const API_KEY_DIRECTORY_TABLE = "api_key_directory";
/** The AUTHORITY for a virtual key's scopes (TENANT database). */
export const TENANT_API_KEY_TABLE = "api_keys";
/** RBAC edges (CONTROL database) — where `permissions` on {@link AuthContext} comes from. */
export const ROLE_TABLE = "roles";
export const TENANT_ROLE_BINDING_TABLE = "tenant_role_bindings";

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
 * Rust `hash_virtual_api_key_secret` — the ONE construction FerroGate mints and
 * the exact value `static_api_keys.key_hash` / `api_keys.key_hash` hold.
 *
 * There is deliberately NO fallback lookup on the raw secret. Because every
 * probe carries the `"sha256:"` tag and a full digest, a row that stored the
 * PLAINTEXT secret (the accident that matters) can never be matched — the
 * fail-closed rule is structural, not a code path that could be forgotten.
 */
export async function hashApiKeySecret(secret: string): Promise<string> {
  return `sha256:${await sha256Hex(secret.trim())}`;
}

/**
 * `scopes_json` for an OPERATOR-authored static key.
 *
 * `NULL` ⇒ the wildcard `["*"]`; `'[]'` ⇒ the EMPTY set. The migration states
 * that asymmetry and it must not be normalized away — they mean opposite
 * things. Anything unparseable is the EMPTY set: a column this code cannot read
 * must never be the one that hands out platform-wide access.
 */
export function parseStaticScopes(raw: string | null): readonly string[] {
  if (raw === null) return ["*"];
  return parseStringArray(raw);
}

/**
 * `scopes_json` for a VIRTUAL key.
 *
 * Deliberately NOT {@link parseStaticScopes}: a durable key minted under a
 * tenant must never acquire the wildcard through an absent or unreadable
 * column, so `NULL` here is the empty set rather than `["*"]`.
 */
export function parseVirtualKeyScopes(raw: string | null): readonly string[] {
  if (raw === null) return [];
  return parseStringArray(raw);
}

function parseStringArray(raw: string): readonly string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((entry): entry is string => typeof entry === "string");
}

// ---------------------------------------------------------------------------
// Which control tables this deployment actually has
// ---------------------------------------------------------------------------

/**
 * The credential tables belong to the MIGRATIONS slice (`sql/d1-ts/control/`),
 * not to this app — the MCP identity tables live in `TenantDataObject` and are
 * applied by its migration ledger. This Worker deliberately creates no control
 * plane key tables, because a typo'd table name would silently become an empty
 * (and therefore permanently unauthenticable) credential store.
 *
 * So "the table is not there" is a real, distinguishable state, and it is
 * distinguished STRUCTURALLY rather than by string-matching a D1 error message:
 *
 *   * table ABSENT  ⇒ that leg is NOT PROVISIONED ⇒ skip it and fall through.
 *     A database with no `static_api_keys` has no rows to revoke either, so
 *     skipping it cannot resurrect a revoked credential.
 *   * table PRESENT ⇒ any query failure is an OUTAGE ⇒ 503, never 401. A
 *     database outage must not be indistinguishable from a revoked credential,
 *     and must not silently fall through to a dev table that may still list a
 *     key the database revoked.
 *
 * Cached per D1 handle for the life of the isolate, exactly like
 * `durable.ts`'s `migrated` set. CONSEQUENCE, stated rather than discovered: an
 * operator who applies the control migration under a LIVE isolate is not seen
 * by that isolate until it recycles. Provisioning precedes traffic, and the
 * alternative — a `sqlite_master` read on every authentication — is a hot-path
 * cost paid forever to serve a one-time transition.
 */
const tableCache = new WeakMap<D1Database, Promise<ReadonlySet<string>>>();

const PROBED_TABLES = [
  STATIC_API_KEY_TABLE,
  API_KEY_DIRECTORY_TABLE,
  ROLE_TABLE,
  TENANT_ROLE_BINDING_TABLE,
] as const;

async function controlTables(db: D1Database): Promise<ReadonlySet<string>> {
  const cached = tableCache.get(db);
  if (cached !== undefined) return cached;
  const probe = (async (): Promise<ReadonlySet<string>> => {
    const placeholders = PROBED_TABLES.map(() => "?").join(", ");
    const rows = await db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`)
      .bind(...PROBED_TABLES)
      .all<{ name: string }>();
    return new Set(rows.results.map((row) => row.name));
  })();
  tableCache.set(db, probe);
  // A FAILED probe must not be remembered as "no tables" — that would turn a
  // transient D1 blip into a permanently unauthenticable isolate.
  probe.catch(() => tableCache.delete(db));
  return probe;
}

/** Test seam: forget the probe for one database (an isolate recycle, simulated). */
export function forgetControlTableProbe(db: D1Database): void {
  tableCache.delete(db);
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

interface StaticKeyRow {
  readonly id: string;
  readonly tenant_id: string | null;
  readonly platform_operator: number;
  readonly scopes_json: string | null;
  readonly enabled: number;
  readonly expires_at_unix: number | null;
}

const STATIC_KEY_SQL = `SELECT id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix
   FROM ${STATIC_API_KEY_TABLE} WHERE key_hash = ?`;

interface DirectoryRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly project_id: string;
  readonly workspace_id: string;
  readonly enabled: number;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
}

const DIRECTORY_SQL = `SELECT id, tenant_id, project_id, workspace_id, enabled,
          expires_at_unix, revoked_at_unix
   FROM ${API_KEY_DIRECTORY_TABLE} WHERE key_hash = ?`;

interface TenantKeyRow {
  readonly id: string;
  readonly project_id: string;
  readonly workspace_id: string;
  readonly enabled: number;
  readonly scopes_json: string | null;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
  /**
   * TOK-12 `api_keys.request_limit_per_minute` — the per-CREDENTIAL RPM cap,
   * independent of the `quota_policies` chain.
   *
   * Read here because this is the only place the row is opened. Dropping it
   * (which this file did until the admission gate landed) leaves the column
   * inert: an operator sets a per-key rate limit, the admin API echoes it back,
   * and nothing on the request path ever counts against it.
   */
  readonly request_limit_per_minute: number | null;
}

const TENANT_KEY_SQL = `SELECT id, project_id, workspace_id, enabled, scopes_json,
          expires_at_unix, revoked_at_unix, request_limit_per_minute
   FROM ${TENANT_API_KEY_TABLE} WHERE key_hash = ?`;

const ROLE_PERMISSIONS_SQL = `SELECT r.permission_keys_json AS permission_keys_json
   FROM ${TENANT_ROLE_BINDING_TABLE} b
   JOIN ${ROLE_TABLE} r ON r.id = b.role_id
   WHERE b.tenant_id = ?`;

const TENANT_ROLE_PERMISSIONS_SQL = `SELECT b.role_id, c.permission_keys_json AS permission_keys_json
   FROM tenant_role_bindings AS b
   JOIN tenant_role_catalog AS c ON c.role_id = b.role_id
  WHERE b.tenant_id = ?`;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** 401 for EVERY unresolvable credential — state is never disclosed. */
const INVALID_KEY: AuthError = {
  status: 401,
  code: "invalid_api_key",
  message: "API key is not recognized",
};

const MISSING_BEARER: AuthError = {
  status: 401,
  code: "unauthenticated",
  message: "a Bearer API key is required",
};

function unavailable(detail: string): AuthError {
  return {
    status: 503,
    code: "mcp_auth_unavailable",
    // The DETAIL never names the credential — only the dependency that failed.
    message: `the MCP authentication store is unavailable: ${detail}`,
  };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

export interface D1McpAuthOptions {
  /**
   * Per-tenant database routing for the NATIVE leg. Omit it and a virtual key
   * resolves to NOTHING (401) rather than to a guessed scope set — the same
   * answer `apps/control-plane` gives for a tenant it cannot route.
   */
  readonly router?: TenantDatabaseRouter;
  /**
   * Consulted ONLY when no durable row matched. `resolvePorts` passes the
   * in-memory dev table here, which is why the order matters: a stale dev key
   * can never re-enable a credential the database revoked.
   */
  readonly fallback?: AuthPort;
  /** Injected unix-SECONDS clock, so expiry is deterministic in tests. */
  readonly now?: () => number;
}

export class D1McpAuth implements AuthPort {
  readonly #db: D1Database;
  readonly #router: TenantDatabaseRouter | undefined;
  readonly #fallback: AuthPort | undefined;
  readonly #now: () => number;

  constructor(db: D1Database, options: D1McpAuthOptions = {}) {
    this.#db = db;
    this.#router = options.router;
    this.#fallback = options.fallback;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async authenticate(headers: Headers, requiredScope: string): Promise<AuthContext | AuthError> {
    const header = headers.get("authorization");
    if (header === null || !/^Bearer\s+/i.test(header)) return MISSING_BEARER;
    const token = header.replace(/^Bearer\s+/i, "").trim();
    if (token === "") return MISSING_BEARER;

    const resolved = await this.#resolve(token, headers, requiredScope);
    if (isAuthErrorValue(resolved)) return resolved;

    // The ONE place a 403 can be produced: the caller IS authenticated and is
    // merely missing the operation's scope.
    if (!hasScope(resolved, requiredScope)) {
      return {
        status: 403,
        code: "insufficient_scope",
        message: `this credential is missing the ${requiredScope} scope`,
      };
    }
    return resolved;
  }

  async #resolve(
    token: string,
    headers: Headers,
    requiredScope: string,
  ): Promise<AuthContext | AuthError> {
    let tables: ReadonlySet<string>;
    try {
      tables = await controlTables(this.#db);
    } catch (error) {
      return unavailable(`control database probe failed: ${describe(error)}`);
    }

    const keyHash = await hashApiKeySecret(token);

    if (tables.has(STATIC_API_KEY_TABLE)) {
      const outcome = await this.#staticLeg(keyHash, tables);
      if (outcome !== undefined) return outcome;
    }
    if (tables.has(API_KEY_DIRECTORY_TABLE)) {
      const outcome = await this.#nativeLeg(keyHash, tables);
      if (outcome !== undefined) return outcome;
    }
    if (this.#fallback !== undefined) return this.#fallback.authenticate(headers, requiredScope);
    return INVALID_KEY;
  }

  /** `undefined` ⇒ this leg does not know the credential; try the next one. */
  async #staticLeg(
    keyHash: string,
    tables: ReadonlySet<string>,
  ): Promise<AuthContext | AuthError | undefined> {
    let row: StaticKeyRow | null;
    try {
      row = await this.#db.prepare(STATIC_KEY_SQL).bind(keyHash).first<StaticKeyRow>();
    } catch (error) {
      return unavailable(`static api key lookup failed: ${describe(error)}`);
    }
    if (row === null) return undefined;

    // Known credential, inactive ⇒ the SAME 401 an unknown one gets.
    if (row.enabled === 0) return INVALID_KEY;
    if (row.expires_at_unix !== null && row.expires_at_unix <= this.#now()) return INVALID_KEY;

    const tenantId = row.tenant_id ?? undefined;
    const permissions = await this.#permissions(tenantId, tables);
    if (isAuthErrorValue(permissions)) return permissions;

    const auth: AuthContext = {
      apiKeyId: row.id,
      scopes: parseStaticScopes(row.scopes_json),
      permissions,
      // Unlike a virtual key, an OPERATOR-authored static key MAY declare
      // platform root — that is why the column exists and why the table can
      // only live in the control database (#515).
      platformOperator: row.platform_operator === 1,
    };
    if (tenantId !== undefined) auth.organizationId = tenantId;
    return auth;
  }

  /** `undefined` ⇒ this leg does not know the credential; try the next one. */
  async #nativeLeg(
    keyHash: string,
    tables: ReadonlySet<string>,
  ): Promise<AuthContext | AuthError | undefined> {
    let directory: DirectoryRow | null;
    try {
      directory = await this.#db.prepare(DIRECTORY_SQL).bind(keyHash).first<DirectoryRow>();
    } catch (error) {
      return unavailable(`api key directory lookup failed: ${describe(error)}`);
    }
    if (directory === null) return undefined;

    // The directory is checked FIRST because it is the leg a revoke writes
    // first (`packages/storage/README.md` fixes that ordering), so a revoke
    // that crashed halfway has already disabled the credential here.
    if (
      !isActive(
        directory.enabled,
        directory.expires_at_unix,
        directory.revoked_at_unix,
        this.#now(),
      )
    )
      return INVALID_KEY;

    if (this.#router === undefined) {
      // No router mounted: the tenant `api_keys` row — the AUTHORITY for scopes
      // — is unreachable, and INVENTING a scope set is the one thing that must
      // never happen. Resolve to nothing.
      return INVALID_KEY;
    }

    let handle: TenantDatabaseHandle;
    try {
      handle = await this.#router.forTenant(directory.tenant_id);
    } catch (error) {
      // Same split `apps/control-plane/src/store/tenancy.ts` uses: NO registry
      // row means this deployment cannot authorize the key at all (401, and the
      // caller learns nothing); a registry row this Worker cannot REACH is a
      // deployment fault an operator must see (503).
      if (error instanceof StorageError && error.kind === "not_found") return INVALID_KEY;
      return unavailable(`tenant database routing failed: ${describe(error)}`);
    }

    let row: TenantKeyRow | null;
    try {
      row = await handle.db.prepare(TENANT_KEY_SQL).bind(keyHash).first<TenantKeyRow>();
    } catch (error) {
      return unavailable(`tenant api key lookup failed: ${describe(error)}`);
    }
    // The directory says the credential exists and the tenant database does
    // not. Indistinguishable from a typo, by design.
    if (row === null) return INVALID_KEY;
    if (!isActive(row.enabled, row.expires_at_unix, row.revoked_at_unix, this.#now())) {
      return INVALID_KEY;
    }

    const permissions = await this.#permissions(directory.tenant_id, tables);
    if (isAuthErrorValue(permissions)) return permissions;
    return virtualKeyContext(directory, row, permissions);
  }

  /**
   * RBAC permission keys bound to the tenant (`tenant_role_bindings` × `roles`).
   *
   * This is the real source for {@link AuthContext.permissions} — the field
   * `InMemoryEntitlements` reads `mcp.execute` off. A deployment that has not
   * provisioned the RBAC tables has no bindings, which is the empty set, which
   * is the fail-closed reading.
   */
  async #permissions(
    tenantId: string | undefined,
    tables: ReadonlySet<string>,
  ): Promise<readonly string[] | AuthError> {
    if (tenantId === undefined) return [];
    if (this.#router !== undefined && this.#router.backend === "durable_object") {
      try {
        const registered = await this.#db
          .prepare("SELECT 1 AS present FROM tenant_databases WHERE tenant_id = ?1")
          .bind(tenantId)
          .all();
        if ((registered.results ?? []).length === 0) return INVALID_KEY;
        await backfillTenantConfigurationPolicy(this.#db, this.#router, tenantId);
        const handle = await this.#router.forTenant(tenantId);
        const rows = await handle.db
          .prepare(TENANT_ROLE_PERMISSIONS_SQL)
          .bind(tenantId)
          .all<{ role_id: string; permission_keys_json: string | null }>();
        const keys = new Set<string>();
        for (const row of rows.results) {
          const shared = await this.#db
            .prepare("SELECT 1 AS present FROM roles WHERE id = ?1")
            .bind(row.role_id)
            .all();
          if ((shared.results ?? []).length === 0) continue;
          for (const key of parseVirtualKeyScopes(row.permission_keys_json)) keys.add(key);
        }
        return [...keys].sort();
      } catch (error) {
        return unavailable(`tenant RBAC lookup failed: ${describe(error)}`);
      }
    }
    if (!tables.has(ROLE_TABLE) || !tables.has(TENANT_ROLE_BINDING_TABLE)) return [];
    let rows: { results: { permission_keys_json: string | null }[] };
    try {
      rows = await this.#db
        .prepare(ROLE_PERMISSIONS_SQL)
        .bind(tenantId)
        .all<{ permission_keys_json: string | null }>();
    } catch (error) {
      return unavailable(`rbac lookup failed: ${describe(error)}`);
    }
    const keys = new Set<string>();
    for (const row of rows.results) {
      for (const key of parseVirtualKeyScopes(row.permission_keys_json)) keys.add(key);
    }
    return [...keys].sort();
  }
}

/** Rust `api_key_record_is_active`. An expiry exactly equal to now is EXPIRED. */
function isActive(
  enabled: number,
  expiresAtUnix: number | null,
  revokedAtUnix: number | null,
  nowUnix: number,
): boolean {
  if (enabled === 0) return false;
  if (revokedAtUnix !== null) return false;
  if (expiresAtUnix !== null && expiresAtUnix <= nowUnix) return false;
  return true;
}

/**
 * Build the caller context for a durable VIRTUAL key.
 *
 * `platformOperator` is the literal `false`. No row field is read to produce
 * it, so no D1 value can promote a tenant key to platform root.
 */
export function virtualKeyContext(
  directory: Pick<DirectoryRow, "id" | "tenant_id" | "project_id" | "workspace_id">,
  row: Pick<TenantKeyRow, "scopes_json"> & Partial<Pick<TenantKeyRow, "request_limit_per_minute">>,
  permissions: readonly string[],
): AuthContext {
  const context: AuthContext = {
    apiKeyId: directory.id,
    organizationId: directory.tenant_id,
    projectId: directory.project_id,
    workspaceId: directory.workspace_id,
    scopes: parseVirtualKeyScopes(row.scopes_json),
    permissions,
    platformOperator: false,
  };
  // `0` is a REAL Rust value meaning "refuse every request", so the field is
  // carried on an explicit null/undefined check and never on a falsy one —
  // `?? undefined` on a `0` would silently unlimit a deliberately frozen key.
  const perKeyRpm = row.request_limit_per_minute;
  if (perKeyRpm !== null && perKeyRpm !== undefined) context.requestLimitPerMinute = perKeyRpm;
  return context;
}

function isAuthErrorValue(value: unknown): value is AuthError {
  return (
    typeof value === "object" && value !== null && typeof (value as AuthError).status === "number"
  );
}
