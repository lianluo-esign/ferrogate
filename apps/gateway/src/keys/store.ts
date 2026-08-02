/**
 * The `api_keys` table, read from D1.
 *
 * Clean-room port of `ferrogate_storage::StoredApiKey` (crates/
 * ferrogate-storage/src/lib.rs) and the `find_api_key_records_by_prefix`
 * repository call the Rust authenticator makes. The Postgres/Supabase backend
 * becomes the D1 binding; the row shape is `sql/d1/001_init_d1.sql` verbatim.
 *
 * SQLite dialect notes carried over from that migration: `BOOLEAN` is
 * `INTEGER 0/1`, `JSONB` is `TEXT` holding a JSON array, `BIGINT` is `INTEGER`.
 * Nothing in this file writes — the gateway data plane only ever reads keys.
 */

/** The one column set this module reads, named once. */
const API_KEY_COLUMNS = [
  "id",
  "workspace_id",
  "tenant_id",
  "project_id",
  "name",
  "key_prefix",
  "key_hash",
  "last4",
  "enabled",
  "scopes_json",
  "allowed_models_json",
  "allowed_providers_json",
  "monthly_token_budget",
  "request_limit_per_minute",
  "expires_at_unix",
  "revoked_at_unix",
  // #678 — the tags this virtual key stands for, defaulted onto a request whose
  // tenant policy says `default_from_key`. `sql/d1-ts/tenant/0003_*.sql`.
  "attribution_tags_json",
].join(", ");

/**
 * The prefix lookup, mirroring `find_api_key_records_by_prefix`.
 *
 * `key_prefix` is indexed (`idx_api_keys_prefix`), so this is one index seek
 * regardless of table size. It is a plain equality bind — never string
 * interpolation and never a `LIKE` — so a presented value cannot become SQL and
 * cannot widen the candidate set with a wildcard character.
 *
 * It deliberately does NOT filter on `enabled` / `revoked_at_unix` /
 * `expires_at_unix` in SQL: Rust evaluates liveness in `api_key_record_is_active`
 * after the fetch, and keeping that in one place means the 401-vs-403 decision
 * is made by code the tests can reach, not by a WHERE clause.
 */
const FIND_BY_PREFIX_SQL = `SELECT ${API_KEY_COLUMNS} FROM api_keys WHERE key_prefix = ?`;

/** A row of `api_keys` as D1 hands it back. */
interface ApiKeyRow {
  readonly id: string;
  readonly workspace_id: string | null;
  readonly tenant_id: string | null;
  readonly project_id: string | null;
  readonly name: string | null;
  readonly key_prefix: string | null;
  readonly key_hash: string | null;
  readonly last4: string | null;
  readonly enabled: number | null;
  readonly scopes_json: string | null;
  readonly allowed_models_json: string | null;
  readonly allowed_providers_json: string | null;
  readonly monthly_token_budget: number | null;
  readonly request_limit_per_minute: number | null;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
  readonly attribution_tags_json?: string | null;
}

/** Rust `StoredApiKey`, narrowed to the fields authentication actually uses. */
export interface StoredApiKey {
  readonly id: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly workspaceId: string;
  readonly name: string;
  readonly keyPrefix: string;
  readonly keyHash: string;
  readonly last4: string;
  readonly enabled: boolean;
  readonly scopes: readonly string[];
  readonly allowedModels: readonly string[];
  readonly allowedProviders: readonly string[];
  readonly monthlyTokenBudget: number | null;
  readonly requestLimitPerMinute: number | null;
  readonly expiresAtUnix: number | null;
  readonly revokedAtUnix: number | null;
  /**
   * #678 — `attribution_tags_json`, the tags this key stands for. Empty means
   * the key declares no attribution, which under a `default_from_key` policy is
   * a refusal rather than a pass (`attribution/policy.ts`).
   */
  readonly attributionTags: Readonly<Record<string, string>>;
}

/**
 * `serde(default)` for a `Vec<String>` column: a NULL, blank, malformed, or
 * non-array `*_json` value reads as the EMPTY list.
 *
 * Fail-closed for `allowed_models` / `allowed_providers` (an empty allow-list
 * means "unrestricted" in Rust, which is what those columns default to, so a
 * malformed value cannot narrow or widen anything it did not already).
 * For `scopes` the empty list is the "durable key minted without explicit
 * scopes" state, which `hasScope` already handles: data-plane scopes yes,
 * `admin.*` never. A corrupted `scopes_json` therefore degrades to the LEAST
 * privileged interpretation, never to a wildcard.
 */
function parseJsonStringArray(raw: string | null): readonly string[] {
  if (raw === null || raw.trim() === "") return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is string => typeof entry === "string");
  } catch {
    return [];
  }
}

/** `Option<u64>` column → `number | null`, rejecting non-finite/negative junk. */
function parseOptionalUnsigned(raw: number | null): number | null {
  if (raw === null || raw === undefined) return null;
  if (!Number.isFinite(raw) || raw < 0) return null;
  return Math.floor(raw);
}

/** D1 row → `StoredApiKey`. */
export function storedApiKeyFromRow(row: ApiKeyRow): StoredApiKey {
  return {
    id: row.id,
    tenantId: row.tenant_id ?? "",
    projectId: row.project_id ?? "",
    workspaceId: row.workspace_id ?? "",
    name: row.name ?? "",
    keyPrefix: row.key_prefix ?? "",
    keyHash: row.key_hash ?? "",
    last4: row.last4 ?? "",
    // SQLite has no boolean: anything other than a literal 1 is false, so a
    // NULL or a garbage value disables the key rather than enabling it.
    enabled: row.enabled === 1,
    scopes: parseJsonStringArray(row.scopes_json),
    allowedModels: parseJsonStringArray(row.allowed_models_json),
    allowedProviders: parseJsonStringArray(row.allowed_providers_json),
    monthlyTokenBudget: parseOptionalUnsigned(row.monthly_token_budget),
    requestLimitPerMinute: parseOptionalUnsigned(row.request_limit_per_minute),
    expiresAtUnix: parseOptionalUnsigned(row.expires_at_unix),
    revokedAtUnix: parseOptionalUnsigned(row.revoked_at_unix),
    attributionTags: parseJsonStringMap(row.attribution_tags_json ?? null),
  };
}

/**
 * `serde(default)` for the `attribution_tags_json` column: a NULL, blank,
 * malformed, or non-object value reads as the EMPTY map.
 *
 * Fail-CLOSED here, unlike the allowlist columns above: an unreadable
 * attribution map degrades to "this key declares nothing", which under a
 * `default_from_key` policy REFUSES the request rather than admitting untagged
 * spend. Non-string values are dropped rather than coerced, so a corrupted
 * entry can never satisfy a required tag with `"[object Object]"`.
 */
function parseJsonStringMap(raw: string | null): Readonly<Record<string, string>> {
  if (raw === null || raw.trim() === "") return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const map: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === "string" && value !== "") map[key] = value;
    }
    return map;
  } catch {
    return {};
  }
}

/**
 * The narrow storage surface the resolver needs. Injected rather than reached
 * for, so the resolver's semantics are testable without a database and so a
 * later `@ferrogate/storage` implementation can replace this one without
 * touching `resolver.ts`.
 */
export interface ApiKeyStore {
  findByPrefix(keyPrefix: string): Promise<readonly StoredApiKey[]>;
}

/** Thrown when D1 itself is unreachable, so the resolver can answer 503, not 401. */
export class ApiKeyStoreUnavailable extends Error {
  constructor(readonly detail: string) {
    super(`api key store is unavailable: ${detail}`);
    this.name = "ApiKeyStoreUnavailable";
  }
}

/** `ApiKeyStore` over a real D1 binding. */
export class D1ApiKeyStore implements ApiKeyStore {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async findByPrefix(keyPrefix: string): Promise<readonly StoredApiKey[]> {
    let result: D1Result<ApiKeyRow>;
    try {
      result = await this.#db.prepare(FIND_BY_PREFIX_SQL).bind(keyPrefix).all<ApiKeyRow>();
    } catch (error) {
      // A D1 outage is NOT "no such key". Collapsing the two would answer 401
      // for a perfectly valid credential and, worse, would look identical to a
      // revocation — so it is raised and the resolver turns it into a 503.
      throw new ApiKeyStoreUnavailable(error instanceof Error ? error.message : String(error));
    }
    return (result.results ?? []).map(storedApiKeyFromRow);
  }
}

/** In-memory `ApiKeyStore` for pure-logic tests. Not used in production. */
export class InMemoryApiKeyStore implements ApiKeyStore {
  readonly #rows: StoredApiKey[];

  constructor(rows: readonly StoredApiKey[] = []) {
    this.#rows = [...rows];
  }

  async findByPrefix(keyPrefix: string): Promise<readonly StoredApiKey[]> {
    return this.#rows.filter((row) => row.keyPrefix === keyPrefix);
  }
}
