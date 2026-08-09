/**
 * The TWO-HOP virtual/native API-key resolution seam, shared by every Worker
 * that authenticates a caller's bearer credential.
 *
 * ## Why a directory, and why two hops
 *
 * A `TenantDatabaseRouter` maps `tenantId -> handle`, but a gateway starts a
 * request holding only a bearer token and no tenant id. Something has to resolve
 * `credential -> tenant`, and that something CANNOT itself be tenant-routed — it
 * is the lookup that PRODUCES the tenant id. `api_key_directory` in the CONTROL
 * database is that narrow index: `key_hash` (the same value the tenant database's
 * `api_keys.key_hash` column holds) mapped to the owning tenant/project/workspace
 * plus the two fail-closed lifecycle columns. So resolution is exactly two hops,
 * never a fan-out:
 *
 *   1. `api_key_directory` (CONTROL) maps the credential's hash to its tenant.
 *   2. the routed tenant database supplies the AUTHORITATIVE `api_keys` row —
 *      scopes, allow-lists, budgets — the columns that are that tenant's data
 *      and are physically isolated from every other tenant's.
 *
 * This is the clean-room port of Rust's `StorageApiKeyAuthenticator`, and it is
 * the SINGLE implementation the gateway, the agent-runtime and (eventually) the
 * control plane share, so the taxonomy below cannot drift between them.
 *
 * ## The result is FACTUAL, never an HTTP decision
 *
 * This module reports {@link TwoHopApiKeyResolution} — a neutral description of
 * what the two hops found — and maps NOTHING onto a status code or onto a
 * consumer's own `ApiKeyResolution` enum. Each app owns:
 *
 *  - its own outcome variants and the 401/403/429/503 mapping,
 *  - whether a `no_directory_row`/`suspended` result falls through to a config
 *    fallback (Rust's `find_map` skip lets a suspended durable row still let the
 *    static table answer; the control plane returns the suspension directly —
 *    those are app policies, not facts about the row), and
 *  - whether `monthly_token_budget == 0` is a 429 (a property of the ACCOUNT,
 *    which the gateway and control plane enforce and the agent-runtime does not
 *    read at all).
 *
 * Keeping those OUT of here is what lets one implementation serve consumers whose
 * `AuthContext` shapes and fallback rules genuinely differ.
 *
 * ## The fail-closed invariants this seam holds structurally
 *
 *  - **Keys are matched by their `sha256:`-tagged hash, not verified against a
 *    plaintext column.** The lookup IS the verification: a row whose `key_hash`
 *    holds a plaintext secret, an untagged digest or a different algorithm can
 *    never be the row a probe matches, because every probe carries the exact
 *    stored construction. There is no raw-secret fallback lookup.
 *  - **The directory is checked first AND the tenant row is checked too.** The
 *    dual write across two databases has no spanning transaction, so the ordering
 *    rule (create writes the tenant row then the directory; revoke writes the
 *    directory then the tenant row) only pays off if BOTH halves are read: a
 *    revoke that crashed after its first leg has already disabled the credential
 *    here, and a create that crashed after its first leg has not yet enabled one.
 *  - **An unroutable tenant is `unavailable` (→ 503); an UNPROVISIONED one is
 *    `unroutable` (→ the consumer's unknown/401).** A registry row this Worker
 *    cannot reach is a deployment fault an operator must see. No registry row
 *    means this deployment cannot authorize the key at all, and inventing scopes
 *    for it is the one thing that must never happen — so it resolves to nothing.
 *  - **A control-object OUTAGE is `unavailable`, never a silent miss.** An outage
 *    must not be indistinguishable from a revoked credential, and must not fall
 *    through to a var that may still list a key the database revoked.
 */
import { StorageError } from "./errors.js";
import type { ApiKeyDirectoryProjection } from "./key-directory-projection.js";
import type { TenantDatabaseRouter } from "./tenant-router.js";

/** The narrow credential→tenant routing index in the CONTROL database. */
export const API_KEY_DIRECTORY_TABLE = "api_key_directory";
/** The tenant-database `api_keys` table — the AUTHORITY for a virtual key. */
export const TENANT_API_KEY_TABLE = "api_keys";

/** One `api_key_directory` row (CONTROL database) — routing plus lifecycle bits. */
export interface ApiKeyDirectoryRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly project_id: string;
  readonly workspace_id: string;
  readonly enabled: number;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
}

/**
 * One `api_keys` row (TENANT database), as the AUTHORITY hands it back.
 *
 * The column set is the SUPERSET every consumer needs: the gateway reads the
 * allow-lists, the per-credential RPM cap and the attribution tags; the
 * agent-runtime reads only a subset; the control plane a third. Reading the
 * superset once and letting each consumer project what it uses keeps a single
 * SQL statement, so a column rename breaks one place.
 */
export interface TenantApiKeyRow {
  readonly id: string;
  readonly tenant_id: string | null;
  readonly project_id: string | null;
  readonly workspace_id: string | null;
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
  readonly attribution_tags_json: string | null;
}

/** The three lifecycle states that deny, reported for logs only — all mean 401. */
export type ApiKeyLifecycleReason = "disabled" | "revoked" | "expired";

/**
 * What the two hops found. A NEUTRAL fact, not an HTTP decision — see the module
 * header for why the outcome enum, the fallback rule and the budget rule live in
 * the consumer, not here.
 */
export type TwoHopApiKeyResolution =
  /** No `api_key_directory` row: not a durable key. The consumer may fall back. */
  | { readonly kind: "no_directory_row" }
  /**
   * A row matched but is retired (directory disabled/revoked/expired, or the
   * tenant row disabled/revoked/expired, or the directory names a tenant row
   * that is GONE — a revoke that landed its second leg). Every one is
   * indistinguishable from a typo to an unauthenticated caller.
   */
  | { readonly kind: "suspended"; readonly reason: ApiKeyLifecycleReason }
  /**
   * The directory named a tenant with no provisioned database. The scopes are
   * unreachable, so this resolves to NOTHING — the consumer must not invent a
   * scope for it, and must not let a config var speak for it.
   */
  | { readonly kind: "unroutable" }
  /** The control object, the tenant router, or the tenant read is DOWN. → 503. */
  | { readonly kind: "unavailable"; readonly detail: string }
  /** A live key. The consumer applies budget/scope policy and builds its AuthContext. */
  | {
      readonly kind: "resolved";
      readonly directory: ApiKeyDirectoryRow;
      readonly row: TenantApiKeyRow;
    };

/** The seam consumers depend on. Injected so the resolver is testable without a database. */
export interface TwoHopApiKeyDirectory {
  /**
   * Resolve a `sha256:`-tagged (or `blake2b:`-tagged) key hash through the two
   * hops. `keyHash` is the EXACT stored construction — the caller hashes the
   * presented secret before calling, so the plaintext never enters this seam.
   */
  resolve(keyHash: string): Promise<TwoHopApiKeyResolution>;
}

const DIRECTORY_SQL = `SELECT id, tenant_id, project_id, workspace_id, enabled, expires_at_unix, revoked_at_unix
   FROM ${API_KEY_DIRECTORY_TABLE} WHERE key_hash = ?`;

const TENANT_KEY_SQL = `SELECT id, tenant_id, project_id, workspace_id, name, key_prefix, key_hash, last4,
          enabled, scopes_json, allowed_models_json, allowed_providers_json,
          monthly_token_budget, request_limit_per_minute,
          expires_at_unix, revoked_at_unix, attribution_tags_json
   FROM ${TENANT_API_KEY_TABLE} WHERE key_hash = ?`;

/**
 * Which of the three retirement states a row is in, or `null` when it is live.
 * Ordered as Rust's `api_key_record_is_active` tests them, so the reason always
 * names the FIRST failing condition. Exported because both hops use it and so a
 * consumer can reuse the exact liveness rule when it reads a row itself.
 */
export function apiKeyLifecycleReason(
  row: {
    readonly enabled: number | null;
    readonly expires_at_unix: number | null;
    readonly revoked_at_unix: number | null;
  },
  nowUnixSeconds: number,
): ApiKeyLifecycleReason | null {
  if ((row.enabled ?? 0) === 0) return "disabled";
  if (row.revoked_at_unix !== null && row.revoked_at_unix !== undefined) return "revoked";
  if (
    row.expires_at_unix !== null &&
    row.expires_at_unix !== undefined &&
    row.expires_at_unix <= nowUnixSeconds
  ) {
    return "expired";
  }
  return null;
}

export interface TwoHopApiKeyDirectoryOptions {
  /** Injected unix-SECONDS clock, so expiry is deterministic in tests. */
  readonly now?: () => number;
  /**
   * Zero-D1 S6 (#882): the per-colo KV projection of `api_key_directory`, read
   * AHEAD of the control-object RPC in HOP 1. OPTIONAL — absent means the pure
   * two-hop RPC behaviour, so this class stays inject-free by default.
   *
   * It changes ONLY where HOP 1's routing row comes from, never HOP 2 and never
   * the taxonomy: a KV hit still runs the directory-lifecycle check and the full
   * tenant read below. See the read-ahead in {@link D1TwoHopApiKeyDirectory.resolve}
   * for the three fail-closed properties (KV never masks an outage; a corrupt
   * entry is a miss; only a POSITIVE row is populated).
   */
  readonly projection?: ApiKeyDirectoryProjection;
}

/**
 * {@link TwoHopApiKeyDirectory} over a CONTROL database handle and a
 * {@link TenantDatabaseRouter}.
 *
 * The `controlDb` is a D1-shaped handle — a native binding, or the
 * `ControlDataObject` facade every current Worker resolves through
 * `controlDatabaseFrom(env)`. The `router` is the SAME one the rest of the
 * Worker routes tenant data with, so credential resolution and data access can
 * never disagree about which database a tenant is.
 */
export class D1TwoHopApiKeyDirectory implements TwoHopApiKeyDirectory {
  readonly #controlDb: D1Database;
  readonly #router: TenantDatabaseRouter;
  readonly #now: () => number;
  readonly #projection: ApiKeyDirectoryProjection | undefined;

  constructor(
    controlDb: D1Database,
    router: TenantDatabaseRouter,
    options: TwoHopApiKeyDirectoryOptions = {},
  ) {
    this.#controlDb = controlDb;
    this.#router = router;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#projection = options.projection;
  }

  async resolve(keyHash: string): Promise<TwoHopApiKeyResolution> {
    // Hop 1 — the CONTROL directory. This is what makes the whole thing
    // possible: the lookup that PRODUCES the tenant id cannot itself be routed.
    //
    // #882: read the per-colo KV projection AHEAD of the RPC. A hit supplies the
    // routing row and skips the round trip to the singleton control object; a
    // miss (or no projection, or a KV error) falls through to the authoritative
    // RPC. This can only ever move where the ROUTING row comes from — the
    // directory-lifecycle check and HOP 2 below run identically either way.
    let directory: ApiKeyDirectoryRow | null = null;
    if (this.#projection !== undefined) {
      try {
        directory = await this.#projection.read(keyHash);
      } catch {
        // A KV read failure must NOT mask the authoritative source: fall through
        // to the RPC, so an outage is still detected there rather than swallowed.
        directory = null;
      }
    }

    if (directory === null) {
      try {
        directory = await this.#controlDb
          .prepare(DIRECTORY_SQL)
          .bind(keyHash)
          .first<ApiKeyDirectoryRow>();
      } catch (error) {
        // A control-object OUTAGE is `unavailable` → 503, NEVER masked by KV: a
        // KV miss always reaches this RPC, and its failure is surfaced, not
        // rewritten into a silent miss or a stale allow.
        return {
          kind: "unavailable",
          detail: `api key directory lookup failed: ${messageOf(error)}`,
        };
      }
      if (directory === null) return { kind: "no_directory_row" };

      // POSITIVE ONLY, and LIVE only: populate KV for a row the control object
      // actually holds AND that is live — never the unknown-key (null) case above
      // (so a miss can never be seeded as a hit and a key-spray cannot fill the
      // namespace), and never a RETIRED row (a revoke that only landed its
      // directory leg, or a disabled/expired row). The lifecycle check below
      // would reject such a row anyway, and delete-on-revoke removes its KV
      // entry, so caching it would only widen the stale-positive window.
      // Best-effort: a failed populate just leaves the next request on the RPC.
      if (this.#projection !== undefined && apiKeyLifecycleReason(directory, this.#now()) === null) {
        try {
          await this.#projection.write(keyHash, directory);
        } catch {
          // Caching is an optimization; a write failure must not deny a live key.
        }
      }
    }

    // The directory's own lifecycle bits are checked BEFORE routing, so a
    // revoke that only landed its first (directory) leg denies here without
    // depending on whether the tenant database is reachable.
    const directoryReason = apiKeyLifecycleReason(directory, this.#now());
    if (directoryReason !== null) return { kind: "suspended", reason: directoryReason };

    // Hop 2 — route to the tenant's OWN database.
    let tenantDb: D1Database;
    try {
      tenantDb = (await this.#router.forTenant(directory.tenant_id)).db;
    } catch (error) {
      // No provisioned database ⇒ the scopes are unreachable ⇒ resolve NOTHING.
      if (error instanceof StorageError && error.kind === "not_found") {
        return { kind: "unroutable" };
      }
      // A registry row this Worker cannot reach is a deployment fault → 503.
      return {
        kind: "unavailable",
        detail: `tenant ${directory.tenant_id} database is unreachable: ${messageOf(error)}`,
      };
    }

    let row: TenantApiKeyRow | null;
    try {
      row = await tenantDb.prepare(TENANT_KEY_SQL).bind(keyHash).first<TenantApiKeyRow>();
    } catch (error) {
      return {
        kind: "unavailable",
        detail: `tenant api key lookup failed: ${messageOf(error)}`,
      };
    }
    // The directory names a key whose tenant row is gone — a revoke that landed
    // its second leg, or a create that never did. The authority for its scopes
    // does not exist, so it authenticates nothing (401, never disclosed as 403).
    //
    // NOTE this ALSO absorbs the "unprovisioned tenant" case under a Durable
    // Object router: `forTenant` materializes an object by addressing it and
    // never throws `not_found`, so an unprovisioned tenant reaches here with a
    // null row rather than taking the `unroutable` branch above (which only fires
    // for a router that SIGNALS not_found, e.g. the env-binding shared router).
    // Both are fail-closed. The one practical difference is that a consumer which
    // lets `suspended` fall through to a static-config table (the gateway does,
    // for Rust `find_map` parity) would then let a config key answer — but only a
    // config key holding the byte-identical secret, which is not reachable by an
    // attacker. If a strict no-fallthrough guarantee for unprovisioned tenants is
    // ever required under the DO router, distinguish the two here with a
    // tenant-provisioned probe rather than relying on the `unroutable` branch.
    if (row === null) return { kind: "suspended", reason: "revoked" };

    // The TENANT row is the authority for lifecycle too, not the directory
    // mirror: a key an operator disabled on the row an operator actually edits
    // must deny even if the directory copy is momentarily stale.
    const rowReason = apiKeyLifecycleReason(row, this.#now());
    if (rowReason !== null) return { kind: "suspended", reason: rowReason };

    return { kind: "resolved", directory, row };
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
