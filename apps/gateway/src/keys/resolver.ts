/**
 * TWO-HOP API-key resolution — the `ApiKeyAuthenticatorPort` implementation.
 *
 * Clean-room port of the Rust key-source chain:
 *
 *   `crates/ferrogate-gateway/src/auth.rs::authenticate`
 *     ├─ `authenticate_durable`  → `ferrogate_auth_service::StorageApiKeyAuthenticator`
 *     │                            (the DURABLE/virtual key, now two hops)
 *     └─ `config.api_keys` loop  → the operator-authored static table
 *
 * — in that exact order, and with the exact same refusal taxonomy. The durable
 * leg used to be a SINGLE-hop flat lookup of `api_keys` by `key_prefix` over the
 * ferrogate-tenant D1 binding (`env.DB`). It is now the TWO-HOP directory model
 * (#821): `@ferrogate/storage`'s {@link TwoHopApiKeyDirectory} hashes the
 * presented secret, reads `api_key_directory` in CONTROL to find the owning
 * tenant, then reads THAT tenant's own `api_keys` row through the gateway's
 * existing tenant router. The config/dev-auth table remains the fallback, so the
 * change moves the CREDENTIAL SOURCE without touching the middleware taxonomy.
 *
 * ## The 401-vs-403 taxonomy — the invariant this file exists to hold
 *
 * A **durable/native** key is the strict case, and it is a repeat defect class
 * in this codebase (see `docs/rewrite/PORT-PLAN.md` "parity verification" #4):
 *
 * | presented credential                       | outcome                 | HTTP |
 * |--------------------------------------------|-------------------------|------|
 * | unknown / absent from `api_key_directory`  | `unknown`               | 401  |
 * | directory names an UNPROVISIONED tenant    | `unknown`               | 401  |
 * | **SUSPENDED** (`enabled = 0`)              | `key_suspended`         | 401  |
 * | **REVOKED** (`revoked_at_unix` set)        | `key_suspended`         | 401  |
 * | **EXPIRED** (`expires_at_unix <= now`)     | `key_suspended`         | 401  |
 * | directory row whose tenant row is GONE     | `key_suspended`         | 401  |
 * | valid, but lacks the operation's scope     | *resolved* → `hasScope` | 403  |
 * | valid, `monthly_token_budget = 0`          | `token_budget_exhausted`| 429  |
 * | control object / tenant DB unreachable     | `unavailable`           | 503  |
 *
 * **A suspended key is 401, NOT 403.** Every retirement state collapses onto the
 * very same `401 invalid_api_key` an unknown key gets — key *state is not
 * disclosed*, so an attacker cannot use the status code to learn that a guessed
 * key exists. `src/middleware/auth.ts::resolveOrThrow` collapses `unknown` and
 * `key_suspended` onto one identical 401 for exactly that reason.
 *
 * 403 is reserved for a caller who IS authenticated: insufficient scope
 * (`scope_denied`), a suspended *tenant* (`tenancy_suspended`), a denied RBAC
 * action. Those are decided downstream of this port, by the middleware.
 *
 * ## Cross-tenant isolation
 *
 * A durable/virtual key can never be platform root. `resolve_platform_operator`
 * → `false`, because the key declares a tenant and neither `api_key_directory`
 * nor `api_keys` has a `platform_operator` column to declare anything else with
 * (auth.rs invariant `durable_virtual_key_is_never_platform_root`). This port
 * keeps that structural: {@link toAuthContext} writes the literal `false` and
 * reads no row field to get there, so no value — hostile, corrupted, or
 * otherwise — can turn a tenant key into an operator key. The resolved
 * `tenancy.tenantId` is the DIRECTORY's `tenant_id` (the routing authority), and
 * the two hops guarantee the `api_keys` row was read from THAT tenant's own,
 * physically isolated database and no other.
 */
import {
  type ApiKeyDirectoryRow,
  D1TwoHopApiKeyDirectory,
  DurableObjectTenantDatabaseRouter,
  KvApiKeyDirectoryProjection,
  type TenantApiKeyRow,
  type TwoHopApiKeyDirectory,
  type TwoHopApiKeyResolution,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { controlDatabaseFrom } from "../control-data.js";
import type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AuthContext,
  GatewayBindings,
} from "../ports.js";
import { ApiKeyResolutionCache, type Clock, DEFAULT_API_KEY_CACHE_TTL_SECONDS } from "./cache.js";
import { sha256Hex } from "./hash.js";
import { type StoredApiKey, storedApiKeyFromRow } from "./store.js";

/** Worker bindings this module reads, on top of {@link GatewayBindings}. */
export interface ApiKeyBindings {
  /**
   * The ferrogate-tenant D1 binding. Still declared for wallet/quota/metering
   * reads; the credential resolver NO LONGER reads it — the durable leg is the
   * two-hop directory model over `CONTROL_DATA` + the tenant router (#821).
   */
  readonly DB?: D1Database;
  /**
   * TTL, in seconds, for the in-isolate resolution cache. Absent ⇒ the
   * 30-second default; explicit `"0"` disables it. See `./cache.ts` for the
   * revocation-lag trade this buys.
   */
  readonly GATEWAY_API_KEY_CACHE_TTL_SECONDS?: string;
  /**
   * The per-colo KV projection of `api_key_directory` (#882), read AHEAD of the
   * control-object RPC in HOP 1. Absent ⇒ HOP 1 always takes the RPC path, the
   * pre-#882 behaviour. Bound, it is the SAME namespace `apps/control-plane`
   * writes; both derive the key with `keyDirectoryProjectionKey`.
   */
  readonly KEY_DIRECTORY?: KVNamespace;
}

/** Construction options for {@link D1ApiKeyResolver}. */
export interface ApiKeyResolverOptions {
  /**
   * The two-hop directory seam — `api_key_directory` (CONTROL) → the routed
   * tenant's `api_keys` row. A real {@link D1TwoHopApiKeyDirectory} in
   * production; injectable for tests.
   */
  readonly directory: TwoHopApiKeyDirectory;
  /**
   * The SECOND key source, consulted only when the durable directory produced no
   * usable match — Rust's `config.api_keys` compatibility loop. Pass
   * `ConfiguredApiKeyAuthenticator.fromEnv(env)` to keep the static/dev-auth
   * table working. Omit it and a non-durable credential is simply `unknown`.
   */
  readonly fallback?: ApiKeyAuthenticatorPort;
  /** Shared TTL cache. Omit for the uncached (Rust-parity) behavior. */
  readonly cache?: ApiKeyResolutionCache;
}

/**
 * Rust `api_key_tenant_context` + `authenticate_durable`'s `AuthContext`
 * construction, narrowed to what `../ports.ts::AuthContext` carries.
 *
 * The tenant row is the AUTHORITY for the credential's columns
 * (`scopes`, the allow-lists, the RPM cap, the attribution tags), but the
 * `tenantId` is the DIRECTORY's — the value the request was ROUTED by. The two
 * agree in a healthy dual write; taking the directory's keeps a key that was
 * moved between workspaces from being gated by a stale mirror, and is what every
 * downstream isolation check, per-tenant DB route and metering attribution keys
 * off.
 *
 * `requestLimitPerMinute` is `null` for a row with no cap, and `null` must NOT
 * become `0` — `0` is a real value meaning "refuse every request". An EMPTY
 * allow-list means "no allowlist", never "deny everything".
 */
function toAuthContext(row: StoredApiKey): AuthContext {
  return {
    subject: row.id,
    tenancy: {
      tenantId: row.tenantId,
      projectId: row.projectId === "" ? null : row.projectId,
      workspaceId: row.workspaceId === "" ? null : row.workspaceId,
      // `api_keys` models machine/tenant access; a human identity comes from a
      // console session, never from this table.
      userId: null,
    },
    scopes: row.scopes,
    // NEVER read from the row. See the cross-tenant isolation note above.
    platformOperator: false,
    source: "durable_native",
    allowedModels: row.allowedModels,
    allowedProviders: row.allowedProviders,
    ...(row.requestLimitPerMinute === null
      ? {}
      : { requestLimitPerMinute: row.requestLimitPerMinute }),
    ...(Object.keys(row.attributionTags).length === 0
      ? {}
      : { attributionTags: row.attributionTags }),
    // #945 — the billing group whose multiplier scales this key's settled cost.
    // Forwarded only when the key names one; absent means "no group", which
    // settles at the official price (a `1.0` multiplier).
    ...(row.billingGroupId === null ? {} : { billingGroupId: row.billingGroupId }),
  };
}

/** What the durable leg concluded about a presented secret. */
type DurableOutcome =
  | { readonly kind: "resolution"; readonly resolution: ApiKeyResolution }
  /** No directory row authenticated this secret — fall through to the config table. */
  | { readonly kind: "no_match" }
  /**
   * A directory row matched but is not usable (suspended/revoked/expired). Rust
   * SKIPS such a record inside `find_map`, so the config table is still
   * consulted; if that also misses, this is the answer.
   */
  | { readonly kind: "matched_unusable"; readonly resolution: ApiKeyResolution };

/**
 * The `ApiKeyAuthenticatorPort` the gateway middleware already codes against,
 * implemented over the two-hop directory.
 *
 * Drop-in for `ConfiguredApiKeyAuthenticator`: same interface, same
 * `ApiKeyResolution` variants, same middleware.
 */
export class D1ApiKeyResolver implements ApiKeyAuthenticatorPort {
  readonly #directory: TwoHopApiKeyDirectory;
  readonly #fallback: ApiKeyAuthenticatorPort | undefined;
  readonly #cache: ApiKeyResolutionCache;

  constructor(options: ApiKeyResolverOptions) {
    this.#directory = options.directory;
    this.#fallback = options.fallback;
    this.#cache = options.cache ?? new ApiKeyResolutionCache();
  }

  /**
   * Resolve a presented bearer / `x-api-key` credential.
   *
   * Never throws for a credential problem — every refusal is an
   * `ApiKeyResolution` variant, so the middleware owns the whole status/code
   * taxonomy and this class cannot accidentally invent one.
   */
  async authenticate(presentedKey: string): Promise<ApiKeyResolution> {
    const durable = await this.#authenticateDurable(presentedKey);
    if (durable.kind === "resolution") return durable.resolution;

    const fallbackResolution = await this.#fallback?.authenticate(presentedKey);
    if (fallbackResolution !== undefined && fallbackResolution.outcome !== "unknown") {
      return fallbackResolution;
    }
    // Rust order preserved: a directory row that matched but is suspended/
    // revoked/expired still lets the static config table answer first (it is
    // skipped inside `find_map`, not returned). Only when that misses too does
    // the suspension become the answer — and `middleware/auth.ts` renders it as
    // the same `401 invalid_api_key` an unknown key gets.
    if (durable.kind === "matched_unusable") return durable.resolution;
    return { outcome: "unknown" };
  }

  /**
   * The full stored row behind a presented secret, for callers that need more
   * than `AuthContext` carries (allow-lists, per-key RPM, budgets).
   *
   * Returns `null` for anything that does not authenticate, including a
   * suspended row — a caller must not be able to use this to learn key state
   * that `authenticate` deliberately hides.
   */
  async resolveStoredKey(presentedKey: string): Promise<StoredApiKey | null> {
    const trimmed = presentedKey.trim();
    if (trimmed === "") return null;
    const twoHop = await this.#directory.resolve(`sha256:${await sha256Hex(trimmed)}`);
    if (twoHop.kind !== "resolved") return null;
    return this.#toStored(twoHop.directory, twoHop.row);
  }

  async #authenticateDurable(presentedKey: string): Promise<DurableOutcome> {
    // Rust trims first; a blank secret makes the whole durable leg a no-op.
    const trimmed = presentedKey.trim();
    if (trimmed === "") return { kind: "no_match" };

    // The digest doubles as the cache key: the plaintext secret never enters the
    // cache, and the `sha256:`-tagged hash is what the directory is keyed by.
    const digest = await sha256Hex(trimmed);
    const cached = this.#cache.get(digest);
    if (cached !== undefined) {
      return cached.outcome === "resolved" || cached.outcome === "token_budget_exhausted"
        ? { kind: "resolution", resolution: cached }
        : { kind: "matched_unusable", resolution: cached };
    }

    const twoHop = await this.#directory.resolve(`sha256:${digest}`);
    const outcome = this.#classify(twoHop);
    if (outcome.kind !== "no_match") {
      // `set` itself refuses to store `unknown`/`unavailable`, so an outage or a
      // miss is never pinned in front of a recovered database or a minted key.
      this.#cache.set(digest, outcome.resolution);
    }
    return outcome;
  }

  /** Map a NEUTRAL two-hop fact onto the gateway's outcome + fallback policy. */
  #classify(twoHop: TwoHopApiKeyResolution): DurableOutcome {
    switch (twoHop.kind) {
      case "no_directory_row":
        return { kind: "no_match" };
      case "unavailable":
        // 503, never 401: an outage must not be indistinguishable from a
        // revocation, and it must not be cached.
        return {
          kind: "resolution",
          resolution: { outcome: "unavailable", detail: twoHop.detail },
        };
      case "unroutable":
        // The directory names a durable key whose tenant is not provisioned:
        // resolve NOTHING and do NOT fall through — a config var must not speak
        // for a durable key the database owns. Renders as the unknown-key 401.
        return { kind: "resolution", resolution: { outcome: "unknown" } };
      case "suspended":
        // Skipped inside Rust's `find_map`, so the config table still answers
        // first; if it misses, this suspension is the answer (also 401).
        return {
          kind: "matched_unusable",
          resolution: { outcome: "key_suspended", reason: twoHop.reason },
        };
      case "resolved": {
        const stored = this.#toStored(twoHop.directory, twoHop.row);
        if (stored.monthlyTokenBudget === 0) {
          // Rust `authenticate_durable`: `Some(0)` is 429; `null` is unlimited.
          return { kind: "resolution", resolution: { outcome: "token_budget_exhausted" } };
        }
        return {
          kind: "resolution",
          resolution: { outcome: "resolved", auth: toAuthContext(stored) },
        };
      }
    }
  }

  /**
   * The tenant `api_keys` row → `StoredApiKey`, with the `tenantId` taken from
   * the DIRECTORY (the routing authority) rather than the row's own mirror.
   */
  #toStored(directory: ApiKeyDirectoryRow, row: TenantApiKeyRow): StoredApiKey {
    return { ...storedApiKeyFromRow(row), tenantId: directory.tenant_id };
  }
}

// ---------------------------------------------------------------------------
// Composition helpers
// ---------------------------------------------------------------------------

/**
 * The isolate-wide resolution cache.
 *
 * A Worker builds its ports per request (`depsFromEnv(c.env)` in
 * `middleware/auth.ts`), so a cache owned by the resolver instance would be
 * born and die inside one request and buy nothing. It lives at module scope
 * instead — the same lifetime a real Worker isolate has — and is created once,
 * with the TTL the first request's bindings named.
 */
let sharedCache: ApiKeyResolutionCache | undefined;

/** Drop the isolate-wide cache. Tests only; a Worker never needs this. */
export function resetSharedApiKeyCache(): void {
  sharedCache = undefined;
}

/** `GATEWAY_API_KEY_CACHE_TTL_SECONDS` → seconds. Unset uses the 30s default. */
export function apiKeyCacheTtlSeconds(
  env: Pick<ApiKeyBindings, "GATEWAY_API_KEY_CACHE_TTL_SECONDS">,
): number {
  const raw = env.GATEWAY_API_KEY_CACHE_TTL_SECONDS;
  // Unset ⇒ the default-on TTL (§3.1 — the auth hot path caches by default).
  // An explicitly blank or malformed value fails closed to 0 (caching off): a
  // misconfigured var must not silently enable a stale-tolerant cache.
  if (raw === undefined) return DEFAULT_API_KEY_CACHE_TTL_SECONDS;
  if (raw.trim() === "") return 0;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return Math.floor(parsed);
}

/**
 * Build the durable two-hop resolver from Worker bindings, or `null` when the
 * durable leg cannot run.
 *
 * `null` — rather than a resolver that always misses — is deliberate: it lets
 * the composition root keep the exact config-only object it uses today, so the
 * credential path stays inert on a deployment that binds no `CONTROL_DATA` or no
 * `TENANT_DATA`. `null` is returned when:
 *
 *  - no `CONTROL_DATA` is bound (`controlDatabaseFrom` → `undefined`): there is
 *    no directory to read, so there are no durable keys; or
 *  - no `TENANT_DATA` namespace is bound: the second hop cannot route, so the
 *    durable leg is off.
 *
 * The second hop routes through the SAME pure-`durable_object` router the rest
 * of the Worker's default tenant topology uses (`src/tenancy/resolver.ts` line
 * ~233): one `TenantDataObject` per tenant, addressed by `idFromName(tenantId)`,
 * with NO `tenant_databases` registry read on the credential hot path. When both
 * bindings are present the durable directory becomes the PRIMARY source and the
 * config/dev-auth table its fallback — the Rust order (`authenticate_durable`
 * first, `config.api_keys` second).
 */
export function d1ApiKeyResolverFromEnv(
  env: GatewayBindings & ApiKeyBindings,
  options: { readonly fallback?: ApiKeyAuthenticatorPort; readonly now?: Clock } = {},
): D1ApiKeyResolver | null {
  const controlDb = controlDatabaseFrom(env);
  if (controlDb === undefined) return null;
  const tenantData = (env as { TENANT_DATA?: TenantDataNamespace }).TENANT_DATA;
  if (tenantData === undefined) return null;
  sharedCache ??= new ApiKeyResolutionCache({
    ttlSeconds: apiKeyCacheTtlSeconds(env),
    now: options.now,
  });
  // #882 — the per-colo KV read-ahead in HOP 1. OPTIONAL: with no `KEY_DIRECTORY`
  // bound the directory takes the control-object RPC on every cold miss, exactly
  // as before. A hit still runs HOP 2 and every lifecycle check.
  const keyDirectoryKv = (env as { KEY_DIRECTORY?: KVNamespace }).KEY_DIRECTORY;
  const projection =
    keyDirectoryKv === undefined ? undefined : new KvApiKeyDirectoryProjection(keyDirectoryKv);
  return new D1ApiKeyResolver({
    directory: new D1TwoHopApiKeyDirectory(
      controlDb,
      new DurableObjectTenantDatabaseRouter(tenantData, controlDb),
      { projection },
    ),
    fallback: options.fallback,
    cache: sharedCache,
  });
}
