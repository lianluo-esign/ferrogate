/**
 * D1-backed API-key resolution — the `ApiKeyAuthenticatorPort` implementation.
 *
 * Clean-room port of the Rust key-source chain:
 *
 *   `crates/ferrogate-gateway/src/auth.rs::authenticate`
 *     ├─ `authenticate_durable`  → `ferrogate_auth_service::StorageApiKeyAuthenticator`
 *     │                            (Supabase `api_keys`; **D1 here**)
 *     └─ `config.api_keys` loop  → the operator-authored static table
 *
 * — in that exact order, and with the exact same refusal taxonomy. Today
 * `apps/gateway` only has the second leg (`src/adapters.ts`,
 * `ConfiguredApiKeyAuthenticator`, fed from Worker vars). This module supplies
 * the first, primary leg and keeps the second as its fallback, so wiring it in
 * ADDS the durable store without removing the config/dev-auth path.
 *
 * ## The 401-vs-403 taxonomy — the invariant this file exists to hold
 *
 * A **durable/native** key is the strict case, and it is a repeat defect class
 * in this codebase (see `docs/rewrite/PORT-PLAN.md` "parity verification" #4):
 *
 * | presented credential                       | outcome                 | HTTP |
 * |--------------------------------------------|-------------------------|------|
 * | unknown / absent from `api_keys`           | `unknown`               | 401  |
 * | **SUSPENDED** (`enabled = 0`)              | `key_suspended`         | 401  |
 * | **REVOKED** (`revoked_at_unix` set)        | `key_suspended`         | 401  |
 * | **EXPIRED** (`expires_at_unix <= now`)     | `key_suspended`         | 401  |
 * | valid, but lacks the operation's scope     | *resolved* → `hasScope` | 403  |
 * | valid, `monthly_token_budget = 0`          | `token_budget_exhausted`| 429  |
 * | D1 unreachable                             | `unavailable`           | 503  |
 *
 * **A suspended key is 401, NOT 403.** In Rust that falls out of
 * `api_key_record_is_active` returning `false` inside a `find_map`: the record
 * is skipped, `authenticate` never sees it, and the request lands on the very
 * same `401 invalid_api_key` an unknown key gets. Key *state is not disclosed*
 * — an attacker cannot use the status code to learn that a guessed key exists.
 * `src/middleware/auth.ts::resolveOrThrow` collapses `unknown` and
 * `key_suspended` onto one identical 401 response for exactly that reason.
 *
 * 403 is reserved for a caller who IS authenticated: insufficient scope
 * (`scope_denied`), a suspended *tenant* (`tenancy_suspended`), a denied RBAC
 * action. Those are decided downstream of this port, by the middleware.
 *
 * ## Cross-tenant isolation
 *
 * A durable/virtual key can never be platform root. Rust:
 * `resolve_platform_operator(implicit, None, Some(tenant_id))` → `false`,
 * because the key declares a tenant and the `api_keys` table has no
 * `platform_operator` column to declare anything else with (auth.rs invariant
 * `durable_virtual_key_is_never_platform_root`). This port keeps that
 * structural: {@link toAuthContext} writes the literal `false` and reads no row
 * field to get there, so no D1 value — hostile, corrupted, or otherwise — can
 * turn a tenant key into an operator key. The resolved `tenancy.tenantId` is
 * the row's own `tenant_id`, which is what every downstream isolation check,
 * per-tenant DB route and metering attribution keys off.
 */
import type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AuthContext,
  GatewayBindings,
} from "../ports.js";
import {
  ApiKeyResolutionCache,
  DEFAULT_API_KEY_CACHE_TTL_SECONDS,
  type Clock,
} from "./cache.js";
import { sha256Hex, verifyStoredKeyHash, virtualApiKeyPrefix } from "./hash.js";
import {
  type ApiKeyStore,
  ApiKeyStoreUnavailable,
  D1ApiKeyStore,
  type StoredApiKey,
} from "./store.js";

/** Worker bindings this module reads, on top of {@link GatewayBindings}. */
export interface ApiKeyBindings {
  /**
   * The D1 binding holding `api_keys`. Absent ⇒ the durable leg is OFF and
   * resolution falls back to the config table, i.e. today's behavior exactly.
   */
  readonly DB?: D1Database;
  /**
   * TTL, in seconds, for the in-isolate resolution cache. Absent ⇒ the
   * 30-second default; explicit `"0"` disables it. See `./cache.ts` for the
   * revocation-lag trade this buys.
   */
  readonly GATEWAY_API_KEY_CACHE_TTL_SECONDS?: string;
}

/** Construction options for {@link D1ApiKeyResolver}. */
export interface ApiKeyResolverOptions {
  /** Where rows come from. A real D1 binding in production. */
  readonly store: ApiKeyStore;
  /**
   * The SECOND key source, consulted only when the durable store produced no
   * usable match — Rust's `config.api_keys` compatibility loop. Pass
   * `ConfiguredApiKeyAuthenticator.fromEnv(env)` to keep the static/dev-auth
   * table working. Omit it and a non-durable credential is simply `unknown`.
   */
  readonly fallback?: ApiKeyAuthenticatorPort;
  /** Shared TTL cache. Omit for the uncached (Rust-parity) behavior. */
  readonly cache?: ApiKeyResolutionCache;
  /** Unix-SECONDS clock, injected for deterministic expiry tests. */
  readonly nowUnixSeconds?: () => number;
}

/** Rust `api_key_record_is_active`. */
function isActive(row: StoredApiKey, nowUnixSeconds: number): boolean {
  if (!row.enabled) return false;
  if (row.revokedAtUnix !== null) return false;
  // Rust: `expires_at.is_none_or(|expires_at| expires_at > now)` — an
  // expiry exactly equal to now is EXPIRED.
  if (row.expiresAtUnix !== null && row.expiresAtUnix <= nowUnixSeconds) return false;
  return true;
}

/**
 * Why an inactive row is inactive. Ordered as `isActive` tests them, so the
 * reason always names the FIRST failing condition.
 *
 * This is observability only — every reason renders as the same
 * `401 invalid_api_key`, which is the point: the caller learns nothing.
 */
function suspensionReason(row: StoredApiKey): "disabled" | "revoked" | "expired" {
  if (!row.enabled) return "disabled";
  if (row.revokedAtUnix !== null) return "revoked";
  return "expired";
}

/** Rust `api_key_record_last4_matches`: a blank `last4` column matches anything. */
function last4Matches(row: StoredApiKey, presentedKey: string): boolean {
  return row.last4 === "" || presentedKey.endsWith(row.last4);
}

/**
 * Rust `api_key_tenant_context` + `authenticate_durable`'s `AuthContext`
 * construction, narrowed to what `../ports.ts::AuthContext` carries.
 *
 * ## The three per-credential limits (marker CLOSED — the transport now lands)
 *
 * `StoredApiKey` also carries `allowed_models`, `allowed_providers` and
 * `request_limit_per_minute`, which Rust threads into `AuthContext` for the
 * routing/quota gates. They were loaded here and DROPPED, because `AuthContext`
 * had no fields for them; it now does (`src/ports.ts`), and all three are
 * copied below.
 *
 * What each one reaching `AuthContext` turns on:
 *
 *  - `requestLimitPerMinute` → `subjectFor` (`src/ratelimit/middleware.ts`)
 *    reads it directly, so the TOK-12 per-credential RPM cap is enforced in the
 *    DEPLOYED Worker and not only where a test injects the
 *    `perKeyRequestLimit` hook. That hook is now an OVERRIDE, not the only
 *    source.
 *  - `allowedModels` / `allowedProviders` → consumed by `callerFromAuth`
 *    (`src/inference/identity.ts`), which builds the inference `Caller` fed to
 *    the already-implemented `callerCanUseModel` gate. `src/inference/` is a
 *    different owner, so that consumer carries its own marker
 *    (`identity.ts`); what is closed HERE is the transport — the values now
 *    arrive on `AuthContext` instead of being discarded at this function.
 *
 * An EMPTY list means "no allowlist", never "deny everything": that is the Rust
 * reading (`callerCanUseModel` treats an empty `allowedModels` as unrestricted)
 * and it is why the fields are copied verbatim rather than normalized here.
 * `request_limit_per_minute` is `null` for a row with no cap, and `null` must
 * NOT become `0` — `0` is a real Rust value meaning "refuse every request".
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
    // `null` (no cap) must stay ABSENT, not become 0 — see the header.
    ...(row.requestLimitPerMinute === null
      ? {}
      : { requestLimitPerMinute: row.requestLimitPerMinute }),
    // #678 — forwarded only when non-empty, so "this key declares nothing" and
    // "this credential source has no such column" are the same value
    // (`undefined`) at the one place that reads it. Read by
    // `attribution/middleware.ts`; an empty map would be indistinguishable from
    // a declared-but-blank one and mean the same thing anyway.
    ...(Object.keys(row.attributionTags).length === 0
      ? {}
      : { attributionTags: row.attributionTags }),
  };
}

/** What the durable leg concluded about a presented secret. */
type DurableOutcome =
  | { readonly kind: "resolution"; readonly resolution: ApiKeyResolution }
  /** No row in `api_keys` authenticated this secret — fall through to the config table. */
  | { readonly kind: "no_match" }
  /**
   * A row authenticated it but the row is not usable. Rust SKIPS such a record
   * inside `find_map`, so the config table is still consulted; if that also
   * misses, this is the answer.
   */
  | { readonly kind: "matched_unusable"; readonly resolution: ApiKeyResolution };

/**
 * The `ApiKeyAuthenticatorPort` the gateway middleware already codes against,
 * implemented over D1.
 *
 * Drop-in for `ConfiguredApiKeyAuthenticator`: same interface, same
 * `ApiKeyResolution` variants, same middleware. See `./index.ts` for the exact
 * one-line wiring.
 */
export class D1ApiKeyResolver implements ApiKeyAuthenticatorPort {
  readonly #store: ApiKeyStore;
  readonly #fallback: ApiKeyAuthenticatorPort | undefined;
  readonly #cache: ApiKeyResolutionCache;
  readonly #nowUnixSeconds: () => number;

  constructor(options: ApiKeyResolverOptions) {
    this.#store = options.store;
    this.#fallback = options.fallback;
    this.#cache = options.cache ?? new ApiKeyResolutionCache();
    this.#nowUnixSeconds = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));
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
    // Rust order preserved: a durable row that matched but is suspended/revoked/
    // expired still lets the static config table answer first (it is skipped
    // inside `find_map`, not returned). Only when that misses too does the
    // suspension become the answer — and `middleware/auth.ts` renders it as the
    // same `401 invalid_api_key` an unknown key gets.
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
    const keyPrefix = virtualApiKeyPrefix(trimmed);
    if (keyPrefix === null) return null;
    const matched = await this.#findMatchingRow(keyPrefix, trimmed);
    if (matched === null) return null;
    return isActive(matched, this.#nowUnixSeconds()) ? matched : null;
  }

  async #authenticateDurable(presentedKey: string): Promise<DurableOutcome> {
    // Rust trims first; `virtual_api_key_prefix` returns `None` for a blank
    // secret, which makes the whole durable leg a no-op.
    const trimmed = presentedKey.trim();
    const keyPrefix = virtualApiKeyPrefix(trimmed);
    if (keyPrefix === null) return { kind: "no_match" };

    // Digest doubles as the cache key: the plaintext secret never enters the
    // cache. See `./cache.ts`.
    const digest = await sha256Hex(trimmed);
    const cached = this.#cache.get(digest);
    if (cached !== undefined) {
      return cached.outcome === "resolved" || cached.outcome === "token_budget_exhausted"
        ? { kind: "resolution", resolution: cached }
        : { kind: "matched_unusable", resolution: cached };
    }

    let matched: StoredApiKey | null;
    try {
      matched = await this.#findMatchingRow(keyPrefix, trimmed);
    } catch (error) {
      if (error instanceof ApiKeyStoreUnavailable) {
        // 503, never 401: an outage must not be indistinguishable from a
        // revocation, and it must not be cached.
        return { kind: "resolution", resolution: { outcome: "unavailable", detail: error.detail } };
      }
      throw error;
    }
    if (matched === null) return { kind: "no_match" };

    const resolution = this.#classify(matched);
    this.#cache.set(digest, resolution);
    return resolution.outcome === "key_suspended"
      ? { kind: "matched_unusable", resolution }
      : { kind: "resolution", resolution };
  }

  /** Everything after the row is in hand. Split out so the cache stores its result. */
  #classify(row: StoredApiKey): ApiKeyResolution {
    const now = this.#nowUnixSeconds();
    if (!isActive(row, now)) {
      return { outcome: "key_suspended", reason: suspensionReason(row) };
    }
    if (row.tenantId.trim() === "") {
      // Rust `finalize_auth` refuses a credential that names no tenant with
      // `403 tenant_identity_required` — a key whose blast radius is unknown
      // must not serve traffic, because `organization_id` is also the
      // attribution key for quota, metering and lifecycle.
      //
      // This used to collapse onto `key_suspended` (→ 401 `invalid_api_key`)
      // because `ApiKeyResolution` had no variant for the 403. It now does, so
      // the OBSERVABLE half matches Rust too: an operator whose key row carries
      // a blank tenant sees the configuration error it is, not a bad secret.
      //
      // `declaredButBlank` is true here by construction — this branch is only
      // reached from a `api_keys` ROW, which always has an `organization_id`
      // column, so the value was declared and is blank. The other Rust shape
      // (no `organization_id` at all) belongs to the external-auth source.
      return { outcome: "tenant_identity_required", declaredButBlank: true };
    }
    if (row.monthlyTokenBudget === 0) {
      // Rust `authenticate_durable`: `Some(0)` is 429 `token_budget_exceeded`.
      // `null` (no budget column) is unlimited and must NOT hit this branch.
      return { outcome: "token_budget_exhausted" };
    }
    return { outcome: "resolved", auth: toAuthContext(row) };
  }

  /**
   * Rust's `find_map` over the prefix candidates, with the same three gates —
   * except that liveness is evaluated by the caller so a matched-but-suspended
   * row can be reported rather than silently skipped (both answer 401).
   *
   * The loop does NOT early-exit on the first hash match: every candidate is
   * verified so the work done is a function of how many rows share a prefix,
   * not of which slot matched. Prefix collisions are the only way to get more
   * than one candidate, and `key_prefix` is 16 chars of a CSPRNG hex secret.
   */
  async #findMatchingRow(keyPrefix: string, presentedKey: string): Promise<StoredApiKey | null> {
    const candidates = await this.#store.findByPrefix(keyPrefix);
    let matched: StoredApiKey | null = null;
    for (const row of candidates) {
      if (!last4Matches(row, presentedKey)) continue;
      const verified = await verifyStoredKeyHash(presentedKey, row.keyHash);
      if (verified && matched === null) matched = row;
    }
    return matched;
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
 * Build the durable resolver from Worker bindings, or `null` when no `DB`
 * binding is present.
 *
 * `null` — rather than a resolver that always misses — is deliberate: it lets
 * the composition root keep the exact object it uses today when D1 is not yet
 * bound, so introducing this module cannot change behavior until the binding
 * exists.
 */
export function d1ApiKeyResolverFromEnv(
  env: GatewayBindings & ApiKeyBindings,
  options: { readonly fallback?: ApiKeyAuthenticatorPort; readonly now?: Clock } = {},
): D1ApiKeyResolver | null {
  const db = env.DB;
  if (db === undefined) return null;
  sharedCache ??= new ApiKeyResolutionCache({
    ttlSeconds: apiKeyCacheTtlSeconds(env),
    now: options.now,
  });
  return new D1ApiKeyResolver({
    store: new D1ApiKeyStore(db),
    fallback: options.fallback,
    cache: sharedCache,
  });
}
