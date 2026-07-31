/**
 * `apps/gateway/src/keys` — D1-backed API-key resolution.
 *
 * The public seam of this slice. Everything the composition root needs is
 * re-exported here; nothing outside this directory imports a deeper path.
 *
 * ===========================================================================
 * WIRING — the exact edit the integrate step makes
 * ===========================================================================
 *
 * `src/adapters.ts::depsFromEnv` builds `GatewayDeps.apiKeys` from
 * `ConfiguredApiKeyAuthenticator.fromEnv(env)`. This module's resolver
 * implements the SAME `ApiKeyAuthenticatorPort`, so it drops into that one
 * slot. In `src/adapters.ts` (owned by the integrate step, not by this slice):
 *
 * ```ts
 * import { d1ApiKeyResolverFromEnv } from "./keys/index.js";
 *
 * export function depsFromEnv(env: GatewayBindings & ApiKeyBindings): GatewayDeps {
 *   const configured = ConfiguredApiKeyAuthenticator.fromEnv(env);
 *   return {
 *     // ── the one changed line ──────────────────────────────────────────
 *     apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured,
 *     lifecycle: ConfiguredTenancyLifecycleGate.fromEnv(env),
 *     rbac: ConfiguredRbacAuthorizer.fromEnv(env),
 *     internalTransport: ConfiguredInternalTransport.fromEnv(env),
 *   };
 * }
 * ```
 *
 * `?? configured` is what makes the change inert until D1 exists: with no `DB`
 * binding {@link d1ApiKeyResolverFromEnv} returns `null` and the deps are
 * byte-identical to today's. With a `DB` binding the durable store becomes the
 * PRIMARY source and the config/dev-auth table becomes the fallback — which is
 * the Rust order (`authenticate_durable` first, `config.api_keys` second).
 *
 * Two supporting edits, both outside this directory:
 *
 * 1. `wrangler.toml` — declare the binding the resolver reads. Under
 *    `@cloudflare/vitest-pool-workers` this also gives every test a real local
 *    SQLite D1, which is how `test/keys/*.test.ts` runs in the shared suite:
 *
 *    ```toml
 *    [[d1_databases]]
 *    binding = "DB"
 *    database_name = "ferrogate-control"
 *    database_id = "replace-at-deploy"
 *    ```
 *
 *    (`preview_database_id` too, if the account uses one. The migration is
 *    `sql/d1/001_init_d1.sql`; only the `api_keys` table is read here.)
 *
 * 2. `src/ports.ts::GatewayBindings` — fold in {@link ApiKeyBindings} (`DB`,
 *    `GATEWAY_API_KEY_CACHE_TTL_SECONDS`). Until then, type the `env` parameter
 *    as `GatewayBindings & ApiKeyBindings` as shown above.
 *
 * NO DURABLE OBJECT is introduced by this slice, so nothing has to be added to
 * `src/worker.ts` (which correctly re-exports only the default handler).
 *
 * ===========================================================================
 * THE INVARIANT, RESTATED
 * ===========================================================================
 *
 * unknown key → 401 · **SUSPENDED key → 401, not 403** · insufficient scope →
 * 403 · zero token budget → 429 · D1 down → 503. `./resolver.ts` holds the
 * first four; the middleware turns them into responses. `test/keys/
 * resolver.test.ts` proves each against a real D1 binding, and the
 * suspended-key case is mutation-proven.
 */

export { blake2b } from "./blake2b.js";
export {
  ApiKeyResolutionCache,
  DEFAULT_API_KEY_CACHE_MAX_ENTRIES,
  DEFAULT_API_KEY_CACHE_TTL_SECONDS,
  isCacheableResolution,
  type Clock,
} from "./cache.js";
export {
  blake2b512Hex,
  constantTimeEqualBytes,
  encodeHex,
  hashVirtualApiKeySecret,
  sha256Hex,
  SUPPORTED_KEY_HASH_ALGORITHMS,
  verifyStoredKeyHash,
  VIRTUAL_API_KEY_PREFIX_CHARS,
  VIRTUAL_API_KEY_SECRET_PREFIX,
  virtualApiKeyLast4,
  virtualApiKeyMaterial,
  virtualApiKeyPrefix,
  type KeyHashAlgorithm,
  type VirtualApiKeyMaterial,
} from "./hash.js";
export {
  apiKeyCacheTtlSeconds,
  D1ApiKeyResolver,
  d1ApiKeyResolverFromEnv,
  resetSharedApiKeyCache,
  type ApiKeyBindings,
  type ApiKeyResolverOptions,
} from "./resolver.js";
export {
  INFERENCE_SCOPES,
  isOwnerRole,
  MEMBERSHIP_ROLES,
  membershipRoleAtLeast,
  membershipRoleFromStored,
  membershipRoleGatewayScopes,
  narrowScopes,
  parseMembershipRole,
  type MembershipRole,
} from "./scopes.js";
export {
  ApiKeyStoreUnavailable,
  D1ApiKeyStore,
  InMemoryApiKeyStore,
  storedApiKeyFromRow,
  type ApiKeyStore,
  type StoredApiKey,
} from "./store.js";
