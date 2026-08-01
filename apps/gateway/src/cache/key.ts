/**
 * The exact-match cache KEY — Rust `AppState::ai_response_cache_key`
 * (`state_routing.rs:281`).
 *
 * The key is the entire isolation story of a shared response cache, so every
 * field below is load-bearing and the tests name the failure each one prevents.
 * Rust serialized this struct and hashed it:
 *
 * ```rust
 * struct CacheKeyInput<'a> {
 *   route, organization_id, team_id, project_id, user_id, api_key_id,
 *   logical_model, provider, provider_model, stream: bool,
 *   request_body, guardrail_policy_fingerprint,
 * }
 * ```
 *
 * ## Three deliberate deviations, each stated
 *
 * **1. SHA-256, not FNV-1a-64.** Rust hashed the serialized input with
 * `fnv1a64` and formatted `ai-cache:{:016x}`. FNV-1a is a *linear*, non-cryptographic
 * hash: given a victim tenant's key material an attacker can construct a
 * different input that collides in a handful of operations. In Rust the cache
 * was a process-local `HashMap` whose keys were full structs behind that hash,
 * but here the store is the **Cloudflare Cache API — a namespace shared by
 * every tenant of the deployment** and addressed by the digest alone. A
 * forgeable digest would therefore be a cross-tenant body-disclosure primitive,
 * so the hash is SHA-256. This is strictly stronger; nothing about the key's
 * INPUTS changed.
 *
 * **2. The request body is CANONICALIZED before hashing.** Object keys are
 * sorted recursively, so `{"a":1,"b":2}` and `{"b":2,"a":1}` — the same request
 * — share one entry instead of two. Rust hashed `serde_json::to_vec` of a
 * `serde_json::Value`, whose default `Map` is a `BTreeMap`, i.e. already
 * key-sorted; this reproduces that rather than changing it.
 *
 * **3. `provider` / `provider_model` are NOT in the key.** They cannot be:
 * this key is computed in middleware, BEFORE the model registry resolves the
 * logical model, and `src/inference/` is another agent's module. What replaces
 * them is {@link CacheKeyInput.registryFingerprint} — a digest of the
 * `GATEWAY_PROVIDERS` + `GATEWAY_MODELS` vars the registry is built from — so
 * any CONFIGURED change of the provider or physical model behind a logical name
 * rotates the key exactly as the Rust fields did.
 *
 * The residual difference is runtime FAILOVER: in Rust, a request served by the
 * secondary provider was cached under the secondary's key, so the next request
 * (back on the primary) missed. Here both share one entry, so a caller can be
 * served a body produced by a provider that a fresh request would not have
 * used. That is a fidelity gap, not an isolation gap — the tenant, key, model
 * and body all still match — and it is bounded by `cache.ttl_secs`.
 * // PORT-TODO(inventory-request-path §1.7 "Caches"): NOT a platform limit, and
 * // NOT the one-liner an earlier revision of this note claimed. That revision
 * // said "one `c.set()` in `inference/route-module.ts` plus two fields here";
 * // it is wrong, and the correction is recorded rather than left to mislead.
 * //
 * // A `c.set()` published by the inference module happens AFTER this
 * // middleware has already run — `src/index.ts` mounts `responseCache` ahead
 * // of the route handler (rate limit → guardrails → tenancy → CACHE → validate
 * // → dispatch), which is the only order in which a cache can serve a HIT
 * // without dispatching. So a variable written during dispatch cannot be an
 * // input to the key that decided whether to dispatch at all.
 * //
 * // Closing it means moving model RESOLUTION (registry lookup + canary/shadow
 * // selection + failover eligibility) ahead of the cache middleware, so the
 * // physical provider is known before the lookup. That is a request-pipeline
 * // reordering across two modules, with its own cost (a resolution on every
 * // cached request) and its own risk (the reliability layer's breaker state is
 * // read at resolution time), which is why it is a slice and not a line.
 * // `registryFingerprint` covers every CONFIGURED rotation in the meantime;
 * // the residue is runtime failover only, exactly as described above.
 *
 * ## What is ADDED to the Rust field set, and why
 *
 * `keySource`, `platformOperator` and `scopeDigest` are not Rust fields. Rust
 * keyed on `api_key_id`, which is already per-credential, and that is normally
 * enough — but `api_key_id` is `Option`, and two DIFFERENT credentials can both
 * present `None` (a static operator key and an external-auth principal both
 * resolve with no durable row id). Under the Rust field set alone those two
 * share a cache entry whenever their tenancy matches. Adding the credential's
 * source, its operator bit and a digest of its granted scopes makes the
 * partition per-authority rather than per-optional-id, which is what
 * "never serve a cached response across API keys with different scopes"
 * requires. Every added field only ever SPLITS the key space.
 */

/** The request/identity material an entry is bound to. */
export interface CacheKeyInput {
  /** Contract `operation_id` — the Rust `endpoint.route()` discriminator. */
  readonly route: string;
  /** The matched contract PATH template, so two ops never share a key. */
  readonly path: string;
  /**
   * The four tenancy fields, named after this tree's `Tenancy` rather than
   * Rust's `TenantContext`. Rust carried `organization_id` / `team_id` /
   * `project_id` / `user_id`; the TS auth context resolves `tenantId` /
   * `workspaceId` / `projectId` / `userId`. They are the same four levels of
   * the same hierarchy under different names, and using the local names keeps
   * the mapping from `AuthContext.tenancy` mechanical instead of guessed.
   */
  readonly tenantId: string | null;
  readonly workspaceId: string | null;
  readonly projectId: string | null;
  readonly userId: string | null;
  /** Rust `tenant.api_key_id`. */
  readonly apiKeyId: string | null;
  /** ADDED — see the header. `AuthContext.source`. */
  readonly keySource: string;
  /** ADDED — see the header. `AuthContext.platformOperator`. */
  readonly platformOperator: boolean;
  /** ADDED — see the header. A digest of the granted scope set. */
  readonly scopeDigest: string;
  readonly logicalModel: string;
  /** Always `false`: a streaming request is never keyed (Rust `if request.stream`). */
  readonly stream: false;
  /** The parsed JSON request body. */
  readonly requestBody: unknown;
  /** Rust `guardrail_policy_fingerprint` (#233). See `./fingerprint.ts`. */
  readonly guardrailPolicyFingerprint: string;
  /** Stands in for Rust's `provider` + `provider_model`. See the header. */
  readonly registryFingerprint: string;
}

/**
 * Bumped whenever the KEY LAYOUT changes.
 *
 * Entries written by an older gateway remain addressable under their old
 * digests, but nothing computes those digests any more, so a layout change can
 * never serve a body that was keyed under different rules. It is the cheapest
 * possible migration and it is inside the hash, not beside it.
 */
export const CACHE_KEY_VERSION = "fg-ai-cache-v1";

/**
 * Deterministic JSON: object keys sorted recursively, everything else verbatim.
 *
 * `undefined` members are dropped exactly as `JSON.stringify` drops them, and
 * arrays keep their order (order is semantic in a `messages` array).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value === null || typeof value !== "object") return value;
  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const name of Object.keys(source).sort()) {
    out[name] = canonicalize(source[name]);
  }
  return out;
}

/**
 * Every field of the identity, as a record.
 *
 * The exact key and the SEMANTIC SCOPE (`./semantic.ts`) are both built from
 * this ONE function — the scope is literally this record with `request_body`
 * and `stream` removed, which is exactly the relationship Rust's
 * `ai_semantic_scope_hash` has to `ai_response_cache_key`. Writing it once is
 * the anti-drift property that matters here: a field added to the exact key to
 * SPLIT the key space (as `key_source`, `platform_operator` and `scope_digest`
 * were) would otherwise have to be remembered a second time for the scope, and
 * forgetting it there is a cross-identity leak in the semantic layer only —
 * the hardest possible place to notice one.
 */
function keyRecord(input: CacheKeyInput): Record<string, unknown> {
  return {
    version: CACHE_KEY_VERSION,
    route: input.route,
    path: input.path,
    tenant_id: input.tenantId,
    workspace_id: input.workspaceId,
    project_id: input.projectId,
    user_id: input.userId,
    api_key_id: input.apiKeyId,
    key_source: input.keySource,
    platform_operator: input.platformOperator,
    scope_digest: input.scopeDigest,
    logical_model: input.logicalModel,
    provider_registry_fingerprint: input.registryFingerprint,
    stream: input.stream,
    request_body: input.requestBody,
    guardrail_policy_fingerprint: input.guardrailPolicyFingerprint,
  };
}

/** The exact byte string that gets hashed. Exported so a test can inspect it. */
export function cacheKeyMaterial(input: CacheKeyInput): string {
  return canonicalJson(keyRecord(input));
}

/**
 * The SEMANTIC SCOPE material — Rust `ai_semantic_scope_hash`'s `ScopeInput`.
 *
 * Every field of the exact key EXCEPT the request body, which is what the
 * embedding replaces: entries in one bucket are compared by cosine similarity
 * of their prompts, so everything that must NOT be compared away — tenant,
 * credential identity, granted scopes, route, logical model, the provider
 * registry fingerprint and the guardrail-policy fingerprint — has to be in the
 * bucket key instead. `stream` goes with the body because the semantic layer,
 * like the exact one, is only ever consulted for a non-streaming request.
 */
export function semanticScopeMaterial(input: CacheKeyInput): string {
  const { request_body: _body, stream: _stream, ...scope } = keyRecord(input);
  return canonicalJson(scope);
}

/**
 * Rust `ai_semantic_scope_hash`, as a `sem-scope:<sha256-hex>` string.
 *
 * SHA-256 rather than Rust's FNV-1a-64 for the reason given in the header:
 * a Rust `HashMap` bucket collision still compares the full key, a
 * digest-addressed bucket has nothing left to compare, and a forged bucket
 * collision here would serve one tenant's body to another.
 */
export async function semanticScopeHash(input: CacheKeyInput): Promise<string> {
  return `sem-scope:${await sha256Hex(semanticScopeMaterial(input))}`;
}

/** Lowercase hex SHA-256 of `bytes`. */
export async function sha256Hex(bytes: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bytes));
  let out = "";
  for (const byte of new Uint8Array(digest)) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Rust `ai_response_cache_key`, as a `ai-cache:<sha256-hex>` string. */
export async function aiResponseCacheKey(input: CacheKeyInput): Promise<string> {
  return `ai-cache:${await sha256Hex(cacheKeyMaterial(input))}`;
}

/**
 * Digest of a credential's granted scopes.
 *
 * Sorted, so scope ORDER is not part of the identity, then JSON-encoded rather
 * than joined on a separator: no separator byte is provably absent from a scope
 * name, and a separator that CAN occur inside an element makes `["a b","c"]`
 * and `["a","b c"]` collide. JSON quoting has no such ambiguity.
 */
export function scopeDigest(scopes: readonly string[]): string {
  return JSON.stringify([...scopes].sort());
}
