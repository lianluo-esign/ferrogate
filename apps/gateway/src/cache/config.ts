/**
 * The `[cache]` section, read off Worker vars.
 *
 * Clean-room port of `packages/config`'s `cacheConfigSchema`
 * (`schema/sections.ts:350`, itself the port of Rust `CacheConfig`) plus the
 * four-level opt-out ladder Rust evaluates in `AppState::ai_cache_enabled`
 * (`state_routing.rs:223`):
 *
 *   1. `cache.enabled` — the global switch, **default `false`** exactly as the
 *      Zod schema defaults it. An unconfigured deployment caches nothing.
 *   2. the gateway-config PROFILE's `cache_enabled` (`x-ferrogate-config`).
 *   3. the MODEL row's `cache_enabled`.
 *   4. the API KEY row's `cache_enabled`.
 *
 * Any of the four saying `false` wins; `None`/absent never turns caching ON.
 *
 * ## Why the vars are named after the section and not invented
 *
 * `packages/config` has validated `[cache]` since wave 1 and — like
 * `[network_access]` before `middleware/network.ts` landed — **nothing read
 * it**. An operator who set `cache.ttl_secs` got a green `ferrogate check` and
 * a gateway that never cached. These vars are that section's Worker spelling,
 * one var per field, so the mapping is mechanical and auditable.
 *
 * ## Misconfiguration turns the cache OFF, it does not 503
 *
 * This is the deliberate opposite of `middleware/network.ts`, and the reason is
 * the direction each control fails in. An unreadable IP allowlist that degrades
 * to "no allowlist" is an OPEN GATEWAY, so that one must refuse traffic. An
 * unreadable cache setting that degrades to "no cache" costs latency and money
 * and nothing else — refusing every request because `GATEWAY_CACHE_TTL_SECONDS`
 * has a typo would be a self-inflicted outage. So a bad value disables the
 * cache and reports the diagnostic on {@link ResponseCachePolicy.misconfiguration},
 * which the middleware surfaces as an `x-ferrogate-cache: bypass` header rather
 * than an error.
 */

/** `cache.enabled` — `"true"` and nothing else switches the cache on. */
export const CACHE_ENABLED_VAR = "GATEWAY_CACHE_ENABLED";
/** `cache.ttl_secs` — positive integer seconds. Rust default 300. */
export const CACHE_TTL_VAR = "GATEWAY_CACHE_TTL_SECONDS";
/** `cache.max_records` — bounded entry count. Rust default 1000. */
export const CACHE_MAX_RECORDS_VAR = "GATEWAY_CACHE_MAX_RECORDS";
/** `cache.mode` — `exact_match` (ported) or `semantic` (see the PORT-TODO). */
export const CACHE_MODE_VAR = "GATEWAY_CACHE_MODE";
/** JSON array of logical model names with `cache_enabled = false`. */
export const CACHE_DISABLED_MODELS_VAR = "GATEWAY_CACHE_DISABLED_MODELS";
/** JSON array of api-key ids with `cache_enabled = false`. */
export const CACHE_DISABLED_API_KEYS_VAR = "GATEWAY_CACHE_DISABLED_API_KEYS";
/** JSON array of `[[gateway_configs]]` profile ids with `cache_enabled = false`. */
export const CACHE_DISABLED_PROFILES_VAR = "GATEWAY_CACHE_DISABLED_PROFILES";

/**
 * Rust `CacheMode`. Only `exact_match` is ported.
 *
 * PORT-TODO(inventory-request-path §1.7 "Caches", issue #273): `semantic` is
 * `SemanticResponseCache` — feature-hashed local embeddings and a cosine
 * threshold (`crates/ferrogate-gateway/src/semantic_cache.rs`). On this
 * platform that is **Vectorize + Workers AI embeddings** (inventory §1.8), and
 * neither binding is declared in `apps/gateway/wrangler.toml` (see its
 * NOT DECLARED section: `[ai]` has no reader, and there is no `[[vectorize]]`
 * entry at all). Rather than fake it, `mode = "semantic"` is accepted, the
 * EXACT-MATCH layer runs, and `semanticCacheHitsTotal` stays 0 — which is the
 * honest reading of `ferrogate_ai_cache_requests_total{status="semantic_hit"}`.
 * `src/cache/metrics.ts` never increments it.
 */
export type ResponseCacheMode = "exact_match" | "semantic";

/** The parsed `[cache]` section. */
export interface ResponseCachePolicy {
  /** `cache.enabled`. */
  readonly enabled: boolean;
  readonly mode: ResponseCacheMode;
  /** `cache.ttl_secs`, seconds. */
  readonly ttlSeconds: number;
  /** `cache.max_records`. Honoured by the memory store; see `store.ts`. */
  readonly maxRecords: number;
  /** Logical models whose row carries `cache_enabled = false`. */
  readonly disabledModels: ReadonlySet<string>;
  /** Api-key ids whose row carries `cache_enabled = false`. */
  readonly disabledApiKeyIds: ReadonlySet<string>;
  /** `[[gateway_configs]]` profile ids carrying `cache_enabled = false`. */
  readonly disabledProfileIds: ReadonlySet<string>;
  /** Non-`null` when a declared value was unusable. Implies `enabled === false`. */
  readonly misconfiguration: string | null;
}

/** Rust `CacheConfig::default()` — `enabled: false`, so caching is opt-in. */
export const CACHE_DISABLED_POLICY: ResponseCachePolicy = {
  enabled: false,
  mode: "exact_match",
  ttlSeconds: 300,
  maxRecords: 1000,
  disabledModels: new Set(),
  disabledApiKeyIds: new Set(),
  disabledProfileIds: new Set(),
  misconfiguration: null,
};

/** The seven vars this module reads. */
export interface ResponseCacheBindings {
  readonly GATEWAY_CACHE_ENABLED?: string | undefined;
  readonly GATEWAY_CACHE_TTL_SECONDS?: string | undefined;
  readonly GATEWAY_CACHE_MAX_RECORDS?: string | undefined;
  readonly GATEWAY_CACHE_MODE?: string | undefined;
  readonly GATEWAY_CACHE_DISABLED_MODELS?: string | undefined;
  readonly GATEWAY_CACHE_DISABLED_API_KEYS?: string | undefined;
  readonly GATEWAY_CACHE_DISABLED_PROFILES?: string | undefined;
}

/**
 * Parse a JSON array of strings, or a bare comma-separated list.
 *
 * Same two accepted spellings as `middleware/network.ts`'s allowlist, and for
 * the same reason: a single entry is the common case and `"gpt-4o"` is not
 * valid JSON. `null` — not an empty set — signals "declared but unusable", so
 * the caller can report it rather than silently widening the cache.
 *
 * A value that begins `{` is refused outright rather than read as a one-element
 * comma list: `{"a":1}` is an operator who wrote the wrong JSON shape, and
 * accepting it as the literal model name `{"a":1}` would silently drop their
 * opt-out — the one failure direction that can start caching something they
 * excluded.
 */
export function parseNameList(raw: string): readonly string[] | null {
  const trimmed = raw.trim();
  if (trimmed === "") return [];
  if (trimmed.startsWith("{")) return null;
  if (trimmed.startsWith("[")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return null;
    }
    if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== "string")) return null;
    return (parsed as string[]).map((entry) => entry.trim()).filter((entry) => entry !== "");
  }
  return trimmed
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

function parsePositiveInt(raw: string): number | null {
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

/** `[cache]` out of the Worker vars. */
export function responseCachePolicy(env: ResponseCacheBindings | undefined): ResponseCachePolicy {
  const enabled = (env?.GATEWAY_CACHE_ENABLED ?? "").trim().toLowerCase() === "true";
  if (!enabled) {
    // Nothing else can matter: `ai_cache_enabled` returns `false` on the global
    // switch before it reads any other field. Parsing the rest would let a typo
    // in an inert deployment produce a diagnostic about a cache that is off.
    return CACHE_DISABLED_POLICY;
  }

  let misconfiguration: string | null = null;
  const fail = (detail: string): void => {
    misconfiguration ??= detail;
  };

  const rawTtl = (env?.GATEWAY_CACHE_TTL_SECONDS ?? "").trim();
  let ttlSeconds = CACHE_DISABLED_POLICY.ttlSeconds;
  if (rawTtl !== "") {
    const parsed = parsePositiveInt(rawTtl);
    if (parsed === null) {
      fail(`${CACHE_TTL_VAR} must be a positive integer (value: ${JSON.stringify(rawTtl)})`);
    } else {
      ttlSeconds = parsed;
    }
  }

  const rawMax = (env?.GATEWAY_CACHE_MAX_RECORDS ?? "").trim();
  let maxRecords = CACHE_DISABLED_POLICY.maxRecords;
  if (rawMax !== "") {
    const parsed = parsePositiveInt(rawMax);
    if (parsed === null) {
      fail(
        `${CACHE_MAX_RECORDS_VAR} must be a positive integer (value: ${JSON.stringify(rawMax)})`,
      );
    } else {
      maxRecords = parsed;
    }
  }

  const rawMode = (env?.GATEWAY_CACHE_MODE ?? "").trim();
  let mode: ResponseCacheMode = "exact_match";
  if (rawMode !== "") {
    if (rawMode === "exact_match" || rawMode === "semantic") {
      mode = rawMode;
    } else {
      fail(
        `${CACHE_MODE_VAR} must be "exact_match" or "semantic" (value: ${JSON.stringify(rawMode)})`,
      );
    }
  }

  const lists: Array<[string, string, Set<string>]> = [];
  for (const [name, raw] of [
    [CACHE_DISABLED_MODELS_VAR, env?.GATEWAY_CACHE_DISABLED_MODELS ?? ""],
    [CACHE_DISABLED_API_KEYS_VAR, env?.GATEWAY_CACHE_DISABLED_API_KEYS ?? ""],
    [CACHE_DISABLED_PROFILES_VAR, env?.GATEWAY_CACHE_DISABLED_PROFILES ?? ""],
  ] as const) {
    const entries = parseNameList(raw);
    if (entries === null) {
      // A dropped opt-out is the one failure that could WIDEN the cache: an
      // operator who excluded a model from caching would find it cached again.
      fail(`${name} must be a JSON array of strings or a comma-separated list`);
      lists.push([name, raw, new Set()]);
    } else {
      lists.push([name, raw, new Set(entries)]);
    }
  }

  if (misconfiguration !== null) {
    return { ...CACHE_DISABLED_POLICY, misconfiguration };
  }

  return {
    enabled: true,
    mode,
    ttlSeconds,
    maxRecords,
    disabledModels: lists[0]![2],
    disabledApiKeyIds: lists[1]![2],
    disabledProfileIds: lists[2]![2],
    misconfiguration: null,
  };
}

/**
 * Memoized by the VAR VALUES, never by the env object — same reasoning as
 * `networkAccessPolicyFromEnv`: keying on the object would make a changed var
 * invisible until the isolate recycled.
 */
const POLICY_CACHE = new Map<string, ResponseCachePolicy>();
const POLICY_CACHE_LIMIT = 32;

export function responseCachePolicyFromEnv(
  env: ResponseCacheBindings | undefined,
): ResponseCachePolicy {
  const key = [
    env?.GATEWAY_CACHE_ENABLED ?? "",
    env?.GATEWAY_CACHE_TTL_SECONDS ?? "",
    env?.GATEWAY_CACHE_MAX_RECORDS ?? "",
    env?.GATEWAY_CACHE_MODE ?? "",
    env?.GATEWAY_CACHE_DISABLED_MODELS ?? "",
    env?.GATEWAY_CACHE_DISABLED_API_KEYS ?? "",
    env?.GATEWAY_CACHE_DISABLED_PROFILES ?? "",
  ].join(" ");
  const cached = POLICY_CACHE.get(key);
  if (cached !== undefined) return cached;
  const policy = responseCachePolicy(env);
  if (POLICY_CACHE.size >= POLICY_CACHE_LIMIT) POLICY_CACHE.clear();
  POLICY_CACHE.set(key, policy);
  return policy;
}

/**
 * `AppState::ai_cache_enabled` — the four-level opt-out, in the Rust order.
 *
 * `profileId` is the `x-ferrogate-config` header value. The full profile
 * resolution (`resolve_gateway_config_profile`, which 400s on an unknown id) is
 * still unported and has its marker in `src/inference/handlers.ts`; the ONE
 * thing that table contributes to caching — `cache_enabled = false` — is
 * honoured here off {@link CACHE_DISABLED_PROFILES_VAR}, so a profile that
 * disables caching disables it, which is the fail-safe half of that gap.
 */
export function aiCacheEnabled(
  policy: ResponseCachePolicy,
  input: {
    readonly apiKeyId: string | null;
    readonly logicalModel: string;
    readonly profileId: string | null;
  },
): boolean {
  if (!policy.enabled) return false;
  if (input.profileId !== null && policy.disabledProfileIds.has(input.profileId)) return false;
  if (policy.disabledModels.has(input.logicalModel)) return false;
  if (input.apiKeyId !== null && policy.disabledApiKeyIds.has(input.apiKeyId)) return false;
  return true;
}
