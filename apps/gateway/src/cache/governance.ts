/**
 * The DURABLE, per-tenant half of the `[cache]` section — issue #695.
 *
 * `./config.ts` reads eight Worker `[vars]`. Vars are DEPLOYMENT state that
 * only `wrangler deploy` can change, so until this file existed a tenant could
 * not enable semantic caching, tune its similarity threshold, narrow it to a
 * model set, or throw away what it already held. `docs/rewrite/FLEET-CONSISTENCY.md`
 * row 18 recorded the whole capability as **V** (var-only) for exactly that
 * reason, and that document's own §1.1 names "durable on one Worker, var-only
 * on another" as the shape of both bypasses this tree has shipped. A control
 * that is var-only EVERYWHERE is the same problem one step earlier: it is not
 * an operator control at all, it is a deploy artefact.
 *
 * This module is the durable source: `semantic_cache_policies` on `CONTROL_DB`
 * (`sql/d1-ts/control/0003_semantic_cache_policies.sql`), written by
 * `/admin/v1/semantic-cache-policies/**` in `apps/control-plane` and read here
 * on the request path.
 *
 * ---
 *
 * ## 1. The precedence rule, and the one thing a tenant may NOT do
 *
 * {@link mergeCacheGovernance} overlays the durable row on the var policy, so
 * a NULL column inherits the deployment value and a non-NULL one overrides it.
 * Every field is overridable in both directions EXCEPT the global switch:
 *
 * > **`GATEWAY_CACHE_ENABLED=false` is the operator's master switch and a
 * > tenant row can never override it upward.**
 *
 * That is a deliberate departure from "make everything tenant-tunable", and it
 * is Rust's own rule generalised rather than invented: `ai_cache_enabled`
 * (`state_routing.rs:223`) evaluates a four-level ladder in which any level
 * saying `false` wins and `None` never turns caching ON. A tenant row that
 * could switch the cache on in a deployment whose operator had switched it off
 * would turn a kill switch into a suggestion — and the kill switch is what an
 * operator reaches for when a cache is implicated in an incident. `enabled = 0`
 * in the row is honoured (narrowing is always allowed); `enabled = 1` only
 * confirms a deployment that is already on.
 *
 * Within an enabled deployment the tenant genuinely governs: `mode`
 * (so semantic caching is a tenant opt-in, which is the issue's headline),
 * `similarity_threshold`, `ttl_seconds`, the model scope, and the invalidation
 * epoch.
 *
 * ## 2. Why a failed read DISABLES the cache instead of falling back
 *
 * `./config.ts` argues at length that a bad cache SETTING must not cost
 * availability — an unparsable var turns the cache off and reports `bypass`
 * rather than 503-ing. That argument is about a value the operator typed. This
 * is a different failure: the durable row could not be READ, so the gateway
 * does not know what the tenant asked for. Falling back to the vars would
 *
 *   - re-enable caching for a tenant that had turned it off,
 *   - widen a threshold the tenant had tightened, and
 *   - ignore an `invalidation_epoch` bump that had just been performed —
 *     i.e. keep serving bodies an operator believes they have purged.
 *
 * All three are the WIDENING direction, which is the one direction a cache
 * opt-out must never fail in (`./config.ts` says the same about a dropped
 * `GATEWAY_CACHE_DISABLED_MODELS` entry). So an unreadable table returns
 * {@link CACHE_GOVERNANCE_UNAVAILABLE} and the middleware neither serves nor
 * stores — the same fail-closed posture `./fingerprint.ts` takes for an
 * unreadable guardrail policy set, and for the same reason.
 *
 * ## 3. Why the read is per REQUEST and not memoized on `env`
 *
 * `./fingerprint.ts` memoizes the guardrail fingerprint per isolate, and says
 * why: the guardrail ENGINE has the same staleness, so the cache can never be
 * staler than the screening it stands in for. Nothing analogous holds here.
 * The whole point of #695 is that a governance change must take effect
 * WITHOUT a deploy, and "the tenant's purge lands whenever this isolate
 * happens to recycle" is the deploy-time problem wearing a shorter timescale.
 * Explicit invalidation in particular is worthless if it is eventually
 * consistent with an unbounded bound.
 *
 * The cost is ONE indexed primary-key row read, on the path of a request that
 * has already paid for a credential resolution and (in the deployed chain) an
 * admission batch against the same database — the same amplification argument
 * `routes/drain.ts` makes for its own durable read, and it is issued only for
 * requests that are already cacheable, i.e. after the operation, the method,
 * the body size and the streaming flag have all been checked.
 */

/** Binding name of the CONTROL D1. Same constant `guardrails/d1.ts` uses. */
export const CONTROL_DATABASE_BINDING = "CONTROL_DB";

/** The scope kinds a governance row may be written for. */
export const CACHE_GOVERNANCE_SCOPE_KINDS = ["tenant"] as const;
export type CacheGovernanceScopeKind = (typeof CACHE_GOVERNANCE_SCOPE_KINDS)[number];

/**
 * One governed scope's overrides. Every field is optional in the SQL sense —
 * `null` means "inherit the deployment value", never "the zero value".
 */
export interface CacheGovernance {
  readonly scopeType: CacheGovernanceScopeKind;
  readonly scopeId: string;
  readonly enabled: boolean | null;
  readonly mode: "exact_match" | "semantic" | null;
  readonly similarityThreshold: number | null;
  readonly ttlSeconds: number | null;
  /** Non-empty ⇒ ONLY these logical models are cached for this scope. */
  readonly scopedModels: readonly string[] | null;
  /** Monotonic. Inside the cache key, so a bump makes every old digest dead. */
  readonly invalidationEpoch: number;
  /** CAS token, mirrored from the row so a reader can report what it saw. */
  readonly generation: number;
}

/**
 * The result of a governance lookup.
 *
 * Three-valued on purpose, and the third value is the one that matters:
 * `unavailable` is NOT `none`. Collapsing them would make a database outage
 * indistinguishable from "this tenant has no policy", which is precisely the
 * silent widening §2 exists to prevent.
 */
export type CacheGovernanceLookup =
  | { readonly kind: "none" }
  | { readonly kind: "found"; readonly governance: CacheGovernance }
  | { readonly kind: "unavailable"; readonly detail: string };

/** Shared singleton for the common answer, so callers can compare cheaply. */
export const CACHE_GOVERNANCE_NONE: CacheGovernanceLookup = { kind: "none" };

/** Build the fail-closed answer with the diagnostic the operator needs. */
export function CACHE_GOVERNANCE_UNAVAILABLE(detail: string): CacheGovernanceLookup {
  return { kind: "unavailable", detail };
}

/** What the middleware asks for one request. */
export interface CacheGovernanceSource {
  governanceFor(scopeId: string): Promise<CacheGovernanceLookup>;
}

// ---------------------------------------------------------------------------
// The narrow database port
// ---------------------------------------------------------------------------

type Row = Record<string, unknown>;

/**
 * The subset of `D1Database` this source reads. A live binding satisfies it
 * structurally, so nothing is cast at the composition root — the same shape
 * `guardrails/d1.ts` uses, for the same reason.
 */
export interface CacheGovernanceDatabase {
  prepare(sql: string): CacheGovernanceStatement;
}

export interface CacheGovernanceStatement {
  bind(...values: unknown[]): CacheGovernanceStatement;
  all(): Promise<{ results?: Row[] | null }>;
}

/** Exported so a test can pin the statement rather than restate it. */
export const CACHE_GOVERNANCE_SELECT_SQL =
  "SELECT scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds, " +
  "scoped_models, invalidation_epoch, generation " +
  "FROM semantic_cache_policies WHERE scope_type = ?1 AND scope_id = ?2";

function isGovernanceDatabase(value: unknown): value is CacheGovernanceDatabase {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as CacheGovernanceDatabase).prepare === "function"
  );
}

/**
 * A row that cannot be interpreted.
 *
 * Thrown rather than defaulted: a `similarity_threshold` of `"0,92"` written
 * by some future admin leg must not silently become "no override", because the
 * tenant would then be caching under the deployment's looser number while the
 * console showed theirs. Fail closed, exactly like an unreadable table.
 */
class GovernanceRowError extends Error {}

function optionalBoolean(value: unknown, column: string): boolean | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "number" && (value === 0 || value === 1)) return value === 1;
  if (typeof value === "boolean") return value;
  throw new GovernanceRowError(`semantic_cache_policies.${column} must be 0, 1 or NULL`);
}

function optionalMode(value: unknown): "exact_match" | "semantic" | null {
  if (value === null || value === undefined || value === "") return null;
  if (value === "exact_match" || value === "semantic") return value;
  throw new GovernanceRowError(
    `semantic_cache_policies.mode must be "exact_match", "semantic" or NULL`,
  );
}

function optionalThreshold(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const parsed = typeof value === "number" ? value : Number(value);
  // The SAME range `config.ts` enforces on the var, and for the same reason:
  // cosine similarity is at most 1.0, so a higher threshold is silently inert,
  // and `cosineSimilarity` answers 0 for a degenerate vector, so a threshold of
  // 0 would turn every zero-magnitude embedding into a hit on an arbitrary
  // entry. An out-of-range durable value is refused rather than clamped —
  // clamping would enforce a number the tenant never chose.
  if (!Number.isFinite(parsed) || !(parsed > 0 && parsed <= 1)) {
    throw new GovernanceRowError(
      "semantic_cache_policies.similarity_threshold must be within (0.0, 1.0] or NULL",
    );
  }
  return parsed;
}

function optionalPositiveInt(value: unknown, column: string): number | null {
  if (value === null || value === undefined) return null;
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new GovernanceRowError(`semantic_cache_policies.${column} must be a positive integer`);
  }
  return parsed;
}

function optionalNameList(value: unknown): readonly string[] | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") {
    throw new GovernanceRowError("semantic_cache_policies.scoped_models must be a JSON array");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new GovernanceRowError("semantic_cache_policies.scoped_models is not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== "string")) {
    throw new GovernanceRowError(
      "semantic_cache_policies.scoped_models must be a JSON array of strings",
    );
  }
  const names = (parsed as string[]).map((entry) => entry.trim()).filter((entry) => entry !== "");
  return names.length === 0 ? null : names;
}

function rowToGovernance(row: Row): CacheGovernance {
  const epoch = row.invalidation_epoch;
  const parsedEpoch = typeof epoch === "number" ? epoch : Number(epoch ?? 0);
  if (!Number.isSafeInteger(parsedEpoch) || parsedEpoch < 0) {
    throw new GovernanceRowError(
      "semantic_cache_policies.invalidation_epoch must be a non-negative integer",
    );
  }
  const generation = Number(row.generation ?? 0);
  return {
    scopeType: "tenant",
    scopeId: String(row.scope_id ?? ""),
    enabled: optionalBoolean(row.enabled, "enabled"),
    mode: optionalMode(row.mode),
    similarityThreshold: optionalThreshold(row.similarity_threshold),
    ttlSeconds: optionalPositiveInt(row.ttl_seconds, "ttl_seconds"),
    scopedModels: optionalNameList(row.scoped_models),
    invalidationEpoch: parsedEpoch,
    generation: Number.isSafeInteger(generation) ? generation : 0,
  };
}

/** The durable {@link CacheGovernanceSource}. */
export function d1CacheGovernanceSource(db: CacheGovernanceDatabase): CacheGovernanceSource {
  return {
    async governanceFor(scopeId: string): Promise<CacheGovernanceLookup> {
      let rows: Row[];
      try {
        const answer = await db.prepare(CACHE_GOVERNANCE_SELECT_SQL).bind("tenant", scopeId).all();
        rows = answer.results ?? [];
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return CACHE_GOVERNANCE_UNAVAILABLE(`semantic cache policy lookup failed: ${detail}`);
      }
      const row = rows[0];
      if (row === undefined) return CACHE_GOVERNANCE_NONE;
      try {
        return { kind: "found", governance: rowToGovernance(row) };
      } catch (error) {
        if (error instanceof GovernanceRowError) {
          return CACHE_GOVERNANCE_UNAVAILABLE(error.message);
        }
        throw error;
      }
    },
  };
}

/**
 * The source the composition root gets.
 *
 * `null` — not an empty source — when `CONTROL_DB` is absent, because "no
 * durable store is bound" and "the durable store failed" must stay distinct:
 * an unbound deployment is a var-only deployment and behaves exactly as it did
 * before this file existed, while a BOUND-but-broken one fails closed. Wiring
 * the two together is how a real outage would come to look like a
 * configuration choice.
 */
export function cacheGovernanceSourceFromEnv(
  env: Record<string, unknown> | undefined,
): CacheGovernanceSource | null {
  const binding = env?.[CONTROL_DATABASE_BINDING];
  return isGovernanceDatabase(binding) ? d1CacheGovernanceSource(binding) : null;
}

// ---------------------------------------------------------------------------
// The merge, and the fingerprint that makes a change take effect
// ---------------------------------------------------------------------------

/** The subset of `ResponseCachePolicy` a governance row can move. */
export interface GovernableCachePolicy {
  readonly enabled: boolean;
  readonly mode: "exact_match" | "semantic";
  readonly semanticSimilarityThreshold: number;
  readonly ttlSeconds: number;
}

/** The effective policy for ONE request, plus what it was derived from. */
export interface EffectiveCachePolicy<P extends GovernableCachePolicy> {
  readonly policy: P;
  /** `null` when no row governed this request. */
  readonly governance: CacheGovernance | null;
}

/**
 * Overlay a governance row on the deployment policy.
 *
 * Order of the two `enabled` clauses is the whole master-switch rule (§1): the
 * var is read first and a `false` there is final.
 */
export function mergeCacheGovernance<P extends GovernableCachePolicy>(
  policy: P,
  governance: CacheGovernance | null,
  logicalModel: string,
): P {
  if (governance === null) return policy;
  if (!policy.enabled) return policy;

  // Narrowing only, in BOTH the explicit and the implicit form: an `enabled`
  // of `false` turns this tenant's caching off, and a model scope that does not
  // name the model being called does the same for that call.
  const scoped = governance.scopedModels;
  const outOfScope = scoped !== null && !scoped.includes(logicalModel);
  if (governance.enabled === false || outOfScope) {
    return { ...policy, enabled: false };
  }

  return {
    ...policy,
    mode: governance.mode ?? policy.mode,
    semanticSimilarityThreshold:
      governance.similarityThreshold ?? policy.semanticSimilarityThreshold,
    ttlSeconds: governance.ttlSeconds ?? policy.ttlSeconds,
  };
}

/**
 * The material mixed into every cache key for a governed request — the
 * `governance_fingerprint` field of `./key.ts`.
 *
 * **This is the correctness half of making the cache configurable, and it is
 * the trap issue #695 names.** `./fingerprint.ts` already mixes in the
 * guardrail policy set, because a cache HIT returns before response screening
 * runs and a body screened under looser rules must not survive a tightening.
 * The moment the cache's OWN rules become mutable at runtime they need the same
 * treatment, for two distinct reasons:
 *
 *  1. **Invalidation.** `invalidation_epoch` is the only purge primitive
 *     available to this port: the Cloudflare Cache API cannot enumerate or
 *     wildcard-delete keys, and the semantic store is per-isolate, so there is
 *     nothing to walk. Bumping a counter INSIDE the digest makes every entry
 *     written under the old value unaddressable, instantly and in every isolate
 *     at once, without a single delete. Take the epoch out of the key and
 *     `POST …/invalidate` becomes a row update with no effect whatsoever.
 *
 *  2. **The threshold.** A change to the similarity threshold changes which
 *     bodies this tenant is willing to have answered by a NEAR match. Entries
 *     already sitting in the bucket were admitted under the previous answer to
 *     that question, so re-matching them under the new one reuses a decision
 *     the tenant has just revoked — and does so invisibly, because nothing in
 *     the entry records the threshold it was admitted under. Putting the
 *     threshold in the bucket key makes a threshold change a clean boundary:
 *     tighten it and the loose-era entries are gone rather than merely harder
 *     to reach; loosen it and the tenant gets matches made under the setting
 *     they actually chose. It costs a cold cache after a tuning change, which
 *     is the correct price for a control that is supposed to mean something.
 *
 * `mode` and `ttl_seconds` are folded in for the same reason as the threshold —
 * they are the governed rules an entry was admitted under.
 *
 * ## The scope id is deliberately NOT in here
 *
 * An earlier revision included `scope=tenant:<id>` as belt-and-braces against
 * two tenants sharing a key. It is redundant — `./key.ts` already carries all
 * four tenancy fields, the api-key id, the credential source and the scope
 * digest, and `test/cache/key.test.ts` fails if any one of them stops changing
 * the digest — and the redundancy was actively harmful: with the scope id in
 * this string, neutralizing `tenant_id` AND `api_key_id` AND `key_source` in
 * `keyRecord` left every cross-tenant assertion in
 * `test/cache/governance.test.ts` GREEN. A field whose only measurable effect
 * is to hide a regression in the fence it is standing behind is worse than
 * absent, so it is absent. The tenant fence is one mechanism, held by one set
 * of tests, and it fails visibly.
 *
 * The string is deliberately READABLE rather than hashed: it is one component
 * of a record that is itself canonicalized and SHA-256'd by `./key.ts`, so
 * hashing here would buy nothing and would make a failing key assertion
 * unreadable.
 */
export function cacheGovernanceFingerprint(
  effective: GovernableCachePolicy,
  governance: CacheGovernance | null,
): string {
  if (governance === null) {
    // A deployment with no governed row must produce the SAME key it produced
    // before #695, or every entry in every existing deployment is orphaned by
    // the upgrade. `CACHE_KEY_VERSION` is the tool for a deliberate rotation;
    // this field must not be a second, accidental one.
    return "ungoverned";
  }
  return [
    `epoch=${governance.invalidationEpoch}`,
    `mode=${effective.mode}`,
    `threshold=${effective.semanticSimilarityThreshold}`,
    `ttl=${effective.ttlSeconds}`,
  ].join("|");
}
