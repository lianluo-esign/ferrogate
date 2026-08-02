/**
 * Where a tenant's attribution policy comes from (#678).
 *
 * ============================================================================
 * WHY THE POLICY LIVES ON `quota_policies` AND NOT ON A NEW TABLE
 * ============================================================================
 *
 * `quota_policies` is already the per-scope governance row: it is what
 * `POST/PUT /admin/v1/quota-policies/{scope_type}/{scope_id}` writes
 * (`apps/control-plane/src/routes/quota_policy.ts`), what
 * `store/quota_registry.ts` projects into, and what the gateway already reads on
 * the admission path of every authenticated request. Two columns on that row
 * give an operator a configuration surface that already exists, already has RBAC
 * and already has the scoped-authorization rule (#185) that stops a tenant-scoped
 * admin from editing another tenant's governance.
 *
 * A new `attribution_policies` table would have needed its own admin group —
 * six more contract operations, a second scope-authorization implementation and
 * a second thing to keep in sync — to express one enum and one string list.
 *
 * ## Only the TENANT scope is consulted
 *
 * `quota_policies` is scoped `tenant | project | workspace | key` and the QUOTA
 * merge walks the whole chain (min-across). This does NOT, and the asymmetry is
 * a decision rather than an omission: the issue asks for a per-TENANT policy,
 * and a chain merge would have to answer "does a project row that requires
 * nothing relax the tenant's requirement, or not?" — a question with two
 * defensible answers, where picking the wrong one silently drops a finance
 * control. One scope, one answer, and the day a narrower scope is wanted it can
 * be added with the merge rule stated explicitly rather than inherited by
 * accident.
 *
 * ## The `enabled` column is deliberately not read
 *
 * `quota_policies.enabled = 0` is a HARD DENY in `resolveEffectiveQuota`, so a
 * request under a disabled row never reaches this gate at all — reading it here
 * would be dead code that looks like a rule. And if that ever changes, the
 * fail-closed reading is the one this file already implements: disabling a
 * SPEND limit must not also, invisibly, switch off an ATTRIBUTION requirement.
 */
import { type AttributionPolicy, parseAttributionPolicy, parseMissingTagAction } from "./policy.js";

/** The `quota_policies` columns this module reads, named once. */
const ATTRIBUTION_COLUMNS = "required_tags_json, on_missing_tags";

/**
 * The lookup, by AUTHENTICATED tenant.
 *
 * `scope_id = ?` is a bound equality against the tenant the credential resolved
 * to — never a scan, never interpolation, and never a `LIKE`. This one predicate
 * IS the tenant fence for the whole slice: it is what stops tenant A's required
 * tags from refusing tenant B's traffic, and (through {@link cachedAttributionPolicySource})
 * what stops tenant A's DEFAULTS from being stamped on tenant B's spend.
 * `(scope_type, scope_id)` is `UNIQUE` and indexed, so this is one index seek.
 */
const SELECT_TENANT_POLICY =
  `SELECT ${ATTRIBUTION_COLUMNS} FROM quota_policies ` +
  "WHERE scope_type = 'tenant' AND scope_id = ?";

/** Worker vars this slice reads. */
export interface AttributionBindings {
  /**
   * DEV/TEST fallback: a JSON array of
   * `{ tenant_id, required_tags, on_missing }`, mirroring how `src/adapters.ts`
   * backs the credential ports from vars when no database is bound. The DURABLE
   * source is `CONTROL_DB`'s `quota_policies`.
   */
  readonly GATEWAY_ATTRIBUTION_POLICIES?: string | undefined;
  readonly CONTROL_DB?: AttributionDatabase | undefined;
  /** The alias the metering/quota readers already accept. */
  readonly BILLING_DB?: AttributionDatabase | undefined;
}

/** The `D1Database` subset this module needs. A live binding fits. */
export interface AttributionDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { first<T = Record<string, unknown>>(): Promise<T | null> };
  };
}

/**
 * `null` = this tenant is not enforced. `unavailable` is a distinct outcome
 * because it is NOT the same answer: a policy that could not be read is unknown,
 * and treating unknown as "not enforced" would make a control-database blip a
 * window in which every untagged request is silently admitted — the exact
 * failure this slice exists to prevent, arriving through the back door.
 */
export type AttributionResolution =
  | { readonly ok: true; readonly policy: AttributionPolicy | null }
  | { readonly ok: false; readonly detail: string };

export interface AttributionPolicySource {
  policyFor(tenantId: string): Promise<AttributionResolution>;
}

/** A source that enforces nothing — the posture of an unconfigured deployment. */
export const NO_ATTRIBUTION_POLICIES: AttributionPolicySource = {
  async policyFor(): Promise<AttributionResolution> {
    return { ok: true, policy: null };
  },
};

/** Wire shape of a `GATEWAY_ATTRIBUTION_POLICIES` entry. */
interface WireAttributionPolicy {
  readonly tenant_id?: unknown;
  readonly required_tags?: unknown;
  readonly on_missing?: unknown;
}

/**
 * Build a source from the var. A malformed var configures NOTHING, exactly as
 * `parseJsonVar` does elsewhere — see {@link parseAttributionPolicy} on why the
 * fail-open direction is the right one for this control specifically.
 */
export function attributionPolicySourceFromVars(env: AttributionBindings): AttributionPolicySource {
  let rows: WireAttributionPolicy[] = [];
  const raw = env.GATEWAY_ATTRIBUTION_POLICIES;
  if (raw !== undefined && raw.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) rows = parsed as WireAttributionPolicy[];
    } catch {
      rows = [];
    }
  }

  const index = new Map<string, AttributionPolicy>();
  for (const row of rows) {
    if (typeof row?.tenant_id !== "string" || row.tenant_id === "") continue;
    const policy = parseAttributionPolicy({
      requiredTagKeys: row.required_tags,
      onMissing: row.on_missing,
    });
    if (policy !== null) index.set(row.tenant_id, policy);
  }

  return {
    async policyFor(tenantId: string): Promise<AttributionResolution> {
      return { ok: true, policy: index.get(tenantId) ?? null };
    },
  };
}

/** The durable source — one indexed seek against the CONTROL database. */
export function d1AttributionPolicySource(db: AttributionDatabase): AttributionPolicySource {
  return {
    async policyFor(tenantId: string): Promise<AttributionResolution> {
      try {
        const row = await db.prepare(SELECT_TENANT_POLICY).bind(tenantId).first();
        if (row === null || row === undefined) return { ok: true, policy: null };
        return {
          ok: true,
          policy: parseAttributionPolicy({
            requiredTagKeys: jsonArrayColumn(row["required_tags_json"]),
            onMissing: parseMissingTagAction(row["on_missing_tags"]),
          }),
        };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        // A schema that does not HAVE this control cannot be holding a policy,
        // so "not enforced" is not a guess here — it is the only state the
        // database can be in, and it is the pre-#678 behaviour exactly.
        if (schemaPredatesAttribution(detail)) return { ok: true, policy: null };
        // Everything else is an OUTAGE, reported as one. The middleware renders
        // it 503 rather than admitting the request — see `./middleware.ts`.
        return { ok: false, detail };
      }
    },
  };
}

/**
 * Does this D1 failure mean "the schema predates #678" rather than "the
 * database is unavailable"?
 *
 * ## Why this distinction exists at all
 *
 * Without it, deploying this Worker BEFORE applying
 * `sql/d1-ts/control/0006_attribution_tag_policy.sql` would answer 503 on every
 * inference request with a bound `CONTROL_DB` — a total data-plane outage
 * caused by a control that no operator had switched on. Migrations are supposed
 * to run first, and during a rollout the two orders overlap for real.
 *
 * ## Why it is not a fail-open hole
 *
 * The generic fail-open ("we could not read the policy, so serve the request")
 * IS a hole, and this is not it: a `quota_policies` table with no
 * `on_missing_tags` column is physically incapable of holding a policy, so the
 * answer "this tenant is not enforced" is not a guess about unknown state — it
 * is a complete reading of a known one. Once the column exists, any failure to
 * read it is an outage again, and the 503 arm below is the one that fires.
 *
 * Matched on the message because D1 surfaces SQLite's `SQLITE_ERROR` for both
 * cases and offers no error code to switch on. The two shapes are SQLite's own
 * and stable: `no such column: <name>` and `no such table: <name>`.
 */
function schemaPredatesAttribution(detail: string): boolean {
  return (
    /no such column:\s*(required_tags_json|on_missing_tags)/i.test(detail) ||
    /no such table:\s*quota_policies/i.test(detail)
  );
}

/** `TEXT` column holding a JSON array → `unknown[]`; anything else → `[]`. */
function jsonArrayColumn(value: unknown): unknown[] {
  if (typeof value !== "string" || value.trim() === "") return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * A per-isolate, per-TENANT memo in front of any source.
 *
 * ## The cache key is the fence
 *
 * The entry key is the AUTHENTICATED tenant id and nothing else. That is the
 * second half of the tenant fence (`SELECT … scope_id = ?` is the first): a
 * memo keyed on anything coarser — the env, the isolate, "the last policy we
 * saw" — would let tenant A's policy, and therefore tenant A's DEFAULT TAGS,
 * be applied to tenant B's request the moment two tenants share a warm isolate,
 * which on Workers is the normal case rather than the edge case. That is the
 * one failure this slice must not have: it would attribute one tenant's spend
 * to another, in a chargeback export, silently.
 *
 * ## Why an OUTAGE is never cached
 *
 * Caching `{ ok: false }` would extend a one-request blip into a TTL-long
 * refusal window for that tenant. Only successful resolutions are stored.
 */
export function cachedAttributionPolicySource(
  inner: AttributionPolicySource,
  options: { readonly ttlMs?: number; readonly now?: () => number } = {},
): AttributionPolicySource {
  const ttlMs = options.ttlMs ?? DEFAULT_POLICY_TTL_MS;
  const now = options.now ?? (() => Date.now());
  const entries = new Map<string, { policy: AttributionPolicy | null; expiresAtMs: number }>();

  return {
    async policyFor(tenantId: string): Promise<AttributionResolution> {
      const hit = entries.get(tenantId);
      if (hit !== undefined && hit.expiresAtMs > now()) return { ok: true, policy: hit.policy };
      const resolved = await inner.policyFor(tenantId);
      if (resolved.ok) {
        entries.set(tenantId, { policy: resolved.policy, expiresAtMs: now() + ttlMs });
      }
      return resolved;
    },
  };
}

/**
 * How long a resolved policy is trusted inside one isolate.
 *
 * Short on purpose: this is a control an operator turns ON during an incident
 * ("stop admitting untagged spend"), and a long TTL would make the fleet obey
 * minutes later on whichever isolates happen to be warm.
 */
export const DEFAULT_POLICY_TTL_MS = 30_000;

/**
 * The source the deployed Worker uses: durable when a control database is
 * bound, the var otherwise, memoized per isolate either way.
 *
 * Memoized PER ENV OBJECT, because that is the identity `envScopedDeps` and the
 * guardrail engine already key on: Workers hands the same `env` to every request
 * an isolate serves, so this is an isolate-lifetime cache without a
 * module-global that a test cannot reset.
 */
const SOURCES = new WeakMap<object, AttributionPolicySource>();

export function attributionPolicySourceFromEnv(env: AttributionBindings): AttributionPolicySource {
  const key = env as unknown as object;
  const memoized = SOURCES.get(key);
  if (memoized !== undefined) return memoized;
  const db = env.CONTROL_DB ?? env.BILLING_DB;
  const source = cachedAttributionPolicySource(
    db === undefined ? attributionPolicySourceFromVars(env) : d1AttributionPolicySource(db),
  );
  SOURCES.set(key, source);
  return source;
}
