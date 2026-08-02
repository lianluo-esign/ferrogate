/**
 * Where a tenant's residency policy comes from (#681).
 *
 * ============================================================================
 * WHY THE POLICY LIVES ON `quota_policies`, AND WHY ONLY THE TENANT SCOPE
 * ============================================================================
 *
 * Verbatim the reasoning `attribution/source.ts` gives for #678, and
 * deliberately the same table: `quota_policies` is already the per-scope
 * governance row, already has RBAC, already carries the #185 scoped-authorization
 * rule that stops a tenant-scoped admin editing another tenant's governance, and
 * is already read on the admission path. A `residency_policies` table would have
 * needed its own admin group — six more contract operations and a second copy of
 * that authorization rule — to express one list, one flag and one enum.
 *
 * Only `scope_type = 'tenant'` is consulted. Residency is a property of the
 * legal entity, and a chain merge would have to answer "does a project row that
 * states no regions relax the tenant's?", a question whose wrong answer is a
 * silent compliance breach rather than a visible refusal.
 *
 * ============================================================================
 * THE FAIL DIRECTION IS THE OPPOSITE OF #678's, ON PURPOSE
 * ============================================================================
 *
 * `attributionPolicySourceFromVars` returns "not enforced" for a malformed var,
 * and argues correctly that an unreadable ATTRIBUTION requirement can only
 * refuse traffic that was previously served, so failing open costs a bill line
 * and failing closed costs an outage.
 *
 * Residency inverts that. An unreadable residency requirement read as "not
 * enforced" does not refuse anything — it SERVES, possibly out of region, and
 * every request succeeds, so nobody finds out. {@link ResidencyResolution}
 * therefore has an explicit `ok: false` arm for BOTH the transport failure and
 * the unparseable row, and `./middleware.ts` renders it `503
 * residency_policy_unavailable` rather than admitting the request.
 *
 * The one exception is a schema that PREDATES this migration — see
 * {@link schemaPredatesResidency}. A `quota_policies` table with no
 * `residency_regions_json` column is physically incapable of holding a policy,
 * so "this tenant is not governed" is a complete reading of a known state
 * rather than a guess about an unknown one. Without that arm, deploying this
 * Worker before applying `sql/d1-ts/control/0007_residency_policy.sql` would
 * 503 every request on every deployment with a bound `CONTROL_DB`.
 */
import {
  type ResidencyPolicy,
  type ResidencyPolicyRow,
  parseResidencyPolicyRow,
} from "./policy.js";

/** The `quota_policies` columns this module reads, named once. */
const RESIDENCY_COLUMNS = "residency_regions_json, require_zero_data_retention, log_residency";

/**
 * The lookup, by AUTHENTICATED tenant.
 *
 * `scope_id = ?` is a bound equality against the tenant the credential resolved
 * to — never a scan, never interpolation, never a `LIKE`. This predicate IS the
 * tenant fence: it is what stops tenant A's EU-only policy from refusing tenant
 * B's US traffic, and (with the per-tenant cache key below) what stops tenant
 * B's unpoliced traffic from being served under tenant A's absent policy.
 */
const SELECT_TENANT_POLICY =
  `SELECT ${RESIDENCY_COLUMNS} FROM quota_policies ` +
  "WHERE scope_type = 'tenant' AND scope_id = ?";

/** Worker vars and bindings this slice reads. */
export interface ResidencyBindings {
  /**
   * DEV/TEST fallback: a JSON array of
   * `{ tenant_id, residency_regions, require_zero_data_retention, log_residency }`,
   * mirroring how `src/adapters.ts` backs the credential ports from vars when no
   * database is bound. The DURABLE source is `CONTROL_DB`'s `quota_policies`.
   */
  readonly GATEWAY_RESIDENCY_POLICIES?: string | undefined;
  /**
   * The region the operator ASSERTS this deployment's durable request log and
   * metering rows land in — see `./middleware.ts` for what is verified against
   * it and why an absent value cannot satisfy an `in_region` log policy.
   */
  readonly GATEWAY_LOG_REGION?: string | undefined;
  readonly CONTROL_DB?: ResidencyDatabase | undefined;
  /** The alias the metering/quota readers already accept. */
  readonly BILLING_DB?: ResidencyDatabase | undefined;
}

/** The `D1Database` subset this module needs. A live binding fits. */
export interface ResidencyDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { first<T = Record<string, unknown>>(): Promise<T | null> };
  };
}

/**
 * `null` = this tenant is not governed. `ok: false` is a DIFFERENT answer and
 * must never collapse into it — see the module docs on the fail direction.
 */
export type ResidencyResolution =
  | { readonly ok: true; readonly policy: ResidencyPolicy | null }
  | { readonly ok: false; readonly detail: string };

export interface ResidencyPolicySource {
  policyFor(tenantId: string): Promise<ResidencyResolution>;
}

/** A source that governs nothing — the posture of an unconfigured deployment. */
export const NO_RESIDENCY_POLICIES: ResidencyPolicySource = {
  async policyFor(): Promise<ResidencyResolution> {
    return { ok: true, policy: null };
  },
};

/** Wire shape of a `GATEWAY_RESIDENCY_POLICIES` entry. */
interface WireResidencyPolicy {
  readonly tenant_id?: unknown;
  readonly residency_regions?: unknown;
  readonly require_zero_data_retention?: unknown;
  readonly log_residency?: unknown;
}

/**
 * Build a source from the var.
 *
 * A var that is not a JSON array configures NOTHING — that is the same reading
 * `parseJsonVar` gives everywhere and it is safe here because an ABSENT
 * residency table cannot be distinguished from an empty one, so there is no
 * policy to fail closed on. A var that IS an array but contains an entry this
 * file cannot parse is a different matter: that entry names a tenant and then
 * fails to say what its policy is, so it is stored as a permanent
 * `ok: false` for that tenant and refuses its traffic until the operator fixes
 * it. Dropping the entry instead would serve exactly the tenant whose control
 * was mistyped.
 */
export function residencyPolicySourceFromVars(env: ResidencyBindings): ResidencyPolicySource {
  let rows: WireResidencyPolicy[] = [];
  const raw = env.GATEWAY_RESIDENCY_POLICIES;
  if (raw !== undefined && raw.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) rows = parsed as WireResidencyPolicy[];
    } catch {
      rows = [];
    }
  }

  const index = new Map<string, ResidencyResolution>();
  for (const row of rows) {
    if (typeof row?.tenant_id !== "string" || row.tenant_id === "") continue;
    const parsed = parseResidencyPolicyRow({
      allowedRegions: row.residency_regions,
      requireZeroDataRetention: row.require_zero_data_retention,
      logResidency: row.log_residency,
    });
    index.set(
      row.tenant_id,
      parsed.ok
        ? { ok: true, policy: parsed.policy }
        : { ok: false, detail: `GATEWAY_RESIDENCY_POLICIES: ${parsed.detail}` },
    );
  }

  return {
    async policyFor(tenantId: string): Promise<ResidencyResolution> {
      return index.get(tenantId) ?? { ok: true, policy: null };
    },
  };
}

/** The durable source — one indexed seek against the CONTROL database. */
export function d1ResidencyPolicySource(db: ResidencyDatabase): ResidencyPolicySource {
  return {
    async policyFor(tenantId: string): Promise<ResidencyResolution> {
      let row: Record<string, unknown> | null;
      try {
        row = await db.prepare(SELECT_TENANT_POLICY).bind(tenantId).first();
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (schemaPredatesResidency(detail)) return { ok: true, policy: null };
        return { ok: false, detail };
      }
      if (row === null || row === undefined) return { ok: true, policy: null };
      const parsed = parseResidencyPolicyRow({
        allowedRegions: jsonArrayColumn(row["residency_regions_json"]),
        requireZeroDataRetention: row["require_zero_data_retention"],
        logResidency: row["log_residency"],
      });
      return parsed.ok
        ? { ok: true, policy: parsed.policy }
        : { ok: false, detail: `quota_policies row is unreadable: ${parsed.detail}` };
    },
  };
}

/**
 * Does this D1 failure mean "the schema predates #681" rather than "the
 * database is unavailable"?
 *
 * Matched on the message because D1 surfaces SQLite's `SQLITE_ERROR` for both
 * and offers no code to switch on; the two shapes are SQLite's own and stable.
 * See the module docs for why this arm is not the generic fail-open hole.
 */
function schemaPredatesResidency(detail: string): boolean {
  return (
    /no such column:\s*(residency_regions_json|require_zero_data_retention|log_residency)/i.test(
      detail,
    ) || /no such table:\s*quota_policies/i.test(detail)
  );
}

/**
 * `TEXT` column holding a JSON array → the parsed value, or `undefined`.
 *
 * `undefined` (not `[]`) for a column that is NULL or blank, so "no regions
 * listed" reaches {@link parseResidencyPolicyRow} as "this row states no region
 * constraint". A column holding text that is not a JSON array is passed through
 * AS THE STRING, which that parser rejects — a residency list that does not
 * parse must refuse, not read as empty.
 */
function jsonArrayColumn(value: unknown): unknown {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") return undefined;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

/**
 * A per-isolate, per-TENANT memo in front of any source.
 *
 * The entry key is the AUTHENTICATED tenant id and nothing else — the second
 * half of the tenant fence. A memo keyed on anything coarser would let tenant
 * A's EU-only policy govern tenant B's request the moment two tenants share a
 * warm isolate, which on Workers is the normal case; here that would either
 * refuse traffic that is perfectly legal or, in the other direction, serve
 * tenant A's prompt from a region tenant A forbade.
 *
 * An `ok: false` is never cached: caching it would extend a one-request blip
 * into a TTL-long refusal window for that tenant.
 */
export function cachedResidencyPolicySource(
  inner: ResidencyPolicySource,
  options: { readonly ttlMs?: number; readonly now?: () => number } = {},
): ResidencyPolicySource {
  const ttlMs = options.ttlMs ?? DEFAULT_RESIDENCY_TTL_MS;
  const now = options.now ?? (() => Date.now());
  const entries = new Map<string, { policy: ResidencyPolicy | null; expiresAtMs: number }>();

  return {
    async policyFor(tenantId: string): Promise<ResidencyResolution> {
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
 * The same 30s #678 uses, for the same reason and one more: this is a control an
 * operator TIGHTENS during an incident ("stop routing us outside the EU"), and a
 * long TTL would leave warm isolates serving under the old policy for minutes
 * after the change.
 */
export const DEFAULT_RESIDENCY_TTL_MS = 30_000;

/**
 * The source the deployed Worker uses: durable when a control database is
 * bound, the var otherwise, memoized per isolate either way.
 *
 * Memoized PER ENV OBJECT — the identity `envScopedDeps`, the guardrail engine
 * and `attribution/source.ts` already key on. Workers hands the same `env` to
 * every request an isolate serves, so this is an isolate-lifetime cache without
 * a module global a test cannot reset.
 */
const SOURCES = new WeakMap<object, ResidencyPolicySource>();

export function residencyPolicySourceFromEnv(env: ResidencyBindings): ResidencyPolicySource {
  const key = env as unknown as object;
  const memoized = SOURCES.get(key);
  if (memoized !== undefined) return memoized;
  const db = env.CONTROL_DB ?? env.BILLING_DB;
  const source = cachedResidencyPolicySource(
    db === undefined ? residencyPolicySourceFromVars(env) : d1ResidencyPolicySource(db),
  );
  SOURCES.set(key, source);
  return source;
}
