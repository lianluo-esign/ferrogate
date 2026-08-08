/**
 * Where a tenant's online-evaluation policy comes from (#692).
 *
 * ## Same table, same reasons, as #678 and #681
 *
 * `quota_policies`, `scope_type = 'tenant'`. It is already the per-scope
 * governance row, already has RBAC, already carries #185's scoped-authorization
 * rule that stops a tenant-scoped admin editing another tenant's governance, and
 * is already read on the admission path. A dedicated `online_eval_policies`
 * table would have needed its own admin group — six more contract operations and
 * a second copy of that authorization rule — to express one flag, one rate and
 * one list.
 *
 * Only the TENANT scope is consulted, exactly as residency is: an opt-in to
 * having your traffic copied to a judge is a property of the legal entity, and a
 * project-scoped row that widened it would be a consent decision made by
 * somebody who cannot give that consent.
 *
 * ## The fail direction: NOT SAMPLED, always
 *
 * Residency (#681) fails CLOSED to a refusal because an unreadable residency
 * policy read as "unenforced" would serve out of region and nobody would find
 * out. This control's unsafe direction is the opposite one: the irreversible act
 * here is COPYING A PROMPT, so an unreadable policy must never be read as "opted
 * in", and the honest failure is to sample nothing. A gateway that cannot read
 * the policy therefore evaluates nothing for that tenant, loudly (the resolution
 * carries `ok: false` and the sink counts it) and never refuses a request — an
 * observability control must not be able to take the data plane down.
 *
 * ## `peek()` — why this source has a synchronous half
 *
 * The sampling decision has to be taken BEFORE `next()` (that is the only moment
 * the request body can still be cloned), and D1 has no synchronous read. Doing
 * the read inline would put a database round trip in front of every client's
 * response, which is exactly what this slice promises never to do.
 *
 * So the request path calls {@link OnlineEvalPolicySource.peek}, which answers
 * ONLY from the isolate memo and never does I/O, and the deferred half calls
 * `policyFor` (which warms the memo for the next request). The consequence is
 * stated rather than hidden: **the first requests an isolate serves for a tenant
 * are never sampled**, and the sampler therefore under-samples slightly after a
 * cold start. Under-sampling is the safe error for a measurement — the sample is
 * still an unbiased hash of the key space, just smaller — whereas the
 * alternative, blocking on D1, would be a latency regression on 100% of traffic
 * to measure 5% of it.
 */
import {
  type OnlineEvalPolicy,
  type OnlineEvalPolicyRow,
  parseOnlineEvalPolicyRow,
} from "./policy.js";

/** The `quota_policies` columns this module reads, named once. */
const ONLINE_EVAL_COLUMNS =
  "online_eval_enabled, online_eval_sample_rate, online_eval_sampling_unit, " +
  "online_eval_judge_model, online_eval_criteria_json, online_eval_regression_drop, " +
  "online_eval_regression_min_samples, online_eval_coverage_percent";

/**
 * The lookup, by AUTHENTICATED tenant. `scope_id = ?` is a bound equality — the
 * tenant fence, and (with the per-tenant memo key below) what stops tenant A's
 * opt-in from causing tenant B's prompts to be copied to a judge.
 */
export const SELECT_TENANT_ONLINE_EVAL_POLICY =
  `SELECT ${ONLINE_EVAL_COLUMNS} FROM quota_policies ` +
  "WHERE scope_type = 'tenant' AND scope_id = ?";

/** The `D1Database` subset this module needs. A live binding fits. */
export interface OnlineEvalDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { first<T = Record<string, unknown>>(): Promise<T | null> };
  };
}

export interface OnlineEvalBindings {
  /**
   * DEV/TEST fallback: a JSON array of
   * `{ tenant_id, enabled, sample_rate, sampling_unit, judge_model, criteria }`,
   * mirroring `GATEWAY_RESIDENCY_POLICIES`. The DURABLE source is `CONTROL_DB`.
   */
  readonly GATEWAY_ONLINE_EVAL_POLICIES?: string | undefined;
  readonly CONTROL_DB?: OnlineEvalDatabase | undefined;
  readonly BILLING_DB?: OnlineEvalDatabase | undefined;
}

/**
 * `policy: null` = this tenant did not opt in. `ok: false` = the policy could
 * not be read or does not parse; the caller samples nothing either way, but the
 * two are counted separately so a broken policy is visible rather than looking
 * like a tenant that never asked.
 */
export type OnlineEvalResolution =
  | { readonly ok: true; readonly policy: OnlineEvalPolicy | null }
  | { readonly ok: false; readonly detail: string };

export interface OnlineEvalPolicySource {
  policyFor(tenantId: string): Promise<OnlineEvalResolution>;
  /** The memoized answer, or `undefined`. NEVER does I/O. See the module docs. */
  peek(tenantId: string): OnlineEvalResolution | undefined;
}

/** A source that governs nothing — an unconfigured deployment. */
export const NO_ONLINE_EVAL_POLICIES: OnlineEvalPolicySource = {
  async policyFor(): Promise<OnlineEvalResolution> {
    return { ok: true, policy: null };
  },
  peek(): OnlineEvalResolution {
    return { ok: true, policy: null };
  },
};

interface WireOnlineEvalPolicy {
  readonly tenant_id?: unknown;
  readonly enabled?: unknown;
  readonly sample_rate?: unknown;
  readonly sampling_unit?: unknown;
  readonly judge_model?: unknown;
  readonly criteria?: unknown;
  readonly regression_drop?: unknown;
  readonly regression_min_samples?: unknown;
  readonly coverage_percent?: unknown;
}

function rowFromWire(row: WireOnlineEvalPolicy): OnlineEvalPolicyRow {
  return {
    enabled: row.enabled,
    sampleRate: row.sample_rate,
    samplingUnit: row.sampling_unit,
    judgeModel: row.judge_model,
    criteria: row.criteria,
    regressionDrop: row.regression_drop,
    regressionMinSamples: row.regression_min_samples,
    coveragePercent: row.coverage_percent,
  };
}

/**
 * The var-backed source.
 *
 * An entry that names a tenant and then fails to say what its policy is becomes
 * a permanent `ok: false` for that tenant — the same reading
 * `residencyPolicySourceFromVars` takes, and for the mirror-image reason:
 * dropping the entry would silently NOT sample a tenant who asked to be
 * sampled, and an operator would have no way to see the typo.
 */
export function onlineEvalPolicySourceFromVars(env: OnlineEvalBindings): OnlineEvalPolicySource {
  let rows: WireOnlineEvalPolicy[] = [];
  const raw = env.GATEWAY_ONLINE_EVAL_POLICIES;
  if (raw !== undefined && raw.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) rows = parsed as WireOnlineEvalPolicy[];
    } catch {
      rows = [];
    }
  }

  const index = new Map<string, OnlineEvalResolution>();
  for (const row of rows) {
    if (typeof row?.tenant_id !== "string" || row.tenant_id === "") continue;
    const parsed = parseOnlineEvalPolicyRow(rowFromWire(row));
    index.set(
      row.tenant_id,
      parsed.ok
        ? { ok: true, policy: parsed.policy }
        : { ok: false, detail: `GATEWAY_ONLINE_EVAL_POLICIES: ${parsed.detail}` },
    );
  }

  const answer = (tenantId: string): OnlineEvalResolution =>
    index.get(tenantId) ?? { ok: true, policy: null };
  return {
    async policyFor(tenantId: string): Promise<OnlineEvalResolution> {
      return answer(tenantId);
    },
    // A var-backed source is already in memory: `peek` is the same answer, so a
    // deployment with no control database samples from the FIRST request rather
    // than from the second.
    peek: answer,
  };
}

/** The durable source — one indexed seek against the CONTROL database. */
export function d1OnlineEvalPolicySource(db: OnlineEvalDatabase): OnlineEvalPolicySource {
  return {
    async policyFor(tenantId: string): Promise<OnlineEvalResolution> {
      let row: Record<string, unknown> | null;
      try {
        row = await db.prepare(SELECT_TENANT_ONLINE_EVAL_POLICY).bind(tenantId).first();
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        // A schema that predates this migration cannot hold an opt-in, so
        // "nobody opted in" is a complete reading of a known state — and
        // unlike #681's version of this arm it cannot widen anything, because
        // the fail direction here is already "sample nothing".
        if (schemaPredatesOnlineEval(detail)) return { ok: true, policy: null };
        return { ok: false, detail };
      }
      if (row === null || row === undefined) return { ok: true, policy: null };
      const parsed = parseOnlineEvalPolicyRow({
        enabled: row["online_eval_enabled"],
        sampleRate: row["online_eval_sample_rate"],
        samplingUnit: row["online_eval_sampling_unit"],
        judgeModel: row["online_eval_judge_model"],
        criteria: jsonColumn(row["online_eval_criteria_json"]),
        regressionDrop: row["online_eval_regression_drop"],
        regressionMinSamples: row["online_eval_regression_min_samples"],
        coveragePercent: row["online_eval_coverage_percent"],
      });
      return parsed.ok
        ? { ok: true, policy: parsed.policy }
        : { ok: false, detail: `quota_policies row is unreadable: ${parsed.detail}` };
    },
    peek(): undefined {
      // D1 has no synchronous read. The memo in `cachedOnlineEvalPolicySource`
      // is what makes `peek` answer anything at all.
      return undefined;
    },
  };
}

function schemaPredatesOnlineEval(detail: string): boolean {
  return (
    /no such column:\s*online_eval_/i.test(detail) ||
    /no such table:\s*quota_policies/i.test(detail)
  );
}

/** A TEXT column holding JSON → the parsed value; the raw string if it does not parse. */
function jsonColumn(value: unknown): unknown {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") return undefined;
  try {
    return JSON.parse(value);
  } catch {
    // Passed through as the STRING, which `parseOnlineEvalPolicyRow` rejects: a
    // criteria list that does not parse must be visible, not read as empty.
    return value;
  }
}

/**
 * How long a resolved policy is trusted inside one isolate.
 *
 * The same 30s #678/#681 use, and one extra reason: this is a control an
 * operator switches OFF in a hurry (a customer objects to their traffic being
 * sampled), and a long TTL would keep warm isolates copying that customer's
 * prompts for minutes after the opt-out.
 */
export const DEFAULT_ONLINE_EVAL_TTL_MS = 30_000;

/**
 * A per-isolate, per-TENANT memo in front of any source, and the thing that
 * makes `peek` possible.
 *
 * The entry key is the AUTHENTICATED tenant id and nothing else — the second
 * half of the tenant fence. An `ok: false` is never cached: a one-request D1
 * blip must not become a TTL-long hole in the sample.
 */
export function cachedOnlineEvalPolicySource(
  inner: OnlineEvalPolicySource,
  options: { readonly ttlMs?: number; readonly now?: () => number } = {},
): OnlineEvalPolicySource {
  const ttlMs = options.ttlMs ?? DEFAULT_ONLINE_EVAL_TTL_MS;
  const now = options.now ?? (() => Date.now());
  const entries = new Map<string, { policy: OnlineEvalPolicy | null; expiresAtMs: number }>();

  return {
    async policyFor(tenantId: string): Promise<OnlineEvalResolution> {
      const hit = entries.get(tenantId);
      if (hit !== undefined && hit.expiresAtMs > now()) return { ok: true, policy: hit.policy };
      const resolved = await inner.policyFor(tenantId);
      if (resolved.ok) {
        entries.set(tenantId, { policy: resolved.policy, expiresAtMs: now() + ttlMs });
      }
      return resolved;
    },
    peek(tenantId: string): OnlineEvalResolution | undefined {
      const hit = entries.get(tenantId);
      if (hit !== undefined && hit.expiresAtMs > now()) return { ok: true, policy: hit.policy };
      return inner.peek(tenantId);
    },
  };
}

/**
 * The source the deployed Worker uses: durable when a control database is bound,
 * the var otherwise, memoized per isolate either way.
 *
 * Memoized PER ENV OBJECT — the identity `envScopedDeps`, the guardrail engine,
 * `attribution/source.ts` and `residency/source.ts` already key on. Workers hands
 * the same `env` to every request an isolate serves, so this is an
 * isolate-lifetime cache with no module global a test cannot reset.
 */
const SOURCES = new WeakMap<object, OnlineEvalPolicySource>();

export function onlineEvalPolicySourceFromEnv(env: OnlineEvalBindings): OnlineEvalPolicySource {
  const key = env as unknown as object;
  const memoized = SOURCES.get(key);
  if (memoized !== undefined) return memoized;
  const db = env.CONTROL_DB ?? env.BILLING_DB;
  const source = cachedOnlineEvalPolicySource(
    db === undefined ? onlineEvalPolicySourceFromVars(env) : d1OnlineEvalPolicySource(db),
  );
  SOURCES.set(key, source);
  return source;
}
