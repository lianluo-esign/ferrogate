/**
 * Where the multi-level quota for a request comes from.
 *
 * The MERGE ITSELF IS NOT IMPLEMENTED HERE. `@ferrogate/policy`'s
 * `resolveEffectiveQuota` already ports `ferrogate-policy/quota.rs` (62 tests):
 * min-across tenant → project → workspace → key, model-allowlist intersection,
 * `enabled = false` anywhere is a hard deny, and a plan supplies the FLOOR (a
 * field takes the plan default only when no policy set it). This module only
 * decides *which policies to feed it* and turns the result into the RPM/TPM
 * windows in `keys.ts`.
 *
 * `resolveEffectiveQuota` takes its policy lookup as a closure precisely so the
 * source is swappable, so the port is a `QuotaPolicySource`. Two are shipped:
 *
 *  - {@link d1QuotaPolicySource} — the CONTROL database's `quota_policies` +
 *    `plans` + `tenants.plan_id`, which is what `AppState::resolve_effective_quota`
 *    reads from Supabase in Rust. Selected automatically whenever the binding is
 *    present ({@link quotaPolicySourceFromEnv}).
 *  - {@link quotaPolicySourceFromEnv}'s var fallback — the
 *    `GATEWAY_QUOTA_POLICIES` / `GATEWAY_PLANS` Worker vars, mirroring how
 *    `src/adapters.ts` backs the auth ports from vars. Fail-closed on malformed
 *    JSON exactly as `parseJsonVar` does: an unreadable table configures NO
 *    policies, which cannot widen a limit that a policy would have imposed.
 *
 * Both fail-closed differently on purpose, and the difference is the Rust one: a
 * VAR that cannot be parsed is a static misconfiguration and configures nothing,
 * while a D1 lookup that FAILS is an outage and answers `503
 * quota_resolution_unavailable` — a limiter that admitted every caller during a
 * database outage would be a free-traffic hole, not a graceful degradation.
 */
import {
  type EffectiveQuota,
  type QuotaScopeChain,
  type QuotaScopeKind,
  QuotaScopeSelector,
  type StoredPlan,
  type StoredQuotaPolicy,
  resolveEffectiveQuota,
} from "@ferrogate/policy";
import {
  WALLET_RESERVATION_ACTIVE,
  boolFromSqlite,
  optionalNumber,
  periodMonthFromUnix,
} from "@ferrogate/storage";
import { controlDatabaseFrom } from "../control-data.js";
import { tenantQuotaPolicyDbFrom } from "../tenancy/quota-policy-source.js";
import { type CounterWindow, counterKeyForScope, requestWindows, tpmWindow } from "./keys.js";

/**
 * Everything the limiter needs about one caller, projected out of the resolved
 * `AuthContext` by the composition root.
 */
export interface QuotaSubject {
  /** The presented credential's id. `key`-scope windows are namespaced with it. */
  readonly apiKeyId: string;
  /** Tenant / project / workspace / key ids to merge policies across. */
  readonly chain: QuotaScopeChain;
  /**
   * The TOK-12 per-key `request_limit_per_minute` carried on the credential
   * itself, independent of the quota chain. Rust `AuthContext.request_limit_per_minute`.
   */
  readonly requestLimitPerMinute?: number | undefined;
}

/**
 * Supplies the policies + plan for a subject.
 *
 * `AppState::resolve_effective_quota` reads both from Supabase in Rust and
 * returns `503 quota_resolution_unavailable` on a lookup error — which is why
 * {@link QuotaResolution} has an `unavailable` variant rather than defaulting to
 * "no quota". {@link d1QuotaPolicySource} is the durable implementation.
 */
export interface QuotaPolicySource {
  policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot>;
}

export type QuotaPolicySnapshot =
  | {
      readonly ok: true;
      /** Rust's `lookup` closure. `undefined` = that scope does not restrict. */
      readonly lookup: (kind: QuotaScopeKind, id: string) => StoredQuotaPolicy | undefined;
      /** The tenant's plan, if any — the merge FLOOR (issue #168). */
      readonly plan?: StoredPlan | undefined;
    }
  | { readonly ok: false; readonly detail: string };

/** The merged quota plus the windows it implies. */
export type QuotaResolution =
  | {
      readonly ok: true;
      readonly quota: EffectiveQuota;
      readonly rpm: CounterWindow[];
      readonly tpm: CounterWindow | null;
    }
  | { readonly ok: false; readonly detail: string };

/**
 * Merge the chain and derive the windows.
 *
 * A `deniedBy` result is returned as-is on `quota` — it is a **403
 * `quota_scope_disabled`**, not a rate-limit denial, and the caller must check
 * for it before enforcing any window (Rust `finalize_auth` does exactly that,
 * ahead of the budget and RPM checks).
 */
export async function resolveQuotaWindows(
  source: QuotaPolicySource,
  subject: QuotaSubject,
): Promise<QuotaResolution> {
  const snapshot = await source.policiesFor(subject);
  if (!snapshot.ok) return { ok: false, detail: snapshot.detail };

  const quota = resolveEffectiveQuota(subject.chain, snapshot.lookup, snapshot.plan);
  if (quota.deniedBy !== undefined) {
    // No windows: the request never reaches admission counting.
    return { ok: true, quota, rpm: [], tpm: null };
  }
  return {
    ok: true,
    quota,
    rpm: requestWindows(subject.apiKeyId, quota, subject.requestLimitPerMinute),
    tpm: tpmWindow(subject.apiKeyId, quota),
  };
}

// ---------------------------------------------------------------------------
// Config-var adapter
// ---------------------------------------------------------------------------

/** Worker bindings this module reads. */
export interface QuotaBindings {
  /**
   * JSON array of `StoredQuotaPolicy` rows (snake_case on the wire, matching
   * the storage column names). Absent/malformed ⇒ no policy restricts.
   */
  readonly GATEWAY_QUOTA_POLICIES?: string | undefined;
  /** JSON map of tenant id → `StoredPlan` (the merge floor). */
  readonly GATEWAY_PLANS?: string | undefined;
  /** JSON map of tenant id → plan slug/id, selecting which plan applies. */
  readonly GATEWAY_TENANT_PLANS?: string | undefined;
  /**
   * The CONTROL database (`sql/d1-ts/control/`), holding `quota_policies`,
   * `plans` and `tenants`. Present ⇒ {@link quotaPolicySourceFromEnv} reads
   * policies from D1 and the three vars above are no longer consulted.
   *
   * Two names, one database, in preference order. `BILLING_DB` is the binding
   * `apps/gateway/wrangler.toml` ALREADY declares for metering and it points at
   * exactly this database — the metering tables and the quota tables are in the
   * same control migration, which is the whole reason a single `batch()` is
   * atomic across them. `CONTROL_DB` is the purpose-named binding an operator
   * should add once quota reads are not incidental to billing; it wins when
   * both are bound so the rename can happen without a flag day.
   */
  readonly CONTROL_DB?: D1Database | undefined;
  /** See {@link QuotaBindings.CONTROL_DB} — the already-declared alias. */
  readonly BILLING_DB?: D1Database | undefined;
}

function parseJsonVar<T>(raw: string | undefined, fallback: T): T {
  if (raw === undefined || raw.trim() === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    // Fail closed: an unreadable table configures nothing, and "nothing
    // configured" can only leave a limit unset, never raise one.
    return fallback;
  }
}

interface WirePolicy {
  id?: string;
  scope_type: QuotaScopeKind;
  scope_id: string;
  model_allowlist?: string[];
  rpm_limit?: number;
  tpm_limit?: number;
  monthly_budget_usd?: number;
  agent_cost_budget_usd?: number;
  asset_storage_quota_bytes?: number;
  asset_max_object_bytes?: number;
  monthly_egress_bytes_budget?: number;
  download_rpm_limit?: number;
  alert_threshold_pcts?: number[];
  enabled?: boolean;
}

interface WirePlan {
  id?: string;
  name?: string;
  slug?: string;
  default_model_allowlist?: string[];
  default_rpm_limit?: number;
  default_tpm_limit?: number;
  default_monthly_budget_usd?: number;
  default_agent_cost_budget_usd?: number;
  default_monthly_egress_bytes_budget?: number;
  default_download_rpm_limit?: number;
  default_asset_storage_quota_bytes?: number;
  default_asset_max_object_bytes?: number;
}

function toStoredPolicy(wire: WirePolicy): StoredQuotaPolicy {
  return {
    id: wire.id ?? `${wire.scope_type}:${wire.scope_id}`,
    scopeType: wire.scope_type,
    scopeId: wire.scope_id,
    modelAllowlist: wire.model_allowlist ?? [],
    rpmLimit: wire.rpm_limit,
    tpmLimit: wire.tpm_limit,
    monthlyBudgetUsd: wire.monthly_budget_usd,
    agentCostBudgetUsd: wire.agent_cost_budget_usd,
    assetStorageQuotaBytes: wire.asset_storage_quota_bytes,
    assetMaxObjectBytes: wire.asset_max_object_bytes,
    monthlyEgressBytesBudget: wire.monthly_egress_bytes_budget,
    downloadRpmLimit: wire.download_rpm_limit,
    alertThresholdPcts: wire.alert_threshold_pcts ?? [],
    // Rust default for a persisted policy row is enabled; only an explicit
    // `false` denies, so an omitted column cannot lock a tenant out by accident.
    enabled: wire.enabled ?? true,
    createdAtUnix: 0,
    updatedAtUnix: 0,
  };
}

function toStoredPlan(wire: WirePlan): StoredPlan {
  return {
    id: wire.id ?? wire.slug ?? "plan",
    name: wire.name ?? wire.slug ?? "plan",
    slug: wire.slug ?? wire.id ?? "plan",
    mcpEnabled: false,
    selfHostedWorkersEnabled: false,
    defaultModelAllowlist: wire.default_model_allowlist ?? [],
    defaultRpmLimit: wire.default_rpm_limit,
    defaultTpmLimit: wire.default_tpm_limit,
    defaultMonthlyBudgetUsd: wire.default_monthly_budget_usd,
    defaultAgentCostBudgetUsd: wire.default_agent_cost_budget_usd,
    defaultMonthlyEgressBytesBudget: wire.default_monthly_egress_bytes_budget,
    defaultDownloadRpmLimit: wire.default_download_rpm_limit,
    defaultAssetStorageQuotaBytes: wire.default_asset_storage_quota_bytes,
    defaultAssetMaxObjectBytes: wire.default_asset_max_object_bytes,
    createdAtUnix: 0,
    updatedAtUnix: 0,
    assetHostingEnabled: false,
    extensionToolsEnabled: false,
  };
}

/**
 * Build a {@link QuotaPolicySource} from Worker vars. Policies are indexed by
 * `"{scope_type}:{scope_id}"` — the same shape as `quotaPolicyId` in
 * `@ferrogate/policy`, and NOT the counter key (a policy row's identity and a
 * counter window's identity are different things; conflating them is how the
 * `key`-scope namespacing gets lost).
 */
export function quotaPolicySourceFromVars(env: QuotaBindings): QuotaPolicySource {
  const rows = parseJsonVar<WirePolicy[]>(env.GATEWAY_QUOTA_POLICIES, []);
  const index = new Map<string, StoredQuotaPolicy>();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (typeof row?.scope_type !== "string" || typeof row?.scope_id !== "string") continue;
    index.set(`${row.scope_type}:${row.scope_id}`, toStoredPolicy(row));
  }

  const planRows = parseJsonVar<Record<string, WirePlan>>(env.GATEWAY_PLANS, {});
  const tenantPlans = parseJsonVar<Record<string, string>>(env.GATEWAY_TENANT_PLANS, {});

  const lookup = (kind: QuotaScopeKind, id: string): StoredQuotaPolicy | undefined =>
    index.get(`${kind}:${id}`);

  return {
    async policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot> {
      const tenantId = subject.chain.tenantId;
      const planKey = tenantId === undefined ? undefined : tenantPlans[tenantId];
      const wirePlan = planKey === undefined ? undefined : planRows[planKey];
      return {
        ok: true,
        lookup,
        plan: wirePlan === undefined ? undefined : toStoredPlan(wirePlan),
      };
    },
  };
}

/** A source that configures nothing — the fail-open-to-no-limits default. */
export const NO_QUOTA_POLICIES: QuotaPolicySource = {
  async policiesFor(): Promise<QuotaPolicySnapshot> {
    return { ok: true, lookup: () => undefined };
  },
};

// ---------------------------------------------------------------------------
// D1 adapter — `AppState::resolve_effective_quota`'s storage half
// ---------------------------------------------------------------------------

/** The `quota_policies` columns this module reads, in one place. */
const QUOTA_POLICY_COLUMNS =
  "id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit, " +
  "monthly_budget_usd, enabled, created_at_unix, updated_at_unix, " +
  "alert_threshold_pcts_json, asset_storage_quota_bytes, " +
  "monthly_egress_bytes_budget, download_rpm_limit, asset_max_object_bytes, " +
  "agent_cost_budget_usd";

/** Raised inside the row decoders; caught by `policiesFor` and rendered as 503. */
class QuotaRowError extends Error {}

/**
 * The auto-throttle table the spend-anomaly detector writes (#697,
 * `sql/d1-ts/control/0010_spend_anomaly.sql`).
 *
 * Named here rather than imported from `apps/control-plane`: the two Workers
 * share a DATABASE, not a module graph, and a cross-app import would be the
 * first one in the tree.
 */
const SPEND_THROTTLE_TABLE = "spend_throttles";

/**
 * Is `spend_throttles` provisioned in this control database?
 *
 * Probed STRUCTURALLY and cached per handle, exactly as
 * `apps/mcp/src/admission/quota.ts` probes its own quota tables, and for a
 * reason that is a live deploy hazard rather than tidiness: D1 fails a whole
 * `batch()` when any statement in it errors, so adding an unconditional
 * `SELECT … FROM spend_throttles` to the admission batch would turn every
 * authenticated request into `503 quota_resolution_unavailable` on any
 * deployment whose control database has not had `0010_spend_anomaly.sql`
 * applied yet. Deploying the Worker and applying the migration are separate
 * operator actions; a release that requires them in one order and fails the
 * whole gateway in the other is not shippable.
 *
 * Absent ⇒ no throttle rows can exist ⇒ skipping the read cannot drop a brake
 * that was applied. Present ⇒ any failure is an OUTAGE and stays a 503, which
 * is the direction a limiter must fail in.
 *
 * CONSEQUENCE, stated: an operator who applies the migration under a LIVE
 * isolate is not seen by that isolate until it recycles. Provisioning precedes
 * traffic, and the alternative is a `sqlite_master` read on every admission —
 * a hot-path cost paid forever to serve a one-time transition.
 */
const throttleTableCache = new WeakMap<D1Database, Promise<boolean>>();

async function spendThrottlesProvisioned(db: D1Database): Promise<boolean> {
  const cached = throttleTableCache.get(db);
  if (cached !== undefined) return cached;
  const probe = (async (): Promise<boolean> => {
    const row = await db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
      .bind(SPEND_THROTTLE_TABLE)
      .first<{ name: string }>();
    return row !== null;
  })();
  throttleTableCache.set(db, probe);
  // A FAILED probe must not be remembered as "not provisioned": that would turn
  // a transient D1 blip into an isolate that never applies a brake again.
  probe.catch(() => throttleTableCache.delete(db));
  return probe;
}

/** Test seam: forget the probe for one database (an isolate recycle, simulated). */
export function forgetSpendThrottleProbe(db: D1Database): void {
  throttleTableCache.delete(db);
}

interface ThrottleRow {
  readonly scope_type: string;
  readonly scope_id: string;
  readonly rpm_limit: number;
}

/**
 * Overlay unexpired auto-throttles onto the policy index.
 *
 * ## The one property that matters: it can only ever NARROW
 *
 * A throttle contributes exactly one field, `rpmLimit`, and it contributes it
 * as a `min` against whatever the operator configured. It cannot raise a limit,
 * cannot enable a disabled scope, cannot widen a model allowlist, cannot grant
 * a budget. That is what makes it safe for an automated writer — the detector
 * — to touch a table the admission path reads: the worst a bug in the detector
 * can do is refuse traffic, which is loud, recoverable and expires by itself.
 * The opposite direction would be a silent free-traffic hole.
 *
 * A throttle for a scope with NO policy row becomes a synthetic policy carrying
 * `rpmLimit` and nothing else — empty `modelAllowlist` (which
 * `resolveEffectiveQuota` reads as "does not restrict", not as "allow
 * nothing"), `enabled: true` (a throttle must never become a 403
 * `quota_scope_disabled`), and every other limit `undefined`.
 *
 * `expires_at_unix` is filtered in SQL rather than swept by a job: a throttle
 * whose lifting depends on a cron that may never run again is a throttle that
 * outlives its incident forever, and nothing on the request path would say why.
 */
function applySpendThrottles(
  index: Map<string, StoredQuotaPolicy>,
  rows: readonly ThrottleRow[],
): void {
  for (const row of rows) {
    const scopeType = row.scope_type;
    if (
      scopeType !== "tenant" &&
      scopeType !== "project" &&
      scopeType !== "workspace" &&
      scopeType !== "key"
    ) {
      // Unlike a `quota_policies` row with an unknown scope kind — which is a
      // 503, because dropping it would UNLIMIT whoever it governs — dropping an
      // unknown throttle scope can only fail open on a brake nothing else
      // depends on. Silently ignored rather than taking the admission path down.
      continue;
    }
    const rpm = row.rpm_limit;
    if (!Number.isFinite(rpm) || rpm < 0) continue;
    const key = `${scopeType}:${row.scope_id}`;
    const existing = index.get(key);
    if (existing === undefined) {
      index.set(key, {
        id: `spend-throttle:${key}`,
        scopeType,
        scopeId: row.scope_id,
        modelAllowlist: [],
        rpmLimit: rpm,
        alertThresholdPcts: [],
        enabled: true,
        createdAtUnix: 0,
        updatedAtUnix: 0,
      });
      continue;
    }
    index.set(key, {
      ...existing,
      rpmLimit: existing.rpmLimit === undefined ? rpm : Math.min(existing.rpmLimit, rpm),
    });
  }
}

/** `JSON` TEXT column → array, refusing (never silently emptying) a bad value. */
function jsonArrayColumn<T>(value: unknown, column: string, id: string): T[] {
  if (value === null || value === undefined || value === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(String(value));
  } catch {
    // NOT `[]`. An unreadable allowlist that decodes to "no allowlist" would
    // WIDEN the effective quota — the one direction a failure must never take.
    throw new QuotaRowError(`quota_policies.${column} on row ${id} is not valid JSON`);
  }
  if (!Array.isArray(parsed)) {
    throw new QuotaRowError(`quota_policies.${column} on row ${id} is not a JSON array`);
  }
  return parsed as T[];
}

/** One `quota_policies` row → `StoredQuotaPolicy`. */
function rowToStoredPolicy(row: Record<string, unknown>): StoredQuotaPolicy {
  const id = String(row.id ?? "");
  const scopeType = String(row.scope_type ?? "");
  if (
    scopeType !== "tenant" &&
    scopeType !== "project" &&
    scopeType !== "workspace" &&
    scopeType !== "key"
  ) {
    // A scope kind the merge does not know cannot be applied, and dropping the
    // row would silently unlimit whoever it governs.
    throw new QuotaRowError(`quota_policies.scope_type on row ${id} is unknown: ${scopeType}`);
  }
  return {
    id,
    scopeType,
    scopeId: String(row.scope_id ?? ""),
    modelAllowlist: jsonArrayColumn<string>(row.model_allowlist_json, "model_allowlist_json", id),
    rpmLimit: optionalNumber(row.rpm_limit),
    tpmLimit: optionalNumber(row.tpm_limit),
    monthlyBudgetUsd: optionalNumber(row.monthly_budget_usd),
    assetStorageQuotaBytes: optionalNumber(row.asset_storage_quota_bytes),
    assetMaxObjectBytes: optionalNumber(row.asset_max_object_bytes),
    agentCostBudgetUsd: optionalNumber(row.agent_cost_budget_usd),
    alertThresholdPcts: jsonArrayColumn<number>(
      row.alert_threshold_pcts_json,
      "alert_threshold_pcts_json",
      id,
    ),
    enabled: boolFromSqlite(row.enabled),
    createdAtUnix: Number(row.created_at_unix ?? 0),
    updatedAtUnix: Number(row.updated_at_unix ?? 0),
    monthlyEgressBytesBudget: optionalNumber(row.monthly_egress_bytes_budget),
    downloadRpmLimit: optionalNumber(row.download_rpm_limit),
  };
}

/** One `plans` row → `StoredPlan`. */
function rowToStoredPlan(row: Record<string, unknown>): StoredPlan {
  const id = String(row.id ?? "");
  const allowlist = row.default_model_allowlist_json;
  let defaultModelAllowlist: string[] = [];
  if (allowlist !== null && allowlist !== undefined && allowlist !== "") {
    try {
      const parsed: unknown = JSON.parse(String(allowlist));
      if (!Array.isArray(parsed)) {
        throw new Error("not an array");
      }
      defaultModelAllowlist = parsed as string[];
    } catch {
      throw new QuotaRowError(
        `plans.default_model_allowlist_json on row ${id} is not a JSON array`,
      );
    }
  }
  return {
    id,
    name: String(row.name ?? ""),
    slug: String(row.slug ?? ""),
    mcpEnabled: boolFromSqlite(row.mcp_enabled),
    selfHostedWorkersEnabled: boolFromSqlite(row.self_hosted_workers_enabled),
    ...(optionalNumber(row.admin_console_seats) === undefined
      ? {}
      : { adminConsoleSeats: optionalNumber(row.admin_console_seats) }),
    defaultModelAllowlist,
    defaultRpmLimit: optionalNumber(row.default_rpm_limit),
    defaultTpmLimit: optionalNumber(row.default_tpm_limit),
    defaultMonthlyBudgetUsd: optionalNumber(row.default_monthly_budget_usd),
    createdAtUnix: Number(row.created_at_unix ?? 0),
    updatedAtUnix: Number(row.updated_at_unix ?? 0),
    assetHostingEnabled: boolFromSqlite(row.asset_hosting_enabled),
    defaultAssetStorageQuotaBytes: optionalNumber(row.default_asset_storage_quota_bytes),
    defaultAssetMaxObjectBytes: optionalNumber(row.default_asset_max_object_bytes),
    defaultAgentCostBudgetUsd: optionalNumber(row.default_agent_cost_budget_usd),
    defaultMonthlyEgressBytesBudget: optionalNumber(row.default_monthly_egress_bytes_budget),
    defaultDownloadRpmLimit: optionalNumber(row.default_download_rpm_limit),
    extensionToolsEnabled: boolFromSqlite(row.extension_tools_enabled),
  };
}

/**
 * The durable {@link QuotaPolicySource}: the CONTROL database's `quota_policies`
 * chain plus the tenant's `plans` floor.
 *
 * ## One `batch()`, not five queries
 *
 * `resolveEffectiveQuota` walks tenant → project → workspace → key, so up to
 * four policy rows and one plan row are needed BEFORE the request is admitted —
 * i.e. on the hot path of every authenticated call. They go out as a single
 * `db.batch()`: D1 runs a batch as one round trip inside one implicit
 * transaction, so the five reads cost one hop and cannot interleave with a
 * control-plane write that would let the chain be read half-updated.
 *
 * The policy leg is ONE statement with an OR-ed `(scope_type, scope_id)`
 * predicate rather than four statements, because `(scope_type, scope_id)` is
 * `UNIQUE` and indexed (`idx_quota_policies_scope`): SQLite satisfies the whole
 * disjunction from that index.
 *
 * ## Why every failure is 503, never "no policies"
 *
 * A `QuotaPolicySource` that answered `{ ok: true, lookup: () => undefined }` on
 * a database error would turn an outage into UNLIMITED traffic for every caller
 * — the exact opposite of what a limiter is for. So a rejected query, a row with
 * an unknown `scope_type`, and a malformed JSON column all become
 * `{ ok: false, detail }`, which `rateLimit` renders as the Rust
 * `503 quota_resolution_unavailable`.
 *
 * The plan lookup joins `tenants.plan_id → plans.id`; a tenant row that names a
 * plan that does not exist yields NO plan (no floor), which is the Rust
 * behavior for a dangling `plan_id` — the join simply misses.
 *
 * ## The auto-throttle overlay (#697)
 *
 * A third statement joins the batch: the unexpired `spend_throttles` rows for
 * the same scopes. See {@link applySpendThrottles} for what it may and may not
 * do to the resolved quota.
 */
export function d1QuotaPolicySource(
  db: D1Database,
  /**
   * The clock the throttle expiry is compared against. Injectable ONLY so a
   * test can state "this throttle expired an hour ago" without sleeping;
   * production reads the real clock at call time, never at module load.
   */
  nowSeconds: () => number = () => Math.floor(Date.now() / 1000),
  /**
   * Resolver for the tenant-scoped legs (Track A red line, HARD CUT).
   *
   * Per-scope `quota_policies` and `spend_throttles` rows are TENANT data, so
   * their sole authoritative home is the tenant's OWN object — the shared
   * control mirror has been removed. When a subject is tenant-attributed those
   * two legs read from the resolved tenant object; the account-global `plans`
   * floor always stays on the control `db` (it has no per-tenant snapshot). For
   * an ownerless subject with no `tenantId`, OR when no resolver is wired, the
   * tenant-scoped legs are SKIPPED entirely and the limiter fails OPEN (no policy
   * row = no cap) — acceptable because a subject with no tenant object has no
   * relocated rows to enforce. A failure to RESOLVE the tenant handle for a
   * subject that DOES have a tenant is a 503, never a silent fall-through: the
   * control mirror no longer exists to fall through to.
   */
  tenantPolicyDb?: (tenantId: string) => Promise<D1Database>,
): QuotaPolicySource {
  return {
    async policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot> {
      const scopes: [QuotaScopeKind, string][] = [];
      const { tenantId, projectId, workspaceId, keyId } = subject.chain;
      if (tenantId !== undefined) scopes.push(["tenant", tenantId]);
      if (projectId !== undefined) scopes.push(["project", projectId]);
      if (workspaceId !== undefined) scopes.push(["workspace", workspaceId]);
      if (keyId !== undefined) scopes.push(["key", keyId]);

      const index = new Map<string, StoredQuotaPolicy>();
      let plan: StoredPlan | undefined;

      // The tenant-scoped legs (`quota_policies` + the #697 `spend_throttles`
      // overlay) read ONLY the tenant's OWN object — never the shared control
      // `db`, which no longer holds a mirror (Track A hard-cut). Without a
      // resolver, or for an ownerless subject with no tenant to resolve, there is
      // no object to read: the legs are skipped and the limiter fails OPEN, which
      // is safe because such a subject has no relocated rows to enforce anyway.
      if (tenantPolicyDb !== undefined && tenantId !== undefined && scopes.length > 0) {
        let policyDb: D1Database;
        try {
          policyDb = await tenantPolicyDb(tenantId);
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          return {
            ok: false,
            detail: `cloudflare d1: routed tenant quota database unavailable: ${detail}`,
          };
        }

        const predicate = scopes.map(() => "(scope_type = ? AND scope_id = ?)").join(" OR ");
        const bindings = scopes.flat();

        const statements = [
          policyDb
            .prepare(`SELECT ${QUOTA_POLICY_COLUMNS} FROM quota_policies WHERE ${predicate}`)
            .bind(...bindings),
        ];
        // #697 — the auto-throttle overlay, in the SAME batch as its sibling
        // `quota_policies` (both are tenant-scoped and read the tenant object),
        // so it costs one extra statement and no extra round trip. The probe is
        // per-handle, not per-request; see {@link spendThrottlesProvisioned}.
        let throttleIndex = -1;
        try {
          if (await spendThrottlesProvisioned(policyDb)) {
            throttleIndex = statements.length;
            statements.push(
              policyDb
                .prepare(
                  `SELECT scope_type, scope_id, rpm_limit
                     FROM ${SPEND_THROTTLE_TABLE}
                    WHERE expires_at_unix > ? AND (${predicate})`,
                )
                .bind(nowSeconds(), ...bindings),
            );
          }
        } catch (error) {
          // The PROBE failing is a database outage, and a limiter that answered
          // "no policies" during one would be a free-traffic hole. Same 503 the
          // policy read itself takes.
          const detail = error instanceof Error ? error.message : String(error);
          return { ok: false, detail: `cloudflare d1: spend throttle probe failed: ${detail}` };
        }

        let results: { results?: unknown[] }[];
        try {
          results = (await policyDb.batch(statements)) as unknown as { results?: unknown[] }[];
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          return { ok: false, detail: `cloudflare d1: quota policy lookup failed: ${detail}` };
        }

        try {
          for (const row of (results[0]?.results ?? []) as Record<string, unknown>[]) {
            const policy = rowToStoredPolicy(row);
            index.set(`${policy.scopeType}:${policy.scopeId}`, policy);
          }
          if (throttleIndex >= 0) {
            applySpendThrottles(index, (results[throttleIndex]?.results ?? []) as ThrottleRow[]);
          }
        } catch (error) {
          if (error instanceof QuotaRowError) {
            return { ok: false, detail: error.message };
          }
          throw error;
        }
      }

      // The plan floor joins `tenants.plan_id → plans.id`, both control-owned, so
      // it stays on the control `db` in its own round trip.
      if (tenantId !== undefined) {
        let planResults: { results?: unknown[] }[];
        try {
          planResults = (await db.batch([
            db
              .prepare("SELECT p.* FROM plans p JOIN tenants t ON t.plan_id = p.id WHERE t.id = ?")
              .bind(tenantId),
          ])) as unknown as { results?: unknown[] }[];
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          return { ok: false, detail: `cloudflare d1: quota plan lookup failed: ${detail}` };
        }
        const planRow = (planResults[0]?.results ?? [])[0] as Record<string, unknown> | undefined;
        if (planRow !== undefined) {
          try {
            plan = rowToStoredPlan(planRow);
          } catch (error) {
            if (error instanceof QuotaRowError) {
              return { ok: false, detail: error.message };
            }
            throw error;
          }
        }
      }

      return {
        ok: true,
        lookup: (kind: QuotaScopeKind, id: string): StoredQuotaPolicy | undefined =>
          index.get(`${kind}:${id}`),
        ...(plan === undefined ? {} : { plan }),
      };
    },
  };
}

export const DEFAULT_QUOTA_POLICY_CACHE_TTL_MS = 5_000;
export const DEFAULT_QUOTA_POLICY_CACHE_MAX_ENTRIES = 1_000;

/**
 * Isolate-local TTL cache in front of a durable {@link QuotaPolicySource}.
 *
 * Quota rows change rarely relative to request rate, and the control object
 * (or D1 primary) is on the admission hot path of every authenticated call.
 * Caching a successful snapshot for a few seconds drops that hop to a map
 * lookup; a failure is never cached so an outage cannot become a TTL-long
 * "no policies" / unlimited-traffic window.
 */
export function cachedQuotaPolicySource(
  inner: QuotaPolicySource,
  options: {
    readonly ttlMs?: number;
    readonly maxEntries?: number;
    readonly now?: () => number;
  } = {},
): QuotaPolicySource {
  const ttlMs = options.ttlMs ?? DEFAULT_QUOTA_POLICY_CACHE_TTL_MS;
  const maxEntries = options.maxEntries ?? DEFAULT_QUOTA_POLICY_CACHE_MAX_ENTRIES;
  const now = options.now ?? Date.now;
  const entries = new Map<string, { expiresAtMs: number; snapshot: QuotaPolicySnapshot }>();
  return {
    async policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot> {
      const key = [
        subject.apiKeyId,
        subject.chain.tenantId ?? "",
        subject.chain.projectId ?? "",
        subject.chain.workspaceId ?? "",
        subject.chain.keyId ?? "",
      ].join("\0");
      const hit = entries.get(key);
      if (hit !== undefined && now() < hit.expiresAtMs) return hit.snapshot;
      if (hit !== undefined) entries.delete(key);
      const snapshot = await inner.policiesFor(subject);
      if (snapshot.ok) {
        entries.delete(key);
        entries.set(key, { expiresAtMs: now() + ttlMs, snapshot });
        while (entries.size > maxEntries) {
          const oldest = entries.keys().next();
          if (oldest.done === true) break;
          entries.delete(oldest.value);
        }
      }
      return snapshot;
    },
  };
}

/**
 * The {@link QuotaPolicySource} the composition root gets.
 *
 * D1 whenever the control database is bound, the Worker vars otherwise. The
 * order is deliberate and is NOT a merge: a deployment that has provisioned
 * `quota_policies` rows must not have them silently widened (or narrowed) by a
 * stale `GATEWAY_QUOTA_POLICIES` var left over from before the migration. One
 * source of truth per deployment, chosen by which binding exists.
 *
 * Durable lookups are wrapped in {@link cachedQuotaPolicySource} so the
 * control-object hop is not paid on every authenticated request.
 */
export function quotaPolicySourceFromEnv(
  env: QuotaBindings,
  /**
   * The tenant-scoped resolver for the `quota_policies`/`spend_throttles` legs.
   * Track A hard-cut: the tenant object is the SOLE authority, so when a caller
   * omits this it DEFAULTS to {@link tenantQuotaPolicyDbFrom} — every reader
   * routes those legs to the tenant's own object, never the (removed) control
   * mirror. A caller that has already resolved the tenant database (e.g. the
   * metering budget-alert reader, which must run its config backfill first) may
   * pass its own resolver. See {@link d1QuotaPolicySource}.
   */
  tenantPolicyDb?: (tenantId: string) => Promise<D1Database>,
): QuotaPolicySource {
  const db = controlDatabaseFrom(env);
  const resolver = tenantPolicyDb ?? tenantQuotaPolicyDbFrom(env);
  return db === undefined
    ? quotaPolicySourceFromVars(env)
    : cachedQuotaPolicySource(d1QuotaPolicySource(db, undefined, resolver));
}

// ---------------------------------------------------------------------------
// Spend + prepaid wallet — `finalize_auth` steps 2 and 3
// ---------------------------------------------------------------------------

/**
 * The BALANCE half of the admission chain: what has already been spent, and
 * what is left in the prepaid wallet.
 *
 * `QuotaPolicySource` answers "what is this caller allowed"; this answers "how
 * much of it is gone". They are separate ports because they read separate
 * DATABASES — policies live in the CONTROL database (`quota_policies`, `plans`)
 * and spend lives in the TENANT database (`usage_monthly_rollups`, `wallets`,
 * `wallet_reservations`, all defined in `sql/d1-ts/tenant/0001_init_tenant.sql`).
 *
 * Rust reads both off `AppState.repositories`:
 * `state_wallets.rs::monthly_budget_exceeded` (→ `get_usage_monthly_rollup`)
 * and `state_wallets.rs::wallet_balance_exhausted` (→ `get_wallet`, minus the
 * cluster counters' outstanding reservations).
 *
 * Both readings are RESULT types, never bare numbers, for the same reason
 * {@link QuotaPolicySnapshot} is: Rust maps an `Err` from either lookup to
 * `503 quota_resolution_unavailable`, NOT to "0 spent" / "no wallet". A source
 * that swallowed a database outage into `0` would hand every over-budget tenant
 * unlimited spend for the duration of the outage.
 */
export interface SpendSource {
  /**
   * `get_usage_monthly_rollup(scope_type, scope_id, period_month).cost_usd`.
   *
   * An ABSENT rollup row is `0`, not a failure — that is Rust's
   * `.map(|rollup| rollup.cost_usd).unwrap_or(0.0)`, and it is the normal state
   * for a scope that has not been billed this month.
   */
  committedSpendUsd(
    scopeKind: QuotaScopeKind,
    scopeId: string,
    periodMonth: string,
  ): Promise<MonthlySpendReading>;
  /**
   * `wallet.balance_credits - reserved`, or `null` when the tenant has NO
   * wallet row.
   *
   * `null` is load-bearing: the prepaid wallet is OPT-IN per tenant
   * (`wallet_balance_exhausted` returns `Ok(false)` for a tenant with no
   * wallet), so "no row" must be distinguishable from "a row at zero". A source
   * that reported `0` for an absent wallet would refuse every tenant that has
   * not adopted prepaid billing.
   */
  walletBalanceCredits(tenantId: string): Promise<WalletBalanceReading>;
}

export type MonthlySpendReading =
  | { readonly ok: true; readonly committedSpendUsd: number }
  | { readonly ok: false; readonly detail: string };

export type WalletBalanceReading =
  | { readonly ok: true; readonly availableCredits: number | null }
  | { readonly ok: false; readonly detail: string };

/**
 * The source for a deployment with no tenant database bound.
 *
 * NOT a fail-open stub: with no `usage_monthly_rollups` table there is no
 * recorded spend, and `0` is the true reading (the same value the D1 source
 * returns for a scope with no rollup row). Likewise `null` — no wallet table
 * means no tenant has adopted prepaid billing, which is exactly the case Rust
 * never denies. Both answers are the Rust behavior for an empty store, so
 * binding the database can only ever TIGHTEN admission, never loosen it.
 */
export const NO_SPEND_SOURCE: SpendSource = {
  async committedSpendUsd(): Promise<MonthlySpendReading> {
    return { ok: true, committedSpendUsd: 0 };
  },
  async walletBalanceCredits(): Promise<WalletBalanceReading> {
    return { ok: true, availableCredits: null };
  },
};

/** Worker bindings {@link spendSourceFromEnv} reads. */
export interface SpendBindings {
  /**
   * The TENANT database (`sql/d1-ts/tenant/`), holding `usage_monthly_rollups`,
   * `wallets` and `wallet_reservations`.
   *
   * This is the SAME binding `d1ApiKeyResolverFromEnv` reads for `api_keys`, and
   * it is already declared in `apps/gateway/wrangler.toml` — which is why the
   * budget and wallet gates need no composition-root edit to go live.
   */
  readonly DB?: D1Database | undefined;
}

/** `usage_monthly_rollups` is UNIQUE on `(period_month, scope_type, scope_id)`. */
const MONTHLY_SPEND_SQL =
  "SELECT cost_usd FROM usage_monthly_rollups " +
  "WHERE period_month = ? AND scope_type = ? AND scope_id = ?";

const WALLET_BALANCE_SQL = "SELECT balance_credits FROM wallets WHERE tenant_id = ?";

/**
 * The live holds, i.e. the port of Rust's
 * `cluster_counters.reserved_wallet_credits(tenant_id)`.
 *
 * Rust keeps outstanding reservations in the cluster counter backend; this port
 * keeps them in the durable `wallet_reservations` table, whose schema comment
 * names this exact query ("the active, unexpired holds are summed against
 * `balance_credits` to compute AVAILABLE balance for the no-oversell guard").
 * `idx_wallet_reservations_live_holds` covers it. EXPIRED holds are excluded so
 * a crashed request cannot strand credits forever — the expiry IS the release
 * that JS has no `Drop` for.
 */
const WALLET_HELD_SQL =
  "SELECT COALESCE(SUM(amount_credits), 0) AS held FROM wallet_reservations " +
  "WHERE tenant_id = ? AND status = ? AND expires_at_unix > ?";

/**
 * The durable {@link SpendSource}: the tenant database's spend rollups and
 * prepaid wallet.
 *
 * The wallet leg is ONE `db.batch()` — balance and live holds must be read from
 * the same committed snapshot, or a hold that settles between the two reads is
 * counted twice (balance already debited AND still summed as outstanding),
 * which would refuse a tenant that is in fact funded.
 */
export function d1SpendSource(
  db: D1Database,
  nowUnixSeconds: () => number = () => Math.floor(Date.now() / 1000),
): SpendSource {
  return {
    async committedSpendUsd(
      scopeKind: QuotaScopeKind,
      scopeId: string,
      periodMonth: string,
    ): Promise<MonthlySpendReading> {
      try {
        const row = await db
          .prepare(MONTHLY_SPEND_SQL)
          .bind(periodMonth, scopeKind, scopeId)
          .first<{ cost_usd: number | null }>();
        // No row = nothing billed to this scope this month.
        return { ok: true, committedSpendUsd: Number(row?.cost_usd ?? 0) };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `cloudflare d1: monthly spend lookup failed: ${detail}` };
      }
    },

    async walletBalanceCredits(tenantId: string): Promise<WalletBalanceReading> {
      try {
        const results = (await db.batch([
          db.prepare(WALLET_BALANCE_SQL).bind(tenantId),
          db.prepare(WALLET_HELD_SQL).bind(tenantId, WALLET_RESERVATION_ACTIVE, nowUnixSeconds()),
        ])) as unknown as { results?: unknown[] }[];

        const walletRow = (results[0]?.results ?? [])[0] as
          | { balance_credits?: number | null }
          | undefined;
        // Opt-in: no wallet row means this tenant has not adopted prepaid
        // billing and the gate must never deny it.
        if (walletRow === undefined) return { ok: true, availableCredits: null };

        const heldRow = (results[1]?.results ?? [])[0] as { held?: number | null } | undefined;
        const balance = Number(walletRow.balance_credits ?? 0);
        const held = Number(heldRow?.held ?? 0);
        return { ok: true, availableCredits: balance - held };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `cloudflare d1: wallet balance lookup failed: ${detail}` };
      }
    },
  };
}

/**
 * A {@link SpendSource} whose WALLET leg reads a different database from its
 * monthly-rollup leg — because since #819 they really are in different
 * databases, and pretending otherwise is what broke.
 *
 * ## The defect this exists to close
 *
 * `wallets` and `wallet_reservations` are TENANT-schema tables
 * (`sql/d1-ts/tenant/0001_init_tenant.sql`). Under the `durable_object` default
 * they live inside `env.TENANT_DATA.idFromName(tenantId)`, and admission step 3b
 * (`../ratelimit/wallet.ts::routedWalletAdmission`) already reserves against
 * exactly that object. Step 3 — the balance PRE-CHECK — kept reading `env.DB`,
 * so the two halves of one wallet decision were deciding from different
 * topologies. Two concrete outcomes, both observed:
 *
 *  - a deployment migrated from `"off"` still carries a legacy `wallets` row in
 *    `DB` that nothing in the routed topology ever writes, so a tenant funded in
 *    its object is refused `429 wallet_balance_exhausted` forever and topping up
 *    the object cannot clear it;
 *  - a fresh routed deployment has no row in `DB` at all, so the pre-check
 *    reads `null` on every request and is dead code.
 *
 * This is precisely what `../ratelimit/middleware.ts::defaultWorkflowBudgets`
 * already argues must not happen for steps 3b and 5. The rule is the same one:
 * every leg of one admission decision reads the database that leg's rows are
 * actually written to.
 *
 * ## The rollup leg is PASSED THROUGH — the caller routes it
 *
 * `usage_monthly_rollups` is a tenant-schema table too, and the metering sink
 * now WRITES it to the tenant object (`../metering/usage-ledger.ts::
 * usageDatabaseFrom(env, tenantId)` → `TENANT_DATA`), not `env.DB`. So this
 * source passes `committedSpendUsd` through UNCHANGED from the `rollups` it is
 * handed, letting the CALLER pick the rollup database: under the
 * `durable_object` default `../ratelimit/middleware.ts::defaultSpendSource`
 * supplies a tenant-DO-routed rollups source, so BOTH legs of one decision read
 * the same object the sink writes — the rule above, held for the rollup leg too.
 * (An earlier revision of this note claimed the sink still wrote `env.DB`; that
 * is stale — the tenant-scoped rollup write moved to the object.)
 *
 * @param rollups the source for `committedSpendUsd` — unchanged.
 * @param walletDb resolves the database holding THIS tenant's `wallets` row.
 *   Throwing is reported as `ok: false` (→ 503), never as an empty wallet: an
 *   unresolvable tenant has not proven the caller is out of credit.
 */
export function routedWalletSpendSource(
  rollups: SpendSource,
  walletDb: (tenantId: string) => Promise<D1Database>,
  nowUnixSeconds: () => number = () => Math.floor(Date.now() / 1000),
): SpendSource {
  return {
    committedSpendUsd: (scopeKind, scopeId, periodMonth) =>
      rollups.committedSpendUsd(scopeKind, scopeId, periodMonth),
    async walletBalanceCredits(tenantId: string): Promise<WalletBalanceReading> {
      let db: D1Database;
      try {
        db = await walletDb(tenantId);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `routed wallet database unavailable: ${detail}` };
      }
      return d1SpendSource(db, nowUnixSeconds).walletBalanceCredits(tenantId);
    },
  };
}

/**
 * The scope a monthly budget is CHARGED against — `finalize_auth`'s
 * `budget_scope` argument.
 *
 * The winner recorded by `resolveEffectiveQuota` (the scope whose
 * `monthly_budget_usd` won the chain's `min`) is authoritative, so a
 * tenant/project/workspace budget is measured against that scope's AGGREGATE
 * rollup and holds across every key under it. Counting it per key would let N
 * keys each spend the full cap.
 *
 * The fallback — most specific attributed scope first — is Rust's `or_else`
 * arm, reached when a budget has no recorded scope (it came from the plan
 * FLOOR rather than from a policy row). `null` means the request carries no
 * attribution at all, which Rust answers `Ok(false)`: nothing to measure, so
 * nothing to refuse.
 */
export function monthlyBudgetScope(
  quota: EffectiveQuota,
  chain: QuotaScopeChain,
): { readonly kind: QuotaScopeKind; readonly id: string } | null {
  const winner = quota.monthlyBudgetScope;
  if (winner !== undefined) return { kind: winner.kind, id: winner.id };
  const candidates: [QuotaScopeKind, string | undefined][] = [
    ["key", chain.keyId],
    ["workspace", chain.workspaceId],
    ["project", chain.projectId],
    ["tenant", chain.tenantId],
  ];
  for (const [kind, id] of candidates) {
    if (id !== undefined && id !== "") return { kind, id };
  }
  return null;
}

/**
 * One rung of the nested budget as the ADMISSION PATH needs it: which scope's
 * aggregate spend to read, what ceiling applies there, and which counter the
 * in-flight holds contend on.
 */
export interface MonthlyBudgetCharge {
  readonly kind: QuotaScopeKind;
  readonly id: string;
  readonly limitUsd: number;
  /**
   * The shared counter for this rung — `"{kind}:{id}"`, always namespaced (see
   * `keys.ts`). A `project` rung is ONE counter for every key under the
   * project, which is what makes "$5k/month, split however its keys like" a
   * single budget instead of a per-key one.
   */
  readonly counterKey: string;
}

/**
 * The full ladder of budgets a request must satisfy (#679), broadest first.
 *
 * Every rung is enforced, because each is measured against a DIFFERENT
 * aggregate: a project rung against the project's rollup (every key under it),
 * a key rung against that one credential. Enforcing only the tightest NUMBER —
 * which is what {@link monthlyBudgetScope} alone gave — leaves the others
 * unevaluated, and an ancestor cap that is never evaluated is not a cap.
 *
 * The fallback keeps the pre-#679 behavior for a quota that carries a budget
 * but no ladder: a plan floor on a chain with no tenant id, and any caller that
 * builds an `EffectiveQuota` by hand. It charges the single scope
 * {@link monthlyBudgetScope} picks, exactly as before.
 */
export function monthlyBudgetCharges(
  quota: EffectiveQuota,
  chain: QuotaScopeChain,
  apiKeyId: string,
): MonthlyBudgetCharge[] {
  const ladder = quota.monthlyBudgets ?? [];
  if (ladder.length > 0) {
    return ladder.map((rung) => ({
      kind: rung.scope.kind,
      id: rung.scope.id,
      limitUsd: rung.limitUsd,
      counterKey: counterKeyForScope(rung.scope, apiKeyId),
    }));
  }

  const budgetUsd = quota.monthlyBudgetUsd;
  if (budgetUsd === undefined) return [];
  const scope = monthlyBudgetScope(quota, chain);
  if (scope === null) return [];
  return [
    {
      kind: scope.kind,
      id: scope.id,
      limitUsd: budgetUsd,
      counterKey: counterKeyForScope(new QuotaScopeSelector(scope.kind, scope.id), apiKeyId),
    },
  ];
}

// ---------------------------------------------------------------------------
// The in-flight hold — sizing the reservation a request takes against a budget
// ---------------------------------------------------------------------------

/**
 * USD held per admitted request when the operator configures none.
 *
 * ## Why a flat hold, and what it does and does not buy
 *
 * A budget hold has to be sized in middleware, BEFORE the body is parsed and
 * the model resolved, so there is no price to hold (the same constraint
 * `wallet.ts` documents for `GATEWAY_WALLET_HOLD_CREDITS`, and it disappears
 * the day pre-dispatch pricing lands — then this number becomes the estimate).
 *
 * What the hold DOES bound: concurrency. A budget with `H` dollars of headroom
 * admits at most `H / hold` genuinely-simultaneous requests, instead of
 * unbounded (every one of them reading the same `cost_usd` off D1 and passing).
 * At one cent that is 100 concurrent requests per dollar of remaining budget,
 * and exactly ZERO once the budget is spent.
 *
 * What it does NOT bound: the cost of the requests it admits. A hold is not a
 * price. Cumulative spend is still bounded by the rollup the metering path
 * writes, which is why the read-based check upstream of the reservation is kept
 * rather than replaced — the two gates compose (see `middleware.ts` step 2/2b).
 *
 * A cent, and not the smallest representable amount, because a hold far below
 * a request's true cost bounds nothing in practice; and not a dollar, because
 * that would refuse a caller with 99 cents of real headroom.
 */
export const DEFAULT_BUDGET_HOLD_USD = 0.01;

/** Worker bindings that size the budget hold. */
export interface BudgetHoldBindings {
  /**
   * USD to hold per admitted request against each budget rung. Absent or not a
   * positive finite number ⇒ {@link DEFAULT_BUDGET_HOLD_USD}; a bad value is
   * IGNORED rather than applied, because a `0` or `NaN` hold would silently
   * disable the concurrency guard for every tenant.
   */
  readonly GATEWAY_BUDGET_HOLD_USD?: string | undefined;
}

/** {@link BudgetHoldBindings.GATEWAY_BUDGET_HOLD_USD}, validated. */
export function budgetHoldUsdFromEnv(env: BudgetHoldBindings): number {
  const raw = env.GATEWAY_BUDGET_HOLD_USD;
  if (raw === undefined || raw.trim() === "") return DEFAULT_BUDGET_HOLD_USD;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_BUDGET_HOLD_USD;
  return parsed;
}

/** The current UTC `YYYY-MM`, Rust `AppState::current_period_month`. */
export function currentPeriodMonth(nowUnixSeconds: number = Math.floor(Date.now() / 1000)): string {
  return periodMonthFromUnix(nowUnixSeconds);
}
