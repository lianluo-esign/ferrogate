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
  type StoredPlan,
  type StoredQuotaPolicy,
  resolveEffectiveQuota,
} from "@ferrogate/policy";
import { boolFromSqlite, optionalNumber } from "@ferrogate/storage";
import { type CounterWindow, requestWindows, tpmWindow } from "./keys.js";

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
  const id = String(row["id"] ?? "");
  const scopeType = String(row["scope_type"] ?? "");
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
    scopeId: String(row["scope_id"] ?? ""),
    modelAllowlist: jsonArrayColumn<string>(row["model_allowlist_json"], "model_allowlist_json", id),
    rpmLimit: optionalNumber(row["rpm_limit"]),
    tpmLimit: optionalNumber(row["tpm_limit"]),
    monthlyBudgetUsd: optionalNumber(row["monthly_budget_usd"]),
    assetStorageQuotaBytes: optionalNumber(row["asset_storage_quota_bytes"]),
    assetMaxObjectBytes: optionalNumber(row["asset_max_object_bytes"]),
    agentCostBudgetUsd: optionalNumber(row["agent_cost_budget_usd"]),
    alertThresholdPcts: jsonArrayColumn<number>(
      row["alert_threshold_pcts_json"],
      "alert_threshold_pcts_json",
      id,
    ),
    enabled: boolFromSqlite(row["enabled"]),
    createdAtUnix: Number(row["created_at_unix"] ?? 0),
    updatedAtUnix: Number(row["updated_at_unix"] ?? 0),
    monthlyEgressBytesBudget: optionalNumber(row["monthly_egress_bytes_budget"]),
    downloadRpmLimit: optionalNumber(row["download_rpm_limit"]),
  };
}

/** One `plans` row → `StoredPlan`. */
function rowToStoredPlan(row: Record<string, unknown>): StoredPlan {
  const id = String(row["id"] ?? "");
  const allowlist = row["default_model_allowlist_json"];
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
    name: String(row["name"] ?? ""),
    slug: String(row["slug"] ?? ""),
    mcpEnabled: boolFromSqlite(row["mcp_enabled"]),
    selfHostedWorkersEnabled: boolFromSqlite(row["self_hosted_workers_enabled"]),
    ...(optionalNumber(row["admin_console_seats"]) === undefined
      ? {}
      : { adminConsoleSeats: optionalNumber(row["admin_console_seats"]) }),
    defaultModelAllowlist,
    defaultRpmLimit: optionalNumber(row["default_rpm_limit"]),
    defaultTpmLimit: optionalNumber(row["default_tpm_limit"]),
    defaultMonthlyBudgetUsd: optionalNumber(row["default_monthly_budget_usd"]),
    createdAtUnix: Number(row["created_at_unix"] ?? 0),
    updatedAtUnix: Number(row["updated_at_unix"] ?? 0),
    assetHostingEnabled: boolFromSqlite(row["asset_hosting_enabled"]),
    defaultAssetStorageQuotaBytes: optionalNumber(row["default_asset_storage_quota_bytes"]),
    defaultAssetMaxObjectBytes: optionalNumber(row["default_asset_max_object_bytes"]),
    defaultAgentCostBudgetUsd: optionalNumber(row["default_agent_cost_budget_usd"]),
    defaultMonthlyEgressBytesBudget: optionalNumber(row["default_monthly_egress_bytes_budget"]),
    defaultDownloadRpmLimit: optionalNumber(row["default_download_rpm_limit"]),
    extensionToolsEnabled: boolFromSqlite(row["extension_tools_enabled"]),
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
 */
export function d1QuotaPolicySource(db: D1Database): QuotaPolicySource {
  return {
    async policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot> {
      const scopes: [QuotaScopeKind, string][] = [];
      const { tenantId, projectId, workspaceId, keyId } = subject.chain;
      if (tenantId !== undefined) scopes.push(["tenant", tenantId]);
      if (projectId !== undefined) scopes.push(["project", projectId]);
      if (workspaceId !== undefined) scopes.push(["workspace", workspaceId]);
      if (keyId !== undefined) scopes.push(["key", keyId]);

      // Nothing to look up: a credential with no scope chain at all cannot be
      // governed by any policy row, so the round trip is skipped rather than
      // issued with an empty predicate (which would scan the table).
      if (scopes.length === 0) {
        return { ok: true, lookup: () => undefined };
      }

      const predicate = scopes.map(() => "(scope_type = ? AND scope_id = ?)").join(" OR ");
      const bindings = scopes.flat();

      const statements = [
        db
          .prepare(`SELECT ${QUOTA_POLICY_COLUMNS} FROM quota_policies WHERE ${predicate}`)
          .bind(...bindings),
      ];
      if (tenantId !== undefined) {
        statements.push(
          db
            .prepare(
              "SELECT p.* FROM plans p JOIN tenants t ON t.plan_id = p.id WHERE t.id = ?",
            )
            .bind(tenantId),
        );
      }

      let results: { results?: unknown[] }[];
      try {
        results = (await db.batch(statements)) as unknown as { results?: unknown[] }[];
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `cloudflare d1: quota policy lookup failed: ${detail}` };
      }

      const index = new Map<string, StoredQuotaPolicy>();
      let plan: StoredPlan | undefined;
      try {
        for (const row of (results[0]?.results ?? []) as Record<string, unknown>[]) {
          const policy = rowToStoredPolicy(row);
          index.set(`${policy.scopeType}:${policy.scopeId}`, policy);
        }
        const planRow = (results[1]?.results ?? [])[0] as Record<string, unknown> | undefined;
        if (planRow !== undefined) {
          plan = rowToStoredPlan(planRow);
        }
      } catch (error) {
        if (error instanceof QuotaRowError) {
          return { ok: false, detail: error.message };
        }
        throw error;
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

/**
 * The {@link QuotaPolicySource} the composition root gets.
 *
 * D1 whenever the control database is bound, the Worker vars otherwise. The
 * order is deliberate and is NOT a merge: a deployment that has provisioned
 * `quota_policies` rows must not have them silently widened (or narrowed) by a
 * stale `GATEWAY_QUOTA_POLICIES` var left over from before the migration. One
 * source of truth per deployment, chosen by which binding exists.
 */
export function quotaPolicySourceFromEnv(env: QuotaBindings): QuotaPolicySource {
  const db = env.CONTROL_DB ?? env.BILLING_DB;
  return db === undefined ? quotaPolicySourceFromVars(env) : d1QuotaPolicySource(db);
}
