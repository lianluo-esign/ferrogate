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
import {
  WALLET_RESERVATION_ACTIVE,
  boolFromSqlite,
  optionalNumber,
  periodMonthFromUnix,
} from "@ferrogate/storage";
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

/**
 * `env.DB`, but only when it is really a D1 binding.
 *
 * Same guard as `meteringBindingsFromEnv`: a `[vars]` entry named `DB` is a
 * STRING, and handing a string to `db.prepare()` would throw on the request
 * path rather than degrading to {@link NO_SPEND_SOURCE}.
 */
function spendDatabase(env: SpendBindings): D1Database | undefined {
  const candidate = env.DB;
  return candidate !== undefined && typeof candidate.prepare === "function" ? candidate : undefined;
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
 * The {@link SpendSource} the composition root gets: D1 whenever the tenant
 * database is bound, {@link NO_SPEND_SOURCE} otherwise.
 */
export function spendSourceFromEnv(env: SpendBindings): SpendSource {
  const db = spendDatabase(env);
  return db === undefined ? NO_SPEND_SOURCE : d1SpendSource(db);
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

/** The current UTC `YYYY-MM`, Rust `AppState::current_period_month`. */
export function currentPeriodMonth(nowUnixSeconds: number = Math.floor(Date.now() / 1000)): string {
  return periodMonthFromUnix(nowUnixSeconds);
}
