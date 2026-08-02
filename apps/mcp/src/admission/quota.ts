/**
 * Where the multi-level quota, the committed spend and the prepaid balance for
 * an MCP request come from.
 *
 * ## Nothing here re-implements a decision
 *
 * The MERGE is `@ferrogate/policy`'s `resolveEffectiveQuota` (the clean-room
 * port of `ferrogate-policy/quota.rs`): min-across tenant → project → workspace
 * → key, `enabled = false` anywhere is a hard deny, and a plan supplies the
 * FLOOR. The prepaid NO-OVERSELL guard is `@ferrogate/storage`'s
 * `D1WalletStore.reserveWalletCredits`, whose predicate lives INSIDE the
 * writing statement. This module only decides *which rows to feed them*.
 *
 * ## Two databases, because the rows live in two databases
 *
 * | reading                      | table                        | database |
 * |------------------------------|------------------------------|----------|
 * | quota policy chain + plan    | `quota_policies` / `plans`   | CONTROL  |
 * | committed monthly spend      | `usage_monthly_rollups`      | TENANT   |
 * | prepaid balance + live holds | `wallets` / `wallet_reservations` | TENANT |
 *
 * `apps/mcp` binds the CONTROL database as `env.DB` (`wrangler.toml`,
 * `database_name = "ferrogate-control"`), which is where `sql/d1-ts/control/`
 * creates `quota_policies`. The tenant tables are reached the SAME way
 * `src/auth.ts` reaches `api_keys`: through `@ferrogate/storage`'s
 * `EnvBindingTenantDatabaseRouter`, so one tenant's balance can never be read
 * out of another tenant's database.
 *
 * ## Why every failure is 503 and never "no limit"
 *
 * `AppState::resolve_effective_quota` returns `503 quota_resolution_unavailable`
 * on a lookup error, and `finalize_auth` maps an `Err` from the rollup or the
 * wallet read to the same. A source that answered "no policies" / "0 spent" /
 * "no wallet" on a database error would turn an outage into UNLIMITED traffic
 * for every caller — the exact opposite of what a limiter is for. So a rejected
 * query, a row with an unknown `scope_type` and a malformed JSON column all
 * become `{ ok: false, detail }`.
 *
 * The ONE thing that is not an error is a tenant with no `tenant_databases`
 * registry row. That tenant has no `usage_monthly_rollups` and no `wallets` row
 * anywhere, so `0 spent` / `no wallet` is the TRUE reading rather than a
 * degraded one — the same argument `apps/gateway`'s `NO_SPEND_SOURCE` makes for
 * a deployment with no tenant database bound. A tenant whose registry row
 * EXISTS but whose binding is missing is a deployment fault and is 503, exactly
 * as `src/auth.ts` splits the same two cases.
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
  D1WalletStore,
  StorageError,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  WALLET_RESERVATION_ACTIVE,
  type WalletReservationResult,
  boolFromSqlite,
  optionalNumber,
  periodMonthFromUnix,
} from "@ferrogate/storage";

import { type CounterWindow, requestWindows } from "./counters.js";

/** Everything the gate needs about one caller. */
export interface QuotaSubject {
  /** The presented credential's id. `key`-scope windows are namespaced with it. */
  readonly apiKeyId: string;
  /** Tenant / project / workspace / key ids to merge policies across. */
  readonly chain: QuotaScopeChain;
  /**
   * The TOK-12 per-key `request_limit_per_minute` carried on the `api_keys`
   * row itself, independent of the quota chain. Rust
   * `AuthContext.request_limit_per_minute`.
   */
  readonly requestLimitPerMinute?: number | undefined;
}

// ---------------------------------------------------------------------------
// The policy chain (CONTROL database)
// ---------------------------------------------------------------------------

export type QuotaPolicySnapshot =
  | {
      readonly ok: true;
      /** Rust's `lookup` closure. `undefined` = that scope does not restrict. */
      readonly lookup: (kind: QuotaScopeKind, id: string) => StoredQuotaPolicy | undefined;
      /** The tenant's plan, if any — the merge FLOOR. */
      readonly plan?: StoredPlan | undefined;
    }
  | { readonly ok: false; readonly detail: string };

export interface QuotaPolicySource {
  policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot>;
}

/** The merged quota plus the RPM windows it implies. */
export type QuotaResolution =
  | { readonly ok: true; readonly quota: EffectiveQuota; readonly rpm: CounterWindow[] }
  | { readonly ok: false; readonly detail: string };

/**
 * Merge the chain and derive the windows.
 *
 * A `deniedBy` result is returned as-is on `quota` — it is a **403
 * `quota_scope_disabled`**, not a rate-limit denial, and the caller must check
 * for it before enforcing any window (Rust `finalize_auth` does exactly that,
 * ahead of the budget and RPM checks). No windows are produced on that branch:
 * a hard-denied request never reaches admission counting.
 */
export async function resolveQuotaWindows(
  source: QuotaPolicySource,
  subject: QuotaSubject,
): Promise<QuotaResolution> {
  const snapshot = await source.policiesFor(subject);
  if (!snapshot.ok) return { ok: false, detail: snapshot.detail };

  const quota = resolveEffectiveQuota(subject.chain, snapshot.lookup, snapshot.plan);
  if (quota.deniedBy !== undefined) return { ok: true, quota, rpm: [] };
  // Rust `request_windows()` returns an EMPTY vec when `api_key_id` is None, so
  // a credential with no key id is UNLIMITED on the RPM dimension — not denied,
  // and not counted under an unnamespaceable `"key:"` window. The budget and
  // wallet legs above still apply to it, exactly as they do in `finalize_auth`.
  if (subject.apiKeyId === "") return { ok: true, quota, rpm: [] };
  return {
    ok: true,
    quota,
    rpm: requestWindows(subject.apiKeyId, quota, subject.requestLimitPerMinute),
  };
}

/** A source that configures nothing. Used when no control database is bound. */
export const NO_QUOTA_POLICIES: QuotaPolicySource = {
  async policiesFor(): Promise<QuotaPolicySnapshot> {
    return { ok: true, lookup: () => undefined };
  },
};

// ---------------------------------------------------------------------------
// Which control tables this deployment actually has
// ---------------------------------------------------------------------------

/** The CONTROL tables the policy chain reads. */
export const QUOTA_POLICY_TABLE = "quota_policies";
export const PLAN_TABLE = "plans";
export const TENANT_TABLE = "tenants";
/** The per-tenant database registry the SPEND half must go through. */
export const TENANT_DATABASE_TABLE = "tenant_databases";

const PROBED_TABLES = [
  QUOTA_POLICY_TABLE,
  PLAN_TABLE,
  TENANT_TABLE,
  TENANT_DATABASE_TABLE,
] as const;

/**
 * The quota tables belong to the MIGRATIONS slice (`sql/d1-ts/control/`), not
 * to this app, so "the table is not there" is a real, distinguishable state —
 * and it is distinguished STRUCTURALLY rather than by string-matching a D1
 * error message, exactly as `src/auth.ts` distinguishes the credential tables:
 *
 *   * table ABSENT  ⇒ NOT PROVISIONED ⇒ no policy could have been configured,
 *     so nothing restricts. A database with no `quota_policies` has no rows to
 *     enforce either, so skipping it cannot drop a limit that exists.
 *   * table PRESENT ⇒ any query failure is an OUTAGE ⇒ 503, never "no policy".
 *     A database outage must not be indistinguishable from an unlimited
 *     tenant, which is the direction that turns an incident into free traffic.
 *
 * Cached per D1 handle for the life of the isolate, like `src/auth.ts`'s probe.
 * CONSEQUENCE, stated rather than discovered: an operator who applies the
 * control migration under a LIVE isolate is not seen by that isolate until it
 * recycles. Provisioning precedes traffic, and the alternative — a
 * `sqlite_master` read on every admission — is a hot-path cost paid forever to
 * serve a one-time transition.
 */
const quotaTableCache = new WeakMap<D1Database, Promise<ReadonlySet<string>>>();

async function quotaTables(db: D1Database): Promise<ReadonlySet<string>> {
  const cached = quotaTableCache.get(db);
  if (cached !== undefined) return cached;
  const probe = (async (): Promise<ReadonlySet<string>> => {
    const placeholders = PROBED_TABLES.map(() => "?").join(", ");
    const rows = await db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`)
      .bind(...PROBED_TABLES)
      .all<{ name: string }>();
    return new Set(rows.results.map((row) => row.name));
  })();
  quotaTableCache.set(db, probe);
  // A FAILED probe must not be remembered as "no tables" — that would turn a
  // transient D1 blip into a permanently unlimited isolate.
  probe.catch(() => quotaTableCache.delete(db));
  return probe;
}

/** Test seam: forget the probe for one database (an isolate recycle, simulated). */
export function forgetQuotaTableProbe(db: D1Database): void {
  quotaTableCache.delete(db);
}

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
    // NOT `[]`. An unreadable allowlist that decoded to "no allowlist" would
    // WIDEN the effective quota — the one direction a failure must never take.
    throw new QuotaRowError(`quota_policies.${column} on row ${id} is not valid JSON`);
  }
  if (!Array.isArray(parsed)) {
    throw new QuotaRowError(`quota_policies.${column} on row ${id} is not a JSON array`);
  }
  return parsed as T[];
}

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
    modelAllowlist: jsonArrayColumn<string>(
      row["model_allowlist_json"],
      "model_allowlist_json",
      id,
    ),
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

function rowToStoredPlan(row: Record<string, unknown>): StoredPlan {
  const id = String(row["id"] ?? "");
  const allowlist = row["default_model_allowlist_json"];
  let defaultModelAllowlist: string[] = [];
  if (allowlist !== null && allowlist !== undefined && allowlist !== "") {
    try {
      const parsed: unknown = JSON.parse(String(allowlist));
      if (!Array.isArray(parsed)) throw new Error("not an array");
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
 * ONE `batch()`, not five queries. `resolveEffectiveQuota` walks tenant →
 * project → workspace → key, so up to four policy rows and one plan row are
 * needed BEFORE the request is admitted, i.e. on the hot path of every
 * authenticated call. D1 runs a batch as one round trip inside one implicit
 * transaction, so the reads cost one hop and cannot interleave with a
 * control-plane write that would let the chain be read half-updated. The policy
 * leg is ONE statement with an OR-ed `(scope_type, scope_id)` predicate because
 * that pair is `UNIQUE` and indexed.
 */
export function d1QuotaPolicySource(db: D1Database): QuotaPolicySource {
  return {
    async policiesFor(subject: QuotaSubject): Promise<QuotaPolicySnapshot> {
      let tables: ReadonlySet<string>;
      try {
        tables = await quotaTables(db);
      } catch (error) {
        return {
          ok: false,
          detail: `cloudflare d1: control database probe failed: ${describe(error)}`,
        };
      }
      // Not provisioned: there is no policy table, therefore no policy.
      if (!tables.has(QUOTA_POLICY_TABLE)) return { ok: true, lookup: () => undefined };

      const scopes: [QuotaScopeKind, string][] = [];
      const { tenantId, projectId, workspaceId, keyId } = subject.chain;
      if (tenantId !== undefined) scopes.push(["tenant", tenantId]);
      if (projectId !== undefined) scopes.push(["project", projectId]);
      if (workspaceId !== undefined) scopes.push(["workspace", workspaceId]);
      if (keyId !== undefined) scopes.push(["key", keyId]);

      // A credential with no scope chain cannot be governed by any policy row,
      // so the round trip is skipped rather than issued with an empty predicate
      // (which would scan the table).
      if (scopes.length === 0) return { ok: true, lookup: () => undefined };

      const predicate = scopes.map(() => "(scope_type = ? AND scope_id = ?)").join(" OR ");
      const statements = [
        db
          .prepare(`SELECT ${QUOTA_POLICY_COLUMNS} FROM quota_policies WHERE ${predicate}`)
          .bind(...scopes.flat()),
      ];
      // The plan FLOOR is only reachable when both of its tables exist; a
      // deployment with `quota_policies` but no `plans` simply has no floor.
      if (tenantId !== undefined && tables.has(PLAN_TABLE) && tables.has(TENANT_TABLE)) {
        statements.push(
          db
            .prepare("SELECT p.* FROM plans p JOIN tenants t ON t.plan_id = p.id WHERE t.id = ?")
            .bind(tenantId),
        );
      }

      let results: { results?: unknown[] }[];
      try {
        results = (await db.batch(statements)) as unknown as { results?: unknown[] }[];
      } catch (error) {
        return {
          ok: false,
          detail: `cloudflare d1: quota policy lookup failed: ${describe(error)}`,
        };
      }

      const index = new Map<string, StoredQuotaPolicy>();
      let plan: StoredPlan | undefined;
      try {
        for (const row of (results[0]?.results ?? []) as Record<string, unknown>[]) {
          const policy = rowToStoredPolicy(row);
          index.set(`${policy.scopeType}:${policy.scopeId}`, policy);
        }
        const planRow = (results[1]?.results ?? [])[0] as Record<string, unknown> | undefined;
        if (planRow !== undefined) plan = rowToStoredPlan(planRow);
      } catch (error) {
        if (error instanceof QuotaRowError) return { ok: false, detail: error.message };
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

// ---------------------------------------------------------------------------
// Spend + prepaid wallet (TENANT database)
// ---------------------------------------------------------------------------

export type MonthlySpendReading =
  | { readonly ok: true; readonly committedSpendUsd: number }
  | { readonly ok: false; readonly detail: string };

export type WalletBalanceReading =
  | { readonly ok: true; readonly availableCredits: number | null }
  | { readonly ok: false; readonly detail: string };

/** An admission hold that must be let go, whatever happens. */
export interface WalletHold {
  readonly id: string;
  readonly amountCredits: number;
  /** Idempotent; never throws (a release failure must not fail the response). */
  release(): Promise<void>;
}

export type WalletReserveOutcome =
  | { readonly kind: "admitted"; readonly hold: WalletHold }
  | { readonly kind: "insufficient" }
  /** No wallet row, or no tenant database. NEVER a denial. */
  | { readonly kind: "not_applicable" }
  | { readonly kind: "unavailable"; readonly detail: string };

/**
 * The BALANCE half of the admission chain: what has already been spent, what is
 * left in the prepaid wallet, and the atomic hold that bounds concurrency.
 *
 * Rust reads the first two off `AppState.repositories`
 * (`state_wallets.rs::monthly_budget_exceeded` → `get_usage_monthly_rollup`,
 * and `::wallet_balance_exhausted` → `get_wallet` minus the cluster counters'
 * outstanding reservations).
 */
export interface SpendSource {
  /**
   * `get_usage_monthly_rollup(scope_type, scope_id, period_month).cost_usd`.
   *
   * An ABSENT rollup row is `0`, not a failure — Rust's
   * `.map(|rollup| rollup.cost_usd).unwrap_or(0.0)`, and the normal state for a
   * scope that has not been billed this month.
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
  /**
   * The NO-OVERSELL guard: `@ferrogate/storage`'s three-statement atomic batch,
   * whose predicate lives INSIDE the INSERT. The balance READ above cannot
   * bound a race; this can, and it is the only thing here that can.
   */
  reserveWallet(
    tenantId: string,
    holdId: string,
    nowUnixSeconds: number,
  ): Promise<WalletReserveOutcome>;
}

/**
 * The source for a caller whose tenant has no provisioned database.
 *
 * NOT a fail-open stub: with no `usage_monthly_rollups` table there is no
 * recorded spend and `0` is the true reading; with no `wallets` table no tenant
 * has adopted prepaid billing, which is exactly the case Rust never denies.
 * Both answers are the Rust behaviour for an empty store, so provisioning the
 * database can only ever TIGHTEN admission, never loosen it.
 */
export const NO_SPEND_SOURCE: SpendSource = {
  async committedSpendUsd(): Promise<MonthlySpendReading> {
    return { ok: true, committedSpendUsd: 0 };
  },
  async walletBalanceCredits(): Promise<WalletBalanceReading> {
    return { ok: true, availableCredits: null };
  },
  async reserveWallet(): Promise<WalletReserveOutcome> {
    return { kind: "not_applicable" };
  },
};

/**
 * Credits held per admitted MCP request.
 *
 * One credit is the smallest hold the storage guard accepts (it rejects a
 * non-positive amount outright). At this size a wallet funded with K credits
 * admits K genuinely-concurrent requests and refuses the K+1st, which is the
 * no-oversell property; it is deliberately NOT a claim about the money those K
 * requests go on to spend. Rust passed a PRICED `estimated_credits`; an MCP
 * tool call has no pre-dispatch price, so this is a flat floor — weaker in a
 * known direction (it under-holds an expensive call, never over-holds a cheap
 * one) and never the reverse.
 */
export const MCP_WALLET_HOLD_CREDITS = 1;

/**
 * How long an admission hold survives without an explicit release.
 *
 * The release runs in a `finally`, so this only matters when the isolate dies
 * mid-request. 60s comfortably exceeds a Worker's wall-clock budget for one
 * request, so a live request can never have its own hold swept out from under
 * it, and a dead one frees its credits within a minute.
 */
export const MCP_WALLET_HOLD_TTL_SECONDS = 60;

/** `usage_monthly_rollups` is UNIQUE on `(period_month, scope_type, scope_id)`. */
const MONTHLY_SPEND_SQL =
  "SELECT cost_usd FROM usage_monthly_rollups " +
  "WHERE period_month = ? AND scope_type = ? AND scope_id = ?";

const WALLET_BALANCE_SQL = "SELECT balance_credits FROM wallets WHERE tenant_id = ?";

/**
 * The live holds — the port of Rust's
 * `cluster_counters.reserved_wallet_credits(tenant_id)`. EXPIRED holds are
 * excluded so a crashed request cannot strand credits forever; the expiry IS
 * the release that JS has no `Drop` for.
 */
const WALLET_HELD_SQL =
  "SELECT COALESCE(SUM(amount_credits), 0) AS held FROM wallet_reservations " +
  "WHERE tenant_id = ? AND status = ? AND expires_at_unix > ?";

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The durable {@link SpendSource} over ONE tenant's database handle.
 *
 * The handle carries the tenant identity that `D1WalletStore.assertTenant`
 * checks, so a routing bug can never write one tenant's hold against another's
 * balance. Building it PER REQUEST from the authenticated tenant is what arms
 * that tripwire.
 */
export function d1SpendSource(
  handle: TenantDatabaseHandle,
  nowUnixSeconds: () => number = () => Math.floor(Date.now() / 1000),
): SpendSource {
  const db = handle.db;
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
        return {
          ok: false,
          detail: `cloudflare d1: monthly spend lookup failed: ${describe(error)}`,
        };
      }
    },

    async walletBalanceCredits(tenantId: string): Promise<WalletBalanceReading> {
      try {
        // ONE `batch()`: balance and live holds must be read from the same
        // committed snapshot, or a hold that settles between the two reads is
        // counted twice (balance already debited AND still summed as
        // outstanding), which would refuse a tenant that is in fact funded.
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
        return {
          ok: true,
          availableCredits: Number(walletRow.balance_credits ?? 0) - Number(heldRow?.held ?? 0),
        };
      } catch (error) {
        return {
          ok: false,
          detail: `cloudflare d1: wallet balance lookup failed: ${describe(error)}`,
        };
      }
    },

    async reserveWallet(
      tenantId: string,
      holdId: string,
      now: number,
    ): Promise<WalletReserveOutcome> {
      const store = new D1WalletStore(handle);
      let result: WalletReservationResult;
      try {
        result = await store.reserveWalletCredits(
          holdId,
          tenantId,
          MCP_WALLET_HOLD_CREDITS,
          now + MCP_WALLET_HOLD_TTL_SECONDS,
          now,
        );
      } catch (error) {
        // A storage outage has NOT proven the caller is overdrawn, so it is
        // reported as `unavailable` (→ 503) and never as `insufficient`
        // (→ 429).
        return { kind: "unavailable", detail: describe(error) };
      }
      if (result.kind === "no_wallet") return { kind: "not_applicable" };
      if (result.kind === "insufficient") return { kind: "insufficient" };
      return {
        kind: "admitted",
        hold: {
          id: result.reservation.id,
          amountCredits: result.reservation.amountCredits,
          async release(): Promise<void> {
            try {
              await store.releaseWalletReservation(holdId, Math.floor(Date.now() / 1000));
            } catch {
              // The hold expires on its own, so a failed release costs at most
              // one TTL of stranded credits. It must never surface: by the time
              // this runs the response is already the client's.
            }
          },
        },
      };
    },
  };
}

/** How a tenant's spend store was resolved. */
export type SpendResolution =
  | { readonly ok: true; readonly source: SpendSource }
  | { readonly ok: false; readonly detail: string };

/**
 * Resolve the tenant's spend store, or say why not.
 *
 * The split is the SAME one `src/auth.ts` makes on the credential path, and for
 * the same reason:
 *
 *  * NO registry row ⇒ this tenant has no provisioned database, therefore no
 *    rollups and no wallet ⇒ {@link NO_SPEND_SOURCE}, which is the TRUE reading
 *    of an empty store and not a degradation;
 *  * a registry row this Worker cannot REACH ⇒ a deployment fault an operator
 *    must see ⇒ `{ ok: false }` ⇒ 503. Falling back to "no spend" there would
 *    hand every over-budget tenant unlimited spend by deleting a binding.
 */
export async function spendSourceForTenant(
  router: TenantDatabaseRouter | undefined,
  tenantId: string,
): Promise<SpendResolution> {
  if (router === undefined || tenantId === "") return { ok: true, source: NO_SPEND_SOURCE };
  let handle: TenantDatabaseHandle;
  try {
    handle = await router.forTenant(tenantId);
  } catch (error) {
    if (error instanceof StorageError && error.kind === "not_found") {
      return { ok: true, source: NO_SPEND_SOURCE };
    }
    return { ok: false, detail: `tenant database routing failed: ${describe(error)}` };
  }
  return { ok: true, source: d1SpendSource(handle) };
}

/**
 * The spend resolver the gate uses, with the registry table probed first.
 *
 * `TenantDatabaseRouter.forTenant` reads `tenant_databases` out of the CONTROL
 * database. On a deployment that has not applied the control migration that
 * table does not exist, and the read throws — which, without this probe, would
 * be indistinguishable from an unreachable database and answer 503 on every
 * request. The same NOT-PROVISIONED / OUTAGE split the policy chain uses
 * applies: no registry table means no tenant has a database, therefore no
 * rollups and no wallets, which is {@link NO_SPEND_SOURCE}. A registry that
 * EXISTS and cannot be read is still 503.
 */
export function tenantSpendResolver(
  db: D1Database,
  router?: TenantDatabaseRouter,
): (tenantId: string) => Promise<SpendResolution> {
  return async (tenantId: string): Promise<SpendResolution> => {
    let tables: ReadonlySet<string>;
    try {
      tables = await quotaTables(db);
    } catch (error) {
      return {
        ok: false,
        detail: `cloudflare d1: control database probe failed: ${describe(error)}`,
      };
    }
    if (!tables.has(TENANT_DATABASE_TABLE)) return { ok: true, source: NO_SPEND_SOURCE };
    return spendSourceForTenant(router, tenantId);
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
 * arm, reached when a budget came from the plan FLOOR rather than a policy row.
 * `null` means the request carries no attribution at all, which Rust answers
 * `Ok(false)`: nothing to measure, so nothing to refuse.
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

/** The hold id for a request. Stable, so a retried admission is idempotent. */
export function walletHoldId(requestId: string): string {
  return `mcp_hold_${requestId}`;
}
