/**
 * Where the multi-level quota and the spend/balance readings come from.
 *
 * **The MERGE ITSELF IS NOT IMPLEMENTED HERE.** `@ferrogate/policy`'s
 * `resolveEffectiveQuota` already ports `ferrogate-policy/quota.rs`: min-across
 * tenant → project → workspace → key, model-allowlist intersection,
 * `enabled = false` anywhere is a hard deny, and a plan supplies the FLOOR (a
 * field takes the plan default only when no policy set it). This module only
 * decides *which policies to feed it* and turns the result into the RPM windows
 * in `./keys.ts`.
 *
 * `resolveEffectiveQuota` takes its policy lookup as a closure precisely so the
 * source is swappable, so the port is a {@link QuotaPolicySource}. Two are
 * shipped, chosen exactly the way `resolveDeps` chooses the credential
 * authorities — DURABLE FIRST:
 *
 *  - {@link d1QuotaPolicySource} — the CONTROL database's `quota_policies` +
 *    `plans` + `tenants.plan_id`, which is what `AppState::resolve_effective_quota`
 *    reads from Supabase in Rust. Selected whenever `CONTROL_DB` is bound.
 *  - {@link quotaPolicySourceFromVars} — the `FG_DEV_QUOTA_POLICIES` dev var,
 *    mirroring how `FG_DEV_API_KEYS` backs the api-key port. Fail-closed on
 *    malformed JSON exactly as `parseJsonVar` is elsewhere in this app: an
 *    unreadable table configures NO policies, which can only leave a limit
 *    unset, never raise one.
 *
 * The two fail closed DIFFERENTLY, and the difference is Rust's: a VAR that
 * cannot be parsed is a static misconfiguration and configures nothing, while a
 * D1 lookup that FAILS is an outage and answers `503
 * quota_resolution_unavailable` — a limiter that admitted every caller during a
 * database outage would be a free-traffic hole, not graceful degradation.
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

import { type CounterWindow, requestWindows } from "./keys.js";

/**
 * Everything admission needs about one caller, projected out of the resolved
 * `AuthContext`.
 */
export interface QuotaSubject {
  /** The presented credential's id. `key`-scope windows are namespaced with it. */
  readonly apiKeyId: string;
  /** Tenant / project / workspace / key ids to merge policies across. */
  readonly chain: QuotaScopeChain;
  /**
   * The TOK-12 per-key `api_keys.request_limit_per_minute` carried on the
   * credential itself, independent of the quota chain. Rust
   * `AuthContext.request_limit_per_minute`.
   */
  readonly requestLimitPerMinute?: number | undefined;
}

/** Supplies the policies + plan for a subject. */
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
    return { ok: true, quota, rpm: [] };
  }
  return {
    ok: true,
    quota,
    rpm: requestWindows(subject.apiKeyId, quota, subject.requestLimitPerMinute),
  };
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/** Worker bindings this module reads. */
export interface QuotaBindings {
  /**
   * The CONTROL database (`sql/d1-ts/control/`), holding `quota_policies`,
   * `plans` and `tenants`. It is the SAME binding
   * `d1WorkerIdentityPort` already reads, so the quota chain needs no new
   * database — only the rows.
   */
  readonly CONTROL_DB?: D1Database | undefined;
  /** DEV/TEST ONLY: JSON array of `quota_policies` rows in wire (snake_case) shape. */
  readonly FG_DEV_QUOTA_POLICIES?: string | undefined;
}

function parseJsonVar<T>(raw: string | undefined, fallback: T): T {
  if (raw === undefined || raw.trim() === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/** `env.X`, but only when it is really a D1 binding (a `[vars]` entry is a STRING). */
function d1Binding(candidate: D1Database | undefined): D1Database | undefined {
  return candidate !== undefined && typeof candidate.prepare === "function" ? candidate : undefined;
}

// ---------------------------------------------------------------------------
// The dev-var source
// ---------------------------------------------------------------------------

interface WirePolicy {
  id?: string;
  scope_type: QuotaScopeKind;
  scope_id: string;
  model_allowlist?: string[];
  rpm_limit?: number;
  tpm_limit?: number;
  monthly_budget_usd?: number;
  enabled?: boolean;
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
    alertThresholdPcts: [],
    // Rust's default for a persisted policy row is enabled; only an explicit
    // `false` denies, so an omitted column cannot lock a tenant out by accident.
    enabled: wire.enabled ?? true,
    createdAtUnix: 0,
    updatedAtUnix: 0,
  };
}

/**
 * Build a {@link QuotaPolicySource} from `FG_DEV_QUOTA_POLICIES`.
 *
 * Policies are indexed by `"{scope_type}:{scope_id}"` — the same shape as
 * `quotaPolicyId` in `@ferrogate/policy`, and deliberately NOT the counter key
 * (a policy row's identity and a counter window's identity are different
 * things; conflating them is how the `key`-scope namespacing gets lost).
 */
export function quotaPolicySourceFromVars(env: QuotaBindings): QuotaPolicySource {
  const rows = parseJsonVar<WirePolicy[]>(env.FG_DEV_QUOTA_POLICIES, []);
  const index = new Map<string, StoredQuotaPolicy>();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (typeof row?.scope_type !== "string" || typeof row?.scope_id !== "string") continue;
    index.set(`${row.scope_type}:${row.scope_id}`, toStoredPolicy(row));
  }
  const lookup = (kind: QuotaScopeKind, id: string): StoredQuotaPolicy | undefined =>
    index.get(`${kind}:${id}`);
  return {
    async policiesFor(): Promise<QuotaPolicySnapshot> {
      return { ok: true, lookup };
    },
  };
}

/** A source that configures nothing. Used when neither a database nor a var exists. */
export const NO_QUOTA_POLICIES: QuotaPolicySource = {
  async policiesFor(): Promise<QuotaPolicySnapshot> {
    return { ok: true, lookup: () => undefined };
  },
};

// ---------------------------------------------------------------------------
// The D1 source — `AppState::resolve_effective_quota`'s storage half
// ---------------------------------------------------------------------------

const QUOTA_POLICY_COLUMNS =
  "id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit, " +
  "monthly_budget_usd, enabled, created_at_unix, updated_at_unix";

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
  const id = String(row.id ?? "");
  const scopeType = String(row.scope_type ?? "");
  if (
    scopeType !== "tenant" &&
    scopeType !== "project" &&
    scopeType !== "workspace" &&
    scopeType !== "key"
  ) {
    // A scope kind the merge does not know cannot be applied, and DROPPING the
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
    alertThresholdPcts: [],
    enabled: boolFromSqlite(row.enabled),
    createdAtUnix: Number(row.created_at_unix ?? 0),
    updatedAtUnix: Number(row.updated_at_unix ?? 0),
  };
}

function rowToStoredPlan(row: Record<string, unknown>): StoredPlan {
  return {
    id: String(row.id ?? ""),
    name: String(row.name ?? ""),
    slug: String(row.slug ?? ""),
    mcpEnabled: boolFromSqlite(row.mcp_enabled),
    selfHostedWorkersEnabled: boolFromSqlite(row.self_hosted_workers_enabled),
    defaultModelAllowlist: [],
    defaultRpmLimit: optionalNumber(row.default_rpm_limit),
    defaultTpmLimit: optionalNumber(row.default_tpm_limit),
    defaultMonthlyBudgetUsd: optionalNumber(row.default_monthly_budget_usd),
    createdAtUnix: Number(row.created_at_unix ?? 0),
    updatedAtUnix: Number(row.updated_at_unix ?? 0),
    assetHostingEnabled: boolFromSqlite(row.asset_hosting_enabled),
    extensionToolsEnabled: boolFromSqlite(row.extension_tools_enabled),
  };
}

/**
 * The durable {@link QuotaPolicySource}: the CONTROL database's `quota_policies`
 * chain plus the tenant's `plans` floor.
 *
 * ONE `batch()`, not five queries. `resolveEffectiveQuota` walks tenant →
 * project → workspace → key, so up to four policy rows and one plan row are
 * needed BEFORE the request is admitted — on the hot path of every
 * authenticated call. D1 runs a batch as one round trip inside one implicit
 * transaction, so the reads cost one hop and cannot interleave with a
 * control-plane write that would let the chain be read half-updated.
 *
 * The policy leg is ONE statement with an OR-ed `(scope_type, scope_id)`
 * predicate rather than four, because that pair is `UNIQUE` and indexed.
 *
 * EVERY failure is 503, never "no policies": a source that answered
 * `{ ok: true, lookup: () => undefined }` on a database error would turn an
 * outage into UNLIMITED traffic for every caller.
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

      // A credential with no scope chain at all cannot be governed by any
      // policy row, so the round trip is skipped rather than issued with an
      // empty predicate (which would scan the table).
      if (scopes.length === 0) return { ok: true, lookup: () => undefined };

      const predicate = scopes.map(() => "(scope_type = ? AND scope_id = ?)").join(" OR ");
      const statements = [
        db
          .prepare(`SELECT ${QUOTA_POLICY_COLUMNS} FROM quota_policies WHERE ${predicate}`)
          .bind(...scopes.flat()),
      ];
      if (tenantId !== undefined) {
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

/**
 * The {@link QuotaPolicySource} the request path gets.
 *
 * D1 whenever the control database is bound, the dev var otherwise — the SAME
 * durable-first ordering `resolveDeps` uses for the two credential authorities,
 * and for the same reason: a deployment that provisions `quota_policies` rows
 * must not have them silently widened by a leftover dev var. One source of
 * truth per deployment, chosen by which binding exists.
 */
export function quotaPolicySourceFromEnv(env: QuotaBindings): QuotaPolicySource {
  const db = d1Binding(env.CONTROL_DB);
  return db === undefined ? quotaPolicySourceFromVars(env) : d1QuotaPolicySource(db);
}

// ---------------------------------------------------------------------------
// Spend + prepaid wallet — `finalize_auth` steps 2 and 3
// ---------------------------------------------------------------------------

/**
 * The BALANCE half: what has already been spent, and what is left in the
 * prepaid wallet.
 *
 * {@link QuotaPolicySource} answers "what is this caller allowed"; this answers
 * "how much of it is gone". They are separate ports because they read separate
 * DATABASES — policies live in the CONTROL database, spend lives in the TENANT
 * database (`usage_monthly_rollups`, `wallets`, `wallet_reservations`).
 *
 * Both readings are RESULT types, never bare numbers: Rust maps an `Err` from
 * either lookup to `503 quota_resolution_unavailable`, NOT to "0 spent" / "no
 * wallet". A source that swallowed a database outage into `0` would hand every
 * over-budget tenant unlimited spend for the duration of the outage.
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
   * `null` is load-bearing: the prepaid wallet is OPT-IN per tenant, so "no
   * row" must be distinguishable from "a row at zero". A source that reported
   * `0` for an absent wallet would refuse every tenant that has not adopted
   * prepaid billing.
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
 * recorded spend, and `0` is the TRUE reading (the same value the D1 source
 * returns for a scope with no rollup row). Likewise `null` — no wallet table
 * means no tenant has adopted prepaid billing, which is the case Rust never
 * denies. Both are the Rust answer for an empty store, so binding the database
 * can only ever TIGHTEN admission, never loosen it.
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
   * The TENANT database (`sql/d1-ts/tenant/`). The SAME binding `d1ApiKeyPort`
   * already reads for `api_keys` — so the budget and wallet gates need no new
   * database either.
   */
  readonly DB?: D1Database | undefined;
}

/** `usage_monthly_rollups` is UNIQUE on `(period_month, scope_type, scope_id)`. */
const MONTHLY_SPEND_SQL =
  "SELECT cost_usd FROM usage_monthly_rollups " +
  "WHERE period_month = ? AND scope_type = ? AND scope_id = ?";

const WALLET_BALANCE_SQL = "SELECT balance_credits FROM wallets WHERE tenant_id = ?";

/**
 * The live holds — the port of Rust's
 * `cluster_counters.reserved_wallet_credits(tenant_id)`.
 *
 * EXPIRED holds are excluded so a crashed request cannot strand credits
 * forever: the expiry IS the release that JS has no `Drop` for.
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
        return {
          ok: true,
          availableCredits: Number(walletRow.balance_credits ?? 0) - Number(heldRow?.held ?? 0),
        };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `cloudflare d1: wallet balance lookup failed: ${detail}` };
      }
    },
  };
}

/** D1 whenever the tenant database is bound, {@link NO_SPEND_SOURCE} otherwise. */
export function spendSourceFromEnv(env: SpendBindings): SpendSource {
  const db = d1Binding(env.DB);
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
 * arm, reached when a budget has no recorded scope (it came from the plan FLOOR
 * rather than from a policy row). `null` means the request carries no
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
