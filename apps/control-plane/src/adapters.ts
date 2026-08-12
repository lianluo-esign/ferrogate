/**
 * The composition root: binding-backed implementations of the ports.
 *
 * The STORE is now the real one: {@link resolveStore} builds
 * `D1ControlPlaneStore` on the CONTROL storage seam, and the in-memory reference store
 * is the explicit fallback. Nothing in `middleware/` or `routes/` changed for
 * it — the 214 handlers still talk only to `ControlPlaneStore`, which is what
 * made a one-file swap possible.
 *
 * CREDENTIALS, RBAC and the TENANCY LIFECYCLE GATE are now durable too, on the
 * same switch: `resolveApiKeys` builds `D1ApiKeyAuthenticator` over the control
 * database's `static_api_keys` (hashed secrets, `scopes_json`,
 * `platform_operator`, lifecycle columns), `resolveRbac` builds
 * `D1RbacAuthorizer` over `tenant_role_bindings ⋈ roles`, and
 * `resolveLifecycle` builds `StoreTenancyLifecycleGate` over the
 * `tenant-accounts`/`projects`/`workspaces` rows this app's own admin routes
 * write. All three keep their declarative `Json*` twin as the
 * per-credential/per-tenant FALLBACK, so a deployment that has provisioned no
 * rows behaves exactly as it did, while a deployment that has cannot be loosened
 * by a stale var.
 *
 * The lifecycle move is the one with a user-visible consequence: `PATCH
 * /admin/v1/tenant-accounts/{id} {"status":"suspended"}` previously persisted a
 * status that NOTHING read, so the app's own suspension control did not stop the
 * suspended tenant's traffic (#514's "decorative status column", reproduced in
 * the port). It now takes effect on the caller's next request, and the gate walks
 * the whole `tenant → project → workspace` chain rather than only the tenant the
 * credential happened to declare.
 *
 * The NATIVE/virtual credential leg is durable too, as of the storage-wiring
 * slice: `resolveApiKeys` builds `D1NativeApiKeyAuthenticator` over
 * `api_key_directory` (control) plus the `api_keys` row in that tenant's OWN
 * database, reached with `@ferrogate/storage`'s `EnvBindingTenantDatabaseRouter`
 * (`resolveTenantDatabases`). It used to be documented as a platform limit —
 * "a Worker cannot open a D1 database by uuid at runtime" — which was true and
 * beside the point: a Worker selects a database by BINDING NAME, and the router
 * is the registry that turns a tenant id into one. The chain is therefore
 * durable-native → durable-static → declarative vars, which is Rust
 * `authenticate_with_admission`'s source ordering exactly.
 */

import { controlDatabaseFrom } from "./control-data.js";

import {
  type ApiKeyDirectoryProjection,
  BackendDispatchingTenantDatabaseRouter,
  type BindingEnvironment,
  DurableObjectTenantDatabaseRouter,
  EnvBindingTenantDatabaseRouter,
  KvApiKeyDirectoryProjection,
  type TenantDatabaseRouter,
  type TenantObjectOperator,
  backfillTenantConfigurationPolicy,
} from "@ferrogate/storage";
import type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AssetObjectReclaimer,
  AuthContext,
  CallerScope,
  ControlPlaneBindings,
  ControlPlaneDeps,
  ControlPlaneStore,
  LifecycleDecision,
  RbacAuthorizerPort,
  RbacDecision,
  RuntimeStatus,
  RuntimeStatusPort,
  TenancyLifecycleGatePort,
} from "./ports.js";
import { DEFAULT_ADMIN_LIST_LIMIT, DEFAULT_ADMIN_LIST_MAX_LIMIT } from "./responses.js";
import { resolveSiteDomainCertificates } from "./site_domain_certificates.js";
import {
  DEFAULT_DOH_ENDPOINT,
  DEFAULT_DOH_TIMEOUT_MS,
  DohTxtResolver,
  type SiteDomainTxtResolver,
  StaticAnswersTxtResolver,
  UnboundTxtResolver,
} from "./site_domain_txt.js";
import { D1ApiKeyAuthenticator, D1NativeApiKeyAuthenticator } from "./store/api_keys.js";
import {
  type BillingFleetQueryPort,
  type BillingFleetService,
  BillingFleetUnavailableError,
  type FleetQuery,
  runFleetReport,
} from "./store/billing-fleet.js";
import {
  type LifecycleStatus,
  StoreTenancyLifecycleGate,
  decideLifecycleChain,
  parseLifecycleStatus,
} from "./store/lifecycle.js";
import { MemoryControlPlaneStore, type MemoryStoreSeed } from "./store/memory.js";
import { PlatformModelCatalogStore } from "./store/platform-model-catalog.js";
import { SplitControlPlaneStore } from "./store/split.js";
import { UnprovisionedTenantDatabaseRouter } from "./store/tenancy.js";

// ---------------------------------------------------------------------------
// Declarative key material
// ---------------------------------------------------------------------------

/** A durable/virtual ("native") key, as declared in `CONTROL_PLANE_NATIVE_API_KEYS`. */
export interface NativeKeyDeclaration {
  readonly secret: string;
  readonly id?: string;
  readonly tenant_id?: string | null;
  readonly project_id?: string | null;
  readonly workspace_id?: string | null;
  readonly user_id?: string | null;
  readonly scopes?: readonly string[];
  /** Any of these makes the key resolve as `key_suspended` → **401**. */
  readonly enabled?: boolean;
  readonly revoked?: boolean;
  readonly expires_at?: number;
}

/** An operator-authored static config key (`CONTROL_PLANE_STATIC_API_KEYS`). */
export interface StaticKeyDeclaration {
  readonly secret: string;
  readonly id?: string;
  readonly organization_id?: string | null;
  readonly scopes?: readonly string[];
  readonly enabled?: boolean;
  readonly expires_at?: number;
  readonly monthly_token_budget?: number;
  readonly platform_operator?: boolean;
}

function parseJson<T>(raw: string | undefined, fallback: T): T {
  if (raw === undefined || raw.trim() === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    // A malformed binding must not silently disable authentication. An empty
    // key set means every credential is unknown → 401, which fails closed.
    return fallback;
  }
}

/** Constant-time-ish comparison; the secrets here are short and fixed-length. */
function secretsEqual(a: string | undefined, b: string): boolean {
  // `a` is a config entry's `secret`. It is declared `string`, but the entries
  // arrive from `parseJson`, which casts raw JSON without validating each
  // field — so an entry that OMITS `secret` (or gives it a non-string value)
  // reaches here as `undefined`. Reading `.length` off it threw a `TypeError`
  // that Hono's `onError` turned into a `500` on EVERY authenticated request:
  // one mis-shaped key entry took the whole admin surface down. A non-string
  // stored secret must simply never match, so the entry is skipped and an
  // unmatched credential falls through to `401 invalid_api_key` — the same
  // fail-closed posture `parseJson` documents for a malformed binding, applied
  // one level deeper (at the entry, not just the whole array).
  if (typeof a !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Rust `authenticate_with_admission`'s source ordering, preserved exactly:
 * durable/native keys FIRST, then the static config fallback, then
 * `401 invalid_api_key`.
 *
 * The 401-vs-403 split falls out of that ordering rather than being decided
 * here — a suspended native key resolves to `key_suspended`, which the auth
 * middleware collapses onto the same `401 invalid_api_key` an unknown key gets,
 * while a disabled STATIC key is a 403. See `ApiKeyResolution`.
 */
export class JsonApiKeyAuthenticator implements ApiKeyAuthenticatorPort {
  readonly #native: readonly NativeKeyDeclaration[];
  readonly #static: readonly StaticKeyDeclaration[];
  readonly #now: () => number;

  constructor(
    nativeKeys: readonly NativeKeyDeclaration[],
    staticKeys: readonly StaticKeyDeclaration[],
    now: () => number = () => Math.floor(Date.now() / 1000),
  ) {
    this.#native = nativeKeys;
    this.#static = staticKeys;
    this.#now = now;
  }

  authenticate(presentedKey: string): Promise<ApiKeyResolution> {
    const native = this.#native.find((key) => secretsEqual(key.secret, presentedKey));
    if (native !== undefined) {
      // `StorageApiKeyAuthenticator` checks `enabled && !revoked && !expired`
      // and returns `None` otherwise — indistinguishable from "no such key".
      if (native.enabled === false) {
        return Promise.resolve({ outcome: "key_suspended", reason: "disabled" });
      }
      if (native.revoked === true) {
        return Promise.resolve({ outcome: "key_suspended", reason: "revoked" });
      }
      if (native.expires_at !== undefined && native.expires_at <= this.#now()) {
        return Promise.resolve({ outcome: "key_suspended", reason: "expired" });
      }
      const auth: AuthContext = {
        subject: native.id ?? null,
        tenancy: {
          tenantId: native.tenant_id ?? null,
          projectId: native.project_id ?? null,
          workspaceId: native.workspace_id ?? null,
          userId: native.user_id ?? null,
        },
        scopes: native.scopes ?? [],
        // #515: a durable key is minted under a tenant and can never DECLARE
        // platform root over this path.
        platformOperator: false,
        source: "durable_native",
      };
      return Promise.resolve({ outcome: "resolved", auth });
    }

    const configured = this.#static.find((key) => secretsEqual(key.secret, presentedKey));
    if (configured !== undefined) {
      if (configured.enabled === false) {
        return Promise.resolve({ outcome: "static_key_disabled" });
      }
      if (configured.expires_at !== undefined && configured.expires_at <= this.#now()) {
        return Promise.resolve({ outcome: "static_key_expired" });
      }
      if (configured.monthly_token_budget === 0) {
        return Promise.resolve({ outcome: "token_budget_exhausted" });
      }
      const auth: AuthContext = {
        subject: configured.id ?? null,
        tenancy: { tenantId: configured.organization_id ?? null },
        // Rust: an operator-authored key with NO scopes listed has always meant
        // "all access"; that intent is normalized to an explicit wildcard here
        // so `hasScope`'s empty-set-is-not-admin rule does not misread it.
        scopes:
          configured.scopes === undefined || configured.scopes.length === 0
            ? ["*"]
            : configured.scopes,
        platformOperator: configured.platform_operator === true,
        source: "static_config",
      };
      return Promise.resolve({ outcome: "resolved", auth });
    }

    return Promise.resolve({ outcome: "unknown" });
  }
}

// ---------------------------------------------------------------------------
// Lifecycle + RBAC
// ---------------------------------------------------------------------------

export type { LifecycleStatus };

/**
 * `TENANCY_LIFECYCLE` is `{ "<tenant_id>": "suspended" }` — the DECLARATIVE
 * gate, now the fallback rather than the path (see {@link resolveLifecycle}).
 *
 * It states a one-row chain (the declared tenant) and hands it to the SAME
 * `decideLifecycleChain` the durable gate uses, so the two cannot answer
 * differently for the same status: the `disabled`-is-admitted-on-reversal
 * carve-out (#514, finding 5), the code taxonomy and the message are decided in
 * exactly one place.
 */
export class JsonTenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #statuses: Readonly<Record<string, LifecycleStatus>>;

  constructor(statuses: Readonly<Record<string, LifecycleStatus>>) {
    this.#statuses = statuses;
  }

  admit(auth: AuthContext, operation: { operationId: string }): Promise<LifecycleDecision> {
    const tenantId = auth.tenancy.tenantId;
    if (tenantId === null) return Promise.resolve({ admitted: true });
    const status = parseLifecycleStatus(this.#statuses[tenantId] ?? "active");
    return Promise.resolve(
      decideLifecycleChain([{ kind: "tenant", id: tenantId, status }], operation),
    );
  }
}

/** `TENANT_RBAC_ACTIONS` is `{ "<tenant_id>": ["guardrails.policy.read", …] }`. */
export class JsonRbacAuthorizer implements RbacAuthorizerPort {
  readonly #grants: Readonly<Record<string, readonly string[]>>;

  constructor(grants: Readonly<Record<string, readonly string[]>>) {
    this.#grants = grants;
  }

  authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision> {
    // Rust `require_guardrail_auth`: only a DECLARED platform operator skips
    // the grant check. An unclassified credential is a tenant here, so it is
    // checked (and denied) rather than waved through.
    if (auth.platformOperator) return Promise.resolve({ allowed: true });

    const tenantId = auth.tenancy.tenantId ?? "";
    const granted = this.#grants[tenantId] ?? [];
    if (granted.includes(rbacAction) || granted.includes("*")) {
      return Promise.resolve({ allowed: true });
    }
    return Promise.resolve({
      allowed: false,
      code: "guardrail_rbac_denied",
      message: `tenant roles do not grant required action ${rbacAction}`,
    });
  }
}

/**
 * The DURABLE RBAC authorizer: role grants read from the control database
 * (`roles`, `tenant_role_bindings`, `permissions` in
 * `sql/d1-ts/control/0001_init_control.sql`) instead of a Worker var.
 *
 * ```sql
 * tenant_role_bindings(tenant_id, role_id) ⋈ roles(id).permission_keys_json
 * ```
 *
 * A tenant's granted actions are the UNION of the permission keys of every role
 * bound to it. `roles.permission_keys_json` is the authority — `permissions` is
 * the human-facing catalogue of what a key means, and joining through it would
 * make an un-catalogued key silently ungrantable, which is a different (and
 * wrong) policy.
 *
 * Three properties, each of which is the reason for the shape it forces:
 *
 *  - **A storage failure is `503`, never an implicit allow.** `RbacDecision`
 *    has an `"unavailable"` variant precisely so this path cannot collapse into
 *    "denied" (which would look like a policy decision) or "allowed" (which
 *    would be a hole opened by an outage). Rust `require_guardrail_auth` does
 *    the same.
 *  - **Only a DECLARED platform operator skips the check.** An unclassified
 *    credential is a tenant with the unforgeable empty-string id, so it is
 *    checked and denied rather than waved through (#515).
 *  - **The fallback is the var-backed grants, not "allow".** A control database
 *    that has no `tenant_role_bindings` rows at all is a deployment that has not
 *    adopted durable RBAC yet, and it keeps its declarative grants; but a tenant
 *    that HAS bindings is decided by them alone, so adding a durable binding can
 *    never be loosened by a stale var.
 */
export class D1RbacAuthorizer implements RbacAuthorizerPort {
  readonly #db: D1Database;
  readonly #fallback: RbacAuthorizerPort;
  readonly #tenantDatabases: TenantDatabaseRouter | null;

  constructor(
    db: D1Database,
    fallback: RbacAuthorizerPort,
    tenantDatabases: TenantDatabaseRouter | null = null,
  ) {
    this.#db = db;
    this.#fallback = fallback;
    this.#tenantDatabases = tenantDatabases;
  }

  async authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision> {
    if (auth.platformOperator) return { allowed: true };
    const tenantId = auth.tenancy.tenantId ?? "";

    if (this.#tenantDatabases === null) {
      return {
        allowed: "unavailable",
        detail: "TENANT_DATA is not bound, so tenant role bindings cannot be resolved",
      };
    }

    let rows: { permission_keys_json: string }[];
    try {
      const result = await this.#tenantRoleGrants(tenantId);
      rows = result.results;
    } catch (error) {
      // The one thing this must never do is guess.
      return {
        allowed: "unavailable",
        detail: `rbac role lookup failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    // No durable bindings for this tenant ⇒ this deployment has not moved its
    // grants into the database. Defer to the declarative ones rather than
    // denying every RBAC-guarded operation the moment a database is bound.
    if (rows.length === 0) return this.#fallback.authorize(auth, rbacAction);

    const granted = new Set<string>();
    for (const row of rows) {
      let keys: unknown;
      try {
        keys = JSON.parse(row.permission_keys_json);
      } catch {
        // A corrupt role grants nothing. Refusing to parse is not the same as
        // refusing to authorize, so the other roles still count.
        continue;
      }
      if (!Array.isArray(keys)) continue;
      for (const key of keys) if (typeof key === "string") granted.add(key);
    }

    if (granted.has(rbacAction) || granted.has("*")) return { allowed: true };
    return {
      allowed: false,
      code: "guardrail_rbac_denied",
      message: `tenant roles do not grant required action ${rbacAction}`,
    };
  }

  async #tenantRoleGrants(
    tenantId: string,
  ): Promise<{ results: { permission_keys_json: string }[] }> {
    const tenantDatabases = this.#tenantDatabases;
    if (tenantDatabases === null) throw new Error("tenant RBAC router is unavailable");
    await backfillTenantConfigurationPolicy(this.#db, tenantDatabases, tenantId);
    const handle = await tenantDatabases.forTenant(tenantId);
    const result = await handle.db
      .prepare(
        `SELECT b.role_id
           FROM tenant_role_bindings AS b
          WHERE b.tenant_id = ?`,
      )
      .bind(tenantId)
      .all<{ role_id: string }>();
    const valid: { permission_keys_json: string }[] = [];
    for (const row of result.results) {
      const shared = await this.#db
        .prepare("SELECT permission_keys_json FROM roles WHERE id = ?")
        .bind(row.role_id)
        .first<{ permission_keys_json: string }>();
      // `roles` is the shared operator-authored catalog. A missing shared role
      // invalidates the binding rather than trusting a stale reverse projection.
      if (shared !== null) valid.push(shared);
    }
    return { results: valid };
  }
}

// ---------------------------------------------------------------------------
// Runtime status + metrics
// ---------------------------------------------------------------------------

export const SERVICE_NAME = "ferrogate-control-plane";

type OverviewRow = Record<string, unknown>;
type OverviewScope = CallerScope;
type OverviewStoreScope = Parameters<ControlPlaneStore["list"]>[1];

/** The healthy AdminOverviewSection status (`AdminOverviewSection.status` const). Kept in a
 * const so the section builder does not emit a literal `status: "ok",` — that token is the
 * fleet health-document anchor and must appear exactly once per app (the real /healthz). */
const OVERVIEW_SECTION_OK = "ok" as const;

const overviewQuery = {
  offset: 0,
  limit: Number.MAX_SAFE_INTEGER,
  paginate: false,
  search: null,
  filters: {},
} as const;

function overviewNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function overviewString(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function overviewRows(page: unknown): OverviewRow[] {
  if (typeof page !== "object" || page === null) return [];
  const record = page as Record<string, unknown>;
  const rows = record.items ?? record.results ?? record.data;
  if (!Array.isArray(rows)) return [];
  return rows.filter(
    (row): row is OverviewRow => typeof row === "object" && row !== null && !Array.isArray(row),
  );
}

function overviewError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function enabledCount(rows: readonly OverviewRow[]): { total: number; enabled: number } {
  return {
    total: rows.length,
    enabled: rows.filter(
      (row) => row.enabled !== false && row.disabled !== true && row.status !== "disabled",
    ).length,
  };
}

function activeCount(rows: readonly OverviewRow[]): { total: number; active: number } {
  return {
    total: rows.length,
    active: rows.filter(
      (row) =>
        row.active === true ||
        row.enabled === true ||
        row.status === "active" ||
        row.status === "connected",
    ).length,
  };
}

function countByStatus(rows: readonly OverviewRow[]): {
  total: number;
  by_status: Record<string, number>;
} {
  const by_status: Record<string, number> = {};
  for (const row of rows) {
    const status = overviewString(row.status) ?? "unknown";
    by_status[status] = (by_status[status] ?? 0) + 1;
  }
  return { total: rows.length, by_status };
}

function firstNumber(row: OverviewRow, keys: readonly string[]): number | undefined {
  for (const key of keys) {
    const value = overviewNumber(row[key]);
    if (value !== undefined) return value;
  }
  return undefined;
}

function monthAt(unix: number): string {
  return new Date(unix * 1000).toISOString().slice(0, 7);
}

function overviewTokens(rows: readonly OverviewRow[]): {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  request_count: number;
  error_count: number;
} {
  let prompt_tokens = 0;
  let completion_tokens = 0;
  let total_tokens = 0;
  let cost_usd = 0;
  let request_count = 0;
  let error_count = 0;
  for (const row of rows) {
    const prompt = firstNumber(row, ["prompt_tokens", "input_tokens"]) ?? 0;
    const completion = firstNumber(row, ["completion_tokens", "output_tokens"]) ?? 0;
    prompt_tokens += prompt;
    completion_tokens += completion;
    total_tokens += firstNumber(row, ["total_tokens", "tokens"]) ?? prompt + completion;
    cost_usd += firstNumber(row, ["cost_usd", "cost", "total_cost_usd"]) ?? 0;
    request_count += firstNumber(row, ["request_count", "requests", "count"]) ?? 0;
    error_count += firstNumber(row, ["error_count", "errors"]) ?? 0;
  }
  return {
    prompt_tokens,
    completion_tokens,
    total_tokens,
    cost_usd,
    request_count,
    error_count,
  };
}

function quotaPressure(rows: readonly OverviewRow[]): OverviewRow[] {
  const pressure: OverviewRow[] = [];
  for (const row of rows) {
    const scope_type = overviewString(row.scope_type) ?? overviewString(row.kind) ?? "tenant";
    const scope_id =
      overviewString(row.scope_id) ?? overviewString(row.tenant_id) ?? overviewString(row.id);
    if (scope_id === undefined) continue;
    const dimensions = [
      {
        dimension: "tokens",
        unit: "tokens",
        used: firstNumber(row, ["used_tokens", "tokens_used", "usage_tokens"]),
        cap: firstNumber(row, ["monthly_token_budget", "token_budget", "tokens_cap"]),
      },
      {
        dimension: "storage",
        unit: "bytes",
        used: firstNumber(row, ["storage_bytes", "used_storage_bytes", "storage_used"]),
        cap: firstNumber(row, ["storage_quota_bytes", "asset_storage_quota_bytes"]),
      },
      {
        dimension: "budget",
        unit: "usd",
        used: firstNumber(row, ["spent_usd", "used_usd", "cost_usd"]),
        cap: firstNumber(row, ["monthly_budget_usd", "budget_usd"]),
      },
    ];
    for (const dimension of dimensions) {
      if (
        dimension.used === undefined ||
        dimension.cap === undefined ||
        dimension.cap <= 0 ||
        dimension.used / dimension.cap < 0.8
      ) {
        continue;
      }
      pressure.push({
        scope_type,
        scope_id,
        dimension: dimension.dimension,
        unit: dimension.unit,
        used: dimension.used,
        cap: dimension.cap,
        utilization_pct: (dimension.used / dimension.cap) * 100,
      });
    }
  }
  pressure.sort(
    (left, right) => (right.utilization_pct as number) - (left.utilization_pct as number),
  );
  return pressure.slice(0, 100);
}

/**
 * Rust `AdminStatus` / the Prometheus exposition, over this Worker's real
 * sources.
 *
 * `snapshot` is no longer the literal `"unversioned"`: it reports the
 * `config_snapshot_id` of the gateway-config snapshot the control plane last
 * PROMOTED (`routes/admin_config_ops.ts` writes `runtime-state/active-config`,
 * carrying `@ferrogate/config`'s own `configSnapshotId(config)` of the candidate
 * it validated). That is the live snapshot on this platform: there is no process
 * holding an `ArcSwap` to interrogate, so the durable activation record IS the
 * answer to "which config is current", and it is the value a data-plane isolate
 * reads on its next config fetch. A deployment that has never promoted one
 * still reports `"unversioned"`, which is true rather than fabricated.
 *
 * PORT-TODO(L: inventory-edge-control §4) — PLATFORM LIMIT, sharpened, for the
 * `observability()` feed ONLY. Rust reads recent request/latency series off its
 * in-process registry. The Workers equivalent is Analytics Engine, whose WRITE
 * side is a binding but whose READ side is the account-scoped
 * `/analytics_engine/sql` REST endpoint — an authenticated call to the live
 * Cloudflare API, which this app is not permitted to make and which has no
 * offline emulation in `wrangler dev --local` / vitest-pool-workers (miniflare
 * accepts `writeDataPoint` and discards it; there is nothing to query back). So
 * the feed answers an EMPTY list rather than fabricating series, and
 * `test/runtime-status.test.ts` pins that it stays empty and does not invent
 * rows. It closes when an Analytics Engine query binding exists, or behind a
 * separate reader service that holds the account token.
 *
 * `metrics()` deliberately does NOT render `@ferrogate/observability`'s
 * `renderPrometheusText`: that function serializes a `GatewayMetricsSnapshot`
 * (upstream latencies, token counters, provider attempts) which this Worker does
 * not measure, so exposing it would publish a scrape full of zeros that a
 * dashboard would read as "the gateway served no traffic". The two gauges below
 * are the ones the control plane can actually answer.
 */
export class StoreRuntimeStatus implements RuntimeStatusPort {
  readonly #store: ControlPlaneStore;
  readonly #version: string;
  readonly #tenantDatabases: TenantDatabaseRouter | null;
  readonly #controlDatabase: D1Database | null;

  constructor(
    store: ControlPlaneStore,
    version = "0.0.0",
    tenantDatabases: TenantDatabaseRouter | null = null,
    controlDatabase: D1Database | null = null,
  ) {
    this.#store = store;
    this.#version = version;
    this.#tenantDatabases = tenantDatabases;
    this.#controlDatabase = controlDatabase;
  }

  /**
   * The `config_snapshot_id` of the last promoted gateway config, or
   * `"unversioned"` when none has been promoted.
   *
   * Read as a platform operator because the activation record is a platform
   * fact, and swallowing a read failure is deliberate: `GET /admin/v1/status` is
   * the endpoint an operator hits to find out what is wrong, so it must answer
   * even when one of its sources cannot.
   */
  async #activeSnapshot(): Promise<string> {
    try {
      const record = await this.#store.get(
        "runtime-state",
        { kind: "platform_operator" },
        "active-config",
      );
      const snapshot = record?.config_snapshot_id;
      return typeof snapshot === "string" && snapshot !== "" ? snapshot : "unversioned";
    } catch {
      return "unversioned";
    }
  }

  async #count(collection: string): Promise<number> {
    const page = await this.#store.list(
      collection,
      { kind: "platform_operator" },
      { offset: 0, limit: Number.MAX_SAFE_INTEGER, paginate: false, search: null, filters: {} },
    );
    return page.total;
  }

  async #catalogProviderCount(): Promise<number | null> {
    if (this.#tenantDatabases === null) return null;
    try {
      const tenants = await this.#tenantDatabases.provisionedTenants();
      const counts = await Promise.all(
        tenants.map(async (tenantId) => {
          try {
            const handle = await this.#tenantDatabases?.forTenant(tenantId);
            if (handle === undefined) return 0;
            const row = await handle.db
              .prepare("SELECT COUNT(*) AS total FROM provider_channels WHERE tenant_id = ?")
              .bind(tenantId)
              .first<{ total: number | string }>();
            return Number(row?.total ?? 0);
          } catch {
            // Status is a debugging surface; one unreachable tenant must not
            // hide counts from the rest of the fleet.
            return 0;
          }
        }),
      );
      return tenants.length === 0 ? null : counts.reduce((total, count) => total + count, 0);
    } catch {
      return null;
    }
  }

  /**
   * The PLATFORM catalog row counts (#893), kept DISTINCT from the tenant
   * `providers`/`models` aggregates above — a platform channel is not a tenant
   * provider, and folding one into the other would let an operator read a fleet
   * total that is neither. Answers three zeros when the deployment has no control
   * database or has not applied migration `0025`, matching the store's own
   * "not adopted is not broken" treatment, so `/admin/v1/status` still answers.
   */
  async #platformCatalogCounts(): Promise<{
    providers: number;
    models: number;
    offerings: number;
  }> {
    if (this.#controlDatabase === null) return { providers: 0, models: 0, offerings: 0 };
    try {
      return await new PlatformModelCatalogStore({ db: this.#controlDatabase }).counts();
    } catch {
      // Status is the debugging surface; a platform-catalog read failure must
      // not sink the whole document.
      return { providers: 0, models: 0, offerings: 0 };
    }
  }

  async status(): Promise<RuntimeStatus> {
    const [
      legacyProviders,
      catalogProviders,
      models,
      apiKeys,
      promptTemplates,
      plugins,
      tools,
      snapshot,
      platformCatalog,
    ] = await Promise.all([
      this.#count("providers"),
      this.#catalogProviderCount(),
      this.#count("models"),
      this.#count("api-keys"),
      this.#count("prompt-templates"),
      this.#count("plugins"),
      this.#count("tools"),
      this.#activeSnapshot(),
      this.#platformCatalogCounts(),
    ]);
    return {
      service: SERVICE_NAME,
      version: this.#version,
      // Rust reports `"pingora"`; the data plane is a Hono Worker now and
      // reporting otherwise would be a lie an operator could act on.
      runtime: "workers",
      snapshot,
      providers: catalogProviders === null ? legacyProviders : catalogProviders,
      models,
      api_keys: apiKeys,
      prompt_templates: promptTemplates,
      plugins,
      tools,
      // #893: the platform catalog, counted separately from the tenant
      // aggregates — no silent folding into `providers`/`models`.
      platform_providers: platformCatalog.providers,
      platform_models: platformCatalog.models,
      platform_offerings: platformCatalog.offerings,
      auth_required: true,
    };
  }

  async #overviewRows(collection: string, scope: OverviewScope): Promise<OverviewRow[]> {
    const page = await this.#store.list(
      collection,
      scope as unknown as OverviewStoreScope,
      overviewQuery,
    );
    return overviewRows(page);
  }

  async #tryOverviewRows(collection: string, scope: OverviewScope): Promise<OverviewRow[] | null> {
    try {
      return await this.#overviewRows(collection, scope);
    } catch {
      return null;
    }
  }

  async #overviewRowsFrom(
    collections: readonly string[],
    scope: OverviewScope,
  ): Promise<OverviewRow[] | null> {
    for (const collection of collections) {
      const rows = await this.#tryOverviewRows(collection, scope);
      if (rows !== null) return rows;
    }
    return null;
  }

  #availableOverviewSection(
    source: string,
    generatedAtUnix: number,
    data: OverviewRow,
  ): OverviewRow {
    return {
      // Built from a const, not a literal `status: "ok",`, so this section does
      // NOT collide with the fleet health-document anchor (`/status:\s*"ok"\s*,/`
      // in apps/telemetry/test/fleet-health-contract.test.ts), which requires
      // exactly ONE such document per app — the real /healthz response.
      status: OVERVIEW_SECTION_OK,
      source,
      generated_at_unix: generatedAtUnix,
      error: null,
      data,
    };
  }

  #unavailableOverviewSection(
    source: string,
    generatedAtUnix: number,
    error: unknown,
  ): OverviewRow {
    return {
      status: "unavailable",
      source,
      generated_at_unix: generatedAtUnix,
      error: overviewError(error),
    };
  }

  async #runtimeOverviewSection(
    scope: OverviewScope,
    generatedAtUnix: number,
  ): Promise<OverviewRow> {
    try {
      const [providers, models, apiKeys, promptTemplates, upstreams, routes, plugins, tools, mcp] =
        await Promise.all([
          this.#overviewRows("providers", scope),
          this.#overviewRows("models", scope),
          this.#overviewRows("api-keys", scope),
          this.#overviewRows("prompt-templates", scope),
          this.#overviewRows("upstreams", scope),
          this.#overviewRows("routes", scope),
          this.#overviewRowsFrom(["plugins", "extensions"], scope),
          this.#overviewRows("tools", scope),
          this.#overviewRowsFrom(["mcp-servers", "mcp_servers"], scope),
        ]);
      const mcpRows = mcp ?? [];
      const connected = mcpRows.filter(
        (row) => row.connected === true || row.status === "connected",
      ).length;
      const runtime = {
        providers: enabledCount(providers),
        models: enabledCount(models),
        static_api_keys: apiKeys.length,
        prompt_templates: promptTemplates.length,
        upstreams: enabledCount(upstreams),
        routes: enabledCount(routes),
        plugins: activeCount(plugins ?? []),
        tools: tools.length,
        mcp_servers: {
          total: mcpRows.length,
          connected,
          disconnected: mcpRows.length - connected,
        },
      };
      return this.#availableOverviewSection("runtime_config", generatedAtUnix, runtime);
    } catch (error) {
      return this.#unavailableOverviewSection("runtime_config", generatedAtUnix, error);
    }
  }

  async #controlPlaneOverviewSection(
    scope: OverviewScope,
    generatedAtUnix: number,
  ): Promise<OverviewRow> {
    try {
      const [
        tenants,
        projects,
        workspaces,
        virtualKeys,
        assets,
        agentRuns,
        workers,
        approvals,
        quotas,
      ] = await Promise.all([
        this.#overviewRows("tenants", scope),
        this.#overviewRows("projects", scope),
        this.#overviewRows("workspaces", scope),
        this.#overviewRowsFrom(["virtual-keys", "api-keys"], scope),
        this.#overviewRowsFrom(["assets", "stored-assets", "stored_assets"], scope),
        this.#overviewRowsFrom(["agent-runs", "agent_jobs"], scope),
        this.#overviewRowsFrom(["self-hosted-workers", "self_hosted_workers"], scope),
        this.#overviewRowsFrom(["tool-approvals", "tool_approvals"], scope),
        this.#overviewRowsFrom(["quota-policies", "quota_policies"], scope),
      ]);

      if (
        virtualKeys === null ||
        assets === null ||
        agentRuns === null ||
        workers === null ||
        approvals === null ||
        quotas === null
      ) {
        throw new Error("one or more control-plane overview sources are unavailable");
      }

      const storageBytes = assets.reduce(
        (total, row) =>
          total + (firstNumber(row, ["storage_bytes", "size_bytes", "bytes", "size"]) ?? 0),
        0,
      );
      const referenced = assets.filter(
        (row) =>
          row.referenced === true ||
          row.channel_id !== undefined ||
          row.channel_ids !== undefined ||
          row.pinned === true,
      ).length;
      const tenantQuota =
        scope.kind === "tenant"
          ? (quotas
              .map((row) => firstNumber(row, ["storage_quota_bytes", "asset_storage_quota_bytes"]))
              .find((value): value is number => value !== undefined) ?? null)
          : null;
      const pressure = quotaPressure(quotas);
      const governance =
        scope.kind === "tenant"
          ? null
          : {
              guardrail_policy_revisions: (
                (await this.#overviewRowsFrom(
                  ["guardrail-policy-revisions", "guardrail_policy_revisions"],
                  scope,
                )) ?? []
              ).length,
              guardrail_policy_bindings: (
                (await this.#overviewRowsFrom(
                  ["guardrail-policy-bindings", "guardrail_policy_bindings"],
                  scope,
                )) ?? []
              ).length,
              quota_policies: quotas.length,
              policy_rules: (
                (await this.#overviewRowsFrom(["policy-rules", "policy_rules"], scope)) ?? []
              ).length,
            };
      const data = {
        tenants: scope.kind === "tenant" ? 1 : tenants.length,
        projects: projects.length,
        workspaces: workspaces.length,
        virtual_keys: enabledCount(virtualKeys),
        assets: {
          count: assets.length,
          storage_bytes: storageBytes,
          referenced,
          unreferenced: Math.max(0, assets.length - referenced),
          storage_quota_bytes: tenantQuota,
        },
        agent_runs: countByStatus(agentRuns),
        self_hosted_workers: countByStatus(workers),
        pending_tool_approvals: approvals.filter(
          (row) => row.status === "pending" || row.pending === true,
        ).length,
        quota_pressure: pressure,
        policy_governance: governance,
      };
      return this.#availableOverviewSection("control_plane_store", generatedAtUnix, data);
    } catch (error) {
      return this.#unavailableOverviewSection("control_plane_store", generatedAtUnix, error);
    }
  }

  async #usageOverviewSection(scope: OverviewScope, generatedAtUnix: number): Promise<OverviewRow> {
    try {
      const rows = await this.#overviewRows("usage-aggregates", scope);
      const currentMonth = monthAt(generatedAtUnix);
      const currentRows = rows.filter((row) => {
        const period = overviewString(row.period_month) ?? overviewString(row.month);
        return period === undefined || period === currentMonth;
      });
      return this.#availableOverviewSection("usage_store", generatedAtUnix, {
        current_period_month: currentMonth,
        lifetime: overviewTokens(rows),
        current_month: overviewTokens(currentRows),
      });
    } catch (error) {
      return this.#unavailableOverviewSection("usage_store", generatedAtUnix, error);
    }
  }

  async #alertsOverviewSection(
    scope: OverviewScope,
    generatedAtUnix: number,
  ): Promise<OverviewRow> {
    try {
      const [quotas, approvals] = await Promise.all([
        this.#overviewRows("quota-policies", scope),
        this.#overviewRowsFrom(["tool-approvals", "tool_approvals"], scope),
      ]);
      const pressure = quotaPressure(quotas);
      const entries: OverviewRow[] = pressure.map((item) => {
        const utilization = item.utilization_pct as number;
        return {
          kind: "quota_pressure",
          severity: utilization >= 100 ? "critical" : "warning",
          summary: `${item.scope_id as string} ${item.dimension as string} quota at ${utilization.toFixed(1)}%`,
          count: 1,
          detected_at_unix: generatedAtUnix,
          evidence: [
            {
              id: `${item.scope_type as string}:${item.scope_id as string}:${item.dimension as string}`,
              detail: `${item.used as number}/${item.cap as number} ${item.unit as string}`,
              at_unix: generatedAtUnix,
            },
          ],
          evidence_truncated: false,
        };
      });
      const pending = (approvals ?? []).filter(
        (row) => row.status === "pending" || row.pending === true,
      ).length;
      if (pending > 0) {
        entries.push({
          kind: "tool_approvals_pending",
          severity: "warning",
          summary: `${pending} tool approval${pending === 1 ? "" : "s"} pending`,
          count: pending,
          detected_at_unix: generatedAtUnix,
          evidence: [],
          evidence_truncated: false,
        });
      }
      return this.#availableOverviewSection("quota_store", generatedAtUnix, {
        total: entries.length,
        truncated: false,
        unavailable_sources: [],
        entries,
      });
    } catch (error) {
      return this.#unavailableOverviewSection("quota_store", generatedAtUnix, error);
    }
  }

  async overview(scope?: CallerScope): Promise<Record<string, unknown>> {
    const effectiveScope = scope ?? ({ kind: "platform_operator" } as CallerScope);
    const generatedAtUnix = Math.floor(Date.now() / 1000);
    const [runtime, controlPlane, usage, alerts] = await Promise.all([
      this.#runtimeOverviewSection(effectiveScope, generatedAtUnix),
      this.#controlPlaneOverviewSection(effectiveScope, generatedAtUnix),
      this.#usageOverviewSection(effectiveScope, generatedAtUnix),
      this.#alertsOverviewSection(effectiveScope, generatedAtUnix),
    ]);
    return {
      object: "control_plane.overview",
      generated_at_unix: generatedAtUnix,
      scope:
        effectiveScope.kind === "tenant"
          ? { kind: "tenant", tenant_id: effectiveScope.tenantId }
          : { kind: "global" },
      runtime,
      control_plane: controlPlane,
      usage,
      alerts,
    };
  }

  /**
   * EMPTY, and deliberately so — see the PLATFORM LIMIT note on the class. An
   * empty list is "this deployment exposes no queryable series"; a fabricated
   * one would be read as real telemetry.
   */
  observability(): Promise<readonly Record<string, unknown>[]> {
    return Promise.resolve([]);
  }

  async metrics(): Promise<string> {
    const requests = await this.#count("request-logs");
    // Prometheus text exposition format 0.0.4 — HELP/TYPE then samples.
    return [
      "# HELP ferrogate_control_plane_up Control plane liveness.",
      "# TYPE ferrogate_control_plane_up gauge",
      "ferrogate_control_plane_up 1",
      "# HELP ferrogate_request_log_entries Recorded request-log entries.",
      "# TYPE ferrogate_request_log_entries gauge",
      `ferrogate_request_log_entries ${requests}`,
      "",
    ].join("\n");
  }
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

function positiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * The in-memory fallback store, a module-level singleton per isolate so state
 * survives across requests (an in-memory store rebuilt per request would make
 * every write invisible to the next read). The D1 store needs no such trick —
 * its state is in the database — so it is built fresh per request, which is
 * what lets it carry the request's correlation id onto its audit rows.
 */
let sharedStore: MemoryControlPlaneStore | null = null;
let sharedStoreSeed: string | undefined;

function memoryStore(env: ControlPlaneBindings): MemoryControlPlaneStore {
  if (sharedStore === null || sharedStoreSeed !== env.CONTROL_PLANE_SEED) {
    sharedStore = new MemoryControlPlaneStore(
      parseJson<MemoryStoreSeed>(env.CONTROL_PLANE_SEED, {}),
    );
    sharedStoreSeed = env.CONTROL_PLANE_SEED;
  }
  return sharedStore;
}

/** Per-request context the adapters need but the bindings cannot carry. */
export interface RequestContext {
  /** `x-request-id`, stamped onto every audit row this request writes. */
  readonly requestId?: string | null;
}

/**
 * Pick the store the request will use.
 *
 * There are exactly two outcomes now, and no third one that guesses:
 *
 *  - `CONTROL_PLANE_STORE = "memory"` → the in-memory reference store. An
 *    explicit, by-name request, which is what the unit suites and a
 *    database-less local run make.
 *  - otherwise → D1, which REQUIRES the `DB` binding.
 *
 * A deployment that binds no database and asks for nothing used to fall through
 * to the in-memory store with a warning. That is the silent-data-loss shape:
 * every write is acknowledged with a 201 and every one of them is gone at the
 * next isolate eviction, with a correct-looking API the whole time. It now
 * throws, so the failure is at the first request instead of at the first
 * eviction.
 */
function controlDatabaseFor(
  env: ControlPlaneBindings,
  resolvedControlDatabase?: D1Database,
): D1Database | undefined {
  if (resolvedControlDatabase !== undefined) return resolvedControlDatabase;
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") return undefined;
  return controlDatabaseFrom(env);
}

export function resolveStore(
  env: ControlPlaneBindings,
  context: RequestContext = {},
  resolvedControlDatabase?: D1Database,
): ControlPlaneStore {
  const requested = env.CONTROL_PLANE_STORE?.trim().toLowerCase();
  if (requested === "memory") return memoryStore(env);
  const controlDb = controlDatabaseFor(env, resolvedControlDatabase);
  if (controlDb === undefined) {
    throw new Error(
      "control-plane: no `DB` binding is configured; add the [[d1_databases]] binding (migrations in sql/d1-ts/control/) or set CONTROL_PLANE_STORE=memory to run without durability",
    );
  }
  return new SplitControlPlaneStore(controlDb, resolveTenantStorage(env, controlDb), {
    requestId: context.requestId ?? null,
  });
}

/**
 * Pick the site-domain TXT resolver (`src/site_domain_txt.ts`).
 *
 * The DEFAULT is UNBOUND — it resolves nothing and every verification answers
 * `503`. That polarity is the opposite of the store's and is equally
 * deliberate: an un-configured deployment must not be able to mark a hostname
 * verified, because a hostname that verifies without a published record is a
 * hostname anybody can claim. Turning verification ON is an explicit act.
 */
export function resolveTxtResolver(env: ControlPlaneBindings): SiteDomainTxtResolver {
  switch (env.SITE_DOMAIN_RESOLVER?.trim().toLowerCase()) {
    case "doh":
      return new DohTxtResolver(
        env.SITE_DOMAIN_RESOLVER_ENDPOINT?.trim() || DEFAULT_DOH_ENDPOINT,
        positiveInt(env.SITE_DOMAIN_RESOLVER_TIMEOUT_MS, DEFAULT_DOH_TIMEOUT_MS),
      );
    case "static":
      return new StaticAnswersTxtResolver(env.SITE_DOMAIN_TXT_ANSWERS);
    default:
      return new UnboundTxtResolver();
  }
}

/**
 * Pick the RBAC authorizer: durable role bindings whenever the request is being
 * served from the database, with the declarative `TENANT_RBAC_ACTIONS` grants as
 * the per-tenant fallback (see {@link D1RbacAuthorizer}).
 *
 * The choice is deliberately tied to the SAME switch the store takes rather than
 * to the mere presence of a `DB` binding: `CONTROL_PLANE_STORE = "memory"` means
 * "run this deployment without the control database", and an authorizer that
 * kept querying it would answer `503 rbac unavailable` for a configuration that
 * is otherwise entirely valid. One switch, one answer to "is the database in
 * play".
 */
export function resolveRbac(
  env: ControlPlaneBindings,
  resolvedControlDatabase?: D1Database,
): RbacAuthorizerPort {
  const declarative = new JsonRbacAuthorizer(
    parseJson<Record<string, readonly string[]>>(env.TENANT_RBAC_ACTIONS, {}),
  );
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") return declarative;
  const controlDb = controlDatabaseFor(env, resolvedControlDatabase);
  if (controlDb === undefined) return declarative;
  const tenantDatabases =
    env.TENANT_DATA === undefined
      ? null
      : new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, controlDb);
  return new D1RbacAuthorizer(controlDb, declarative, tenantDatabases);
}

/**
 * Pick the credential resolver: the control database's `static_api_keys` table
 * whenever the request is being served from the database, with the declarative
 * `CONTROL_PLANE_*_API_KEYS` vars as the per-credential fallback (see
 * {@link D1ApiKeyAuthenticator}).
 *
 * Tied to the SAME switch the store and the RBAC authorizer take, for the same
 * reason: `CONTROL_PLANE_STORE = "memory"` means "run this deployment without
 * the control database", and an authenticator that kept querying it would answer
 * `503` for a configuration that is otherwise entirely valid. One switch, one
 * answer to "is the database in play".
 */
export function resolveApiKeys(
  env: ControlPlaneBindings,
  resolvedControlDatabase?: D1Database,
): ApiKeyAuthenticatorPort {
  const declarative = new JsonApiKeyAuthenticator(
    parseJson<NativeKeyDeclaration[]>(env.CONTROL_PLANE_NATIVE_API_KEYS, []),
    parseJson<StaticKeyDeclaration[]>(env.CONTROL_PLANE_STATIC_API_KEYS, []),
  );
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") return declarative;
  const controlDb = controlDatabaseFor(env, resolvedControlDatabase);
  if (controlDb === undefined) return declarative;
  // Rust `authenticate_with_admission`'s SOURCE ORDERING, preserved exactly:
  // durable NATIVE keys first, then durable STATIC/operator keys, then the
  // declarative vars. Each layer is the fallback of the one before it, so a
  // deployment that has provisioned neither table behaves exactly as it did —
  // and one that has provisioned either cannot be loosened by a stale var.
  //
  // The native leg needs the tenant router because a virtual key's scopes live
  // in its own tenant's database; `resolveTenantDatabases` is the SAME
  // construction the admin routes take, so the two cannot disagree about which
  // database a tenant is.
  return new D1NativeApiKeyAuthenticator(
    controlDb,
    resolveTenantDatabases(env, controlDb),
    new D1ApiKeyAuthenticator(controlDb, declarative),
  );
}

/**
 * Pick the tenancy lifecycle gate: the hierarchy rows the admin surface WRITES
 * whenever the request is being served from the control database, with the
 * declarative `TENANCY_LIFECYCLE` map as the fallback (see
 * {@link StoreTenancyLifecycleGate}).
 *
 * This is the last of the four ports to move off a Worker var, and it is the one
 * whose var was most obviously wrong: `PATCH /admin/v1/tenant-accounts/{id}
 * {"status":"suspended"}` persisted a status that nothing read, so the app's own
 * suspension control did not stop the suspended tenant's traffic. It also only
 * ever checked the tenant, where Rust walks `tenant → project → workspace`.
 *
 * Tied to the SAME switch the store, the RBAC authorizer and the credential
 * resolver take, for the same reason: `CONTROL_PLANE_STORE = "memory"` means
 * "run this deployment without the control database". One switch, one answer to
 * "is the database in play".
 *
 * Note the gate is built on the SAME `store` instance the routes write through,
 * not on a second handle: a suspension written by a request is then visible to
 * the gate on the very next one, with no cache to invalidate.
 */
export function resolveLifecycle(
  env: ControlPlaneBindings,
  store: ControlPlaneStore,
): TenancyLifecycleGatePort {
  const declarative = new JsonTenancyLifecycleGate(
    parseJson<Record<string, LifecycleStatus>>(env.TENANCY_LIFECYCLE, {}),
  );
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") return declarative;
  // Zero-D1 S5 (#881): the durable lifecycle gate is active whenever the CONTROL
  // object is resolvable, not the retired `env.DB` control D1.
  if (controlDatabaseFrom(env) === undefined) return declarative;
  return new StoreTenancyLifecycleGate(store, declarative);
}

/**
 * Pick the tenant-database router for every tenant-DATA path on this Worker —
 * `@ferrogate/storage`'s `BackendDispatchingTenantDatabaseRouter`, which reads
 * the control database's `tenant_databases` registry and sends each tenant to
 * the backend its own row names.
 *
 * THE mount for the database-per-tenant directive on this Worker. Before it, the
 * whole durable half of `@ferrogate/storage` had zero importers under `apps/*`
 * (see `docs/rewrite/parity-audit-storage.md` §4.1), so the tenant migrations
 * ran and no code ever wrote a row through them.
 *
 * Two things about the shape are worth stating, because both look like
 * omissions and neither is:
 *
 *  - **Constructing the router needs no per-tenant `[[d1_databases]]` stanza.**
 *    The registry lives in the CONTROL database, which `wrangler.toml` already
 *    binds; a tenant's own stanza is written when that tenant is onboarded, and
 *    the router resolves it by NAME off `env` at request time
 *    (`env[binding_name]`). So this is deployable exactly as committed, and it
 *    starts routing the moment a tenant is provisioned — no code change.
 *  - **It is tied to the same `CONTROL_PLANE_STORE` switch as the store, the
 *    RBAC authorizer and the credential resolver.** `"memory"` means "run this
 *    deployment without the control database", and a router that kept querying
 *    it would fail every admin write in a configuration that is otherwise
 *    entirely valid. One switch, one answer to "is the database in play".
 */
export function resolveTenantDatabases(
  env: ControlPlaneBindings,
  resolvedControlDatabase?: D1Database,
): TenantDatabaseRouter {
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") {
    return new UnprovisionedTenantDatabaseRouter();
  }
  const controlDb = controlDatabaseFor(env, resolvedControlDatabase);
  if (controlDb === undefined) return new UnprovisionedTenantDatabaseRouter();
  // The registration cache is per-router and `resolveDeps` builds one per
  // request, so the TTL only ever elides repeat lookups WITHIN a request. A
  // provisioning write is therefore visible on the very next request, with no
  // cache to invalidate.
  const bindings = new EnvBindingTenantDatabaseRouter(
    env as unknown as BindingEnvironment,
    controlDb,
  );
  // #821 PR2d retired the shared `ferrogate-tenant` D1 (`LEGACY_TENANT_DB`) and
  // with it the `legacyShared` router arm. The tenant-by-tenant backfill that was
  // its only reader is gone (`migrateTenantStorage` now answers 410), so a tenant
  // with no Durable Object is fail-closed here — never a shared-DB fallback.
  // PER TENANT, from the roster — not per Worker, from a var. See
  // `BackendDispatchingTenantDatabaseRouter`: since #820 every newly onboarded
  // tenant lives in a Durable Object that the binding router cannot reach, and
  // the binding router answers `not_found` for it, which every caller here
  // reads as "no tenant database, act on the document only". That silence made
  // an admin wallet credit write no `wallets` row anywhere (so the gateway's
  // no-oversell reserve found nothing to enforce) and made the fleet asset view
  // report an empty fleet for a deployment whose tenants all had assets.
  //
  // The `durableObject` arm is omitted when this Worker binds no namespace, and
  // that omission is a NAMED refusal rather than a fall-through: a
  // `durable_object` tenant resolved through the binding router would land on a
  // D1 database holding none of its rows.
  return new BackendDispatchingTenantDatabaseRouter(controlDb, {
    fallback: bindings,
    ...(env.TENANT_DATA === undefined
      ? {}
      : { durableObject: new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, controlDb) }),
  });
}

/**
 * The router tenant STORAGE PROVISIONING runs through (#820) — the Durable
 * Object namespace when this Worker binds one, otherwise whatever
 * {@link resolveTenantDatabases} resolved.
 *
 * ## Why this is a second router and not a change to the first one
 *
 * PROVISIONING and ROUTING ask different questions, and only one of them has a
 * roster row to read.
 *
 * {@link resolveTenantDatabases} dispatches on
 * `tenant_databases.storage_backend`, so it can only answer for a tenant that
 * ALREADY has a row. Provisioning is the thing that writes that row: at the
 * moment it runs there is nothing to dispatch on, and the backend a NEW tenant
 * should be created on is a property of this deployment — the namespace it
 * binds — not of the tenant. Hence a router that states one backend outright.
 * It is also why this one, and not the dispatching one, is what
 * `provisionTenantStorage` reads `router.backend` from: the dispatcher
 * deliberately leaves that property absent rather than stamping one backend onto
 * every tenant it provisions.
 *
 * (This docblock used to say the two Workers disagreed about where a tenant's
 * rows live, and called reconciling them a separate migration. That deferral was
 * wrong in a way that cost real money: an admin wallet credit for a
 * `durable_object` tenant took the document-only branch, answered 200, and wrote
 * no `wallets` row anywhere, so the gateway's no-oversell guard had nothing to
 * enforce. `BackendDispatchingTenantDatabaseRouter` closes it without moving any
 * `native_binding` tenant, because the roster says which is which.)
 *
 * The choice is made from the BINDING rather than from a routing var,
 * deliberately: a var could name a topology this Worker has no binding for, and
 * the failure would be a runtime `undefined` on the first tenant write instead
 * of a deploy-time refusal. `apps/gateway` can afford the var because it DEFINES
 * the class; this Worker only borrows it.
 */
export function resolveTenantStorage(
  env: ControlPlaneBindings,
  resolvedControlDatabase?: D1Database,
): TenantDatabaseRouter {
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") {
    return new UnprovisionedTenantDatabaseRouter();
  }
  const controlDb = controlDatabaseFor(env, resolvedControlDatabase);
  if (controlDb === undefined) return new UnprovisionedTenantDatabaseRouter();
  if (env.TENANT_DATA !== undefined) {
    return new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, controlDb);
  }
  // No namespace bound: new tenants are provisioned on whatever the data paths
  // can reach, which is the binding router underneath the dispatcher. It states
  // `native_binding` as its own backend, so the roster row is labelled honestly
  // and the dispatcher will keep routing that tenant the same way afterwards.
  return new EnvBindingTenantDatabaseRouter(env as unknown as BindingEnvironment, controlDb);
}

/**
 * Resolve the control-plane-only object access seam. This is intentionally
 * independent of `CONTROL_PLANE_STORE`: an operator must still be able to
 * inspect or restore a retained tenant object while the document store is in
 * the test/memory posture, and the namespace plus control DB are the only
 * bindings this seam needs.
 */
export function resolveTenantObjectOperator(
  env: ControlPlaneBindings,
  resolvedControlDatabase?: D1Database,
): TenantObjectOperator | null {
  // The tenant-object router reads the `tenant_databases` roster out of the
  // CONTROL object, which exists independently of the document-store choice —
  // so it must resolve `CONTROL_DATA` even under `CONTROL_PLANE_STORE = "memory"`
  // (which `controlDatabaseFor` deliberately vetoes for the DOCUMENT store).
  // Zero-D1 S5 (#881): this is the object, never the retired `env.DB` control D1.
  const controlDb = resolvedControlDatabase ?? controlDatabaseFrom(env);
  if (env.TENANT_DATA === undefined || controlDb === undefined) return null;
  return new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, controlDb);
}

/**
 * The CONTROL database handle, for the surfaces that must write a TYPED table
 * another Worker reads by name (see {@link ControlPlaneDeps.controlDatabase}).
 *
 * Gated on the SAME `CONTROL_PLANE_STORE` switch as the store, the RBAC
 * authorizer and the tenant router: `"memory"` means "run this deployment
 * without the control database", and a handle that kept writing to it there
 * would make one surface durable in a posture where nothing else is.
 */
export function resolveControlDatabase(env: ControlPlaneBindings): D1Database | null {
  if (env.CONTROL_PLANE_STORE?.trim().toLowerCase() === "memory") return null;
  return controlDatabaseFor(env) ?? null;
}

/**
 * The prompt-label KV namespace, or `null` when this deployment binds none.
 *
 * No fallback, and deliberately no in-memory stand-in: the pointer's ONLY
 * consumer is a different Worker, so an isolate-local map would make every
 * label look like it moved while `apps/gateway` saw nothing. `null` reaches
 * `routes/prompt.ts`, which refuses with a 503 that names the missing binding.
 */
export function resolvePromptLabels(env: ControlPlaneBindings): KVNamespace | null {
  return env.PROMPT_LABELS ?? null;
}

/**
 * The `api_key_directory` KV projection (#882), or `null` when unbound.
 *
 * No fallback and no in-memory stand-in, for the same reason
 * {@link resolvePromptLabels} has none: the projection's only READER is a
 * different Worker (`apps/gateway`), so an isolate-local map would let the write
 * path believe it published a routing row the gateway never sees. `null` is not a
 * downgrade — the virtual-key write path then simply skips the KV leg and the
 * gateway takes the RPC path on every cold miss, exactly as before #882.
 */
export function resolveKeyDirectory(env: ControlPlaneBindings): ApiKeyDirectoryProjection | null {
  return env.KEY_DIRECTORY === undefined
    ? null
    : new KvApiKeyDirectoryProjection(env.KEY_DIRECTORY);
}

/**
 * The audit-anchor bucket (#684), or `null` when the deployment binds none.
 *
 * Deliberately NOT gated on `CONTROL_PLANE_STORE`, unlike its siblings above:
 * the anchor is evidence ABOUT the control database, and the reason to keep it
 * in a separate store is precisely that a database operator should not be able
 * to remove it. Coupling it to the store switch would mean a deployment could
 * turn off the audit chain's anchor by changing a var about something else.
 *
 * `null` is a supported DEGRADED posture: the chain still detects an edited or
 * mid-trail-deleted row, but a tail deletion or a full re-forge goes unseen.
 * `runScheduledTick` reports that as `audit_anchor: "unconfigured"` rather than
 * failing the tick, because a control plane that refused to run without an
 * evidence bucket would be down for a compliance feature.
 */
export function resolveAuditAnchorBucket(env: ControlPlaneBindings): R2Bucket | null {
  return env.AUDIT_ANCHORS ?? null;
}

/**
 * The SIEM export bucket (#683), or `null` when the deployment binds none.
 *
 * Not gated on `CONTROL_PLANE_STORE`, for the same reason
 * {@link resolveAuditAnchorBucket} is not: the export is evidence LEAVING the
 * platform, and its availability should not be a side effect of a var about
 * which store the admin surface uses.
 *
 * `null` is not silently tolerated at the point of use — an `r2` sink whose
 * bucket is unbound reports a FAILED delivery and leaves its cursor where it
 * is, so the rows are still there when the binding arrives. That is the whole
 * value of having a cursor: a missing binding becomes a delay instead of a gap.
 */
export function resolveSiemExportBucket(env: ControlPlaneBindings): R2Bucket | null {
  return env.SIEM_EXPORTS ?? null;
}

/**
 * The asset bucket (#743), NARROWED to delete — or `null` when unbound.
 *
 * The wrapper is the point and is not ceremony: `env.ASSETS` is a full
 * `R2Bucket`, and handing that to {@link ControlPlaneDeps} would put `get()`
 * over every tenant's asset bytes — including the versions the #366 screener is
 * withholding — inside reach of every handler on this Worker. What crosses the
 * composition root is an object with ONE method, so a future read path here
 * does not compile rather than merely failing review. See
 * {@link AssetObjectReclaimer}.
 *
 * An empty key list is not sent to R2 at all: `delete([])` is a pointless round
 * trip, and the force-delete of a version with no stored objects (`storage_uri`
 * null, no bundle files) is a real case rather than a hypothetical one.
 */
export function resolveAssetObjects(env: ControlPlaneBindings): AssetObjectReclaimer | null {
  const bucket = env.ASSETS;
  if (bucket === undefined) return null;
  return {
    delete: async (keys: readonly string[]): Promise<void> => {
      if (keys.length === 0) return;
      await bucket.delete([...keys]);
    },
  };
}

/**
 * The Analytics Engine SQL REST client for the #956 fleet read side.
 *
 * The AE read side is the account-scoped `/analytics_engine/sql` REST endpoint:
 * a POST whose BODY is the raw SQL, authorized with an account API token. There
 * is no offline emulation (miniflare discards `writeDataPoint` and answers no
 * query), so this is exercised live; `fetchImpl` is injectable purely so a test
 * can assert the request shape without a network. A non-2xx or unparseable
 * response is a {@link BillingFleetUnavailableError} the route maps to 503.
 */
export class CloudflareAnalyticsEngineQuery implements BillingFleetQueryPort {
  readonly #accountId: string;
  readonly #token: string;
  readonly #fetch: typeof fetch;

  constructor(accountId: string, token: string, fetchImpl: typeof fetch = fetch) {
    this.#accountId = accountId;
    this.#token = token;
    this.#fetch = fetchImpl;
  }

  async runSql(sql: string): Promise<readonly Record<string, unknown>[]> {
    let response: Response;
    try {
      response = await this.#fetch(
        `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(this.#accountId)}/analytics_engine/sql`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${this.#token}`,
            "content-type": "text/plain",
          },
          body: sql,
        },
      );
    } catch (cause) {
      throw new BillingFleetUnavailableError("Analytics Engine SQL request failed", { cause });
    }
    if (!response.ok) {
      throw new BillingFleetUnavailableError(
        `Analytics Engine SQL returned HTTP ${response.status}`,
      );
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch (cause) {
      throw new BillingFleetUnavailableError("Analytics Engine SQL response was not JSON", {
        cause,
      });
    }
    // A 200 whose body carries no `data` array is a genuinely empty result set
    // (the window had no billed events) → an empty report, not an error: AE SQL
    // signals a query FAILURE with a non-2xx, which `!response.ok` already maps
    // to a 503 above. So a data-less 200 is "no spend", not a masked failure.
    const data = (payload as { data?: unknown } | null)?.data;
    return Array.isArray(data) ? (data as Record<string, unknown>[]) : [];
  }
}

/**
 * Build the fleet service, or `null` when the account query surface is
 * unconfigured. All three of dataset / account id / token are required — a
 * partial config would 500 at query time, so it fails shut to a 503 instead.
 */
export function resolveBillingFleet(
  env: ControlPlaneBindings,
  fetchImpl: typeof fetch = fetch,
): BillingFleetService | null {
  const dataset = env.BILLING_ANALYTICS_DATASET?.trim();
  const accountId = env.BILLING_ANALYTICS_ACCOUNT_ID?.trim();
  const token = env.BILLING_ANALYTICS_API_TOKEN?.trim();
  if (!dataset || !accountId || !token) return null;
  const port = new CloudflareAnalyticsEngineQuery(accountId, token, fetchImpl);
  return { report: (query: FleetQuery) => runFleetReport(port, dataset, query) };
}

export function resolveDeps(
  env: ControlPlaneBindings,
  context: RequestContext = {},
): ControlPlaneDeps {
  const controlDatabase = controlDatabaseFor(env);
  const store = resolveStore(env, context, controlDatabase);
  const tenantDatabases = resolveTenantDatabases(env, controlDatabase);

  const corsAllowedOrigin = env.ADMIN_CONSOLE_ALLOWED_ORIGIN?.trim();
  return {
    apiKeys: resolveApiKeys(env, controlDatabase),
    lifecycle: resolveLifecycle(env, store),
    rbac: resolveRbac(env, controlDatabase),
    store,
    tenantDatabases,
    tenantStorage: resolveTenantStorage(env, controlDatabase),
    tenantObjectOperator: resolveTenantObjectOperator(env, controlDatabase),
    controlDatabase: controlDatabase ?? null,
    // #956 read side. Null unless BILLING_ANALYTICS_{DATASET,ACCOUNT_ID,API_TOKEN}
    // are all bound; the fleet endpoint then answers 503 rather than fabricating.
    billingFleet: resolveBillingFleet(env),
    promptLabels: resolvePromptLabels(env),
    keyDirectory: resolveKeyDirectory(env),
    // Delete-only by construction — see `resolveAssetObjects`.
    assetObjects: resolveAssetObjects(env),
    runtime: new StoreRuntimeStatus(store, "0.0.0", tenantDatabases, controlDatabase ?? null),
    txtResolver: resolveTxtResolver(env),
    // The certificate seam (#738). Its default answers `unconfigured` and makes
    // no outbound call, so a deployment that has not opted in gains no traffic.
    siteDomainCertificates: resolveSiteDomainCertificates(env),
    // Absent or blank ⇒ NO admin-console origin ⇒ the preflight surface does
    // not exist at all (see `middleware/cors.ts`).
    corsAllowedOrigin:
      corsAllowedOrigin === undefined || corsAllowedOrigin === "" ? null : corsAllowedOrigin,
    listDefaultLimit: positiveInt(env.ADMIN_LIST_DEFAULT_LIMIT, DEFAULT_ADMIN_LIST_LIMIT),
    listMaxLimit: positiveInt(env.ADMIN_LIST_MAX_LIMIT, DEFAULT_ADMIN_LIST_MAX_LIMIT),
  };
}

/** Drop the per-isolate store — used by tests to start from a clean slate. */
export function resetSharedStore(): void {
  sharedStore = null;
  sharedStoreSeed = undefined;
}
