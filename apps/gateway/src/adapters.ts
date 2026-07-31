/**
 * Default, binding-free implementations of the ports in `./ports.ts`.
 *
 * These are the *config* leg of the Rust authenticator — `state.config.api_keys`
 * (`crates/ferrogate-gateway/src/auth.rs`, the loop after the durable lookup) —
 * plus the smallest honest stand-ins for the durable/virtual key store, the
 * tenancy lifecycle gate, and the self-hosted worker transport. They read JSON
 * out of Worker vars so the whole auth taxonomy is exercisable in `workerd`
 * today, and they are swapped for D1/Secrets-Store-backed adapters — with no
 * change to `middleware/auth.ts` — as soon as the wave-2 packages land.
 *
 * Two of the four ports have since grown a DURABLE leg in this file, each in
 * front of its config table: {@link D1RbacAuthorizer} (CONTROL D1
 * Permission → Role → TenantRoleBinding) and, from `./keys/`,
 * `d1ApiKeyResolverFromEnv` (TENANT D1 `api_keys`). See {@link depsFromEnv}.
 *
 * PORT-TODO(inventory-edge-control §5.2): the SELF-HOSTED WORKER TRANSPORT
 * SECRET is the one credential still compared as a plaintext var here
 * (`SELF_HOSTED_WORKER_REGISTRY.transport_secret`, {@link
 * ConfiguredInternalTransport}). It moves to **Cloudflare Secrets Store** via
 * `@ferrogate/secrets`. NOT a platform limit and not blocked on a schema — it
 * is blocked on the BINDING BEING DEPLOY-TIME: a Secrets Store binding is
 * declared in `wrangler.toml` and materialized by `wrangler deploy` against a
 * store that must already exist in the account, so it cannot be exercised by
 * `wrangler dev --local` or `vitest-pool-workers` the way D1/R2/Queues can. The
 * approximation shipped here is the same constant-time comparison against a var
 * the deployment sets with `wrangler secret put` (a secret, never a plaintext
 * var — see the `wrangler.toml` note on `SELF_HOSTED_WORKER_REGISTRY`), which
 * differs from Secrets Store in blast radius and rotation story, not in the
 * comparison itself.
 */
import { d1ApiKeyResolverFromEnv } from "./keys/index.js";
import type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AuthContext,
  GatewayBindings,
  GatewayDeps,
  InternalTransportDecision,
  InternalTransportPort,
  LifecycleDecision,
  RbacAuthorizerPort,
  RbacDecision,
  TenancyLifecycleGatePort,
} from "./ports.js";
import { WILDCARD_SCOPE, callerScope } from "./ports.js";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Length-independent constant-time comparison (Rust `auth::constant_time_eq`).
 * Differing lengths short-circuit exactly as they do in Rust.
 */
export function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function parseJsonVar<T>(raw: string | undefined, fallback: T): T {
  if (raw === undefined || raw.trim() === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    // A malformed var must not silently grant access; behave as "nothing configured".
    return fallback;
  }
}

function nowUnixSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

/** Wire shape of a configured key. Mirrors the Rust `ApiKey` config record. */
export interface ApiKeyRecord {
  readonly key: string;
  readonly id?: string;
  readonly scopes?: readonly string[];
  readonly tenant_id?: string;
  readonly project_id?: string;
  readonly workspace_id?: string;
  readonly user_id?: string;
  readonly platform_operator?: boolean;
  /** Defaults to `true`. */
  readonly enabled?: boolean;
  /** Durable keys only: a revoked key is suspended. */
  readonly revoked?: boolean;
  readonly expires_at_unix?: number | null;
  /** Static keys only: `0` means the budget is exhausted. */
  readonly monthly_token_budget?: number | null;
}

function isExpired(record: ApiKeyRecord, now: number): boolean {
  const expiresAt = record.expires_at_unix;
  return typeof expiresAt === "number" && expiresAt <= now;
}

function toAuthContext(record: ApiKeyRecord, scopes: readonly string[]): AuthContext {
  return {
    subject: record.id ?? record.user_id ?? null,
    tenancy: {
      tenantId: record.tenant_id ?? null,
      projectId: record.project_id ?? null,
      workspaceId: record.workspace_id ?? null,
      userId: record.user_id ?? null,
    },
    scopes,
    platformOperator: record.platform_operator === true,
    source: "durable_native",
  };
}

// ---------------------------------------------------------------------------
// Local development key  (OFF unless three independent conditions all hold)
// ---------------------------------------------------------------------------

/**
 * Prefix a development key MUST carry.
 *
 * A real tenant key can never accidentally take this path, and a leaked dev key
 * is self-identifying in a log or a bug report.
 */
export const DEV_API_KEY_PREFIX = "fg_dev_";

/** Minimum length of the secret part, so a guessable placeholder is refused. */
export const DEV_API_KEY_MIN_LENGTH = DEV_API_KEY_PREFIX.length + 24;

/**
 * The ONLY scopes a development key may hold.
 *
 * The six data-plane inference scopes, spelled out. It is not `["*"]` and it is
 * not the empty set — an empty native scope set already means "data-plane
 * scopes, never `admin.*`" (`hasScope`), but naming them makes the grant
 * auditable and keeps a dev key off every non-inference operation too.
 */
export const DEV_API_KEY_SCOPES: readonly string[] = [
  "models.read",
  "chat.completions",
  "responses.create",
  "messages.create",
  "embeddings.create",
  "images.generate",
];

/**
 * The local-development credential path, and the gate that keeps it out of
 * production.
 *
 * Wiring a request end-to-end against a real upstream needs a key that resolves.
 * Hand-editing `GATEWAY_NATIVE_API_KEYS` for that is how a developer credential
 * ends up committed, so this supplies one — behind a gate with THREE
 * independent conditions, ALL of which must hold:
 *
 *  1. `GATEWAY_DEV_AUTH` is exactly `"true"`. The value committed in
 *     `wrangler.toml` `[vars]` is `"false"`, and top-level `[vars]` is what a
 *     plain `wrangler deploy` ships — so turning this on for a deployed Worker
 *     takes an explicit, reviewable edit or an explicit `[env.<name>.vars]`
 *     override. It cannot happen by forgetting something.
 *  2. `GATEWAY_DEV_API_KEY` is bound and long enough. It is a SECRET (a
 *     `.dev.vars` entry locally, `wrangler secret put` otherwise), never a var,
 *     so no key value is ever committed.
 *  3. The key carries the {@link DEV_API_KEY_PREFIX}. A production credential
 *     shape can never be served by this path.
 *
 * The record is a *native* key, so every native rule applies to it unchanged —
 * notably that suspending it answers `401 invalid_api_key`, not 403. Its scopes
 * are {@link DEV_API_KEY_SCOPES}: inference only, `admin.*` never.
 *
 * Returns `[]` — i.e. contributes nothing at all to the key table — whenever any
 * condition fails. There is no partial state.
 */
export function developmentApiKeys(env: GatewayBindings): readonly ApiKeyRecord[] {
  if (env.GATEWAY_DEV_AUTH !== "true") {
    return [];
  }
  const key = env.GATEWAY_DEV_API_KEY;
  if (typeof key !== "string") {
    return [];
  }
  const trimmed = key.trim();
  if (!trimmed.startsWith(DEV_API_KEY_PREFIX) || trimmed.length < DEV_API_KEY_MIN_LENGTH) {
    return [];
  }
  return [
    {
      key: trimmed,
      id: "key_local_dev",
      tenant_id: env.GATEWAY_DEV_TENANT_ID?.trim() || "tenant_local_dev",
      scopes: DEV_API_KEY_SCOPES,
    },
  ];
}

/**
 * Resolves a presented key against the durable/native store first, then the
 * static operator config store — the Rust order.
 *
 * The two stores intentionally answer differently for an unusable key:
 *
 *  - **durable/native**: `!enabled` / revoked / expired ⇒ `key_suspended`,
 *    which `middleware/auth.ts` renders as `401 invalid_api_key`, identical to
 *    an unknown key. This is the "suspended native API key is 401, not 403"
 *    invariant, and it is enforced here at the source rather than by a caller
 *    remembering to special-case it.
 *  - **static config**: `!enabled` ⇒ `403 api_key_disabled`, expired ⇒
 *    `403 api_key_expired`, zero budget ⇒ `429 token_budget_exceeded`.
 */
export class ConfiguredApiKeyAuthenticator implements ApiKeyAuthenticatorPort {
  readonly #native: readonly ApiKeyRecord[];
  readonly #static: readonly ApiKeyRecord[];

  constructor(nativeKeys: readonly ApiKeyRecord[], staticKeys: readonly ApiKeyRecord[]) {
    this.#native = nativeKeys;
    this.#static = staticKeys;
  }

  static fromEnv(env: GatewayBindings): ConfiguredApiKeyAuthenticator {
    return new ConfiguredApiKeyAuthenticator(
      // The development record goes FIRST so a configured native record with
      // the same value overrides it: the scan below takes the LAST match, so
      // explicit configuration always wins over the convenience path.
      [
        ...developmentApiKeys(env),
        ...parseJsonVar<ApiKeyRecord[]>(env.GATEWAY_NATIVE_API_KEYS, []),
      ],
      parseJsonVar<ApiKeyRecord[]>(env.GATEWAY_STATIC_API_KEYS, []),
    );
  }

  async authenticate(presentedKey: string): Promise<ApiKeyResolution> {
    const now = nowUnixSeconds();

    // Scan every record without an early exit so timing does not leak which
    // slot matched (Rust compares each configured key in turn).
    let nativeMatch: ApiKeyRecord | null = null;
    for (const record of this.#native) {
      if (constantTimeEqual(record.key, presentedKey)) nativeMatch = record;
    }
    if (nativeMatch !== null) {
      if (nativeMatch.enabled === false) {
        return { outcome: "key_suspended", reason: "disabled" };
      }
      if (nativeMatch.revoked === true) {
        return { outcome: "key_suspended", reason: "revoked" };
      }
      if (isExpired(nativeMatch, now)) {
        return { outcome: "key_suspended", reason: "expired" };
      }
      // A durable key's empty scope set grants data-plane scopes only — never
      // `admin.*`. `hasScope` encodes that; do NOT widen it to the wildcard.
      return { outcome: "resolved", auth: toAuthContext(nativeMatch, nativeMatch.scopes ?? []) };
    }

    let staticMatch: ApiKeyRecord | null = null;
    for (const record of this.#static) {
      if (constantTimeEqual(record.key, presentedKey)) staticMatch = record;
    }
    if (staticMatch !== null) {
      if (staticMatch.enabled === false) return { outcome: "static_key_disabled" };
      if (isExpired(staticMatch, now)) return { outcome: "static_key_expired" };
      if (staticMatch.monthly_token_budget === 0) return { outcome: "token_budget_exhausted" };
      // A STATIC config key is operator-authored: an empty scope list has
      // always meant "all access", so preserve that intent as an explicit
      // wildcard (Rust does exactly this, and only for this path).
      const scopes =
        staticMatch.scopes === undefined || staticMatch.scopes.length === 0
          ? [WILDCARD_SCOPE]
          : staticMatch.scopes;
      return {
        outcome: "resolved",
        auth: { ...toAuthContext(staticMatch, scopes), source: "static_config" },
      };
    }

    return { outcome: "unknown" };
  }
}

// ---------------------------------------------------------------------------
// Tenancy lifecycle gate
// ---------------------------------------------------------------------------

export type LifecycleStatus = "active" | "suspended" | "deleted" | "disabled";

/**
 * Rust `ferrogate-storage/src/lifecycle_gate.rs`, narrowed to the tenant tier.
 * Refusals name the ROOT cause so "your account is suspended, pay the bill" is
 * distinguishable from "you pointed a key at something that does not exist".
 *
 * PORT-TODO(inventory-data-billing §lifecycle): walk the full
 * tenant → project → workspace chain from D1, and honour the `Permissive`
 * admission the lifecycle status PUT/PATCH routes use to turn a hierarchy back
 * on. This adapter reads the TENANT tier only.
 *
 * Not a platform limit; blocked on the CHAIN, and it is a widening-risk
 * decision rather than a mechanical one. The CONTROL migration has `tenants`,
 * but the per-tier `lifecycle_status` columns and the project/workspace rows
 * this needs are a `sql/d1-ts` + `packages/storage` slice, neither of which is
 * this app's to write. The consequence of the gap is stated precisely so it is
 * not mistaken for parity: a SUSPENDED PROJECT inside an ACTIVE TENANT is
 * admitted today, where Rust refuses it with `403 tenancy_suspended`. It fails
 * OPEN for the sub-tenant tiers and CLOSED for the tenant tier, which is why
 * the tenant tier was ported first.
 */
export class ConfiguredTenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #statuses: Readonly<Record<string, LifecycleStatus>>;

  constructor(statuses: Readonly<Record<string, LifecycleStatus>>) {
    this.#statuses = statuses;
  }

  static fromEnv(env: GatewayBindings): ConfiguredTenancyLifecycleGate {
    return new ConfiguredTenancyLifecycleGate(
      parseJsonVar<Record<string, LifecycleStatus>>(env.TENANCY_LIFECYCLE, {}),
    );
  }

  async admit(auth: AuthContext): Promise<LifecycleDecision> {
    const scope = callerScope(auth);
    if (scope.kind === "platform_operator") return { admitted: true };
    const status = this.#statuses[scope.tenantId];
    switch (status) {
      case "suspended":
        return {
          admitted: false,
          code: "tenancy_suspended",
          message: `tenant ${scope.tenantId} is suspended`,
        };
      case "deleted":
        return {
          admitted: false,
          code: "tenancy_deleted",
          message: `tenant ${scope.tenantId} is deleted`,
        };
      case "disabled":
        return {
          admitted: false,
          code: "tenancy_disabled",
          message: `tenant ${scope.tenantId} is disabled`,
        };
      default:
        return { admitted: true };
    }
  }
}

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

/**
 * The operator-authored bootstrap grant table — the `[vars]` half of RBAC.
 *
 * Rust has no config-file RBAC: `tenant_has_permission_result` reads the
 * durable Permission → Role → TenantRoleBinding graph and nothing else. This
 * table is a port-local bootstrap, in the same role `GATEWAY_STATIC_API_KEYS`
 * plays for credentials, and {@link D1RbacAuthorizer} is the faithful leg that
 * now sits in front of it. Empty ⇒ grants nothing, so it can only ever be
 * additive to the durable graph, never a way around it.
 */
export class ConfiguredRbacAuthorizer implements RbacAuthorizerPort {
  readonly #actionsByTenant: Readonly<Record<string, readonly string[]>>;

  constructor(actionsByTenant: Readonly<Record<string, readonly string[]>>) {
    this.#actionsByTenant = actionsByTenant;
  }

  static fromEnv(env: GatewayBindings): ConfiguredRbacAuthorizer {
    return new ConfiguredRbacAuthorizer(
      parseJsonVar<Record<string, readonly string[]>>(env.TENANT_RBAC_ACTIONS, {}),
    );
  }

  async authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision> {
    const scope = callerScope(auth);
    if (scope.kind === "platform_operator") return { allowed: true };
    const granted = this.#actionsByTenant[scope.tenantId] ?? [];
    if (granted.includes(rbacAction) || granted.includes(WILDCARD_SCOPE)) {
      return { allowed: true };
    }
    return {
      allowed: false,
      // Rust names the denial after the action's own domain
      // (`guardrail_rbac_denied` is the only one that exists today).
      code: rbacDenialCode(rbacAction),
      message: rbacDenialMessage(rbacAction),
    };
  }
}

/**
 * Rust names the denial after the action's own domain
 * (`guardrail_rbac_denied` is the only domain-specific one that exists today —
 * `guardrail_policies.rs:959`, `local.rs:236`).
 */
export function rbacDenialCode(rbacAction: string): string {
  return rbacAction.startsWith("guardrails.") ? "guardrail_rbac_denied" : "rbac_denied";
}

/** The Rust denial message, verbatim. */
export function rbacDenialMessage(rbacAction: string): string {
  return `tenant roles do not grant required action ${rbacAction}`;
}

/** Binding name of the CONTROL D1 holding the RBAC graph (`wrangler.toml`). */
export const CONTROL_DATABASE_BINDING = "CONTROL_DB";

/** The two statements `D1RbacAuthorizer` issues. Exported so a test can pin them. */
export const RBAC_PERMISSION_EXISTS_SQL = "SELECT 1 AS present FROM permissions WHERE key = ?1";
export const RBAC_TENANT_ROLE_GRANTS_SQL =
  "SELECT roles.permission_keys_json AS permission_keys_json " +
  "FROM tenant_role_bindings " +
  "JOIN roles ON roles.id = tenant_role_bindings.role_id " +
  "WHERE tenant_role_bindings.tenant_id = ?1";

/**
 * The subset of `D1Database` this adapter reads. A live binding satisfies it
 * structurally, so nothing is cast and nothing is wrapped.
 */
export interface RbacDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { all(): Promise<{ results?: unknown[] | null }> };
  };
}

function isRbacDatabase(value: unknown): value is RbacDatabase {
  return typeof value === "object" && value !== null && typeof (value as RbacDatabase).prepare === "function";
}

/**
 * `state_rbac.rs::tenant_has_permission_result`, over the CONTROL D1.
 *
 * The Rust resolution is a three-table walk and every step of it is reproduced:
 *
 *  1. **The permission must EXIST.** `list_permissions().any(key == …)` — an
 *     action nobody declared is denied even if a role happens to name it. That
 *     is not a formality: it is what stops a typo in a role's
 *     `permission_keys` from minting an entitlement.
 *  2. **The tenant's role bindings are walked**, and a binding whose role row
 *     is missing is SKIPPED (`let Some(role) = … else { continue }`), not
 *     treated as a grant. The `JOIN` below drops exactly those rows.
 *  3. **A role grants when its `permission_keys` contains the action.** No
 *     wildcard: the Rust compares `key == permission_key`, so `"*"` in a role
 *     is a permission literally named `*` and nothing else. The var table's
 *     wildcard is a bootstrap convenience and is deliberately NOT copied here.
 *
 * Two departures from the Rust, both narrowing:
 *
 *  - a **platform operator** is waved through before any query, matching every
 *    Rust call site (`if let CallerScope::Tenant(..) = auth.caller_scope()`);
 *  - a **storage failure** answers `allowed: "unavailable"` → 503
 *    `rbac_unavailable`, and does NOT fall through to {@link fallback}. This is
 *    the `D1ApiKeyResolver` rule and the Rust one (`Err(error) => 503
 *    guardrail_rbac_unavailable`): an outage must never be indistinguishable
 *    from a decision, and must never be papered over by config.
 *
 * A durable NOT-GRANTED does fall through to `fallback`, because the two tables
 * are additive sources (see {@link ConfiguredRbacAuthorizer}); with no fallback
 * supplied it is a plain 403.
 */
export class D1RbacAuthorizer implements RbacAuthorizerPort {
  readonly #db: RbacDatabase;
  readonly #fallback: RbacAuthorizerPort | undefined;

  constructor(db: RbacDatabase, options: { fallback?: RbacAuthorizerPort | undefined } = {}) {
    this.#db = db;
    this.#fallback = options.fallback;
  }

  /** `null` when `CONTROL_DB` is unbound, so the caller keeps its config path. */
  static fromEnv(
    env: Record<string, unknown>,
    options: { fallback?: RbacAuthorizerPort | undefined } = {},
  ): D1RbacAuthorizer | null {
    const binding = env[CONTROL_DATABASE_BINDING];
    return isRbacDatabase(binding) ? new D1RbacAuthorizer(binding, options) : null;
  }

  async authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision> {
    const scope = callerScope(auth);
    if (scope.kind === "platform_operator") return { allowed: true };

    let granted: boolean;
    try {
      granted = await this.#durablyGrants(scope.tenantId, rbacAction);
    } catch (error) {
      return {
        allowed: "unavailable",
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    if (granted) return { allowed: true };

    if (this.#fallback !== undefined) {
      return this.#fallback.authorize(auth, rbacAction);
    }
    return {
      allowed: false,
      code: rbacDenialCode(rbacAction),
      message: rbacDenialMessage(rbacAction),
    };
  }

  async #durablyGrants(tenantId: string, rbacAction: string): Promise<boolean> {
    const declared = await this.#db.prepare(RBAC_PERMISSION_EXISTS_SQL).bind(rbacAction).all();
    if ((declared.results ?? []).length === 0) {
      return false;
    }
    const grants = await this.#db.prepare(RBAC_TENANT_ROLE_GRANTS_SQL).bind(tenantId).all();
    for (const row of grants.results ?? []) {
      const raw = (row as { permission_keys_json?: unknown }).permission_keys_json;
      if (typeof raw !== "string") continue;
      let keys: unknown;
      try {
        keys = JSON.parse(raw);
      } catch {
        // A corrupt role document grants nothing — it must not deny the whole
        // lookup either, because one bad row would then revoke every other
        // role the tenant holds.
        continue;
      }
      if (Array.isArray(keys) && keys.some((key) => key === rbacAction)) {
        return true;
      }
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// Self-hosted worker transport (auth.kind: "internal")
// ---------------------------------------------------------------------------

/** A registered self-hosted worker (Rust `SelfHostedWorkerRegistration`). */
export interface SelfHostedWorkerRegistration {
  readonly worker_id: string;
  readonly tenant_id: string;
  readonly workspace_id: string;
  /** Rust `identity_fingerprint`; must equal the envelope's `token_id`. */
  readonly identity_fingerprint: string;
  /** Server-provisioned transport secret. */
  readonly transport_secret: string;
  /** Defaults to `active`. */
  readonly status?: "active" | "inactive";
}

/** Header a worker presents its provisioned transport secret in. */
export const WORKER_TRANSPORT_HEADER = "x-ferrogate-worker-token";

/**
 * Verifies the 6 `/v1/self-hosted-workers/*` callbacks.
 *
 * The credential is the worker's own server-provisioned transport secret,
 * looked up from the registration named by the envelope identity — never an API
 * key. This class has no reference to `ApiKeyAuthenticatorPort`, which is what
 * makes "a tenant bearer cannot reach an internal operation" structural.
 *
 * PORT-TODO(inventory-edge-control §self-hosted worker transport): the Rust
 * transport is an AEAD-sealed frame (`read_self_hosted_transport_body`) whose
 * key is derived from the same provisioned secret; this adapter verifies the
 * secret and the identity binding but not yet the seal.
 */
export class ConfiguredInternalTransport implements InternalTransportPort {
  readonly #registrations: readonly SelfHostedWorkerRegistration[];

  constructor(registrations: readonly SelfHostedWorkerRegistration[]) {
    this.#registrations = registrations;
  }

  static fromEnv(env: GatewayBindings): ConfiguredInternalTransport {
    return new ConfiguredInternalTransport(
      parseJsonVar<SelfHostedWorkerRegistration[]>(env.SELF_HOSTED_WORKER_REGISTRY, []),
    );
  }

  async verify(request: Request): Promise<InternalTransportDecision> {
    const invalidIdentity = (message: string): InternalTransportDecision => ({
      verified: false,
      status: 401,
      code: "invalid_self_hosted_worker_identity",
      message,
    });

    const presentedSecret = request.headers.get(WORKER_TRANSPORT_HEADER)?.trim() ?? "";
    if (presentedSecret === "") {
      return invalidIdentity("self-hosted worker transport credential is missing");
    }

    let identity: Record<string, unknown> | undefined;
    try {
      const body: unknown = await request.clone().json();
      const candidate =
        typeof body === "object" && body !== null
          ? (body as Record<string, unknown>).identity
          : undefined;
      identity =
        typeof candidate === "object" && candidate !== null
          ? (candidate as Record<string, unknown>)
          : undefined;
    } catch {
      return invalidIdentity("self-hosted worker transport body is not JSON");
    }
    if (identity === undefined) {
      return invalidIdentity("self-hosted worker transport body has no identity");
    }

    const { tenant_id: tenantId, workspace_id: workspaceId } = identity;
    const { worker_id: workerId, token_id: tokenId } = identity;
    if (
      typeof tenantId !== "string" ||
      typeof workspaceId !== "string" ||
      typeof workerId !== "string" ||
      typeof tokenId !== "string"
    ) {
      return invalidIdentity("self-hosted worker transport identity is incomplete");
    }

    const registration = this.#registrations.find(
      (candidate) =>
        candidate.worker_id === workerId &&
        candidate.tenant_id === tenantId &&
        candidate.workspace_id === workspaceId,
    );
    if (registration === undefined) {
      return invalidIdentity(
        `self-hosted worker ${workerId} was not found for encrypted transport`,
      );
    }
    if (registration.identity_fingerprint !== tokenId) {
      return invalidIdentity(
        "self-hosted worker encrypted transport token_id does not match registration",
      );
    }
    if (!constantTimeEqual(registration.transport_secret, presentedSecret)) {
      return invalidIdentity("self-hosted worker transport credential is invalid");
    }
    if (registration.status === "inactive") {
      return {
        verified: false,
        status: 403,
        code: "inactive_self_hosted_worker",
        message: `self-hosted worker ${workerId} is inactive`,
      };
    }

    return { verified: true, identity: { tenantId, workspaceId, workerId, tokenId } };
  }
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/**
 * Build the default port set from Worker bindings.
 *
 * Two ports resolve durably-first, each with the config table behind it as a
 * fallback, and each returning `null` from its `fromEnv` when its binding is
 * absent so the `?? configured` keeps the binding-free object exactly:
 *
 *  - `apiKeys` — the `DB` (TENANT) `api_keys` table is the PRIMARY credential
 *    source, the `[vars]` key tables its fallback. That is the Rust order:
 *    `authenticate_durable` first, `config.api_keys` second.
 *  - `rbac` — the `CONTROL_DB` Permission → Role → TenantRoleBinding graph is
 *    the primary grant source (`state_rbac.rs`, which has no config leg at
 *    all), the `TENANT_RBAC_ACTIONS` var its bootstrap fallback.
 *
 * In BOTH cases the fallback is consulted only on a durable NOT-FOUND, never on
 * a durable FAILURE: an outage answers 503 and stops there.
 */
export function depsFromEnv(env: GatewayBindings): GatewayDeps {
  const configured = ConfiguredApiKeyAuthenticator.fromEnv(env);
  const configuredRbac = ConfiguredRbacAuthorizer.fromEnv(env);
  return {
    apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured,
    lifecycle: ConfiguredTenancyLifecycleGate.fromEnv(env),
    rbac:
      D1RbacAuthorizer.fromEnv(env as unknown as Record<string, unknown>, {
        fallback: configuredRbac,
      }) ?? configuredRbac,
    internalTransport: ConfiguredInternalTransport.fromEnv(env),
  };
}
