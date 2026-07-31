/**
 * Narrow local interfaces the gateway codes against (dependency inversion).
 *
 * Wave-2 packages (`@ferrogate/storage`, `policy`, `secrets`, `config`, …) are
 * still being written concurrently, so nothing in `apps/gateway` may reach into
 * their internals. Instead the gateway declares the *smallest* surface it needs
 * here; a later slice supplies adapters that implement these ports on top of the
 * real packages, with no change to the middleware.
 *
 * The shapes are ported from the Rust authorization vocabulary in
 * `crates/ferrogate-gateway/src/auth.rs` (`AuthContext`, `CallerScope`,
 * `AuthError`) and `crates/ferrogate-storage/src/lifecycle_gate.rs`.
 */
import type { ApiOperation } from "./contract.js";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** Tenancy attribution carried by a resolved credential (Rust `AuthContext`). */
export interface Tenancy {
  readonly tenantId: string | null;
  readonly projectId?: string | null;
  readonly workspaceId?: string | null;
  readonly userId?: string | null;
}

/** Where a resolved credential came from. Decides the 401-vs-403 taxonomy. */
export type KeySource =
  /** Durable/virtual "native" API key (Supabase in Rust, D1 here). */
  | "durable_native"
  /** Operator-authored static key from configuration. */
  | "static_config"
  /** Answered by the external auth service. */
  | "external_auth_service";

/**
 * Rust `CallerScope` (#515): a credential either *declared* platform root or it
 * is confined to one tenant. An unclassified credential is a tenant, never root.
 */
export type CallerScope =
  | { readonly kind: "platform_operator" }
  | { readonly kind: "tenant"; readonly tenantId: string };

/** A successfully authenticated caller. */
export interface AuthContext {
  /** RBAC subject / api-key id, when the credential carries one. */
  readonly subject: string | null;
  readonly tenancy: Tenancy;
  /** Granted scopes. `["*"]` is the wildcard. Empty has special meaning — see `hasScope`. */
  readonly scopes: readonly string[];
  readonly platformOperator: boolean;
  readonly source: KeySource;

  // -------------------------------------------------------------------------
  // Per-credential limits. Rust `AuthContext` carries all three; they are
  // populated by `keys/resolver.ts::toAuthContext` off the `api_keys` row and
  // are `undefined` for every credential source that has no such row (static
  // config, external auth, development).
  //
  // Each is OPTIONAL and each absence means "no limit from this credential" —
  // never "deny". That asymmetry is deliberate: a source with no column for a
  // limit must not become a source that denies everything.
  // -------------------------------------------------------------------------

  /**
   * Rust `AuthContext.allowed_models` — the per-key model allowlist. Empty or
   * absent means "no allowlist" (every model the tenant can see). Consumed by
   * `inference/identity.ts::callerFromAuth` → `callerCanUseModel`.
   */
  readonly allowedModels?: readonly string[];
  /** Rust `AuthContext.allowed_providers` — the per-key provider allowlist. */
  readonly allowedProviders?: readonly string[];
  /**
   * Rust `AuthContext.request_limit_per_minute` (TOK-12) — the per-credential
   * RPM cap carried on the key row itself, independent of the quota-policy
   * chain. Read by `ratelimit/middleware.ts::subjectFor`.
   */
  readonly requestLimitPerMinute?: number;
}

/** Rust `AuthContext::caller_scope`. */
export function callerScope(auth: AuthContext): CallerScope {
  if (auth.platformOperator) return { kind: "platform_operator" };
  // Rust: the empty string is unforgeable as a real tenant id, so an
  // unclassified credential is confined to a tenant that matches no row.
  return { kind: "tenant", tenantId: auth.tenancy.tenantId ?? "" };
}

/** Rust `AuthContext::is_privileged_scope`. */
export function isPrivilegedScope(scope: string): boolean {
  return scope.startsWith("admin.");
}

/** Rust `WILDCARD_SCOPE`. */
export const WILDCARD_SCOPE = "*";

/**
 * Rust `scope_set_allows` / `AuthContext::has_scope`.
 *
 * An *empty* scope set grants data-plane scopes only and never an `admin.*`
 * scope — that asymmetry is load-bearing: a durable/virtual key with no scopes
 * must not become an admin key. Static config keys are normalized to `["*"]`
 * by their adapter before they ever reach here, preserving the operator intent
 * that "no scopes listed" means "all access".
 */
export function hasScope(scopes: readonly string[], required: string): boolean {
  if (scopes.includes(required)) return true;
  if (scopes.includes(WILDCARD_SCOPE)) return true;
  return scopes.length === 0 && !isPrivilegedScope(required);
}

// ---------------------------------------------------------------------------
// Port: API-key authentication  (→ @ferrogate/storage + @ferrogate/config)
// ---------------------------------------------------------------------------

/**
 * Outcome of resolving a presented bearer/`x-api-key` credential.
 *
 * The variants encode the Rust 401-vs-403 taxonomy exactly, and this is the
 * single place the "suspended native API key is 401, not 403" invariant lives:
 *
 * | variant             | Rust origin                                   | HTTP |
 * |---------------------|-----------------------------------------------|------|
 * | `unknown`           | no key matched → `invalid_api_key`            | 401  |
 * | `key_suspended`     | durable key `!enabled` / revoked / expired —  | 401  |
 * |                     | the authenticator returns `None`, so it falls |      |
 * |                     | through to the same `invalid_api_key` as a    |      |
 * |                     | typo. A suspended key is INDISTINGUISHABLE    |      |
 * |                     | from an unknown one.                          |      |
 * | `static_key_disabled` | static config key `!enabled`                | 403  |
 * | `static_key_expired`  | static config key past `expires_at`         | 403  |
 * | `token_budget_exhausted` | static key `monthly_token_budget == 0`   | 429  |
 * | `unavailable`       | external auth service unreachable             | 503  |
 * | `tenant_identity_required` | `finalize_auth`: the credential          | 403  |
 * |                     | authenticated but names no tenant             |      |
 *
 * `tenant_identity_required` is the ONE authenticated-but-refused variant that
 * is NOT indistinguishable from `unknown`, and that is the Rust behaviour
 * (`auth.rs::finalize_auth`, #540): a key row whose `organization_id` is blank
 * is an operator CONFIGURATION error, not a credential probe, and reporting it
 * as `invalid_api_key` sends the operator hunting for a bad secret. The secret
 * itself was already proven correct by the hash comparison that reached this
 * branch, so nothing about the credential is disclosed by saying so.
 */
export type ApiKeyResolution =
  | { readonly outcome: "resolved"; readonly auth: AuthContext }
  | { readonly outcome: "unknown" }
  | { readonly outcome: "key_suspended"; readonly reason: "disabled" | "revoked" | "expired" }
  | { readonly outcome: "static_key_disabled" }
  | { readonly outcome: "static_key_expired" }
  | { readonly outcome: "token_budget_exhausted" }
  /** Rust `finalize_auth`: authenticated, but the row declares no tenant. */
  | { readonly outcome: "tenant_identity_required"; readonly declaredButBlank: boolean }
  | { readonly outcome: "unavailable"; readonly detail: string };

/** Resolves a presented credential. Rust `ApiKeyAuthenticator` + config fallback. */
export interface ApiKeyAuthenticatorPort {
  authenticate(presentedKey: string): Promise<ApiKeyResolution>;
}

// ---------------------------------------------------------------------------
// Port: tenancy lifecycle gate  (→ @ferrogate/storage)
// ---------------------------------------------------------------------------

/**
 * Rust `ferrogate-storage/src/lifecycle_gate.rs`. Distinct from key suspension:
 * a *tenant/project/workspace* whose lifecycle status is suspended or deleted is
 * an authenticated-but-forbidden caller → **403**, with a code that names the
 * root cause (`tenancy_suspended` / `tenancy_deleted`).
 */
export type LifecycleDecision =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly code: string; readonly message: string };

export interface TenancyLifecycleGatePort {
  admit(auth: AuthContext, operation: ApiOperation): Promise<LifecycleDecision>;
}

// ---------------------------------------------------------------------------
// Port: RBAC  (→ @ferrogate/policy)
// ---------------------------------------------------------------------------

/**
 * Evaluates an operation's `rbac_action` for the caller. A platform-operator
 * credential is waved through by the Rust implementation; a tenant credential
 * is checked against its tenant's role bindings.
 */
export type RbacDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly code: string; readonly message: string }
  | { readonly allowed: "unavailable"; readonly detail: string };

export interface RbacAuthorizerPort {
  authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision>;
}

// ---------------------------------------------------------------------------
// Port: internal worker-plane transport  (→ @ferrogate/secrets + storage)
// ---------------------------------------------------------------------------

/** Identity a self-hosted worker presents in its transport envelope. */
export interface SelfHostedWorkerIdentity {
  readonly tenantId: string;
  readonly workspaceId: string;
  readonly workerId: string;
  readonly tokenId: string;
}

/**
 * `auth.kind: "internal"` verification for the 6 `/v1/self-hosted-workers/*`
 * callbacks. In Rust these routes never call `authenticate()` at all: they read
 * a signed transport envelope and verify it against the *per-worker*
 * server-provisioned secret. There is no bearer path into them, which is what
 * makes "a normal tenant bearer key cannot reach an internal operation" a
 * structural property rather than a policy check.
 */
export type InternalTransportDecision =
  | { readonly verified: true; readonly identity: SelfHostedWorkerIdentity }
  | {
      readonly verified: false;
      readonly status: 401 | 403;
      readonly code: string;
      readonly message: string;
    };

export interface InternalTransportPort {
  verify(request: Request, operation: ApiOperation): Promise<InternalTransportDecision>;
}

// ---------------------------------------------------------------------------
// Composition root
// ---------------------------------------------------------------------------

/** Everything the auth middleware needs, injected. */
export interface GatewayDeps {
  readonly apiKeys: ApiKeyAuthenticatorPort;
  readonly lifecycle: TenancyLifecycleGatePort;
  readonly rbac: RbacAuthorizerPort;
  readonly internalTransport: InternalTransportPort;
}

// ---------------------------------------------------------------------------
// Worker bindings + per-request variables
// ---------------------------------------------------------------------------

/**
 * Worker bindings this app reads. Deliberately tiny: real bindings (D1, KV, R2,
 * DO, Secrets Store) arrive with the adapters that back the ports above.
 *
 * The durable halves have landed for two of the four tables: the virtual-key
 * store is D1 `api_keys` on `DB` (`./keys/`) and the RBAC grant graph is D1
 * `permissions`/`roles`/`tenant_role_bindings` on `CONTROL_DB`
 * (`D1RbacAuthorizer`, `./adapters.ts`). In both cases the var below became the
 * FALLBACK, consulted only on a durable not-found and never on a durable
 * failure.
 *
 * PORT-TODO(inventory-edge-control §5.2): `SELF_HOSTED_WORKER_REGISTRY` still
 * carries a transport SECRET as a var. It moves to Cloudflare Secrets Store —
 * see the marker at the top of `./adapters.ts` for why that binding cannot be
 * exercised locally and what the shipped approximation is.
 * `TENANCY_LIFECYCLE` is the other var with no durable leg yet; the marker on
 * `ConfiguredTenancyLifecycleGate` names the tables it needs.
 */
export interface GatewayBindings {
  /** JSON array of durable/native virtual keys (see `adapters.ts`). */
  readonly GATEWAY_NATIVE_API_KEYS?: string;
  /** JSON array of operator-authored static config keys. */
  readonly GATEWAY_STATIC_API_KEYS?: string;
  /** JSON array of self-hosted worker registrations for the internal callbacks. */
  readonly SELF_HOSTED_WORKER_REGISTRY?: string;
  /** JSON map of tenant id → lifecycle status (`active`/`suspended`/`deleted`). */
  readonly TENANCY_LIFECYCLE?: string;
  /** JSON map of tenant id → granted RBAC actions. */
  readonly TENANT_RBAC_ACTIONS?: string;

  /**
   * The pre-auth `[network_access]` gate (issue #166), read by
   * `middleware/network.ts`. All four are inert when empty; a declared-but
   * unusable value answers `503 network_access_misconfigured` rather than
   * degrading to "no allowlist".
   */
  readonly GATEWAY_IP_ALLOWLIST?: string;
  readonly GATEWAY_TRUST_FORWARDED_FOR?: string;
  readonly GATEWAY_TRUSTED_PROXY_HOPS?: string;
  readonly GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE?: string;
  /**
   * Local-development key gate. `"true"` — and nothing else — opens the
   * development credential path in `adapters.ts`; the value committed in
   * `wrangler.toml` is `"false"`. See `developmentApiKeys`.
   */
  readonly GATEWAY_DEV_AUTH?: string;
  /** Development key VALUE. A secret (`.dev.vars` / `wrangler secret put`). */
  readonly GATEWAY_DEV_API_KEY?: string;
  /** Tenant the development key is attributed to. Defaults `tenant_local_dev`. */
  readonly GATEWAY_DEV_TENANT_ID?: string;
  /** JSON array of provider connections — read by `inference/catalog.ts`. */
  readonly GATEWAY_PROVIDERS?: string;
  /** JSON array of logical model entries — read by `inference/catalog.ts`. */
  readonly GATEWAY_MODELS?: string;

  /**
   * The OPERATOR REVERSE-PROXY TABLE — Rust `[[routes]]` / `[[upstreams]]`,
   * read by `routes/reverse-proxy.ts`. On this platform the vars ARE the config
   * document, so these are the `configSnapshot` the ROUTE-MAP's "Dynamic
   * surfaces" catch-all is resolved against.
   *
   * Both are parsed with `routeRuleSchema` / `upstreamSchema` from
   * `@ferrogate/config`. BOTH ABSENT ⇒ the catch-all is inert and every
   * uncontracted path keeps answering `404 not_found`; PRESENT BUT UNPARSEABLE
   * ⇒ `503 runtime_route_table_invalid`, never a silent empty table.
   *
   * Neither is declared in `wrangler.toml` (an operator with no reverse-proxy
   * routes should not carry two empty vars). The exact lines to add when one is
   * needed, in the `[vars]` block next to `GATEWAY_PROVIDERS`:
   *
   * ```toml
   * GATEWAY_ROUTES = "[]"
   * GATEWAY_UPSTREAMS = "[]"
   * ```
   */
  readonly GATEWAY_ROUTES?: string;
  readonly GATEWAY_UPSTREAMS?: string;

  // -------------------------------------------------------------------------
  // Wave-5 bindings. Each is declared in `wrangler.toml` and read by the
  // module named below; nothing here is optional-for-decoration.
  // -------------------------------------------------------------------------

  /**
   * The tenant control database (`sql/d1-ts/tenant/0001_init_tenant.sql`).
   * Read by `src/keys/resolver.ts` (`d1ApiKeyResolverFromEnv`) — with it bound
   * the durable `api_keys` table is the PRIMARY credential source and the
   * `GATEWAY_*_API_KEYS` vars above become the fallback, which is the Rust
   * order (`authenticate_durable` first, `config.api_keys` second). Unbound,
   * `depsFromEnv` returns byte-identically what it returned before wave 5.
   */
  readonly DB?: D1Database;
  /** Resolution-cache TTL for `src/keys/cache.ts`. Absent/junk ⇒ 0 (disabled). */
  readonly GATEWAY_API_KEY_CACHE_TTL_SECONDS?: string;

  /**
   * `RateLimiterDurableObject` namespace — one DO instance per counter key,
   * read by `src/ratelimit/middleware.ts` (`limiterForEnv`). Unbound, the
   * limiter degrades to the per-isolate in-memory counter, which is NOT a
   * correct production limiter (see `src/ratelimit/memory.ts`).
   *
   * The class itself must be re-exported from `src/worker.ts`: workerd resolves
   * a binding's `class_name` against the ENTRY module.
   */
  readonly RATE_LIMIT?: DurableObjectNamespace;
  /** JSON array of quota policy rows — `src/ratelimit/quota.ts`. Fail-closed empty. */
  readonly GATEWAY_QUOTA_POLICIES?: string;
  /** JSON map plan slug → plan defaults — `src/ratelimit/quota.ts`. */
  readonly GATEWAY_PLANS?: string;
  /** JSON map tenant id → plan slug — `src/ratelimit/quota.ts`. */
  readonly GATEWAY_TENANT_PLANS?: string;

  /** JSON array of `PolicyRevision` — `src/guardrails/config.ts`. Empty ⇒ no screening. */
  readonly GATEWAY_GUARDRAIL_POLICIES?: string;
  /** JSON array of `{ policy_id, active_revision }` — `src/guardrails/config.ts`. */
  readonly GATEWAY_GUARDRAIL_BINDINGS?: string;
  /**
   * Keyed-HMAC secret for guardrail evidence `input_fingerprint`. A SECRET
   * (`wrangler secret put`), never a committed var.
   */
  readonly GUARDRAIL_EVIDENCE_HMAC_KEY?: string;

  // -------------------------------------------------------------------------
  // Wave-9 bindings — "the great wiring". Each is declared in `wrangler.toml`
  // and read by the module named below.
  // -------------------------------------------------------------------------

  /**
   * `ProviderCircuitDurableObject` namespace — one instance per provider name,
   * read by `src/inference/defaults.ts` (`providerCircuitFor`). Unbound, the
   * breaker degrades to a per-isolate `Map`, which counts failures per isolate
   * and so is NOT a correct cross-isolate breaker.
   *
   * The class must be re-exported from `src/worker.ts`: workerd resolves a
   * binding's `class_name` against the ENTRY module.
   */
  readonly PROVIDER_CIRCUIT?: DurableObjectNamespace;
  /**
   * JSON object of the three provider-reliability settings — read by
   * `src/inference/reliability.ts`. Absent/empty ⇒ NO breaker and no retry,
   * reproducing Rust's "both fields unset ⇒ the breaker is not constructed".
   */
  readonly GATEWAY_RELIABILITY?: string;

  /** JSON array of `@ferrogate/policy` deny/allow rules — `src/ratelimit/policy.ts`. */
  readonly GATEWAY_POLICY_RULES?: string;
  /** Credits held per in-flight request — `src/ratelimit/wallet.ts`. */
  readonly GATEWAY_WALLET_HOLD_CREDITS?: string;

  /**
   * The `[cache]` section, one var per field — read by `src/cache/config.ts`.
   * `GATEWAY_CACHE_ENABLED` defaults FALSE; a malformed value here disables the
   * cache and reports `x-ferrogate-cache: bypass` rather than failing the
   * request (see `src/cache/config.ts` on why this fails the opposite way from
   * the network gate).
   */
  readonly GATEWAY_CACHE_ENABLED?: string;
  readonly GATEWAY_CACHE_TTL_SECONDS?: string;
  readonly GATEWAY_CACHE_MAX_RECORDS?: string;
  readonly GATEWAY_CACHE_MODE?: string;
  readonly GATEWAY_CACHE_DISABLED_MODELS?: string;
  readonly GATEWAY_CACHE_DISABLED_API_KEYS?: string;
  readonly GATEWAY_CACHE_DISABLED_PROFILES?: string;

  /**
   * Per-tenant D1 routing mode — `src/tenancy/resolver.ts`. `"off"` (the
   * committed default) leaves the middleware inert; no mode ever falls back to
   * the shared `DB`.
   */
  readonly GATEWAY_TENANT_DB_ROUTING?: string;
  /** D1 REST account id — `"rest"` mode only. */
  readonly GATEWAY_TENANT_DB_ACCOUNT_ID?: string;
  /** D1 REST API token — `"rest"` mode only. A SECRET, never a committed var. */
  readonly GATEWAY_TENANT_DB_API_TOKEN?: string;

  // -------------------------------------------------------------------------
  // Wave-10 bindings. Same rule: each is declared in `wrangler.toml` and read
  // by the module named below.
  // -------------------------------------------------------------------------

  /**
   * `ShadowBudgetDurableObject` namespace — the CROSS-ISOLATE spend cap on
   * shadow (mirror) traffic, read by `src/inference/shadow.ts`
   * (`shadowBudgetFor`). Unbound, the ledger degrades to a per-isolate `Map`,
   * which over-spends the operator's configured cap by a bounded factor
   * (one budget per isolate); it is deliberately never "no cap".
   *
   * The class is re-exported from `src/worker.ts`: workerd resolves a binding's
   * `class_name` against the ENTRY module.
   */
  readonly SHADOW_BUDGET?: DurableObjectNamespace;

  /**
   * `[[services]] TELEMETRY_COLLECTOR` → the `ferrogate-telemetry` Worker's
   * OTLP receiver. Read by `src/telemetry/emit.ts`. The PREFERRED transport:
   * no DNS/TLS handshake, never leaves the colo, so the bearer token never
   * crosses a public network.
   */
  readonly TELEMETRY_COLLECTOR?: { fetch(request: Request): Promise<Response> };
  /** Absolute collector base URL — the fallback transport when no service binding exists. */
  readonly TELEMETRY_ENDPOINT?: string;
  /**
   * The collector's `COLLECTOR_TOKEN`. A SECRET (`wrangler secret put`), never
   * a committed var. WITHOUT IT NOTHING IS EMITTED — the collector answers 401
   * to an unauthenticated ingest, so emitting would be a guaranteed round trip
   * to a rejection on every request.
   */
  readonly TELEMETRY_TOKEN?: string;
  /** `resource.service.name` on every record. Defaults to `"ferrogate-gateway"`. */
  readonly TELEMETRY_SERVICE_NAME?: string;
  /** Comma-separated subset of `metric,trace,log`. Absent ⇒ all three. */
  readonly TELEMETRY_SIGNALS?: string;
  //
  // The per-tenant D1 handles themselves are deliberately NOT declared here:
  // each is bound under the name recorded in `tenant_databases.binding_name`,
  // so the set is deploy-time data and an index signature would erase every
  // typo check on the fields above. `TenancyBindings` (src/tenancy/ports.ts)
  // carries the `Record<string, unknown>` lookup shape for that one read.
}

/** Per-request context values set by the middleware chain. */
export interface GatewayVariables {
  requestId: string;
  /**
   * W3C trace id adopted from a valid inbound `traceparent`, else the request
   * id (`middleware/trace.ts`). This is what `x-trace-id` reports.
   */
  traceId: string;
  /** The verbatim valid inbound `traceparent`, or `null`. */
  traceparent: string | null;
  /** The inbound `tracestate` carried with a valid `traceparent`, or `null`. */
  tracestate: string | null;
  /** Canonicalized request path (`/control/v1/*` folded onto `/admin/v1/*`). */
  canonicalPath: string;
  operation: ApiOperation | null;
  auth: AuthContext | null;
  workerIdentity: SelfHostedWorkerIdentity | null;
}

/** The Hono generic for every gateway route and middleware. */
export type GatewayEnv = {
  Bindings: GatewayBindings;
  Variables: GatewayVariables;
};
