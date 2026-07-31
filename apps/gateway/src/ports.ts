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
 */
export type ApiKeyResolution =
  | { readonly outcome: "resolved"; readonly auth: AuthContext }
  | { readonly outcome: "unknown" }
  | { readonly outcome: "key_suspended"; readonly reason: "disabled" | "revoked" | "expired" }
  | { readonly outcome: "static_key_disabled" }
  | { readonly outcome: "static_key_expired" }
  | { readonly outcome: "token_budget_exhausted" }
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
 * PORT-TODO(inventory-edge-control §5.2): the `*_API_KEYS` vars are the
 * bootstrap/config-key path only. The durable virtual-key store moves to D1 via
 * `@ferrogate/storage`, and the worker transport secret to Secrets Store, as
 * soon as those packages land.
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
}

/** Per-request context values set by the middleware chain. */
export interface GatewayVariables {
  requestId: string;
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
