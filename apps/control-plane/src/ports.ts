/**
 * Narrow local interfaces `apps/control-plane` codes against (dependency
 * inversion).
 *
 * The wave-2 packages (`@ferrogate/storage`, `policy`, `secrets`, `config`,
 * `billing`, `observability`) are still being written concurrently, so nothing
 * here may reach into their internals. This module declares the *smallest*
 * surface the control plane needs; a later slice supplies adapters that
 * implement these ports on top of D1 / KV / Secrets Store, with no change to
 * the middleware or the route modules.
 *
 * The vocabulary is ported from the Rust authorization model in
 * `crates/ferrogate-gateway/src/auth.rs` (`AuthContext`, `CallerScope`,
 * `AuthError`), `crates/ferrogate-storage/src/lifecycle_gate.rs`, and the admin
 * handler family in `crates/ferrogate-gateway/src/server/*.rs`.
 */
import type { ApiOperation } from "./contract.js";
import type { SiteDomainTxtResolver } from "./site_domain_txt.js";

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
 * is confined to one tenant. An unclassified credential is a tenant, never
 * root — that asymmetry is what stops an unscoped key from reading every
 * tenant's admin surface.
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
 * scope. That asymmetry is load-bearing on this Worker in particular: every
 * operation it serves is `admin.read`/`admin.write`, so a durable/virtual key
 * minted with no scopes must reach none of them. Static config keys are
 * normalized to `["*"]` by their adapter before they ever get here, preserving
 * the operator intent that "no scopes listed" means "all access".
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
 * Outcome of resolving a presented bearer / `x-api-key` credential.
 *
 * The variants encode the Rust 401-vs-403 taxonomy exactly, and this is the
 * single place the **"a suspended native API key is 401, not 403"** invariant
 * lives (`ROUTE-MAP.md` invariant 6):
 *
 * | variant                  | Rust origin                                      | HTTP |
 * |--------------------------|--------------------------------------------------|------|
 * | `unknown`                | no key matched → `invalid_api_key`                | 401  |
 * | `key_suspended`          | durable key `!enabled` / revoked / expired. The   | 401  |
 * |                          | `StorageApiKeyAuthenticator` returns `None`, so   |      |
 * |                          | `authenticate_with_admission` falls through the   |      |
 * |                          | static-config loop to the same `invalid_api_key`  |      |
 * |                          | a typo gets. A suspended key is INDISTINGUISHABLE |      |
 * |                          | from an unknown one — key state is not disclosed. |      |
 * | `static_key_disabled`    | static config key `!enabled`                      | 403  |
 * | `static_key_expired`     | static config key past `expires_at`                | 403  |
 * | `token_budget_exhausted` | `monthly_token_budget == 0`                        | 429  |
 * | `unavailable`            | external auth service unreachable                  | 503  |
 *
 * Distinct again from *tenancy* suspension, which is authenticated-but-
 * forbidden: `403 tenancy_suspended` from {@link TenancyLifecycleGatePort}.
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
 * Rust `ferrogate-storage/src/lifecycle_gate.rs`. A *tenant/project/workspace*
 * whose lifecycle status is suspended or deleted is an authenticated-but-
 * forbidden caller → **403**, with a code naming the root cause.
 *
 * The `"unavailable"` variant is Rust `LifecycleGateError::Unavailable` → a
 * retryable **503 `lifecycle_status_unavailable`**, and it exists for the same
 * reason {@link RbacDecision}'s does: the durable gate reads rows, reads can
 * fail, and a failed read must not collapse into `admitted: true`. Rust states
 * the consequence plainly — "fail-open here would hand every suspended tenant a
 * trivial bypass (make the control plane flap and keep serving)" — so the
 * outcome is a distinct variant the type system forces every caller to handle
 * rather than a boolean that has to default one way.
 */
export type LifecycleDecision =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly code: string; readonly message: string }
  | { readonly admitted: "unavailable"; readonly detail: string };

export interface TenancyLifecycleGatePort {
  admit(auth: AuthContext, operation: ApiOperation): Promise<LifecycleDecision>;
}

// ---------------------------------------------------------------------------
// Port: RBAC  (→ @ferrogate/policy)
// ---------------------------------------------------------------------------

/**
 * Evaluates an operation's `rbac_action` for the caller. Rust
 * `require_guardrail_auth`: a declared platform operator skips the check; a
 * tenant-scoped caller must clear its tenant's role grant, and a storage
 * failure is `503`, never an implicit allow.
 */
export type RbacDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly code: string; readonly message: string }
  | { readonly allowed: "unavailable"; readonly detail: string };

export interface RbacAuthorizerPort {
  authorize(auth: AuthContext, rbacAction: string): Promise<RbacDecision>;
}

// ---------------------------------------------------------------------------
// Port: the control-plane store  (→ @ferrogate/storage / D1)
// ---------------------------------------------------------------------------

/**
 * A stored admin record. Every collection is keyed by a string `id`; tenant
 * attribution rides on `tenant_id`, which the store stamps on create and
 * filters on for a tenant-scoped caller.
 */
export interface StoreRecord {
  readonly id: string;
  readonly tenant_id?: string | null;
  readonly [field: string]: unknown;
}

/** Rust `AdminPagination` + the `?search=`/filter query the admin lists accept. */
export interface ListQuery {
  readonly offset: number;
  readonly limit: number;
  /**
   * Rust `admin_list_query::list_response`: an admin list is only *paginated*
   * when the request carried a query string at all; a bare list answers the
   * un-paginated `{object, data}` envelope.
   */
  readonly paginate: boolean;
  readonly search: string | null;
  /** Remaining `?k=v` filters, matched against the record's own fields. */
  readonly filters: Readonly<Record<string, string>>;
}

/** One page of a collection. */
export interface ListPage {
  readonly items: readonly StoreRecord[];
  /** Total BEFORE pagination (Rust `AdminList::paginated`'s `total`). */
  readonly total: number;
}

/**
 * The narrow persistence surface every route module talks to.
 *
 * Deliberately generic over a collection name rather than one method per
 * resource: the 197 operations are overwhelmingly CRUD over ~60 named
 * collections, and a per-resource method-per-operation interface would be the
 * hand-written-197-handlers problem moved down a layer.
 *
 * Every method takes the caller's {@link CallerScope} so tenant isolation is a
 * property of the store, not of each handler — the Rust tree's repeat defect
 * class was a handler that looked a row up by bare id and forgot the tenant
 * check (issues #185/#186).
 */
export interface ControlPlaneStore {
  list(collection: string, scope: CallerScope, query: ListQuery): Promise<ListPage>;
  get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null>;
  /** Insert. Rejects with a `conflict` when `record.id` already exists. */
  create(collection: string, scope: CallerScope, record: StoreRecord): Promise<StoreRecord>;
  /** Full replace of an existing row; `null` when it does not exist / is not visible. */
  replace(
    collection: string,
    scope: CallerScope,
    id: string,
    record: Omit<StoreRecord, "id">,
  ): Promise<StoreRecord | null>;
  /** Shallow merge into an existing row; `null` when it does not exist / is not visible. */
  merge(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
  ): Promise<StoreRecord | null>;
  /** `true` when a row was removed, `false` when it did not exist / is not visible. */
  remove(collection: string, scope: CallerScope, id: string): Promise<boolean>;
  /**
   * Apply several mutations as ONE all-or-nothing unit. See {@link StoreMutation}.
   *
   * Exists because two of this app's writes are a PAIR that must not half-land:
   * a wallet movement is a ledger entry plus the balance it explains
   * (`routes/wallets.ts`). Sequencing two `create`/`merge` calls is atomic only
   * by accident of the isolate being single-threaded; this is atomic by
   * construction, because the D1 implementation is one `batch()` — a real
   * SQLite transaction — with every statement guarded on the revision the read
   * saw.
   *
   * Returns the resulting records positionally, or `null` when a `merge`
   * target does not exist / is not visible to `scope` (in which case NOTHING
   * was written). Rejects with {@link StoreConflictError} when a `create`
   * collides, again having written nothing.
   */
  atomic(
    scope: CallerScope,
    mutations: readonly StoreMutation[],
  ): Promise<readonly StoreRecord[] | null>;
}

/**
 * One leg of an {@link ControlPlaneStore.atomic} unit.
 *
 * Deliberately only `create` and `merge`: those are the two halves of the
 * ledger-plus-balance write. `replace`/`remove` are not part of any atomic pair
 * in this app, and an operation nobody needs is an operation whose concurrency
 * semantics nobody tests.
 */
export type StoreMutation =
  | { readonly kind: "create"; readonly collection: string; readonly record: StoreRecord }
  | {
      readonly kind: "merge";
      readonly collection: string;
      readonly id: string;
      readonly patch: Readonly<Record<string, unknown>>;
    };

/** Thrown by {@link ControlPlaneStore.create} on a duplicate id. */
export class StoreConflictError extends Error {
  override readonly name = "StoreConflictError";
  readonly collection: string;
  readonly id: string;

  constructor(collection: string, id: string) {
    super(`${collection} ${id} already exists`);
    this.collection = collection;
    this.id = id;
  }
}

// ---------------------------------------------------------------------------
// Port: runtime snapshot + metrics  (→ @ferrogate/config + observability)
// ---------------------------------------------------------------------------

/**
 * The counts `GET /admin/v1/status` reports (Rust `AdminStatus`). Kept as a
 * loose record because the real shape is assembled from the config snapshot,
 * which `@ferrogate/config` owns and is still being written.
 */
export interface RuntimeStatus {
  readonly service: string;
  readonly version: string;
  readonly runtime: string;
  readonly snapshot: string;
  readonly [field: string]: unknown;
}

/**
 * Runtime introspection the overview group reads. Rust reads these off
 * `AppState`; on Workers they come from the config snapshot + Analytics Engine.
 */
export interface RuntimeStatusPort {
  status(): Promise<RuntimeStatus>;
  overview(): Promise<Record<string, unknown>>;
  observability(): Promise<readonly Record<string, unknown>[]>;
  /** Prometheus text exposition (`text/plain; version=0.0.4`). */
  metrics(): Promise<string>;
}

// ---------------------------------------------------------------------------
// Composition root
// ---------------------------------------------------------------------------

/** Everything the middleware chain and the route modules need, injected. */
export interface ControlPlaneDeps {
  readonly apiKeys: ApiKeyAuthenticatorPort;
  readonly lifecycle: TenancyLifecycleGatePort;
  readonly rbac: RbacAuthorizerPort;
  readonly store: ControlPlaneStore;
  readonly runtime: RuntimeStatusPort;
  /**
   * The DNS seam `POST /admin/v1/site-domains/{hostname}/verify` resolves the
   * ownership challenge through (`src/site_domain_txt.ts`). A port because the
   * lookup is I/O and because the DEFAULT must be the one that verifies nothing
   * — see {@link UnboundTxtResolver}.
   */
  readonly txtResolver: SiteDomainTxtResolver;
  /**
   * Admin-console origin allowed to drive this API from a browser
   * (Rust `config.admin.cors_allowed_origin`). `null` = no console configured,
   * and then the `OPTIONS /admin/{*rest}` preflight surface DOES NOT EXIST.
   */
  readonly corsAllowedOrigin: string | null;
  /** Rust `storage.admin_list_default_limit` (100) / `admin_list_max_limit` (1000). */
  readonly listDefaultLimit: number;
  readonly listMaxLimit: number;
}

// ---------------------------------------------------------------------------
// Worker bindings + per-request variables
// ---------------------------------------------------------------------------

/**
 * Worker bindings this app reads.
 *
 * The credential vars below are now the FALLBACK, not the path: `resolveApiKeys`
 * resolves operator keys from the control database's hashed `static_api_keys`
 * table and consults these only when the database has no matching row (see
 * `src/store/api_keys.ts`).
 *
 * PORT-TODO(inventory-edge-control §6) — PLATFORM LIMIT, sharpened: the admin
 * JWT signing secret cannot follow them into Secrets Store from inside this
 * app. A `[[secrets_store_secrets]]` binding is resolved at DEPLOY time and
 * `@ferrogate/secrets`' Cloudflare client needs an account-scoped token, so
 * there is no runtime "fetch this secret by name" call a Worker can make
 * offline; the local test runtime (`wrangler dev --local` / vitest-pool-workers)
 * has no Secrets Store emulation at all. What IS implemented is the half that
 * does not need it: no credential is stored in plaintext any more — the durable
 * table holds `"sha256:"`-tagged digests and a bare/plaintext value in that
 * column can only ever deny.
 */
export interface ControlPlaneBindings {
  /**
   * JSON array of durable/native virtual keys, the DECLARATIVE fallback for the
   * one leg the control database cannot answer — see the platform-limit
   * PORT-TODO in `src/store/api_keys.ts` (a virtual key's scopes live in the
   * per-tenant database, and D1 bindings resolve at deploy time).
   */
  readonly CONTROL_PLANE_NATIVE_API_KEYS?: string;
  /** JSON array of operator-authored static config keys; fallback for `static_api_keys`. */
  readonly CONTROL_PLANE_STATIC_API_KEYS?: string;
  /**
   * JSON map of tenant id → lifecycle status (`active`/`suspended`/`deleted`),
   * the FALLBACK for a deployment whose tenancy hierarchy is not in the control
   * database yet. `resolveLifecycle` builds `StoreTenancyLifecycleGate` over the
   * `tenant-accounts`/`projects`/`workspaces` rows the admin surface itself
   * writes and consults this only when the caller's declared chain resolves to
   * no row at all (see `src/store/lifecycle.ts`).
   */
  readonly TENANCY_LIFECYCLE?: string;
  /** JSON map of tenant id → granted RBAC actions. */
  readonly TENANT_RBAC_ACTIONS?: string;
  /** Admin-console origin; absent ⇒ no CORS preflight surface at all. */
  readonly ADMIN_CONSOLE_ALLOWED_ORIGIN?: string;
  /** Seed rows for the in-memory store, as `{ collection: record[] }`. */
  readonly CONTROL_PLANE_SEED?: string;
  /**
   * Which {@link ControlPlaneStore} the composition root builds.
   *
   * `"d1"` (the DEFAULT whenever {@link ControlPlaneBindings.DB} is bound) is
   * the durable store; `"memory"` forces the in-memory reference store even
   * when a D1 binding exists, which is how the unit suites pin behaviour that
   * has nothing to do with persistence. The polarity is deliberate: a
   * deployment that binds a database gets the database, and running without one
   * has to be asked for.
   */
  readonly CONTROL_PLANE_STORE?: string;
  readonly ADMIN_LIST_DEFAULT_LIMIT?: string;
  readonly ADMIN_LIST_MAX_LIMIT?: string;
  /**
   * Which site-domain TXT resolver to build (`src/site_domain_txt.ts`):
   * `"doh"`, `"static"`, or — absent, the DEFAULT — unbound, which verifies
   * nothing. Rust `FERROGATE_SITE_DOMAIN_RESOLVER`.
   */
  readonly SITE_DOMAIN_RESOLVER?: string;
  /** DoH endpoint (`FERROGATE_SITE_DOMAIN_RESOLVER_ENDPOINT`). */
  readonly SITE_DOMAIN_RESOLVER_ENDPOINT?: string;
  /** DoH request timeout in ms (`FERROGATE_SITE_DOMAIN_RESOLVER_TIMEOUT_SECS`). */
  readonly SITE_DOMAIN_RESOLVER_TIMEOUT_MS?: string;
  /**
   * The curated `<name> <value>` answer document for the `"static"` resolver —
   * the Workers stand-in for Rust's zone FILE, since a Worker has no filesystem.
   */
  readonly SITE_DOMAIN_TXT_ANSWERS?: string;
  /**
   * The control database (`[[d1_databases]] binding = "DB"` in
   * `wrangler.toml`) — the native replacement for BOTH the D1 REST client and
   * the `workers/d1-proxy` batch/`RETURNING` hot path.
   *
   * `resolveDeps` builds {@link ControlPlaneStore} on it (`src/store/d1.ts`)
   * unless {@link ControlPlaneBindings.CONTROL_PLANE_STORE} explicitly asks for
   * `"memory"`.
   *
   * REQUIRED. The TS-era migrations shipped (`sql/d1-ts/control/`, which
   * `wrangler.toml` names as `migrations_dir`), so there is no longer a
   * "database not provisioned yet" state to accommodate, and `resolveStore`
   * REFUSES a deployment that binds no database instead of silently serving the
   * in-memory store — writes that a 201 acknowledged and the next isolate
   * eviction discards are the worst failure this app has, because nothing about
   * it is visible until the data is already gone. Running without a database is
   * still possible and is now something an operator has to ASK for, by name:
   * `CONTROL_PLANE_STORE = "memory"`.
   */
  readonly DB: D1Database;
}

/** Per-request context values set by the middleware chain. */
export interface ControlPlaneVariables {
  requestId: string;
  /** Canonicalized request path (`/control/v1/*` folded onto `/admin/v1/*`). */
  canonicalPath: string;
  operation: ApiOperation | null;
  auth: AuthContext | null;
  deps: ControlPlaneDeps;
}

/** The Hono generic for every control-plane route and middleware. */
export type ControlPlaneEnv = {
  Bindings: ControlPlaneBindings;
  Variables: ControlPlaneVariables;
};
