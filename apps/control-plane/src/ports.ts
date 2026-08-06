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
import type { PromptLabelKv } from "@ferrogate/config";
import type { TenantDatabaseRouter, TenantObjectOperator } from "@ferrogate/storage";
// TYPE-ONLY, and it must stay that way: `@ferrogate/storage/durable-objects`
// imports `DurableObject` from `cloudflare:workers`, which resolves in workerd
// and nowhere else. A value import here would break `apps/cli` and every plain
// node importer of this module's siblings.
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import type { ApiOperation } from "./contract.js";
import type { SiteDomainCertificatePort } from "./site_domain_certificates.js";
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
 * resource: the 214 operations are overwhelmingly CRUD over ~60 named
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
  /**
   * A CONDITIONAL merge: apply `patch` only while the stored row still satisfies
   * `precondition`, decided against the same snapshot the write is guarded on.
   *
   * This is the port's compare-and-set, and it exists because
   * `get` → decide → `merge` is **not** one. Two requests that read the same row
   * both decide "yes" and both write; a rate limit built that way admits a
   * concurrent burst that it was written to refuse. `routes/site_domain.ts` is
   * the case that forced it — #576 requires that an `admin.write` credential
   * cannot drive unbounded outbound DNS, and the cooldown slot has to be
   * *reserved*, not merely checked.
   *
   * The contract both stores implement:
   *
   *  - `precondition` runs on the CURRENT stored record;
   *  - if it holds, the patch is applied atomically with respect to that exact
   *    record — a writer that commits in between makes this attempt fail and
   *    re-evaluate `precondition` against the state that writer left, never
   *    against the stale snapshot;
   *  - `precondition` must therefore be PURE and cheap: it is called once per
   *    attempt, and an impure one would make the retry observable.
   *
   * The outcome is a discriminated union rather than `null` because
   * "no such row" (→ 404) and "the row says no" (→ 429/409) are different
   * answers, and collapsing them is how a rate limit reports itself as a
   * missing resource.
   */
  mergeIf(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
    precondition: (current: StoreRecord) => boolean,
  ): Promise<MergeIfOutcome>;
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

/** The three answers {@link ControlPlaneStore.mergeIf} can give. */
export type MergeIfOutcome =
  | { readonly kind: "merged"; readonly record: StoreRecord }
  /** No such row, or not visible to `scope` — the same fact `merge`'s `null` is. */
  | { readonly kind: "not_found" }
  /**
   * The row exists and the precondition did not hold. `current` is the record
   * the refusal was decided against, so a caller can label it (how long is left
   * on a cooldown, which generation it lost to) instead of guessing.
   */
  | { readonly kind: "precondition_failed"; readonly current: StoreRecord };

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

/**
 * The asset bucket, narrowed to DELETE (#743's force-delete).
 *
 * A method-by-method narrowing of `R2Bucket`, and the narrowing is the security
 * decision rather than a typing convenience. `admin_asset.ts`'s whole read side
 * is built on "metadata is not content": the inventory withholds `storage_uri`
 * so this surface can never become the first half of an exfiltration path. A
 * bare `R2Bucket` on {@link ControlPlaneDeps} would put `get()` — every tenant's
 * asset bytes, including the ones the #366 screener is withholding — one line
 * away from any handler on this Worker, and the next endpoint to reach for it
 * would compile. This port cannot read; it can only reclaim.
 *
 * `null` (no `ASSETS` binding) is NOT a degraded posture here and must not be
 * treated as one: the force-delete answers `503` and deletes NOTHING, because a
 * metadata-only delete would report `deleted` while the bytes stayed in the
 * bucket — a takedown that took nothing down, and the reason the verb was
 * deferred in the first place.
 */
export interface AssetObjectReclaimer {
  /** Delete these object keys. Idempotent: an absent key is not an error. */
  delete(keys: readonly string[]): Promise<void>;
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
  /**
   * `@ferrogate/storage`'s `TenantDatabaseRouter` — the tenantId → per-tenant D1
   * handle seam, and the reason the database-per-tenant directive is in effect
   * on this Worker at all.
   *
   * The control plane is where a tenant's hierarchy is MINTED, so it is where
   * the typed per-tenant tables (`projects`, `workspaces`, `api_keys` in
   * `sql/d1-ts/tenant/`) get their rows. Before this seam existed the admin
   * surface wrote only the account-global `control_plane_resources` document and
   * the tenant databases stayed empty, which made two package-level guards
   * unreachable: `D1ReferenceGuardedDeletes` (a project deleted out from under a
   * live workspace) and everything downstream that reads those tables.
   *
   * `forTenant` NEVER falls back. A tenant with no registry row throws
   * `StorageError` `not_found`; one whose `binding_name` is absent or names a
   * non-D1 binding throws `runtime`. `src/store/tenancy.ts` is the single place
   * that decides what those two mean for an admin request, and the split there
   * is load-bearing — see its docblock.
   */
  readonly tenantDatabases: TenantDatabaseRouter;
  /**
   * The router tenant STORAGE PROVISIONING runs through (#820) — the Durable
   * Object namespace when {@link ControlPlaneBindings.TENANT_DATA} is bound,
   * otherwise the same router as {@link ControlPlaneDeps.tenantDatabases}.
   *
   * Optional so that a test composing a partial `deps` literal keeps compiling;
   * {@link resolveDeps} always sets it. `provisionTenantStorageFor` falls back to
   * `tenantDatabases` when it is absent, which is the correct answer for any
   * deployment that binds no object namespace.
   *
   * The two are separate on purpose and the reason is not tidiness — see
   * `resolveTenantStorage` in `src/adapters.ts` for what closing the gap costs
   * and why it is not this slice.
   */
  readonly tenantStorage?: TenantDatabaseRouter;
  /** Platform-operator-only reads, exports and PITR against a tenant object. */
  readonly tenantObjectOperator?: TenantObjectOperator | null;
  /**
   * The CONTROL database itself, or `null` when this deployment is running
   * without one (`CONTROL_PLANE_STORE = "memory"`, or no `DB` binding).
   *
   * Distinct from {@link ControlPlaneDeps.store} on purpose: the store is a
   * DOCUMENT abstraction over `control_plane_resources` and is deliberately
   * swappable, while a handful of surfaces must also write the TYPED tables in
   * the same database that OTHER Workers read by name. Today that is
   * `self_hosted_worker_registrations` — the row
   * `apps/agent-runtime`'s `d1WorkerIdentityPort` authenticates the six
   * `/v1/self-hosted-workers/*` internal callbacks against (see
   * `src/store/worker_registry.ts`).
   *
   * `null` is not a silent downgrade: the routes that need it answer `503`
   * rather than writing only the document, because a worker that appears
   * registered and can authenticate nobody is the failure this seam exists to
   * remove.
   */
  readonly controlDatabase: D1Database | null;
  /**
   * The legacy shared tenant database used only by the #824 backfill and by
   * tenants whose migration state is still pre-cutover. It is deliberately
   * separate from `controlDatabase`: the former contains tenant business rows,
   * while the latter contains the account-global registry and audit chain.
   */
  readonly legacyTenantDatabase?: D1Database | null;
  /**
   * The KV namespace `apps/gateway` resolves prompt deployment labels from
   * (`PROMPT_LABELS`), or `null` when this deployment binds none.
   *
   * The label RECORD is a store document like every other admin resource; this
   * is the EDGE POINTER that makes a label readable on the inference hot path
   * without a database round trip per request.
   *
   * `null` is not a silent downgrade. `routes/prompt.ts` answers `503` rather
   * than writing only the document, for the same reason
   * {@link ControlPlaneDeps.controlDatabase} does: a label the operator is told
   * moved, that the data plane never sees, is worse than a refusal — the
   * operator's next action is to stop looking.
   */
  readonly promptLabels: PromptLabelKv | null;
  /**
   * The delete-only handle on the asset bucket (`ASSETS`), or `null` when this
   * deployment binds none — see {@link AssetObjectReclaimer} for why it is
   * narrowed and why `null` is a refusal rather than a degradation.
   */
  readonly assetObjects: AssetObjectReclaimer | null;
  readonly runtime: RuntimeStatusPort;
  /**
   * The DNS seam `POST /admin/v1/site-domains/{hostname}/verify` resolves the
   * ownership challenge through (`src/site_domain_txt.ts`). A port because the
   * lookup is I/O and because the DEFAULT must be the one that verifies nothing
   * — see {@link UnboundTxtResolver}.
   */
  readonly txtResolver: SiteDomainTxtResolver;
  /**
   * The CERTIFICATE seam `GET /admin/v1/site-domains/{hostname}` reports
   * `certificate_status` through (#738, `src/site_domain_certificates.ts`).
   *
   * A port for the same two reasons the resolver above is one — the lookup is
   * outbound I/O, and the DEFAULT must be the one that claims to know nothing.
   * It is NOT the same seam: DNS ownership decides whether the gateway serves,
   * and a certificate decides whether the request ever reaches it. Neither
   * implies the other and nothing here may ever gate a serving decision.
   */
  readonly siteDomainCertificates: SiteDomainCertificatePort;
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
 * PORT-TODO(L: inventory-edge-control §6) — PLATFORM LIMIT, sharpened: the admin
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
   * JSON array of durable/native virtual keys — now the FALLBACK, not the path.
   *
   * `D1NativeApiKeyAuthenticator` (`src/store/api_keys.ts`) resolves a virtual
   * key from `api_key_directory` in the control database plus the `api_keys` row
   * in that tenant's OWN database, reached through `@ferrogate/storage`'s tenant
   * router. This var is consulted only for a credential neither table knows,
   * exactly like its static and lifecycle siblings — so a stale var can never
   * re-enable a key the database revoked.
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
   * Which site-domain CERTIFICATE backend to build
   * (`src/site_domain_certificates.ts`): `"cloudflare_for_saas"`, `"static"`,
   * or — absent, the DEFAULT — unconfigured, which reports that this deployment
   * cannot tell. A separate switch from {@link SITE_DOMAIN_RESOLVER} because
   * they answer different questions (#738).
   */
  readonly SITE_DOMAIN_CERTIFICATES?: string;
  /**
   * The curated `hostname -> custom_hostnames row` table for the `"static"`
   * certificate backend, in Cloudflare's own result shape.
   */
  readonly SITE_DOMAIN_CERTIFICATE_RECORDS?: string;
  /**
   * The Cloudflare zone the custom hostnames live on — the FALLBACK-ORIGIN zone
   * in this account that every tenant CNAMEs at, never a tenant's own zone.
   */
  readonly SITE_DOMAIN_CF_ZONE_ID?: string;
  /** The Cloudflare account id the zone belongs to. */
  readonly SITE_DOMAIN_CF_ACCOUNT_ID?: string;
  /**
   * The Cloudflare API token, as a `wrangler secret put` binding. Never a
   * `[vars]` entry — that file is committed plaintext.
   */
  readonly SITE_DOMAIN_CF_API_TOKEN?: string;
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
  /**
   * The old shared tenant D1 (`apps/gateway`'s `DB`), exposed to the control
   * plane only for the resumable #824 migration path. It must never be used as
   * the control database or as an implicit fallback for an unregistered tenant.
   */
  readonly LEGACY_TENANT_DB?: D1Database;
  /**
   * The gateway's `TenantDataObject` namespace, bound CROSS-SCRIPT (#820).
   *
   * The same namespace `apps/gateway` binds, reached with
   * `script_name = "ferrogate-gateway"` — so `idFromName(tenantId)` names the
   * SAME object from both Workers. That identity is the whole point: this app
   * mints a tenant, and the object it provisions has to be the one the data
   * plane will later read. A second, locally-defined namespace would give every
   * tenant two disjoint databases and the failure would look like data loss.
   *
   * OPTIONAL, and its absence is a real deployment posture rather than an
   * oversight: a `native_binding` (single-tenant / self-hosted) deployment has
   * no tenant object namespace at all, and under that topology onboarding
   * genuinely still requires a `wrangler deploy` to add the tenant's
   * `[[d1_databases]]` stanza — there is nothing this Worker could provision.
   * `resolveTenantDatabases` picks the router from this binding's presence.
   */
  readonly TENANT_DATA?: TenantDataNamespace;
  /**
   * The prompt-label KV namespace (`[[kv_namespaces]] binding = "PROMPT_LABELS"`).
   *
   * The SAME namespace `apps/gateway` reads. Both sides derive the key with
   * `promptLabelPointerKey` from `@ferrogate/config`, so the only way to break
   * the link is to bind two different namespace ids at deploy time — which is
   * why both `wrangler.toml`s say so where an operator will read it.
   */
  readonly PROMPT_LABELS?: KVNamespace;
  /**
   * The audit-anchor bucket (`[[r2_buckets]] binding = "AUDIT_ANCHORS"`) — the
   * tamper-evidence half that does not live in the database (#684).
   *
   * `src/audit/anchor.ts` writes one small object per audit chain per new head,
   * and never overwrites one. OPTIONAL, and absent is a supported degraded
   * posture: the hash chain still detects an edited or mid-trail-deleted row
   * from an export alone, but a TAIL deletion and a wholesale re-forge both
   * leave a perfect chain and are only caught by comparing against a head
   * published outside the database. The scheduled tick reports
   * `audit_anchor: "unconfigured"` so the gap is visible in a tail log rather
   * than silent.
   */
  readonly AUDIT_ANCHORS?: R2Bucket;
  /**
   * The SIEM export sinks (#683) — a JSON array declaring where this
   * deployment pushes evidence, parsed by `src/siem/config.ts`.
   *
   * Absent or `"[]"` means NO EGRESS, which is the default posture: evidence
   * leaving the platform is an operator decision, never an accident of
   * deployment. Every sink names a TENANT (a sink without one does not parse)
   * and carries its credential as an `env://` REFERENCE, never a literal — this
   * var is committed plaintext in `wrangler.toml`, so a literal here would be a
   * credential in git.
   */
  readonly SIEM_EXPORT_SINKS?: string;
  /**
   * The R2 bucket an `{"kind":"r2"}` sink writes NDJSON batches into (#683).
   *
   * Separate from {@link ControlPlaneBindings.AUDIT_ANCHORS} on purpose: the
   * anchor bucket exists to be un-writable by anyone who could edit the
   * database, and pointing bulk evidence export at the same bucket would give
   * the export path write access to the tamper-evidence store. Absent is
   * supported — an `r2` sink then reports a failed delivery, and its cursor
   * does not move, so nothing is lost.
   */
  readonly SIEM_EXPORTS?: R2Bucket;
  /**
   * The ASSET bucket (`[[r2_buckets]] binding = "ASSETS"`) — the SAME bucket
   * `apps/gateway` holds every hosted artifact's bytes in.
   *
   * Read through {@link AssetObjectReclaimer} and nothing else, so this Worker
   * can delete an object and cannot fetch one; `src/adapters.ts` does the
   * narrowing at the composition root. It exists for exactly one operation,
   * `DELETE /admin/v1/assets/{asset_id}`, because a force-delete that leaves the
   * bytes behind is not a takedown.
   *
   * ABSENT IS A REFUSAL, not a degraded mode: that operation answers `503` and
   * writes nothing. Every other operation on this Worker is unaffected.
   */
  readonly ASSETS?: R2Bucket;
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
