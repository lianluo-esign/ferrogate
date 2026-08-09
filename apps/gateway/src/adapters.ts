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
 * THREE of the four ports have since grown a DURABLE leg, each in front of its
 * config table: {@link D1RbacAuthorizer} (CONTROL D1
 * Permission → Role → TenantRoleBinding), {@link D1TenancyLifecycleGate} (the
 * full tenant → project → workspace `status` walk across CONTROL + TENANT D1)
 * and, from `./keys/`, `d1ApiKeyResolverFromEnv` (TENANT D1 `api_keys`). See
 * {@link depsFromEnv} — and note that the two GRANT tables compose by
 * fallback while the one DENY table composes by {@link denyIfEitherDenies}.
 *
 * PORT-TODO(P: inventory-edge-control §5.2): the SELF-HOSTED WORKER TRANSPORT
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
import {
  DurableObjectTenantDatabaseRouter,
  type LifecycleStatus as LifecycleStatusValue,
  type TenantDatabaseRouter,
  backfillTenantConfigurationPolicy,
  lifecycleStatusAllowsRecovery,
  lifecycleStatusAllowsRequests,
  parseLifecycleStatus,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import type { ApiOperation } from "./contract.js";
import { controlDatabaseFrom } from "./control-data.js";
import { d1ApiKeyResolverFromEnv } from "./keys/index.js";
import type { TenancyBindings } from "./tenancy/ports.js";
import { parseTenantDatabaseRoutingMode, resolverForEnv } from "./tenancy/resolver.js";
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
  /**
   * #678 — the attribution tags this credential stands for, defaulted onto a
   * request whose tenant policy says `default_from_key`. The durable twin is
   * `api_keys.attribution_tags_json` (`keys/store.ts`).
   */
  readonly attribution_tags?: Readonly<Record<string, string>>;
}

/**
 * A configured key's `attribution_tags`, keeping only string→string entries.
 *
 * A var is operator-authored JSON with no schema behind it, so a number or a
 * nested object would otherwise reach `Usage.metadata` and from there
 * `billing_events.event_json`. Dropping non-strings rather than stringifying
 * them means a malformed entry cannot SATISFY a required tag — it stays missing
 * and the request is refused, which is the fail-closed direction for this
 * control.
 */
function attributionTagsOf(record: ApiKeyRecord): Readonly<Record<string, string>> | undefined {
  const raw = record.attribution_tags;
  if (typeof raw !== "object" || raw === null) return undefined;
  const tags: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "string" && value !== "") tags[key] = value;
  }
  return Object.keys(tags).length === 0 ? undefined : tags;
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
    ...(attributionTagsOf(record) === undefined
      ? {}
      : { attributionTags: attributionTagsOf(record) }),
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
 * The seven data-plane inference scopes, spelled out. It is not `["*"]` and it
 * is not the empty set — an empty native scope set already means "data-plane
 * scopes, never `admin.*`" (`hasScope`), but naming them makes the grant
 * auditable and keeps a dev key off every non-inference operation too.
 *
 * `audio.create` (issue #703) is on the list because a developer wiring the
 * audio surface end to end needs to reach it; leaving it off would make the one
 * credential this file exists to provide useless for the newest surface, which
 * is precisely how a hand-edited `GATEWAY_NATIVE_API_KEYS` gets committed.
 */
export const DEV_API_KEY_SCOPES: readonly string[] = [
  "models.read",
  "chat.completions",
  "responses.create",
  "messages.create",
  "embeddings.create",
  "images.generate",
  "audio.create",
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

/**
 * Re-exported from `@ferrogate/storage` so this file has ONE vocabulary.
 *
 * It used to be a private copy of the same four strings. That is exactly the
 * duplication that lets one half of a decision drift from the other, and the
 * chain walk below reads statuses out of three different tables — so the parse
 * and the three seam predicates all come from the crate that owns the column.
 */
export type { LifecycleStatus } from "@ferrogate/storage";

/**
 * Which #514 seam an authentication runs — Rust `LifecycleAdmission`
 * (`auth.rs:1159`) over `ferrogate_storage::LifecycleSeam`.
 *
 * `"request"` is every ordinary route: `suspended`, `disabled` and `deleted`
 * all deny. `"recovery"` is the handful of routes that exist to turn an OFF
 * hierarchy back ON, where `disabled` — the tenant's own self-service switch —
 * is admitted and nothing else is.
 *
 * Rust carries it as a parameter chosen at the CALL SITE rather than derived
 * inside the gate, because `finalize_auth` is reached from every auth source
 * and knows nothing about routing. This port has the opposite shape: the guard
 * is table-driven off the contract and already holds the matched
 * {@link ApiOperation}, so the same choice is expressed as a table of
 * `operation_id`s. Same decision, same three routes, read from the contract
 * instead of from three hand-edited handler bodies.
 */
export type LifecycleSeam = "request" | "recovery";

/**
 * The contract operations that run the RECOVERY seam.
 *
 * Rust calls `authenticate_for_lifecycle_recovery` from exactly three handler
 * arms (`server/virtual_keys.rs:435/1194/1819`), each of which serves
 * `Method::PUT | Method::PATCH` on a tenant-account / project / workspace row.
 * The TS contract splits every PUT/PATCH pair into two operation ids, so three
 * Rust arms are the four ids below plus the tenant-account pair, which the
 * runtime contract does not publish on this Worker (`/admin/v1/tenants` is
 * list-only here) — naming an id that does not exist would be a lie, so the set
 * carries what the contract actually has.
 *
 * Why the carve-out is scoped to these and not to the whole deny set: the
 * alternative — dropping `disabled` from the request-time deny list entirely —
 * would let a disabled project keep serving `/v1/chat/completions`, which is
 * the whole point of the switch. Scoping it to the reversal routes keeps the
 * switch real AND keeps it reversible; without it a tenant that disabled the
 * project its console key is scoped to could never reach the PUT that undoes
 * it (a one-way door out of a reversible state — Rust #514 finding 5).
 */
export const LIFECYCLE_RECOVERY_OPERATIONS: ReadonlySet<string> = new Set([
  "replaceProject",
  "updateProject",
  "replaceWorkspace",
  "updateWorkspace",
]);

/** Rust `LifecycleAdmission::seam`, resolved from the matched operation. */
export function lifecycleSeamFor(operation: ApiOperation | undefined): LifecycleSeam {
  return operation !== undefined && LIFECYCLE_RECOVERY_OPERATIONS.has(operation.operationId)
    ? "recovery"
    : "request";
}

/** Rust `LifecycleSeam::allows`. */
export function lifecycleSeamAllows(seam: LifecycleSeam, status: LifecycleStatusValue): boolean {
  return seam === "recovery"
    ? lifecycleStatusAllowsRecovery(status)
    : lifecycleStatusAllowsRequests(status);
}

/** One resolved ancestor in the chain — Rust `LifecycleRef`. */
export interface LifecycleRef {
  /** `"tenant"` / `"project"` / `"workspace"`, used verbatim in the message. */
  readonly kind: "tenant" | "project" | "workspace";
  readonly id: string;
  readonly status: LifecycleStatusValue;
}

/**
 * Rust `LifecycleRejection::code` — distinguishable per state, so a client can
 * tell "your account is suspended, pay the bill" from "this project is off".
 *
 * The `Attach` seam's `inactive_tenancy_reference` is deliberately absent: that
 * seam is row CREATION (minting a key under an existing hierarchy), which this
 * Worker's request-time guard never runs.
 */
export function lifecycleRejectionCode(status: LifecycleStatusValue): string {
  switch (status) {
    case "suspended":
      return "tenancy_suspended";
    case "disabled":
      return "tenancy_disabled";
    case "deleted":
      return "tenancy_deleted";
    default:
      // Unreachable: an active status never produces a rejection. Kept total
      // rather than thrown so a future variant cannot turn this into a 500.
      return "tenancy_inactive";
  }
}

/** Rust `LifecycleRejection::message` for the Request/Recovery seams. */
export function lifecycleRejectionMessage(reference: LifecycleRef): string {
  return `${reference.kind} ${reference.id} is ${reference.status}; requests authenticated against this tenancy chain are refused`;
}

/**
 * Rust `check_lifecycle_chain`.
 *
 * `chain` MUST be ordered shallowest-first (tenant, then project, then
 * workspace) so the rejection names the ROOT cause: when an operator suspends a
 * tenant and the cascade marks its project and workspace too, the caller is
 * told the TENANT is suspended rather than being sent chasing the workspace.
 * {@link resolveLifecycleChain} is the only supported way to build one.
 */
export function checkLifecycleChain(
  seam: LifecycleSeam,
  chain: readonly LifecycleRef[],
): LifecycleDecision {
  for (const reference of chain) {
    if (!lifecycleSeamAllows(seam, reference.status)) {
      return {
        admitted: false,
        code: lifecycleRejectionCode(reference.status),
        message: lifecycleRejectionMessage(reference),
      };
    }
  }
  return { admitted: true };
}

/**
 * The `tenant → project → workspace` ids a caller declares — Rust
 * `TenancyRefs`. Passed as one value rather than three positional strings that
 * are trivially transposed at a call site.
 */
export interface TenancyRefs {
  readonly tenantId?: string | null | undefined;
  readonly projectId?: string | null | undefined;
  readonly workspaceId?: string | null | undefined;
}

/** Rust `present`: trim, and treat blank as absent. */
function presentId(value: string | null | undefined): string | undefined {
  const trimmed = (value ?? "").trim();
  return trimmed === "" ? undefined : trimmed;
}

function pushUnique(ids: string[], candidate: string | null | undefined): void {
  const value = presentId(candidate);
  if (value === undefined || ids.includes(value)) return;
  ids.push(value);
}

/** A `projects` / `workspaces` / `tenants` row, narrowed to what the gate reads. */
interface LifecycleRow {
  readonly id: string;
  readonly status: string;
  readonly tenant_id?: string | null;
  readonly project_id?: string | null;
}

/**
 * The three row reads {@link resolveLifecycleChain} needs — Rust
 * `LifecycleRowSource`, a trait for the same reason it is an interface here: a
 * test can implement a FAILING source to hold the fail-closed claim. Rust says
 * outright that, as originally landed, no test held it (swapping the error
 * mapping for `unwrap_or_default()` changed no assertion), so
 * `test/lifecycle-chain.test.ts` implements a throwing source and mutation is
 * what proves it bites.
 */
export interface LifecycleRowSource {
  tenantRow(id: string): Promise<LifecycleRow | null>;
  projectRow(id: string): Promise<LifecycleRow | null>;
  workspaceRow(id: string): Promise<LifecycleRow | null>;
}

/**
 * Rust `resolve_lifecycle_chain` — resolve the status of every row in the
 * caller's tenancy chain, shallowest first, **walking the hierarchy rather than
 * the caller's declaration**.
 *
 * That distinction is the whole bug Rust's second landing fixed, and it is
 * reproduced rather than re-derived: three independent lookups that push only
 * the rows the caller NAMED mean a credential declaring only a `project_id`
 * (entirely legal — a native key's tenant id is optional) yields the chain
 * `[project(active)]` and the suspended TENANT above it is never read. So:
 *
 *  1. resolve the declared workspace; its row carries `project_id` and
 *     `tenant_id`, so its ancestors join the chain even when the caller named
 *     neither;
 *  2. resolve every candidate project — the declared one AND the workspace's
 *     parent — each of which carries `tenant_id`;
 *  3. resolve every candidate tenant — the declared one AND every ancestor
 *     discovered above.
 *
 * Declared and derived ids are UNIONed, never substituted: when a caller names
 * a tenant that disagrees with the row's own parent, BOTH are checked and
 * either one being inactive denies. There is no ordering in which a suspended
 * ancestor is skipped.
 *
 * An id that is absent, blank, or names no row is SKIPPED — absence is not
 * suspension. Inventing a denial there would make a typo indistinguishable from
 * a suspension, and the api-key tenancy rules already treat a dangling
 * reference as "resolves to nothing".
 */
export async function resolveLifecycleChain(
  source: LifecycleRowSource,
  refs: TenancyRefs,
): Promise<LifecycleRef[]> {
  const tenantIds: string[] = [];
  const projectIds: string[] = [];
  const workspaceRows: LifecycleRow[] = [];

  pushUnique(tenantIds, refs.tenantId);
  pushUnique(projectIds, refs.projectId);

  const workspaceId = presentId(refs.workspaceId);
  if (workspaceId !== undefined) {
    const workspace = await source.workspaceRow(workspaceId);
    if (workspace !== null) {
      // Backfill from the row itself: this is what makes the walk a walk.
      pushUnique(projectIds, workspace.project_id);
      pushUnique(tenantIds, workspace.tenant_id);
      workspaceRows.push(workspace);
    }
  }

  const projectRows: LifecycleRow[] = [];
  // Indexed, not `for…of`: step 2 appends tenant ids discovered from a project
  // row, and a project row may itself be reached only via the workspace above.
  for (let index = 0; index < projectIds.length; index += 1) {
    const project = await source.projectRow(projectIds[index] as string);
    if (project !== null) {
      pushUnique(tenantIds, project.tenant_id);
      projectRows.push(project);
    }
  }

  const chain: LifecycleRef[] = [];
  for (const tenantId of tenantIds) {
    const tenant = await source.tenantRow(tenantId);
    if (tenant !== null) {
      chain.push({ kind: "tenant", id: tenant.id, status: parseLifecycleStatus(tenant.status) });
    }
  }
  for (const project of projectRows) {
    chain.push({ kind: "project", id: project.id, status: parseLifecycleStatus(project.status) });
  }
  for (const workspace of workspaceRows) {
    chain.push({
      kind: "workspace",
      id: workspace.id,
      status: parseLifecycleStatus(workspace.status),
    });
  }
  return chain;
}

/**
 * The operator-authored `[vars]` lifecycle table — the TENANT tier only.
 *
 * Rust has no config-file lifecycle table at all; this is a port-local
 * bootstrap in the same role `GATEWAY_STATIC_API_KEYS` plays for credentials,
 * and {@link D1TenancyLifecycleGate} is the faithful leg. It is composed with
 * {@link denyIfEitherDenies}, so it can only ever ADD a refusal — never
 * authorize past a durable one.
 */
export class ConfiguredTenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #statuses: Readonly<Record<string, LifecycleStatusValue>>;

  constructor(statuses: Readonly<Record<string, LifecycleStatusValue>>) {
    this.#statuses = statuses;
  }

  static fromEnv(env: GatewayBindings): ConfiguredTenancyLifecycleGate {
    return new ConfiguredTenancyLifecycleGate(
      parseJsonVar<Record<string, LifecycleStatusValue>>(env.TENANCY_LIFECYCLE, {}),
    );
  }

  async admit(auth: AuthContext, operation?: ApiOperation): Promise<LifecycleDecision> {
    const scope = callerScope(auth);
    if (scope.kind === "platform_operator") return { admitted: true };
    const raw = this.#statuses[scope.tenantId];
    if (raw === undefined) return { admitted: true };
    return checkLifecycleChain(lifecycleSeamFor(operation), [
      { kind: "tenant", id: scope.tenantId, status: parseLifecycleStatus(raw) },
    ]);
  }
}

/** Binding name of the TENANT D1 holding `projects` / `workspaces`. */
export const TENANT_DATABASE_BINDING = "DB";

/** The three statements the durable gate issues. Exported so a test can pin them. */
export const LIFECYCLE_TENANT_SQL = "SELECT id, status FROM tenants WHERE id = ?1";
export const LIFECYCLE_PROJECT_SQL = "SELECT id, status, tenant_id FROM projects WHERE id = ?1";
export const LIFECYCLE_WORKSPACE_SQL =
  "SELECT id, status, tenant_id, project_id FROM workspaces WHERE id = ?1";

/** The `D1Database` subset the lifecycle reads need. A live binding fits. */
export interface LifecycleDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): { first(): Promise<unknown> };
  };
}

function isLifecycleDatabase(value: unknown): value is LifecycleDatabase {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as LifecycleDatabase).prepare === "function"
  );
}

function asLifecycleRow(value: unknown): LifecycleRow | null {
  if (typeof value !== "object" || value === null) return null;
  const row = value as Record<string, unknown>;
  if (typeof row.id !== "string") return null;
  return {
    id: row.id,
    // A NULL/absent `status` is not a decision — `parseLifecycleStatus` reads
    // it as `active` (the fail-OPEN read default #514 chose deliberately, so
    // the decorative pre-#514 rows do not revoke every existing tenant).
    status: typeof row.status === "string" ? row.status : "",
    tenant_id: typeof row.tenant_id === "string" ? row.tenant_id : null,
    project_id: typeof row.project_id === "string" ? row.project_id : null,
  };
}

/**
 * The two-database row source: `tenants` lives in CONTROL, `projects` and
 * `workspaces` are TENANT data (see the split rule in `sql/d1-ts/`).
 */
export class D1LifecycleRowSource implements LifecycleRowSource {
  readonly #control: LifecycleDatabase | undefined;
  readonly #tenant: LifecycleDatabase | undefined;

  constructor(control: LifecycleDatabase | undefined, tenant: LifecycleDatabase | undefined) {
    this.#control = control;
    this.#tenant = tenant;
  }

  async tenantRow(id: string): Promise<LifecycleRow | null> {
    if (this.#control === undefined) return null;
    return asLifecycleRow(await this.#control.prepare(LIFECYCLE_TENANT_SQL).bind(id).first());
  }

  async projectRow(id: string): Promise<LifecycleRow | null> {
    if (this.#tenant === undefined) return null;
    return asLifecycleRow(await this.#tenant.prepare(LIFECYCLE_PROJECT_SQL).bind(id).first());
  }

  async workspaceRow(id: string): Promise<LifecycleRow | null> {
    if (this.#tenant === undefined) return null;
    return asLifecycleRow(await this.#tenant.prepare(LIFECYCLE_WORKSPACE_SQL).bind(id).first());
  }
}

/**
 * Rust `check_usable_tenancy` over D1 — the full tenant → project → workspace
 * walk, at the request-time seam.
 *
 * Three departures, all stated:
 *
 *  - a **platform operator** is waved through before any query, matching every
 *    Rust call site (an operator key carries no tenancy chain, so Rust never
 *    gates it either);
 *  - a **lookup failure** answers `admitted: "unavailable"` → 503
 *    `lifecycle_status_unavailable`, and does NOT fall through to the config
 *    table. This is `LifecycleGateError::Unavailable`, and Rust names the
 *    reason: fail-open would hand every suspended tenant a trivial bypass;
 *  - the `projects` / `workspaces` reads go to the DEFAULT `DB` binding, and
 *    since #819 that is A KNOWN GAP rather than the shipped posture. Under
 *    `GATEWAY_TENANT_DB_ROUTING = "off"` `DB` IS the tenant database and this
 *    walk is complete; under the `durable_object` default the rows live in the
 *    tenant's own object, so this gate reads a `DB` that a routed deployment
 *    never writes and every tenant looks un-suspended to it unless the
 *    `TENANCY_LIFECYCLE` config table names them.
 *
 *    The ordering is what makes it a gap rather than a bug to fix here:
 *    `src/tenancy/` resolves AFTER this guard, deliberately, because the router
 *    can refuse a tenant and running it inside the auth guard would turn an
 *    unresolvable tenant into an authentication failure. The lifecycle rows
 *    have to be PROJECTED into the control plane next to `tenants`, which is
 *    what `docs/design/tenant-data-classification-2026-08.md` classifies them
 *    for. See {@link lifecycleRowSourceFromEnv} for the one line that changes.
 */
/**
 * A row source for ONE resolved credential. A FACTORY rather than a fixed source
 * because the `projects` / `workspaces` tier is routed to the caller's OWN
 * tenant object (#821), and the routing tenant is not known until the request's
 * `AuthContext` exists. A deployment on the `"off"` posture passes a factory
 * that ignores the argument (the shared `env.DB` source), so the legacy posture
 * is a special case of the same shape.
 */
export type LifecycleRowSourceFactory = (routingTenantId: string | null) => LifecycleRowSource;

export class D1TenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #sourceFor: LifecycleRowSourceFactory;

  constructor(source: LifecycleRowSource | LifecycleRowSourceFactory) {
    // A plain source is wrapped into a constant factory, so the unit tests that
    // hand in a fixed `rowSource(...)` and the routed `fromEnv` path share one
    // `admit` body.
    this.#sourceFor = typeof source === "function" ? source : () => source;
  }

  /** `null` when NO lifecycle authority is bound, so the caller keeps its config path. */
  static fromEnv(env: Record<string, unknown>): D1TenancyLifecycleGate | null {
    const factory = lifecycleRowSourceFactoryFromEnv(env);
    return factory === null ? null : new D1TenancyLifecycleGate(factory);
  }

  async admit(auth: AuthContext, operation?: ApiOperation): Promise<LifecycleDecision> {
    const scope = callerScope(auth);
    if (scope.kind === "platform_operator") return { admitted: true };

    // The tenant `projects`/`workspaces` reads route to THIS caller's object.
    // A credential pinned to the empty-string tenant routes nowhere and the
    // factory hands back the shared source — the pre-routing behaviour.
    const source = this.#sourceFor(scope.tenantId);
    let chain: readonly LifecycleRef[];
    try {
      chain = await resolveLifecycleChain(source, {
        tenantId: auth.tenancy.tenantId,
        projectId: auth.tenancy.projectId,
        workspaceId: auth.tenancy.workspaceId,
      });
    } catch (error) {
      return {
        admitted: "unavailable",
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    return checkLifecycleChain(lifecycleSeamFor(operation), chain);
  }
}

/**
 * The shared `env.DB` row source — `tenants` in CONTROL, `projects`/`workspaces`
 * in the shared `DB`. `null` when neither is bound.
 *
 * This is the `"off"`/`"shared_development"` arm the later stanza-removal PR
 * deletes; the routed default reaches for the caller's object instead — see
 * {@link lifecycleRowSourceFactoryFromEnv}.
 */
export function lifecycleRowSourceFromEnv(env: Record<string, unknown>): LifecycleRowSource | null {
  const control = controlDatabaseFrom(env);
  const tenant = env[TENANT_DATABASE_BINDING];
  const controlDb = isLifecycleDatabase(control) ? control : undefined;
  const tenantDb = isLifecycleDatabase(tenant) ? tenant : undefined;
  if (controlDb === undefined && tenantDb === undefined) return null;
  return new D1LifecycleRowSource(controlDb, tenantDb);
}

/**
 * The per-credential row-source factory (#821 PR2a).
 *
 * Under the routed default (`durable_object`/`binding*` WITH a `TENANT_DATA`
 * namespace) the `projects`/`workspaces` reads resolve the caller tenant's own
 * database through the SAME `resolverForEnv` router `tenantDatabaseOf(c)` uses —
 * so a suspended project/workspace is seen in the object the control plane
 * actually writes, not the shared `env.DB` a routed deployment never touches.
 * `tenants` stays a CONTROL read on every arm.
 *
 * ## Why an UNROUTABLE tenant falls back to `env.DB` rather than 503ing
 *
 * This gate runs INSIDE `contractAuth`, BEFORE `src/tenancy/` resolves — so a
 * tenant the router cannot place (no `tenant_databases` roster row, i.e. one not
 * yet cut over to a durable object) must not become a lifecycle 503 on every
 * request, which is the exact hazard `D1TenancyLifecycleGate`'s own docblock
 * names ("running the router inside the auth guard would turn an unresolvable
 * tenant into an authentication failure"). A ROUTING failure therefore falls
 * back to the shared `env.DB` source — the pre-cutover behaviour, unchanged for
 * those tenants — while a provisioned durable tenant reads its object and a REAL
 * object outage (the handle resolved, the statement threw) still propagates as a
 * 503. Money paths do NOT take this fallback; a lifecycle READ against the
 * pre-cutover shared row is not the cross-tenant money hazard the wallet is.
 *
 * The `"off"`/`"shared_development"` postures, and any deployment that binds no
 * `TENANT_DATA`, keep reading `env.DB` — the arm the later stanza-removal PR
 * deletes, and what keeps `env.DB` declared-and-read here.
 *
 * `null` — no authority at all — is preserved exactly: neither a control
 * database nor a shared `env.DB` nor a `TENANT_DATA` namespace bound.
 */
export function lifecycleRowSourceFactoryFromEnv(
  env: Record<string, unknown>,
): LifecycleRowSourceFactory | null {
  const control = controlDatabaseFrom(env);
  const controlDb = isLifecycleDatabase(control) ? control : undefined;
  const legacy = lifecycleRowSourceFromEnv(env);
  const routingRaw = env.GATEWAY_TENANT_DB_ROUTING;
  const mode = parseTenantDatabaseRoutingMode(
    typeof routingRaw === "string" ? routingRaw : undefined,
  );
  const tenantDataBound = env.TENANT_DATA !== undefined;
  const routed =
    mode !== undefined && mode !== "off" && mode !== "shared_development" && tenantDataBound;

  if (legacy === null && !routed) return null;
  if (!routed) return () => legacy as LifecycleRowSource;

  const sharedFallback = legacy ?? new D1LifecycleRowSource(controlDb, undefined);
  return (routingTenantId: string | null): LifecycleRowSource => {
    if (routingTenantId === null || routingTenantId === "") return sharedFallback;
    // Resolve the tenant's own object, or `null` when it is not routable yet
    // (no roster row) — in which case the shared source below answers instead.
    // Only the ROUTING is guarded; a statement that throws after the handle
    // resolved is a real outage and propagates.
    const routedDb = async (): Promise<D1Database | null> => {
      try {
        return (await resolverForEnv(env as unknown as TenancyBindings).forTenant(routingTenantId))
          .db;
      } catch {
        return null;
      }
    };
    return {
      async tenantRow(id: string): Promise<LifecycleRow | null> {
        if (controlDb === undefined) return null;
        return asLifecycleRow(await controlDb.prepare(LIFECYCLE_TENANT_SQL).bind(id).first());
      },
      async projectRow(id: string): Promise<LifecycleRow | null> {
        const db = await routedDb();
        if (db === null) return sharedFallback.projectRow(id);
        return asLifecycleRow(await db.prepare(LIFECYCLE_PROJECT_SQL).bind(id).first());
      },
      async workspaceRow(id: string): Promise<LifecycleRow | null> {
        const db = await routedDb();
        if (db === null) return sharedFallback.workspaceRow(id);
        return asLifecycleRow(await db.prepare(LIFECYCLE_WORKSPACE_SQL).bind(id).first());
      },
    };
  };
}

/**
 * Compose two lifecycle gates so a refusal from EITHER refuses, and an outage
 * from either is an outage.
 *
 * This is deliberately NOT the `durable-first, fall back on not-found` shape
 * that {@link D1RbacAuthorizer} and the key resolver use, and the asymmetry is
 * the point: RBAC and credentials are GRANT tables, where a second source can
 * only widen, so consulting the fallback on a miss is safe. A lifecycle table
 * is a DENY table. "Fall back when the durable leg admitted" would mean the
 * `TENANCY_LIFECYCLE` var could never suspend a tenant that D1 says is active,
 * and "stop when the durable leg admitted" would mean the var could never
 * suspend anything at all once `CONTROL_DB` is bound — silently disarming the
 * operator's own kill switch the day a binding lands.
 */
export function denyIfEitherDenies(
  ...gates: readonly TenancyLifecycleGatePort[]
): TenancyLifecycleGatePort {
  return {
    async admit(auth: AuthContext, operation: ApiOperation): Promise<LifecycleDecision> {
      for (const gate of gates) {
        const decision = await gate.admit(auth, operation);
        if (decision.admitted !== true) return decision;
      }
      return { admitted: true };
    },
  };
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

/** The two statements `D1RbacAuthorizer` issues. Exported so a test can pin them. */
export const RBAC_PERMISSION_EXISTS_SQL = "SELECT 1 AS present FROM permissions WHERE key = ?1";
// ONE template literal rather than the `"SELECT …" + "FROM …"` concatenation
// this used to be, and the change is load-bearing rather than cosmetic:
// `test/fleet-control-matrix.test.ts` derives which durable authority each
// Worker reads by scanning SQL string literals that carry BOTH the verb and the
// table, so a statement split across fragments is invisible to it and this
// Worker scored as reading neither `tenant_role_bindings` nor `roles` — i.e.
// the fleet gate could not see the gateway enforcing the control it defines.
// The SQL is unchanged apart from whitespace.
export const RBAC_TENANT_ROLE_GRANTS_SQL = `SELECT roles.permission_keys_json AS permission_keys_json
     FROM tenant_role_bindings
     JOIN roles ON roles.id = tenant_role_bindings.role_id
    WHERE tenant_role_bindings.tenant_id = ?1`;

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
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as RbacDatabase).prepare === "function"
  );
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
  readonly #tenantDatabases: TenantDatabaseRouter | undefined;

  constructor(
    db: RbacDatabase,
    options: {
      fallback?: RbacAuthorizerPort | undefined;
      tenantDatabases?: TenantDatabaseRouter | undefined;
    } = {},
  ) {
    this.#db = db;
    this.#fallback = options.fallback;
    this.#tenantDatabases = options.tenantDatabases;
  }

  /** `null` when `CONTROL_DB` is unbound, so the caller keeps its config path. */
  static fromEnv(
    env: Record<string, unknown>,
    options: {
      fallback?: RbacAuthorizerPort | undefined;
      tenantDatabases?: TenantDatabaseRouter | undefined;
    } = {},
  ): D1RbacAuthorizer | null {
    const binding = controlDatabaseFrom(env);
    if (!isRbacDatabase(binding)) return null;
    const namespace = env.TENANT_DATA as TenantDataNamespace | undefined;
    const tenantDatabases =
      options.tenantDatabases ??
      (namespace === undefined
        ? undefined
        : new DurableObjectTenantDatabaseRouter(namespace, binding as D1Database));
    return new D1RbacAuthorizer(binding, { ...options, tenantDatabases });
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
    const grants =
      this.#tenantDatabases === undefined
        ? await this.#db.prepare(RBAC_TENANT_ROLE_GRANTS_SQL).bind(tenantId).all()
        : await this.#tenantRoleGrants(tenantId);
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

  /**
   * The tenant-local binding is authoritative after #863. The shared roles
   * catalog is still checked in CONTROL so a stale object snapshot can never
   * mint a grant after an operator deletes the role.
   */
  async #tenantRoleGrants(tenantId: string): Promise<{ results: unknown[] }> {
    const router = this.#tenantDatabases;
    if (router === undefined) throw new Error("tenant object router is not configured");
    await backfillTenantConfigurationPolicy(this.#db as unknown as D1Database, router, tenantId);
    const handle = await router.forTenant(tenantId);
    const local = await handle.db
      .prepare(
        `SELECT b.role_id
           FROM tenant_role_bindings AS b
          WHERE b.tenant_id = ?1`,
      )
      .bind(tenantId)
      .all<{ role_id: string }>();
    const valid: unknown[] = [];
    for (const row of local.results) {
      const shared = await this.#db
        .prepare("SELECT permission_keys_json FROM roles WHERE id = ?1")
        .bind(row.role_id)
        .all();
      const role = (shared.results ?? [])[0] as { permission_keys_json?: unknown } | undefined;
      if (role !== undefined) {
        valid.push({
          permission_keys_json:
            typeof role.permission_keys_json === "string" ? role.permission_keys_json : null,
        });
      }
    }
    return { results: valid };
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
 * PORT-TODO(P: inventory-edge-control §self-hosted worker transport): the Rust
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
 *
 * `lifecycle` composes rather than falls back, because it is a DENY table and
 * not a grant table — see {@link denyIfEitherDenies} for why the two shapes
 * must not be confused. With neither D1 bound the durable leg is `null` and the
 * composition is exactly the config gate, so a binding-free deployment behaves
 * as it did before this leg existed.
 */
export function depsFromEnv(env: GatewayBindings): GatewayDeps {
  const configured = ConfiguredApiKeyAuthenticator.fromEnv(env);
  const configuredRbac = ConfiguredRbacAuthorizer.fromEnv(env);
  const configuredLifecycle = ConfiguredTenancyLifecycleGate.fromEnv(env);
  const durableLifecycle = D1TenancyLifecycleGate.fromEnv(
    env as unknown as Record<string, unknown>,
  );
  return {
    apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured,
    lifecycle:
      durableLifecycle === null
        ? configuredLifecycle
        : denyIfEitherDenies(durableLifecycle, configuredLifecycle),
    rbac:
      D1RbacAuthorizer.fromEnv(env as unknown as Record<string, unknown>, {
        fallback: configuredRbac,
      }) ?? configuredRbac,
    internalTransport: ConfiguredInternalTransport.fromEnv(env),
  };
}
