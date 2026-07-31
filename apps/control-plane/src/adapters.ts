/**
 * The composition root: binding-backed implementations of the ports.
 *
 * These are the *bootstrap* adapters — they read declarative JSON from Worker
 * vars so the control plane runs, is testable, and behaves correctly today,
 * while `@ferrogate/storage` (D1), `@ferrogate/policy` (RBAC) and
 * `@ferrogate/secrets` (Secrets Store) are written concurrently. Swapping in
 * the real backends touches ONLY this file: nothing in `middleware/` or
 * `routes/` knows where a key comes from.
 *
 * PORT-TODO(inventory-edge-control §5.2): replace `JsonApiKeyAuthenticator`
 * with the D1-backed `StorageApiKeyAuthenticator` twin (prefix lookup +
 * constant-time hash verify) and move the credential material into Secrets
 * Store; replace `JsonRbacAuthorizer` with `@ferrogate/policy`'s role
 * resolution.
 */
import type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AuthContext,
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
import { MemoryControlPlaneStore, type MemoryStoreSeed } from "./store/memory.js";

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
function secretsEqual(a: string, b: string): boolean {
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

/** Rust `LifecycleStatus`. */
export type LifecycleStatus = "active" | "disabled" | "suspended" | "deleted";

/**
 * `TENANCY_LIFECYCLE` is `{ "<tenant_id>": "suspended" }`.
 *
 * `disabled` is admitted ONLY on the lifecycle-reversal operations (#514,
 * finding 5): a tenant that used its self-service `disabled` switch on the
 * project its session key is scoped to must still be able to turn it back on,
 * or the switch is a one-way door. `suspended`/`deleted` remain platform
 * actions a tenant cannot self-serve out of.
 */
const RECOVERY_OPERATION_IDS = new Set([
  "updateTenantAccount",
  "replaceTenantAccount",
  "updateProject",
  "replaceProject",
  "updateWorkspace",
  "replaceWorkspace",
]);

export class JsonTenancyLifecycleGate implements TenancyLifecycleGatePort {
  readonly #statuses: Readonly<Record<string, LifecycleStatus>>;

  constructor(statuses: Readonly<Record<string, LifecycleStatus>>) {
    this.#statuses = statuses;
  }

  admit(auth: AuthContext, operation: { operationId: string }): Promise<LifecycleDecision> {
    const tenantId = auth.tenancy.tenantId;
    if (tenantId === null) return Promise.resolve({ admitted: true });
    const status = this.#statuses[tenantId] ?? "active";

    if (status === "active") return Promise.resolve({ admitted: true });
    if (status === "disabled") {
      if (RECOVERY_OPERATION_IDS.has(operation.operationId)) {
        return Promise.resolve({ admitted: true });
      }
      return Promise.resolve({
        admitted: false,
        code: "tenancy_disabled",
        message: `tenancy ${tenantId} is disabled`,
      });
    }
    return Promise.resolve({
      admitted: false,
      code: status === "deleted" ? "tenancy_deleted" : "tenancy_suspended",
      message: `tenancy ${tenantId} is ${status}`,
    });
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

// ---------------------------------------------------------------------------
// Runtime status + metrics
// ---------------------------------------------------------------------------

export const SERVICE_NAME = "ferrogate-control-plane";

/**
 * PORT-TODO(inventory-edge-control §4): source these from the live config
 * snapshot (`@ferrogate/config`) and Analytics Engine (`@ferrogate/observability`)
 * instead of the store. The SHAPE is the Rust `AdminStatus`/Prometheus
 * exposition, so consumers do not change when the sources are wired.
 */
export class StoreRuntimeStatus implements RuntimeStatusPort {
  readonly #store: ControlPlaneStore;
  readonly #version: string;

  constructor(store: ControlPlaneStore, version = "0.0.0") {
    this.#store = store;
    this.#version = version;
  }

  async #count(collection: string): Promise<number> {
    const page = await this.#store.list(
      collection,
      { kind: "platform_operator" },
      { offset: 0, limit: Number.MAX_SAFE_INTEGER, paginate: false, search: null, filters: {} },
    );
    return page.total;
  }

  async status(): Promise<RuntimeStatus> {
    const [providers, models, apiKeys, promptTemplates, plugins, tools] = await Promise.all([
      this.#count("providers"),
      this.#count("models"),
      this.#count("api-keys"),
      this.#count("prompt-templates"),
      this.#count("plugins"),
      this.#count("tools"),
    ]);
    return {
      service: SERVICE_NAME,
      version: this.#version,
      // Rust reports `"pingora"`; the data plane is a Hono Worker now and
      // reporting otherwise would be a lie an operator could act on.
      runtime: "workers",
      snapshot: "unversioned",
      providers,
      models,
      api_keys: apiKeys,
      prompt_templates: promptTemplates,
      plugins,
      tools,
      auth_required: true,
    };
  }

  async overview(): Promise<Record<string, unknown>> {
    return { object: "overview", status: await this.status() };
  }

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
 * Build the dependency set for one request from the Worker's bindings.
 *
 * The store is a module-level singleton per isolate so state survives across
 * requests (an in-memory store rebuilt per request would make every write
 * invisible to the next read). Everything else is cheap and rebuilt per call.
 */
let sharedStore: MemoryControlPlaneStore | null = null;
let sharedStoreSeed: string | undefined;

export function resolveDeps(env: ControlPlaneBindings): ControlPlaneDeps {
  if (sharedStore === null || sharedStoreSeed !== env.CONTROL_PLANE_SEED) {
    sharedStore = new MemoryControlPlaneStore(
      parseJson<MemoryStoreSeed>(env.CONTROL_PLANE_SEED, {}),
    );
    sharedStoreSeed = env.CONTROL_PLANE_SEED;
  }

  const corsAllowedOrigin = env.ADMIN_CONSOLE_ALLOWED_ORIGIN?.trim();
  return {
    apiKeys: new JsonApiKeyAuthenticator(
      parseJson<NativeKeyDeclaration[]>(env.CONTROL_PLANE_NATIVE_API_KEYS, []),
      parseJson<StaticKeyDeclaration[]>(env.CONTROL_PLANE_STATIC_API_KEYS, []),
    ),
    lifecycle: new JsonTenancyLifecycleGate(
      parseJson<Record<string, LifecycleStatus>>(env.TENANCY_LIFECYCLE, {}),
    ),
    rbac: new JsonRbacAuthorizer(
      parseJson<Record<string, readonly string[]>>(env.TENANT_RBAC_ACTIONS, {}),
    ),
    store: sharedStore,
    runtime: new StoreRuntimeStatus(sharedStore),
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
