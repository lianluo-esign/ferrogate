/**
 * Narrow local interfaces this Worker codes against (dependency inversion).
 *
 * Wave-2 packages (`@ferrogate/storage`, `policy`, `secrets`, `config`,
 * `billing`, `observability`) are still being written concurrently, so nothing
 * here may reach into their internals. `apps/agent-runtime` therefore declares
 * the SMALLEST surface it needs, plus in-memory defaults good enough to run the
 * whole lifecycle offline. A later slice supplies adapters over the real
 * packages with no change to the routes.
 *
 * The shapes are ported from:
 *  - `crates/ferrogate-gateway/src/auth.rs`            → `AuthContext`, `ApiKeyResolution`
 *  - `crates/ferrogate-runtime/src/self_hosted_worker.rs`
 *      → `SelfHostedWorkerIdentity`, `SelfHostedWorkerRegistry::validate_identity`,
 *        `SelfHostedTransportPolicy`, `SelfHostedTelemetryTrustLevel`
 *  - `crates/agent-worker/src/external_actions.rs`     → the capability envelope
 *  - `workers/agent-gateway/src/container.ts`          → the sealed-egress posture
 */
import { timingSafeEqualStrings } from "./crypto.js";

// ---------------------------------------------------------------------------
// Worker environment
// ---------------------------------------------------------------------------

/** Bindings + vars declared in `wrangler.toml`. */
export interface AgentRuntimeBindings {
  /** Per-`${tenant_id}:${run_id}` run state + event fan-out. */
  readonly AGENT_RUN_STATE: DurableObjectNamespace;
  /** Per-`${tenant_id}:${workspace_id}` self-hosted dispatch queue. */
  readonly WORKER_PLANE: DurableObjectNamespace;
  /** DEV/TEST ONLY: install the in-memory port bundle. Absent ⇒ fail closed. */
  readonly FG_DEV_IN_MEMORY_PORTS?: string;
  /** `"1"` selects the Rust `RequireProductionMtls` transport posture. */
  readonly FG_REQUIRE_PRODUCTION_MTLS?: string;
  /** Comma-separated bare hostnames. EMPTY MEANS SEALED (#471). */
  readonly CONTAINER_GOVERNED_EGRESS_HOSTS?: string;
  /** Operator override of Rust `AGENT_JOB_MAX_OPEN_PER_TENANT` (default 200). */
  readonly AGENT_JOB_MAX_OPEN_PER_TENANT?: string;
  /** Operator override of Rust `AGENT_JOB_DISPATCH_TTL_SECS` (default 24h). */
  readonly AGENT_JOB_DISPATCH_TTL_SECS?: string;
  /** `"0"` disables every run/job verb (`403 agent_runtime_disabled`). */
  readonly AGENT_RUNTIME_ENABLED?: string;
  /** DEV/TEST ONLY: JSON array of `RegisteredSelfHostedWorker` rows. */
  readonly FG_DEV_SELF_HOSTED_WORKERS?: string;
  /** DEV/TEST ONLY: JSON array of `DevApiKey` rows. */
  readonly FG_DEV_API_KEYS?: string;
  /** DEV/TEST ONLY: JSON array of `AgentUpstream` rows. */
  readonly FG_DEV_AGENT_UPSTREAMS?: string;
}

/** Hono `Env` for this Worker: bindings + the per-request variables we set. */
export interface AgentRuntimeEnv {
  readonly Bindings: AgentRuntimeBindings;
  Variables: {
    requestId: string;
    traceId?: string;
    /** Set by the bearer leg of `middleware/auth.ts`. Never set for internal ops. */
    auth?: AuthContext;
    /** Set by the internal leg. Never set for tenant-bearer ops. */
    worker?: RegisteredSelfHostedWorker;
    /** The matched contract operation. */
    operationId?: string;
    deps?: AgentRuntimeDeps;
  };
}

// ---------------------------------------------------------------------------
// Tenant identity (bearer leg)
// ---------------------------------------------------------------------------

/** Tenancy attribution carried by a resolved tenant credential. */
export interface Tenancy {
  readonly tenantId: string | null;
  readonly workspaceId?: string | null;
  readonly projectId?: string | null;
  readonly userId?: string | null;
}

/** A successfully authenticated tenant caller (Rust `AuthContext`). */
export interface AuthContext {
  /** RBAC subject / api-key id, when the credential carries one. */
  readonly subject: string | null;
  readonly tenancy: Tenancy;
  /** Granted scopes. `"*"` is the wildcard. */
  readonly scopes: readonly string[];
  readonly platformOperator: boolean;
}

/**
 * Outcome of resolving a presented tenant API key.
 *
 * `unknown` and `key_suspended` are DELIBERATELY distinct inputs that the
 * middleware collapses onto the SAME `401 invalid_api_key` — the Rust durable
 * authenticator returns `None` for a suspended/revoked/expired native key, so
 * key state is never disclosed. (Static operator-authored config keys are the
 * documented exception and report 403.) Preserving that asymmetry here is what
 * keeps the 401-vs-403 defect class from reappearing.
 */
export type ApiKeyResolution =
  | { readonly outcome: "resolved"; readonly auth: AuthContext }
  | { readonly outcome: "unknown" }
  | { readonly outcome: "key_suspended" }
  | { readonly outcome: "static_key_disabled" }
  | { readonly outcome: "static_key_expired" }
  | { readonly outcome: "tenancy_suspended" }
  | { readonly outcome: "unavailable"; readonly detail: string };

/** Resolves a presented tenant bearer / `x-api-key` credential. */
export interface ApiKeyPort {
  resolve(presentedKey: string): Promise<ApiKeyResolution>;
}

// ---------------------------------------------------------------------------
// Self-hosted worker identity (internal leg)
// ---------------------------------------------------------------------------

/**
 * Rust `SelfHostedWorkerIdentity`. `token_id` is a NON-SECRET lookup key;
 * `token_secret` is the 256-bit CSPRNG value from
 * `generate_transport_token_secret`. They are different values on purpose: the
 * pre-fix Rust wiring reused the public fingerprint as the secret, which made
 * the AEAD/bearer key public and let anyone forge frames.
 */
export interface SelfHostedWorkerIdentity {
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly token_id: string;
  readonly token_secret: string;
  /** Worker-reported clock, checked against `identity_expires_at_unix`. */
  readonly observed_at_unix?: number;
}

/** Rust `RegisteredSelfHostedWorker` (the secret stays inside the registry). */
export interface RegisteredSelfHostedWorker {
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly framework_adapter: string;
  readonly token_id: string;
  readonly identity_expires_at_unix: number | null;
  readonly capabilities: readonly string[];
  readonly active: boolean;
}

/** Registry row including the secret — never leaves `ports.ts`. */
interface RegistryRow extends RegisteredSelfHostedWorker {
  readonly token_secret: string;
}

/** Rust `SelfHostedWorkerError` variants the transport leg can surface. */
export type WorkerIdentityFailure =
  | { readonly reason: "invalid_shape"; readonly detail: string }
  | { readonly reason: "unknown_worker" }
  | { readonly reason: "inactive_worker" }
  | { readonly reason: "invalid_identity"; readonly detail: string }
  | { readonly reason: "unavailable"; readonly detail: string };

export type WorkerIdentityResolution =
  | { readonly outcome: "resolved"; readonly worker: RegisteredSelfHostedWorker }
  | { readonly outcome: "rejected"; readonly failure: WorkerIdentityFailure };

/**
 * The worker-plane credential authority. This is the ONLY authority the six
 * internal callbacks consult — there is no code path from a tenant API key to
 * a `RegisteredSelfHostedWorker`, which is precisely ROUTE-MAP invariant 2.
 */
export interface WorkerIdentityPort {
  validate(identity: SelfHostedWorkerIdentity): Promise<WorkerIdentityResolution>;
}

// ---------------------------------------------------------------------------
// Governance: capability envelope, isolation, egress (agent-worker)
// ---------------------------------------------------------------------------

/**
 * Rust `ClientActionIdentity` (inventory-edge-control §"action_identity"): a
 * REQUIRED transport argument so no verb is unattributable. `action_id` is the
 * caller's idempotent handle; the fingerprint is the canonical-target digest an
 * ALLOW decision binds to.
 */
export interface ActionIdentity {
  readonly action_id: string;
  /** `sha256:<64 hex>` — Rust `ACTION_FINGERPRINT_CONTRACT`. */
  readonly canonical_target_sha256: string | null;
  readonly client_clock_unix: number | null;
  readonly server_time_token: string | null;
}

/** What the caller asked the isolation tier to be allowed to do. */
export interface CapabilityRequest {
  readonly tenantId: string;
  readonly workspaceId: string;
  readonly frameworkAdapter: string;
  readonly requiredCapabilities: readonly string[];
  /** Bare hostnames the workload wants outbound access to. */
  readonly egressAllowlist: readonly string[];
  /** `sha256:<hex>` of the UPSTREAM governed action, when this is a child (#307). */
  readonly parentActionFingerprint: string | null;
}

/** A governance refusal, rendered verbatim by the route. */
export interface GovernanceDenial {
  readonly status: 403 | 422;
  readonly code: string;
  readonly message: string;
}

/**
 * The isolation posture actually granted. Rust offers four backends
 * (Firecracker microVM / Docker / `unshare` local-process / Cloudflare
 * Containers). Only the last has a CF equivalent.
 */
export interface IsolationGrant {
  /** Always `cloudflare_sandbox` on this platform. */
  readonly backend: "cloudflare_sandbox";
  /** Pinned `false` — load-bearing #471. */
  readonly enableInternet: false;
  /** Pinned `true` — load-bearing #471. */
  readonly interceptHttps: true;
  /** The intersection of the request and the operator allowlist. */
  readonly allowedHosts: readonly string[];
  /** Rust advertises snapshotting OFF for the CF backend (no CF primitive). */
  readonly snapshotSupported: false;
}

export type GovernanceDecision =
  | { readonly outcome: "allow"; readonly grant: IsolationGrant }
  | { readonly outcome: "deny"; readonly denial: GovernanceDenial };

/**
 * The external-action gate, at the API boundary.
 *
 * In Rust every handler action is authorized over a kernel-authenticated Unix
 * socket (SO_PEERCRED PID check) before execution, and an ALLOW binds to a
 * canonical-target fingerprint. Workers have no Unix sockets and no peer-cred
 * concept, so the transport changes to a bearer/service-binding trust model —
 * but the DECISION logic (capability envelope evaluation, fingerprint binding,
 * sealed-by-default egress) is preserved here rather than dropped.
 *
 * // PORT-TODO(inventory-edge-control §agent-worker §8.3): the SO_PEERCRED
 * // kernel-authenticated authorizer has no CF equivalent. The trust model
 * // changes from "the kernel proved the peer PID" to "the caller presented a
 * // registered worker identity / service binding". Recorded, not silently
 * // dropped — see §8.4 "flag the hardest items" (b).
 */
export interface GovernancePort {
  authorize(request: CapabilityRequest): Promise<GovernanceDecision>;
}

// ---------------------------------------------------------------------------
// Agent upstreams (A2A ingress)
// ---------------------------------------------------------------------------

/** One operator-configured A2A agent upstream (Rust `config.agent_upstreams`). */
export interface AgentUpstream {
  readonly id: string;
  readonly enabled: boolean;
  /** Absolute URL the A2A envelope is forwarded to. */
  readonly url: string;
  /** Tenants the upstream is visible to. Empty ⇒ visible to all. */
  readonly visibleToTenantIds: readonly string[];
  /** `true` when the upstream is only visible to platform operators. */
  readonly operatorOnly: boolean;
}

export interface AgentUpstreamPort {
  lookup(agentId: string): Promise<AgentUpstream | undefined>;
}

// ---------------------------------------------------------------------------
// Operator config
// ---------------------------------------------------------------------------

/** The slice of operator config this Worker reads (Rust `config.agent_runtime`). */
export interface AgentRuntimeConfig {
  /** `false` ⇒ every job/run verb answers `403 agent_runtime_disabled`. */
  readonly enabled: boolean;
  /** Rust `AGENT_JOB_MAX_OPEN_PER_TENANT`. */
  readonly maxOpenJobsPerTenant: number;
  /** Rust `AGENT_JOB_DISPATCH_TTL_SECS`. */
  readonly dispatchTtlSecs: number;
  /** Rust `limits().worker_transport_body_max_bytes()`. */
  readonly workerTransportBodyMaxBytes: number;
  /** Rust `SelfHostedTelemetryIngestor::max_payload_bytes` (64 KiB default). */
  readonly telemetryMaxPayloadBytes: number;
  /** Rust `limits().agent_ingress_body_max_bytes()`. */
  readonly agentIngressBodyMaxBytes: number;
  /** Default framework adapter for a submission that names none. */
  readonly defaultFrameworkAdapter: string;
}

export interface ConfigPort {
  agentRuntime(): AgentRuntimeConfig;
}

// ---------------------------------------------------------------------------
// Clock (injectable so lease expiry is testable without sleeping)
// ---------------------------------------------------------------------------

export interface ClockPort {
  nowUnix(): number;
}

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

export interface AgentRuntimeDeps {
  readonly apiKeys: ApiKeyPort;
  readonly workerIdentities: WorkerIdentityPort;
  readonly governance: GovernancePort;
  readonly upstreams: AgentUpstreamPort;
  readonly config: ConfigPort;
  readonly clock: ClockPort;
}

// ---------------------------------------------------------------------------
// In-memory defaults
// ---------------------------------------------------------------------------

/** Rust `SELF_HOSTED_WORKER_PROTOCOL_VERSION`. */
export const SELF_HOSTED_WORKER_PROTOCOL_VERSION = 1;

/** Rust `SelfHostedTelemetryTrustLevel` — one variant, and it is not "trusted". */
export const REPORTED_BY_SELF_HOSTED_WORKER = "reported_by_self_hosted_worker" as const;
export type SelfHostedTelemetryTrustLevel = typeof REPORTED_BY_SELF_HOSTED_WORKER;

export const DEFAULT_AGENT_RUNTIME_CONFIG: AgentRuntimeConfig = {
  enabled: true,
  maxOpenJobsPerTenant: 200,
  dispatchTtlSecs: 24 * 60 * 60,
  workerTransportBodyMaxBytes: 1024 * 1024,
  telemetryMaxPayloadBytes: 64 * 1024,
  agentIngressBodyMaxBytes: 1024 * 1024,
  defaultFrameworkAdapter: "native",
};

/** A dev/test API key row (`FG_DEV_API_KEYS`). */
export interface DevApiKey {
  readonly key: string;
  readonly subject?: string;
  readonly tenantId: string;
  readonly workspaceId?: string;
  readonly scopes?: readonly string[];
  readonly platformOperator?: boolean;
  /** Native/durable key state. `suspended` collapses to 401, never 403. */
  readonly state?: "active" | "suspended";
  /** Operator-authored static config key: reports 403 when disabled/expired. */
  readonly staticState?: "disabled" | "expired";
  readonly tenancySuspended?: boolean;
}

/** In-memory {@link ApiKeyPort} over a static table. */
export function inMemoryApiKeyPort(keys: readonly DevApiKey[]): ApiKeyPort {
  const byKey = new Map(keys.map((row) => [row.key, row]));
  return {
    async resolve(presentedKey: string): Promise<ApiKeyResolution> {
      const row = byKey.get(presentedKey);
      if (row === undefined) return { outcome: "unknown" };
      if (row.staticState === "disabled") return { outcome: "static_key_disabled" };
      if (row.staticState === "expired") return { outcome: "static_key_expired" };
      // The load-bearing asymmetry: a suspended NATIVE key is indistinguishable
      // from an unknown one.
      if (row.state === "suspended") return { outcome: "key_suspended" };
      if (row.tenancySuspended === true) return { outcome: "tenancy_suspended" };
      return {
        outcome: "resolved",
        auth: {
          subject: row.subject ?? row.key,
          tenancy: { tenantId: row.tenantId, workspaceId: row.workspaceId ?? null },
          scopes: row.scopes ?? [],
          platformOperator: row.platformOperator ?? false,
        },
      };
    },
  };
}

/** A dev/test registry row (`FG_DEV_SELF_HOSTED_WORKERS`). */
export interface DevSelfHostedWorker {
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly framework_adapter: string;
  readonly token_id: string;
  readonly token_secret: string;
  readonly identity_expires_at_unix?: number | null;
  readonly capabilities?: readonly string[];
  readonly active?: boolean;
}

/** Rust `normalized_capabilities`: trimmed, lowercased, deduped, sorted. */
export function normalizedCapabilities(
  capabilities: readonly string[] | undefined,
): readonly string[] {
  const seen = new Set<string>();
  for (const raw of capabilities ?? []) {
    const value = raw.trim().toLowerCase();
    if (value !== "") seen.add(value);
  }
  return [...seen].sort();
}

/** Rust `worker_key` — the registry is keyed by the full tenancy triple. */
function workerKey(tenantId: string, workspaceId: string, workerId: string): string {
  return `${tenantId}${workspaceId}${workerId}`;
}

/**
 * Rust `validate_identity_shape`: every field non-blank. A blank field can
 * never be a real registration, and rejecting it before the lookup keeps a
 * partially-filled envelope from matching a partially-filled row.
 */
function identityShapeError(identity: SelfHostedWorkerIdentity): string | null {
  const fields: ReadonlyArray<[string, unknown]> = [
    ["tenant_id", identity.tenant_id],
    ["workspace_id", identity.workspace_id],
    ["worker_id", identity.worker_id],
    ["token_id", identity.token_id],
    ["token_secret", identity.token_secret],
  ];
  for (const [name, value] of fields) {
    if (typeof value !== "string" || value.trim() === "") {
      return `self-hosted worker identity ${name} must not be empty`;
    }
  }
  return null;
}

/**
 * In-memory {@link WorkerIdentityPort} — a faithful port of Rust
 * `SelfHostedWorkerRegistry::validate_identity`, including the constant-time
 * secret comparison (#114): a differing-PREFIX attempt must not be
 * distinguishable from a differing-SUFFIX one by response timing.
 *
 * An EMPTY table rejects everything. That is the fail-closed default: a
 * deployment that forgets to bind the real registry admits no worker at all
 * rather than admitting any caller.
 */
export function inMemoryWorkerIdentityPort(
  workers: readonly DevSelfHostedWorker[],
): WorkerIdentityPort {
  const rows = new Map<string, RegistryRow>();
  for (const worker of workers) {
    rows.set(workerKey(worker.tenant_id, worker.workspace_id, worker.worker_id), {
      tenant_id: worker.tenant_id,
      workspace_id: worker.workspace_id,
      worker_id: worker.worker_id,
      framework_adapter: worker.framework_adapter,
      token_id: worker.token_id,
      token_secret: worker.token_secret,
      identity_expires_at_unix: worker.identity_expires_at_unix ?? null,
      capabilities: normalizedCapabilities(worker.capabilities),
      active: worker.active ?? true,
    });
  }

  return {
    async validate(identity: SelfHostedWorkerIdentity): Promise<WorkerIdentityResolution> {
      const shape = identityShapeError(identity);
      if (shape !== null) {
        return { outcome: "rejected", failure: { reason: "invalid_shape", detail: shape } };
      }
      const row = rows.get(
        workerKey(identity.tenant_id, identity.workspace_id, identity.worker_id),
      );
      if (row === undefined) {
        return { outcome: "rejected", failure: { reason: "unknown_worker" } };
      }
      if (!row.active) {
        return { outcome: "rejected", failure: { reason: "inactive_worker" } };
      }
      // `token_id` is a non-secret lookup key; only `token_secret` needs the
      // constant-time path. Both must match.
      const secretMatches = timingSafeEqualStrings(row.token_secret, identity.token_secret);
      if (row.token_id !== identity.token_id || !secretMatches) {
        return {
          outcome: "rejected",
          failure: {
            reason: "invalid_identity",
            detail: "worker token does not match registered identity envelope",
          },
        };
      }
      if (
        row.identity_expires_at_unix !== null &&
        typeof identity.observed_at_unix === "number" &&
        identity.observed_at_unix >= row.identity_expires_at_unix
      ) {
        return {
          outcome: "rejected",
          failure: { reason: "invalid_identity", detail: "worker identity has expired" },
        };
      }
      const { token_secret: _secret, ...worker } = row;
      return { outcome: "resolved", worker };
    },
  };
}

/**
 * In-memory {@link GovernancePort}: the capability-envelope + sealed-egress
 * decision, with no isolation host to drive.
 *
 * `governedEgressHosts` EMPTY MEANS SEALED (#471): with no authorized host
 * every workload starts with no egress at all and any `egressAllowlist` request
 * is refused 422. A forgotten configuration must fail closed.
 */
export function inMemoryGovernancePort(options: {
  readonly governedEgressHosts: readonly string[];
  /** Capabilities the platform is willing to grant. `["*"]` grants all. */
  readonly grantableCapabilities?: readonly string[];
}): GovernancePort {
  const allowedHosts = new Set(
    options.governedEgressHosts.map((host) => host.trim().toLowerCase()).filter((h) => h !== ""),
  );
  const grantable = normalizedCapabilities(options.grantableCapabilities ?? ["*"]);
  const grantsAll = grantable.includes("*");

  return {
    async authorize(request: CapabilityRequest): Promise<GovernanceDecision> {
      // #307: a declared parent identity must be a canonical fingerprint. A
      // malformed one is rejected rather than persisted.
      const parent = request.parentActionFingerprint;
      if (parent !== null && !isCanonicalActionFingerprint(parent)) {
        return {
          outcome: "deny",
          denial: {
            status: 422,
            code: "invalid_parent_action_fingerprint",
            message: "parent_action_fingerprint must be sha256:<64 lowercase hex>",
          },
        };
      }

      if (!grantsAll) {
        const ungrantable = normalizedCapabilities(request.requiredCapabilities).filter(
          (capability) => !grantable.includes(capability),
        );
        if (ungrantable.length > 0) {
          return {
            outcome: "deny",
            denial: {
              status: 403,
              code: "capability_not_granted",
              message: `capabilities not granted to this workspace: ${ungrantable.join(", ")}`,
            },
          };
        }
      }

      const requested = request.egressAllowlist
        .map((host) => host.trim().toLowerCase())
        .filter((host) => host !== "");
      const ungoverned = requested.filter((host) => !allowedHosts.has(host));
      if (ungoverned.length > 0) {
        return {
          outcome: "deny",
          denial: {
            status: 422,
            code: "egress_host_not_governed",
            message:
              allowedHosts.size === 0
                ? "no governed egress host is configured; the isolation tier is sealed and no egress may be opened"
                : `egress hosts outside the governed allowlist: ${ungoverned.join(", ")}`,
          },
        };
      }

      return {
        outcome: "allow",
        grant: {
          backend: "cloudflare_sandbox",
          enableInternet: false,
          interceptHttps: true,
          allowedHosts: requested,
          snapshotSupported: false,
        },
      };
    },
  };
}

/** Rust `ACTION_FINGERPRINT_CONTRACT`: `sha256:` + 64 lowercase hex chars. */
export function isCanonicalActionFingerprint(value: string): boolean {
  return /^sha256:[0-9a-f]{64}$/.test(value);
}

/** In-memory {@link AgentUpstreamPort}. */
export function inMemoryAgentUpstreamPort(upstreams: readonly AgentUpstream[]): AgentUpstreamPort {
  const byId = new Map(upstreams.map((upstream) => [upstream.id, upstream]));
  return {
    async lookup(agentId: string): Promise<AgentUpstream | undefined> {
      return byId.get(agentId);
    },
  };
}

/** In-memory {@link ConfigPort}. */
export function inMemoryConfigPort(overrides: Partial<AgentRuntimeConfig> = {}): ConfigPort {
  const config: AgentRuntimeConfig = { ...DEFAULT_AGENT_RUNTIME_CONFIG, ...overrides };
  return { agentRuntime: () => config };
}

/** Wall-clock {@link ClockPort}. */
export const systemClock: ClockPort = {
  nowUnix: () => Math.floor(Date.now() / 1000),
};

// ---------------------------------------------------------------------------
// Dev bundle assembly
// ---------------------------------------------------------------------------

function parseJsonVar<T>(raw: string | undefined, fallback: T): T {
  if (raw === undefined || raw.trim() === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/** Split `CONTAINER_GOVERNED_EGRESS_HOSTS`. Empty ⇒ sealed. */
export function parseGovernedEgressHosts(raw: string | undefined): readonly string[] {
  if (raw === undefined) return [];
  return raw
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host !== "");
}

/** Parse a positive-integer operator var, falling back on anything else. */
function parsePositiveIntVar(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const parsed = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * The operator-tunable slice of {@link AgentRuntimeConfig}, read from `[vars]`.
 *
 * These are real deployment knobs, not test seams: the Rust constants they
 * mirror (`AGENT_JOB_MAX_OPEN_PER_TENANT`, `AGENT_JOB_DISPATCH_TTL_SECS`,
 * `config.agent_runtime.enabled`) were operator-visible there too. Anything
 * unset or unparseable falls back to the Rust default rather than to zero,
 * because a mistyped var must not silently disable the concurrency bound.
 */
export function configFromEnv(env: AgentRuntimeBindings): AgentRuntimeConfig {
  return {
    ...DEFAULT_AGENT_RUNTIME_CONFIG,
    enabled: env.AGENT_RUNTIME_ENABLED?.trim() !== "0",
    maxOpenJobsPerTenant: parsePositiveIntVar(
      env.AGENT_JOB_MAX_OPEN_PER_TENANT,
      DEFAULT_AGENT_RUNTIME_CONFIG.maxOpenJobsPerTenant,
    ),
    dispatchTtlSecs: parsePositiveIntVar(
      env.AGENT_JOB_DISPATCH_TTL_SECS,
      DEFAULT_AGENT_RUNTIME_CONFIG.dispatchTtlSecs,
    ),
  };
}

/**
 * Build the dependency bundle for a request.
 *
 * Returns `undefined` when `FG_DEV_IN_MEMORY_PORTS` is unset and no real
 * adapters are bound — the Worker then fails CLOSED (503) on every
 * authenticated surface rather than defaulting to a permissive stub.
 */
export function resolveDeps(env: AgentRuntimeBindings): AgentRuntimeDeps | undefined {
  if (env.FG_DEV_IN_MEMORY_PORTS !== "1") return undefined;
  return {
    apiKeys: inMemoryApiKeyPort(parseJsonVar<DevApiKey[]>(env.FG_DEV_API_KEYS, [])),
    workerIdentities: inMemoryWorkerIdentityPort(
      parseJsonVar<DevSelfHostedWorker[]>(env.FG_DEV_SELF_HOSTED_WORKERS, []),
    ),
    governance: inMemoryGovernancePort({
      governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS),
    }),
    upstreams: inMemoryAgentUpstreamPort(
      parseJsonVar<AgentUpstream[]>(env.FG_DEV_AGENT_UPSTREAMS, []),
    ),
    config: inMemoryConfigPort(configFromEnv(env)),
    clock: systemClock,
  };
}
