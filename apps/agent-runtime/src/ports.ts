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
import {
  type ContentSource,
  DeterministicDetector,
  type SecretPattern,
  envelopeFromText,
  flattenedText,
} from "@ferrogate/guardrails";

import { normalizedCapabilities } from "./capabilities.js";
import { timingSafeEqualStrings } from "./crypto.js";
import { d1ApiKeyPort, d1WorkerIdentityPort } from "./durable/adapters.js";
import { type FrameOpenResult, type SealedWorkerFrame, openWorkerFrame } from "./workers/frame.js";

/**
 * Re-exported so every existing importer of `normalizedCapabilities` from this
 * module keeps working; the implementation lives in the leaf `capabilities.ts`
 * so `durable/adapters.ts` can share it without an import cycle.
 */
export { normalizedCapabilities } from "./capabilities.js";

// ---------------------------------------------------------------------------
// Worker environment
// ---------------------------------------------------------------------------

/** Bindings + vars declared in `wrangler.toml`. */
export interface AgentRuntimeBindings {
  /** Per-`${tenant_id}:${run_id}` run state + event fan-out. */
  readonly AGENT_RUN_STATE: DurableObjectNamespace;
  /** Per-`${tenant_id}:${workspace_id}` self-hosted dispatch queue. */
  readonly WORKER_PLANE: DurableObjectNamespace;
  /**
   * The TENANT database (`sql/d1-ts/tenant`), holding `api_keys`.
   *
   * Bound ⇒ tenant bearer credentials resolve from D1 through
   * {@link d1ApiKeyPort}. Absent ⇒ see {@link resolveDeps} for what is left.
   * Same binding name and same schema `apps/gateway/wrangler.toml` declares, so
   * one key authenticates identically on both Workers.
   */
  readonly DB?: D1Database;
  /**
   * The CONTROL database (`sql/d1-ts/control`), holding
   * `self_hosted_worker_registrations`.
   *
   * Bound ⇒ worker-plane identities resolve from D1 through
   * {@link d1WorkerIdentityPort}. The registry is account-global operator
   * state, which is why it is not in the tenant database.
   */
  readonly CONTROL_DB?: D1Database;
  /**
   * OPERATOR config: JSON array of {@link AgentUpstream} rows (Rust
   * `config.agent_upstreams`).
   *
   * This is a real deployment knob, not a test seam — the A2A upstream catalog
   * was TOML configuration in Rust too, exactly as `GATEWAY_PROVIDERS` /
   * `GATEWAY_MODELS` are vars in `apps/gateway`. Absent ⇒ no upstream resolves
   * ⇒ every `/v1/agents/*` dispatch is 404, which is fail-closed.
   */
  readonly AGENT_UPSTREAMS?: string;
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
  /**
   * DEV/TEST ONLY: JSON `{ keywords?, regex?, secretPatterns? }` configuring
   * the A2A deterministic guardrail. ABSENT ⇒ no detector is configured ⇒
   * nothing matches, which is the Rust behavior when no guardrail is set up.
   * The real detector policy lives in the control plane, not in a var.
   */
  readonly FG_DEV_A2A_GUARDRAILS?: string;
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
    /**
     * The PLAINTEXT worker transport document, published by the internal leg.
     *
     * For a cleartext body this is just the parsed body; for a sealed AEAD
     * frame it is the UNSEALED payload, which the raw request bytes no longer
     * contain. The six callbacks read this rather than re-parsing `c.req.text()`
     * so a sealed request is not silently seen as `{ sealed: … }`.
     */
    workerEnvelope?: Record<string, unknown>;
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
  /**
   * Open a sealed `symmetric_aead` transport frame.
   *
   * This lives on the REGISTRY, not on the middleware, for the same reason
   * `token_secret` does: the frame key is derived from that secret, and the
   * secret must never leave this module. The caller gets back the plaintext
   * envelope and nothing else — it still has to hand the identity inside it to
   * {@link validate} to be admitted, so opening a frame is never by itself an
   * authorization.
   */
  unseal(frame: SealedWorkerFrame): Promise<FrameOpenResult>;
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
 * // PORT-TODO(inventory-edge-control §agent-worker §8.3): PLATFORM LIMIT —
 * // workerd has no Unix domain sockets and therefore no `SO_PEERCRED`, so
 * // there is no way for this Worker to learn the OS identity of its caller.
 * // The Rust authorizer's root of trust is a KERNEL fact ("the peer process
 * // is PID N, running as UID U"); a Worker's is a CRYPTOGRAPHIC one. That
 * // substitution cannot be coded away at any effort — it is a property of the
 * // sandbox, not a missing API.
 * //
 * // IMPLEMENTED INSTEAD, and fully: the caller proves a registered worker
 * // identity. `internalAuth` in `middleware/auth.ts` admits the six
 * // `/v1/self-hosted-workers/*` callbacks only via
 * // {@link WorkerIdentityPort.validate}, which requires a `token_id` +
 * // constant-time-compared `token_secret` from the registry, optionally inside
 * // an AEAD-sealed frame keyed by that same secret. There is NO code path from
 * // a tenant bearer key to a `RegisteredSelfHostedWorker`.
 * //
 * // CONSEQUENCES that follow from the substitution and cannot be removed:
 * //  1. the credential is BEARER-shaped, so possession is authorization —
 * //     unlike SO_PEERCRED, a leaked `token_secret` is a full impersonation,
 * //     which is why `identity_expires_at_unix` and `active` exist;
 * //  2. the gateway can no longer distinguish two processes running as the
 * //     same registered worker, because there is no PID to distinguish them by.
 * //
 * // Pinned by `test/internal-auth.test.ts` (all six callbacks refuse a valid,
 * // fully-scoped tenant key) and `test/transport-frame.test.ts`.
 */
export interface GovernancePort {
  authorize(request: CapabilityRequest): Promise<GovernanceDecision>;
}

// ---------------------------------------------------------------------------
// Guardrails (A2A ingress, issue #278)
// ---------------------------------------------------------------------------

/** Rust `GuardrailStage`. */
export type GuardrailStage = "request" | "response";

/** A guardrail that matched, rendered by the route as a refusal. */
export interface GuardrailDenial {
  /** The detector that matched — evidence, never the matched text itself. */
  readonly detector: string;
  readonly stage: GuardrailStage;
  readonly message: string;
}

export type GuardrailDecision =
  | { readonly outcome: "allow" }
  | { readonly outcome: "deny"; readonly denial: GuardrailDenial };

/** One envelope to evaluate. Mirrors Rust `GuardrailEvaluationContext`. */
export interface GuardrailEvaluation {
  readonly stage: GuardrailStage;
  readonly tenantId: string;
  /** The upstream, recorded as Rust records `provider`. */
  readonly agentId: string;
  readonly streaming: boolean;
  /**
   * The FLATTENED text of every A2A part, already collected by the caller.
   *
   * The walk lives in `agents/ingress.ts` (Rust `collect_a2a_text`) because it
   * is A2A-protocol knowledge; this port only sees text, exactly as the Rust
   * detector stack only sees a `GuardrailEnvelope`.
   */
  readonly text: string;
}

/**
 * The detector chokepoint, at the API boundary.
 *
 * Rust calls `state.match_guardrail(stage, ctx)` and gets back an optional
 * matched guardrail; a `None` means nothing matched and the request proceeds.
 * `{ outcome: "allow" }` is that `None`.
 */
export interface GuardrailPort {
  evaluate(input: GuardrailEvaluation): Promise<GuardrailDecision>;
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
  readonly guardrails: GuardrailPort;
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
      // Rust security fix #113: expiry is judged against the SERVER's clock. An
      // identity that carries no `observed_at_unix` is judged against wall-clock
      // now, so an expired registration can never be admitted by OMITTING the
      // field. `middleware/auth.ts` additionally overwrites any client-supplied
      // value before calling this, exactly as Rust `validate_worker_identity`
      // does — a caller-supplied number is honoured here only so unit tests can
      // drive expiry deterministically.
      if (
        row.identity_expires_at_unix !== null &&
        (typeof identity.observed_at_unix === "number"
          ? identity.observed_at_unix
          : Math.floor(Date.now() / 1000)) >= row.identity_expires_at_unix
      ) {
        return {
          outcome: "rejected",
          failure: { reason: "invalid_identity", detail: "worker identity has expired" },
        };
      }
      const { token_secret: _secret, ...worker } = row;
      return { outcome: "resolved", worker };
    },

    async unseal(frame: SealedWorkerFrame): Promise<FrameOpenResult> {
      const row = rows.get(
        workerKey(frame.header.tenant_id, frame.header.workspace_id, frame.header.worker_id),
      );
      // An unknown worker, an inactive one, and a wrong `token_id` all produce
      // the SAME opaque refusal an undecryptable frame produces. The frame
      // header is attacker-controlled, so answering it differently would turn
      // the sealed path into an enumeration oracle for the registry — exactly
      // the disclosure the 401-vs-403 invariant exists to prevent on the bearer
      // leg.
      if (row === undefined || !row.active || row.token_id !== frame.header.token_id) {
        return {
          outcome: "rejected",
          failure: { reason: "unopenable", detail: "sealed worker transport frame did not open" },
        };
      }
      return openWorkerFrame(frame, row.token_secret);
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

/**
 * The A2A guardrail chokepoint, backed by the REAL detector stack in
 * `@ferrogate/guardrails` — the clean-room port of the Rust
 * `ferrogate-guardrails` crate.
 *
 * This is not a stub with a detector-shaped hole: `DeterministicDetector` is
 * the same in-repo keyword/regex/secret detector Rust runs, and the envelope
 * is built with `envelopeFromText("a2a", …)`, which is precisely what Rust's
 * `a2a_input_envelope` / `a2a_output_envelope` construct — same protocol, same
 * stage, same `ContentSource`, same `a2a:{agent}/…` protocol location.
 *
 * An EMPTY configuration matches nothing and therefore allows everything. That
 * mirrors Rust `match_guardrail` returning `None` when no guardrail is
 * configured, and it is the reason wiring this port cannot change the behavior
 * of a deployment that has configured no detectors.
 *
 * Findings are reported by DETECTOR ID and severity only. `matched_text` is
 * deliberately never propagated into the denial message — the Rust crate's
 * standing invariant is that matched text is never persisted or echoed, and a
 * refusal that quoted the secret it caught would defeat the detector.
 */
export function deterministicGuardrailPort(config: {
  readonly keywords?: readonly string[];
  readonly regex?: readonly string[];
  readonly secretPatterns?: readonly SecretPattern[];
}): GuardrailPort {
  const keywords = [...(config.keywords ?? [])];
  const regex = [...(config.regex ?? [])];
  const secretPatterns = [...(config.secretPatterns ?? [])];
  const configured = keywords.length > 0 || regex.length > 0 || secretPatterns.length > 0;

  const detector = configured
    ? DeterministicDetector.new({
        id: "a2a.deterministic",
        // A2A flattens user text on the request leg and assistant text on the
        // response leg; both sources must be in scope or one direction would
        // silently skip evaluation.
        supported_sources: ["user", "assistant"],
        keywords,
        regex,
        secret_patterns: secretPatterns,
      })
    : undefined;

  return {
    async evaluate(input: GuardrailEvaluation): Promise<GuardrailDecision> {
      if (detector === undefined) return { outcome: "allow" };
      const source: ContentSource = input.stage === "request" ? "user" : "assistant";
      const location =
        input.stage === "request"
          ? `a2a:${input.agentId}/message`
          : `a2a:${input.agentId}/response`;
      let result: Awaited<ReturnType<typeof detector.evaluate>>;
      try {
        // Envelope construction is INSIDE the guard on purpose: flattening the
        // content is part of the scan, and a failure there has cleared exactly
        // as little as a failure inside the detector.
        const envelope = envelopeFromText("a2a", input.stage, source, location, input.text);
        result = await detector.evaluate(
          {
            protocol: "a2a",
            stage: input.stage,
            // `DetectorTenant` has no tenant field of its own — Rust attributes
            // a guardrail evaluation by ORGANIZATION, and this Worker's
            // `tenantId` is that organization.
            tenant: { organization_id: input.tenantId },
            provider: input.agentId,
            text: flattenedText(envelope),
            segments: envelope.segments,
          },
          // An ABSOLUTE deadline, not a duration — `evaluate` compares it
          // against `Date.now()`.
          Date.now() + GUARDRAIL_BUDGET_MS,
        );
      } catch (error) {
        // FAIL CLOSED. The Rust crate's standing posture on truncation,
        // disablement and detector error is to refuse, not to pass: a detector
        // that could not run has not cleared the content, and treating "the
        // scan broke" as "the scan passed" is how a guardrail silently stops
        // being one.
        return {
          outcome: "deny",
          denial: {
            detector: "a2a.deterministic",
            stage: input.stage,
            message: `a2a ${input.stage}-stage guardrail could not be evaluated: ${
              error instanceof Error ? error.message : "detector error"
            }`,
          },
        };
      }
      if (result.verdict === "pass") return { outcome: "allow" };
      const severities = result.findings.map((finding) => finding.severity).join(", ");
      return {
        outcome: "deny",
        denial: {
          detector: "a2a.deterministic",
          stage: input.stage,
          message:
            `a2a ${input.stage}-stage guardrail matched ` +
            `${result.findings.length} finding(s) [${severities}]`,
        },
      };
    },
  };
}

/**
 * Time budget handed to the detector, mirroring Rust's per-detector deadline.
 *
 * The deterministic detector is in-process and does not block on I/O, so this
 * is a ceiling rather than an expected cost; it exists so a pathological regex
 * cannot hold the request path open indefinitely.
 */
export const GUARDRAIL_BUDGET_MS = 250;

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
 * ## The two credential authorities, and how each is chosen
 *
 * `apiKeys` and `workerIdentities` are the only ports that decide whether a
 * caller is admitted, and each is resolved INDEPENDENTLY, DURABLE FIRST:
 *
 * | port | durable source | dev source |
 * |---|---|---|
 * | `apiKeys` | `env.DB` → `api_keys` ({@link d1ApiKeyPort}) | `FG_DEV_API_KEYS` |
 * | `workerIdentities` | `env.CONTROL_DB` → `self_hosted_worker_registrations` ({@link d1WorkerIdentityPort}) | `FG_DEV_SELF_HOSTED_WORKERS` |
 *
 * **A bound database WINS over the dev flag**, and that ordering is deliberate
 * rather than incidental: `wrangler.toml` commits `FG_DEV_IN_MEMORY_PORTS = "1"`
 * under a comment reading *"Production MUST NOT set this"*, so a deployment
 * that binds real databases but forgets to delete the var must still get the
 * real databases. Reversing the order would reproduce
 * `docs/rewrite/parity-audit-dead-packages.md` §7.2 — a fully-built durable
 * identity store bypassed by one leftover variable.
 *
 * Either authority missing BOTH sources ⇒ `undefined` ⇒ the Worker answers
 * `503 agent_runtime_unavailable` on every authenticated surface. There is no
 * permissive default: an unconfigured deployment admits nobody.
 *
 * ## The remaining ports
 *
 *  - `upstreams` — operator config, from `AGENT_UPSTREAMS` (falling back to the
 *    dev var). A catalog of A2A endpoints was TOML configuration in Rust too;
 *    a var is the faithful port, not a stub. Empty ⇒ every dispatch 404s.
 *  - `guardrails` — the REAL `@ferrogate/guardrails` deterministic detector.
 *  - `config`, `clock` — real; `configFromEnv` reads operator vars.
 *  - `AGENT_RUN_STATE` / `WORKER_PLANE` — real Durable Objects, declared in
 *    `wrangler.toml` and re-exported from `src/worker.ts`.
 *
 * ## PORT-TODO(inventory-edge-control §8) — KEPT for `governance` ONLY
 *
 * §7.1 of the audit found EVERY port in-memory in the committed deployment.
 * The two credential authorities above close that finding and are gated by
 * `test/durable/*.spec.ts`, which drives the REAL Worker with the dev flag
 * ABSENT and only D1 bound — deleting either durable branch turns those specs
 * red (503) while the rest of the suite stays green.
 *
 * `governance` is NOT closed and is not closable here. `inMemoryGovernancePort`
 * already evaluates the real capability-envelope / sealed-egress DECISION over
 * a real operator var, and that decision is complete; what is missing is an
 * isolation HOST to hand the grant to. The only Cloudflare equivalent of Rust's
 * four backends is Containers / `@cloudflare/sandbox`, whose
 * `[[containers]]` + `CONTAINER_SANDBOX` binding needs a PAID account and a
 * published image, so it cannot be exercised in the offline docker-free
 * harness — and `wrangler.toml`, where the binding would be declared, is the
 * integrate step's file. See the PORT-TODOs in `src/runs/governance.ts` for the
 * three Rust backends (Firecracker microVM, Docker `--network none`, `unshare`
 * namespaces) that have no CF equivalent at any effort.
 *
 * ## WIRING — the `apps/agent-runtime/wrangler.toml` edits (integrate step)
 *
 * Both D1 stanzas are already written out, commented, in `wrangler.toml`
 * itself: UNCOMMENT them at deploy time (filling in the real `database_id`s)
 * and DELETE the committed `FG_DEV_IN_MEMORY_PORTS = "1"` line, or move it into
 * an `[env.dev]` block. Nothing else changes — `src/index.ts` and
 * `src/worker.ts` need no edit at all, because the posture is chosen inside
 * this function.
 *
 * TWO EDITS THAT MUST NOT BE MADE AT DEVELOPMENT TIME, both measured rather
 * than feared, and both explained at length in `wrangler.toml`:
 *
 *  1. **Do not uncomment the D1 stanzas and leave them committed.**
 *     `vitest.config.ts` loads `wrangler.toml` via `wrangler: { configPath }`,
 *     so a committed stanza injects `env.DB` / `env.CONTROL_DB` into every unit
 *     test, where miniflare provisions an EMPTY unmigrated database. The
 *     durable-first rule above then routes the default suite onto schema-less
 *     tables: 106 of 259 tests go red on a correct tree. The durable adapters
 *     have their own harness (`test/durable/harness/vitest.config.ts`, chained
 *     from `bun run test`) which binds and MIGRATES both databases.
 *  2. **Do not add `AGENT_UPSTREAMS = "[]"`.** Absent and `"[]"` give a
 *     deployment the identical empty catalog, so it buys nothing — but the
 *     `??` below makes a committed value SHADOW `FG_DEV_AGENT_UPSTREAMS`, which
 *     empties the catalog the harness seeds and turns 14 A2A dispatch tests
 *     red. An operator states a real catalog by SETTING the var; leaving it out
 *     is how the repo says "no upstreams" without leaking into the harness.
 */
export function resolveDeps(env: AgentRuntimeBindings): AgentRuntimeDeps | undefined {
  const dev = env.FG_DEV_IN_MEMORY_PORTS === "1";

  const apiKeys: ApiKeyPort | undefined =
    env.DB !== undefined
      ? d1ApiKeyPort(env.DB)
      : dev
        ? inMemoryApiKeyPort(parseJsonVar<DevApiKey[]>(env.FG_DEV_API_KEYS, []))
        : undefined;

  const workerIdentities: WorkerIdentityPort | undefined =
    env.CONTROL_DB !== undefined
      ? d1WorkerIdentityPort(env.CONTROL_DB)
      : dev
        ? inMemoryWorkerIdentityPort(
            parseJsonVar<DevSelfHostedWorker[]>(env.FG_DEV_SELF_HOSTED_WORKERS, []),
          )
        : undefined;

  // FAIL CLOSED. A Worker that cannot consult one of its credential authorities
  // must refuse every authenticated surface, not serve the ones it can.
  if (apiKeys === undefined || workerIdentities === undefined) return undefined;

  return {
    apiKeys,
    workerIdentities,
    governance: inMemoryGovernancePort({
      governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS),
    }),
    upstreams: inMemoryAgentUpstreamPort(
      parseJsonVar<AgentUpstream[]>(
        env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined),
        [],
      ),
    ),
    guardrails: deterministicGuardrailPort(
      parseJsonVar<{
        keywords?: string[];
        regex?: string[];
        secretPatterns?: SecretPattern[];
      }>(env.FG_DEV_A2A_GUARDRAILS, {}),
    ),
    config: inMemoryConfigPort(configFromEnv(env)),
    clock: systemClock,
  };
}
