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
import {
  type LifecycleStatus,
  lifecycleStatusAllowsRequests,
  parseLifecycleStatus,
} from "@ferrogate/storage";

import {
  type AdmissionBindings,
  type AdmissionGrant,
  type AdmissionPort,
  admissionFromEnv,
} from "./admission/index.js";
import { agentUpstreamPortFromEnv } from "./agents/registry.js";
import { normalizedCapabilities } from "./capabilities.js";
import { timingSafeEqualStrings } from "./crypto.js";
import { d1ApiKeyPort, d1WorkerIdentityPort } from "./durable/adapters.js";
import { durableA2aGuardrailPort } from "./guardrails.js";
// `./rbac.js` imports the `AuthContext` TYPE back out of this module. The cycle
// is type-only, so nothing is evaluated in either direction at module load —
// the same shape `./admission/index.js` and `./guardrails.js` already have.
import { type RbacAuthorizerPort, rbacAuthorizerFromEnv } from "./rbac.js";
import { type WorkflowCatalogPort, workflowCatalogFromEnv } from "./runs/workflow.js";
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
   *
   * **READ ONLY WHEN `CONTROL_DB` IS UNBOUND.** With a control database the
   * durable `control_plane_resources` documents of kind `agent-upstreams` are
   * the WHOLE registry (`src/agents/registry.ts`), so one
   * `DELETE /admin/v1/agent-upstreams/{id}` withdraws an upstream from this
   * Worker's dispatch path and from `apps/gateway`'s discovery document
   * together. The var is NOT merged over them: a union would keep dispatching
   * to an id declared in both after the document is deleted.
   */
  readonly AGENT_UPSTREAMS?: string;
  /**
   * OPERATOR config: JSON array of `[[agent_workflows]]` documents (Rust
   * `config.agent_workflows`), read by the tool-side graph gate in
   * `src/runs/workflow.ts`.
   *
   * A real deployment knob, not a test seam — the workflow table was TOML
   * configuration in Rust, exactly as `[[agent_upstreams]]` was. It is
   * materialised OVER the durable `control_plane_resources` documents of kind
   * `agent-workflows` (the same rows `apps/gateway`'s model-side gate reads and
   * `apps/control-plane`'s `admin_agent_workflow` group writes), so an operator
   * can pin a graph per deployment without a control-plane round trip.
   *
   * Absent ⇒ no workflow resolves ⇒ a step DECLARING one is refused
   * `400 workflow_not_found` and a step declaring none is untouched. The gate is
   * opt-in by header, which is why an empty table can only ever add refusals.
   */
  readonly AGENT_WORKFLOWS?: string;
  /**
   * `apps/gateway`'s `RateLimiterDurableObject` namespace, bound with
   * `script_name = "ferrogate-gateway"` so BOTH Workers charge ONE window per
   * counter key (`src/admission/counter.ts`). Absent ⇒ a per-isolate counter.
   *
   * Typed as `unknown` here rather than `DurableObjectNamespace` because the
   * class lives in another Worker's script: there is no type to import, and
   * `counterFromEnv` probes the binding for its RPC surface before using it.
   */
  readonly RATE_LIMIT?: unknown;
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
   * DEV/TEST ONLY: JSON array of `quota_policies` rows in the snake_case wire
   * shape. The DURABLE source is `CONTROL_DB`'s `quota_policies` table, which
   * WINS whenever it is bound — same durable-first rule as the two credential
   * authorities. Absent ⇒ no policy restricts, which can only leave a limit
   * unset, never raise one.
   */
  readonly FG_DEV_QUOTA_POLICIES?: string;
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
    /**
     * The wallet holds admission took for this request, released by
     * `contractAuth`'s `finally`. Absent for an internal (worker-plane)
     * operation and for any request refused before admission ran.
     */
    admissionGrant?: AdmissionGrant;
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
  /**
   * TOK-12 `api_keys.request_limit_per_minute` — the per-CREDENTIAL RPM cap,
   * independent of the quota-policy chain. Rust
   * `AuthContext.request_limit_per_minute`.
   *
   * `undefined` means the credential imposes no cap of its own. `0` is a REAL
   * value meaning "refuse every request", which is why every consumer tests for
   * `undefined` explicitly and never writes `limit ?? fallback`.
   */
  readonly requestLimitPerMinute?: number | undefined;
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
 * // PORT-TODO(L: inventory-edge-control §agent-worker §8.3): PLATFORM LIMIT —
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
  /**
   * The refusal code the ROUTE reports, when the matching authority named one.
   *
   * Present only for a DURABLE activated revision (`src/guardrails.ts`), where
   * it is the operator's own `PolicyAction.code`. That is what lets one
   * activation refuse with the SAME code on every Worker that enforces it
   * (`docs/rewrite/FLEET-CONSISTENCY.md` FC-3) instead of each Worker inventing
   * a private one. Absent for the var-driven detector, whose refusals keep the
   * route's historical `guardrail_blocked`.
   */
  readonly code?: string | undefined;
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

/**
 * The caller the registry is fenced to.
 *
 * `tenantId === null` is a PLATFORM OPERATOR: no row-ownership predicate. It is
 * a separate member rather than an empty string so "operator" can never be
 * produced by a credential that merely names no tenant — that caller is already
 * refused `403 tenant_scope_denied` by `tenantIdOf`, and conflating the two
 * would hand it the operator's view of the table.
 */
export interface AgentUpstreamScope {
  readonly tenantId: string | null;
}

/**
 * The outcome of one registry lookup.
 *
 * `unavailable` is a THIRD member on purpose. Collapsing it onto `not_found`
 * would make a registry outage indistinguishable from a withdrawal — the
 * dispatch would be refused either way, but an operator watching this surface
 * would read "the upstream is gone" and stop looking, and any later decision to
 * fail open would have nothing left to branch on. `src/agents/registry.ts`
 * states the full argument; `apps/gateway/src/ratelimit/quota.ts` makes the
 * same shape for the admission ladder.
 */
export type AgentUpstreamLookup =
  | { readonly outcome: "found"; readonly upstream: AgentUpstream }
  | { readonly outcome: "not_found" }
  | { readonly outcome: "unavailable"; readonly detail: string };

export interface AgentUpstreamPort {
  /**
   * Resolve `agentId` for `scope`.
   *
   * The scope is a PARAMETER rather than something the port closes over,
   * because the durable implementation binds it into the SQL fence and a
   * per-request value must not be captured in a per-isolate object.
   */
  lookup(agentId: string, scope: AgentUpstreamScope): Promise<AgentUpstreamLookup>;
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
  /**
   * Rust `config.agent_runtime.max_turns` (`default_agent_runtime_max_turns()`
   * = 4). The OPERATOR ceiling: a run may ask for fewer turns, never more.
   */
  readonly maxTurns: number;
  /**
   * Rust `config.agent_runtime.timeout_millis`
   * (`default_agent_runtime_timeout_millis()` = 30 000). Same ceiling rule.
   */
  readonly timeoutMillis: number;
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
  /**
   * The ADMISSION half of Rust's `authenticate()` — quota scope, monthly
   * budget, wallet balance, RPM. See `src/admission/index.ts`.
   *
   * It sits in the SAME bundle as the credential authorities on purpose:
   * `finalize_auth` was one function with `authenticate` in Rust, and a
   * deployment that cannot consult its credential authority cannot consult its
   * spend controls either. Both fail closed together.
   */
  readonly admission: AdmissionPort;
  /**
   * THE RBAC GATE — an operation's `rbac_action` (`docs/rewrite/
   * FLEET-CONSISTENCY.md` finding **FC-7**), see `src/rbac.ts`.
   *
   * It sits beside the credential authorities for the same reason
   * {@link admission} does: in Rust these were one `authenticate()` chain, and
   * a deployment that cannot consult its grant graph must not serve an
   * rbac-guarded operation as though nothing were declared.
   */
  readonly rbac: RbacAuthorizerPort;
  readonly workerIdentities: WorkerIdentityPort;
  readonly governance: GovernancePort;
  readonly upstreams: AgentUpstreamPort;
  readonly guardrails: GuardrailPort;
  /**
   * The `[[agent_workflows]]` table the TOOL-side graph gate reads
   * (`src/runs/workflow.ts`). Durable documents in `CONTROL_DB` with the
   * operator var materialised over them; see {@link workflowCatalogFromEnv}.
   */
  readonly workflows: WorkflowCatalogPort;
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
  maxTurns: 4,
  timeoutMillis: 30_000,
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
  /**
   * TOK-12 per-credential RPM cap (the `api_keys.request_limit_per_minute`
   * column). `0` refuses every request; absent imposes no per-key cap.
   */
  readonly requestLimitPerMinute?: number;
}

// ---------------------------------------------------------------------------
// THE TENANCY LIFECYCLE LEG  (FLEET-CONSISTENCY finding FC-2)
// ---------------------------------------------------------------------------

/**
 * ## What this closes
 *
 * This Worker could NAME `tenancy_suspended` — `src/middleware/auth.ts`
 * renders it — and its DEPLOYED credential port could never PRODUCE it. The
 * only implementation that returned that outcome was
 * {@link inMemoryApiKeyPort}, reading the `FG_DEV_API_KEYS` var;
 * `d1ApiKeyPort` (`src/durable/adapters.ts`), the port every real deployment
 * mounts, returns exactly `unknown` / `key_suspended` / `resolved` /
 * `unavailable` and nothing else.
 *
 * So the Worker had a PASSING suspension test that proved nothing about
 * production — the `lifecycle-tenancy-scenario-neverrun` failure mode, and the
 * reason `docs/rewrite/FLEET-CONSISTENCY.md` classifies this cell **M**
 * (in-memory) rather than **D**. An operator suspending a tenant saw
 * `/v1/chat/completions` refuse and `POST /v1/agents/{name}` keep dispatching
 * on the same un-revoked credential.
 *
 * ## Why it is a DECORATOR and not an edit to `d1ApiKeyPort`
 *
 * Two reasons, and the first is the load-bearing one:
 *
 *  1. **It must apply to whichever port `resolveDeps` chose.** Wrapping the
 *     resolved port means a lifecycle suspension bites the durable leg AND the
 *     dev leg AND anything mounted later. Editing `d1ApiKeyPort` would gate
 *     exactly one of them, which is the shape of the defect being closed.
 *  2. `api_keys` is TENANT data and `tenants` is CONTROL data. A credential
 *     resolver that reached across both databases would collapse the split
 *     `src/durable/adapters.ts` draws deliberately.
 *
 * ## The authority, and the order
 *
 * `tenants.status` in `CONTROL_DB` plus `projects` / `workspaces` in `DB` —
 * the SAME columns `apps/gateway/src/adapters.ts::D1TenancyLifecycleGate`
 * reads and `apps/control-plane`'s lifecycle routes write. The gate runs
 * inside credential resolution, therefore BEFORE `admission` in
 * `src/middleware/auth.ts` — Rust's `finalize_auth` order, and the order is the
 * control: a suspended tenant must never reach the step that authorizes spend.
 *
 * ## Fail closed
 *
 * A lookup that throws returns `unavailable` (503), never `resolved`. Rust
 * `LifecycleGateError::Unavailable` states the reason: fail-open would make
 * "flap the control plane" a suspension bypass. `src/admission/` argues the
 * identical posture for spend.
 *
 * ## PORT-TODO(P: FLEET-CONSISTENCY §FC-2) — the ONE divergence, stated
 *
 * `apps/gateway` distinguishes `tenancy_suspended` / `tenancy_disabled` /
 * `tenancy_deleted`; {@link ApiKeyResolution} here has a SINGLE inactive-tenancy
 * arm, so all three collapse onto `tenancy_suspended` (403). Every inactive
 * status still DENIES — the divergence is in the reason string a client is
 * given, never in the decision — but a tenant told "suspended" when its project
 * was `disabled` is being sent to the wrong remedy.
 *
 * NOT a platform limit and not blocked on a schema: it is one widened union
 * plus one `switch` arm in `src/middleware/auth.ts::resolveOrThrow`, and that
 * file is outside this slice's ownership. Adding a `code` field HERE that the
 * middleware never reads would be worse than the gap — a dead field is this
 * repo's dominant defect — so the vocabulary stays honest until both halves
 * land together. Pinned by `test/durable/lifecycle.spec.ts`.
 */

/** The `tenants` read — CONTROL database. Exported so a test can pin it. */
export const LIFECYCLE_TENANT_SQL = "SELECT id, status FROM tenants WHERE id = ?1";
/** The `projects` read — TENANT database. */
export const LIFECYCLE_PROJECT_SQL = "SELECT id, status, tenant_id FROM projects WHERE id = ?1";
/** The `workspaces` read — TENANT database. */
export const LIFECYCLE_WORKSPACE_SQL =
  "SELECT id, status, tenant_id, project_id FROM workspaces WHERE id = ?1";

/** A `tenants` / `projects` / `workspaces` row, narrowed to what the gate reads. */
export interface LifecycleRow {
  readonly id: string;
  readonly status: string;
  readonly tenant_id?: string | null;
  readonly project_id?: string | null;
}

/**
 * The three row reads the walk needs.
 *
 * An interface for the reason Rust makes it a trait: a test can implement a
 * THROWING source and hold the fail-closed claim, which is the one property a
 * healthy live binding cannot express.
 */
export interface LifecycleRowSource {
  tenantRow(id: string): Promise<LifecycleRow | null>;
  projectRow(id: string): Promise<LifecycleRow | null>;
  workspaceRow(id: string): Promise<LifecycleRow | null>;
}

function asLifecycleRow(value: unknown): LifecycleRow | null {
  if (typeof value !== "object" || value === null) return null;
  const row = value as Record<string, unknown>;
  if (typeof row.id !== "string") return null;
  return {
    id: row.id,
    // A NULL/absent `status` is not a decision: `parseLifecycleStatus` reads it
    // as `active`, the fail-OPEN READ default #514 chose so the decorative
    // pre-#514 rows do not revoke every existing tenant.
    status: typeof row.status === "string" ? row.status : "",
    tenant_id: typeof row.tenant_id === "string" ? row.tenant_id : null,
    project_id: typeof row.project_id === "string" ? row.project_id : null,
  };
}

/**
 * The two-database row source. `tenants` is CONTROL state, `projects` and
 * `workspaces` are TENANT data — the split rule `sql/d1-ts/` draws and
 * `apps/gateway` deploys.
 *
 * An UNBOUND database answers `null` for its tier rather than throwing: with no
 * `CONTROL_DB` there is no tenant row to read, which is "absent", and absence
 * is not suspension. It is the same degradation `apps/gateway`'s
 * `lifecycleRowSourceFromEnv` performs, so the two Workers agree on a partial
 * deployment as well as a complete one.
 */
export function d1LifecycleRowSource(
  control: D1Database | undefined,
  tenant: D1Database | undefined,
): LifecycleRowSource {
  return {
    async tenantRow(id: string): Promise<LifecycleRow | null> {
      if (control === undefined) return null;
      return asLifecycleRow(await control.prepare(LIFECYCLE_TENANT_SQL).bind(id).first());
    },
    async projectRow(id: string): Promise<LifecycleRow | null> {
      if (tenant === undefined) return null;
      return asLifecycleRow(await tenant.prepare(LIFECYCLE_PROJECT_SQL).bind(id).first());
    },
    async workspaceRow(id: string): Promise<LifecycleRow | null> {
      if (tenant === undefined) return null;
      return asLifecycleRow(await tenant.prepare(LIFECYCLE_WORKSPACE_SQL).bind(id).first());
    },
  };
}

/** Rust `present`: trim, and treat blank as absent. */
function presentTenancyId(value: string | null | undefined): string | undefined {
  const trimmed = (value ?? "").trim();
  return trimmed === "" ? undefined : trimmed;
}

function pushUniqueId(ids: string[], candidate: string | null | undefined): void {
  const value = presentTenancyId(candidate);
  if (value === undefined || ids.includes(value)) return;
  ids.push(value);
}

/** One resolved ancestor — Rust `LifecycleRef`. */
export interface LifecycleRef {
  readonly kind: "tenant" | "project" | "workspace";
  readonly id: string;
  readonly status: LifecycleStatus;
}

/**
 * Rust `resolve_lifecycle_chain` — walk the HIERARCHY, not the caller's
 * declaration, shallowest-first.
 *
 * That distinction is the bug Rust's second landing fixed, reproduced rather
 * than re-derived: three lookups that check only the ids the CALLER named mean
 * a credential carrying just a `project_id` yields `[project(active)]` and the
 * suspended TENANT above it is never read. So the workspace row backfills its
 * `project_id`/`tenant_id`, each project row backfills its `tenant_id`, and
 * declared ids are UNIONed with derived ones — never substituted. There is no
 * ordering in which a suspended ancestor is skipped.
 *
 * Shallowest-first is what makes the refusal name the ROOT cause when a tenant
 * suspension cascades onto its children.
 */
export async function resolveLifecycleChain(
  source: LifecycleRowSource,
  tenancy: Tenancy,
): Promise<LifecycleRef[]> {
  const tenantIds: string[] = [];
  const projectIds: string[] = [];
  const workspaceRows: LifecycleRow[] = [];

  pushUniqueId(tenantIds, tenancy.tenantId);
  pushUniqueId(projectIds, tenancy.projectId);

  const workspaceId = presentTenancyId(tenancy.workspaceId);
  if (workspaceId !== undefined) {
    const workspace = await source.workspaceRow(workspaceId);
    if (workspace !== null) {
      pushUniqueId(projectIds, workspace.project_id);
      pushUniqueId(tenantIds, workspace.tenant_id);
      workspaceRows.push(workspace);
    }
  }

  const projectRows: LifecycleRow[] = [];
  // Indexed, not `for…of`: a project may be reached only via the workspace
  // above, and each project row appends tenant ids the caller never named.
  for (let index = 0; index < projectIds.length; index += 1) {
    const project = await source.projectRow(projectIds[index] as string);
    if (project !== null) {
      pushUniqueId(tenantIds, project.tenant_id);
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
 * The first entry in the chain that forbids requests, or `null` when the whole
 * chain is usable. Rust `check_lifecycle_chain` at the REQUEST seam — this
 * Worker serves no lifecycle RECOVERY route, so `disabled` denies here.
 */
export function firstInactiveTenancy(chain: readonly LifecycleRef[]): LifecycleRef | null {
  for (const reference of chain) {
    if (!lifecycleStatusAllowsRequests(reference.status)) return reference;
  }
  return null;
}

/**
 * Wrap an {@link ApiKeyPort} so a RESOLVED credential is additionally checked
 * against its tenancy chain.
 *
 * Only `resolved` is post-processed: every other outcome is already a refusal
 * and must reach `resolveOrThrow` untouched, or a suspended KEY (401) would
 * start reporting a tenancy failure (403) and disclose that the credential
 * exists. That asymmetry is the 401-vs-403 invariant, and it is preserved by
 * construction here rather than by a check that could be forgotten.
 */
export function tenancyGatedApiKeyPort(inner: ApiKeyPort, source: LifecycleRowSource): ApiKeyPort {
  return {
    async resolve(presentedKey: string): Promise<ApiKeyResolution> {
      const resolution = await inner.resolve(presentedKey);
      if (resolution.outcome !== "resolved") return resolution;
      // A platform operator carries no tenancy chain; Rust never gates it.
      if (resolution.auth.platformOperator) return resolution;

      let chain: readonly LifecycleRef[];
      try {
        chain = await resolveLifecycleChain(source, resolution.auth.tenancy);
      } catch (error) {
        // FAIL CLOSED. 503, never the `resolved` this function was handed.
        return {
          outcome: "unavailable",
          detail: `tenancy lifecycle lookup failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        };
      }
      return firstInactiveTenancy(chain) === null ? resolution : { outcome: "tenancy_suspended" };
    },
  };
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
          // Explicit `undefined`, never `?? 0` / `|| undefined`: `0` is the
          // Rust "refuse everything" cap and must survive the round trip.
          requestLimitPerMinute: row.requestLimitPerMinute,
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

/**
 * In-memory {@link AgentUpstreamPort} over the deploy-time `AGENT_UPSTREAMS`
 * table.
 *
 * It applies NO tenancy predicate, and that is not an oversight: the var is a
 * single operator-authored file with no `tenant_id` column to fence on — Rust's
 * `[[agent_upstreams]]` is likewise one global table. The per-upstream
 * `visibleToTenantIds` / `operatorOnly` filter still applies, in
 * `agents/ingress.ts::upstreamVisibleTo`, exactly as it did before. The ROW
 * ownership fence exists only where rows have owners, i.e. in
 * `agents/registry.ts` over `control_plane_resources`.
 *
 * It also never reports `unavailable`: an in-memory map cannot fail to be read,
 * so the fail-closed branch has no meaning here and inventing one would be an
 * assertion that can never fire.
 */
export function inMemoryAgentUpstreamPort(upstreams: readonly AgentUpstream[]): AgentUpstreamPort {
  const byId = new Map(upstreams.map((upstream) => [upstream.id, upstream]));
  return {
    async lookup(agentId: string): Promise<AgentUpstreamLookup> {
      const upstream = byId.get(agentId);
      return upstream === undefined ? { outcome: "not_found" } : { outcome: "found", upstream };
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
 *  - `upstreams` — the A2A REACH SET, and durable-first for the same reason the
 *    credential authorities are. `CONTROL_DB` bound ⇒ the
 *    `control_plane_resources` documents of kind `agent-upstreams`
 *    ({@link agentUpstreamPortFromEnv}), the SAME rows `apps/gateway` publishes
 *    discovery from, so ONE `DELETE /admin/v1/agent-upstreams/{id}` withdraws a
 *    compromised upstream from BOTH reach paths. Unbound ⇒ `AGENT_UPSTREAMS`
 *    (falling back to the dev var), which is a faithful port of the Rust TOML
 *    table, not a stub. Empty ⇒ every dispatch 404s. The two sources do not
 *    merge — see `src/agents/registry.ts`.
 *  - `guardrails` — the REAL `@ferrogate/guardrails` deterministic detector.
 *  - `config`, `clock` — real; `configFromEnv` reads operator vars.
 *  - `AGENT_RUN_STATE` / `WORKER_PLANE` — real Durable Objects, declared in
 *    `wrangler.toml` and re-exported from `src/worker.ts`.
 *
 * ## PORT-TODO(P: inventory-edge-control §8) — KEPT for `governance` ONLY
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

  const resolvedApiKeys: ApiKeyPort | undefined =
    env.DB !== undefined
      ? d1ApiKeyPort(env.DB)
      : dev
        ? inMemoryApiKeyPort(parseJsonVar<DevApiKey[]>(env.FG_DEV_API_KEYS, []))
        : undefined;

  /**
   * THE TENANCY LIFECYCLE GATE (FC-2), composed OVER whichever credential port
   * was chosen above — the durable one AND the dev one alike, which is the
   * whole point: the shipped defect was a lifecycle outcome only the dev table
   * could produce.
   *
   * Wrapped whenever EITHER database is bound, because either one carries a
   * tier of the chain (`tenants` in CONTROL, `projects`/`workspaces` in the
   * tenant database). Neither bound ⇒ no lifecycle authority exists to consult
   * and the port is left alone: that is the offline default-suite posture, and
   * a deployment in it has no `tenants` table to have suspended anything in.
   * It is the same degradation `apps/gateway`'s `lifecycleRowSourceFromEnv`
   * performs, so the two Workers agree on a partial deployment too.
   *
   * Deleting this wrap turns `test/durable/lifecycle.spec.ts` and
   * `apps/mcp/test/fleet-tenancy-suspension.test.ts` red.
   */
  const apiKeys: ApiKeyPort | undefined =
    resolvedApiKeys === undefined || (env.DB === undefined && env.CONTROL_DB === undefined)
      ? resolvedApiKeys
      : tenancyGatedApiKeyPort(resolvedApiKeys, d1LifecycleRowSource(env.CONTROL_DB, env.DB));

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
    // The admission ladder reads `CONTROL_DB` (quota policies), `DB` (monthly
    // spend + prepaid wallet) and `RATE_LIMIT` (the shared RPM counter). All
    // three are OPTIONAL and each degrades in the tightening direction only —
    // see `src/admission/index.ts`.
    admission: admissionFromEnv(env as AdmissionBindings),
    // FC-7. THE MOUNT of the RBAC gate. Deleting this line returns the Worker
    // to the state FLEET-CONSISTENCY records: `rbac_action` parsed off the
    // contract (`src/contract.ts`) and never read, so a role an operator uses
    // to withhold an action is enforced on `apps/gateway` and silently ignored
    // here. `CONTROL_DB` unbound ⇒ 503, never an implicit grant — see
    // `src/rbac.ts`.
    rbac: rbacAuthorizerFromEnv(env),
    workerIdentities,
    governance: inMemoryGovernancePort({
      governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS),
    }),
    // THE A2A REACH SET. `CONTROL_DB` bound ⇒ the durable
    // `control_plane_resources` documents of kind `agent-upstreams` — the SAME
    // rows `apps/control-plane`'s `admin_agent_upstream` group writes and
    // `apps/gateway`'s discovery surface reads — so ONE
    // `DELETE /admin/v1/agent-upstreams/{id}` withdraws the upstream from BOTH
    // reach paths. Absent ⇒ the deploy-time var alone, which is the offline
    // harness's posture and a legitimate var-only deployment's.
    //
    // The durable table REPLACES the var rather than merging with it: a union
    // would keep dispatching to an id the operator configured twice and then
    // deleted. See `src/agents/registry.ts`.
    upstreams: agentUpstreamPortFromEnv(
      env,
      inMemoryAgentUpstreamPort(
        parseJsonVar<AgentUpstream[]>(
          env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined),
          [],
        ),
      ),
    ),
    // FC-3. The DURABLE activated revision runs FIRST and the operator var is
    // its fallback, so a `guardrail_policy_bindings` row the control plane
    // activated screens A2A messages on the very next request — no redeploy —
    // while a var-only deployment behaves exactly as it did. Dropping the
    // wrapper here silently returns this Worker to the state
    // `docs/rewrite/FLEET-CONSISTENCY.md` FC-3 describes: an operator activates
    // a policy, sees it bound, and it covers one of three doors.
    guardrails: durableA2aGuardrailPort(
      env,
      deterministicGuardrailPort(
        parseJsonVar<{
          keywords?: string[];
          regex?: string[];
          secretPatterns?: SecretPattern[];
        }>(env.FG_DEV_A2A_GUARDRAILS, {}),
      ),
    ),
    // Real in every posture: with no `CONTROL_DB` the operator var alone is the
    // table, which is exactly the offline harness's posture and a legitimate
    // deployment's. There is no in-memory stand-in to forget to replace.
    workflows: workflowCatalogFromEnv(env),
    config: inMemoryConfigPort(configFromEnv(env)),
    clock: systemClock,
  };
}
