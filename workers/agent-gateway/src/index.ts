// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: FerroGate agent-gateway Worker (issue #413). The required front for ALL
//   Cloudflare agent operations: Cloudflare exposes NO first-party REST API to
//   create/start/stop/invoke/inspect/destroy an individual agent instance, so every
//   agent operation FerroGate drives is fronted by THIS Worker.

import { Agent, routeAgentRequest, getAgentByName } from "agents";
import { Sandbox, ContainerProxy } from "@cloudflare/sandbox";

import { json, requireBearer } from "./auth";
import {
  handleMemory,
  memoryChatHistoryGet,
  memoryChatHistoryPrune,
  memorySqlQuery,
  memoryStateGet,
  memoryStateSet,
  persistedMessageCap,
} from "./memory";
import type { RawSqlResult, SqlBinding } from "./memory";
import {
  dispatchScheduledTask,
  handleSchedule,
  scheduleCancel,
  scheduleCreate,
  scheduleList,
  scheduledTaskCap,
} from "./schedule";
import type { ScheduleKind } from "./schedule";
import { handleContainer } from "./container";
import {
  brokerAudit,
  brokerAuthorize,
  brokerClose,
  brokerRecordMint,
  brokerRegister,
  handleGitCredential,
} from "./git-credential";
import type { BrokerRunRecord } from "./git-credential";

// Container/sandbox class for the CONTAINER_SANDBOX binding (issue #415).
// Deploy-time enablement (test gate, live validation): the prebuilt
// docker.io/cloudflare/sandbox image backs this class, so no local Docker build
// is needed. Absent the binding, /container/* stays fail-closed (501).
//
// DENY-BY-DEFAULT EGRESS: the SDK's `Sandbox` (via the `@cloudflare/containers`
// base) defaults `enableInternet = true`, which would grant untrusted agent
// code FULL internet. We subclass it and pin the field to `false`, so EVERY
// container start — including the lazy auto-start on the first `exec` — is
// sealed. A governed allowlist opens specific hosts at runtime via
// `sandbox.setAllowedHosts(...)` (container.ts `/container/start`), which the
// Container base grants egress to even while `enableInternet` stays false.
//
// THIS FIELD IS THE LOAD-BEARING CONTROL FOR ISSUE #471. Cloudflare enforces it
// OUTSIDE the container (per the Containers "Handle outbound traffic" docs, with
// `enableInternet = false` "only traffic you explicitly allow ... can leave the
// container"; only ports 80/443 and Cloudflare-resolver DNS survive), so code
// running inside — including model-authored code — cannot switch it back on.
// Changing it, or binding CONTAINER_SANDBOX to a class that does not extend this
// one, silently converts the whole tier from enforced to cooperative.
//
// HTTPS INTERCEPTION (#471 rework). `@cloudflare/containers@0.3.7` defaults
// `interceptHttps = false` (dist/lib/container.js:329) and
// `@cloudflare/sandbox@0.12.4` never assigns it — the single occurrence in that
// package is a READ. With it off, `applyOutboundInterception` registers only
// `interceptAllOutboundHttp`, so `setDeniedHosts` binds PLAINTEXT HTTP ONLY and
// the provider denylist — whose entire purpose is stopping `https://api.anthropic.com`
// — never sees a provider request. We pin it `true` so the denylist binds the
// protocol every LLM provider actually speaks. The SDK then exports
// `SANDBOX_INTERCEPT_HTTPS=1` into the container, which is how the official
// sandbox image is told to trust `/etc/cloudflare/certs/cloudflare-containers-ca.crt`.
//
// FAILURE MODE IF THE IMAGE DOES NOT TRUST THE CA: TLS validation fails and
// HTTPS from inside the container stops working — including to the governed
// gateway. That is loud and fail-CLOSED (a broken run, not a silent bypass), but
// it is a LIVE-CF question we cannot settle offline: workerd has no container
// engine. See the LIVE-CF gate list in docs/cloudflare-container-isolation.md.
export class AgentSandbox extends Sandbox {
  enableInternet = false;
  interceptHttps = true;
}

// `ContainerProxy` MUST be exported from the Worker entrypoint: the Sandbox DO
// constructs outbound-interception fetchers via `ctx.exports.ContainerProxy`
// when a governed egress allowlist is applied (`setAllowedHosts`). Without this
// export, allowlist configuration throws "ctx.exports.ContainerProxy is
// undefined" at runtime. Since the #471 rework the SEALED path needs it too: it
// applies `setAllowedHosts([])` / `setDeniedHosts([])` so a reused instance name
// cannot carry a previous run's grant into a container attested as sealed.
export { ContainerProxy };

/**
 * Worker bindings. `AGENT_GATEWAY` is the Durable Object namespace for the
 * {@link AgentGateway} agent class; `GATEWAY_CONTROL_TOKEN` is the DIY bearer
 * credential FerroGate presents (seeded via `wrangler secret put`).
 *
 * The memory-layer bindings (issue #427) are OPTIONAL: `VECTORIZE` + `AI`
 * exist only when the default-off semantic-memory pilot is enabled, and the
 * `MEMORY_*` vars tune the governed memory routes in `memory.ts`.
 */
export interface Env {
  AGENT_GATEWAY: DurableObjectNamespace<AgentGateway>;
  /** DIY auth secret. Compared (constant-time) against the request bearer token. */
  GATEWAY_CONTROL_TOKEN: string;
  /** Semantic-memory pilot flag (beta). The pilot runs ONLY when `"true"`. */
  MEMORY_SEMANTIC_ENABLED?: string;
  /** Chat-history retention cap; defaults to `DEFAULT_MAX_PERSISTED_MESSAGES`. */
  MEMORY_MAX_PERSISTED_MESSAGES?: string;
  /** Per-instance schedule-row cap; defaults to `DEFAULT_MAX_SCHEDULED_TASKS`. */
  SCHEDULE_MAX_TASKS_PER_INSTANCE?: string;
  /** Vectorize index for the semantic pilot (unbound unless piloting). */
  VECTORIZE?: Vectorize;
  /** Workers AI binding used for pilot embeddings (unbound unless piloting). */
  AI?: Ai;
  /**
   * Container/sandbox isolation binding (issue #415): the Durable Object
   * namespace for a Cloudflare `Container` or `@cloudflare/sandbox` class. The
   * `/container/*` routes address a per-tenant instance BY NAME through it.
   * OPTIONAL — absent it, every container verb fails closed with
   * `container_unbound` (HTTP 501). Bind it in wrangler.toml to enable the tier.
   * Typed as a `Sandbox` namespace so `getSandbox(...)` in container.ts resolves
   * the real, fully-typed SDK stub (the bound class {@link AgentSandbox} is a
   * `Sandbox` subclass).
   */
  CONTAINER_SANDBOX?: DurableObjectNamespace<Sandbox>;
  /** Cap on captured container stdout/stderr bytes; defaults to 1_000_000. */
  CONTAINER_MAX_OUTPUT_BYTES?: string;
  /**
   * Comma-separated set of hosts an operator has authorized the container tier
   * to open egress to (issue #471) — in practice the FerroGate gateway, and
   * nothing else. `/container/start` rejects any `egressAllowlist` entry outside
   * this set.
   *
   * UNSET OR EMPTY MEANS NO HOST MAY BE OPENED: every container is sealed. The
   * failure mode of a forgotten configuration is "the agent reaches nothing",
   * never "the agent reaches everything".
   */
  CONTAINER_GOVERNED_EGRESS_HOSTS?: string;
  /**
   * GitHub App id backing the brokered per-operation git credential path
   * (issue #475). A plain var, not a secret. Absent it, `/git-credential/*`
   * fails closed with `github_app_unbound` (HTTP 501) — there is deliberately
   * no fallback to an injected `GITHUB_TOKEN`.
   */
  GITHUB_APP_ID?: string;
  /**
   * Secrets Store binding for the App private key. `get()` takes NO argument:
   * the secret NAME is fixed at deploy time in `secrets_store_secrets`, which
   * is precisely why a per-USER secret cannot be read through a binding.
   * OPTIONAL, and today usually absent: an RSA App key PEM is ~1.7 KB and the
   * Secrets Store beta caps a value at 1024 bytes, so the key normally lives in
   * `GITHUB_APP_PRIVATE_KEY` (Worker secret, 5 KB limit) instead.
   */
  GITHUB_APP_PRIVATE_KEY_STORE?: { get(): Promise<string> };
  /** App private key as a Worker secret (PKCS#8 PEM). Fallback read path. */
  GITHUB_APP_PRIVATE_KEY?: string;
  /** GitHub API origin; defaults to `https://api.github.com` (GHES: `/api/v3`). */
  GITHUB_API_BASE_URL?: string;
}

/**
 * Durable Object storage key holding the run's brokered git credential record
 * (issue #475): the grant, the callback-capability fingerprint, the operation
 * counter, the audit ring, and the outstanding revocation handle. Read and
 * written ONLY through the `brokerRecord*` seam below.
 */
const BROKER_RECORD_KEY = "ferrogate:git-credential:record";

/** Lifecycle status vocabulary mirrored by the Rust `CloudflareRunStatus`. */
export type RunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "stopped"
  | "cleaned_up";

/**
 * Transient per-run **init props** delivered to {@link AgentGateway.onStart}.
 *
 * Cloudflare has NO deploy-time `model` field: the agent picks its model / tools
 * / system prompt IN CODE at start, reading them from these props. That makes the
 * run runtime-selectable without redeploying the Worker. Props are the INPUT to a
 * run; they are distinct from the agent's persistent {@link AgentGatewayState}.
 */
interface RunProps {
  /** Runtime-selected model id (mirrors the Rust `CloudflareRunProps.model`). */
  model?: string;
  /** Runtime-selected tool set. */
  tools?: string[];
  /** Runtime-selected system prompt. */
  systemPrompt?: string;
  /**
   * Durable Object placement hint (`wnam`/`enam`/`weur`/…). **HONORED**: passed
   * to `getAgentByName(ns, name, { locationHint })` on `POST /control/start`.
   *
   * It is applied on the START call only, and that is not a shortcut — a
   * location hint is consumed by `namespace.get(id, options)` when the instance
   * is FIRST created and is identity-neutral (`idFromName` never sees it, see
   * partyserver `getServerByName`). Re-addressing an existing instance without
   * it therefore resolves the same object in the same place.
   *
   * An unrecognized value is REFUSED (422 `unsupported_location_hint`) rather
   * than dropped, so a typo cannot silently unplace a run.
   */
  locationHint?: string;
  /**
   * Data-jurisdiction constraint (`eu`/`fedramp`). **REFUSED** — a start
   * carrying it fails closed with 422 `jurisdiction_unsupported`.
   *
   * Why refuse instead of honoring or ignoring it: `getAgentByName` applies a
   * jurisdiction as `namespace.jurisdiction(j).idFromName(name)` — it changes
   * the Durable Object's IDENTITY, not just its placement. FerroGate addresses
   * a run by name from several independent call sites that do not share per-run
   * state (the managed-worker scheduler, the #428 cost governor's kill switch,
   * the #426/#427 schedule and memory clients). Honoring a per-run jurisdiction
   * on `start` alone would leave the instance reachable from the starter and
   * INVISIBLE to every other caller — including the over-budget kill path,
   * which would then "kill" an empty object while the real run kept spending.
   *
   * A jurisdiction is a property of the addressing scheme, so it belongs on the
   * DEPLOYMENT (one gateway Worker per jurisdiction), not on a run's props.
   * Until that exists, a compliance dial that cannot be honored is refused.
   * Silently recording it and reporting it back is the failure mode this
   * refusal exists to prevent.
   */
  jurisdiction?: string;
  /**
   * Dispatch routing-retry budget. **RECORDED ONLY** — persisted as
   * `recordedRoutingRetry` and reported by `status()`, but the Worker performs
   * no retry of its own: retrying a control call is FerroGate's transport
   * concern (it owns the timeout, the backoff, and the idempotency key), and a
   * second retry loop inside the Worker would multiply, not bound, the attempts.
   */
  routingRetry?: number;
}

/** Durable Object location hints Cloudflare accepts (`namespace.get` option). */
const LOCATION_HINTS: readonly string[] = [
  "wnam",
  "enam",
  "sam",
  "weur",
  "eeur",
  "apac",
  "oc",
  "afr",
  "me",
];

/**
 * Persisted per-agent state (lives in the DO's embedded SQLite).
 *
 * The `resolved*` fields are the model/tools/prompt/placement the agent RESOLVED
 * from the run's transient {@link RunProps} at start. They are persistent (they
 * survive hibernation) so a re-addressed, woken agent reads its already-chosen
 * runtime configuration from state without props being re-delivered.
 */
export interface AgentGatewayState {
  status: RunStatus;
  runId: string | null;
  sessionId: string | null;
  workerTemplateId: string | null;
  frameworkAdapter: string | null;
  capabilityEnvelopeId: string | null;
  resolvedModel: string | null;
  resolvedTools: string[];
  resolvedSystemPrompt: string | null;
  resolvedLocationHint: string | null;
  /** The `routingRetry` prop, recorded only — the Worker never retries on it. */
  recordedRoutingRetry: number | null;
  /**
   * DURABLE half of cancellation. The in-memory `AbortController` that aborts
   * work already in flight dies with hibernation/eviction, so the latch that
   * stops the run from starting NEW work has to live in persistent state. Once
   * set, every subsequent `invoke` on this instance is refused.
   */
  cancelRequested: boolean;
  /** Operator-supplied reason recorded with {@link cancelRequested}. */
  cancelReason: string | null;
  lastMessage: string | null;
  exitCode: number | null;
  updatedAt: number;
}

const INITIAL_STATE: AgentGatewayState = {
  status: "queued",
  runId: null,
  sessionId: null,
  workerTemplateId: null,
  frameworkAdapter: null,
  capabilityEnvelopeId: null,
  resolvedModel: null,
  resolvedTools: [],
  resolvedSystemPrompt: null,
  resolvedLocationHint: null,
  recordedRoutingRetry: null,
  cancelRequested: false,
  cancelReason: null,
  lastMessage: null,
  exitCode: null,
  updatedAt: 0,
};

/**
 * Statuses a run cannot leave. A lifecycle verb that would move a run OUT of
 * one of these is refused rather than applied: flipping a `completed` run to
 * `stopped` (or re-starting it) rewrites history the control plane already
 * recorded.
 */
const TERMINAL_STATUSES: readonly RunStatus[] = ["completed", "failed", "cleaned_up"];

/** Body of a `start` control call. */
interface StartRequest {
  sessionId: string;
  runId: string;
  workerTemplateId: string;
  frameworkAdapter: string;
  capabilityEnvelopeId: string;
  /** Per-run init props handed to `onStart(props)`. Optional; defaults empty. */
  props?: RunProps;
}

/** Body of an `invoke` (exec/attach) control call. */
export interface InvokeRequest {
  runRef: string;
  workloadRef: string;
  args: string[];
}

/**
 * Refusal envelope a lifecycle verb returns instead of a success envelope.
 *
 * Returned as a VALUE (not a thrown error) because Durable Object RPC strips a
 * thrown error's class identity — the same reason the memory verbs return a
 * `MemoryResult`. {@link controlJson} maps each code onto its HTTP status.
 */
export interface ControlRefusal {
  error: "not_found" | "run_conflict";
  runRef: string;
  detail: string;
}

/** Type guard used by the control routes to pick the HTTP status. */
function isRefusal(value: unknown): value is ControlRefusal {
  return typeof value === "object" && value !== null && "error" in value;
}

/** Success envelope of `start`. */
export interface StartResult {
  runRef: string;
  status: RunStatus;
}

/** Success envelope of `invoke`. */
export interface InvokeResult {
  runRef: string;
  status: RunStatus;
  exitCode: number | null;
  message: string;
}

/** Success envelope of the custom `status` RPC. */
export interface StatusResult {
  runRef: string;
  status: RunStatus;
  message: string | null;
  resolvedModel: string | null;
  resolvedLocationHint: string | null;
  recordedRoutingRetry: number | null;
  cancelRequested: boolean;
}

/**
 * Success envelope of `cancel`. `aborted` is the honest part: it says whether
 * in-flight work on the instance was actually signalled, or whether only the
 * durable cancel latch was set (nothing was running there).
 */
export interface CancelResult {
  runRef: string;
  status: RunStatus;
  aborted: boolean;
  detail: string;
}

/** Success envelope of `destroyRun`. */
export interface DestroyResult {
  runRef: string;
  status: RunStatus;
}

/**
 * The abort reason the Agents SDK passes to `ctx.abort()` as the FINAL step of
 * `Agent.destroy()` (agents@0.0.109,
 * `node_modules/agents/dist/chunk-3IQQY2UH.js:879-898`).
 *
 * Aborting the Durable Object also tears down the RPC channel the destroy call
 * arrived on, so a destroy that ran to completion surfaces to the caller as a
 * REJECTED RPC carrying exactly this message. That rejection is therefore proof
 * of success, not failure: it is only reachable after the DROPs, `deleteAlarm`
 * and `deleteAll` have already run. {@link handleControl} maps it back onto the
 * success envelope. `lifecycle.test.ts` pins the string so an SDK change breaks
 * a test instead of silently turning every destroy into a 502.
 */
export const SDK_DESTROY_ABORT_REASON = "destroyed";

/**
 * Reject at an observation point once the run has been cancelled.
 *
 * Written out rather than using `signal.throwIfAborted()` so the abort reason a
 * workload sees is always the one {@link AgentGateway.cancel} supplied.
 */
function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw signal.reason ?? new Error("aborted");
}

/**
 * The refusal a lifecycle verb returns for a `runRef` that was never started.
 *
 * Addressing a name ALWAYS yields a Durable Object stub — Cloudflare has no
 * "does this instance exist" primitive — so without this guard
 * `POST /control/destroy {"runRef":"typo"}` returned 200 `cleaned_up` and
 * FerroGate recorded lifecycle evidence for a run that never existed (and a
 * token holder could mint unbounded instances). Refusing before the first
 * `setState` also means no storage write ever happens, so the addressed object
 * stays empty and is never persisted.
 */
function notFound(runRef: string): ControlRefusal {
  return {
    error: "not_found",
    runRef,
    detail: `no run is bound to instance ${runRef}`,
  };
}

/**
 * The agent Durable Object. Each instance is addressable by name
 * (`getAgentByName(env.AGENT_GATEWAY, name)`), single-threaded, and stateful.
 *
 * The control-route verbs are plain async methods: called over Durable Object
 * RPC from the Worker's fetch handler. This is the ONLY way to drive an
 * individual agent instance's lifecycle — Cloudflare has no first-party REST
 * API for it.
 */
export class AgentGateway extends Agent<Env, AgentGatewayState> {
  initialState = INITIAL_STATE;

  /**
   * Abort handle for the workload currently executing on THIS instance, or
   * `null` when nothing is in flight.
   *
   * IN-MEMORY ONLY, and deliberately so: it dies with hibernation/eviction,
   * exactly like the in-run fiber handles Cloudflare documents. The DURABLE
   * half of cancellation is {@link AgentGatewayState.cancelRequested}, which a
   * woken instance re-reads before starting any further work. Together they are
   * the two halves a cancel needs: stop what is running, and stop what would
   * run next.
   */
  #inFlight: AbortController | null = null;

  /**
   * RPC: start (provision) this run. Maps the Rust `start_run`.
   *
   * "create" is LAZY on Cloudflare: `getAgentByName(ns, this.name)` already
   * instantiated this Durable Object (first addressing creates it; the same name
   * always resolves to the same instance). There is no separate create call — so
   * `start` resolves the per-run {@link RunProps} into persistent state and
   * records the run ids.
   *
   * The identity triple (`runId`/`sessionId`/`capabilityEnvelopeId`) is bound
   * ONCE. A start that disagrees with the bound triple is refused (`run_conflict`)
   * instead of re-pointing a live instance at a different run — silently
   * re-pointing would detach the control plane's evidence from the workload it
   * describes. An identical re-start is idempotent (a safe transport retry), and
   * a start against a terminal run is refused.
   *
   * NOTE ON `onStart`: the props are resolved HERE, not by calling
   * `this.onStart(props)`. The pinned Agents SDK (agents@0.0.109) rebinds
   * `this.onStart` in its constructor to a zero-argument wrapper
   * (`node_modules/agents/dist/chunk-3IQQY2UH.js:316-317`) which invokes the
   * user hook with NO arguments, so props handed to it were silently discarded
   * and every `resolved*` field fell back to its initial value.
   */
  async start(request: StartRequest): Promise<StartResult | ControlRefusal> {
    const bound = this.state.runId;
    if (bound !== null) {
      const sameRun =
        bound === request.runId &&
        this.state.sessionId === request.sessionId &&
        this.state.capabilityEnvelopeId === request.capabilityEnvelopeId;
      if (!sameRun) {
        return {
          error: "run_conflict",
          runRef: this.name,
          detail: `instance ${this.name} is already bound to run ${bound} (session ${this.state.sessionId})`,
        };
      }
      if (TERMINAL_STATUSES.includes(this.state.status) || this.state.cancelRequested) {
        return {
          error: "run_conflict",
          runRef: this.name,
          detail: `run ${bound} is already ${this.state.cancelRequested ? "cancelled" : this.state.status}`,
        };
      }
      // Identical re-start of a live run: idempotent, props are not re-resolved.
      return { runRef: this.name, status: this.state.status };
    }

    const props = request.props ?? {};
    this.setState({
      ...this.state,
      status: "running",
      runId: request.runId,
      sessionId: request.sessionId,
      workerTemplateId: request.workerTemplateId,
      frameworkAdapter: request.frameworkAdapter,
      capabilityEnvelopeId: request.capabilityEnvelopeId,
      // The agent chooses its model / tools / system prompt IN CODE here
      // (Cloudflare has no deploy-time model field). Written into PERSISTENT
      // state so they survive hibernation and every later invoke reads them
      // without props being re-sent.
      resolvedModel: props.model ?? this.state.resolvedModel,
      resolvedTools: props.tools ?? this.state.resolvedTools,
      resolvedSystemPrompt: props.systemPrompt ?? this.state.resolvedSystemPrompt,
      resolvedLocationHint: props.locationHint ?? this.state.resolvedLocationHint,
      recordedRoutingRetry: props.routingRetry ?? this.state.recordedRoutingRetry,
      cancelRequested: false,
      cancelReason: null,
      lastMessage: "started",
      updatedAt: Date.now(),
    });
    return { runRef: this.name, status: this.state.status };
  }

  /**
   * Agents SDK wake hook. Runs automatically on every cold start / wake and is
   * invoked by the SDK with NO arguments (see the note on {@link start}), so it
   * cannot carry per-run props. It is intentionally a no-op: a woken instance
   * reads its already-resolved run configuration from persistent state.
   */
  onStart(): void {}

  /**
   * Run the workload for one `invoke`, honoring `signal`.
   *
   * THE CANCELLATION CONTRACT. Cancellation on Cloudflare is COOPERATIVE (see
   * {@link cancel}), so everything a run does must flow through here and must
   * observe `signal`: work that ignores it keeps running and keeps spending
   * after the control plane has been told the run was killed. An implementation
   * must reject once aborted rather than resolve.
   *
   * The minimal deployable Worker has no long-running work to abort — it records
   * the invocation and returns. A framework harness / tool loop overrides this
   * and threads `signal` into every await and every subrequest it makes.
   */
  protected async dispatchWorkload(request: InvokeRequest, signal: AbortSignal): Promise<string> {
    throwIfAborted(signal);
    return `invoked ${request.workloadRef} (${request.args.length} args)`;
  }

  /** RPC: exec/attach and drive the run. Maps the Rust `exec_run`. */
  async invoke(request: InvokeRequest): Promise<InvokeResult | ControlRefusal> {
    if (this.state.runId === null) return notFound(this.name);
    if (this.state.cancelRequested) {
      // The durable half of the cancel latch: a cancelled run starts no further
      // work even after hibernation dropped the in-memory abort handle.
      const message = `refused: run cancelled (${this.state.cancelReason ?? "unspecified"})`;
      return { runRef: this.name, status: this.state.status, exitCode: null, message };
    }

    const controller = new AbortController();
    this.#inFlight = controller;
    try {
      const message = await this.dispatchWorkload(request, controller.signal);
      this.setState({
        ...this.state,
        status: "completed",
        lastMessage: message,
        exitCode: 0,
        updatedAt: Date.now(),
      });
      return { runRef: this.name, status: this.state.status, exitCode: 0, message };
    } catch (err) {
      if (controller.signal.aborted) {
        const message = `cancelled: ${this.state.cancelReason ?? "unspecified"}`;
        this.setState({
          ...this.state,
          status: "stopped",
          lastMessage: message,
          exitCode: null,
          updatedAt: Date.now(),
        });
        return { runRef: this.name, status: this.state.status, exitCode: null, message };
      }
      const message = `invoke failed: ${(err as Error).message}`;
      this.setState({
        ...this.state,
        status: "failed",
        lastMessage: message,
        exitCode: 1,
        updatedAt: Date.now(),
      });
      return { runRef: this.name, status: this.state.status, exitCode: 1, message };
    } finally {
      if (this.#inFlight === controller) this.#inFlight = null;
    }
  }

  /**
   * RPC: current status (out-of-band reconcile). Maps the Rust `run_status`.
   *
   * This is a CUSTOM status method — Cloudflare has NO `getStatus` primitive.
   * Returns the resolved model so a caller can confirm props round-tripped into
   * the run's persistent configuration, and the cancel latch so an operator can
   * tell "cancel was requested" from "the run reached a terminal state".
   */
  async status(): Promise<StatusResult | ControlRefusal> {
    if (this.state.runId === null) return notFound(this.name);
    return {
      runRef: this.name,
      status: this.state.status,
      message: this.state.lastMessage,
      resolvedModel: this.state.resolvedModel,
      resolvedLocationHint: this.state.resolvedLocationHint,
      recordedRoutingRetry: this.state.recordedRoutingRetry,
      cancelRequested: this.state.cancelRequested,
    };
  }

  /**
   * RPC: actively CANCEL in-flight work. Maps the Rust `cancel_run`.
   *
   * COOPERATIVE, NOT A FIBER CANCEL. Cloudflare documents fibers
   * (`startFiber().cancel` / `abortSubAgent`) as the in-run cancellation
   * primitive, but the pinned SDK does NOT ship it: `agents@0.0.109` contains no
   * fiber API at all (`grep -ri fiber node_modules/agents/` finds nothing). So
   * this route implements cancellation with the mechanism the runtime does give
   * us — an `AbortSignal` the workload observes:
   *
   *   1. abort {@link #inFlight}, which makes the in-flight
   *      {@link dispatchWorkload} reject at its next observation of the signal;
   *   2. set the DURABLE `cancelRequested` latch so a later `invoke` — including
   *      one that arrives after hibernation dropped the handle — is refused.
   *
   * WHAT AN OPERATOR ACTUALLY GETS. `aborted: true` means in-flight work on this
   * instance was signalled; `aborted: false` means nothing was running here and
   * only the latch was set. Neither can stop a workload that IGNORES the signal
   * (or one running outside this Durable Object, e.g. in a container). That is
   * why the #428 cost governor's `KillMode::Cancel` verifies the run afterwards
   * and escalates to `destroy` — a budget kill may not be best-effort.
   *
   * Distinct from a terminal "stop": there is no stop/pause primitive, an idle
   * agent hibernates on its own. A run that already reached a terminal state is
   * NOT flipped to `stopped`.
   */
  async cancel(reason: string): Promise<CancelResult | ControlRefusal> {
    if (this.state.runId === null) return notFound(this.name);
    if (TERMINAL_STATUSES.includes(this.state.status)) {
      return {
        runRef: this.name,
        status: this.state.status,
        aborted: false,
        detail: `run ${this.state.runId} already ${this.state.status}; nothing to cancel`,
      };
    }
    const aborted = this.#inFlight !== null;
    this.#inFlight?.abort(new Error(`ferrogate cancel: ${reason}`));
    this.#inFlight = null;
    this.setState({
      ...this.state,
      status: "stopped",
      cancelRequested: true,
      cancelReason: reason,
      lastMessage: `cancelled: ${reason}`,
      updatedAt: Date.now(),
    });
    return {
      runRef: this.name,
      status: this.state.status,
      aborted,
      detail: aborted
        ? "in-flight workload signalled and the cancel latch set"
        : "no workload in flight on this instance; cancel latch set",
    };
  }

  /**
   * RPC: tear down the run's resources. Maps the Rust `cleanup_run`.
   *
   * Calls the Agents SDK's own `this.destroy()` — the primitive #414's mapping
   * table names for this verb. It DROPs `cf_agents_state` /
   * `cf_agents_schedules` / `cf_agents_mcp_servers` / `cf_agents_queues`,
   * DELETES the Durable Object's alarm, and clears storage. Its predecessor here
   * called `ctx.storage.deleteAll()`, which leaves the alarm armed so a destroyed
   * run's schedules keep waking the object (issue #482).
   *
   * Named `destroyRun` (not `destroy`) because the base class reserves
   * `destroy(): Promise<void>`; this variant returns the status envelope the
   * control route reports back to FerroGate. The envelope is built BEFORE the
   * teardown because `destroy()` ends with `ctx.abort("destroyed")` — after it,
   * this object's state is gone.
   */
  async destroyRun(): Promise<DestroyResult | ControlRefusal> {
    if (this.state.runId === null) return notFound(this.name);
    // Signal any in-flight workload first: destroy pulls the storage out from
    // under it, and an un-signalled workload would keep running against a torn
    // down object.
    this.#inFlight?.abort(new Error("ferrogate destroy"));
    this.#inFlight = null;
    const result: DestroyResult = { runRef: this.name, status: "cleaned_up" };
    this.setState({
      ...this.state,
      status: "cleaned_up",
      lastMessage: "destroyed",
      updatedAt: Date.now(),
    });
    await this.destroy();
    return result;
  }

  // ---- Memory verbs (issue #427) ----------------------------------------
  //
  // Thin RPC delegates: the verb implementations live in `memory.ts` against
  // the structural `AgentMemoryHost` seam so index.ts stays a routing shell
  // (engineering standard #429). Each returns the RPC-safe `MemoryResult`
  // envelope — DO RPC would strip a thrown error's class identity.

  /** Layer 2 escape hatch used by the memory verbs: dynamic SqlStorage exec. */
  rawSql(query: string, bindings: SqlBinding[]): RawSqlResult {
    const cursor = this.ctx.storage.sql.exec(query, ...bindings);
    const rows = cursor.toArray() as Record<string, unknown>[];
    return { columns: cursor.columnNames, rows };
  }

  /** Chat-history retention cap for this deployment (layer 3 eviction). */
  get maxPersistedMessages(): number {
    return persistedMessageCap(this.env.MEMORY_MAX_PERSISTED_MESSAGES);
  }

  /** RPC: read the synced JSON state (memory layer 1). */
  async memoryStateGet() {
    return memoryStateGet(this);
  }

  /** RPC: validated whole-object state replace (memory layer 1). */
  async memoryStateSet(candidate: unknown) {
    return memoryStateSet(this, candidate);
  }

  /** RPC: query the embedded per-agent SQLite (memory layer 2). */
  async memorySqlQuery(sql: string, params: SqlBinding[]) {
    return memorySqlQuery(this, sql, params);
  }

  /** RPC: read persisted chat history (memory layer 3). */
  async memoryChatHistoryGet(limit?: number) {
    return memoryChatHistoryGet(this, limit);
  }

  /** RPC: prune chat history to the retention cap (memory layer 3). */
  async memoryChatHistoryPrune(maxMessages?: number) {
    return memoryChatHistoryPrune(this, maxMessages);
  }

  // ---- Scheduling verbs (issue #426) ------------------------------------
  //
  // Thin RPC delegates: the verb implementations live in `schedule.ts`
  // against the structural `AgentScheduleHost` seam (engineering standard
  // #429). Schedules persist as rows in `cf_agents_schedules`, multiplexed
  // through this DO's single alarm — they survive hibernation, and the SDK
  // re-arms the alarm in the constructor on wake.

  /** Per-instance schedule-row cap for this deployment. */
  get maxScheduledTasks(): number {
    return scheduledTaskCap(this.env.SCHEDULE_MAX_TASKS_PER_INSTANCE);
  }

  /** RPC: cancel-before-recreate + schedule one task (once/cron/interval). */
  async scheduleCreate(task: unknown) {
    return scheduleCreate(this, task);
  }

  /** RPC: list schedules, optionally filtered by taskId/kind. */
  async scheduleList(criteria?: { taskId?: string; kind?: ScheduleKind }) {
    return scheduleList(this, criteria);
  }

  /** RPC: cancel by FerroGate taskId or raw SDK schedule id. */
  async scheduleCancel(selector: { taskId?: string; scheduleId?: string }) {
    return scheduleCancel(this, selector);
  }

  // ---- Brokered git credential verbs (issue #475) -----------------------
  //
  // The run's credential grant lives HERE, in the run's own Durable Object,
  // and the `/git-credential/get` callback path reads it from here rather than
  // from the request body. That is the whole point: the container is the
  // untrusted party, so a grant it could supply is a grant it could forge.
  // Only `gitCredentialRegister` writes one, and only the control-plane-gated
  // `/git-credential/register` route can call it.

  /** DO storage seam for the broker verbs (`GitCredentialHost`). */
  async brokerRecordGet(): Promise<BrokerRunRecord | undefined> {
    return this.ctx.storage.get<BrokerRunRecord>(BROKER_RECORD_KEY);
  }

  async brokerRecordPut(record: BrokerRunRecord): Promise<void> {
    await this.ctx.storage.put(BROKER_RECORD_KEY, record);
  }

  async brokerRecordDelete(): Promise<void> {
    await this.ctx.storage.delete(BROKER_RECORD_KEY);
  }

  /** RPC: register this run's grant + callback-capability fingerprint. */
  async gitCredentialRegister(registration: unknown) {
    return brokerRegister(this, registration);
  }

  /** RPC: authorize one helper callback, charge the budget, audit the row. */
  async gitCredentialAuthorize(callback: unknown, capability: string, nowUnix: number) {
    return brokerAuthorize(this, callback, capability, nowUnix);
  }

  /** RPC: retain the just-minted token as this run's revocation handle. */
  async gitCredentialRecordMint(operationId: string, token: string, expiresAtUnix: number) {
    return brokerRecordMint(this, operationId, token, expiresAtUnix);
  }

  /** RPC: close the grant and surrender the outstanding token for revocation. */
  async gitCredentialClose() {
    return brokerClose(this);
  }

  /** RPC: this run's material-free credential audit rows. */
  async gitCredentialAudit() {
    return brokerAudit(this);
  }

  /**
   * The ONE method name FerroGate-minted schedules call back into (pinned by
   * `SCHEDULE_DISPATCH_METHOD` — callers can never schedule arbitrary agent
   * methods). Logs the firing and re-arms emulated intervals; the pinned
   * agents SDK (0.0.109) has NO `scheduleEvery`, so intervals are delayed
   * one-shots that re-schedule themselves here.
   */
  async runScheduledTask(payload: unknown) {
    await dispatchScheduledTask(this, payload);
  }

  /**
   * DIY auth gate for path-routed agent traffic (`/agents/:agent/:name/...`).
   * `routeAgentRequest` hands the request here after `onBeforeRequest`; we
   * re-check the bearer token as defense-in-depth before any agent work.
   */
  override async onRequest(request: Request): Promise<Response> {
    const denied = requireBearer(request, this.env.GATEWAY_CONTROL_TOKEN);
    if (denied) return denied;
    return super.onRequest(request);
  }
}

/**
 * Explicit control routes. Each verb addresses an agent instance BY NAME and
 * invokes an RPC method on it. This is the lifecycle surface FerroGate's Rust
 * control-surface impl (#412/#414) calls. The routes map onto the ACTUAL
 * Cloudflare agent primitives (issue #414), which are narrower than a typical
 * lifecycle API:
 *
 *   POST /control/start   { ..., props }  -> { runRef, status }  (LAZY create via
 *       getAgentByName + agent.start(props), which resolves model/tools/prompt)
 *   POST /control/invoke  { runRef, workloadRef, args }  -> { runRef, status, exitCode, message }
 *   POST /control/cancel  { runRef, reason }  -> { runRef, status, aborted, detail }
 *       (COOPERATIVE AbortSignal cancel — the pinned SDK ships no fiber API;
 *        NOT a "stop")
 *   POST /control/destroy { runRef }  -> { runRef, status }  (this.destroy())
 *   GET  /control/status?runRef=NAME  -> { runRef, status, message, resolvedModel, ... }
 *       (CUSTOM status method — there is no getStatus primitive)
 *
 * Every verb but `start` refuses an unknown `runRef` with 404 `not_found`, and
 * `start` refuses a conflicting re-bind with 409 `run_conflict`.
 *
 * There is deliberately NO stop/pause/resume/restart route: Cloudflare hibernates
 * an idle agent automatically (zero compute, state retained) and wakes it on the
 * next request. FerroGate models "stop" as hibernate + re-address, entirely
 * client-side (see the Rust `stop_run`), so it needs no route here.
 */
async function handleControl(request: Request, env: Env, url: URL): Promise<Response> {
  const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
  if (denied) return denied;

  const verb = url.pathname.slice("/control/".length);

  try {
    switch (verb) {
      case "start": {
        const body = (await request.json()) as StartRequest;
        const refusal = placementRefusal(body.props);
        if (refusal) return json(refusal, 422);
        // The run's agent instance is addressed by its runId. `locationHint` is
        // applied HERE, at first addressing, because that is when Cloudflare
        // places the Durable Object.
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runId, {
          locationHint: body.props?.locationHint as DurableObjectLocationHint | undefined,
        });
        return controlJson(await agent.start(body));
      }
      case "invoke": {
        const body = (await request.json()) as InvokeRequest;
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runRef);
        return controlJson(await agent.invoke(body));
      }
      case "cancel": {
        const body = (await request.json()) as { runRef: string; reason?: string };
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runRef);
        return controlJson(await agent.cancel(body.reason ?? "unspecified"));
      }
      case "destroy": {
        const body = (await request.json()) as { runRef: string };
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runRef);
        try {
          return controlJson(await agent.destroyRun());
        } catch (err) {
          // `this.destroy()` ends by aborting the Durable Object, which kills
          // the RPC channel this call arrived on. See SDK_DESTROY_ABORT_REASON:
          // this rejection means the teardown COMPLETED.
          if ((err as Error).message !== SDK_DESTROY_ABORT_REASON) throw err;
          return json({ runRef: body.runRef, status: "cleaned_up" satisfies RunStatus });
        }
      }
      case "status": {
        const runRef = url.searchParams.get("runRef");
        if (!runRef) return json({ error: "missing runRef" }, 400);
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, runRef);
        return controlJson(await agent.status());
      }
      default:
        return json({ error: `unknown control verb: ${verb}` }, 404);
    }
  } catch (err) {
    return json({ error: `control call failed: ${(err as Error).message}` }, 502);
  }
}

/**
 * Map a lifecycle verb's envelope onto an HTTP status: a {@link ControlRefusal}
 * becomes 404/409, anything else 200.
 */
function controlJson(result: unknown): Response {
  if (isRefusal(result)) {
    return json(result, result.error === "not_found" ? 404 : 409);
  }
  return json(result);
}

/**
 * Fail a start whose placement props cannot be honored, instead of accepting
 * and echoing them.
 *
 * `jurisdiction` is refused outright: `getAgentByName` applies it as
 * `namespace.jurisdiction(j).idFromName(name)`, so honoring it would change the
 * Durable Object's IDENTITY and leave the run unreachable from every FerroGate
 * call site that does not also carry it — including the #428 over-budget kill
 * switch. An unknown `locationHint` is refused because Cloudflare would reject
 * it at `namespace.get(...)` anyway, and a 422 naming the bad value beats a 502.
 */
function placementRefusal(props: RunProps | undefined): { error: string; detail: string } | null {
  if (props?.jurisdiction) {
    return {
      error: "jurisdiction_unsupported",
      detail:
        `props.jurisdiction=${props.jurisdiction} is refused: a jurisdiction changes the ` +
        "Durable Object's identity (namespace.jurisdiction(j).idFromName(name)), so a run " +
        "started with one would be invisible to every caller that addresses it without one. " +
        "Deploy a gateway Worker per jurisdiction instead of setting it per run.",
    };
  }
  if (props?.locationHint && !LOCATION_HINTS.includes(props.locationHint)) {
    return {
      error: "unsupported_location_hint",
      detail: `props.locationHint=${props.locationHint} is not one of ${LOCATION_HINTS.join("/")}`,
    };
  }
  return null;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Unauthenticated liveness probe (no secret exposed).
    if (url.pathname === "/healthz") {
      return json({ ok: true, worker: "ferrogate-agent-gateway" });
    }

    // 1. Explicit control routes (RPC to a named agent). Auth checked inside.
    if (url.pathname.startsWith("/control/")) {
      return handleControl(request, env, url);
    }

    // 1b. Memory routes (issue #427): governed read/write/query over the
    //     agent's per-instance memory layers. Auth checked inside.
    if (url.pathname.startsWith("/memory/")) {
      return handleMemory(request, env, url);
    }

    // 1c. Schedule routes (issue #426): governed create/list/cancel over the
    //     agent's in-DO SQLite scheduler. Auth checked inside. There is NO
    //     external enqueue primitive — scheduling is in-agent only, so this
    //     is the sole path FerroGate schedules future agent work through.
    if (url.pathname.startsWith("/schedule/")) {
      return handleSchedule(request, env, url);
    }

    // 1d. Container/sandbox routes (issue #415): governed
    //     prepare/start/exec/stop/logs/artifacts/cleanup over a per-tenant
    //     Cloudflare Container or @cloudflare/sandbox instance. Auth checked
    //     inside. Cloudflare exposes NO public container lifecycle REST API, so
    //     this is the sole tethered path FerroGate drives the isolation tier
    //     through — egress deny-by-default (enableInternet=false unless a
    //     governed allowlist is provided).
    if (url.pathname.startsWith("/container/")) {
      return handleContainer(request, env, url);
    }

    // 1e. Brokered git credential routes (issue #475): the container's git
    //     credential helper calls back here PER GIT OPERATION instead of
    //     holding a secret. The Worker authorizes the operation against the
    //     grant REGISTERED IN THE RUN'S DURABLE OBJECT (never against a grant
    //     the caller supplies), mints a repo-scoped GitHub App installation
    //     token, answers git, and records a material-free audit row — so
    //     nothing GitHub-shaped ever rests in the container, and every use is
    //     counted. Auth is checked per verb INSIDE: `register`/`revoke`/`audit`
    //     take GATEWAY_CONTROL_TOKEN, while `get` — the only verb the untrusted
    //     container can reach — takes the run-scoped callback capability and
    //     NOT the gateway control token. Fails closed (501) with no App bound.
    if (url.pathname.startsWith("/git-credential/")) {
      return handleGitCredential(request, env, url, ctx);
    }

    // 2. Path-routed agent traffic: /agents/:agent/:name/... — DIY-gated in
    //    onBeforeRequest/onBeforeConnect BEFORE the Durable Object is touched.
    const routed = await routeAgentRequest(request, env, {
      cors: true,
      onBeforeRequest: (req: Request) =>
        requireBearer(req, env.GATEWAY_CONTROL_TOKEN) ?? undefined,
      onBeforeConnect: (req: Request) =>
        requireBearer(req, env.GATEWAY_CONTROL_TOKEN) ?? undefined,
    });
    return routed ?? json({ error: "not found" }, 404);
  },
} satisfies ExportedHandler<Env>;
