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
export class AgentSandbox extends Sandbox {
  enableInternet = false;
}

// `ContainerProxy` MUST be exported from the Worker entrypoint: the Sandbox DO
// constructs outbound-interception fetchers via `ctx.exports.ContainerProxy`
// when a governed egress allowlist is applied (`setAllowedHosts`). Without this
// export, allowlist configuration throws "ctx.exports.ContainerProxy is
// undefined" at runtime. The sealed (no-allowlist) path never needs it.
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
}

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
  /** DO placement hint (`wnam`/`enam`/`weur`/…). */
  locationHint?: string;
  /** Data-jurisdiction constraint (`eu`/`fedramp`). */
  jurisdiction?: string;
  /** Dispatch routing-retry budget. */
  routingRetry?: number;
}

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
  resolvedJurisdiction: string | null;
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
  resolvedJurisdiction: null,
  lastMessage: null,
  exitCode: null,
  updatedAt: 0,
};

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
interface InvokeRequest {
  runRef: string;
  workloadRef: string;
  args: string[];
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
   * RPC: start (provision) this run. Maps the Rust `start_run`.
   *
   * "create" is LAZY on Cloudflare: `getAgentByName(ns, this.name)` already
   * instantiated this Durable Object (first addressing creates it; the same name
   * always resolves to the same instance). There is no separate create call — so
   * `start` just delivers the per-run {@link RunProps} to {@link onStart}, which
   * resolves the runtime-selectable model/tools/prompt, then records the run ids.
   */
  async start(request: StartRequest): Promise<{ runRef: string; status: RunStatus }> {
    // onStart(props) reads the runtime-selectable model/tools/prompt from the
    // transient props. On a real cold start/wake Cloudflare calls onStart
    // automatically; here we invoke it at run start with the per-run props.
    this.onStart(request.props ?? {});
    this.setState({
      ...this.state,
      status: "running",
      runId: request.runId,
      sessionId: request.sessionId,
      workerTemplateId: request.workerTemplateId,
      frameworkAdapter: request.frameworkAdapter,
      capabilityEnvelopeId: request.capabilityEnvelopeId,
      lastMessage: "started",
      updatedAt: Date.now(),
    });
    return { runRef: this.name, status: this.state.status };
  }

  /**
   * Resolve this run's runtime configuration from its transient init props.
   *
   * This is where the agent chooses its model / tools / system prompt IN CODE
   * (Cloudflare has no deploy-time model field). The selections are read from the
   * per-run props and written into persistent state so they survive hibernation
   * and are available to every subsequent invoke without props being re-sent.
   * `locationHint` / `jurisdiction` are recorded for placement/compliance; a real
   * deployment would honor them when addressing sub-agents or storage.
   */
  onStart(props?: RunProps): void {
    this.setState({
      ...this.state,
      resolvedModel: props?.model ?? this.state.resolvedModel,
      resolvedTools: props?.tools ?? this.state.resolvedTools,
      resolvedSystemPrompt: props?.systemPrompt ?? this.state.resolvedSystemPrompt,
      resolvedLocationHint: props?.locationHint ?? this.state.resolvedLocationHint,
      resolvedJurisdiction: props?.jurisdiction ?? this.state.resolvedJurisdiction,
      updatedAt: Date.now(),
    });
  }

  /** RPC: exec/attach and drive the run. Maps the Rust `exec_run`. */
  async invoke(
    request: InvokeRequest,
  ): Promise<{ runRef: string; status: RunStatus; exitCode: number | null; message: string }> {
    // A real adapter dispatch (framework harness, tool loop, ...) runs here.
    // The minimal deployable Worker records the invocation and completes.
    const message = `invoked ${request.workloadRef} (${request.args.length} args)`;
    this.setState({
      ...this.state,
      status: "completed",
      lastMessage: message,
      exitCode: 0,
      updatedAt: Date.now(),
    });
    return { runRef: this.name, status: this.state.status, exitCode: 0, message };
  }

  /**
   * RPC: current status (out-of-band reconcile). Maps the Rust `run_status`.
   *
   * This is a CUSTOM status method — Cloudflare has NO `getStatus` primitive.
   * Returns the resolved model so a caller can confirm props round-tripped into
   * `onStart`.
   */
  async status(): Promise<{
    runRef: string;
    status: RunStatus;
    message: string | null;
    resolvedModel: string | null;
  }> {
    return {
      runRef: this.name,
      status: this.state.status,
      message: this.state.lastMessage,
      resolvedModel: this.state.resolvedModel,
    };
  }

  /**
   * RPC: actively CANCEL in-flight work. Maps the Rust `cancel_run`.
   *
   * Cloudflare's only cancellation primitive is FIBERS: a real run would hold a
   * `startFiber()` handle and call `.cancel()` (or `abortSubAgent(...)`) here.
   * This is distinct from a terminal "stop" — there is no stop/pause primitive;
   * an idle agent hibernates automatically. The minimal Worker records the cancel
   * and marks the run stopped.
   */
  async cancel(reason: string): Promise<{ runRef: string; status: RunStatus }> {
    // e.g. this.fiber?.cancel(); await this.abortSubAgent(...);
    this.setState({
      ...this.state,
      status: "stopped",
      lastMessage: `cancelled: ${reason}`,
      updatedAt: Date.now(),
    });
    return { runRef: this.name, status: this.state.status };
  }

  /**
   * RPC: tear down the run's resources. Maps the Rust `cleanup_run`.
   *
   * Named `destroyRun` (not `destroy`) because the Agents SDK base class
   * reserves `destroy(): Promise<void>`; this variant returns the status
   * envelope the control route reports back to FerroGate.
   */
  async destroyRun(): Promise<{ runRef: string; status: RunStatus }> {
    this.setState({
      ...this.state,
      status: "cleaned_up",
      lastMessage: "destroyed",
      updatedAt: Date.now(),
    });
    // Free the DO's stored rows; the instance may be evicted after this.
    await this.ctx.storage.deleteAll();
    return { runRef: this.name, status: "cleaned_up" };
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
 *       getAgentByName + agent.start(props); onStart(props) picks model/tools)
 *   POST /control/invoke  { runRef, workloadRef, args }  -> { runRef, status, exitCode, message }
 *   POST /control/cancel  { runRef, reason }  -> { runRef, status }  (FIBER cancel —
 *       the only cancellation primitive; NOT a "stop")
 *   POST /control/destroy { runRef }  -> { runRef, status }  (this.destroy())
 *   GET  /control/status?runRef=NAME  -> { runRef, status, message, resolvedModel }
 *       (CUSTOM status method — there is no getStatus primitive)
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
        // The run's agent instance is addressed by its runId.
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runId);
        return json(await agent.start(body));
      }
      case "invoke": {
        const body = (await request.json()) as InvokeRequest;
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runRef);
        return json(await agent.invoke(body));
      }
      case "cancel": {
        const body = (await request.json()) as { runRef: string; reason?: string };
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runRef);
        return json(await agent.cancel(body.reason ?? "unspecified"));
      }
      case "destroy": {
        const body = (await request.json()) as { runRef: string };
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, body.runRef);
        return json(await agent.destroyRun());
      }
      case "status": {
        const runRef = url.searchParams.get("runRef");
        if (!runRef) return json({ error: "missing runRef" }, 400);
        const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, runRef);
        return json(await agent.status());
      }
      default:
        return json({ error: `unknown control verb: ${verb}` }, 404);
    }
  } catch (err) {
    return json({ error: `control call failed: ${(err as Error).message}` }, 502);
  }
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
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
