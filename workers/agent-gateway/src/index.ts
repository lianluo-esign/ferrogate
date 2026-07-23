// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: FerroGate agent-gateway Worker (issue #413). The required front for ALL
//   Cloudflare agent operations: Cloudflare exposes NO first-party REST API to
//   create/start/stop/invoke/inspect/destroy an individual agent instance, so every
//   agent operation FerroGate drives is fronted by THIS Worker.

import { Agent, routeAgentRequest, getAgentByName } from "agents";

/**
 * Worker bindings. `AGENT_GATEWAY` is the Durable Object namespace for the
 * {@link AgentGateway} agent class; `GATEWAY_CONTROL_TOKEN` is the DIY bearer
 * credential FerroGate presents (seeded via `wrangler secret put`).
 */
export interface Env {
  AGENT_GATEWAY: DurableObjectNamespace<AgentGateway>;
  /** DIY auth secret. Compared (constant-time) against the request bearer token. */
  GATEWAY_CONTROL_TOKEN: string;
}

/** Lifecycle status vocabulary mirrored by the Rust `CloudflareRunStatus`. */
type RunStatus =
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
interface AgentGatewayState {
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
  onStart(props: RunProps): void {
    this.setState({
      ...this.state,
      resolvedModel: props.model ?? this.state.resolvedModel,
      resolvedTools: props.tools ?? this.state.resolvedTools,
      resolvedSystemPrompt: props.systemPrompt ?? this.state.resolvedSystemPrompt,
      resolvedLocationHint: props.locationHint ?? this.state.resolvedLocationHint,
      resolvedJurisdiction: props.jurisdiction ?? this.state.resolvedJurisdiction,
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

  /** RPC: tear down the run's resources. Maps the Rust `cleanup_run`. */
  async destroy(): Promise<{ runRef: string; status: RunStatus }> {
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
 * Constant-time-ish bearer check. Returns a 401/403 `Response` when the request
 * is NOT authorized, or `null` when it is.
 *
 * DIY auth is required: Cloudflare fronts the DO but does not authenticate the
 * caller for us. Bearer-token is the baseline; mTLS (client-cert on a custom
 * domain) and Cloudflare Access (JWT in `Cf-Access-Jwt-Assertion`) are the
 * documented stronger alternatives — swap the check below for those.
 */
function requireBearer(request: Request, expected: string | undefined): Response | null {
  if (!expected) {
    return json({ error: "gateway misconfigured: no control token" }, 500);
  }
  const header = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) {
    return json({ error: "missing bearer token" }, 401);
  }
  const presented = header.slice(prefix.length);
  if (!timingSafeEqual(presented, expected)) {
    return json({ error: "invalid bearer token" }, 403);
  }
  return null;
}

/** Length-independent constant-time string comparison. */
function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  // Fold length into the accumulator so mismatched lengths still run to the end.
  let diff = ab.length ^ bb.length;
  const max = Math.max(ab.length, bb.length);
  for (let i = 0; i < max; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
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
        const agent = await getAgentByName(env.AGENT_GATEWAY, body.runId);
        return json(await agent.start(body));
      }
      case "invoke": {
        const body = (await request.json()) as InvokeRequest;
        const agent = await getAgentByName(env.AGENT_GATEWAY, body.runRef);
        return json(await agent.invoke(body));
      }
      case "cancel": {
        const body = (await request.json()) as { runRef: string; reason?: string };
        const agent = await getAgentByName(env.AGENT_GATEWAY, body.runRef);
        return json(await agent.cancel(body.reason ?? "unspecified"));
      }
      case "destroy": {
        const body = (await request.json()) as { runRef: string };
        const agent = await getAgentByName(env.AGENT_GATEWAY, body.runRef);
        return json(await agent.destroy());
      }
      case "status": {
        const runRef = url.searchParams.get("runRef");
        if (!runRef) return json({ error: "missing runRef" }, 400);
        const agent = await getAgentByName(env.AGENT_GATEWAY, runRef);
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
