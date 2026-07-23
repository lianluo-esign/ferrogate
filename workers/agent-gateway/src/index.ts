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

/** Persisted per-agent state (lives in the DO's embedded SQLite). */
interface AgentGatewayState {
  status: RunStatus;
  runId: string | null;
  sessionId: string | null;
  workerTemplateId: string | null;
  frameworkAdapter: string | null;
  capabilityEnvelopeId: string | null;
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

  /** RPC: start (provision) this run. Maps the Rust `start_run`. */
  async start(request: StartRequest): Promise<{ runRef: string; status: RunStatus }> {
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

  /** RPC: current status (out-of-band reconcile). Maps the Rust `run_status`. */
  async status(): Promise<{ runRef: string; status: RunStatus; message: string | null }> {
    return { runRef: this.name, status: this.state.status, message: this.state.lastMessage };
  }

  /** RPC: cancel/stop the run. Maps the Rust `stop_run`. */
  async cancel(reason: string): Promise<{ runRef: string; status: RunStatus }> {
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
 * control-surface impl (#412) calls.
 *
 *   POST /control/start   { sessionId, runId, ... }      -> { runRef, status }
 *   POST /control/invoke  { runRef, workloadRef, args }  -> { runRef, status, exitCode, message }
 *   POST /control/cancel  { runRef, reason }             -> { runRef, status }
 *   POST /control/destroy { runRef }                     -> { runRef, status }
 *   GET  /control/status?runRef=NAME                     -> { runRef, status, message }
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
