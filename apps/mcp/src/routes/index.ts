/**
 * Contract-driven route registration and the composition root for the
 * `ferrogate-mcp` Worker.
 *
 * Routes are never hand-written here: {@link McpRouter.register} takes an
 * `operation_id`, looks the operation up in `../contract.ts`, and mounts the
 * handler at the contract's OWN path and method. A typo cannot produce a route
 * that is not in the contract, and the router records what it mounted so
 * `test/contract.test.ts` can assert the two never drift.
 *
 * ## Why a composition root at all
 *
 * `apps/gateway` shipped with an EMPTY module list in its composition root: 24
 * of its 31 contract operations were unreachable in the deployed Worker while
 * every test stayed green, because each suite built its own router instead of
 * driving the app the Worker exports. The defence is structural, not a
 * convention:
 *
 *  - {@link createMcpApp} is the ONLY place an `apps/mcp` route is mounted;
 *  - `src/index.ts` owns the single production module list and hands it here;
 *  - the router it returns is exported, and the anti-drift gate asserts that
 *    registry — plus `SELF.fetch` reachability probes against the real Worker —
 *    covers all 6 owned + 2 shared operations.
 */
import { type Context, Hono } from "hono";

import { PUBLIC_API_MAJOR } from "@ferrogate/core";

import {
  type ApiOperation,
  type HttpMethod,
  OWNED_OPERATION_IDS,
  SHARED_OPERATION_IDS,
  operationById,
} from "../contract.js";
import {
  DRAIN_UNAVAILABLE_CODE,
  type DrainBindings,
  type DrainState,
  NOT_DRAINING,
  resolveDrain,
} from "../drain.js";
import {
  errorEnvelope,
  recordOperation,
  releaseAdmissionHolds,
  requestIdentity,
  respondError,
} from "../http.js";
import { type McpEnv, portsBound } from "../ports.js";

/** Service identity echoed by `/healthz` and `/readyz` (Rust `SERVICE_NAME`). */
export const SERVICE_NAME = "ferrogate-mcp";
/** Rust reports `runtime: "pingora"`; that data plane is eliminated. */
export const RUNTIME_NAME = "workers";

/** The MCP protocol revision this ingress pins (see `src/protocol.ts`). */
export const MCP_PROTOCOL_REVISION = "2026-07-28";

/**
 * `HealthResponse.version` — Rust `env!("CARGO_PKG_VERSION")`
 * (`crates/ferrogate-gateway/src/responses.rs:72`).
 *
 * `docs/rewrite/cert2-dataplane.md` finding **A11** recorded its absence on this
 * Worker: an operator checking which build a colo serves had nothing to read.
 * (The finding named `apps/mcp` alone; the wave-19 boot proof found the same
 * hole on `control-plane` and `telemetry` too.)
 *
 * The TypeScript equivalent of `CARGO_PKG_VERSION` is the workspace version —
 * `package.json`'s `"0.0.0"` — carried as a constant rather than imported,
 * because a `resolveJsonModule` import of the ROOT manifest would bundle it into
 * the Worker. `apps/gateway/src/routes/service.ts` and
 * `apps/agent-runtime/src/routes/health.ts` carry it the same way for the same
 * reason.
 */
export const SERVICE_VERSION = "0.0.0";

export { OWNED_OPERATION_IDS, SHARED_OPERATION_IDS };

/**
 * Owned operations no module mounts yet. The anti-drift gate requires every
 * owned id to be either registered on the app the Worker exports or listed
 * here, so nothing can be quietly forgotten.
 *
 * EMPTY: `src/index.ts` mounts both modules, so all 6 are live.
 */
export const PENDING_MODULE_OPERATION_IDS: readonly string[] = [];

/** Hono environment for this Worker. */
export interface McpAppEnv {
  Bindings: McpEnv;
}

/** Handler signature for a contract operation. */
export type OperationHandler = (c: Context<McpAppEnv>) => Response | Promise<Response>;

/**
 * Mounts operations by `operation_id` and records what it mounted.
 *
 * The `app` is exposed because two routes this Worker serves are NOT contract
 * operations — the `405` method guards on `/v1/mcp`, `/v1/mcp/tool/execute` and
 * the identity paths, and the legacy `/health` + `/version` probes. Those go on
 * `router.app` directly and are deliberately absent from the registry, which is
 * asserted to equal the contract set exactly.
 */
export class McpRouter {
  readonly app: Hono<McpAppEnv>;
  readonly #registered = new Set<string>();

  constructor(app: Hono<McpAppEnv>) {
    this.app = app;
  }

  /** Operation ids mounted so far, in registration order. */
  registeredOperationIds(): readonly string[] {
    return [...this.#registered];
  }

  /** Look up an operation, or fail loudly — an unknown id is a porting bug. */
  static operationOrThrow(operationId: string): ApiOperation {
    const operation = operationById(operationId);
    if (operation === undefined) {
      throw new Error(`operation_id ${operationId} is not in the runtime API contract`);
    }
    return operation;
  }

  /**
   * Mount a handler at the contract's own path + method.
   *
   * Every registered operation is wrapped in ONE `finally` that releases the
   * admission reservations `src/http.ts` parked for this request. That is the
   * TS replacement for Rust's `Drop`-released `WalletCreditReservation`, and it
   * lives HERE rather than in each handler for the reason a per-handler
   * `finally` fails: a new operation added later would silently strand credits
   * for a whole TTL, and nothing would go red. `release()` never throws (see
   * `src/admission/quota.ts`), so a settlement problem cannot turn an
   * already-computed response into a 500.
   */
  register(operationId: string, handler: OperationHandler): this {
    const operation = McpRouter.operationOrThrow(operationId);
    if (this.#registered.has(operationId)) {
      throw new Error(`operation_id ${operationId} is already registered`);
    }
    const method: HttpMethod = operation.method;
    this.app.on(method, operation.honoPath, async (c) => {
      // FC-7: publish WHICH contract operation this request matched, before the
      // handler runs. `src/http.ts::authenticateRequest` reads it back and
      // enforces what the operation DECLARES (`rbac_action`), so the guard
      // arrives with the route instead of being re-stated by each of the five
      // authenticated surfaces — the same reason the `finally` below lives here
      // rather than in every handler.
      recordOperation(c.req.raw, operation);
      try {
        return await handler(c as Context<McpAppEnv>);
      } finally {
        await releaseAdmissionHolds(c.req.raw);
      }
    });
    this.#registered.add(operationId);
    return this;
  }
}

/**
 * A pluggable group of routes. Each module declares the contract operation ids
 * it mounts so the anti-drift gate can cross-check the production module list
 * against the router's registry.
 */
export interface RouteModule {
  /** A short name, used in assertion messages. */
  readonly name: string;
  /** Contract operation ids this module mounts. */
  readonly operationIds: readonly string[];
  register(router: McpRouter): void;
}

// ---------------------------------------------------------------------------
// Shared operations — `/healthz` + `/readyz`, present in EVERY Worker
// ---------------------------------------------------------------------------

/**
 * Body of `GET /healthz` — Rust `HealthResponse`, all four members, in the
 * struct's own declaration order (`serde` serialises in that order, so this is
 * the document a Rust deployment actually produced).
 *
 * ## `protocol` used to be here and is deliberately gone
 *
 * This Worker answered `{status, service, runtime, protocol}`: it had invented a
 * fifth member and dropped the one the contract requires, so `/healthz` was the
 * one operation in the fleet whose document depended on WHICH Worker answered
 * it. `docs/rewrite/CUTOVER-READINESS.md` §2.1 (A12) records the same class of
 * damage on `/readyz` — "three different documents for one contract operation".
 * A shared probe whose shape varies per Worker cannot be consumed by one uptime
 * check, which is the entire point of it being shared.
 *
 * Nothing is lost: the protocol revision is still on `GET /version`, still on
 * this Worker's `/readyz`, and is still negotiated authoritatively in the
 * JSON-RPC `initialize` result (`src/protocol.ts`) — which is where an MCP
 * client reads it. `apps/telemetry/test/fleet-health-contract.test.ts` is the
 * gate that keeps all five documents identical from now on.
 */
export interface HealthReport {
  status: "ok";
  service: string;
  version: string;
  runtime: string;
}

/**
 * Body of `GET /readyz` (Rust `ReadinessResponse`): the same four identity
 * members as {@link HealthReport}, then this Worker's own readiness evidence.
 */
export interface ReadinessReport {
  status: "ready" | "not_ready";
  service: string;
  version: string;
  runtime: string;
  protocol: string;
  /** Which conjunct failed. Same vocabulary as `apps/gateway` and `apps/agent-runtime`. */
  readiness_reason: string;
  /** The operator drain (`runtime-state/drain`), as of THIS request. */
  draining: boolean;
  accepting_new_requests: boolean;
  dependencies: { ready: boolean };
}

export function healthReport(): HealthReport {
  return {
    status: "ok",
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    runtime: RUNTIME_NAME,
  };
}

/**
 * Liveness vs readiness, exactly as the Rust probe pair splits them:
 * `/healthz` answers 200 as soon as the process runs, `/readyz` answers 200
 * only while the dependencies it needs are actually usable and `503 not_ready`
 * otherwise (Rust: `cluster_status().ready`).
 *
 * For this Worker "usable" means the port bundle is bound — an isolate running
 * without it answers `503 mcp_auth_unavailable` on every authenticated surface,
 * so reporting `ready` there would make the probe lie to the load balancer.
 */
export function readinessReport(
  env: McpEnv,
  operatorDrain: DrainState = NOT_DRAINING,
): { status: number; body: ReadinessReport } {
  // TWO conjuncts, exactly as `apps/gateway`'s `clusterStatus` ANDs them:
  // `state_ready` (this Worker: the port bundle is bound) and `accepting` (the
  // operator has not drained this deployment). Before FC-1 only the first
  // existed here, so `POST /admin/v1/drain` left this probe answering `ready`
  // from a Worker that would refuse every `tools/call` it was then sent — the
  // "probe lies to the load balancer" failure this decision table exists for.
  const dependenciesReady = portsBound(env);
  // "The operator drained this deployment" and "the drain document could not be
  // READ" are DIFFERENT FACTS and only one of them is a drain. Both refuse —
  // fail-closed is non-negotiable, a probe that reports ready when its control
  // could not be evaluated is the bypass again — but reporting `operator_drain`
  // when `GET /admin/v1/drain` says the fleet is NOT draining is the
  // incident-time lie `src/drain.ts` refused to ship on the DATA plane, and it
  // must not be shipped on the PROBE either. `drainRefusal` already splits the
  // two codes; this splits the same two reasons.
  //
  // Found by the wave-22 INTEGRATE boot proof, not by any suite: a fresh
  // `wrangler dev --local` answered `503 not_ready` with
  // `readiness_reason: "operator_drain"`, `draining: true`, on a deployment
  // nobody had drained. The vitest harness migrates `DB`, so the arm was never
  // reached there.
  const unavailable = operatorDrain.source === "unavailable";
  const draining = operatorDrain.draining && !unavailable;
  const ready = dependenciesReady && !draining && !unavailable;
  // Drain outranks dependencies in the REASON, as `clusterStatus` orders it: an
  // operator who drained a node wants to be told that, not told about the
  // dependencies a drained node was never going to serve from. An unevaluable
  // drain outranks both, because it is the reason the other two cannot be
  // trusted.
  const readinessReason = unavailable
    ? DRAIN_UNAVAILABLE_CODE
    : draining
      ? "operator_drain"
      : dependenciesReady
        ? "state_loaded"
        : "revision_missing";
  return {
    status: ready ? 200 : 503,
    body: {
      status: ready ? "ready" : "not_ready",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      protocol: MCP_PROTOCOL_REVISION,
      readiness_reason: readinessReason,
      draining,
      // NOT `!draining`: an unevaluable drain is not a drain, and it is still a
      // refusal. Reporting `accepting_new_requests: true` alongside
      // `status: "not_ready"` would be self-contradictory in one document — a
      // load balancer reading the field and an operator reading the status
      // would act on opposite answers.
      accepting_new_requests: !draining && !unavailable,
      dependencies: { ready: dependenciesReady },
    },
  };
}

function healthzHandler(c: Context<McpAppEnv>): Response {
  return c.json(healthReport());
}

async function readyzHandler(c: Context<McpAppEnv>): Promise<Response> {
  // The durable drain read happens HERE, on the readiness probe, and NOT on
  // `/healthz`: liveness must have no backend dependency, or a control-database
  // blip would make an orchestrator RESTART every node in the fleet — which
  // destroys exactly the in-flight work a drain exists to let finish.
  const report = readinessReport(c.env, await resolveDrain(c.env as DrainBindings));
  return c.json(report.body, report.status as 200);
}

// ---------------------------------------------------------------------------
// Composition root
// ---------------------------------------------------------------------------

export interface CreateMcpAppOptions {
  /** The route modules to mount. `src/index.ts` passes the production list. */
  readonly modules?: readonly RouteModule[];
}

/** The assembled Worker plus the registry the anti-drift gate inspects. */
export interface McpApp {
  readonly app: Hono<McpAppEnv>;
  readonly router: McpRouter;
}

export function createMcpApp(options: CreateMcpAppOptions = {}): McpApp {
  const app = new Hono<McpAppEnv>();
  const router = new McpRouter(app);

  // Shared health/readiness (contract `anonymous`, present in every Worker).
  // Registered FIRST so a probe can never be shadowed by a `:server` capture.
  router.register("getHealthz", healthzHandler);
  router.register("getReadyz", readyzHandler);

  // Retained from the pre-contract scaffold so existing probes keep working.
  // Neither is a contract operation, so neither enters the registry.
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/version", (c) =>
    c.json({
      api: PUBLIC_API_MAJOR,
      protocol: MCP_PROTOCOL_REVISION,
      transports: ["streamable_http", "sse"],
    }),
  );

  for (const module of options.modules ?? []) {
    module.register(router);
  }

  app.notFound((c) => {
    const { requestId } = requestIdentity(c.req.raw);
    return respondError(c, 404, errorEnvelope("not_found", "no such route", requestId));
  });

  app.onError((error, c) => {
    const { requestId } = requestIdentity(c.req.raw);
    // Never leak an internal message across the boundary.
    console.error("ferrogate-mcp unhandled error", error);
    return respondError(
      c,
      500,
      errorEnvelope("internal_error", "the MCP gateway could not complete this request", requestId),
    );
  });

  return { app, router };
}

/** The `405` guard shared by every fixed-method MCP path. */
export function methodNotAllowed(message: string): (c: Context<McpAppEnv>) => Response {
  return (c) => {
    const { requestId } = requestIdentity(c.req.raw);
    return respondError(c, 405, errorEnvelope("method_not_allowed", message, requestId));
  };
}
