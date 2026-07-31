/**
 * Contract-driven route registration for the 31 gateway-owned operations.
 *
 * Routes are never hand-written here: `GatewayRouter.register` takes an
 * `operation_id`, looks the operation up in the contract, and mounts it at the
 * contract's own path/method translated into Hono syntax. A typo cannot produce
 * a route that is not in the contract, and the router records what it mounted so
 * `test/contract.test.ts` can assert the two never drift.
 *
 * Ownership (see the task split in ROUTE-MAP.md):
 *   - the 6 inference operations  → `src/inference/route-module.ts`
 *   - the 18 `/v1/assets/**` ops  → `src/assets/handlers.ts`
 * Both are in the contract table and both are guarded by `contractAuth`; each
 * is mounted by its own `RouteModule`, listed in `GATEWAY_ROUTE_MODULES` in
 * `src/index.ts` and passed to `createGatewayApp({ modules })`. Everything else
 * is mounted here.
 */
import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import { depsFromEnv } from "../adapters.js";
import { type ApiOperation, type HttpMethod, operationById } from "../contract.js";
import { type DepsResolver, contractAuth } from "../middleware/auth.js";
import {
  HttpError,
  gatewayErrorHandler,
  gatewayNotFoundHandler,
  requestId,
} from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";

/** Service identity echoed by `/healthz` and `/readyz` (Rust `SERVICE_NAME`). */
export const SERVICE_NAME = "ferrogate-gateway";
/** Rust reports `runtime: "pingora"`; the Pingora data plane is eliminated. */
export const RUNTIME_NAME = "workers";

// ---------------------------------------------------------------------------
// Ownership tables
// ---------------------------------------------------------------------------

/** `/healthz` + `/readyz` — implemented in EVERY Worker, not owned by one app. */
export const SHARED_OPERATION_IDS = ["getHealthz", "getReadyz"] as const;

/** The 6 inference operations. Owned by the inference agent this wave. */
export const INFERENCE_OPERATION_IDS = [
  "listModels",
  "createChatCompletion",
  "createResponse",
  "createEmbedding",
  "createMessage",
  "createImage",
] as const;

/** The 18 `/v1/assets/**` operations. Owned by the assets agent this wave. */
export const ASSET_OPERATION_IDS = [
  "listAssets",
  "getAssetStorageSummary",
  "listWithheldAssets",
  "listAssetsByType",
  "getAsset",
  "putAsset",
  "deleteAsset",
  "getAssetManifest",
  "listAssetChannels",
  "putAssetChannel",
  "deleteAssetChannel",
  "yankAssetVersion",
  "unyankAssetVersion",
  "promoteAssetVisibility",
  "createAssetUploadIntent",
  "commitAssetUpload",
  "abortAssetUpload",
  "getAssetDownloadUrl",
] as const;

/** Tools / functions / skills / prompts / agent discovery — mounted here. */
export const TOOLING_OPERATION_IDS = [
  "listTools",
  "executeTool",
  "executeFunction",
  "listAgentSkills",
  "getAgentSkill",
  "renderPromptTemplate",
  "getAgentDiscovery",
] as const;

/** All 31 operations `apps/gateway` owns per ROUTE-MAP.md. */
export const GATEWAY_OWNED_OPERATION_IDS: readonly string[] = [
  ...TOOLING_OPERATION_IDS,
  ...INFERENCE_OPERATION_IDS,
  ...ASSET_OPERATION_IDS,
];

/**
 * Gateway-owned operations no module mounts yet. The anti-drift test requires
 * every gateway-owned id to be either registered on the app the Worker exports
 * or listed here, so this list cannot be forgotten.
 *
 * EMPTY as of the composition-root wiring: `src/index.ts` mounts
 * `inferenceRouteModule()` + `assetRouteModule()`, so all 31 are live.
 */
export const PENDING_MODULE_OPERATION_IDS: readonly string[] = [];

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/** Handler signature for a contract operation. */
export type OperationHandler = (c: Context<GatewayEnv>) => Response | Promise<Response>;

/**
 * Mounts operations by `operation_id` and records what it mounted.
 *
 * This is the seam the inference / assets / streaming agents plug into: they
 * receive a `GatewayRouter` and call `register("createChatCompletion", handler)`
 * — they never restate a path, a method, or an auth rule.
 */
export class GatewayRouter {
  readonly app: Hono<GatewayEnv>;
  readonly #registered = new Set<string>();

  constructor(app: Hono<GatewayEnv>) {
    this.app = app;
  }

  /** Operation ids mounted so far. */
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

  /** Mount a handler at the contract's own path + method. */
  register(operationId: string, handler: OperationHandler): this {
    const operation = GatewayRouter.operationOrThrow(operationId);
    if (this.#registered.has(operationId)) {
      throw new Error(`operation_id ${operationId} is already registered`);
    }
    const method: HttpMethod = operation.method;
    this.app.on(method, operation.honoPath, (c) => handler(c as Context<GatewayEnv>));
    this.#registered.add(operationId);
    return this;
  }

  /** Mount a not-yet-ported operation as an explicit 501. */
  registerNotImplemented(operationId: string, note: string): this {
    return this.register(operationId, () => {
      throw new HttpError(501, "not_implemented", note);
    });
  }
}

/**
 * A pluggable group of routes. The inference and assets agents each export one
 * from their own directory (`src/inference/`, `src/assets/`) and it is passed to
 * `createGatewayApp`; nothing in this file needs to change for them to land.
 */
export interface RouteModule {
  /** Contract operation ids this module mounts. Used by the anti-drift test. */
  readonly operationIds: readonly string[];
  register(router: GatewayRouter): void;
}

// ---------------------------------------------------------------------------
// Handlers mounted here
// ---------------------------------------------------------------------------

function healthzHandler(c: Context<GatewayEnv>): Response {
  return c.json({ status: "ok", service: SERVICE_NAME, runtime: RUNTIME_NAME });
}

function readyzHandler(c: Context<GatewayEnv>): Response {
  // PORT-TODO(inventory-request-path §readiness): Rust answers 503 `not_ready`
  // while the upstream cluster has no healthy peer (`state.cluster_status()`).
  // Cluster health moves to the routing snapshot in `@ferrogate/routing`; until
  // that port lands a Worker isolate is ready as soon as it is running.
  return c.json({
    status: "ready",
    service: SERVICE_NAME,
    runtime: RUNTIME_NAME,
    cluster: { ready: true },
  });
}

/**
 * Thin stubs for the tooling operations. They are real *routes* — matched,
 * authenticated, scope-checked — that answer 501 until their behavior lands, so
 * an unauthenticated caller still gets 401 rather than a misleading 501.
 */
function registerToolingRoutes(router: GatewayRouter): void {
  router.registerNotImplemented(
    "listTools",
    "PORT-TODO(inventory-request-path §tool catalog): tool catalog projection",
  );
  router.registerNotImplemented(
    "executeTool",
    "PORT-TODO(inventory-request-path §tool execution): native + MCP tool dispatch",
  );
  router.registerNotImplemented(
    "executeFunction",
    "PORT-TODO(inventory-request-path §function execution): sandboxed function dispatch",
  );
  router.registerNotImplemented(
    "listAgentSkills",
    "PORT-TODO(inventory-request-path §skills): skill catalog",
  );
  router.registerNotImplemented(
    "getAgentSkill",
    "PORT-TODO(inventory-request-path §skills): skill detail",
  );
  router.registerNotImplemented(
    "renderPromptTemplate",
    "PORT-TODO(inventory-request-path §prompts): prompt template rendering",
  );
  router.registerNotImplemented(
    "getAgentDiscovery",
    "PORT-TODO(inventory-edge-control §agent discovery): /.well-known/agent.json document",
  );
}

// ---------------------------------------------------------------------------
// Composition root
// ---------------------------------------------------------------------------

export interface CreateGatewayAppOptions {
  /**
   * Ports backing the auth middleware. A factory receives the Worker bindings;
   * defaults to the config-var adapters in `../adapters.ts`.
   */
  readonly deps?: DepsResolver;
  /** Extra route modules (inference, assets, …). */
  readonly modules?: readonly RouteModule[];
  /**
   * Cross-cutting middleware mounted AFTER `contractAuth` and BEFORE every
   * route — the seam the rate-limit and guardrail slices are wired through.
   *
   * The position is load-bearing twice over. Hono runs matched handlers in
   * REGISTRATION order, so an `app.use("*", …)` added by the caller after
   * `createGatewayApp` returns would run after the route handler and gate
   * nothing; and both middlewares read `c.get("auth")`, so they must follow the
   * guard that sets it. `src/index.ts` supplies them in the Rust ingress order
   * — admission (rate limit / quota) before content screening (guardrails).
   */
  readonly middleware?: readonly MiddlewareHandler<GatewayEnv>[];
}

/** The assembled Worker plus the registry the anti-drift test inspects. */
export interface GatewayApp {
  readonly app: Hono<GatewayEnv>;
  readonly router: GatewayRouter;
}

export function createGatewayApp(options: CreateGatewayAppOptions = {}): GatewayApp {
  const app = new Hono<GatewayEnv>();

  app.onError(gatewayErrorHandler);
  app.notFound(gatewayNotFoundHandler);
  app.use("*", requestId);

  // ONE table-driven guard for all 251 operations, ahead of every route.
  // Passed straight through (no wrapping middleware) — see `contractAuth`.
  app.use("*", contractAuth(options.deps ?? depsFromEnv));

  // Post-auth, pre-route: rate limit / quota admission, then guardrail
  // screening. See `CreateGatewayAppOptions.middleware`.
  for (const middleware of options.middleware ?? []) {
    app.use("*", middleware);
  }

  const router = new GatewayRouter(app);

  // Shared health/readiness (contract `anonymous`, present in every Worker).
  router.register("getHealthz", healthzHandler);
  router.register("getReadyz", readyzHandler);

  registerToolingRoutes(router);

  for (const module of options.modules ?? []) {
    module.register(router);
  }

  // Retained from the pre-contract scaffold so existing probes keep working;
  // neither is a contract operation, so both fall through `contractAuth`.
  app.get("/health", (c) => c.json({ ok: true }));

  return { app, router };
}
