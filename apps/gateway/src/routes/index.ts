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
import { agentDiscoveryHandler } from "./agent-discovery.js";
import { readinessResponse } from "./readiness.js";
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
  // The readiness decision table (config revision loaded ∧ not draining →
  // 200/503) lives in `./readiness.ts`, together with the marker naming the one
  // input the platform constrains.
  return readinessResponse(c, SERVICE_NAME, RUNTIME_NAME);
}

/**
 * The tooling operations, as real ROUTES that answer 501.
 *
 * ## Why 501 and not a payload
 *
 * Each of the six below is a projection of, or a dispatch into, a SUBSYSTEM
 * THAT DOES NOT EXIST IN THIS TREE YET — see the note on each. Answering an
 * empty list, or an invented tool result, would be a fake that papers over the
 * gap: a client cannot tell "this gateway has no tools registered" from "this
 * gateway cannot register tools", and the second is the truth today. 501 says
 * the second.
 *
 * What IS real about them is everything the router owns. They are matched at
 * the contract's own path, guarded by `contractAuth`, and scope-checked, so an
 * anonymous caller gets `401 missing_api_key` and an under-scoped one
 * `403 scope_denied` — the 501 is only ever reached by a caller who was
 * entitled to the operation. `test/auth.test.ts` pins exactly that ladder
 * (401 / 403 / 501 on the same path), which is the test that keeps this
 * approximation honest: it fails if a stub ever starts answering before the
 * guard, and it is what will have to be updated when a real handler lands.
 *
 * NONE of these is a platform limit. Every one is a missing upstream:
 * Cloudflare can host all six.
 */
function registerToolingRoutes(router: GatewayRouter): void {
  router.registerNotImplemented(
    "listTools",
    // Rust `local.rs::handle_tools` → `state_tools.rs::tools_for`, which is
    // `extension_registry.tools_for(tenant, api_key_id, route)` PLUS the
    // registered MCP servers' tools. Neither source exists in the TS tree: the
    // plugin/extension registry (`ferrogate-runtime`) has no package yet, and
    // the MCP server registry lives in `apps/mcp`. Listing only one of the two
    // would understate what a tenant may call, which is worse than 501.
    "PORT-TODO(inventory-request-path §tool catalog): scoped projection of the " +
      "extension registry + registered MCP servers. Blocked on both registries " +
      "existing; not a platform limit.",
  );
  router.registerNotImplemented(
    "executeTool",
    // Rust `handle_tool_execute_with_backend(ToolExecuteBackend::Extension)`:
    // approval record → governed chokepoint → extension dispatch. The governed
    // decision path and the approval store are unported.
    "PORT-TODO(inventory-request-path §tool execution): governed native + MCP " +
      "tool dispatch (approval record, chokepoint allowlist, backend call). " +
      "Blocked on the extension registry and the governed-decision port.",
  );
  router.registerNotImplemented(
    "executeFunction",
    // The only one with a real deployment constraint attached: the Rust ran
    // user functions in an out-of-process sandbox. On Workers that is
    // `@cloudflare/sandbox`/containers, which `apps/agent-runtime` owns —
    // `apps/gateway` deliberately declares no container binding (see the
    // `compatibility_date` note in wrangler.toml).
    "PORT-TODO(inventory-request-path §function execution): sandboxed function " +
      "dispatch. Belongs to apps/agent-runtime (containers/@cloudflare/sandbox), " +
      "not to this Worker.",
  );
  router.registerNotImplemented(
    "listAgentSkills",
    // Skill PACKAGES are control-plane rows (`skill_packages`, admin CRUD);
    // this is their tenant-facing read projection.
    "PORT-TODO(inventory-request-path §skills): skill-package catalog projection. " +
      "Blocked on the skill_packages read model in apps/control-plane.",
  );
  router.registerNotImplemented(
    "getAgentSkill",
    "PORT-TODO(inventory-request-path §skills): skill detail. Same dependency as " +
      "listAgentSkills.",
  );
  router.registerNotImplemented(
    "renderPromptTemplate",
    // Template rows plus the renderer. The renderer is pure TS and trivial on
    // this platform; the rows are the missing half.
    "PORT-TODO(inventory-request-path §prompts): prompt-template rendering. " +
      "Blocked on the prompt_templates read model in apps/control-plane; the " +
      "renderer itself has no platform obstacle.",
  );
  // `/.well-known/agent.json` is a pure projection of the operator's
  // `[[agent_upstreams]]` table, so it is ported rather than stubbed. See
  // `./agent-discovery.ts`.
  router.register("getAgentDiscovery", agentDiscoveryHandler);
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
