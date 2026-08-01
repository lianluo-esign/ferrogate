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
import { PUBLIC_API_MAJOR } from "@ferrogate/core";
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
import { networkAccess } from "../middleware/network.js";
import { responseCache } from "../middleware/response-cache.js";
import type { GatewayEnv } from "../ports.js";
import { agentDiscoveryHandler } from "./agent-discovery.js";
import { nodeDrainGate } from "./drain.js";
import { metricsHandler, requestMetrics } from "./metrics.js";
import { renderPromptTemplateHandler } from "./prompts.js";
import { readinessResponse } from "./readiness.js";
import { reverseProxyFallThrough } from "./reverse-proxy.js";
import { RUNTIME_NAME, SERVICE_NAME, SERVICE_VERSION } from "./service.js";
import { getAgentSkillHandler, listAgentSkillsHandler } from "./skills.js";

// Service identity — `./service.ts`, re-exported here so every existing
// importer is unchanged. It is a separate module because `./metrics.ts` needs
// `SERVICE_NAME` and this file mounts `./metrics.ts`.
export { RUNTIME_NAME, SERVICE_NAME, SERVICE_VERSION } from "./service.js";

// ---------------------------------------------------------------------------
// Ownership tables
// ---------------------------------------------------------------------------

/** `/healthz` + `/readyz` — implemented in EVERY Worker, not owned by one app. */
export const SHARED_OPERATION_IDS = ["getHealthz", "getReadyz"] as const;

/**
 * `GET /metrics` — the Prometheus exposition, mounted HERE and not (only) on
 * `apps/control-plane`.
 *
 * `ROUTE-MAP.md` assigns the operation to the control plane, and that is where
 * the ADMIN projection of it belongs. But the cutover certification found the
 * consequence of leaving it there alone: the control plane measures none of the
 * 47 `ferrogate_*` series, emits two gauges, and every dashboard that queries
 * the rest breaks at cutover. Its own note names the remedy — *"the counters
 * live in `apps/gateway`; exposing them means a gateway-side `/metrics`"*.
 *
 * It is kept OUT of {@link SHARED_OPERATION_IDS} deliberately: that list means
 * "implemented in every Worker", and this is not — `apps/mcp` and
 * `apps/telemetry` measure nothing worth exposing. Being its own list is what
 * makes `test/contract.test.ts`'s exact-registry assertion say so out loud.
 */
export const OBSERVABILITY_OPERATION_IDS = ["getMetrics"] as const;

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
  // All four `HealthResponse` fields, in Rust's own order. `version` was the
  // one the certification found missing — see {@link SERVICE_VERSION}.
  return c.json({
    status: "ok",
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    runtime: RUNTIME_NAME,
  });
}

function readyzHandler(c: Context<GatewayEnv>): Response {
  // The readiness decision table (config revision loaded ∧ not draining →
  // 200/503) lives in `./readiness.ts`, together with the marker naming the one
  // input the platform constrains.
  return readinessResponse(c, SERVICE_NAME, RUNTIME_NAME);
}

/**
 * The tooling operations. FOUR are ported; THREE still answer 501.
 *
 * ## The split, and how it was decided
 *
 * The three that are ported all turned out to be pure projections of OPERATOR
 * CONFIG with no I/O — `handle_agent_skills` reads `state.config.skill_packages`
 * and `handle_prompt_template_render` reads `state.config.prompt_templates`.
 * Their old 501 notes claimed a dependency on "the read model in
 * `apps/control-plane`" that does not exist in the Rust path at all; re-reading
 * the Rust rather than trusting the note is what closed them. They now live in
 * `./skills.ts` and `./prompts.ts`, on `GATEWAY_SKILL_PACKAGES` /
 * `GATEWAY_PROMPT_TEMPLATES`, exactly as `./agent-discovery.ts` reads
 * `GATEWAY_AGENT_UPSTREAMS`.
 *
 * ## Why the remaining three are still 501 and not a payload
 *
 * Each is a projection of, or a dispatch into, a SUBSYSTEM THAT DOES NOT EXIST
 * IN THIS TREE — see the note on each. Answering an empty list, or an invented
 * tool result, would be a fake that papers over the gap: a client cannot tell
 * "this gateway has no tools registered" from "this gateway cannot register
 * tools", and the second is the truth today. 501 says the second.
 *
 * What IS real about them is everything the router owns. They are matched at
 * the contract's own path, guarded by `contractAuth`, and scope-checked, so an
 * anonymous caller gets `401 missing_api_key` and an under-scoped one
 * `403 scope_denied` — the 501 is only ever reached by a caller who was
 * entitled to the operation. `test/auth.test.ts` pins exactly that ladder
 * (401 / 403 / 501 on `/v1/tools`), which is the test that keeps this
 * approximation honest: it fails if a stub ever starts answering before the
 * guard, and it is what will have to be updated when a real handler lands.
 *
 * NONE of the three is a platform limit. Every one is a missing upstream:
 * Cloudflare can host all of them.
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
    "PORT-TODO(P: inventory-request-path §tool catalog): scoped projection of the " +
      "extension registry + registered MCP servers. Blocked on both registries " +
      "existing; not a platform limit.",
  );
  router.registerNotImplemented(
    "executeTool",
    // Rust `handle_tool_execute_with_backend(ToolExecuteBackend::Extension)`:
    // approval record → governed chokepoint → extension dispatch. The governed
    // decision path and the approval store are unported.
    "PORT-TODO(P: inventory-request-path §tool execution): governed native + MCP " +
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
    "PORT-TODO(P: inventory-request-path §function execution): sandboxed function " +
      "dispatch. Belongs to apps/agent-runtime (containers/@cloudflare/sandbox), " +
      "not to this Worker.",
  );
  // Skill packages are the `[[skill_packages]]` OPERATOR CONFIG TABLE, not
  // control-plane rows — `handle_agent_skills` reads `state.config`. Ported in
  // `./skills.ts`; see the header there for why the old note was wrong.
  router.register("listAgentSkills", listAgentSkillsHandler);
  router.register("getAgentSkill", getAgentSkillHandler);
  // Same story for `[[prompt_templates]]`, plus the renderer. `./prompts.ts`.
  router.register("renderPromptTemplate", renderPromptTemplateHandler);
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
  /**
   * Override the PRE-AUTH network gate. Production never passes this — the
   * default reads the `GATEWAY_IP_ALLOWLIST` / `GATEWAY_TRUST_FORWARDED_FOR` /
   * `GATEWAY_TRUSTED_PROXY_HOPS` /
   * `GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE` vars and is inert with none
   * of them set. It exists so a test can inject a fresh
   * `UnauthenticatedIpRateLimiter` and a fixed clock, since the real one is
   * isolate-scoped by design (see `middleware/network.ts`).
   *
   * It is deliberately NOT nullable: there is no way to ask for "no gate".
   */
  readonly networkAccess?: MiddlewareHandler<GatewayEnv>;
  /**
   * Override the exact-match AI response cache (Rust `AiResponseCache`).
   *
   * Production never passes this: the default reads the `GATEWAY_CACHE_*` vars
   * and is inert until `GATEWAY_CACHE_ENABLED=true`, which is Rust's
   * `CacheConfig::default().enabled == false`. It exists so a test can inject
   * the in-memory store with a fixed clock and assert TTL/LRU expiry, which no
   * test can do against the platform Cache API.
   *
   * Like `networkAccess` it is NOT nullable — there is no way to ask for "no
   * cache middleware", only for a cache that is switched off by config.
   */
  readonly responseCache?: MiddlewareHandler<GatewayEnv>;
  /**
   * Override the operator reverse-proxy catch-all (`./reverse-proxy.ts`).
   *
   * Production never passes this: the default reads `GATEWAY_ROUTES` /
   * `GATEWAY_UPSTREAMS` and is inert with neither set. It exists so a test can
   * inject a route table and a stub transport, because the real one performs an
   * outbound `fetch` that a hermetic suite must not make.
   *
   * NOT nullable, for the same reason as the two above: there is no way to ask
   * for "no fall-through", only for a fall-through with an empty table — and an
   * empty table is exactly `404 not_found`.
   */
  readonly reverseProxy?: MiddlewareHandler<GatewayEnv>;
  /**
   * Override the operator-drain gate (`./drain.ts`).
   *
   * Production never passes this: the default reads `GATEWAY_DRAIN` — the same
   * var, with the same parse, that `/readyz` reports — and is inert unless it
   * is the exact string `"true"`. It exists so a test can narrow or widen the
   * guarded operation set without restating the mount.
   *
   * NOT nullable, for the same reason as the three above: there is no way to
   * ask for "no drain gate", only for a gate whose flag is off.
   */
  readonly nodeDrain?: MiddlewareHandler<GatewayEnv>;
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

  // The producer behind `ferrogate_request_logs_total` /
  // `ferrogate_request_errors_total` / `ferrogate_request_status_total`.
  // AHEAD of the network gate on purpose: an `ip_denied` flood is exactly the
  // traffic the counters have to show, and counting behind the gate would
  // report an attack as silence. It does its work on the way OUT, so being
  // outermost costs nothing and still observes the client's final status.
  app.use("*", requestMetrics());

  // PRE-AUTH network gate (Rust `check_network_access`, issue #166). Mounted
  // HERE — after the request id is minted so a refusal still carries one, and
  // BEFORE `contractAuth` — because the Rust reason for its existence is that a
  // flood or credential-stuffing scan must never pay the virtual-key/storage
  // lookup cost. Inert until one of the four `GATEWAY_*` vars is set.
  app.use("*", options.networkAccess ?? networkAccess());

  // ONE table-driven guard for all 251 operations, ahead of every route.
  // Passed straight through (no wrapping middleware) — see `contractAuth`.
  app.use("*", contractAuth(options.deps ?? depsFromEnv));

  // Post-auth, pre-route: rate limit / quota admission, then guardrail
  // screening. See `CreateGatewayAppOptions.middleware`.
  for (const middleware of options.middleware ?? []) {
    app.use("*", middleware);
  }

  // OPERATOR DRAIN (Rust `plan_ai_ingress`'s `state.is_draining()` check, plus
  // its four siblings) → `503 node_draining` on the five spend-producing
  // operations. Mounted HERE — after admission, before the cache and the routes
  // — because that is where the Rust check sits relative to `finalize_auth`.
  // Inert unless `GATEWAY_DRAIN` is the exact string `"true"`, which is the
  // same value and the same parse `/readyz` uses. See `./drain.ts`.
  app.use("*", options.nodeDrain ?? nodeDrainGate());

  // The exact-match AI response cache (Rust `AiResponseCache`, consulted at
  // `server/chat.rs:481`). LAST in the chain and immediately before the routes,
  // which is the same place the Rust seam sits inside the handler: after the
  // credential is resolved (the key is built from the AUTHENTICATED identity),
  // after admission (a hit is still a request, so it must not bypass the rate
  // limiter) and after request-stage screening (a hit must not let a prompt
  // skip guardrails) — but before dispatch, because not dispatching is the
  // point. Inert until `GATEWAY_CACHE_ENABLED=true`.
  app.use("*", options.responseCache ?? responseCache());

  const router = new GatewayRouter(app);

  // Shared health/readiness (contract `anonymous`, present in every Worker).
  router.register("getHealthz", healthzHandler);
  router.register("getReadyz", readyzHandler);

  // `GET /metrics` — the Prometheus exposition over THIS isolate's counters.
  // Registered through the router, so `contractAuth` gives it the contract's
  // own `bearer` + `admin.read` ladder rather than a bespoke guard: an
  // anonymous scrape is `401 missing_api_key` and a data-plane key is
  // `403 scope_denied`. See `./metrics.ts` and
  // {@link OBSERVABILITY_OPERATION_IDS}.
  router.register("getMetrics", metricsHandler);

  registerToolingRoutes(router);

  for (const module of options.modules ?? []) {
    module.register(router);
  }

  // Retained from the pre-contract scaffold so existing probes keep working;
  // neither is a contract operation, so both fall through `contractAuth`.
  app.get("/health", (c) => c.json({ ok: true }));

  // GW-C11, fixed in wave 18. This route used to be registered in
  // `src/index.ts` AFTER `createGatewayApp` returned — i.e. after the
  // `app.all("*")` fall-through below — so the deployed gateway answered
  // `404 not_found` on `/version` while every one of 1875 tests stayed green.
  // It was the only one of the five Workers not serving `/version`.
  // `docs/rewrite/MOUNT-SEAMS.md` §3.2 has the measurement; the rule that a
  // route registered after the fall-through is DEAD is pinned by
  // `test/routes/registration-order.test.ts`, and this line's own gate is
  // `test/version.test.ts`.
  app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

  // The OPERATOR REVERSE-PROXY FALL-THROUGH (Rust step 12, §1.3;
  // `docs/rewrite/parity-audit-request-path.md` F9). See `./reverse-proxy.ts`.
  //
  // LAST, and the position is the whole correctness argument: Hono runs matched
  // handlers in REGISTRATION order, so an `app.all("*")` placed any earlier
  // would shadow all 251 contract operations AND `/health`. It is registered
  // after every `router.register`, after every caller-supplied module, and after
  // `/health` above.
  //
  // Inert with `GATEWAY_ROUTES` unset: the handler sees an empty table and calls
  // `c.notFound()`, so an undocumented path still gets the gateway's own
  // `404 not_found` envelope. `test/routes/reverse-proxy.test.ts` pins both
  // halves — that a configured operator route proxies, and that mounting this
  // changed nothing for a path no operator claimed.
  app.all("*", options.reverseProxy ?? reverseProxyFallThrough());

  return { app, router };
}
