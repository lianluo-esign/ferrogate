/**
 * Contract-driven route registration for the 40 gateway-owned operations.
 *
 * Routes are never hand-written here: `GatewayRouter.register` takes an
 * `operation_id`, looks the operation up in the contract, and mounts it at the
 * contract's own path/method translated into Hono syntax. A typo cannot produce
 * a route that is not in the contract, and the router records what it mounted so
 * `test/contract.test.ts` can assert the two never drift.
 *
 * Ownership (see the task split in ROUTE-MAP.md):
 *   - the 14 inference operations → `src/inference/route-module.ts`
 *   - the 18 `/v1/assets/**` ops  → `src/assets/handlers.ts`
 *   - the 1 `/sites/{*rest}` op   → `src/sites/index.ts`
 * All three are in the contract table; the first two are guarded by
 * `contractAuth` and the third defers the same ladder into its handler (see
 * {@link SITE_OPERATION_IDS}). Each
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
import { gatewayCors } from "../middleware/cors.js";
import {
  HttpError,
  envelopeBoundary,
  gatewayErrorHandler,
  gatewayNotFoundHandler,
  requestId,
} from "../middleware/errors.js";
import { networkAccess } from "../middleware/network.js";
import { responseCache } from "../middleware/response-cache.js";
import type { GatewayEnv } from "../ports.js";
import { defaultSiteDomainRouting } from "../sites/host.js";
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

/**
 * The 14 inference operations. Owned by the inference agent this wave.
 *
 * `countMessageTokens` (issue #671) is the Anthropic-native
 * `POST /v1/messages/count_tokens` pre-flight. It is an inference operation
 * even though it dispatches nothing: it reads the model registry, it is gated
 * by the same `messages.create` scope as `createMessage`, and it answers with
 * the same estimator the `/v1/messages` reservation uses. Putting it anywhere
 * else would separate the count from the arithmetic it must agree with.
 */
export const INFERENCE_OPERATION_IDS = [
  "listModels",
  // `getModel` — the single-model read (issue #670). It sits beside
  // `listModels` rather than in a discovery family of its own because it is the
  // same catalogue, the same `models.read` scope and the same tenant filters,
  // served by the same module.
  "getModel",
  "createChatCompletion",
  "createResponse",
  // The Responses conversation-state reads (issue #689). They sit beside
  // `createResponse` rather than in a "state" family of their own for the same
  // reason `getModel` sits beside `listModels`: same resource, same scope
  // (`responses.create` — see the registration note in
  // `../inference/handlers.ts`), same module, same tenant fence.
  "getResponse",
  "deleteResponse",
  "createEmbedding",
  "createMessage",
  "countMessageTokens",
  "createImage",
  // `createRerank` — `POST /v1/rerank` (issue #676). Reranking is an inference
  // operation in the only sense that matters here: it resolves a logical model
  // out of the same registry, plans against the same candidate ladder, spends
  // the same TPM window and lands in the same usage sink. It is bearer-guarded
  // on `embeddings.create` rather than a scope of its own — see the note on
  // `handleRerank` in `../inference/handlers.ts` for why a seventh data-plane
  // scope would have re-minted every existing RAG key to buy nothing.
  "createRerank",
  // The audio surface — `POST /v1/audio/{transcriptions,translations,speech}`
  // (issue #703). Inference operations for the same reason `createRerank` is:
  // the same registry, the same candidate ladder, the same TPM window, the same
  // usage sink and the same drain gate. They are guarded on a NEW
  // `audio.create` scope rather than a reuse — see `INFERENCE_SCOPES` in
  // `../keys/scopes.ts` for why audio, unlike reranking, has no existing family
  // whose scope would be the honest name for it.
  "createTranscription",
  "createTranslation",
  "createSpeech",
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

/** The five OpenAI-compatible `/v1/files` operations, backed by assets. */
export const FILES_OPERATION_IDS = [
  "listFiles",
  "createFile",
  "getFile",
  "getFileContent",
  "deleteFile",
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

/**
 * The `site` route group — `GET /sites/{*rest}` (issue #737).
 *
 * Its own list rather than a 19th entry in {@link ASSET_OPERATION_IDS}, because
 * the contract puts it in a different route GROUP (`site`, not `asset`) and
 * because its guard is different in kind: every asset operation is
 * bearer-guarded by the contract middleware, while this one is `anonymous`
 * there and runs the bearer ladder inside its handler, per site. Folding it
 * into the asset list would have hidden that distinction inside a count.
 *
 * Mounted by `src/sites/index.ts`, which serves it out of the same
 * `AssetService` the asset operations use.
 */
export const SITE_OPERATION_IDS = ["serveSite"] as const;

/** All 40 operations `apps/gateway` owns per ROUTE-MAP.md. */
export const GATEWAY_OWNED_OPERATION_IDS: readonly string[] = [
  ...TOOLING_OPERATION_IDS,
  ...INFERENCE_OPERATION_IDS,
  ...ASSET_OPERATION_IDS,
  ...FILES_OPERATION_IDS,
  ...SITE_OPERATION_IDS,
];

/**
 * Gateway-owned operations no module mounts yet. The anti-drift test requires
 * every gateway-owned id to be either registered on the app the Worker exports
 * or listed here, so this list cannot be forgotten.
 *
 * EMPTY as of the composition-root wiring: `src/index.ts` mounts
 * `inferenceRouteModule()` + `assetRouteModule()` + `siteRouteModule()`, so all
 * 40 are live.
 */
export const PENDING_MODULE_OPERATION_IDS: readonly string[] = [];

// ---------------------------------------------------------------------------
// Dropped capabilities — a DECISION, recorded where it is served
// ---------------------------------------------------------------------------

/**
 * The HTTP status a dropped capability answers with.
 *
 * **The contract does not prescribe one.** `docs/openapi/runtime-api-contract.json`
 * carries no response-status vocabulary at all — an operation is
 * `{path, method, operation_id, visibility, auth, rbac_action}` and nothing
 * more — so there was no contract rule to satisfy here and no status to change
 * to. 501 stays for three independent reasons:
 *
 *  1. **It is the house precedent.** The only 501 the Rust gateway ever
 *     originates is `crates/ferrogate-gateway/src/server/local.rs:11835`
 *     `self_hosted_worker_production_mtls_not_implemented` — "this build does
 *     not do this", which is exactly the shape of the answer here.
 *  2. **It is the only status whose meaning fits.** RFC 9110 §15.6.2 is "the
 *     server does not support the functionality required to fulfil the
 *     request", and is the one non-2xx defined as cacheable by default, i.e.
 *     *permanent unless stated otherwise*. That is a dropped capability.
 *  3. **Every alternative lies about something.** `404` would deny a route that
 *     exists, is contract-matched and is auth-guarded. `403` would blame the
 *     caller's credential for a decision about the deployment. `503` would
 *     promise the capability comes back when something recovers.
 *
 * What was wrong before this decision was never the status. It was the BODY:
 * `501 not_implemented` + a `PORT-TODO(...)` note reads as a promise, and after
 * 2026-08-02 there is nothing being promised. See {@link DROPPED_CAPABILITIES}.
 */
export const DROPPED_CAPABILITY_STATUS = 501;

/**
 * The machine-readable code a dropped capability answers with.
 *
 * Deliberately NOT `not_implemented`. A client switching on `not_implemented`
 * is being told to retry after the next release; a client switching on
 * `capability_not_offered` is being told to stop asking, or to choose a
 * deployment that offers it. That distinction is the entire product decision,
 * and the code is the only part of the envelope a machine reads.
 */
export const DROPPED_CAPABILITY_CODE = "capability_not_offered";

/** The date the owner made the call. Carried on the wire so it can be audited. */
export const DROPPED_CAPABILITY_DECIDED_ON = "2026-08-02";

/** Where the reasoning is written down, cited in every refusal. */
export const DROPPED_CAPABILITY_DOC = "docs/rewrite/DROPPED-CAPABILITIES.md";

/** One capability this deployment has decided not to offer. */
export interface DroppedCapability {
  /** Contract operation id. Must be a real one — `register` verifies it. */
  readonly operationId: string;
  /** The `CUTOVER-READINESS.md` §3 spec-bound cluster this belonged to. */
  readonly cluster: "S1" | "S2";
  /** One clause, present tense: what this deployment does not do. */
  readonly what: string;
}

/**
 * THE DROPPED SET — the owner's decision of 2026-08-02, recorded in code.
 *
 * `docs/rewrite/CUTOVER-READINESS.md` §0.3 offered three exits per spec-bound
 * cluster — **build**, **transcribe**, or **drop** — and §0.5.6 left exactly two
 * clusters open. The owner took the third exit on both:
 *
 *   * **S1 · `executeFunction`** — the brokered edge-function egress path.
 *   * **S2 · `listTools` / `executeTool`** — the native tool catalogue and the
 *     governed dispatch into it.
 *
 * These three operations answered 501 before the decision and answer 501 after
 * it, which is precisely the hazard: *a 501 nobody decided and a 501 somebody
 * chose look identical in the code*. They are distinguishable to an operator,
 * an auditor and a future maintainer only if the difference is written into the
 * response and into the tree, so it is written into both — here, in the body
 * {@link droppedCapabilityMessage} builds, and in {@link DROPPED_CAPABILITY_DOC}.
 *
 * Adding an entry here is not a code change, it is a PRODUCT change, and
 * `test/routes/dropped-capabilities.test.ts` treats it as one: that gate
 * hard-codes this list rather than importing it, so growing or shrinking the
 * set is RED until the gate and the document are updated too.
 */
export const DROPPED_CAPABILITIES: readonly DroppedCapability[] = [
  {
    operationId: "executeFunction",
    cluster: "S1",
    what: "this gateway does not broker calls out to tenant edge functions",
  },
  {
    operationId: "listTools",
    cluster: "S2",
    what: "this gateway does not publish a native tool catalogue",
  },
  {
    operationId: "executeTool",
    cluster: "S2",
    what: "this gateway does not execute catalogue tools on a caller's behalf",
  },
];

/** Operation ids in {@link DROPPED_CAPABILITIES}, in decision order. */
export const DROPPED_OPERATION_IDS: readonly string[] = DROPPED_CAPABILITIES.map(
  (capability) => capability.operationId,
);

/** Look up a dropped capability, or fail loudly — an unknown id is a wiring bug. */
export function droppedCapability(operationId: string): DroppedCapability {
  const capability = DROPPED_CAPABILITIES.find((entry) => entry.operationId === operationId);
  if (capability === undefined) {
    throw new Error(`operation_id ${operationId} is not a declared dropped capability`);
  }
  return capability;
}

/**
 * The refusal an operator reads at 3am.
 *
 * Four things, in the order someone triaging needs them: WHAT was refused and
 * that it is a property of this deployment rather than of their request; WHY —
 * a decision, with a date, attributable to the owner; that it is NOT an outage
 * and NOT work in flight, so nobody waits for it to come back; and WHERE the
 * full reasoning lives, which survives the deletion of the Rust tree.
 *
 * It deliberately contains no "yet", no "not implemented" and no TODO marker.
 * `test/routes/dropped-capabilities.test.ts` asserts their absence, because
 * promise language is how a decision silently turns back into a backlog item.
 */
export function droppedCapabilityMessage(capability: DroppedCapability): string {
  return [
    `${capability.operationId} is not offered by this deployment: ${capability.what}.`,
    `The capability was dropped by owner decision on ${DROPPED_CAPABILITY_DECIDED_ON}`,
    `(cutover cluster ${capability.cluster}) — a deliberate product position, not an outage`,
    "and not a build under way. The decision, the behaviour it dropped and what a future",
    `implementer would need are recorded in ${DROPPED_CAPABILITY_DOC}.`,
  ].join(" ");
}

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

  /**
   * Mount an operation this deployment has DECIDED not to offer.
   *
   * The mount is real: the operation is matched at the contract's own path and
   * method and runs the full `contractAuth` ladder, so an anonymous caller
   * still gets `401 missing_api_key` and an under-scoped one `403 scope_denied`
   * — the refusal below is only ever reached by a caller who was entitled to
   * the operation. Leaving it UNMOUNTED instead would answer `404 not_found`,
   * which claims the endpoint does not exist; it does, and this deployment
   * declines to serve it. See {@link DROPPED_CAPABILITIES}.
   *
   * Takes no note argument, unlike the `registerNotImplemented` it replaced: a
   * per-call-site string is how the old three refusals drifted into three
   * different PORT-TODO paragraphs. The wording is derived from the decision
   * table so all of them say the same thing and can only change together.
   */
  registerDropped(operationId: string): this {
    const capability = droppedCapability(operationId);
    return this.register(operationId, () => {
      throw new HttpError(
        DROPPED_CAPABILITY_STATUS,
        DROPPED_CAPABILITY_CODE,
        droppedCapabilityMessage(capability),
      );
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

function readyzHandler(c: Context<GatewayEnv>): Promise<Response> {
  // The readiness decision table (config revision loaded ∧ not draining →
  // 200/503) lives in `./readiness.ts`. ASYNC since wave 22: the drain input is
  // now the durable `runtime-state/drain` document OR the `GATEWAY_DRAIN` var,
  // so `POST /admin/v1/drain` flips readiness without a deploy (FC-1).
  return readinessResponse(c, SERVICE_NAME, RUNTIME_NAME);
}

/**
 * The tooling operations. FOUR are served; THREE are DROPPED.
 *
 * ## The four that are served
 *
 * They all turned out to be pure projections of OPERATOR CONFIG with no I/O —
 * `handle_agent_skills` reads `state.config.skill_packages` and
 * `handle_prompt_template_render` reads `state.config.prompt_templates`. Their
 * old 501 notes claimed a dependency on "the read model in
 * `apps/control-plane`" that does not exist in the Rust path at all; re-reading
 * the Rust rather than trusting the note is what closed them. They now live in
 * `./skills.ts` and `./prompts.ts`, on `GATEWAY_SKILL_PACKAGES` /
 * `GATEWAY_PROMPT_TEMPLATES`, exactly as `./agent-discovery.ts` reads
 * `GATEWAY_AGENT_UPSTREAMS`.
 *
 * ## The three that are dropped — a DECISION, taken on 2026-08-02
 *
 * `listTools`, `executeTool` (cluster S2) and `executeFunction` (cluster S1)
 * are **not offered by this deployment**. `docs/rewrite/CUTOVER-READINESS.md`
 * §0.3 gave each spec-bound cluster three exits — build, transcribe, or drop —
 * and the owner took the third for both of these. It was a legitimate exit and
 * it is now a settled product position, not a backlog item.
 *
 * They answered 501 BEFORE that decision too, as unported stubs carrying
 * `PORT-TODO(...)` notes, and that is exactly why the difference has to be
 * visible on the wire: a 501 nobody decided and a 501 somebody chose are
 * indistinguishable in a route table. Since the decision they answer
 * `501 capability_not_offered` with a body that names the decision and its date
 * — see {@link DROPPED_CAPABILITIES} for the reasoning, the status choice and
 * the wording, and `docs/rewrite/DROPPED-CAPABILITIES.md` for what the Rust did,
 * why it was dropped, and what a future implementer would need if it is ever
 * revisited.
 *
 * Answering an empty list or an invented tool result instead would be strictly
 * worse than refusing: a client cannot tell "this gateway has no tools
 * registered" from "this gateway does not do tools", and the second is the
 * truth. The refusal says the second, out loud.
 *
 * What IS real about them is everything the router owns. They are matched at
 * the contract's own path, guarded by `contractAuth`, and scope-checked, so an
 * anonymous caller gets `401 missing_api_key` and an under-scoped one
 * `403 scope_denied` — the refusal is only ever reached by a caller who was
 * entitled to the operation. `test/auth.test.ts` pins that ladder
 * (401 / 403 / 501 on `/v1/tools`) and
 * `test/routes/dropped-capabilities.test.ts` pins the drop itself, so a silent
 * re-enable, a re-route to a real handler, or a slide back into promise
 * language is RED.
 *
 * NONE of the three was dropped because of a platform limit — Cloudflare can
 * host all three, and `executeFunction` in particular needs only `fetch()` and
 * WebCrypto HMAC. They were dropped because the owner decided this product does
 * not offer them.
 */
function registerToolingRoutes(router: GatewayRouter): void {
  // S2 · Rust `local.rs:2890 handle_tools` → `extensions.rs:214 tools_for`,
  // i.e. `extension_registry.tools_for(tenant, api_key_id, route)` PLUS the
  // registered MCP servers' tools.
  router.registerDropped("listTools");
  // S2 · Rust `local.rs:3573 handle_tool_execute_with_backend(Extension)`:
  // approval record → governed chokepoint → extension dispatch.
  router.registerDropped("executeTool");
  // S1 · Rust `local.rs:3219 handle_function_execute` — a BROKER, not a
  // sandbox: fail-closed per-tenant `FunctionEgressAllowlist`, a short-lived
  // signed function token, and a `POST` to a Supabase Edge Function or a
  // Cloudflare Worker. `docs/rewrite/DROPPED-CAPABILITIES.md` §S1 carries the
  // full description, because the `crates/` tree is being deleted and these
  // citations stop resolving. (Written without a `crates` glob on purpose: the
  // `/` + `*` + `*` sequence opens a block comment to the naive stripper
  // `test/fleet-control-matrix.test.ts` runs over this file, which then eats
  // the next `export` — its §1 vacuity guard catches exactly that.)
  router.registerDropped("executeFunction");
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
  /**
   * Override the VERIFIED-CUSTOM-DOMAIN router (`../sites/host.ts`, issue #738).
   *
   * Production never passes this: the default reads `env.CONTROL_DB` and is
   * inert with no control database, with no `site_domains` row for the inbound
   * authority, or with an unreadable directory. It exists so a test can inject
   * a pre-built `AssetService` and a fixed clock, since the real one resolves
   * bundles out of R2 and reads the wall clock to apply verification expiry.
   *
   * NOT nullable, for the same reason as its four siblings: there is no way to
   * ask for "no custom-domain routing", only for a router whose directory
   * contains nothing.
   */
  readonly siteDomains?: MiddlewareHandler<GatewayEnv>;
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

  // THE OUTER ENVELOPE BOUNDARY (issue #733) — the last line for a value Hono
  // itself will not route to `app.onError`, which is anything that is not an
  // `Error` (`compose` rethrows those). Below `requestMetrics` so a refusal it
  // renders is still counted, and above everything else so a throw raised BY
  // the network gate, the auth guard or any cross-cutting middleware is still
  // answered with the documented body. See `middleware/errors.ts` for why one
  // mount is not enough.
  app.use("*", envelopeBoundary);

  // PRE-AUTH network gate (Rust `check_network_access`, issue #166). Mounted
  // HERE — after the request id is minted so a refusal still carries one, and
  // BEFORE `contractAuth` — because the Rust reason for its existence is that a
  // flood or credential-stuffing scan must never pay the virtual-key/storage
  // lookup cost. Inert until one of the four `GATEWAY_*` vars is set.
  app.use("*", options.networkAccess ?? networkAccess());

  // CORS preflight must run before contractAuth: browsers do not send bearer
  // credentials on OPTIONS, and only the configured origin is allowed.
  app.use("*", gatewayCors);

  // VERIFIED CUSTOM DOMAINS (issue #738) — a request that arrived on a hostname
  // some tenant has PROVEN it controls is served from that tenant's published
  // site bundle, through the very same `SiteServer.serve` the `/sites/{slug}`
  // route calls.
  //
  // Mounted HERE, above `contractAuth` and above every route, because on such a
  // hostname the AUTHORITY belongs to the tenant: `/healthz`, `/version`,
  // `/metrics` and `/v1/**` are paths inside the tenant's document tree, not
  // this gateway's API. Below the routes they would shadow the tenant's files,
  // and — the part that actually matters — a hostname whose proof has EXPIRED
  // would still answer on them, so its refusal would not be about the authority
  // at all. Below the network gate, because an IP the operator refused is
  // refused on every authority.
  //
  // Inert unless `CONTROL_DB` is bound AND holds a `site_domains` row for the
  // inbound host AND that row's owner holds a live DNS ownership proof. See
  // `../sites/host.ts`.
  app.use("*", options.siteDomains ?? defaultSiteDomainRouting());

  // ONE table-driven guard for all 281 operations, ahead of every route.
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
  // — because that is where the Rust check sits relative to `finalize_auth`,
  // and because by this point the caller has already paid for the credential
  // and admission lookups, so the one durable row read below is not a new
  // amplification surface.
  // Inert unless the durable `runtime-state/drain` document says `true` or
  // `GATEWAY_DRAIN` is the exact string `"true"` — the same two sources and the
  // same parse `/readyz` uses (`./readiness.ts::resolveDrainState`), which is
  // what makes ONE `POST /admin/v1/drain` stop this Worker, `apps/mcp` and
  // `apps/agent-runtime` together. See `./drain.ts` and FLEET-CONSISTENCY FC-1.
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

  // THE INNER ENVELOPE BOUNDARY (issue #733) — the same middleware, mounted
  // again as the LAST thing before the routes.
  //
  // This one exists for the request log, not for the client: `requestLogging()`
  // writes its #664 row after `await next()`, so a throw from a route handler
  // that unwound all the way to `app.onError` produced a 500 the client saw and
  // a durable trail that recorded nothing. Converting the throw HERE means
  // every middleware above — the request log, the metering drain, the telemetry
  // emitter and the status counters — observes an ordinary `Response` and does
  // its job.
  app.use("*", envelopeBoundary);

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
  // would shadow all 281 contract operations AND `/health`. It is registered
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
