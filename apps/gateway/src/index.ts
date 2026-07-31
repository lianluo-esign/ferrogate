/**
 * `ferrogate-gateway` Worker — the native TS data plane.
 *
 * Replaces the Rust `ferrogate-gateway` + `ferrogate-runtime` + the Pingora
 * container (eliminated). A Hono streaming proxy for OpenAI-compatible
 * inference, tool/MCP execution, and agent invoke.
 *
 * Routing and auth are **contract-driven**: `src/contract.ts` is the 251
 * operations from `docs/openapi/runtime-api-contract.json`, `src/middleware/
 * auth.ts` is the single guard that enforces each operation's declared
 * `auth.kind` / `auth.scope` / `rbac_action`, and `src/routes/index.ts` mounts
 * the 31 operations this Worker owns.
 *
 * The inference (6 ops) and asset (18 ops) handlers arrive as `RouteModule`s
 * from their own directories and are mounted in `GATEWAY_ROUTE_MODULES` below;
 * they need no change to the router, the guard, or the contract table.
 */
import { PUBLIC_API_MAJOR } from "@ferrogate/core";
import { assetRouteModule } from "./assets/index.js";
import { guardrailDepsFromEnv, guardrails } from "./guardrails/index.js";
import {
  defaultAnthropicTranslator,
  fetchDispatcher,
  inferenceRouteModule,
  modelsFromEnv,
} from "./inference/index.js";
import { createMeteringUsageSink } from "./metering/index.js";
import { rateLimit } from "./ratelimit/index.js";
import { type RouteModule, createGatewayApp } from "./routes/index.js";

/**
 * The durable metering sink behind `UsageSink` (wave 5).
 *
 * Until now the inference module took its `InMemoryUsageSink` default, i.e.
 * captured usage went nowhere. `MeteringUsageSink` prices the usage through
 * `@ferrogate/billing`, writes an idempotent ledger entry keyed on the
 * `ledger_entry_id`, and commits a durable outbox record in the same batch.
 *
 * It is built ONCE, at module scope, because `UsageSink` is a construction-time
 * dependency of the route module while Worker bindings are per request — so it
 * takes the in-memory ledger/outbox and the isolate-lifetime scheduler.
 *
 * PORT-TODO(inventory-data-billing §2.5): backing it with `D1LedgerStore(env.DB)`
 * + `QueueBillingReportPublisher(env.BILLING)` and `executionContextScheduler(ctx)`
 * needs `UsageSink.record` widened to carry the `ExecutionContext`
 * (`src/metering/index.ts` states the one-line signature change). Binding a
 * module-scoped "current ctx" is NOT a substitute — workerd refuses I/O started
 * on behalf of a different request. Until then no `[[queues]]` binding is
 * declared, because declaring one nothing reads is the drift `wrangler.toml`
 * forbids.
 */
const usage = createMeteringUsageSink();

/**
 * The route modules THIS Worker mounts — the single source of truth for what
 * the deployed data plane serves. `test/contract.test.ts` imports this exact
 * array (never a bespoke copy) and asserts all 31 gateway-owned operation ids
 * are registered, so a module dropped from this list fails the suite.
 *
 * The inference module is wired to the REAL data plane here:
 *
 *  - `models: modelsFromEnv` — the config-driven registry built from the
 *    `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` vars (`src/inference/catalog.ts`),
 *    which is the port of the Rust `[[providers]]` + `[[models]]` tables. It is
 *    passed as a FACTORY, not a value, because a Worker's bindings only exist
 *    per request while this array is built at module scope; the router calls it
 *    once per `env` and memoizes. With neither var set the registry is empty and
 *    every model answers `400 model_not_found`, which is the old behavior.
 *  - `dispatcher: fetchDispatcher` — the provider egress
 *    (`server/dispatch.rs`): `redirect: "manual"`, no transparent content
 *    re-encoding, the streaming body handed back untouched, and the inbound
 *    request's abort signal forwarded so a client disconnect stops the upstream.
 *
 * The asset ports still take their offline in-memory defaults: they presign
 * nothing until a bucket binding exists. Neither default is a stub route —
 * every one of the 24 operations is matched, authenticated and scope-checked.
 */
export const GATEWAY_ROUTE_MODULES: readonly RouteModule[] = [
  inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher, usage }),
  assetRouteModule(),
];

/**
 * The cross-cutting middleware the deployed data plane runs, in the Rust
 * ingress order (`docs/legacy/inventory-request-path.md` §"Cross-crate
 * architecture", steps 5/11 + `auth::finalize_auth` → `server/chat.rs`):
 *
 *   contractAuth  →  rateLimit  →  guardrails  →  validate  →  dispatch
 *
 * Admission comes FIRST because the Rust charges the RPM/quota windows inside
 * `finalize_auth`, before the body is ever examined; screening comes second
 * because `server/chat.rs` evaluates guardrail policies after the credential
 * and its budget are settled. Reversing the two would spend detector work —
 * including paid provider calls — on requests that were never admitted.
 *
 * `createGatewayApp` mounts these after the auth guard and before every route,
 * so all 31 gateway operations are covered (see `CreateGatewayAppOptions`).
 */
export const GATEWAY_MIDDLEWARE = [
  // `rateLimit()` with no arguments picks the DO limiter when `RATE_LIMIT` is
  // bound and the config-var quota source; both fail closed.
  rateLimit(),
  // Provider-scoped policies need the model→provider join, and `/v1/messages`
  // must be screened over the same document `inference/handlers.ts` dispatches.
  guardrails((env) => ({
    ...guardrailDepsFromEnv(env),
    providerForModel: (model, e) => modelsFromEnv(e as never).resolve(model)?.provider,
    translateAnthropicRequest: (body) => {
      const translated = defaultAnthropicTranslator.toChatCompletions(body);
      return translated.ok ? translated.body : undefined;
    },
  })),
] as const;

const { app, router } = createGatewayApp({
  modules: GATEWAY_ROUTE_MODULES,
  middleware: GATEWAY_MIDDLEWARE,
});

/** The registry of what the deployed Worker actually mounted (anti-drift test). */
export const gatewayRouter = router;

app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

export default app;

export { createGatewayApp, GatewayRouter } from "./routes/index.js";
export type { RouteModule, OperationHandler, GatewayApp } from "./routes/index.js";
export type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AuthContext,
  GatewayDeps,
  GatewayEnv,
  InternalTransportPort,
  RbacAuthorizerPort,
  TenancyLifecycleGatePort,
} from "./ports.js";
export * from "./contract.js";
