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
import {
  fetchDispatcher,
  inferenceRouteModule,
  modelsFromEnv,
} from "./inference/index.js";
import { type RouteModule, createGatewayApp } from "./routes/index.js";

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
  inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher }),
  assetRouteModule(),
];

const { app, router } = createGatewayApp({ modules: GATEWAY_ROUTE_MODULES });

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
