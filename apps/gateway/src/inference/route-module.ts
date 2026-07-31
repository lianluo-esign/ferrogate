/**
 * The `RouteModule` seam for the six inference operations.
 *
 * `createInferenceRouter` (see `./handlers.ts`) is a standalone `Hono` built
 * around ABSOLUTE contract paths and per-route middleware chains — a bounded
 * body reader that owns `payload_too_large` / `invalid_json`, then a Zod
 * `validateBody` that owns `invalid_request`. That chain is the port of the
 * Rust request pipeline and its ORDER is load-bearing, so this adapter does not
 * re-implement it and does not reach past it to the handlers: it registers the
 * six contract operation ids on the gateway router and DELEGATES the untouched
 * `Request` into the inner app.
 *
 * Why delegation is safe here, given `contractAuth` is an `app.use("*")` guard
 * on the OUTER app:
 *
 *  - The inner app is a bare `Hono` whose only global middleware is the
 *    request-identity setter. It carries no auth, so nothing is authenticated
 *    twice and the 401/403 taxonomy stays owned by the single table-driven
 *    guard (ROUTE-MAP invariant 1).
 *  - `contractAuth` reads the request BODY only for `method_dependent`
 *    operations (`POST /v1/mcp`). All six inference operations are `bearer`, so
 *    the body arrives at the inner reader unread and the cap is still enforced
 *    before any bytes are materialized.
 *  - The inner app answers with the provider's `Response` object itself on the
 *    streaming branches, so the `ReadableStream` is handed straight back to the
 *    client — delegation adds no buffering and no first-token latency.
 *
 * The inner app is built ONCE, at module construction, not per request: the
 * model resolver, adapter registry and usage sink are long-lived and a
 * per-request rebuild would throw away the isolate's warm state.
 */
import type { Context, Hono } from "hono";
import type { GatewayEnv } from "../ports.js";
import {
  GatewayRouter,
  INFERENCE_OPERATION_IDS,
  type RouteModule,
} from "../routes/index.js";
import { createInferenceRouter } from "./handlers.js";
import type { InferenceEnv } from "./handlers.js";
import type { InferenceDeps } from "./ports.js";

/**
 * `c.executionCtx` THROWS when the context was not created with one — which is
 * exactly what happens under `app.request(...)` in a test. The inner app only
 * uses it for `waitUntil`, so an absent one is passed through as `undefined`
 * rather than allowed to fail the request.
 */
function executionCtxOf(c: Context<GatewayEnv>): Context<GatewayEnv>["executionCtx"] | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

/**
 * Fail loudly at construction if the contract has moved an inference operation
 * to a path the inner router does not serve.
 *
 * Delegation routes by URL, so a contract path and an inner absolute path that
 * disagree would surface as a silent 404 from the inner app on a route the
 * outer router happily reports as "registered" — the precise class of drift
 * this module exists to make impossible.
 */
function assertInnerRouteExists(inner: Hono<InferenceEnv>, operationId: string): void {
  const operation = GatewayRouter.operationOrThrow(operationId);
  const served = inner.routes.some(
    (route) => route.method === operation.method && route.path === operation.honoPath,
  );
  if (!served) {
    throw new Error(
      `inference router does not serve ${operation.method} ${operation.honoPath} ` +
        `for operation_id ${operationId}`,
    );
  }
}

/**
 * The `RouteModule` `createGatewayApp({ modules })` mounts.
 *
 * With no arguments every port falls back to the in-memory default in
 * `defaults.ts` — enough to boot, but it resolves no models, so every
 * invocation answers `model_not_found` until real routing is wired in.
 */
export function inferenceRouteModule(deps: InferenceDeps = {}): RouteModule {
  const inner = createInferenceRouter(deps);
  for (const operationId of INFERENCE_OPERATION_IDS) {
    assertInnerRouteExists(inner, operationId);
  }

  return {
    operationIds: [...INFERENCE_OPERATION_IDS],
    register(router: GatewayRouter): void {
      for (const operationId of INFERENCE_OPERATION_IDS) {
        router.register(operationId, (c) =>
          inner.fetch(c.req.raw, c.env, executionCtxOf(c)),
        );
      }
    },
  };
}
