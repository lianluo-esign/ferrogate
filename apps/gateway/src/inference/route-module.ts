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
  admitTokensPerMinute,
  isTokenAdmissionRefusal,
  settleTokenUsage,
} from "../ratelimit/middleware.js";
import type { TokenAdmission } from "../ratelimit/ports.js";
import {
  GatewayRouter,
  INFERENCE_OPERATION_IDS,
  type RouteModule,
} from "../routes/index.js";
import { createInferenceRouter } from "./handlers.js";
import type { InferenceEnv } from "./handlers.js";
import {
  type TokenAdmissionHandle,
  type TokenGovernor,
  callerFromAuth,
  setInferenceRequestScope,
} from "./identity.js";
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
 * invocation answers `model_not_found`. The deployed Worker passes
 * `{ models: modelsFromEnv, dispatcher: fetchDispatcher }` (see
 * `apps/gateway/src/index.ts`); `models` is a factory precisely because the
 * inner app is built ONCE here while Worker bindings are per request.
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
        router.register(operationId, (c) => {
          publishRequestScope(c);
          return inner.fetch(c.req.raw, c.env, executionCtxOf(c));
        });
      }
    },
  };
}

/**
 * Hand the inner app everything the OUTER middleware chain resolved.
 *
 * This is the whole reason `identity.ts` exists: `inner.fetch` opens a fresh
 * Hono context, so without this line the handlers see neither `c.get("auth")`
 * nor the quota windows `rateLimit()` merged — and silently fall back to a
 * platform-operator caller with no TPM gate. Both fallbacks are green in every
 * unit test that injects its own ports, which is precisely why the wiring is
 * asserted directly (`test/inference/wiring.test.ts`).
 *
 * The scope is keyed by `c.req.raw` — the exact `Request` passed to
 * `inner.fetch` on the next line.
 */
function publishRequestScope(c: Context<GatewayEnv>): void {
  const auth = c.get("auth");
  setInferenceRequestScope(c.req.raw, {
    // `auth` is absent only for a contract-`anonymous` operation, which none of
    // the six inference operations is; leaving it undefined keeps the injected
    // `deps.caller` in charge rather than fabricating an identity.
    ...(auth === null || auth === undefined ? {} : { caller: callerFromAuth(auth) }),
    tokens: honoTokenGovernor(c),
  });
}

/**
 * The TPM window as a {@link TokenGovernor}, bound to the OUTER context.
 *
 * `admitTokensPerMinute` / `settleTokenUsage` both read the windows
 * `rateLimit()` published on `c`. When `rateLimit()` is not mounted at all they
 * find nothing and answer `null`, i.e. "no TPM limit governs this request",
 * which is the correct reading — there is no policy source to have set one.
 */
function honoTokenGovernor(c: Context<GatewayEnv>): TokenGovernor {
  return {
    async admit(estimatedTokens: number) {
      const admitted = await admitTokensPerMinute(c, estimatedTokens);
      if (admitted === null) return null;
      if (isTokenAdmissionRefusal(admitted)) {
        return { status: admitted.status, code: admitted.code, message: admitted.message };
      }
      return admitted;
    },
    async settle(handle: TokenAdmissionHandle | null, actualTokens: number) {
      await settleTokenUsage(c, handle as TokenAdmission | null, actualTokens);
    },
  };
}
