/**
 * The `RouteModule` seam for the twelve inference operations.
 *
 * `createInferenceRouter` (see `./handlers.ts`) is a standalone `Hono` built
 * around ABSOLUTE contract paths and per-route middleware chains — a bounded
 * body reader that owns `payload_too_large` / `invalid_json`, then a Zod
 * `validateBody` that owns `invalid_request`. That chain is the port of the
 * Rust request pipeline and its ORDER is load-bearing, so this adapter does not
 * re-implement it and does not reach past it to the handlers: it registers the
 * eight contract operation ids on the gateway router and DELEGATES the untouched
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
 *    operations (`POST /v1/mcp`). All twelve inference operations are `bearer`, so
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
import { attributionDefaultsFor } from "../attribution/index.js";
import { publishShadowEvalLeg, shadowEvalRetentionRequested } from "../evals/shadow-leg.js";
import type { GatewayEnv } from "../ports.js";
import {
  admitTokensPerMinute,
  isTokenAdmissionRefusal,
  settleTokenUsage,
} from "../ratelimit/middleware.js";
import type { TokenAdmission } from "../ratelimit/ports.js";
import { residencyPolicyFor } from "../residency/carrier.js";
import { contributeRequestLogFacts } from "../requestlog/facts.js";
import {
  GatewayRouter,
  INFERENCE_OPERATION_IDS,
  type RouteModule,
} from "../routes/index.js";
import { emitRequestTelemetry, genAiInvocationFor } from "../telemetry/index.js";
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
        router.register(operationId, async (c) => {
          publishRequestScope(c);
          const startedAtMs = Date.now();
          // `await` costs nothing here: Hono resolves as soon as the RESPONSE
          // OBJECT exists, and a streaming branch hands back the provider's
          // `Response` with its `ReadableStream` untouched — the body is still
          // relayed lazily, so first-token latency is unchanged.
          const response = await inner.fetch(c.req.raw, c.env, executionCtxOf(c));
          emitInferenceTelemetry(c, operationId, startedAtMs, response);
          return response;
        });
      }
    },
  };
}

/**
 * THE TELEMETRY MOUNT — `@ferrogate/observability` reaching a destination.
 *
 * `apps/telemetry` has been a complete OTLP receiver since wave 4 and the
 * gateway sent it nothing: the only `@ferrogate/observability` import anywhere
 * in `apps/gateway/src` was an `import type` in `cache/metrics.ts`, which is
 * ERASED at build time, so not one byte of the package reached the deployed
 * bundle. This call is what changes that for the twelve inference operations, and
 * `test/telemetry/mount.test.ts` drives it through `SELF.fetch` so removing the
 * line turns that suite RED.
 *
 * Everything about NOT hurting the request lives behind
 * `emitRequestTelemetry`: it returns synchronously, defers the build and the
 * send to `ctx.waitUntil`, swallows every failure, and is a no-op when no
 * collector is configured (which is the committed default, so this mount
 * changes no deployed behavior until the `[[services]]` binding lands — see
 * `src/telemetry/index.ts`).
 *
 * ## The ids are the CLIENT'S ids, not the outer context's
 *
 * The inner inference router mints its own `fg-<16 hex>` request id and that is
 * what the client is told in `x-request-id` — the OUTER `c.get("requestId")` is
 * a different value (a UUID) that the caller never sees on this surface. A span
 * stamped with the outer id would be unjoinable to the id in a customer's
 * incident report, which is the single thing a request span is for. So the
 * response's own `x-request-id` wins, with the outer id as the fallback for a
 * response that carries none.
 *
 * The trace id is the reverse: a valid inbound `traceparent` was adopted by
 * `middleware/trace.ts` and only the OUTER context knows it, so when one
 * arrived it wins and the span joins the caller's existing trace. With no
 * traceparent the trace id falls back to the client-visible request id, so the
 * span still lands under an id the caller holds.
 */
function emitInferenceTelemetry(
  c: Context<GatewayEnv>,
  operationId: string,
  startedAtMs: number,
  response: Response,
): void {
  const auth = c.get("auth");
  const requestId = response.headers.get("x-request-id") ?? c.get("requestId");
  const endedAtMs = Date.now();
  // #669. Derived exactly as `src/telemetry/middleware.ts` derives it, and that
  // is a REQUIREMENT rather than a coincidence: `test/telemetry/mount.test.ts`
  // pins that the two mounts produce one de-duplicated emission, so the moment
  // they disagree about a field the surviving emission is whichever one ran
  // first — a non-deterministic payload. If this expression and the
  // middleware's ever diverge, one of them is wrong.
  const genai = genAiInvocationFor(c.req.raw, {
    durationSeconds: (endedAtMs - startedAtMs) / 1000,
    ...(response.status >= 400 ? { errorType: String(response.status) } : {}),
  });
  emitRequestTelemetry(c.env, executionCtxOf(c), c.req.raw, {
    requestId,
    traceId: c.get("traceparent") ? (c.get("traceId") ?? requestId) : requestId,
    method: c.req.method,
    path: c.get("canonicalPath") ?? new URL(c.req.url).pathname,
    route: operationId,
    statusCode: response.status,
    startedAtMs,
    endedAtMs,
    ...(genai === undefined ? {} : { genai }),
    // The AUTHENTICATED tenant, never a client-declared header. Absent for a
    // platform-operator credential, which the collector indexes under its own
    // `unknown` sentinel rather than under a fabricated tenant.
    ...(auth?.tenancy.tenantId ? { tenantId: auth.tenancy.tenantId } : {}),
  });
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
  const request = c.req.raw;
  setInferenceRequestScope(request, {
    // `auth` is absent only for a contract-`anonymous` operation, which none of
    // the twelve inference operations is; leaving it undefined keeps the injected
    // `deps.caller` in charge rather than fabricating an identity.
    // #681 — the residency policy travels ON the caller, so every gate that
    // reads a caller (route eligibility, and the shadow mirror through
    // `planUpstream`) sees it without a second lookup. `residencyPolicyFor`
    // reads the SAME `Request` object `residency()` keyed it by on the outer
    // app, and answers `null` for a tenant nothing governs.
    ...(auth === null || auth === undefined
      ? {}
      : { caller: callerFromAuth(auth, residencyPolicyFor(request)) }),
    tokens: honoTokenGovernor(c),
    // #664 — the request log's model/provider/token facts. `request` is the
    // OUTER inbound `Request`, which is both the key the fact collector uses
    // and the object `requestLogging()` reads back on the way out; the inner
    // app's own `c.req.raw` is a DIFFERENT object by the time the handlers run
    // (`readInferenceBody()` re-presents it), which is why the identity is
    // captured here rather than inside the callback.
    log: (facts) => contributeRequestLogFacts(request, facts),
    // #678 — whatever `attributionTags()` defaulted for this request, read back
    // off the SAME `Request` object it keyed them by. Empty for every request
    // the gate did not touch, which is every request under a deployment that
    // configured no policy.
    attributionDefaults: attributionDefaultsFor(request),
    // #693 — the shadow arm's eval leg, and its RETENTION GATE, in one
    // expression. `onlineEvaluation()` runs earlier in the same chain and marks
    // this `Request` only when its capture plan cleared opt-in, ZDR, criteria
    // and the sample bucket; without that mark the key is absent from the
    // scope, `handlers.ts` attaches no retainer, and the mirrored response is
    // discarded exactly as it was before #693's quality half existed.
    //
    // Spelled as a conditional SPREAD rather than an `undefined`-valued key so
    // an ungated deployment cannot satisfy an `in` check on the scope.
    ...(shadowEvalRetentionRequested(request)
      ? { scoreShadowLeg: (leg) => publishShadowEvalLeg(request, leg) }
      : {}),
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
        return {
          status: admitted.status,
          code: admitted.code,
          message: admitted.message,
          // #726 — the pacing headers travel with the refusal. This re-shaping
          // step is exactly where they were being dropped: the limiter computed
          // them, `admitTokensPerMinute` attached them, and a three-field copy
          // here silently discarded them before `errorResponse` ever saw one.
          ...(admitted.headers === undefined ? {} : { headers: admitted.headers }),
        };
      }
      return admitted;
    },
    async settle(handle: TokenAdmissionHandle | null, actualTokens: number) {
      await settleTokenUsage(c, handle as TokenAdmission | null, actualTokens);
    },
  };
}
