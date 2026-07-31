/**
 * `requestTelemetry()` — the app-wide Hono mount for the OTLP egress.
 *
 * The inference route module mounts the emission itself
 * (`src/inference/route-module.ts`), because that is the surface this slice
 * owns and it is the one that matters for AI observability. This middleware is
 * the SAME emission expressed as ordinary Hono middleware, so the integrate
 * step can cover the other 25 gateway operations with one line in
 * `GATEWAY_MIDDLEWARE` — see the WIRING block in `./index.ts`.
 *
 * Mounting both is safe and intended: `emitRequestTelemetry` de-duplicates on
 * the inbound `Request` object, so an inference request that passes through
 * both emits exactly once.
 *
 * Like `meteringDrain`, it does its work on the way OUT — it wraps `await
 * next()` so it can see the final `Response` — which is why it belongs at the
 * TOP of the middleware array rather than the bottom.
 */
import type { MiddlewareHandler } from "hono";
import type { GatewayEnv } from "../ports.js";
import { emitRequestTelemetry } from "./emit.js";
import type { RequestTelemetry } from "./ports.js";

/**
 * `c.executionCtx` THROWS when the context was built without one (every
 * `app.request(...)` in a unit test). Absent is passed through as `undefined`,
 * where `emitRequestTelemetry` degrades to a detached promise.
 */
function executionCtxOf(c: {
  executionCtx: { waitUntil(work: Promise<unknown>): void };
}): { waitUntil(work: Promise<unknown>): void } | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

/**
 * Emit one `ferrogate.gateway.request` span + one request/status metric point
 * per request, on `ctx.waitUntil`.
 *
 * `next()` is awaited (that is how the status is known) and NOTHING else is:
 * the emission is fired after the response object exists and is never in front
 * of it.
 */
export function requestTelemetry(): MiddlewareHandler<GatewayEnv> {
  return async (c, next) => {
    const startedAtMs = Date.now();
    await next();

    const auth = c.get("auth");
    const telemetry: RequestTelemetry = {
      // The id the CLIENT was told, read off the response the client got —
      // not `c.get("requestId")`. The two are usually the same string, but the
      // inference route module mints its own `fg-…` id and puts THAT on
      // `x-request-id`, so an emitter that published the context variable would
      // attach a span to an id no client ever saw, and a client-side incident
      // report could never be joined to it. Found by removing the route
      // module's own emission and watching this middleware answer in its place
      // with the wrong id.
      requestId: c.res.headers.get("x-request-id") ?? c.get("requestId"),
      // `traceId` is the ADOPTED W3C trace id when the caller sent a valid
      // `traceparent`, so a gateway span joins the caller's existing trace
      // rather than starting an orphan one.
      traceId: c.get("traceId") ?? c.get("requestId"),
      method: c.req.method,
      // The CANONICAL path (`/control/v1/*` folded onto `/admin/v1/*`), not the
      // raw one: two spellings of one operation must not become two series.
      path: c.get("canonicalPath") ?? new URL(c.req.url).pathname,
      route: c.get("operation")?.operationId ?? "unmatched",
      statusCode: c.res.status,
      startedAtMs,
      endedAtMs: Date.now(),
      // `auth.tenancy.tenantId` is the AUTHENTICATED tenant — never a
      // client-declared header. A platform-operator credential carries none,
      // and the collector indexes those under its own `unknown` sentinel
      // rather than being handed a fabricated one.
      ...(auth?.tenancy.tenantId ? { tenantId: auth.tenancy.tenantId } : {}),
    };
    emitRequestTelemetry(c.env, executionCtxOf(c), c.req.raw, telemetry);
  };
}
