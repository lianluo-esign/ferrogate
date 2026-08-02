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
 * ## Provability of the two mounts — verified, not assumed
 *
 * THIS mount is independently provable and is proved twice: make
 * `requestTelemetry()` a pass-through and
 * `test/telemetry/middleware-mount.test.ts` (an asset push) plus the "MOUNT:
 * emits for a NON-inference operation" case in `test/telemetry/mount.test.ts`
 * (a tooling operation) both time out at zero. Both drive operations the
 * inference route module does not mount, which is what makes them gates rather
 * than coincidences.
 *
 * The ROUTE-MODULE emission is NOT individually provable any more, and that is
 * stated here rather than left to be rediscovered. It once was: this middleware
 * published `c.get("requestId")` while the route module published the `fg-…` id
 * it mints, so removing the route module's call changed the id on the wire.
 * That was a BUG in this middleware (a span attached to an id no client ever
 * saw) and it was fixed by reading `x-request-id` off the response the client
 * got — after which the two emissions are byte-identical for an inference
 * request and either one alone satisfies every assertion.
 *
 * So the route-module emission is now REDUNDANT: this middleware covers all 31
 * gateway operations including the 6 inference ones, with the same payload and
 * the same id. It is kept only because `src/inference/` is a different owner and
 * deleting a caller across an ownership boundary is not this slice's call. If
 * that slice wants it gone, nothing here changes; if it wants it KEPT, it needs
 * a gate this middleware cannot answer for — e.g. asserting an attribute only
 * the route module can know — because "remove it and a test goes red" is not
 * currently true and must not be claimed.
 *
 * THE REDUNDANCY ITSELF IS NOW PINNED, so it is not a claim either. The
 * "REDUNDANCY: two mounts on one inference request emit EXACTLY one batch pair"
 * case in `test/telemetry/mount.test.ts` drives `/v1/chat/completions` (both
 * emitters), waits past the settle window and requires the collector to have
 * received exactly two batches carrying exactly one span, whose `request_id` is
 * the `x-request-id` the client was served. That is the assertion the earlier
 * `waitForCollected(2)` cases could not make — a `>=` check is satisfied by a
 * doubled emission. It goes red if `emitRequestTelemetry`'s `EMITTED` guard is
 * removed (observed: 5 batches, 6 telemetry cases fail) and it goes red if the
 * two emissions ever disagree about the request id, since a different id is a
 * different de-dup key and a second pair lands. In other words: the day the
 * route-module emission becomes individually OBSERVABLE again, a test says so.
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
