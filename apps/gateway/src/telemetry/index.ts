/**
 * `apps/gateway` telemetry egress — the data plane's OTLP producer.
 *
 * `apps/telemetry` has shipped a complete OTLP/HTTP+JSON receiver with an
 * Analytics Engine sink since wave 4, and until this directory landed the
 * gateway sent it nothing: `@ferrogate/observability` was imported by exactly
 * one gateway module, `cache/metrics.ts`, and that import is `import type`, so
 * it is ERASED at build time. The deployed Worker emitted no span and no metric
 * to anything, which is the same "implemented, tested, never mounted" shape the
 * porting rules name — with the extra twist that the CONSUMER existed too.
 *
 *  - `ports.ts` — bindings, the `RequestTelemetry` record, the emitter seam.
 *  - `emit.ts`  — `CloudflareBackend` → service binding / `fetch`, on
 *                 `ctx.waitUntil`, swallowing every failure.
 *
 * ## WHERE IT IS MOUNTED TODAY
 *
 * `src/inference/route-module.ts`, around the delegation into the inference
 * router — so all SIX inference operations of the deployed Worker emit a
 * `ferrogate.gateway.request` span and a request/status metric point.
 * `test/telemetry/mount.test.ts` drives that through `SELF.fetch` and goes RED
 * if the call is removed.
 *
 * ## ========================================================================
 * ## WIRING — what the integrate step must add (NOT this slice's to edit)
 * ## ========================================================================
 *
 * **1. `apps/gateway/wrangler.toml`** — the service binding to the collector.
 * This is the one binding kind `wrangler.toml`'s own "not yet declared" note
 * has always deferred ("`[[services]]` stays undeclared … it names another
 * deployed Worker"), and it is now read by code:
 *
 * ```toml
 * [[services]]
 * binding = "TELEMETRY_COLLECTOR"
 * service = "ferrogate-telemetry"
 * ```
 *
 * plus the credential, which is a SECRET and must NOT be written into the file:
 *
 * ```
 * bunx wrangler secret put TELEMETRY_TOKEN     # == apps/telemetry's COLLECTOR_TOKEN
 * ```
 *
 * With no service binding the HTTPS arm is used instead, and needs one var:
 *
 * ```toml
 * TELEMETRY_ENDPOINT = "https://telemetry.example.com"
 * ```
 *
 * Optional, both defaulted in code:
 * `TELEMETRY_SERVICE_NAME` (default `"ferrogate-gateway"`) and
 * `TELEMETRY_SIGNALS` (default: all of `metric,trace,log`).
 *
 * **2. `apps/gateway/src/ports.ts`** — add to `GatewayBindings`:
 *
 * ```ts
 * TELEMETRY_COLLECTOR?: { fetch(request: Request): Promise<Response> };
 * TELEMETRY_ENDPOINT?: string;
 * TELEMETRY_TOKEN?: string;
 * ```
 *
 * **3. `apps/gateway/src/index.ts` (OPTIONAL, widens coverage)** — the mount
 * above covers the seven inference operations. To cover all 32, add
 * `requestTelemetry()` to `GATEWAY_MIDDLEWARE`. It is safe to mount BOTH: the
 * emitter de-duplicates on the inbound `Request` object, so an inference
 * request that passes through the middleware AND the route module emits once.
 * Position it FIRST in the array (outermost), next to `meteringDrain`, for the
 * same reason that one is first — it does its work on the way OUT and has to
 * see the final `Response`.
 *
 * Until edit 1 lands, `telemetryFromEnv` returns `NO_TELEMETRY` and every emit
 * is a no-op: the gateway behaves exactly as it did before this directory
 * existed, which is why the fallback is explicit rather than a thrown
 * "binding missing".
 */
export {
  NO_TELEMETRY,
  emitRequestTelemetry,
  snapshotFor,
  spanFor,
  telemetryEmitterFor,
  telemetryFromEnv,
  telemetryIds,
} from "./emit.js";
export type { TelemetryIds } from "./emit.js";
export {
  DEFAULT_TELEMETRY_SERVICE_NAME,
  SERVICE_BINDING_ORIGIN,
} from "./ports.js";
export type {
  GatewayTelemetryBindings,
  RequestTelemetry,
  TelemetryEmitter,
  TelemetryService,
} from "./ports.js";
export { requestTelemetry } from "./middleware.js";
export {
  genAiInvocationFor,
  genAiOperationForRouteLabel,
  observeGenAiInvocation,
} from "./genai.js";
export type { GenAiObservation } from "./genai.js";
