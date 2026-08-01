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
import { assetDepsFromEnv, assetRouteModule } from "./assets/index.js";
import { guardrailDepsFromEnv, guardrails } from "./guardrails/index.js";
import {
  defaultAnthropicTranslator,
  fetchDispatcher,
  inferenceRouteModule,
  modelsFromEnv,
} from "./inference/index.js";
import {
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
} from "./metering/index.js";
import { rateLimit } from "./ratelimit/index.js";
import { type RouteModule, createGatewayApp } from "./routes/index.js";
import { requestTelemetry } from "./telemetry/index.js";
import { tenantDatabase } from "./tenancy/index.js";

/**
 * The durable metering sink behind `UsageSink`.
 *
 * `MeteringUsageSink` prices captured usage through `@ferrogate/billing`,
 * writes an idempotent ledger entry keyed on the `ledger_entry_id`, and commits
 * the billing-report outbox row in the SAME D1 `batch()` as the metering row
 * (issue #150), then publishes onto Cloudflare Queues.
 *
 * It is built ONCE, at module scope, because `UsageSink` is a construction-time
 * dependency of the route module while Worker bindings are per request. That is
 * why it takes a `bindings` RESOLVER rather than bindings: `meteringBindingsFromEnv`
 * reads `env.BILLING_DB` (the CONTROL D1 holding `billing_events` /
 * `billing_ledger` / `billing_report_outbox` — NOT the tenant `DB`, whose
 * migration excludes those tables) and `env.BILLING` (the Queue producer) from
 * whichever request is being served, and memoizes the wrappers on the env
 * object itself. Nothing is ambient, so nothing can leak between concurrent
 * requests.
 *
 * With a resolver configured the sink does not drain itself — see
 * `GATEWAY_MIDDLEWARE` below.
 */
const usage = createMeteringUsageSink({ bindings: meteringBindingsFromEnv });

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
 * The asset module is wired to the REAL object storage the same way, and for
 * the same reason a factory is used: `env.ASSETS` is a per-request binding
 * while this array is module scope.
 *
 *  - `depsFromEnv: assetDepsFromEnv` — `env.ASSETS` (the `[[r2_buckets]]`
 *    binding) becomes the object store, and the five `ASSET_S3_*` values, when
 *    bound, become a real `SigV4Presigner` and switch `presignEnabled` on. The
 *    built `AssetService` is memoized on the `env` object, so it is constructed
 *    once per isolate and never shared across two requests' bindings.
 *
 * With no bucket bound the module falls back to the offline in-memory store and
 * the presign family answers `503 asset_bucket_unavailable` — the Rust
 * unconfigured posture, which never routes object bytes through the Worker.
 * Neither default is a stub route: every one of the 24 operations is matched,
 * authenticated and scope-checked.
 */
export const GATEWAY_ROUTE_MODULES: readonly RouteModule[] = [
  inferenceRouteModule({ models: modelsFromEnv, dispatcher: fetchDispatcher, usage }),
  assetRouteModule({ depsFromEnv: assetDepsFromEnv }),
];

/**
 * The cross-cutting middleware the deployed data plane runs, in the Rust
 * ingress order (`docs/legacy/inventory-request-path.md` §"Cross-crate
 * architecture", steps 5/11 + `auth::finalize_auth` → `server/chat.rs`):
 *
 *   contractAuth → meteringDrain → requestTelemetry → rateLimit → guardrails
 *                → tenantDatabase → responseCache → validate → dispatch
 *
 * (`responseCache` is mounted by `createGatewayApp` itself, immediately after
 * this array and immediately before the routes — see `CreateGatewayAppOptions`.)
 *
 * `meteringDrain` is FIRST because it is the only one that does its work on the
 * way OUT: it wraps `await next()`, so being outermost is what lets it see the
 * final `Response`. It is where the request's `env` and `ExecutionContext` are
 * both in scope, which is the whole reason durable metering can exist at all on
 * a module-scoped sink — and for an SSE response it defers the drain until the
 * body has finished OR the client has hung up, because the usage frame arrives
 * near the end of the stream and a disconnect must still bill what was
 * consumed. Being ahead of `rateLimit` costs nothing: a request refused with
 * 429 records no usage, so its drain finds an empty outbox and returns.
 *
 * Admission comes FIRST because the Rust charges the RPM/quota windows inside
 * `finalize_auth`, before the body is ever examined; screening comes second
 * because `server/chat.rs` evaluates guardrail policies after the credential
 * and its budget are settled. Reversing the two would spend detector work —
 * including paid provider calls — on requests that were never admitted.
 *
 * `createGatewayApp` mounts these after the auth guard and before every route,
 * so all 31 gateway operations are covered (see `CreateGatewayAppOptions`).
 *
 * ## The two PRE-AUTH ingress steps are NOT in this array — by construction
 *
 * Rust steps 3 and 5 run BEFORE `authenticate()`, so appending them here (this
 * array is mounted AFTER `contractAuth`) would have been the wrong shape even
 * though it would have passed a functional test. Both are now mounted by
 * `createGatewayApp` itself, ahead of the auth guard:
 *
 *  - **step 5 — the network gate** (`AppState::check_network_access`,
 *    `state.rs:5011`, issue #166) → `middleware/network.ts`. The CIDR IP
 *    allowlist and the unauthenticated per-source-IP flood limit, answering
 *    `403 ip_denied` / `429 unauthenticated_rate_limited`, reading the
 *    `[network_access]` primitives `packages/config` has carried since wave 2
 *    (`IpCidr`, `resolveClientIp`, `UnauthenticatedIpRateLimiter`) — which
 *    until now NOTHING read, so an operator who set `ip_allowlist` got a green
 *    `ferrogate check` and a gateway open to the world. Position is the point:
 *    the Rust reason for the gate is that a flood or credential-stuffing scan
 *    must never pay the virtual-key/storage lookup cost, and
 *    `test/routes/network.test.ts` asserts an anonymous request from a denied
 *    IP answers 403 `ip_denied` rather than 401 `missing_api_key`.
 *  - **step 3 — W3C trace-context ingress** (`server/mod.rs:156
 *    `ingress_trace_context`) → `middleware/trace.ts`, folded into the
 *    `requestId` middleware because they answer one question between them.
 *    A valid inbound `traceparent` donates its trace id to `x-trace-id` and to
 *    every error envelope; `tracestate` rides along; anything malformed falls
 *    back to the request id. The remaining half — INJECTING the pair toward an
 *    upstream (`proxy.rs::apply_upstream_request_filter`) — belongs to the
 *    operator reverse-proxy fall-through, which has its own marker in
 *    `routes/index.ts`; the adopted values are parked on the request context
 *    (`traceparent` / `tracestate` vars) for it.
 *
 * ## PORT-TODO(P: inventory-request-path §"Cross-crate architecture", steps 2/8)
 *
 * **`ClientActionTimeModule` and `run_pre_request_hooks`**
 * (`handlers.rs:29-41`, `handlers.rs:124`): signed action-time tokens on CLI
 * requests, rejected with the module's own status/code before anything else
 * runs. Not a platform limit — ordinary Hono middleware — but a CROSS-APP
 * boundary: the signing half lives in `apps/cli` and the token format
 * (`ferrogate-core`'s action-time claim set) has no TS port yet, so a verifier
 * here would have nothing to verify against and no way to be tested end to
 * end. Opt-in posture in Rust, so the shipped behaviour matches an
 * unconfigured Rust gateway: a CLI that signs an action-time token today has it
 * ignored rather than verified. It belongs AHEAD of `contractAuth` when it
 * lands, next to the network gate. See
 * `docs/rewrite/parity-audit-request-path.md` F1/F2/F12.
 */
export const GATEWAY_MIDDLEWARE = [
  // Durable metering, on `ctx.waitUntil`, after the response is flushed.
  meteringDrain(usage),
  // OTLP egress to `apps/telemetry`, on `ctx.waitUntil` — the analogue of
  // Pingora's `logging` hook: it wraps `await next()` and does its work on the
  // way OUT, with the final `Response` in hand.
  //
  // SECOND, not first. Being outermost would have been the natural reading of
  // "last hook to run", but `meteringDrain` owns index 0 and
  // `test/metering/wiring.test.ts` pins it there — money is the reason, and it
  // outranks observability: the drain has to wrap every middleware that can
  // short-circuit (`rateLimit`'s 429, `guardrails`' 403) or the usage captured
  // for such a request would never be billed. Nothing is lost by sitting one
  // layer in: `meteringDrain` returns the same `Response` object it received,
  // so the status this emitter records is the client's.
  //
  // `src/inference/route-module.ts` ALSO emits, so the six inference
  // operations pass through two emitters; `emitRequestTelemetry` de-duplicates
  // on the inbound `Request` object, so they still produce exactly one span
  // and one metric point. Mounting here is what widens the coverage from those
  // six to all 31 gateway operations.
  //
  // Inert until `TELEMETRY_TOKEN` is set (a secret, never a committed var):
  // `telemetryFromEnv` returns `NO_TELEMETRY` and every emit is a no-op.
  requestTelemetry(),
  // `rateLimit()` with no arguments picks the DO limiter when `RATE_LIMIT` is
  // bound and the config-var quota source; both fail closed.
  rateLimit(),
  // Provider-scoped policies need the model→provider join, and `/v1/messages`
  // must be screened over the same document `inference/handlers.ts` dispatches.
  // `guardrailDepsFromEnv` is ASYNC whenever `CONTROL_DB` is bound: the durable
  // `guardrail_policy_revisions` / `guardrail_policy_bindings` rows have to be
  // read before the engine can be compiled, and D1 has no synchronous read.
  // `guardrails()` awaits and memoizes the resolution once per `env`, so the
  // load happens once per isolate, not once per request.
  guardrails(async (env) => ({
    ...(await guardrailDepsFromEnv(env)),
    providerForModel: (model, e) => modelsFromEnv(e as never).resolve(model)?.provider,
    translateAnthropicRequest: (body) => {
      const translated = defaultAnthropicTranslator.toChatCompletions(body);
      return translated.ok ? translated.body : undefined;
    },
  })),
  // Per-tenant D1 — ONE DATABASE PER TENANT (`src/tenancy/`, which is the only
  // importer of `@ferrogate/storage`'s `EnvBindingTenantDatabaseRouter` /
  // `ControlDatabaseTenantRegistry`). It is LAST in this array because it is
  // the only entry that routes on the tenant the credential resolved to and
  // nothing ahead of it reads a tenant handle: the admission counters and the
  // guardrail policies are CONTROL-plane state (`CONTROL_DB` / `BILLING_DB`),
  // which per-tenant routing deliberately does not move — see `tenancy/ports.ts`
  // on the CONTROL/TENANT split.
  //
  // Inert while `GATEWAY_TENANT_DB_ROUTING` is `"off"` (the committed default),
  // and it NEVER falls back to the shared `DB`: an unprovisioned or unbound
  // tenant is refused `503 tenant_database_unavailable` rather than silently
  // served another tenant's rows.
  tenantDatabase(),
] as const;

const { app, router } = createGatewayApp({
  modules: GATEWAY_ROUTE_MODULES,
  middleware: GATEWAY_MIDDLEWARE,
});

/** The registry of what the deployed Worker actually mounted (anti-drift test). */
export const gatewayRouter = router;

/**
 * `/version` used to be registered HERE, and it was DEAD (GW-C11).
 *
 * `createGatewayApp` ends with `app.all("*", … reverseProxyFallThrough())`,
 * which TERMINATES the chain, and Hono runs matched handlers in registration
 * order — so a route attached to the returned `app` could never run. Measured
 * through `SELF`, the deployed gateway answered
 * `404 {"code":"not_found","message":"no route for GET /version"}` while the
 * other four Workers all served it. Wave 15 read the mutation's GREEN as
 * "unproven" when the truth was "unreachable".
 *
 * The route now lives inside `createGatewayApp`, immediately beside `/health`
 * and immediately ABOVE the fall-through. Nothing else may be registered on
 * `app` below this comment.
 */
export default app;

/**
 * The `[triggers] crons` handler — recovery for charges the request path could
 * not finish reporting.
 *
 * A Worker has no background thread, so the Rust `sweep_billing_outbox_once`
 * loop has no direct equivalent: the request-time drain (`meteringDrain`) is the
 * primary path, and it retries from the in-isolate outbox. What that CANNOT
 * cover is an isolate that is evicted between the D1 ledger commit and the Queue
 * publish — the charge is on the tenant's ledger, nothing downstream was told,
 * and the only surviving record is the `billing_report_outbox` row written in
 * the same batch (#150). A Cron trigger is the platform's answer: it is the one
 * thing that runs with the bindings in hand and no request to serve.
 *
 * `MeteringUsageSink.sweep` skips rows younger than `OUTBOX_SWEEP_GRACE_SECONDS`
 * — those are still owned by their own request's `waitUntil` — and never
 * rejects, so a metering outage cannot fail the scheduled event either.
 */
export async function gatewayScheduled(
  _controller: unknown,
  env: unknown,
  ctx: { waitUntil(work: Promise<unknown>): void },
): Promise<void> {
  await usage.sweep({ env, ctx });
}

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
