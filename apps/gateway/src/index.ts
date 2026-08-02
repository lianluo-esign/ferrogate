/**
 * `ferrogate-gateway` Worker — the native TS data plane.
 *
 * Replaces the Rust `ferrogate-gateway` + `ferrogate-runtime` + the Pingora
 * container (eliminated). A Hono streaming proxy for OpenAI-compatible
 * inference, tool/MCP execution, and agent invoke.
 *
 * Routing and auth are **contract-driven**: `src/contract.ts` is the 274
 * operations from `docs/openapi/runtime-api-contract.json`, `src/middleware/
 * auth.ts` is the single guard that enforces each operation's declared
 * `auth.kind` / `auth.scope` / `rbac_action`, and `src/routes/index.ts` mounts
 * the 40 operations this Worker owns.
 *
 * The inference (14 ops), asset (18 ops) and site (1 op) handlers arrive as
 * `RouteModule`s from their own directories and are mounted in
 * `GATEWAY_ROUTE_MODULES` below; they need no change to the router, the guard,
 * or the contract table.
 */
import { assetDepsFromEnv, assetRouteModule } from "./assets/index.js";
import { attributionTags } from "./attribution/index.js";
import { delegationChain } from "./delegation/index.js";
import { residency } from "./residency/index.js";
import { guardrailDepsFromEnv, guardrails, sweepGuardrailEvidence } from "./guardrails/index.js";
import {
  defaultAnthropicTranslator,
  dispatcherFromEnv,
  inferenceRouteModule,
  modelsFromEnv,
  sweepResponseConversations,
} from "./inference/index.js";
import {
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
  routePriceSettledCostUsd,
} from "./metering/index.js";
import { rateLimit } from "./ratelimit/index.js";
import {
  consumeRequestLogBatch,
  createRequestLogSink,
  requestLogBindingsFromEnv,
  requestLogDatabaseFrom,
  requestLogging,
  sweepRequestLogs,
} from "./requestlog/index.js";
import type { RequestLogMessageBatch } from "./requestlog/index.js";
import { type RouteModule, createGatewayApp } from "./routes/index.js";
import { siteRouteModule } from "./sites/index.js";
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
 *
 * ## `settledCostUsd` and `diagnostics` — the #663 wiring
 *
 * Both slots used to be empty here, and the two omissions compounded into a
 * SILENT loss: a served, billable request against a model absent from
 * `PriceBook.withDefaultRateCard()` (11 hard-coded entries, no `("*","*")`
 * wildcard) failed closed in `charge()`, wrote nothing anywhere, and — because
 * no `diagnostics` were supplied — logged nothing either. It was found on the
 * live account, not by a test.
 *
 * - `settledCostUsd: routePriceSettledCostUsd` carries the SERVED route's own
 *   `[[models]].input_price_per_1m` / `output_price_per_1m` into settlement, so
 *   an operator who priced a model on its registry row gets that model billed
 *   at those prices instead of refused. Those numbers were already parsed and,
 *   until now, read only by cost-based routing.
 * - `diagnostics.onPriceNotFound` makes what is left of the refusal LOUD. It is
 *   the last resort — no card rule and no row price — and it is exactly the
 *   condition an operator must act on, so it goes to the Worker log with the
 *   request id, provider and model in it.
 */
const usage = createMeteringUsageSink({
  bindings: meteringBindingsFromEnv,
  settledCostUsd: routePriceSettledCostUsd,
  diagnostics: {
    onPriceNotFound: ({ requestId, provider, providerModel, message }) => {
      // `console.warn` is the Worker's `tracing::warn!`: it reaches
      // `wrangler tail` and the Logpush sink. The usage itself is NOT lost —
      // `MeteringUsageSink` persists a cost-less `billing_events` row for it —
      // so this line names the model to price rather than announcing a
      // dropped request.
      console.warn(
        `[ferrogate] billing: no price for provider '${provider}' model '${providerModel}' ` +
          `(request ${requestId}); usage recorded with a null cost_usd. ${message}`,
      );
    },
  },
});

/**
 * The durable request-log sink (#664) — one evidence row per decision.
 *
 * Module scope, and a binding RESOLVER rather than bindings, for the same
 * reason `usage` above is: the middleware is built once and Worker bindings are
 * per request, and workerd refuses I/O started on behalf of a different
 * request, so a captured `env` is a correctness bug that only shows up under
 * concurrency. `requestLogBindingsFromEnv` reads `env.REQUEST_LOG` (the Queue
 * producer) and `env.CONTROL_DB` (the CONTROL database that owns
 * `request_logs` — NOT the tenant `DB`, whose migration has no such table) off
 * whichever request is being served.
 */
const requestLogs = createRequestLogSink(requestLogBindingsFromEnv);

/**
 * The route modules THIS Worker mounts — the single source of truth for what
 * the deployed data plane serves. `test/contract.test.ts` imports this exact
 * array (never a bespoke copy) and asserts all 33 gateway-owned operation ids
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
 *  - `dispatcher: dispatcherFromEnv` — the provider egress
 *    (`server/dispatch.rs`): `redirect: "manual"`, no transparent content
 *    re-encoding, the streaming body handed back untouched, and the inbound
 *    request's abort signal forwarded so a client disconnect stops the upstream.
 *    A FACTORY, for the same reason `models` is: it wraps that `fetch` egress
 *    with the `env.AI` short-circuit the `workers-ai` family dispatches through
 *    (issue #673), and a Worker binding only exists per request. Passing the
 *    bare `fetchDispatcher` here — which is what this line used to do — would
 *    leave the ninth family registered and unreachable, the exact defect class
 *    `packages/providers/src/registry.ts` warns about.
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
  inferenceRouteModule({ models: modelsFromEnv, dispatcher: dispatcherFromEnv, usage }),
  assetRouteModule({ depsFromEnv: assetDepsFromEnv }),
  // The static-site serve mode (issue #737), wired to the SAME `env.ASSETS`
  // bucket and the same tenant D1 bundle index the asset module is: it serves
  // published `static_site` bundles through `AssetService.pullAsset`, so a site
  // read and an asset read cannot resolve differently. With no bucket bound it
  // degrades exactly as the asset module does — `503 asset_bucket_unavailable`
  // — rather than serving nothing quietly.
  siteRouteModule({ depsFromEnv: assetDepsFromEnv }),
];

/**
 * The cross-cutting middleware the deployed data plane runs, in the Rust
 * ingress order (`docs/legacy/inventory-request-path.md` §"Cross-crate
 * architecture", steps 5/11 + `auth::finalize_auth` → `server/chat.rs`):
 *
 *   contractAuth → meteringDrain → requestTelemetry → requestLogging
 *                → rateLimit → attributionTags → residency → guardrails
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
 * so all 33 gateway operations are covered (see `CreateGatewayAppOptions`).
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
  // `src/inference/route-module.ts` ALSO emits, so the eight inference
  // operations pass through two emitters; `emitRequestTelemetry` de-duplicates
  // on the inbound `Request` object, so they still produce exactly one span
  // and one metric point. Mounting here is what widens the coverage from those
  // six to all 33 gateway operations.
  //
  // Inert until `TELEMETRY_TOKEN` is set (a secret, never a committed var):
  // `telemetryFromEnv` returns `NO_TELEMETRY` and every emit is a no-op.
  requestTelemetry(),
  // #664 — the per-decision evidence row, on `ctx.waitUntil`.
  //
  // THIRD, and specifically AHEAD of `rateLimit()` and `guardrails()`: it
  // wraps `await next()`, so everything below it is inside its window and the
  // responses those two SHORT-CIRCUIT with (429 `rate_limited`, 403
  // `guardrail_*`) are recorded. Mounting it below either would delete from the
  // trail exactly the refusals an incident review and an audit are looking for
  // — an evidence surface that only records the requests that succeeded is the
  // same lie, one layer down, as the one this issue closes.
  //
  // Behind `meteringDrain` and `requestTelemetry` because money outranks
  // evidence for outermost position and nothing is lost by sitting two layers
  // in: both return the same `Response` object they received.
  requestLogging(requestLogs),
  // `rateLimit()` with no arguments picks the DO limiter when `RATE_LIMIT` is
  // bound and the config-var quota source; both fail closed.
  rateLimit(),
  // #691 — the VERIFIABLE agent delegation chain.
  //
  // BETWEEN admission and attribution, and both edges are decisions:
  //
  //  - AFTER `rateLimit()` so a request with a forged chain still burns the
  //    caller's admission window. Ahead of it, probing chain forgeries would be
  //    free and unthrottled — the same argument `attributionTags()` makes for
  //    its own position, and the same one `nodeDrainGate` makes for its.
  //  - BEFORE `attributionTags()` because identity precedes attribution: the
  //    chain contributes the `agent_run_id` the #677 cost query groups by, and
  //    attributing spend to a chain nothing verified is precisely the
  //    approximate audit answer this issue exists to end.
  //
  // Inert until a caller PRESENTS `x-ferrogate-delegation`: one header read and
  // `next()`. A request that presents one on a Worker with no
  // `DELEGATION_SIGNING_KEY` bound is refused `503
  // delegation_verification_unavailable` rather than served with the header
  // ignored — otherwise deleting the binding would bypass the whole verifier.
  delegationChain(),
  // #678 — `403 attribution_tags_required` on the five spend-producing
  // operations, per the CALLING TENANT's policy.
  //
  // BETWEEN admission and screening, and both edges are the decision:
  //
  //  - AFTER `rateLimit()` so an untagged request still burns the caller's
  //    RPM/quota window. Ahead of it, an untagged flood would be an UNMETERED
  //    flood — the refusal would cost the caller nothing and the limiter would
  //    never see it.
  //  - BEFORE `guardrails()` for the reason the paragraph above gives about
  //    admission and screening: detector work can include PAID provider calls,
  //    and a request this gate refuses reaches no model at all. Spending
  //    screening budget on it would be the worse bug.
  //
  // The refusal is still recorded: `requestLogging()` is mounted two entries
  // above and wraps everything below it, so a 403 from here lands in the #664
  // trail exactly like `rateLimit()`'s 429 and `guardrails()`' 403.
  //
  // Inert until an operator sets `quota_policies.required_tags_json` +
  // `on_missing_tags` on a TENANT-scope row (or the
  // `GATEWAY_ATTRIBUTION_POLICIES` var): with no policy for the calling tenant
  // it is one cached lookup and `next()`.
  attributionTags(),
  // #681 — the calling TENANT's data-residency + zero-data-retention policy.
  //
  // It makes no ROUTING decision here (the candidate list does not exist yet):
  // it resolves the policy, refuses what this deployment cannot satisfy at all
  // — `503 residency_policy_unavailable` when the policy cannot be READ, `403
  // log_residency_unsatisfiable` when the durable log cannot stay in region —
  // and publishes the policy for `inference/candidates.ts` and
  // `inference/shadow.ts` to enforce per route.
  //
  // BETWEEN `attributionTags()` and `guardrails()`, and the second edge is the
  // one that is a residency argument rather than an economic one: guardrail
  // screening can call OUT (an LLM judge, a hosted detector) with the prompt
  // itself, so screening ahead of this gate would send a governed prompt to the
  // detector's region and ask about residency afterwards.
  //
  // Inert until an operator sets `quota_policies.residency_regions_json` /
  // `require_zero_data_retention` on a TENANT-scope row (or the
  // `GATEWAY_RESIDENCY_POLICIES` var): with no policy for the calling tenant it
  // is one cached lookup and `next()`.
  residency(),
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
  await gatewayRequestLogRetention(env);
  // #689 — expired `/v1/responses` conversation state, on the SAME tick.
  //
  // It is a SEPARATE call rather than a line inside `gatewayRequestLogRetention`
  // because the two read different databases: the request log lives in
  // `CONTROL_DB` and conversation state lives in the TENANT database (`DB`), so
  // a deployment can bind one without the other and the sweep for either must
  // still run.
  //
  // This call is the whole reason the storage decision went to D1 rather than a
  // Durable Object per conversation: a DO namespace cannot be enumerated, so
  // eviction there needs a per-object alarm — which is #765, where MCP sessions
  // are never evicted because nothing walks the namespace. Never throws.
  await sweepResponseConversations(env, Math.floor(Date.now() / 1000));
}

/**
 * The request-log retention sweep (#664), on the same Cron tick.
 *
 * `@ferrogate/storage`'s `retention.ts` has said for two waves that its
 * planners are ported and tested and that *nothing ever CALLED a planner*, so
 * `request_logs` grows without bound in a deployed environment — a library
 * package has no entry module and therefore no `[triggers] crons` to hang a
 * schedule on. This is that call site.
 *
 * Never throws: `sweepRequestLogs` swallows its own failures, and a retention
 * outage must not take the billing-outbox sweep down with it. With neither
 * `REQUEST_LOG_RETENTION_DAYS` nor `REQUEST_LOG_RETENTION_POLICIES` set it
 * resolves zero scopes and touches nothing, because keeping evidence is the
 * only safe default.
 */
async function gatewayRequestLogRetention(env: unknown): Promise<void> {
  const db = requestLogDatabaseFrom(env);
  if (db === undefined) return;
  const nowUnix = Math.floor(Date.now() / 1000);
  await sweepRequestLogs(db, env, nowUnix);
  // Guardrail screening evidence (#665) is swept on the SAME tick, with the
  // SAME policy, against the same database. Deliberately not a separate
  // retention window: a request log whose screening evidence has been deleted
  // (or the reverse) makes the investigation view able to half-answer, which is
  // the failure #665 exists to fix. See `guardrails/evidence-retention.ts`.
  await sweepGuardrailEvidence(db, env, nowUnix);
}

/**
 * The `[[queues.consumers]]` handler — request-log messages become D1 rows.
 *
 * Exposed here and re-exported through `src/worker.ts` for the same reason
 * `gatewayScheduled` is: workerd only dispatches a queue event to a handler
 * found on the ENTRY module's DEFAULT export, so a named export alone would be
 * silently accepted as a service entrypoint and the queue would fill and
 * dead-letter with nothing consuming it.
 */
export async function gatewayQueue(batch: RequestLogMessageBatch, env: unknown): Promise<void> {
  await consumeRequestLogBatch(batch, env);
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
