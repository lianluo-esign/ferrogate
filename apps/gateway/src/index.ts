/**
 * `ferrogate-gateway` Worker — the native TS data plane.
 *
 * Replaces the Rust `ferrogate-gateway` + `ferrogate-runtime` + the Pingora
 * container (eliminated). A Hono streaming proxy for OpenAI-compatible
 * inference, tool/MCP execution, and agent invoke.
 *
 * Routing and auth are **contract-driven**: `src/contract.ts` is the 281
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
import {
  assetDepsFromEnv,
  assetRouteModule,
  sweepAssetRetentionForTenants,
} from "./assets/index.js";
import { attributionTags } from "./attribution/index.js";
import { controlDatabaseFrom, platformDatabaseFrom } from "./control-data.js";
import {
  batchJobFromWire,
  batchRouteModule,
  consumeBatchJobBatch,
  sweepBatchExecution,
} from "./batch/index.js";
import type { BatchJobMessageBatch } from "./batch/index.js";
import { delegationChain } from "./delegation/index.js";
import {
  consumeOnlineEvalBatch,
  createOnlineEvalSink,
  onlineEvalSampleFromWire,
  onlineEvaluation,
  sweepAllOnlineEvalRegressions,
} from "./evals/index.js";
import type { OnlineEvalMessageBatch } from "./evals/index.js";
import { guardrailDepsFromEnv, guardrails, sweepGuardrailEvidence } from "./guardrails/index.js";
import {
  defaultAnthropicTranslator,
  dispatcherFromEnv,
  inferenceRouteModule,
  modelsFromEnv,
  platformModelCatalogFromSharedConfig,
  responseStateCommit,
  sweepResponseConversations,
  tenantModelCatalogFromD1,
} from "./inference/index.js";
import {
  GATEWAY_PLATFORM_BILLING_DRAIN,
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
  platformBillingFlagEnabled,
  routePriceSettledCostUsd,
  sweepPlatformBillingBackfill,
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
import { residency } from "./residency/index.js";
import { type RouteModule, createGatewayApp } from "./routes/index.js";
import { siteRouteModule } from "./sites/index.js";
import { requestTelemetry } from "./telemetry/index.js";
import { type TenancyBindings, resolverForEnv, tenantDatabase } from "./tenancy/index.js";

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
 * resolves tenant-scoped billing events, ledger, wallet settlement, and outbox
 * rows through `TENANT_DATA`; it uses `env.BILLING_DB` as the legacy control
 * compatibility/projection surface and `env.BILLING` as the Queue producer.
 * Resolution happens from whichever request is being served, and wrappers are
 * memoized on the env object itself. Nothing is ambient, so nothing can leak
 * between concurrent requests.
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
 * - `settlementMode: "serving_offering"` prevents the inference sink from
 *   using the legacy wildcard rate card as a second source of truth.
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
  settlementMode: "serving_offering",
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
 * producer), `env.TENANT_DATA` (the authoritative tenant object), and
 * `env.CONTROL_DB` (the derived fleet compatibility projection) off whichever
 * request is being served. Unattributed platform rows remain control-only.
 */
const requestLogs = createRequestLogSink(requestLogBindingsFromEnv);

/**
 * The online-evaluation sample producer (#692) — the fraction of production
 * traffic a tenant asked to have scored.
 *
 * Module scope for the same reason `usage` and `requestLogs` are: the
 * middleware is built once and Worker bindings are per request, so the sink
 * resolves `env.ONLINE_EVAL` (the Queue producer) off whichever request is
 * being served rather than capturing one.
 *
 * INERT until two things are true together: a tenant has opted in on its
 * `quota_policies` row (or `GATEWAY_ONLINE_EVAL_POLICIES`), AND the queue is
 * bound. With no opt-in it is one map lookup per request; with an opt-in and no
 * queue the samples are counted as dropped rather than judged inline, because
 * running a judge inference inside the request's own `waitUntil` would keep the
 * isolate — and its CPU budget — alive for the length of a model call on every
 * sampled request.
 */
const onlineEvals = createOnlineEvalSink();

/**
 * The route modules THIS Worker mounts — the single source of truth for what
 * the deployed data plane serves. `test/contract.test.ts` imports this exact
 * array (never a bespoke copy) and asserts all 33 gateway-owned operation ids
 * are registered, so a module dropped from this list fails the suite.
 *
 * The inference module is wired to the REAL data plane here:
 *
 *  - `tenantCatalog: tenantModelCatalogFromD1()` — authenticated tenant
 *    requests read one joined catalog graph from that tenant's D1/DO database,
 *    keyed by `catalog_revisions.revision` and cached per tenant in the Worker
 *    isolate. `models: modelsFromEnv` remains the explicit fallback for
 *    platform-operator requests, `GATEWAY_TENANT_DB_ROUTING = "off"`, and an
 *    empty tenant catalog; a D1 read failure is a 503 and never widens scope.
 *    `platform-default` rows use env provider metadata only because the seed
 *    rate card intentionally carries no provider credential or endpoint.
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
  inferenceRouteModule({
    models: modelsFromEnv,
    tenantCatalog: tenantModelCatalogFromD1(),
    platformCatalog: platformModelCatalogFromSharedConfig(),
    dispatcher: dispatcherFromEnv,
    usage,
    // Raise the inference body cap from the 1 MiB Rust-parity default
    // (`DEFAULT_INFERENCE_LIMITS`) to 64 MiB so large multimodal / long-context
    // requests (base64 images, big documents in `/v1/responses` etc.) are not
    // rejected with `413 payload_too_large` at 1 MiB. This is a PERMITTED
    // ceiling, not a guaranteed-safe one: `readInferenceBody` fully buffers the
    // body via `arrayBuffer()` and then decodes + `JSON.parse`s it, so peak
    // memory is ~3-4x the body size against a 128 MB Workers isolate. Bodies
    // that actually approach this cap can OOM the isolate rather than answer a
    // clean 413; typical requests sit far below it. Override lives here (not in
    // the shared default) so the Rust-parity constant and its tests stay intact.
    limits: { inferenceBodyMaxBytes: 64 * 1024 * 1024 },
  }),
  assetRouteModule({ depsFromEnv: assetDepsFromEnv }),
  batchRouteModule(),
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
 *                → residency → tenantDatabase → rateLimit → attributionTags
 *                → onlineEvaluation → responseStateCommit → guardrails
 *                → responseCache → validate → dispatch
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
  // Per-tenant storage — ONE SQLite-backed DURABLE OBJECT PER TENANT
  // (`src/tenancy/`, the only importer of `@ferrogate/storage`'s
  // `DurableObjectTenantDatabaseRouter` / `EnvBindingTenantDatabaseRouter` /
  // `ControlDatabaseTenantRegistry`).
  //
  // IMMEDIATELY ABOVE `rateLimit()`, AND THE ORDER IS LOAD-BEARING. It used to
  // be LAST in this array, on the argument that nothing ahead of it read a
  // tenant handle. #819 falsified that argument by giving `tenantDatabaseOf(c)`
  // its first production call site: the wallet no-oversell guard, which is
  // admission step 3b INSIDE `rateLimit()`. Mounted below it, `c.get(
  // "tenantDatabase")` is `undefined` when that guard runs and every wallet
  // reserve becomes a 500 naming this middleware — loudly, by design, but the
  // fix is the position, not the throw.
  //
  // Everything else in this array stays where it was: the admission counters
  // and the guardrail policies are CONTROL-plane state (`CONTROL_DB` /
  // `BILLING_DB`), which per-tenant routing deliberately does not move — see
  // `tenancy/ports.ts` on the CONTROL/TENANT split.
  //
  // Resolution is LAZY and does NO I/O: the address is selected by the
  // preceding `residency()` middleware and `TENANT_DATA.idFromName(tenantId)`
  // remains a pure function of the authenticated tenant. It NEVER falls back
  // to the shared `DB`: an unresolvable tenant is refused
  // `503 tenant_database_unavailable` rather than silently served another
  // tenant's rows.
  // #827: residency resolves the hard object jurisdiction before the first
  // tenant-data resolution below. The router itself remains free of control
  // database I/O.
  residency(),
  tenantDatabase(),
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
  // #692 — online evaluation of SAMPLED traffic, on `ctx.waitUntil`.
  //
  // AFTER `residency()`, and that edge is the whole reason it is here rather
  // than anywhere else: `residency()` is what resolves and publishes the
  // tenant's zero-data-retention posture for this request, and this middleware
  // must be able to read it BEFORE it clones a body. A ZDR
  // tenant is never sampled (evaluating a prompt means copying it), and a
  // sampler mounted ahead of the resolver would have no way to know.
  //
  // Nothing it does is in front of a client byte: before `next()` it takes one
  // in-memory policy peek, one hash and — only for a request already SELECTED
  // — one `Request.clone()`, which tees a stream and reads nothing. The judge
  // does not run here at all; it runs in the queue consumer below, in a
  // different Worker invocation.
  //
  // Being INSIDE `guardrails()` would also have worked (it only reads the
  // final response), and outside is preferred for one reason: a request a
  // guardrail blocks answers 403, and this middleware then declines it as
  // not-evaluable and COUNTS the skip, so a deployment whose traffic is mostly
  // being blocked can see that in the sampler's own diagnostics.
  //
  // It sits ABOVE `responseStateCommit()` rather than below it because that is
  // the only order satisfying BOTH adjacency claims — this one's "immediately
  // after `residency()`" and the next one's "immediately above `guardrails()`,
  // with nothing in between that touches a response body". Either order is
  // safe for THIS middleware (it only clones a request, never rewrites a
  // response), so the stricter claim wins the slot next to the screener.
  onlineEvaluation(onlineEvals),
  // #689 — the `/v1/responses` conversation-state WRITE.
  //
  // IMMEDIATELY ABOVE `guardrails()`, and the position is the entire security
  // argument rather than a preference. This middleware does its work on the way
  // OUT, so sitting one layer further out than the screener is what makes the
  // bytes it files the bytes the client receives: redacted where the policy
  // redacted, and ABSENT where the policy refused. Mounted below `guardrails()`
  // it would see the pre-screening body and `GET /v1/responses/{id}` would hand
  // back content the operator's policy had already rejected — which is exactly
  // the defect the first shape of #689 shipped, with every guardrail test green.
  //
  // Nothing between it and the screener may rewrite a response body; today
  // nothing between here and `guardrails()` touches one at all — the list below
  // this entry is `guardrails()` and nothing else.
  //
  // Inert for every request that is not a STORING `/v1/responses` call: one
  // `WeakMap` lookup after `next()` and nothing else. See
  // `src/inference/conversation-commit.ts`.
  responseStateCommit(),
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
  let tenantRouter: ReturnType<typeof resolverForEnv>["router"] | undefined;
  let tenantIds: readonly string[] | undefined;
  try {
    tenantRouter = resolverForEnv(env as TenancyBindings).router;
    tenantIds = await tenantRouter.provisionedTenants();
    await usage.sweep({ env, ctx }, undefined, tenantIds);
    // The usage/presence → control-D1 projection repair sweep is intentionally
    // NOT run (removed with `MeteringUsageSink.sweepUsageProjections` and
    // `src/metering/usage-projection.ts`): those rows are tenant-object
    // authoritative and no longer mirrored to control D1 (no-tenant-data mirror
    // red line). Admission reads the tenant object directly; nothing reads the
    // control copy.
    // The experiment-shadow-leg → control-D1 projection repair sweep is
    // intentionally NOT run (removed with `sweepExperimentProjections` and the
    // control projection in `experiments/{d1,sink}.ts`): the shadow leg is
    // tenant-object authoritative and the control projection was DROPPED by
    // control migration 0043 (no-tenant-data mirror red line). The operator
    // report reads the tenant objects by fan-out (`admin_experiment.ts`);
    // nothing reads the control copy.
    // The managed-isolation-evidence → control-D1 rebuild sweep is intentionally
    // NOT run (removed with `src/managed-evidence-projection.ts`): that evidence
    // is tenant-object authoritative and no longer mirrored to control D1
    // (no-tenant-data mirror red line). Nothing reads the control copy.
    //
    // The asset-audit → control-D1 projection sweep is intentionally NOT run.
    //
    // It re-UPSERTed EVERY tenant's entire `audit_events` set into control D1 on
    // every one-minute tick with no persisted watermark, which — against a fleet
    // with essentially no traffic — was pure write churn: it metered ~120M
    // `rows_written` in a week (5 indexes × the whole table, every minute) and
    // was the sole cause of the D1 billing spike. Nothing on the gateway reads
    // that mirror: the authority is each tenant's own hash-chained
    // `audit_events` in its Durable Object (`appendAudit`), and the only
    // gateway-side reader — `D1AssetAuditSink.screeningEvidence`, the #379
    // withheld-asset listing — reads the DO, not this projection. Fleet-wide
    // operator audit reads, if ever needed, fan out to the tenant objects (the
    // Polaris monitoring pattern). Re-enable = restore this call plus the
    // env-wired projection in `assetAuditSinkFromEnv` (`assets/d1.ts`).
  } catch (error) {
    // Keep compatibility deployments recoverable when the tenant registry is
    // unavailable; tenant-aware deployments enter the branch above and sweep
    // each tenant object's billing outbox.
    await usage.sweep({ env, ctx });
    console.warn(
      `[ferrogate] usage projection repair skipped: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (tenantRouter !== undefined && tenantIds !== undefined) {
    await sweepAssetRetentionForTenants(env, tenantRouter, tenantIds);
  }
  await gatewayRequestLogRetention(env, tenantIds ?? []);
  // Zero-D1 Plan B billing-outbox co-migration: recover crash-stranded PLATFORM
  // outbox rows. RECOVERY ONLY — the request path publishes each unattributed
  // platform charge once and reaps its platform outbox row in the same pass, so
  // this sweep only re-delivers rows an isolate death stranded (money-safe:
  // downstream dedups on the ledger-entry-id). Gated OFF by default
  // (`GATEWAY_PLATFORM_BILLING_DRAIN`; that same gate forces the request-path
  // shadow to WRITE the platform outbox, so the sweep is never fed an empty
  // store). Placed OUTSIDE the try/catch above and grouped with the other
  // Zero-D1 Plan B leg, AFTER money recovery (`usage.sweep`), so the degraded
  // fallback branch still reaches this gate and `sweepPlatform` never throws.
  if (platformBillingFlagEnabled(env, GATEWAY_PLATFORM_BILLING_DRAIN)) {
    await usage.sweepPlatform({ env, ctx });
  }
  // Zero-D1 Plan B write-migration: back up the control projection's
  // pre-dual-write UNATTRIBUTED billing rows into the authoritative
  // PlatformDataObject, resumably. After G1's `#deliverOnce` dual-write there is
  // still a historical tail in control that no tenant fan-out reader can reach;
  // this is the one-time copy of it. Gated OFF by default
  // (`GATEWAY_PLATFORM_BILLING_BACKFILL`), never throws, and once both table
  // marks are complete it costs two small object reads per tick and zero control
  // reads. Reader cutover stays deferred (owned by the polaris system later), so
  // this is purely getting the data INTO the object. It runs AFTER money
  // recovery (`usage.sweep`, above) so a bulk copy can never delay it.
  await sweepPlatformBillingBackfill(
    env,
    controlDatabaseFrom(env),
    platformDatabaseFrom(env),
    Math.floor(Date.now() / 1000),
  );
  // #689 — expired `/v1/responses` conversation state, on the SAME tick.
  //
  // It is a SEPARATE call rather than a line inside `gatewayRequestLogRetention`
  // because the two read different storage surfaces: request evidence is
  // tenant-object authoritative with a CONTROL_DB projection, while conversation
  // state lives in the TENANT database (`DB`), so a deployment can bind one
  // without the other and the sweep for either must still run.
  //
  // This call is the whole reason the storage decision went to D1 rather than a
  // Durable Object per conversation: a DO namespace cannot be enumerated, so
  // eviction there needs a per-object alarm — which is #765, where MCP sessions
  // are never evicted because nothing walks the namespace. Never throws.
  await sweepResponseConversations(env, Math.floor(Date.now() / 1000));
  // #692 — compare the last day of judge scores against the last week's
  // baseline and record the drops that clear each tenant's own threshold. On
  // the SAME tick as the other two sweeps and after them, because it is the
  // one that can be skipped without consequence: it never throws, and a
  // quality measurement must not be able to delay money recovery.
  //
  // Tenant DISCOVERY is the provisioned-tenant roster (`tenantIds`, from
  // `provisionedTenants()`), threaded in exactly like `sweepBatchExecution`
  // below. It used to `SELECT DISTINCT tenant` over the shared-control
  // `online_eval_scores` mirror — a Track A red line that migration `0043` has
  // since DROPped — so the roster is now the only discovery source, and each
  // tenant's scores are read from its own object. An unresolved registry
  // (degraded fallback) yields an empty roster and the sweep is a clean no-op.
  await sweepAllOnlineEvalRegressions(env, tenantIds ?? [], Math.floor(Date.now() / 1000));
  // #698 slice 2/3 — advance every tenant's claimable batch jobs.
  //
  // LAST on the tick, and only when the tenant registry resolved, for the same
  // reason the eval regression sweep is next-to-last: it is the most expensive
  // thing here (it can dispatch paid provider calls) and it must never be able
  // to delay money recovery. `sweepBatchExecution` never throws and takes a
  // per-tenant lease, so overlapping with the Queue consumer is safe by
  // construction rather than by scheduling luck.
  if (tenantIds !== undefined) {
    await sweepBatchExecution(env, tenantIds, { usage });
  }
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
async function gatewayRequestLogRetention(
  env: unknown,
  tenants: readonly string[],
): Promise<void> {
  const db = requestLogDatabaseFrom(env);
  const nowUnix = Math.floor(Date.now() / 1000);
  // Track A / G2: request-log retention no longer touches the control mirror.
  // It fans the fleet default over the PROVISIONED ROSTER (each tenant's own
  // object) and the PLATFORM_DATA object; the control projection's discovery
  // SELECT and mirror-DELETE were retired (see `requestlog/retention.ts`), so a
  // dropped control `request_logs` cannot fault this sweep.
  await sweepRequestLogs(env, tenants, nowUnix);
  // Guardrail screening evidence (#665/#860) is swept on the SAME tick with
  // the SAME policy. Tenant-attributed rows are deleted from their object first
  // and the CONTROL rows here are removed only as derived mirrors. Deliberately
  // not a separate retention window: a request log whose screening evidence has
  // been deleted (or the reverse) makes the investigation view able to
  // half-answer. With no CONTROL_DB, explicit tenant overrides still run against
  // TenantDataObject; fleet discovery remains unavailable because DO namespaces
  // cannot be enumerated. See `guardrails/evidence-retention.ts`.
  await sweepGuardrailEvidence(db, env, nowUnix);
}

/**
 * The `[[queues.consumers]]` handler — request-log messages become object rows
 * plus derived D1 projection rows.
 *
 * Exposed here and re-exported through `src/worker.ts` for the same reason
 * `gatewayScheduled` is: workerd only dispatches a queue event to a handler
 * found on the ENTRY module's DEFAULT export, so a named export alone would be
 * silently accepted as a service entrypoint and the queue would fill and
 * dead-letter with nothing consuming it.
 */
export async function gatewayQueue(batch: RequestLogMessageBatch, env: unknown): Promise<void> {
  // TWO queues now arrive at this one entry point (#692), so the delivery is
  // routed on the message body's `object` discriminator rather than on the
  // queue NAME: the names in `wrangler.toml` are documented placeholders that
  // the deploy step substitutes, so a name comparison would be a routing rule
  // that works on one account and silently misroutes on another.
  //
  // Discriminating BEFORE decoding is the rule `requestlog/queue.ts` already
  // states: `requestLogFromWire` is permissive and would turn an
  // online-evaluation sample into a plausible, wrong `request_logs` row rather
  // than an error. A Cloudflare batch never mixes queues, so in production this
  // partition is all-or-nothing; it is written as a partition anyway so the
  // code is honest about what it does with a mixed batch.
  // The view is BUILT rather than spread: `MessageBatch.retryAll` lives on the
  // platform object's PROTOTYPE, so `{ ...batch }` would silently produce a
  // batch with no `retryAll` — and a consumer that cannot arm a retry loses
  // every message in a delivery D1 rejected, quietly, which is the worst
  // available failure here.
  const view = (
    messages: readonly { readonly body: unknown; ack?(): void }[],
  ): OnlineEvalMessageBatch => ({
    queue: batch.queue,
    messages,
    retryAll: (options?: unknown) => batch.retryAll?.(options),
  });

  const evalMessages = batch.messages.filter(
    (message) => onlineEvalSampleFromWire(message.body) !== undefined,
  );
  if (evalMessages.length > 0) {
    // A judge score is tenant data: it lands in the owning object and is NOT
    // mirrored to the shared control store (#859/#881 red line). The control
    // projection that once dual-wrote beside it has been retired end to end and
    // its mirror table DROPped (0043); the consumer is now tenant-object
    // single-source, so there is no projection flag left to pass.
    await consumeOnlineEvalBatch(view(evalMessages), env);
  }
  // #698 — the THIRD queue on this entry point. Same rule as the second: the
  // partition is on the body's `object` discriminator (`batch.job`), not on
  // `batch.queue`, because the queue names in `wrangler.toml` are placeholders
  // the deploy step substitutes per account.
  const batchJobs = batch.messages.filter(
    (message) => batchJobFromWire(message.body) !== undefined,
  );
  if (batchJobs.length > 0) {
    await consumeBatchJobBatch(view(batchJobs) as BatchJobMessageBatch, env, { usage });
  }
  const rest = batch.messages.filter(
    (message) =>
      onlineEvalSampleFromWire(message.body) === undefined &&
      batchJobFromWire(message.body) === undefined,
  );
  if (rest.length > 0) {
    // Track A / G2: request_logs AND guardrail evidence are tenant data — each
    // lands in the owning TenantDataObject (and PLATFORM_DATA for unscoped) and
    // is NOT mirrored to the shared control store. Both control projections now
    // have ZERO runtime readers: the SIEM pump reads request_logs from each
    // tenant object (#825), and the finops JOIN readers fan out. Both legs are
    // dropped here; each flag is independently reversible (flip back re-arms the
    // dual write).
    await consumeRequestLogBatch(
      view(rest) as RequestLogMessageBatch,
      env,
      undefined,
      undefined,
      undefined,
      { projectGuardrailToControl: false, projectRequestLogToControl: false },
    );
  }
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
