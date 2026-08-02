/**
 * Narrow local interfaces (dependency inversion) for everything the inference
 * data plane needs but does not own.
 *
 * Wave-2 packages (`@ferrogate/routing`, `@ferrogate/providers`,
 * `@ferrogate/billing`, `@ferrogate/observability`, `@ferrogate/secrets`) are
 * still stubs being written concurrently, so this module declares the *seams*
 * the handlers code against and `defaults.ts` supplies runnable in-memory
 * implementations. When the packages land they are adapted to these interfaces;
 * nothing in `handlers.ts` changes.
 *
 * Every interface here is a projection of a concrete Rust type — the mapping is
 * recorded on each declaration so the adapters can be written mechanically:
 *
 * | this module            | Rust                                                    |
 * |------------------------|---------------------------------------------------------|
 * | `PhysicalRoute`        | `ferrogate_providers::ModelRoute` + `ProviderConfig`     |
 * | `ModelResolver`        | `AppState::resolve_model` / `ModelRegistry`              |
 * | `ProviderAdapter`      | `ferrogate_providers::ProviderAdapter`                   |
 * | `UpstreamRequest`      | `ferrogate_providers::ProviderHttpRequest`               |
 * | `UpstreamDispatcher`   | `server/dispatch.rs::dispatch_provider_{,streaming_}request` |
 * | `Usage`/`UsageSink`    | `ferrogate_billing` metering event sink                  |
 * | `Caller`               | `ferrogate_gateway::auth::AuthContext` + `CallerScope`   |
 * | `StreamNormalizers`    | `messages_stream.rs` / `responses_stream.rs`             |
 */

// ---------------------------------------------------------------------------
// Model catalog / routing
// ---------------------------------------------------------------------------

/**
 * How a provider carries its credential on the wire.
 *
 * Rust hard-codes one scheme per adapter family — `Authorization: Bearer` in
 * `openai.rs::provider_headers`, `x-api-key` in `anthropic.rs::anthropic_headers`
 * — because `ProviderConfig` describes the *vendor* endpoint, where the scheme
 * is a property of the vendor. A FerroGate deployment also points at
 * Anthropic-Messages-COMPATIBLE relays, which speak the same body grammar but
 * authenticate like OpenAI, so the scheme is expressible per provider here.
 * `undefined` keeps the Rust default for the family verbatim
 * (`defaultAuthScheme` in `adapters.ts`); a route only ever deviates because an
 * operator wrote `auth_scheme` in the provider table.
 */
// Type-only, and therefore erased at build time: `reliability.ts` imports
// `PhysicalRoute`/`UpstreamRequest` back out of this module, so a VALUE import
// here would be a real cycle.
import type { AsyncShadowBudgetLedger } from "@ferrogate/routing";
import type { ByokPorts, ByokPortsFactory } from "./byok.js";
import type { ProviderCircuit, ReliabilitySettings } from "./reliability.js";
import type { RoutingMetrics, RoutingStrategy } from "./strategy.js";
import type { WorkflowCatalogSource, WorkflowRunHistory } from "./workflow.js";

export type ProviderAuthScheme = "bearer" | "x-api-key";

/** `ferrogate_providers::ModelCapability` — the closed capability vocabulary. */
export type ModelCapability =
  | "chat"
  | "streaming"
  | "vision"
  | "images"
  | "embeddings"
  | "tools"
  | "structured_output";

/**
 * `ferrogate_providers::AwsProviderCredentials` — the SigV4 credential the
 * `bedrock` family signs with (issue #172).
 *
 * `sessionToken` is present only for temporary/STS credentials; a long-lived
 * IAM user access key omits it. The secrets are plain strings on this seam and
 * are wrapped in `@ferrogate/providers`' `SecretValue` the moment they cross
 * into the package (`packageProviderAdapter`), which is where the Rust wraps
 * them too — the route object itself is never logged or serialized.
 */
export interface AwsRouteCredentials {
  /** `aws_access_key_id` — not a secret; safe in the plain provider table. */
  readonly accessKeyId: string;
  /** Resolved from the Worker SECRET named by `aws_secret_access_key_var`. */
  readonly secretAccessKey: string;
  /** Resolved from `aws_session_token_var`; absent for IAM user keys. */
  readonly sessionToken?: string | undefined;
  /** The AWS region — Rust reuses `Provider.region` (issue #173) for this. */
  readonly region: string;
}

/**
 * `ferrogate_providers::GcpProviderCredentials` — a PRE-MINTED OAuth2 access
 * token plus project/location for the `vertex` family (issue #172).
 *
 * FerroGate deliberately does not mint or refresh this token: the Rust doc on
 * `GcpProviderCredentials` states the reason (`prepare_chat_completions` is
 * synchronous and cannot make a token round trip), and the same holds here
 * because the adapter seam is synchronous in the TS port as well. An operator
 * supplies an externally-refreshed token, exactly as in Rust.
 */
export interface GcpRouteCredentials {
  /** Resolved from the Worker SECRET named by `gcp_access_token_var`. */
  readonly accessToken: string;
  /** `gcp_project_id` — not a secret. */
  readonly projectId: string;
  /** The GCP location — Rust reuses `Provider.region` for this. */
  readonly location: string;
}

/**
 * `ferrogate_providers::CloudflareAiGatewayRouting` — the per-provider upstream
 * routing that puts a request through the tenant's Cloudflare AI Gateway
 * (issue #406, mounted by #672).
 *
 * This is the ROUTE-side twin of `@ferrogate/providers`' interface of the same
 * shape, and it exists here for the same reason `AwsRouteCredentials` does: the
 * token is a plain string on this seam and is wrapped in the package's
 * un-printable `SecretValue` only at the package boundary
 * (`adapters.ts::withCloudflareAiGatewayRouting`).
 *
 * `accountId` / `gatewayBaseUrl` / `apiBaseUrl` come from the ACCOUNT block and
 * are copied onto every route so the seam carries one value — the same
 * flattening `PhysicalRoute` already does for `ModelRoute` + `ProviderConfig`.
 */
export interface CloudflareAiGatewayRoute {
  /** `[cloudflare].account_id` — the account the gateway lives in. */
  readonly accountId: string;
  /** `cloudflare_ai_gateway.gateway_id` — the gateway's name in that account. */
  readonly gatewayId: string;
  /** `[cloudflare].ai_gateway_base_url`; the compat (passthrough) host. */
  readonly gatewayBaseUrl: string;
  /** `[cloudflare].api_base_url`; the unified REST host. */
  readonly apiBaseUrl: string;
  /** Which of the two AI Gateway surfaces this provider is routed onto. */
  readonly mode: "Compat" | "Unified";
  /** Cloudflare's provider slug; derived from the family when absent. */
  readonly providerSlug?: string | undefined;
  /**
   * `cf-aig-authorization` bearer, resolved from the binding named by
   * `aig_token_var`. Absent = an unauthenticated gateway, which is a real
   * Cloudflare configuration and must NOT produce an empty header.
   */
  readonly aigToken?: string | undefined;
}

/**
 * One physical provider/model pair a logical model resolves to, flattened
 * together with the provider connection details the adapter needs.
 *
 * Rust keeps these in two structs (`ModelRoute` for the routing half,
 * `ProviderConfig` for the connection half) because the registry and the
 * adapter are separate crates' concerns; the gateway always holds both at the
 * point of dispatch, so the seam carries one value.
 */
export interface PhysicalRoute {
  /** The name the caller asked for (`ModelRoute` is keyed by it). */
  readonly logicalModel: string;
  /** Configured provider name (`ProviderConfig.name`). */
  readonly provider: string;
  /** Provider-side model id sent on the wire (`ModelRoute.provider_model`). */
  readonly providerModel: string;
  /** Adapter family kind: `openai-compatible`, `anthropic`, … (`ProviderConfig.kind`). */
  readonly providerKind: string;
  /** Provider base URL; adapters append their endpoint path to it. */
  readonly baseUrl: string;
  /** Provider credential. Resolved from Secrets Store in production. */
  readonly apiKey?: string | undefined;
  /**
   * The PER-ROUTE BYOK alias (issue #682) — `[[providers]].byok_alias`.
   *
   * Present ⇒ this route prefers the CALLING TENANT's own credential registered
   * under that alias, resolved per request by `./byok.ts`. It holds an alias,
   * never a credential and never a tenant: the tenant is the authenticated
   * caller's, so the same route serves every tenant with that tenant's own key.
   *
   * A route that names an alias the caller has not registered is served with NO
   * credential rather than with the platform's — see `applyByokOverride`.
   */
  readonly byokAlias?: string | undefined;
  /**
   * `ProviderConfig.aws_credentials` — required by the `bedrock` family and
   * unread by every other one. Absent for a Bedrock route means the adapter
   * fails closed at request-preparation time rather than sending an unsigned
   * request, which is the Rust fail-closed shape.
   */
  readonly awsCredentials?: AwsRouteCredentials | undefined;
  /** `ProviderConfig.gcp_credentials` — the `vertex` family's equivalent. */
  readonly gcpCredentials?: GcpRouteCredentials | undefined;
  /**
   * `ProviderConfig.cloudflare_ai_gateway` (issue #672). Present ⇒ every
   * request built for this route is re-addressed onto the tenant's Cloudflare
   * AI Gateway AFTER the adapter has prepared it, by the wrapper every entry in
   * `defaultAdapterRegistry` is built through. Absent ⇒ the vendor is dialled
   * directly, which is what every deployment did before this field existed.
   */
  readonly cloudflareAiGateway?: CloudflareAiGatewayRoute | undefined;
  /** Credential scheme; `undefined` = the Rust default for `providerKind`. */
  readonly authScheme?: ProviderAuthScheme | undefined;
  /** `owned_by` in the `/v1/models` listing — the Rust code echoes the provider name. */
  readonly ownedBy?: string | undefined;
  /** `ModelRoute.capabilities`; empty is the legacy capability-neutral case. */
  readonly capabilities?: readonly ModelCapability[] | undefined;
  /** `ModelRoute.region` (issue #173) — `undefined` when the provider declares none. */
  readonly region?: string | undefined;
  /**
   * `ModelRoute.context_window` — the declared token ceiling, and half of the
   * `model_routing.rs` eligibility gate. `undefined` means "undeclared", which
   * is only tolerated on a capability-neutral route (see
   * `candidates.ts::routeExclusionReasons`).
   */
  readonly contextWindow?: number | undefined;
  /**
   * `ModelRoute.priority` — ASCENDING, so `0` is tried before `1`. Absent is
   * `0`, i.e. every route a legacy config declares shares one priority group.
   */
  readonly priority?: number | undefined;
  /** `ModelRoute.weight` — DESCENDING within a priority group. Absent is `0`. */
  readonly weight?: number | undefined;
  /**
   * `ModelRoute.input_price_per_1m` — USD per 1,000,000 PROMPT tokens.
   *
   * Read only by `strategy.ts::routeEstimatedCost` / `balancedRouteScore`; it is
   * NOT the billing price (metering prices the provider's REPORTED usage from
   * its own tables). Absent means "unpriced", which `lowest_cost` treats as
   * infinitely expensive and `balanced` treats as 1,000 — the two Rust readings,
   * and they differ on purpose.
   */
  readonly inputPricePer1m?: number | undefined;
  /** `ModelRoute.output_price_per_1m` — USD per 1,000,000 COMPLETION tokens. */
  readonly outputPricePer1m?: number | undefined;
  /**
   * `ModelRoute.cached_input_price_per_1m` — USD per 1M CACHE-READ prompt
   * tokens (issue #667).
   *
   * Unlike the two rates above, these three are read ONLY by settlement
   * (`metering/route-price.ts`), never by routing: a cache-read discount is a
   * property of a request that has already happened, and the router chooses
   * before it knows whether the prompt will hit the cache.
   */
  readonly cachedInputPricePer1m?: number | undefined;
  /** `ModelRoute.cache_write_price_per_1m` — USD per 1M CACHE-WRITE prompt tokens. */
  readonly cacheWritePricePer1m?: number | undefined;
  /** `ModelRoute.reasoning_price_per_1m` — USD per 1M reasoning tokens. */
  readonly reasoningPricePer1m?: number | undefined;
  /**
   * `ModelRegistryEntry.routing_strategy` — the order the ladder walks the
   * eligible candidates in (`strategy.ts`).
   *
   * It lives on the registry ENTRY in Rust, not on a route, so every leg
   * flattened out of one `[[models]]` row carries the same value and
   * `handlers.ts` reads it off whichever leg it has. Absent is `"priority"`,
   * which is `RoutingStrategy::default()` and is the behavior this data plane
   * had before the strategies landed.
   */
  readonly routingStrategy?: RoutingStrategy | undefined;
  /**
   * `CanaryRoute.percent` (0–100). Present ⇒ this route is a CANARY: it is
   * promoted to the head of the candidate list for the sticky subset of callers
   * `canarySelected` picks, and dropped for everyone else. See
   * `candidates.ts::applyCanary`.
   */
  readonly canaryPercent?: number | undefined;
  /**
   * `ShadowRoute.sample_percent` (0–100). Present ⇒ this route is a MIRROR and
   * is never servable to a client — `candidates.ts::servableCandidates` strips
   * it out of the ladder before the first dispatch.
   */
  readonly shadowPercent?: number | undefined;
  /** `ShadowRoute.max_requests` — the budget cap; `0` is uncapped. */
  readonly shadowMaxRequests?: number | undefined;
  /** Disabled models resolve to `null` but still exist; see {@link ModelResolver.catalog}. */
  readonly enabled: boolean;
  /** Tenant that owns a private model; `undefined` means globally visible. */
  readonly tenantId?: string | undefined;
  /** Project that owns a private model; `undefined` means tenant-wide. */
  readonly projectId?: string | undefined;
}

/**
 * `AppState::resolve_model`.
 *
 * `resolve` returns `null` for BOTH "unknown model" and "model disabled" — the
 * Rust `ModelRegistryError` distinguishes them (`model_not_found` vs
 * `model_disabled`, both 400), which is recovered here by consulting
 * {@link catalog}: a `null` resolve whose name appears in the catalog with
 * `enabled: false` is `model_disabled`. Keeping `resolve` at the one-line
 * signature keeps the seam trivial for the wave-2 `@ferrogate/routing` adapter.
 *
 * ## The candidate list (was PORT-TODO F3/F4/F5 — now wired)
 *
 * `resolve` returning ONE route was the reason the entire Rust reliability
 * layer between "resolve a model" and "call the provider" was absent from this
 * data plane. {@link ModelResolver.candidates} is the port of
 * `AppState::candidate_model_routes` (`state_routing.rs:489`) — the ORDERED
 * list `chat.rs:259`'s `'routes:` loop walks — and
 * `handlers.ts::dispatchCandidates` walks it through
 * `reliability.ts::dispatchWithFailover`, consulting a
 * {@link ProviderCircuit} per candidate and `isRetryableStatus` (imported from
 * `@ferrogate/providers`) per attempt. Eligibility (issue #582) is
 * `candidates.ts::eligibleCandidates`, applied BEFORE the first dispatch,
 * exactly as `model_routing.rs` applies it before any strategy reads price or
 * health.
 *
 * `candidates` is OPTIONAL so every existing {@link ModelResolver} keeps
 * compiling; `defaults.ts::resolveCandidates` falls back to
 * `[resolve(model)]`, i.e. the pre-wiring single-route behavior. It is the
 * `InMemoryModelResolver` shipped in `defaults.ts` that implements it for real.
 *
 * ### Still open on this seam
 *
 * One thing, and it is not in this file: `candidates.ts::routeExclusionReasons`
 * is WIDER than Rust on three legs (undeclared `capabilities`, undeclared
 * `context_window`, and unbounded media context), so a route this seam yields
 * can survive an eligibility check Rust would have failed. The marker there
 * states each deviation, why it is not closed unilaterally, and which file has
 * to move first. This heading previously stood EMPTY, immediately above three
 * "now wired" sections, which read as "nothing is open" — it is not nothing.
 *
 * ### The provider attempt index (was PORT-TODO #135 — now wired)
 *
 * The ladder can make more than one attempt per request, so
 * `metering/event.ts::providerAttemptIndexFor` partitions `ledgerEntryId` on
 * {@link Usage.providerAttemptIndex}, which `handlers.ts` sets from
 * `FailoverOutcome.attempts`. Without it two attempts of one request derived one
 * ledger id and the second was absorbed by `ON CONFLICT DO NOTHING` as a silent
 * under-bill.
 *
 * ### Routing strategies (was PORT-TODO F6 — now wired)
 *
 * `candidates` returns the list in `orderCandidates` order (priority ASC, weight
 * DESC, then a total order). `handlers.ts::planRequest` then re-orders the
 * ELIGIBLE survivors through `strategy.ts::orderCandidatesByStrategy`, which is
 * the port of `candidate_model_routes`'s four `RoutingStrategy` arms including
 * the weighted round-robin (`weighted_start_index`) the priority arm applies
 * within each priority group. `PhysicalRoute.routingStrategy` /
 * `.inputPricePer1m` / `.outputPricePer1m` are the config fields that were
 * previously unrepresentable; `catalog.ts` reads them off `[[models]]`.
 */
export interface ModelResolver {
  /** Resolve a logical model to the physical route to dispatch on. */
  resolve(model: string): PhysicalRoute | null;
  /** Every configured route, enabled or not — backs `GET /v1/models`. */
  catalog(): readonly PhysicalRoute[];
  /**
   * `AppState::candidate_model_routes` — every enabled route for the logical
   * model, primary first then fallbacks, in `orderCandidates` order.
   *
   * Optional for backward compatibility only; see the class docs above.
   */
  candidates?(model: string): readonly PhysicalRoute[];
}

/**
 * Worker bindings the inference data plane reads.
 *
 * `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` are the JSON-var form of the Rust
 * config's `[[providers]]` and `[[models]]` tables (`config/ferrogate.example.toml`).
 * Provider CREDENTIALS are never in either var: a provider names the binding
 * that holds its key in `api_key_var`, exactly as the Rust config names an
 * environment variable in `api_key_env`, and that binding is a Worker SECRET.
 * The index signature is what lets `api_key_var` name an arbitrary one.
 */
export interface InferenceBindings {
  /** JSON array of provider connections — Rust `[[providers]]`. */
  readonly GATEWAY_PROVIDERS?: string | undefined;
  /** JSON array of logical model entries — Rust `[[models]]`. */
  readonly GATEWAY_MODELS?: string | undefined;
  /**
   * The account-level Cloudflare block — Rust's top-level `[cloudflare]`
   * (issue #672). JSON object: `account_id` plus the two optional base-URL
   * overrides. It is a separate var rather than a key on every provider row for
   * the same reason Rust makes it a separate section: the account id is a
   * property of the DEPLOYMENT, and repeating it per provider is a chance to
   * write two different ones.
   */
  readonly GATEWAY_CLOUDFLARE?: string | undefined;
  /** Secret bindings, reached by name through a provider's `api_key_var`. */
  readonly [binding: string]: unknown;
}

/**
 * A {@link ModelResolver} that can only be built once the Worker bindings
 * exist.
 *
 * Worker `env` is a per-request value, so the composition root in
 * `apps/gateway/src/index.ts` cannot construct an env-backed registry at module
 * scope. It injects this factory instead and the router calls it once per env
 * object (memoized) — the same shape `middleware/auth.ts` already uses for its
 * `DepsResolver`.
 */
export type ModelResolverFactory = (env: InferenceBindings) => ModelResolver;

// ---------------------------------------------------------------------------
// Provider adapters
// ---------------------------------------------------------------------------

/** Which ingress operation an upstream request is being built for. */
export type InferenceOperation =
  | "chat.completions"
  | "responses"
  | "embeddings"
  | "images"
  | "model_catalog";

/**
 * `ChatCompletionPlan` / `ResponsesPlan` / `EmbeddingsPlan` / `ImagesPlan`
 * unified — the four Rust plan structs are field-identical apart from `stream`,
 * which the two non-streaming ones simply never set.
 */
export interface UpstreamPlan {
  readonly operation: InferenceOperation;
  readonly route: PhysicalRoute;
  readonly logicalModel: string;
  readonly providerModel: string;
  /** Always `false` for `embeddings`/`images` (neither streams — `ImagesPlan` doc). */
  readonly stream: boolean;
  /** The caller's body, already validated; adapters rewrite it in place-ish. */
  readonly body: Record<string, unknown>;
}

/** `ferrogate_providers::ProviderHttpRequest`. */
export interface UpstreamRequest {
  readonly provider: string;
  /** Absolute URL (`ProviderHttpRequest.endpoint`). */
  readonly endpoint: string;
  readonly method: "GET" | "POST";
  /** Header values are secrets; never log this map. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Record<string, unknown> | undefined;
  readonly stream: boolean;
}

/** `ferrogate_providers::AdapterError`. */
export type AdapterError =
  | { readonly kind: "unsupported_provider_kind"; readonly providerKind: string }
  | { readonly kind: "invalid_request"; readonly message: string }
  | {
      readonly kind: "unsupported_capability";
      readonly capability: string;
      readonly providerKind: string;
    };

/** `Result<ProviderHttpRequest, AdapterError>`. */
export type AdapterResult =
  | { readonly ok: true; readonly request: UpstreamRequest }
  | { readonly ok: false; readonly error: AdapterError };

/** Render an {@link AdapterError} with the Rust `Display` text. */
export function adapterErrorMessage(error: AdapterError): string {
  switch (error.kind) {
    case "unsupported_provider_kind":
      return `unsupported provider kind ${error.providerKind}`;
    case "invalid_request":
      return error.message;
    case "unsupported_capability":
      return `provider kind ${error.providerKind} does not support ${error.capability}`;
  }
}

/**
 * `ferrogate_providers::ProviderAdapter`, collapsed to one entry point.
 *
 * Rust has four `prepare_*` methods with defaults that fail closed; the
 * `operation` discriminator on {@link UpstreamPlan} carries the same
 * information, and an adapter that cannot serve an operation returns the
 * matching {@link AdapterError} exactly as the Rust default did (notably
 * `unsupported_capability` for images on a non-OpenAI family — issue #275).
 */
export interface ProviderAdapter {
  /** `ProviderAdapter::kind`. */
  readonly kind: string;
  /** `prepare_chat_completions` / `prepare_responses` / `prepare_embeddings` / `prepare_images`. */
  buildUpstreamRequest(plan: UpstreamPlan): AdapterResult;
  /**
   * `translate_embeddings_response` — return `undefined` to pass the upstream
   * body through byte-for-byte (the OpenAI-compatible family's behavior).
   */
  translateEmbeddingsResponse?(body: unknown, logicalModel: string): unknown | undefined;
}

/** Resolves the adapter for a provider kind (`ferrogate_providers::registry`). */
export interface AdapterRegistry {
  /** `null` when the kind is unknown → `unsupported_provider_kind`. */
  adapterFor(providerKind: string): ProviderAdapter | null;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/**
 * `server/dispatch.rs`. One method covers both the buffered and the streaming
 * Rust functions: on Workers a `Response` carries a `ReadableStream` body, so
 * "buffered" is just "await `.text()`", exactly the distinction
 * `dispatch_provider_request` vs `dispatch_provider_streaming_request` encodes.
 *
 * Implementations MUST NOT follow redirects (Rust uses `Policy::none()`), and
 * MUST surface a transport failure as a thrown error so the handler can map it
 * to `provider_dispatch_error` / 502.
 */
export interface UpstreamDispatcher {
  dispatch(request: UpstreamRequest, signal?: AbortSignal): Promise<Response>;
}

// ---------------------------------------------------------------------------
// Metering
// ---------------------------------------------------------------------------

/**
 * One metered inference call. Union of `ProviderUsage` and the attribution the
 * Rust request log carries (`StoredRequestLog`), because the CF port meters and
 * logs through the same Queue/Analytics-Engine sink.
 */
export interface Usage {
  readonly requestId: string;
  /** Rust route label, e.g. `openai.chat.completions`, `anthropic.messages`. */
  readonly route: string;
  readonly logicalModel: string;
  readonly provider: string;
  readonly providerModel: string;
  readonly stream: boolean;
  /** HTTP status returned to the caller. */
  readonly status: number;
  readonly promptTokens?: number | undefined;
  readonly completionTokens?: number | undefined;
  readonly totalTokens?: number | undefined;
  /**
   * Prompt tokens served from a prompt cache — a SUBSET of {@link promptTokens}
   * (issue #667).
   *
   * The subset normalization and each vendor's conversion onto it are documented
   * on `./usage.ts::ProviderUsage`. What matters HERE is that `promptTokens`
   * remains the WHOLE billable input on every family, so a consumer that ignores
   * this field still bills a correct total — it simply bills the cached portion
   * at the fresh rate instead of the cached one.
   */
  readonly cachedInputTokens?: number | undefined;
  /** Prompt tokens written INTO a prompt cache — a SUBSET of {@link promptTokens}. */
  readonly cacheWriteTokens?: number | undefined;
  /** Reasoning/thinking tokens — a SUBSET of {@link completionTokens}. */
  readonly reasoningTokens?: number | undefined;
  /** `/v1/images/generations` settles on the image count, not tokens (issue #275). */
  readonly imageCount?: number | undefined;
  /** Caller-supplied request tags (issue #171), already bounds-checked. */
  readonly metadata?: Readonly<Record<string, string>> | undefined;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
  /**
   * Rust `ProviderAttempt.index` (#135) — the ZERO-BASED dispatch attempt within
   * ONE logical request, counting retries of a provider and failovers to the
   * next candidate alike.
   *
   * `metering/event.ts::providerAttemptIndexFor` folds it into `ledgerEntryId`,
   * which is a PRIMARY KEY in three tables. Before this field existed, two
   * attempts of one request derived the SAME ledger id, and the second was
   * absorbed by `ON CONFLICT DO NOTHING` as a healthy replay — a silent
   * under-bill rather than a crash. That was latent (only the attempt that
   * produced the served response is metered today) and stops being latent the
   * moment a failed attempt is metered for provider-cost attribution.
   *
   * Absent ⇒ `SINGLE_PROVIDER_ATTEMPT_INDEX` (0), which is the pre-ladder
   * behavior and stays correct for every single-attempt request.
   */
  readonly providerAttemptIndex?: number | undefined;
  /**
   * The SERVED route's own prices (`[[models]].input_price_per_1m` /
   * `output_price_per_1m`), in USD per 1M tokens — carried onto the metering
   * event so the request path can settle a cost the rate card has no rule for
   * (issue #663).
   *
   * These are the same two numbers {@link PhysicalRoute} already carries for
   * cost-based routing (`strategy.ts::routeEstimatedUnitCost`). Before #663
   * that was their ONLY consumer: an operator could publish a model with a
   * price on its registry row, serve real traffic on it, and — because the
   * model was absent from `PriceBook.withDefaultRateCard()` — have every one of
   * those requests fail closed in `charge()` and be recorded NOWHERE.
   *
   * They travel on `Usage` rather than being read from the registry inside the
   * sink for the reason every other field here does: the sink is module-scoped
   * and the registry is per-`env`, and the served route is only unambiguous at
   * the point the dispatch loop actually picked it (a failover means the route
   * that answered is not the route that was planned).
   *
   * Consumed by `metering/route-price.ts::routePriceSettledCostUsd`, which
   * `src/index.ts` passes as `MeteringSinkOptions.settledCostUsd`. Absent ⇒ the
   * rate card decides, exactly as before.
   */
  readonly inputPricePer1m?: number | undefined;
  /** See {@link Usage.inputPricePer1m} — USD per 1M completion tokens. */
  readonly outputPricePer1m?: number | undefined;
  /**
   * `[[models]].cached_input_price_per_1m` — USD per 1M CACHE-READ prompt
   * tokens (issue #667). Absent ⇒ cache reads settle at
   * {@link Usage.inputPricePer1m}.
   *
   * The fallback direction is deliberate and is the same one the rate card
   * takes: a row that states no cached rate has NOT stated a discount, and
   * inventing one would shrink an invoice by a number no operator chose. The
   * cost of the conservative choice is that a cache-heavy Anthropic call on a
   * row-priced model bills its cache reads at the fresh rate until the operator
   * states the discount — visible, and correctable in config, which is exactly
   * what an invisible discount would not be.
   */
  readonly cachedInputPricePer1m?: number | undefined;
  /** `[[models]].cache_write_price_per_1m` — USD per 1M CACHE-WRITE prompt tokens. */
  readonly cacheWritePricePer1m?: number | undefined;
  /** `[[models]].reasoning_price_per_1m` — USD per 1M reasoning tokens. */
  readonly reasoningPricePer1m?: number | undefined;
}

/**
 * The per-request half of the metering seam: the Worker bindings the durable
 * sink writes through, and the `ExecutionContext` that keeps those writes alive
 * past the flushed response.
 *
 * Both are PER REQUEST while a `UsageSink` is built ONCE at module scope, which
 * is why they travel as an argument rather than as construction state. A
 * module-scoped "current env / current ctx" slot is NOT an equivalent: workerd
 * refuses I/O started on behalf of a different request, so a last-write-wins
 * slot corrupts under concurrency exactly when the gateway is busiest.
 *
 * `env` is `unknown` on purpose — this module owns no binding vocabulary, and
 * the sink narrows it (see `src/metering/runtime.ts`). `ctx` is optional
 * because `app.request(...)` in a unit test creates no `ExecutionContext`.
 */
export interface UsageRecordContext {
  /** The Worker bindings for THIS request (`c.env`). */
  readonly env: unknown;
  /** `c.executionCtx`, when the runtime created one. */
  readonly ctx?: { waitUntil(work: Promise<unknown>): void } | undefined;
}

/**
 * Metering sink. `record` is fire-and-forget — it must never throw.
 *
 * `rc` is optional so a caller with no bindings in hand (a unit test, an
 * in-memory harness) still compiles; a sink that needs durable storage treats
 * its absence as "capture now, let whoever owns the request context drain".
 */
export interface UsageSink {
  record(u: Usage, rc?: UsageRecordContext): void;
}

// ---------------------------------------------------------------------------
// Caller identity
// ---------------------------------------------------------------------------

/** `ferrogate_gateway::auth::CallerScope`. */
export type CallerScope =
  | { readonly kind: "platform_operator" }
  | { readonly kind: "tenant"; readonly tenantId: string };

/**
 * The slice of `auth::AuthContext` the inference path actually reads.
 *
 * ROUTE-MAP invariant 1 still holds: bearer authentication and `auth.scope`
 * enforcement belong to the ONE contract-driven middleware that covers all 265
 * operations, not to this module. What the inference handlers own is only the
 * two model gates the Rust inference handlers owned — `can_use_model` (403
 * `model_not_allowed`) and the tenant model-visibility filter on `GET /v1/models`
 * and on invocation (issue #515).
 *
 * Where this value COMES FROM is the part that was missing and is now wired:
 * `route-module.ts` derives it from the outer `c.get("auth")` via
 * `callerFromAuth` (`./identity.ts`) and publishes it for the inner app. Before
 * that, the inner app fell back to `defaultCallerResolver` — a platform
 * operator with no allow/deny list — for every request the deployed Worker
 * served, which made both gates inert in production while every injected-caller
 * unit test stayed green. `test/inference/wiring.test.ts` is the assertion that
 * goes red if the wiring is removed again.
 *
 * `allowedModels` and `allowedProviders` ARE now populated from a real
 * credential — `callerFromAuth` copies both off `AuthContext`, which
 * `keys/resolver.ts` reads off the `api_keys` row (`allowed_models_json` /
 * `allowed_providers_json`). `deniedModels`, `deniedProviders` and
 * `regionAllowlist` are still only ever set by an injected caller: none has a
 * column on that row, so populating them would be inventing a policy rather
 * than porting one. All three stay on the type because {@link callerCanUseModel},
 * {@link callerCanUseProvider} and `candidates.ts::routeExclusionReasons`
 * implement the full Rust predicate for them and are tested on both legs.
 */
export interface Caller {
  readonly scope: CallerScope;
  readonly apiKeyId?: string | undefined;
  readonly projectId?: string | undefined;
  /** `AuthContext.allowed_models` — empty/absent means "no allowlist". */
  readonly allowedModels?: readonly string[] | undefined;
  /** `AuthContext.denied_models`. */
  readonly deniedModels?: readonly string[] | undefined;
  /**
   * `AuthContext.allowed_providers` — the per-key PROVIDER allowlist, read by
   * {@link callerCanUseProvider} inside `reliability.ts::dispatchWithFailover`.
   * Empty/absent means "no allowlist", exactly as for {@link allowedModels}.
   */
  readonly allowedProviders?: readonly string[] | undefined;
  /** `AuthContext.denied_providers` — deny wins over the allowlist. */
  readonly deniedProviders?: readonly string[] | undefined;
  /**
   * `AuthContext.region_allowlist` — the tenant's data-residency policy, read
   * by `candidates.ts::routeExclusionReasons`.
   *
   * EMPTY OR ABSENT MEANS NO GATE, which is the Rust rule
   * (`if !region_allowlist.is_empty()`), and it is the only safe default: a
   * non-empty list excludes every route that does not declare a matching
   * `region`, including routes that declare none at all. Populating this from a
   * credential that does not actually carry a residency policy would black-hole
   * a working catalog.
   */
  readonly regionAllowlist?: readonly string[] | undefined;
}

/** `AuthContext::can_use_model` — deny wins, then the allowlist if non-empty. */
export function callerCanUseModel(caller: Caller, model: string): boolean {
  if (caller.deniedModels?.includes(model)) {
    return false;
  }
  const allowed = caller.allowedModels;
  if (allowed !== undefined && allowed.length > 0) {
    return allowed.includes(model);
  }
  return true;
}

/**
 * `AuthContext::can_use_provider` (`auth.rs:146`) — the same two-legged shape as
 * {@link callerCanUseModel}, over the provider name rather than the model:
 *
 * ```rust
 * !self.denied_providers.contains(provider)
 *     && (self.allowed_providers.is_empty() || self.allowed_providers.contains(provider))
 * ```
 *
 * The name compared is `ModelRoute.provider` — the PROVIDER-TABLE key
 * (`state.providers.get(&model_route.provider)` then `provider.name`), not the
 * provider FAMILY (`providerKind`). A deployment with two `openai`-kind rows
 * `openai-us` / `openai-eu` is gated per row, which is the point of the field.
 *
 * Where it is CONSULTED is load-bearing and is not this file's choice: Rust
 * evaluates it inside the `'routes:` loop, per candidate, immediately after the
 * circuit-breaker check, and a refusal is TERMINAL (`return Ok(())` after a 403)
 * rather than a fall-through to the next candidate. See
 * `reliability.ts::dispatchWithFailover`, which reproduces both the position and
 * the terminality.
 */
export function callerCanUseProvider(caller: Caller, provider: string): boolean {
  if (caller.deniedProviders?.includes(provider)) {
    return false;
  }
  const allowed = caller.allowedProviders;
  if (allowed !== undefined && allowed.length > 0) {
    return allowed.includes(provider);
  }
  return true;
}

/**
 * `AppState::can_tenant_use_model` — a tenant sees a model when the model is
 * global (no owning tenant) or owned by that tenant, and, when the model names
 * a project, only if the caller is in that project.
 */
export function scopeCanSeeModel(
  scope: CallerScope,
  callerProjectId: string | undefined,
  route: PhysicalRoute,
): boolean {
  if (scope.kind === "platform_operator") {
    return true;
  }
  if (route.tenantId !== undefined && route.tenantId !== scope.tenantId) {
    return false;
  }
  if (route.projectId !== undefined && route.projectId !== callerProjectId) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/**
 * Which SSE dialect a stream must be delivered in, keyed by the *ingress*
 * protocol rather than the upstream one — the Rust normalizers translate the
 * provider's dialect into the one the client asked for.
 */
export type StreamDialect = "openai.chat" | "openai.responses" | "anthropic.messages";

/** Everything a normalizer needs to be constructed for one request. */
export interface StreamNormalizerContext {
  /** Dialect the CLIENT was promised, decided by the ingress path. */
  readonly dialect: StreamDialect;
  /** Canonical-or-alias provider kind of the resolved upstream. */
  readonly providerKind: string;
  /** Logical model, used as the `model` a synthesized frame reports. */
  readonly logicalModel: string;
  /** Gateway request id, echoed into `response.*` events. */
  readonly requestId: string;
  /** Upstream `Content-Type`, echoed into `response.completed`. */
  readonly contentType: string;
}

/**
 * Factory for the `TransformStream` that rewrites a provider SSE body into the
 * dialect the ingress promised (`messages_stream.rs` / `responses_stream.rs`).
 *
 * Returning `null` means "pass the upstream bytes through byte-for-byte", which
 * is correct whenever the upstream already speaks the ingress dialect. The
 * shipped implementation is `defaultStreamNormalizers` in `defaults.ts`, backed
 * by `apps/gateway/src/streaming/`.
 */
export interface StreamNormalizers {
  normalizerFor(
    context: StreamNormalizerContext,
  ): TransformStream<Uint8Array, Uint8Array> | null;
}

/**
 * `anthropic_messages.rs` — the pure JSON⇄JSON translation backing `/v1/messages`.
 * Lives behind a seam because it belongs to `@ferrogate/providers` once ported.
 */
export type TranslationResult =
  | { readonly ok: true; readonly body: Record<string, unknown> }
  | { readonly ok: false; readonly error: AdapterError };

export interface AnthropicTranslator {
  /** `to_chat_completions` — Anthropic request → OpenAI chat request. */
  toChatCompletions(body: Record<string, unknown>): TranslationResult;
  /** `chat_completion_to_message` — OpenAI chat response → Anthropic Message. */
  chatCompletionToMessage(chat: unknown, fallbackModel: string): unknown;
}

// ---------------------------------------------------------------------------
// Assorted small seams
// ---------------------------------------------------------------------------

/**
 * `AppState::next_request_id`.
 *
 * PORT-TODO(L: inventory-request-path §"Cross-crate architecture" step 1):
 * PLATFORM LIMIT — Rust formats a process-wide `AtomicU64` as `fg-{:016x}`, so
 * request ids are strictly increasing within one process and two ids can be
 * ORDERED by comparison.
 *
 * Workers cannot reproduce that. A Worker is horizontally replicated across
 * isolates with no shared mutable process state, and the only durable counter
 * on the platform is a Durable Object — i.e. a network round trip on every
 * single request, on the hot path, to produce a log correlation id. That is not
 * a trade the Rust behavior is worth, and it would still not be monotonic
 * across a DO migration.
 *
 * The approximation: the same `fg-` + 16 lowercase hex-digit SHAPE, sourced
 * from `crypto.getRandomValues` (`defaults.ts::defaultRequestIds`). So anything
 * that greps, parses or asserts the format keeps working, and collisions are
 * ~2^-64 per pair rather than impossible-by-construction — but ids are NOT
 * ordered, and nothing may infer arrival order from them.
 *
 * `test/inference/platform-limits.test.ts` pins the approximation ITSELF: the
 * shape, uniqueness across 512 draws, and that the digits come from a CSPRNG
 * rather than from a counter. That last assertion is the one that matters — a
 * per-isolate `AtomicU64` lookalike would look perfectly ordered in a
 * single-isolate test while colliding across isolates in production, and it is
 * the substitution a reader who sees this marker is most likely to reach for.
 * (`test/inference/chat-completions.test.ts` pins only the `x-request-id`
 * passthrough and an INJECTED factory, so it holds none of the above.)
 *
 * The ordering property is deliberately left unpinned in the positive
 * direction: it is the thing that is gone, and a future deliberate ordered
 * implementation should not have to delete an assertion to land.
 */
export interface RequestIdFactory {
  next(): string;
}

/** The subset of `config.limits` the inference path enforces. */
export interface InferenceLimits {
  /** `limits.inference_body_max_bytes` — default 1 MiB in the Rust config. */
  readonly inferenceBodyMaxBytes: number;
  /** `limits.provider_response_body_max_bytes` for the buffered path. */
  readonly providerResponseMaxBytes: number;
  /** Provider dispatch timeout in milliseconds. */
  readonly dispatchTimeoutMs: number;
}

/** Everything the inference router needs, all optional (defaults in `defaults.ts`). */
export interface InferenceDeps {
  /**
   * The model registry, or a {@link ModelResolverFactory} resolved per Worker
   * `env`. Absent = the empty registry, i.e. every model is `model_not_found`.
   */
  readonly models?: ModelResolver | ModelResolverFactory;
  readonly adapters?: AdapterRegistry;
  /**
   * The provider egress, or a factory resolved per Worker `env` — the same
   * shape `circuit` / `shadowBudget` / `workflows` use, and for the same
   * reason: the `AI` binding the `workers-ai` family dispatches through only
   * exists per request, while this deps object is built once per router
   * (issue #673). Absent ⇒ `dispatcherFromEnv`, i.e. `fetch` for every family
   * plus the `env.AI` short-circuit for Workers AI.
   */
  readonly dispatcher?: UpstreamDispatcher | ((env: InferenceBindings) => UpstreamDispatcher);
  readonly usage?: UsageSink;
  readonly normalizers?: StreamNormalizers;
  readonly translator?: AnthropicTranslator;
  readonly requestIds?: RequestIdFactory;
  readonly limits?: Partial<InferenceLimits>;
  /**
   * Resolves the caller for a request. Defaults to a platform operator with no
   * model restrictions so the app is runnable before the auth middleware lands.
   */
  readonly caller?: (request: Request) => Caller;
  /**
   * `[reliability]` — circuit-breaker thresholds and dispatch retries. Absent
   * ⇒ read from the `GATEWAY_RELIABILITY` var, and absent there ⇒ Rust's own
   * defaults, which are "breaker off, no retries" (see
   * `reliability.ts::DEFAULT_RELIABILITY`).
   */
  readonly reliability?: Partial<ReliabilitySettings>;
  /**
   * The provider circuit breaker. Absent ⇒ built per Worker `env`: the
   * `PROVIDER_CIRCUIT` Durable Object when it is bound, the per-isolate
   * approximation otherwise, and `NO_PROVIDER_CIRCUIT` when the operator has
   * not configured a threshold + cooldown.
   */
  readonly circuit?: ProviderCircuit | ((env: InferenceBindings) => ProviderCircuit);
  /**
   * `AppState::shadow_budget_try_consume`'s ledger. Absent ⇒ built per Worker
   * `env` by `shadow.ts::shadowBudgetFor`: the `SHADOW_BUDGET` Durable Object
   * when it is bound, the per-isolate `ShadowBudgetLedger` otherwise.
   */
  readonly shadowBudget?:
    | AsyncShadowBudgetLedger
    | ((env: InferenceBindings) => AsyncShadowBudgetLedger);
  /**
   * `AppState::provider_routing_metrics` — the latency/failure observations the
   * `lowest_latency` and `balanced` strategies steer on.
   *
   * Absent ⇒ the per-isolate {@link ProviderRoutingMetrics} in `defaults.ts`.
   * Injected by tests so a strategy can be exercised against a known set of
   * observations without driving real dispatches.
   */
  readonly routingMetrics?: RoutingMetrics;
  /**
   * `[[agent_workflows]]` — the graph gate's configuration table
   * (`src/inference/workflow.ts`). Absent ⇒ built per Worker `env`: the
   * `control_plane_resources` documents `apps/control-plane`'s
   * `admin_agent_workflow` group writes into `CONTROL_DB`, with the enabled
   * skill packages' own `resources.agent_workflows` materialised over them.
   */
  readonly workflows?: WorkflowCatalogSource | ((env: InferenceBindings) => WorkflowCatalogSource);
  /**
   * The four run facts the graph gate needs (last successful node, run start,
   * model-call count, token usage) plus the step ledger that produces them.
   * Absent ⇒ the `CONTROL_DB`-backed ledger, or {@link NO_WORKFLOW_HISTORY}
   * when nothing durable is bound.
   */
  readonly workflowHistory?: WorkflowRunHistory | ((env: InferenceBindings) => WorkflowRunHistory);
  /**
   * The clock the workflow timeout is measured against. Absent ⇒ the wall
   * clock. Injected by tests so an elapsed-time refusal is deterministic rather
   * than a sleep.
   */
  readonly nowUnixSeconds?: () => number;
  /**
   * Per-tenant BYOK (issue #682) — the alias store plus the fleet master
   * keyring. Absent ⇒ built per Worker `env` by `byok.ts::byokPortsFromEnv`
   * (CONTROL_DB + FERROGATE_BYOK_MASTER_KEY), and `null` there when the
   * deployment has not enabled BYOK.
   *
   * `null` explicitly turns it OFF even on a deployment that has both bindings,
   * which is what lets a test assert the pre-#682 behaviour is untouched.
   */
  readonly byok?: ByokPorts | ByokPortsFactory | null;
}

/** Fully-populated deps, after `defaults.ts` has filled the blanks. */
export interface ResolvedInferenceDeps {
  readonly models: ModelResolver;
  readonly adapters: AdapterRegistry;
  readonly dispatcher: UpstreamDispatcher;
  readonly usage: UsageSink;
  readonly normalizers: StreamNormalizers;
  readonly translator: AnthropicTranslator;
  readonly requestIds: RequestIdFactory;
  readonly limits: InferenceLimits;
  readonly caller: (request: Request) => Caller;
  readonly reliability: ReliabilitySettings;
  readonly circuit: ProviderCircuit;
  readonly shadowBudget: AsyncShadowBudgetLedger;
  readonly routingMetrics: RoutingMetrics;
  readonly workflows: WorkflowCatalogSource;
  readonly workflowHistory: WorkflowRunHistory;
  readonly nowUnixSeconds: () => number;
  /** `null` = BYOK is not enabled on this deployment. */
  readonly byok: ByokPorts | null;
}
