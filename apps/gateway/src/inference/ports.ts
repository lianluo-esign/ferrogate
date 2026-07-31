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
import type { ProviderCircuit, ReliabilitySettings } from "./reliability.js";

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
   * `ProviderConfig.aws_credentials` — required by the `bedrock` family and
   * unread by every other one. Absent for a Bedrock route means the adapter
   * fails closed at request-preparation time rather than sending an unsigned
   * request, which is the Rust fail-closed shape.
   */
  readonly awsCredentials?: AwsRouteCredentials | undefined;
  /** `ProviderConfig.gcp_credentials` — the `vertex` family's equivalent. */
  readonly gcpCredentials?: GcpRouteCredentials | undefined;
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
 * PORT-TODO(`src/metering/event.ts` `SINGLE_PROVIDER_ATTEMPT_INDEX`): the
 * provider ATTEMPT INDEX is not yet threaded onto {@link Usage}. The ladder can
 * now make more than one attempt per request, and the metering event's
 * `ledgerEntryId` is derived without it, so two attempts of one request would
 * collapse onto one ledger row and the second be absorbed by `ON CONFLICT DO
 * NOTHING` as a silent under-bill. Today that is latent rather than live —
 * usage is recorded exactly once, from the attempt that actually produced the
 * served response, and abandoned attempts are never metered — but the moment a
 * failed attempt is metered (for provider-cost attribution) the index has to
 * land with it. The fix is in `src/metering/`, which this slice does not own.
 *
 * PORT-TODO(state_routing.rs:517, F6): `RoutingStrategy::{LowestCost,
 * LowestLatency,Balanced}` and the weighted round-robin WITHIN a priority group
 * are still unported; `candidates.ts::orderCandidates` implements the
 * priority→weight ORDERING only. See the marker on that function.
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
  /** `/v1/images/generations` settles on the image count, not tokens (issue #275). */
  readonly imageCount?: number | undefined;
  /** Caller-supplied request tags (issue #171), already bounds-checked. */
  readonly metadata?: Readonly<Record<string, string>> | undefined;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
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
 * enforcement belong to the ONE contract-driven middleware that covers all 251
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
 * `allowedModels`/`deniedModels` are still never populated from a real
 * credential; see the PORT-TODO on `callerFromAuth`, which names the exact
 * `src/ports.ts` change (that file is the composition root's, not this
 * slice's).
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
 * PORT-TODO(inventory-request-path §"Cross-crate architecture" step 1):
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
  readonly dispatcher?: UpstreamDispatcher;
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
}
