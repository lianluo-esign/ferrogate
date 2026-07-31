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
  /** Credential scheme; `undefined` = the Rust default for `providerKind`. */
  readonly authScheme?: ProviderAuthScheme | undefined;
  /** `owned_by` in the `/v1/models` listing — the Rust code echoes the provider name. */
  readonly ownedBy?: string | undefined;
  /** `ModelRoute.capabilities`; empty is the legacy capability-neutral case. */
  readonly capabilities?: readonly ModelCapability[] | undefined;
  /** `ModelRoute.region` (issue #173) — `undefined` when the provider declares none. */
  readonly region?: string | undefined;
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
 */
export interface ModelResolver {
  /** Resolve a logical model to the physical route to dispatch on. */
  resolve(model: string): PhysicalRoute | null;
  /** Every configured route, enabled or not — backs `GET /v1/models`. */
  catalog(): readonly PhysicalRoute[];
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

/** Metering sink. `record` is fire-and-forget — it must never throw. */
export interface UsageSink {
  record(u: Usage): void;
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
 * PORT-TODO(ROUTE-MAP invariant 1): bearer authentication and `auth.scope`
 * enforcement belong to the ONE contract-driven middleware that covers all 251
 * operations, not to this module. The inference handlers consume an
 * already-resolved caller and enforce only the two model gates the Rust
 * inference handlers owned: `can_use_model` (403 `model_not_allowed`) and the
 * tenant model-visibility filter on `GET /v1/models` (issue #515).
 */
export interface Caller {
  readonly scope: CallerScope;
  readonly apiKeyId?: string | undefined;
  readonly projectId?: string | undefined;
  /** `AuthContext.allowed_models` — empty/absent means "no allowlist". */
  readonly allowedModels?: readonly string[] | undefined;
  /** `AuthContext.denied_models`. */
  readonly deniedModels?: readonly string[] | undefined;
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
 * PORT-TODO(inventory-request-path §"Cross-crate architecture" step 1): Rust
 * formats a process-wide `AtomicU64` as `fg-{:016x}`. A Worker isolate has no
 * durable counter and is horizontally replicated, so the default implementation
 * keeps the `fg-` + 16 hex-digit shape but sources the digits from
 * `crypto.getRandomValues`. Format-compatible, collision-free across isolates,
 * no longer monotonic.
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
}
