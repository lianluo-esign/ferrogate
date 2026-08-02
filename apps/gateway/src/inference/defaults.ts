/**
 * Runnable in-memory implementations of every port in `ports.ts`.
 *
 * These exist so `apps/gateway` boots, serves, and is testable NOW, before the
 * wave-2 packages (`@ferrogate/routing`, `providers`, `billing`,
 * `observability`, `secrets`) land. Each one is a faithful but minimal stand-in
 * for the corresponding Rust subsystem; none of them is a mock in the test
 * sense — they are the real code paths with an in-memory backing store, exactly
 * as `AppState` is an in-memory snapshot of the config in the Rust tree.
 */
import {
  openAiToAnthropicStream,
  responsesNormalizeStream,
} from "../streaming/index.js";
import type { ResponsesStreamProviderKind } from "../streaming/index.js";
import { canonicalProviderKind, defaultAdapterRegistry } from "./adapters.js";
import { defaultAnthropicTranslator } from "./anthropic.js";
import { audioObjectsFromEnv } from "./audio-objects.js";
import { resolveRetentionSeconds, responseStoreMode } from "./conversation.js";
import { conversationStoreFromEnv } from "./conversation-store.js";
import { byokPortsFromEnv } from "./byok.js";
import { orderCandidates } from "./candidates.js";
import { DurableObjectProviderCircuit } from "./circuit-do.js";
import type { ProviderCircuitNamespace } from "./circuit-do.js";
import {
  DEFAULT_RELIABILITY,
  InMemoryProviderCircuit,
  NO_PROVIDER_CIRCUIT,
  circuitEnabled,
  reliabilityFromVar,
} from "./reliability.js";
import type { ProviderCircuit, ReliabilitySettings } from "./reliability.js";
import { shadowBudgetFor } from "./shadow.js";
import type {
  Caller,
  InferenceBindings,
  InferenceDeps,
  InferenceLimits,
  ModelResolver,
  PhysicalRoute,
  RequestIdFactory,
  ResolvedInferenceDeps,
  StreamNormalizerContext,
  StreamNormalizers,
  UpstreamDispatcher,
  UpstreamRequest,
  Usage,
  UsageSink,
} from "./ports.js";
import { MAX_AUDIO_REFERENCE_BYTES, MAX_AUDIO_UPLOAD_BYTES } from "./schemas.js";
import { ProviderRoutingMetrics } from "./strategy.js";
import type { RoutingMetrics } from "./strategy.js";
import { workflowCatalogFromEnv, workflowHistoryFromEnv } from "./workflow.js";
import { workersAiDispatcherFromEnv } from "./workers-ai.js";
import type { WorkflowGateBindings } from "./workflow.js";

/**
 * `config.limits` defaults.
 *
 * `inferenceBodyMaxBytes` is the Rust `Limits::inference_body_max_bytes()`
 * default of 1 MiB (`ferrogate-config`, asserted at
 * `validation_tests.rs:3144`).
 */
export const DEFAULT_INFERENCE_LIMITS: InferenceLimits = {
  inferenceBodyMaxBytes: 1024 * 1024,
  providerResponseMaxBytes: 8 * 1024 * 1024,
  // Issue #703. Imported rather than re-spelled: the handler enforces this cap
  // and the test suite asserts against the constant, and a second literal here
  // is exactly how a ceiling stops matching the thing that enforces it.
  audioUploadMaxBytes: MAX_AUDIO_UPLOAD_BYTES,
  // Issue #703, the by-reference ceiling. Deliberately LARGER than the inline
  // one and bounded by isolate memory rather than by ingest risk — the object's
  // exact size is known from R2 before a byte is read. See the constant.
  audioReferenceMaxBytes: MAX_AUDIO_REFERENCE_BYTES,
  dispatchTimeoutMs: 120_000,
};

/**
 * `AppState::next_request_id` — see the PORT-TODO on `RequestIdFactory`. Keeps
 * the `fg-` + 16 lowercase hex shape so anything grepping request ids in logs
 * or asserting the format keeps working.
 */
export const defaultRequestIds: RequestIdFactory = {
  next(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    let hex = "";
    for (const byte of bytes) {
      hex += byte.toString(16).padStart(2, "0");
    }
    return `fg-${hex}`;
  },
};

/**
 * In-memory `ModelRegistry`.
 *
 * `resolve` returns `null` for an unknown OR disabled model, matching the port
 * contract; `catalog()` exposes the disabled entries so the handler can tell
 * `model_disabled` from `model_not_found`.
 */
export class InMemoryModelResolver implements ModelResolver {
  readonly #routes: readonly PhysicalRoute[];

  constructor(routes: readonly PhysicalRoute[]) {
    this.#routes = routes;
  }

  resolve(model: string): PhysicalRoute | null {
    return this.#routes.find((route) => route.logicalModel === model && route.enabled) ?? null;
  }

  /**
   * `GET /v1/models` lists ONE entry per logical model.
   *
   * Fallbacks flatten into this table as extra rows sharing a `logicalModel`
   * (`catalog.ts::buildModelCatalog`), so without this dedupe a model with two
   * fallbacks would appear three times in the OpenAI listing — a wire-shape
   * regression a client would see. The entry kept is the first ENABLED row,
   * falling back to the first row of any kind, which is what preserves
   * `model_disabled` (a model whose every route is disabled still appears, with
   * `enabled: false`, so `handlers.ts` can tell it from `model_not_found`).
   */
  catalog(): readonly PhysicalRoute[] {
    const byModel = new Map<string, PhysicalRoute>();
    for (const route of this.#routes) {
      const existing = byModel.get(route.logicalModel);
      if (existing === undefined || (!existing.enabled && route.enabled)) {
        byModel.set(route.logicalModel, route);
      }
    }
    return [...byModel.values()];
  }

  /**
   * `AppState::candidate_model_routes` — every ENABLED route for the logical
   * model, in `orderCandidates` order (priority ascending, then weight
   * descending, then a total tiebreak).
   *
   * Disabled routes are filtered here rather than at ordering time so a
   * fallback an operator switched off can never be reached by failover; that is
   * the same rule `resolve` applies to the primary.
   */
  candidates(model: string): readonly PhysicalRoute[] {
    return orderCandidates(
      this.#routes.filter((route) => route.logicalModel === model && route.enabled),
    );
  }
}

/**
 * `ModelResolver.candidates`, with the single-route fallback.
 *
 * A resolver written before the failover ladder existed implements only
 * `resolve`, and for it the candidate list is exactly the one route it returns
 * — i.e. the pre-wiring behavior, preserved bit for bit. Every resolver this
 * app ships implements `candidates` for real.
 */
export function resolveCandidates(
  models: ModelResolver,
  model: string,
): readonly PhysicalRoute[] {
  if (typeof models.candidates === "function") {
    return models.candidates(model);
  }
  const single = models.resolve(model);
  return single === null ? [] : [single];
}

/**
 * Build the {@link ProviderCircuit} for a Worker `env`.
 *
 * Three-way, and the ORDER is the whole contract:
 *
 *  1. breaker not configured (`circuitEnabled` false — Rust's
 *     `provider_circuit_config == None`) ⇒ {@link NO_PROVIDER_CIRCUIT}. This is
 *     the default, so wiring the ladder changes no deployed behavior until an
 *     operator sets `GATEWAY_RELIABILITY`.
 *  2. `PROVIDER_CIRCUIT` bound ⇒ the Durable Object, which is the only
 *     cross-isolate answer (see `./circuit-do.ts`).
 *  3. otherwise ⇒ {@link InMemoryProviderCircuit}, the per-isolate
 *     approximation, marked PORT-TODO on the class itself.
 *
 * A configured breaker with no binding must NOT silently do nothing: shedding
 * late is much better than never shedding, and arm 3 is what makes the config
 * var meaningful before the DO lands.
 */
export function providerCircuitFor(
  settings: ReliabilitySettings,
  env: InferenceBindings,
): ProviderCircuit {
  if (!circuitEnabled(settings)) {
    return NO_PROVIDER_CIRCUIT;
  }
  const namespace = env["PROVIDER_CIRCUIT"];
  if (
    typeof namespace === "object" &&
    namespace !== null &&
    typeof (namespace as ProviderCircuitNamespace).idFromName === "function"
  ) {
    return new DurableObjectProviderCircuit(namespace as ProviderCircuitNamespace, settings);
  }
  return new InMemoryProviderCircuit(settings);
}

/**
 * `AppState::provider_routing_metrics` — the isolate's own observations.
 *
 * Rust holds one `Arc<Mutex<ProviderRoutingMetrics>>` per process and carries it
 * across config reloads (`state.rs:4914` explicitly clones the Arc into the next
 * state rather than starting fresh, so a hot reload does not blind the router).
 * The Workers equivalent of "for the life of the process" is module scope, so
 * this is a module-scope singleton and it survives every per-request `resolveDeps`
 * for the same reason.
 *
 * See `strategy.ts` for why per-isolate is the honest ceiling here and why the
 * error direction is "reacts later", never "reacts wrongly".
 */
export const isolateRoutingMetrics: RoutingMetrics = new ProviderRoutingMetrics();

/** An empty registry — every model resolves to `model_not_found` (400). */
export const emptyModelResolver: ModelResolver = new InMemoryModelResolver([]);

/**
 * `ferrogate_billing::InMemoryBillingEventSink`. `record` must never throw:
 * metering is best-effort relative to serving the response, and a sink failure
 * in Rust was logged, never surfaced to the caller.
 */
export class InMemoryUsageSink implements UsageSink {
  readonly #records: Usage[] = [];

  record(u: Usage): void {
    this.#records.push(u);
  }

  /** Everything recorded so far, in order. */
  get records(): readonly Usage[] {
    return this.#records;
  }

  /** The most recent record, or `undefined`. */
  get last(): Usage | undefined {
    return this.#records.at(-1);
  }

  clear(): void {
    this.#records.length = 0;
  }
}

/**
 * `server/dispatch.rs::dispatch_provider_{,streaming_}request` over the Workers
 * `fetch`.
 *
 * Parity points with the Rust `provider_http_client`:
 *  - `redirect: "manual"` reproduces `Policy::none()`; a provider that 3xx's is
 *    surfaced as-is rather than silently followed to another origin (that was a
 *    deliberate SSRF-ish guard, not an oversight);
 *  - no `Accept-Encoding` negotiation is requested (the Rust client disabled
 *    gzip/brotli/zstd/deflate) so an SSE body is never transparently recoded;
 *  - a transport failure THROWS, which the handler maps to 502
 *    `provider_dispatch_error`.
 *
 * `globalThis.fetch` is read at call time, not captured at module load, so a
 * test may stub it (see `test/inference/provider-mock.ts`).
 */
export const fetchDispatcher: UpstreamDispatcher = {
  async dispatch(request: UpstreamRequest, signal?: AbortSignal): Promise<Response> {
    const init: RequestInit = {
      method: request.method,
      headers: { ...request.headers },
      redirect: "manual",
      ...(signal !== undefined ? { signal } : {}),
    };
    if (request.method !== "GET" && request.body !== undefined) {
      // `FormData` (issue #703) is handed to `fetch` UNTOUCHED, and the
      // `content-type` header the adapter deliberately omitted is what makes
      // that work: `fetch` writes `multipart/form-data; boundary=...` itself,
      // with the boundary it will actually use to serialize the parts. A
      // hand-written header would name a boundary that does not appear in the
      // bytes and every upstream would answer 400.
      init.body = request.body instanceof FormData ? request.body : JSON.stringify(request.body);
    }
    return await globalThis.fetch(request.endpoint, init);
  },
};

/**
 * Byte-for-byte passthrough for every dialect.
 *
 * Kept as a named export because it is the correct normalizer whenever the
 * upstream already speaks the ingress dialect, and because a test that wants to
 * assert raw relaying can inject it explicitly.
 */
/**
 * The deployed egress: {@link fetchDispatcher} for the eight network families,
 * short-circuited through `env.AI` for the ninth (issue #673).
 *
 * A factory because bindings are per request while `InferenceDeps` is built
 * once per router — `resolveDeps` calls this once per `env` object.
 */
export function dispatcherFromEnv(env: InferenceBindings): UpstreamDispatcher {
  return workersAiDispatcherFromEnv(env, fetchDispatcher);
}

export const passthroughNormalizers: StreamNormalizers = {
  normalizerFor(): TransformStream<Uint8Array, Uint8Array> | null {
    return null;
  },
};

/**
 * `ResponsesStreamProviderKind` — the discriminator the Responses normalizer
 * uses to read the upstream's native usage/delta shapes.
 */
function responsesProviderKind(providerKind: string): ResponsesStreamProviderKind {
  const canonical = canonicalProviderKind(providerKind);
  switch (canonical) {
    case "anthropic":
      return "anthropic";
    case "gemini":
      return "gemini";
    case "openai-compatible":
    case "grok":
    case "openrouter":
    case "azure-openai":
      return "openai_compatible";
    default:
      return "other";
  }
}

/**
 * The real normalizer tower (`inventory-request-path.md` §1.5), backed by
 * `apps/gateway/src/streaming/` — the `TransformStream` port of
 * `messages_stream.rs` and `responses_stream.rs`.
 *
 *  - `anthropic.messages` on a NON-Anthropic upstream → `openAiToAnthropicStream`
 *    (`MessagesStreamNormalizer`: `message_start` / `content_block_start|delta|
 *    stop` / `message_delta` / `message_stop`, with tool-call accumulation).
 *  - `openai.responses` on ANY upstream → `responsesNormalizeStream`
 *    (`ResponsesStreamNormalizer`: the `response.*` event sequence). This runs
 *    even for an OpenAI upstream because the Rust tree normalized the Responses
 *    stream unconditionally — and metering depends on it, since the usage
 *    extractor for `/v1/responses` reads the NORMALIZED shape (`chat.rs:1012`).
 *  - everything else → `null`, i.e. byte-for-byte passthrough.
 */
export const defaultStreamNormalizers: StreamNormalizers = {
  normalizerFor(
    context: StreamNormalizerContext,
  ): TransformStream<Uint8Array, Uint8Array> | null {
    switch (context.dialect) {
      case "anthropic.messages":
        return canonicalProviderKind(context.providerKind) === "anthropic"
          ? null
          : openAiToAnthropicStream({ fallbackModel: context.logicalModel });
      case "openai.responses":
        return responsesNormalizeStream({
          providerKind: responsesProviderKind(context.providerKind),
          requestId: context.requestId,
          contentType: context.contentType,
        });
      case "openai.chat":
        return null;
    }
  },
};

/**
 * The caller used until the contract-driven auth middleware lands.
 *
 * A platform operator with no model allow/deny list — i.e. every gate this
 * module owns is open, and nothing is *silently* enforced against an identity
 * that was never resolved. Authentication itself (401/403, scopes,
 * `auth.kind`) is NOT this module's job; see the PORT-TODO on `Caller`.
 */
export const platformOperatorCaller: Caller = { scope: { kind: "platform_operator" } };

/** Default caller resolver: ignores the request, returns the operator caller. */
export function defaultCallerResolver(): Caller {
  return platformOperatorCaller;
}

/**
 * Fill every unset dependency with its default.
 *
 * `env` is the Worker bindings object. It is only consulted for a `models`
 * dependency supplied as a {@link ModelResolverFactory} — the env-backed model
 * registry cannot be built at module scope because bindings are per request, so
 * the composition root injects the factory and the router calls this once per
 * env object. An explicitly injected `ModelResolver` always wins, which is what
 * keeps every existing test independent of the environment.
 */
export function resolveDeps(
  deps: InferenceDeps = {},
  env: InferenceBindings = {},
): ResolvedInferenceDeps {
  const models = typeof deps.models === "function" ? deps.models(env) : deps.models;
  // An INJECTED partial always wins over the var, so a test that asks for a
  // threshold of 2 gets 2 whatever the deployment configured.
  const reliability: ReliabilitySettings = {
    ...reliabilityFromVar(env["GATEWAY_RELIABILITY"]),
    ...deps.reliability,
  };
  const circuit =
    typeof deps.circuit === "function"
      ? deps.circuit(env)
      : (deps.circuit ?? providerCircuitFor(reliability, env));
  return {
    models: models ?? emptyModelResolver,
    adapters: deps.adapters ?? defaultAdapterRegistry,
    // Env-resolved like `circuit`: `dispatcherFromEnv` wraps `fetchDispatcher`
    // so a `workers-ai` route is served by the `AI` binding (no egress) while
    // every other family still goes out over `fetch` (issue #673). An injected
    // dispatcher — value or factory — always wins, which keeps every existing
    // test that stubs the egress independent of the environment.
    dispatcher:
      typeof deps.dispatcher === "function"
        ? deps.dispatcher(env)
        : (deps.dispatcher ?? dispatcherFromEnv(env)),
    usage: deps.usage ?? new InMemoryUsageSink(),
    normalizers: deps.normalizers ?? defaultStreamNormalizers,
    translator: deps.translator ?? defaultAnthropicTranslator,
    requestIds: deps.requestIds ?? defaultRequestIds,
    limits: { ...DEFAULT_INFERENCE_LIMITS, ...deps.limits },
    caller: deps.caller ?? defaultCallerResolver,
    reliability,
    circuit,
    // Same env-resolved shape as `circuit`: the `SHADOW_BUDGET` Durable Object
    // when it is bound, the per-isolate ledger otherwise. Resolved here rather
    // than at the mirror's dispatch site so the choice is made once per env,
    // not once per mirrored request.
    shadowBudget:
      typeof deps.shadowBudget === "function"
        ? deps.shadowBudget(env)
        : (deps.shadowBudget ?? shadowBudgetFor(env)),
    // The default is the ISOLATE-WIDE singleton, not a per-request instance:
    // `lowest_latency` / `balanced` steer on observations accumulated ACROSS
    // requests, so a fresh recorder per request would record diligently and
    // score every provider `NO_ROUTING_OBSERVATIONS` forever — a metric with no
    // reader, which is the exact defect shape this wave exists to remove.
    routingMetrics: deps.routingMetrics ?? isolateRoutingMetrics,
    // The workflow GRAPH gate (certification finding D2). Env-resolved like
    // `circuit` and `shadowBudget`, and DEFAULT-ON: with `CONTROL_DB` bound the
    // gate reads the admin `agent-workflows` documents, with only
    // `GATEWAY_SKILL_PACKAGES` set it reads the packages' own workflows, and
    // with neither it gates nothing — which is the behaviour of a deployment
    // that has declared no workflows, not a switch an operator can flip.
    workflows:
      typeof deps.workflows === "function"
        ? deps.workflows(env)
        : (deps.workflows ?? workflowCatalogFromEnv(env as WorkflowGateBindings)),
    workflowHistory:
      typeof deps.workflowHistory === "function"
        ? deps.workflowHistory(env)
        : (deps.workflowHistory ?? workflowHistoryFromEnv(env as WorkflowGateBindings)),
    nowUnixSeconds: deps.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000)),
    // Per-tenant BYOK (issue #682). Env-resolved like `circuit`, and DEFAULT-ON
    // in the sense that a deployment with CONTROL_DB and a master key bound gets
    // it without a switch — `byokPortsFromEnv` returns `null` when either is
    // absent, so a deployment that has not opted in is byte-for-byte unchanged.
    // An explicit `null` turns it off even where it could be built, which is
    // what lets a test pin the pre-#682 behaviour.
    byok:
      deps.byok === undefined
        ? byokPortsFromEnv(env)
        : typeof deps.byok === "function"
          ? deps.byok(env)
          : deps.byok,
    // Issue #703. Env-resolved like `circuit`: the SAME R2 bucket and the SAME
    // tenant database `/v1/assets/**` already uses, so a deployment that can
    // publish a recording can transcribe it with no further configuration —
    // and one that binds neither gets `NO_AUDIO_OBJECTS`, which refuses a
    // `file_ref` with 503 rather than pretending the request was malformed.
    audioObjects:
      typeof deps.audioObjects === "function"
        ? deps.audioObjects(env)
        : (deps.audioObjects ?? audioObjectsFromEnv(env as Record<string, unknown>)),
    // Issue #689. Env-resolved like `audioObjects`, and fail-CLOSED in the same
    // shape: a deployment that binds no tenant database gets
    // `NO_CONVERSATION_STORE`, which makes `store: true` and
    // `previous_response_id` answer 503 `response_store_disabled` rather than
    // being accepted and forgotten. Every OTHER `/v1/responses` request on such
    // a deployment is served exactly as it was before this slice.
    conversations:
      typeof deps.conversations === "function"
        ? deps.conversations(env)
        : (deps.conversations ?? conversationStoreFromEnv(env)),
    responseStoreMode: deps.responseStoreMode ?? responseStoreMode(env["GATEWAY_RESPONSES_STORE"]),
    responseRetentionSeconds:
      deps.responseRetentionSeconds ??
      ((tenantId: string) =>
        resolveRetentionSeconds(env["GATEWAY_RESPONSES_RETENTION"], tenantId)),
  };
}
