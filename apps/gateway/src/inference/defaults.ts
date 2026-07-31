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
import type {
  Caller,
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

  catalog(): readonly PhysicalRoute[] {
    return this.#routes;
  }
}

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
      init.body = JSON.stringify(request.body);
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

/** Fill every unset dependency with its default. */
export function resolveDeps(deps: InferenceDeps = {}): ResolvedInferenceDeps {
  return {
    models: deps.models ?? emptyModelResolver,
    adapters: deps.adapters ?? defaultAdapterRegistry,
    dispatcher: deps.dispatcher ?? fetchDispatcher,
    usage: deps.usage ?? new InMemoryUsageSink(),
    normalizers: deps.normalizers ?? defaultStreamNormalizers,
    translator: deps.translator ?? defaultAnthropicTranslator,
    requestIds: deps.requestIds ?? defaultRequestIds,
    limits: { ...DEFAULT_INFERENCE_LIMITS, ...deps.limits },
    caller: deps.caller ?? defaultCallerResolver,
  };
}
