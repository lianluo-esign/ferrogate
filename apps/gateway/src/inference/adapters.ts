/**
 * Default `ProviderAdapter` implementations.
 *
 * Clean-room port of `ferrogate-providers/src/openai.rs` and
 * `ferrogate-providers/src/anthropic.rs`, plus the family/alias table from
 * `types.rs` (`SUPPORTED_PROVIDER_ADAPTER_FAMILIES`).
 *
 * The Rust crate ships eight families (openai-compatible, anthropic, gemini,
 * grok, openrouter, azure-openai, bedrock, vertex). Two are implemented here —
 * the two the whole request path is defined against, and the only two needed to
 * exercise every ingress: OpenAI-compatible covers chat/responses/embeddings/
 * images/catalog, Anthropic covers the `/v1/messages` round trip.
 *
 * PORT-TODO(inventory-request-path §3): gemini, grok, openrouter, azure-openai,
 * bedrock (SigV4 — must be byte-exact, incl. the streaming content-hash
 * variant) and vertex belong in `@ferrogate/providers`. Until they land,
 * `defaultAdapterRegistry` resolves their aliases to `null`, which the handler
 * renders as the Rust `unsupported provider kind <kind>` message rather than
 * silently dispatching an unsigned/unsupported request. Grok/OpenRouter/Azure
 * are OpenAI-compatible on the wire, but they each add required headers
 * (`HTTP-Referer`/`X-Title`, `api-key`, `api-version`), so aliasing them onto
 * the plain OpenAI adapter here would ship a subtly wrong request — failing
 * closed is the faithful behavior.
 */
import type {
  AdapterRegistry,
  AdapterResult,
  ProviderAdapter,
  UpstreamPlan,
  UpstreamRequest,
} from "./ports.js";

/** `ProviderConfig.base_url` join — Rust `format!("{}/x", base.trim_end_matches('/'))`. */
function endpoint(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, "")}${path}`;
}

/** `ensure_labeled_object_body`. */
function ensureObjectBody(plan: UpstreamPlan, label: string): AdapterResult | null {
  if (typeof plan.body === "object" && plan.body !== null && !Array.isArray(plan.body)) {
    return null;
  }
  return {
    ok: false,
    error: { kind: "invalid_request", message: `${label} must be a JSON object` },
  };
}

/**
 * `request_openai_stream_usage` — force `stream_options.include_usage = true` so
 * the final SSE frame carries the token counts the meter scrapes
 * (`StreamingUsageCapture`). A caller-supplied non-object `stream_options` is
 * replaced, exactly as the Rust code does.
 */
function requestOpenAiStreamUsage(body: Record<string, unknown>): void {
  const existing = body["stream_options"];
  const options =
    typeof existing === "object" && existing !== null && !Array.isArray(existing)
      ? (existing as Record<string, unknown>)
      : {};
  options["include_usage"] = true;
  body["stream_options"] = options;
}

/** `provider_headers` — content-type always, bearer only when a key is set. */
function openAiHeaders(apiKey: string | undefined): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (apiKey !== undefined && apiKey.trim().length > 0) {
    headers["authorization"] = `Bearer ${apiKey}`;
  }
  return headers;
}

/** `anthropic_headers`. `anthropic-version` is pinned exactly as in Rust. */
function anthropicHeaders(apiKey: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
  };
  if (apiKey !== undefined && apiKey.trim().length > 0) {
    headers["x-api-key"] = apiKey;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Family / alias table — `SUPPORTED_PROVIDER_ADAPTER_FAMILIES`
// ---------------------------------------------------------------------------

/** `ProviderAdapterFamily` canonical kind → its accepted aliases. */
export const PROVIDER_ADAPTER_FAMILIES: ReadonlyArray<{
  readonly canonicalKind: string;
  readonly aliases: readonly string[];
}> = [
  {
    canonicalKind: "openai-compatible",
    aliases: [
      "openai",
      "deepseek",
      "newapi",
      "sub2api",
      "cliproxyapi",
      "cli-proxy-api",
      "vllm",
      "llama.cpp",
      "llama-cpp",
      "llamacpp",
      "tgi",
      "ollama",
      "ollama-compatible",
    ],
  },
  { canonicalKind: "anthropic", aliases: [] },
  { canonicalKind: "gemini", aliases: [] },
  { canonicalKind: "grok", aliases: ["xai"] },
  { canonicalKind: "openrouter", aliases: [] },
  { canonicalKind: "azure-openai", aliases: ["azure"] },
  { canonicalKind: "bedrock", aliases: ["aws-bedrock"] },
  { canonicalKind: "vertex", aliases: ["vertex-ai"] },
];

/** `canonical_provider_adapter_family` — trimmed, ASCII-case-insensitive. */
export function canonicalProviderKind(kind: string): string | null {
  const needle = kind.trim().toLowerCase();
  for (const family of PROVIDER_ADAPTER_FAMILIES) {
    if (
      family.canonicalKind.toLowerCase() === needle ||
      family.aliases.some((alias) => alias.toLowerCase() === needle)
    ) {
      return family.canonicalKind;
    }
  }
  return null;
}

/** `is_openai_compatible_provider_kind`. */
export function isOpenAiCompatibleKind(kind: string): boolean {
  return canonicalProviderKind(kind) === "openai-compatible";
}

// ---------------------------------------------------------------------------
// OpenAI-compatible adapter
// ---------------------------------------------------------------------------

export const openAiCompatibleAdapter: ProviderAdapter = {
  kind: "openai-compatible",

  buildUpstreamRequest(plan: UpstreamPlan): AdapterResult {
    if (!isOpenAiCompatibleKind(plan.route.providerKind)) {
      return {
        ok: false,
        error: {
          kind: "unsupported_provider_kind",
          providerKind: plan.route.providerKind.trim().toLowerCase(),
        },
      };
    }

    const label = {
      "chat.completions": "chat completion request body",
      responses: "responses request body",
      embeddings: "embeddings request body",
      images: "image generation request body",
      model_catalog: "model catalog request body",
    }[plan.operation];
    const invalid = ensureObjectBody(plan, label);
    if (invalid !== null) {
      return invalid;
    }

    const body: Record<string, unknown> = { ...plan.body };
    // The adapter OWNS these two fields — a caller cannot pin the physical model
    // or contradict the resolved stream decision.
    body["model"] = plan.providerModel;

    const headers = openAiHeaders(plan.route.apiKey);
    const base: Omit<UpstreamRequest, "endpoint" | "body" | "stream"> = {
      provider: plan.route.provider,
      method: "POST",
      headers,
    };

    switch (plan.operation) {
      case "chat.completions": {
        body["stream"] = plan.stream;
        if (plan.stream) {
          requestOpenAiStreamUsage(body);
        }
        return {
          ok: true,
          request: {
            ...base,
            endpoint: endpoint(plan.route.baseUrl, "/chat/completions"),
            body,
            stream: plan.stream,
          },
        };
      }
      case "responses": {
        // NOTE: `prepare_responses` deliberately does NOT inject
        // `stream_options.include_usage` — the Responses API reports usage on
        // its own `response.completed` event.
        body["stream"] = plan.stream;
        return {
          ok: true,
          request: {
            ...base,
            endpoint: endpoint(plan.route.baseUrl, "/responses"),
            body,
            stream: plan.stream,
          },
        };
      }
      case "embeddings":
        return {
          ok: true,
          request: {
            ...base,
            endpoint: endpoint(plan.route.baseUrl, "/embeddings"),
            body,
            stream: false,
          },
        };
      case "images":
        return {
          ok: true,
          request: {
            ...base,
            endpoint: endpoint(plan.route.baseUrl, "/images/generations"),
            body,
            stream: false,
          },
        };
      case "model_catalog":
        return {
          ok: true,
          request: {
            ...base,
            method: "GET",
            endpoint: endpoint(plan.route.baseUrl, "/models"),
            body: undefined,
            stream: false,
          },
        };
    }
  },
};

// ---------------------------------------------------------------------------
// Anthropic adapter
// ---------------------------------------------------------------------------

export const anthropicAdapter: ProviderAdapter = {
  kind: "anthropic",

  buildUpstreamRequest(plan: UpstreamPlan): AdapterResult {
    if (plan.route.providerKind !== "anthropic") {
      return {
        ok: false,
        error: {
          kind: "unsupported_provider_kind",
          providerKind: plan.route.providerKind,
        },
      };
    }

    // `prepare_embeddings` / `prepare_images` are not overridden by the Rust
    // Anthropic adapter, so they fall through to the trait defaults: an unknown
    // provider kind for embeddings, and an explicit capability error for images
    // (issue #275 — only the OpenAI-compatible family exposes image generation).
    if (plan.operation === "embeddings" || plan.operation === "model_catalog") {
      return { ok: false, error: { kind: "unsupported_provider_kind", providerKind: "anthropic" } };
    }
    if (plan.operation === "images") {
      return {
        ok: false,
        error: {
          kind: "unsupported_capability",
          capability: "image generation",
          providerKind: "anthropic",
        },
      };
    }

    const invalid = ensureObjectBody(plan, "chat completion request body");
    if (invalid !== null) {
      return invalid;
    }

    // Anthropic's Messages API is not a superset of the OpenAI body: the adapter
    // rebuilds a minimal native body rather than forwarding unknown members,
    // because Anthropic rejects unknown top-level fields. `max_tokens` is
    // REQUIRED there, hence the 1024 default when the caller omitted it.
    const source = plan.body;
    const anthropicBody: Record<string, unknown> = {
      model: plan.providerModel,
      messages: source["messages"] ?? [],
      max_tokens: source["max_tokens"] ?? 1024,
      stream: plan.stream,
    };
    if (source["system"] !== undefined) {
      anthropicBody["system"] = source["system"];
    }
    if (plan.operation === "responses") {
      // `prepare_responses` additionally forwards the canonicalized tool fields.
      if (source["tools"] !== undefined) {
        anthropicBody["tools"] = source["tools"];
      }
      if (source["tool_choice"] !== undefined) {
        anthropicBody["tool_choice"] = source["tool_choice"];
      }
    }

    return {
      ok: true,
      request: {
        provider: plan.route.provider,
        method: "POST",
        endpoint: endpoint(plan.route.baseUrl, "/messages"),
        headers: anthropicHeaders(plan.route.apiKey),
        body: anthropicBody,
        stream: plan.stream,
      },
    };
  },
};

/** `ferrogate_providers::registry` — kind → adapter, alias-aware. */
export const defaultAdapterRegistry: AdapterRegistry = {
  adapterFor(providerKind: string): ProviderAdapter | null {
    const canonical = canonicalProviderKind(providerKind);
    switch (canonical) {
      case "openai-compatible":
        return openAiCompatibleAdapter;
      case "anthropic":
        return anthropicAdapter;
      default:
        // See the PORT-TODO at the top of this file: an unported family fails
        // closed rather than being aliased onto a wire-compatible neighbour.
        return null;
    }
  },
};
