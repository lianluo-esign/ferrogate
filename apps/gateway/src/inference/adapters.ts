/**
 * Default `ProviderAdapter` implementations.
 *
 * Clean-room port of `ferrogate-providers/src/openai.rs` and
 * `ferrogate-providers/src/anthropic.rs`, plus the family/alias table from
 * `types.rs` (`SUPPORTED_PROVIDER_ADAPTER_FAMILIES`).
 *
 * The Rust crate ships eight families (openai-compatible, anthropic, gemini,
 * grok, openrouter, azure-openai, bedrock, vertex). FIVE are re-written here:
 * OpenAI-compatible (chat/responses/embeddings/images/catalog), Anthropic (the
 * `/v1/messages` round trip), and the three families that are OpenAI-compatible
 * on the wire — Grok (`grok.rs`), OpenRouter (`openrouter.rs`) and Azure OpenAI
 * (`azure.rs`). The last three are ports of real Rust adapters, not aliases:
 * each one adds or removes something the plain OpenAI request would get wrong
 * (OpenRouter strips `stream_options` and adds `http-referer`/`x-title`; Azure
 * drops `model` from the body entirely, addresses a DEPLOYMENT in the path and
 * authenticates with `api-key`), which is precisely why aliasing them was
 * refused before they were ported.
 *
 * ALL EIGHT families are resolvable. The other three — `gemini`, `bedrock` and
 * `vertex` — are not re-written here: they are `@ferrogate/providers`'
 * `GeminiAdapter`, `BedrockAdapter` (SigV4) and `VertexAiAdapter` (a pre-minted
 * GCP OAuth2 access token), the ports of `gemini.rs` / `bedrock.rs` /
 * `vertex.rs`, wire grammar and all, reached through
 * {@link packageProviderAdapter} — which is the same crate boundary the Rust
 * has. Writing a second translation for any of them in this file would be the
 * duplication the port rules forbid.
 *
 * Bedrock and Vertex needed a COMPOSITE credential rather than the single
 * opaque `apiKey` string every other family carries, which is the only reason
 * they were unresolvable: `PhysicalRoute` now carries `awsCredentials` /
 * `gcpCredentials` (`./ports.ts`) and the provider table carries the Rust
 * config's `aws_access_key_id` / `aws_secret_access_key_env` /
 * `aws_session_token_env` / `gcp_project_id` / `gcp_access_token_env` /
 * `region` fields, with `_env` becoming `_var` because a Worker names a SECRET
 * BINDING where a process names an environment variable (`catalog.ts`). A route
 * that reaches either adapter without its credential is refused by the adapter
 * (`AdapterError::InvalidRequest`), and a provider table that declares such a
 * provider without one is refused WHOLE by `buildModelCatalog` — the Worker
 * equivalent of the Rust config validator's refusal to boot.
 */
import {
  BedrockAdapter,
  GeminiAdapter,
  AdapterError as PackageAdapterError,
  SecretValue,
  VertexAiAdapter,
} from "@ferrogate/providers";
import type {
  Json,
  ProviderAdapter as PackageProviderAdapter,
  ProviderConfig as PackageProviderConfig,
  ProviderHeader as PackageProviderHeader,
} from "@ferrogate/providers";
import type {
  AdapterError,
  AdapterRegistry,
  AdapterResult,
  PhysicalRoute,
  ProviderAdapter,
  ProviderAuthScheme,
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

/**
 * Write the credential header for `scheme`. No key ⇒ no header at all, which is
 * the Rust behavior (`api_key.filter(|value| !value.trim().is_empty())`) and is
 * what lets an unauthenticated local upstream be pointed at without a secret.
 */
function credentialHeader(
  headers: Record<string, string>,
  apiKey: string | undefined,
  scheme: ProviderAuthScheme,
): void {
  if (apiKey === undefined || apiKey.trim().length === 0) {
    return;
  }
  if (scheme === "bearer") {
    headers["authorization"] = `Bearer ${apiKey}`;
  } else {
    headers["x-api-key"] = apiKey;
  }
}

/**
 * The credential scheme a family uses when the provider table does not say.
 *
 * These two values ARE the Rust hard-codings: `openai.rs::provider_headers`
 * writes `Authorization: Bearer`, `anthropic.rs::anthropic_headers` writes
 * `x-api-key`. A route with no `auth_scheme` is therefore byte-identical to the
 * Rust request.
 */
export function defaultAuthScheme(providerKind: string): ProviderAuthScheme {
  return canonicalProviderKind(providerKind) === "anthropic" ? "x-api-key" : "bearer";
}

/** `provider_headers` — content-type always, credential only when a key is set. */
function openAiHeaders(
  apiKey: string | undefined,
  scheme: ProviderAuthScheme = "bearer",
): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  credentialHeader(headers, apiKey, scheme);
  return headers;
}

/** `anthropic_headers`. `anthropic-version` is pinned exactly as in Rust. */
function anthropicHeaders(
  apiKey: string | undefined,
  scheme: ProviderAuthScheme = "x-api-key",
): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
  };
  credentialHeader(headers, apiKey, scheme);
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

    const headers = openAiHeaders(plan.route.apiKey, plan.route.authScheme ?? "bearer");
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
        headers: anthropicHeaders(plan.route.apiKey, plan.route.authScheme ?? "x-api-key"),
        body: anthropicBody,
        stream: plan.stream,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// The three OpenAI-compatible-on-the-wire families
// ---------------------------------------------------------------------------

/**
 * Re-point a plan at the OpenAI-compatible adapter.
 *
 * `GrokAdapter`/`OpenRouterAdapter` both do `provider.kind = "openai-compatible"`
 * before delegating, which is what makes `OpenAiCompatibleAdapter::validate_kind`
 * accept the call. `provider.name` is deliberately untouched: it is the label
 * that reaches metering, so a Grok route still meters as its own provider.
 */
function asOpenAiCompatible(plan: UpstreamPlan): UpstreamPlan {
  return { ...plan, route: { ...plan.route, providerKind: "openai-compatible" } };
}

/**
 * The Rust `validate_kind` of the delegating families.
 *
 * Note the asymmetry with `openai.rs::validate_kind`, which goes through
 * `is_openai_compatible_provider_kind` (trimmed, ASCII-case-insensitive):
 * `grok.rs`, `openrouter.rs` and `azure.rs` match the RAW string exactly, and
 * report the RAW string back. A `kind = "Grok"` therefore resolves to the Grok
 * adapter through the case-insensitive registry and is then refused by the
 * adapter itself. That is a quirk of the Rust tree, reproduced verbatim rather
 * than quietly "fixed" — changing it is a behavior change that belongs with the
 * `@ferrogate/providers` port, where the Rust tests move too.
 */
function validateExactKind(providerKind: string, accepted: readonly string[]): AdapterResult | null {
  return accepted.includes(providerKind)
    ? null
    : { ok: false, error: { kind: "unsupported_provider_kind", providerKind } };
}

/** `ProviderAdapter` trait default for `prepare_images` (issue #275). */
function imagesUnsupported(kind: string): AdapterResult {
  return {
    ok: false,
    error: { kind: "unsupported_capability", capability: "image generation", providerKind: kind },
  };
}

/** `ProviderAdapter` trait default for the `prepare_*` methods a family omits. */
function operationUnsupported(kind: string): AdapterResult {
  return { ok: false, error: { kind: "unsupported_provider_kind", providerKind: kind } };
}

/**
 * `ferrogate-providers/src/grok.rs::GrokAdapter`.
 *
 * A pure delegation: xAI's API is OpenAI's. Grok overrides only
 * `prepare_chat_completions` and `prepare_responses`, so embeddings and the
 * model catalog fall through to the trait default (`unsupported_provider_kind`)
 * and images to `unsupported_capability`.
 */
export const grokAdapter: ProviderAdapter = {
  kind: "grok",

  buildUpstreamRequest(plan: UpstreamPlan): AdapterResult {
    const invalidKind = validateExactKind(plan.route.providerKind, ["grok", "xai"]);
    if (invalidKind !== null) {
      return invalidKind;
    }
    switch (plan.operation) {
      case "chat.completions":
      case "responses":
        return openAiCompatibleAdapter.buildUpstreamRequest(asOpenAiCompatible(plan));
      case "images":
        return imagesUnsupported("grok");
      case "embeddings":
      case "model_catalog":
        return operationUnsupported("grok");
    }
  },
};

/**
 * The two optional OpenRouter attribution headers.
 *
 * `ProviderConfig` carries `openrouter_http_referer` / `openrouter_x_title` in
 * Rust. `PhysicalRoute` (in `ports.ts`, which this slice may not edit) has no
 * field for them, so they ride as a structural EXTENSION that
 * `buildModelCatalog` populates and every other consumer ignores. Promote them
 * onto `PhysicalRoute` proper the next time `ports.ts` is opened.
 */
export interface OpenRouterProviderExtras {
  /** `ProviderConfig.openrouter_http_referer` → the `http-referer` header. */
  readonly openrouterHttpReferer?: string | undefined;
  /** `ProviderConfig.openrouter_x_title` → the `x-title` header. */
  readonly openrouterXTitle?: string | undefined;
}

/** A route that may carry the OpenRouter attribution fields. */
export type OpenRouterRoute = PhysicalRoute & OpenRouterProviderExtras;

/** `openrouter.rs::non_empty_header_value` — trimmed, empty dropped. */
function nonEmptyHeaderValue(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

/** `openrouter.rs::openrouter_headers`. */
function openRouterHeaders(route: OpenRouterRoute): Record<string, string> {
  const headers: Record<string, string> = {};
  const referer = nonEmptyHeaderValue(route.openrouterHttpReferer);
  if (referer !== undefined) {
    headers["http-referer"] = referer;
  }
  const title = nonEmptyHeaderValue(route.openrouterXTitle);
  if (title !== undefined) {
    headers["x-title"] = title;
  }
  return headers;
}

/**
 * `ferrogate-providers/src/openrouter.rs::OpenRouterAdapter`.
 *
 * Two things separate it from a plain OpenAI request, and both are load-bearing:
 *
 *  - on a STREAM it deletes `stream_options` from the body the OpenAI adapter
 *    just added. OpenRouter includes usage automatically and has deprecated both
 *    OpenAI's `stream_options` opt-in and its older `usage.include` flag, so
 *    sending it is a rejected-request risk for zero benefit;
 *  - it appends the optional `http-referer` / `x-title` attribution headers.
 *
 * `prepare_model_catalog` is overridden too (same delegation + headers), which
 * is why `model_catalog` is served here but not by Grok.
 */
export const openRouterAdapter: ProviderAdapter = {
  kind: "openrouter",

  buildUpstreamRequest(plan: UpstreamPlan): AdapterResult {
    const invalidKind = validateExactKind(plan.route.providerKind, ["openrouter"]);
    if (invalidKind !== null) {
      return invalidKind;
    }
    switch (plan.operation) {
      case "images":
        return imagesUnsupported("openrouter");
      case "embeddings":
        return operationUnsupported("openrouter");
      case "chat.completions":
      case "responses":
      case "model_catalog":
        break;
    }

    const built = openAiCompatibleAdapter.buildUpstreamRequest(asOpenAiCompatible(plan));
    if (!built.ok) {
      return built;
    }

    let body = built.request.body;
    if (plan.operation === "chat.completions" && plan.stream && body !== undefined) {
      const { stream_options: _dropped, ...rest } = body;
      body = rest;
    }

    return {
      ok: true,
      request: {
        ...built.request,
        headers: { ...built.request.headers, ...openRouterHeaders(plan.route) },
        ...(body !== undefined ? { body } : {}),
      },
    };
  },
};

/** `azure.rs::DEFAULT_API_VERSION`. */
export const AZURE_DEFAULT_API_VERSION = "2024-10-21";

/**
 * `azure.rs::split_base_url_api_version`.
 *
 * The Azure `base_url` doubles as the api-version carrier: everything before
 * `?` is the endpoint and an `api-version=` pair in the query wins over the
 * default. A query that carries no (or an empty) `api-version` falls back.
 */
export function splitAzureBaseUrl(baseUrl: string): { endpoint: string; apiVersion: string } {
  const separator = baseUrl.indexOf("?");
  if (separator < 0) {
    return { endpoint: baseUrl, apiVersion: AZURE_DEFAULT_API_VERSION };
  }
  const endpoint = baseUrl.slice(0, separator);
  const query = baseUrl.slice(separator + 1);
  for (const pair of query.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) {
      continue;
    }
    if (pair.slice(0, eq) === "api-version") {
      const value = pair.slice(eq + 1);
      if (value.trim().length > 0) {
        return { endpoint, apiVersion: value };
      }
      break;
    }
  }
  return { endpoint, apiVersion: AZURE_DEFAULT_API_VERSION };
}

/**
 * `azure.rs::encode_path_segment` — percent-encode everything outside the
 * unreserved set. Written out rather than delegated to `encodeURIComponent`,
 * which leaves `!'()*` unescaped and would put different bytes on the wire.
 */
export function encodeAzurePathSegment(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let encoded = "";
  for (const byte of bytes) {
    const isUnreserved =
      (byte >= 0x30 && byte <= 0x39) || // 0-9
      (byte >= 0x41 && byte <= 0x5a) || // A-Z
      (byte >= 0x61 && byte <= 0x7a) || // a-z
      byte === 0x2d || // -
      byte === 0x5f || // _
      byte === 0x2e || // .
      byte === 0x7e; // ~
    encoded += isUnreserved
      ? String.fromCharCode(byte)
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}

/**
 * `ferrogate-providers/src/azure.rs::AzureOpenAiAdapter`.
 *
 * The one family that is emphatically NOT a plain OpenAI request:
 *
 *  - the model is addressed as a **deployment in the path**, so `model` is
 *    DELETED from the body (Azure rejects it) and `provider_model` becomes a
 *    percent-encoded path segment;
 *  - the credential is `api-key`, not `Authorization: Bearer`. `route.authScheme`
 *    is ignored here for the same reason the Rust adapter has no such concept:
 *    Azure's scheme is a property of Azure;
 *  - `api-version` is mandatory and comes from the `base_url` query.
 *
 * `prepare_chat_completions` is the ONLY method Azure overrides, so `/v1/responses`,
 * `/v1/embeddings` and the model catalog are `unsupported_provider_kind` and
 * images is `unsupported_capability`.
 */
export const azureOpenAiAdapter: ProviderAdapter = {
  kind: "azure-openai",

  buildUpstreamRequest(plan: UpstreamPlan): AdapterResult {
    const invalidKind = validateExactKind(plan.route.providerKind, ["azure-openai", "azure"]);
    if (invalidKind !== null) {
      return invalidKind;
    }
    switch (plan.operation) {
      case "images":
        return imagesUnsupported("azure-openai");
      case "responses":
      case "embeddings":
      case "model_catalog":
        return operationUnsupported("azure-openai");
      case "chat.completions":
        break;
    }

    const invalid = ensureObjectBody(plan, "chat completion request body");
    if (invalid !== null) {
      return invalid;
    }

    const { model: _deployment, ...body } = plan.body;
    body["stream"] = plan.stream;
    if (plan.stream) {
      requestOpenAiStreamUsage(body);
    }

    const headers: Record<string, string> = { "content-type": "application/json" };
    const apiKey = plan.route.apiKey;
    if (apiKey !== undefined && apiKey.trim().length > 0) {
      headers["api-key"] = apiKey;
    }

    const { endpoint: base, apiVersion } = splitAzureBaseUrl(plan.route.baseUrl);
    const deployment = encodeAzurePathSegment(plan.providerModel);
    return {
      ok: true,
      request: {
        provider: plan.route.provider,
        method: "POST",
        endpoint: `${base.replace(/\/+$/, "")}/openai/deployments/${deployment}/chat/completions?api-version=${apiVersion}`,
        headers,
        body,
        stream: plan.stream,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// `@ferrogate/providers` bridge
// ---------------------------------------------------------------------------

/**
 * Adapt a crate-shaped `@ferrogate/providers` adapter to this module's
 * collapsed {@link ProviderAdapter}.
 *
 * The two interfaces are the same trait seen from two sides: the package has
 * Rust's four `prepare_*` methods plus `prepare_model_catalog` and signals
 * failure by THROWING `AdapterError`; `./ports.ts` folds those into one entry
 * point discriminated by `plan.operation` and RETURNS the error. This function
 * is the only place that translation lives, so every family added from the
 * package behaves identically at the handler boundary.
 *
 * Two conversions are worth naming because they are lossy in one direction:
 *
 *  - headers arrive as `ProviderHeader[]` with `SecretValue` values (the
 *    package keeps credentials un-printable). They are exposed here, at the
 *    edge of the process that is about to put them on the wire, into the
 *    `Record<string, string>` `UpstreamRequest` declares. Later duplicates win,
 *    matching the header-map semantics the Rust builds.
 *  - `translateEmbeddingsResponse` takes BYTES in the package (it is handed the
 *    raw upstream body, exactly as `translate_embeddings_response(&[u8])` is)
 *    while `handlers.ts` has already parsed the body to JSON. It is re-encoded
 *    here rather than changing either signature; both sides are pure JSON, so
 *    the round trip is value-preserving.
 */
export function packageProviderAdapter(
  canonicalKind: string,
  adapter: PackageProviderAdapter,
): ProviderAdapter {
  const config = (route: PhysicalRoute): PackageProviderConfig => ({
    name: route.provider,
    // The CANONICAL kind, not the operator's spelling: the package adapters
    // validate `provider.kind` against their own `kind()` exactly, so an alias
    // (`vertex-ai`, `xai`, …) has to be resolved before it crosses the boundary.
    kind: canonicalKind,
    baseUrl: route.baseUrl,
    ...(route.apiKey === undefined ? {} : { apiKey: route.apiKey }),
    // The composite credentials the `bedrock` / `vertex` families need. This is
    // the ONLY place the plaintext is wrapped in `SecretValue`, the package's
    // (and the Rust's) un-printable carrier — from here on a `console.log` or
    // `JSON.stringify` of the provider config renders `[redacted]` instead of a
    // signing key. A route that carries no credential passes NONE: the adapter
    // has to see `undefined` and raise its own fail-closed `AdapterError`,
    // never a half-populated credential it might try to sign with.
    ...(route.awsCredentials === undefined
      ? {}
      : {
          awsCredentials: {
            accessKeyId: route.awsCredentials.accessKeyId,
            secretAccessKey: new SecretValue(route.awsCredentials.secretAccessKey),
            ...(route.awsCredentials.sessionToken === undefined
              ? {}
              : { sessionToken: new SecretValue(route.awsCredentials.sessionToken) }),
            region: route.awsCredentials.region,
          },
        }),
    ...(route.gcpCredentials === undefined
      ? {}
      : {
          gcpCredentials: {
            accessToken: new SecretValue(route.gcpCredentials.accessToken),
            projectId: route.gcpCredentials.projectId,
            location: route.gcpCredentials.location,
          },
        }),
  });

  return {
    kind: canonicalKind,

    buildUpstreamRequest(plan: UpstreamPlan): AdapterResult {
      if (canonicalProviderKind(plan.route.providerKind) !== canonicalKind) {
        return {
          ok: false,
          error: {
            kind: "unsupported_provider_kind",
            providerKind: plan.route.providerKind.trim().toLowerCase(),
          },
        };
      }
      const provider = config(plan.route);
      const base = {
        logicalModel: plan.logicalModel,
        providerModel: plan.providerModel,
        body: plan.body as Json,
      };
      try {
        if (plan.operation === "model_catalog") {
          const catalog = adapter.prepareModelCatalog(provider);
          return {
            ok: true,
            request: {
              provider: catalog.provider,
              method: "GET",
              endpoint: catalog.endpoint,
              headers: exposeHeaders(catalog.headers),
              body: undefined,
              stream: false,
            },
          };
        }
        const prepared =
          plan.operation === "chat.completions"
            ? adapter.prepareChatCompletions(provider, { ...base, stream: plan.stream })
            : plan.operation === "responses"
              ? adapter.prepareResponses(provider, { ...base, stream: plan.stream })
              : plan.operation === "embeddings"
                ? adapter.prepareEmbeddings(provider, base)
                : adapter.prepareImages(provider, base);
        return {
          ok: true,
          request: {
            provider: prepared.provider,
            method: "POST",
            endpoint: prepared.endpoint,
            headers: exposeHeaders(prepared.headers),
            body: prepared.body as Record<string, unknown>,
            stream: prepared.stream,
          },
        };
      } catch (error) {
        return { ok: false, error: packageAdapterError(error) };
      }
    },

    translateEmbeddingsResponse(body: unknown, logicalModel: string): unknown | undefined {
      const encoded = new TextEncoder().encode(JSON.stringify(body) ?? "null");
      const translated = adapter.translateEmbeddingsResponse(encoded, logicalModel);
      // The package returns `null` for "pass the upstream body through"
      // (the Rust `Ok(None)`); `./ports.ts` spells that `undefined`.
      return translated === null ? undefined : translated;
    },
  };
}

/** `ProviderHeader[]` (values wrapped in `SecretValue`) → a plain header map. */
function exposeHeaders(headers: readonly PackageProviderHeader[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const header of headers) {
    out[header.name] =
      header.value instanceof SecretValue ? header.value.exposeSecret() : String(header.value);
  }
  return out;
}

/**
 * The package's thrown `AdapterError` → the returned `AdapterError` union.
 *
 * A non-`AdapterError` throw is NOT swallowed as an adapter error: it is a bug
 * in the adapter, and the handler's 500 path is the honest answer for it.
 */
function packageAdapterError(error: unknown): AdapterError {
  if (!(error instanceof PackageAdapterError)) {
    throw error;
  }
  switch (error.kind) {
    case "UnsupportedProviderKind":
      return {
        kind: "unsupported_provider_kind",
        providerKind: error.providerKind ?? "",
      };
    case "UnsupportedCapability":
      return {
        kind: "unsupported_capability",
        capability: error.capability ?? "",
        providerKind: error.providerKind ?? "",
      };
    case "InvalidRequest":
      return { kind: "invalid_request", message: error.message };
  }
}

/**
 * `gemini` — `@ferrogate/providers`' port of `gemini.rs`, wrapped.
 *
 * Chat/responses/embeddings are all reachable; images answers the Rust
 * capability error (`provider kind gemini does not support image generation`,
 * issue #275) and the model catalog the Rust `unsupported provider kind`,
 * because `gemini.rs` overrides neither trait default. The streaming half of
 * the family was already ported: `src/streaming/responses.ts` carries the
 * `gemini` dialect of the Responses normalizer and `src/streaming/usage.ts`
 * `gemini.rs::extract_usage`.
 */
export const geminiAdapter: ProviderAdapter = packageProviderAdapter(
  "gemini",
  new GeminiAdapter(),
);

/**
 * `bedrock` — `@ferrogate/providers`' port of `bedrock.rs` (issue #172).
 *
 * Chat goes to the Bedrock Runtime `Converse` API and embeddings to
 * `InvokeModel`, both signed with SigV4 from `PhysicalRoute.awsCredentials`.
 * `bedrock.rs` routes BOTH through one signing helper and one `/converse` path
 * whether or not the request streams (issue #274), so this port does too. A
 * route with no AWS credential raises the adapter's own
 * `bedrock provider is missing AWS credentials` instead of dispatching an
 * unsigned request — the same fail-closed posture the Rust config validator
 * enforces one step earlier, and which `buildModelCatalog` now also enforces.
 */
export const bedrockAdapter: ProviderAdapter = packageProviderAdapter(
  "bedrock",
  new BedrockAdapter(),
);

/**
 * `vertex` — `@ferrogate/providers`' port of `vertex.rs` (issue #172).
 *
 * Gemini-on-Vertex `generateContent` / `streamGenerateContent?alt=sse` plus
 * `:predict` embeddings, addressed by project + location and authenticated with
 * the PRE-MINTED OAuth2 access token on `PhysicalRoute.gcpCredentials`.
 * FerroGate never mints or refreshes that token (see `GcpRouteCredentials` in
 * `./ports.ts`). Same fail-closed rule as Bedrock.
 */
export const vertexAdapter: ProviderAdapter = packageProviderAdapter(
  "vertex",
  new VertexAiAdapter(),
);

/** `ferrogate_providers::registry` — kind → adapter, alias-aware. */
export const defaultAdapterRegistry: AdapterRegistry = {
  adapterFor(providerKind: string): ProviderAdapter | null {
    const canonical = canonicalProviderKind(providerKind);
    switch (canonical) {
      case "openai-compatible":
        return openAiCompatibleAdapter;
      case "anthropic":
        return anthropicAdapter;
      case "grok":
        return grokAdapter;
      case "openrouter":
        return openRouterAdapter;
      case "azure-openai":
        return azureOpenAiAdapter;
      case "gemini":
        return geminiAdapter;
      case "bedrock":
        return bedrockAdapter;
      case "vertex":
        return vertexAdapter;
      default:
        // `canonicalProviderKind` returned `null`: the operator named a family
        // that does not exist in `PROVIDER_ADAPTER_FAMILIES`. The handler
        // renders the Rust `unsupported provider kind <kind>` message.
        return null;
    }
  },
};
