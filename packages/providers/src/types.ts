/**
 * Core provider-adapter vocabulary — port of `ferrogate-providers/src/types.rs`.
 *
 * The `ProviderAdapter` trait, its config/plan/request/response data shapes, the
 * `AdapterError` taxonomy, the redacted `SecretValue`, and the
 * provider-family/alias table (`SUPPORTED_PROVIDER_ADAPTER_FAMILIES`).
 */
import type { ToolCall, ToolDef, ToolResult } from "@ferrogate/core";

import type { Json } from "./json.js";
import type { CloudflareAiGatewayRouting } from "./cloudflare.js";

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

const REDACTED = "<redacted>";

/**
 * A string whose contents are hidden from every debug/serialization surface,
 * mirroring Rust's `SecretValue` (its `Debug` writes `<redacted>`). Only
 * {@link SecretValue.exposeSecret} reveals the value, matching Rust's
 * `expose_secret`.
 */
export class SecretValue {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  static new(value: string): SecretValue {
    return new SecretValue(value);
  }

  exposeSecret(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  /** Node/console inspection is redacted, mirroring the Rust `Debug` impl. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return REDACTED;
  }
}

/** AWS access-key credentials + region for the Bedrock adapter (issue #172). */
export interface AwsProviderCredentials {
  accessKeyId: string;
  secretAccessKey: SecretValue;
  sessionToken?: SecretValue;
  region: string;
}

/** A pre-minted GCP OAuth2 access token + project/location for Vertex (issue #172). */
export interface GcpProviderCredentials {
  accessToken: SecretValue;
  projectId: string;
  location: string;
}

/** Per-provider dispatch configuration. */
export interface ProviderConfig {
  name: string;
  kind: string;
  baseUrl: string;
  apiKey?: string;
  openrouterHttpReferer?: string;
  openrouterXTitle?: string;
  awsCredentials?: AwsProviderCredentials;
  gcpCredentials?: GcpProviderCredentials;
  // `cloudflareAiGateway` was here (issue #406) and is gone (issue #672). It was
  // read by exactly one thing — `ProviderAdapterRegistry`'s routing leg — which
  // the deployed data plane never ran, and keeping an unread field would leave a
  // second way to "configure" AI Gateway routing that has no effect. The routing
  // now travels on `PhysicalRoute.cloudflareAiGateway`
  // (`apps/gateway/src/inference/ports.ts`) and is applied by that app's adapter
  // decorator, which is the path dispatch actually takes.
}

// ---------------------------------------------------------------------------
// Plans (canonical request → adapter input)
// ---------------------------------------------------------------------------

export interface ChatCompletionPlan {
  logicalModel: string;
  providerModel: string;
  stream: boolean;
  body: Json;
}

export interface ResponsesPlan {
  logicalModel: string;
  providerModel: string;
  stream: boolean;
  body: Json;
}

export interface EmbeddingsPlan {
  logicalModel: string;
  providerModel: string;
  body: Json;
}

/** Plan for `POST /v1/images/generations` (issue #275); never streams. */
export interface ImagesPlan {
  logicalModel: string;
  providerModel: string;
  body: Json;
}

/**
 * Plan for `POST /v1/rerank` (issue #676); never streams.
 *
 * Field-identical to {@link EmbeddingsPlan} — a separate interface rather than a
 * reuse because the two carry DIFFERENT body grammars (`{ input }` vs
 * `{ query, documents }`) and the type is what tells a reader which one an
 * adapter method is about to be handed.
 */
export interface RerankPlan {
  logicalModel: string;
  providerModel: string;
  body: Json;
}

// ---------------------------------------------------------------------------
// Prepared HTTP requests + responses
// ---------------------------------------------------------------------------

export interface ProviderHeader {
  name: string;
  value: SecretValue;
}

export interface ProviderHttpRequest {
  provider: string;
  endpoint: string;
  body: Json;
  stream: boolean;
  headers: ProviderHeader[];
}

export interface ProviderCatalogRequest {
  provider: string;
  endpoint: string;
  headers: ProviderHeader[];
}

export interface ProviderErrorResponse {
  status: number;
  body: Json;
}

export interface ProviderUsage {
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
}

export interface ProviderCatalogModel {
  id: string;
  ownedBy?: string;
  created?: number;
  contextWindow?: number;
  capabilities: string[];
}

// ---------------------------------------------------------------------------
// AdapterError taxonomy
// ---------------------------------------------------------------------------

export type AdapterErrorKind =
  | "UnsupportedProviderKind"
  | "InvalidRequest"
  | "UnsupportedCapability";

/** Port of the Rust `AdapterError` enum, rendered as a throwable error. */
export class AdapterError extends Error {
  override readonly name = "AdapterError";
  readonly kind: AdapterErrorKind;
  /** Set for `UnsupportedProviderKind` and `UnsupportedCapability`. */
  readonly providerKind?: string;
  /** Set for `UnsupportedCapability`. */
  readonly capability?: string;

  private constructor(
    kind: AdapterErrorKind,
    message: string,
    extra?: { providerKind?: string; capability?: string },
  ) {
    super(message);
    this.kind = kind;
    this.providerKind = extra?.providerKind;
    this.capability = extra?.capability;
  }

  static unsupportedProviderKind(kind: string): AdapterError {
    return new AdapterError("UnsupportedProviderKind", `unsupported provider kind ${kind}`, {
      providerKind: kind,
    });
  }

  static invalidRequest(message: string): AdapterError {
    return new AdapterError("InvalidRequest", message);
  }

  static unsupportedCapability(capability: string, kind: string): AdapterError {
    return new AdapterError(
      "UnsupportedCapability",
      `provider kind ${kind} does not support ${capability}`,
      { capability, providerKind: kind },
    );
  }

  /** Structural equality mirroring the Rust `PartialEq` derive (for tests). */
  equals(other: AdapterError): boolean {
    return (
      this.kind === other.kind &&
      this.message === other.message &&
      this.providerKind === other.providerKind &&
      this.capability === other.capability
    );
  }
}

// ---------------------------------------------------------------------------
// Provider families + alias table
// ---------------------------------------------------------------------------

export type ProviderAdapterFamily =
  | "OpenAiCompatible"
  | "Anthropic"
  | "Gemini"
  | "Grok"
  | "OpenRouter"
  | "AzureOpenAi"
  | "Bedrock"
  | "Vertex"
  | "WorkersAi";

export interface ProviderAdapterFamilyDescriptor {
  family: ProviderAdapterFamily;
  canonicalKind: string;
  aliases: readonly string[];
}

export const SUPPORTED_PROVIDER_ADAPTER_FAMILIES: readonly ProviderAdapterFamilyDescriptor[] = [
  {
    family: "OpenAiCompatible",
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
  { family: "Anthropic", canonicalKind: "anthropic", aliases: [] },
  { family: "Gemini", canonicalKind: "gemini", aliases: [] },
  { family: "Grok", canonicalKind: "grok", aliases: ["xai"] },
  { family: "OpenRouter", canonicalKind: "openrouter", aliases: [] },
  { family: "AzureOpenAi", canonicalKind: "azure-openai", aliases: ["azure"] },
  { family: "Bedrock", canonicalKind: "bedrock", aliases: ["aws-bedrock"] },
  { family: "Vertex", canonicalKind: "vertex", aliases: ["vertex-ai"] },
  /**
   * The NINTH family (issue #673). It has no Rust ancestor — a Rust process has
   * no `env.AI` — so unlike the eight above there is no `SUPPORTED_PROVIDER_
   * ADAPTER_FAMILIES` row to port; the aliases are the spellings an operator is
   * likely to reach for. `cloudflare` is deliberately NOT one of them: a
   * provider row already carries an unrelated `cloudflare_ai_gateway` concept
   * (`./cloudflare.ts`), and one word meaning both would be a trap.
   */
  {
    family: "WorkersAi",
    canonicalKind: "workers-ai",
    aliases: ["cloudflare-workers-ai", "cf-workers-ai", "workersai"],
  },
];

/** Resolve a provider `kind` (trimmed, case-insensitive) to its family. */
export function canonicalProviderAdapterFamily(kind: string): ProviderAdapterFamily | undefined {
  const trimmed = kind.trim();
  const descriptor = SUPPORTED_PROVIDER_ADAPTER_FAMILIES.find(
    (d) =>
      d.canonicalKind.toLowerCase() === trimmed.toLowerCase() ||
      d.aliases.some((alias) => alias.toLowerCase() === trimmed.toLowerCase()),
  );
  return descriptor?.family;
}

export const isOpenAiCompatibleProviderKind = (kind: string): boolean =>
  canonicalProviderAdapterFamily(kind) === "OpenAiCompatible";

export const providerCompatibilityKind = (kind: string): "openai-compatible" | "dedicated" =>
  isOpenAiCompatibleProviderKind(kind) ? "openai-compatible" : "dedicated";

// ---------------------------------------------------------------------------
// ProviderAdapter trait
// ---------------------------------------------------------------------------

/**
 * The adapter boundary. Success values are returned; failures throw
 * {@link AdapterError} (the Rust `Result::Err` arm). Every method is pure and
 * synchronous, exactly as in the Rust trait.
 */
export interface ProviderAdapter {
  kind(): string;
  prepareChatCompletions(provider: ProviderConfig, request: ChatCompletionPlan): ProviderHttpRequest;
  prepareResponses(provider: ProviderConfig, request: ResponsesPlan): ProviderHttpRequest;
  prepareEmbeddings(provider: ProviderConfig, request: EmbeddingsPlan): ProviderHttpRequest;
  prepareImages(provider: ProviderConfig, request: ImagesPlan): ProviderHttpRequest;
  prepareRerank(provider: ProviderConfig, request: RerankPlan): ProviderHttpRequest;
  translateEmbeddingsResponse(body: Uint8Array, model: string): Json | null;
  /**
   * Provider rerank dialect → the gateway's canonical `{ object, model, results }`.
   *
   * Takes the caller's REQUEST body as well, which
   * {@link ProviderAdapter.translateEmbeddingsResponse} does not need: no
   * reranker echoes the documents back, so `return_documents` can only be
   * answered by joining the provider's indices against the documents the caller
   * sent. Returning `null` means "pass the upstream body through", the same
   * `Ok(None)` convention the embeddings translation uses.
   */
  translateRerankResponse(body: Uint8Array, model: string, request: Json): Json | null;
  prepareModelCatalog(provider: ProviderConfig): ProviderCatalogRequest;
  parseModelCatalog(body: Uint8Array): ProviderCatalogModel[];
  normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse;
  extractUsage(body: Uint8Array): ProviderUsage | undefined;
  injectTools(body: Json, tools: readonly ToolDef[]): Json;
  extractToolCalls(body: Uint8Array): ToolCall[];
  appendToolResults(body: Json, results: readonly ToolResult[]): Json;
  isRetryableStatus(status: number): boolean;
}

/**
 * Base class supplying the trait's fail-closed default methods. Concrete
 * adapters implement the four methods with no Rust default
 * (`kind`, `prepareChatCompletions`, `normalizeErrorResponse`, `extractUsage`)
 * and override the rest as needed.
 */
export abstract class BaseProviderAdapter implements ProviderAdapter {
  abstract kind(): string;
  abstract prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest;
  abstract normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse;
  abstract extractUsage(body: Uint8Array): ProviderUsage | undefined;

  prepareResponses(_provider: ProviderConfig, _request: ResponsesPlan): ProviderHttpRequest {
    throw AdapterError.unsupportedProviderKind(this.kind());
  }

  prepareEmbeddings(_provider: ProviderConfig, _request: EmbeddingsPlan): ProviderHttpRequest {
    throw AdapterError.unsupportedProviderKind(this.kind());
  }

  prepareImages(_provider: ProviderConfig, _request: ImagesPlan): ProviderHttpRequest {
    throw AdapterError.unsupportedCapability("image generation", this.kind());
  }

  /**
   * Fail CLOSED, and as a capability rather than an unknown kind.
   *
   * `unsupportedCapability` is the arm `prepareImages` uses for the same
   * situation — the family is real, this surface is not one of its. It matters
   * beyond the message: the gateway's failover ladder treats a capability
   * refusal as "this route cannot serve this request, try the next candidate",
   * which is exactly right for a deployment that mixes an OpenAI route and a
   * Workers AI reranker under one logical model.
   */
  prepareRerank(_provider: ProviderConfig, _request: RerankPlan): ProviderHttpRequest {
    throw AdapterError.unsupportedCapability("reranking", this.kind());
  }

  translateEmbeddingsResponse(_body: Uint8Array, _model: string): Json | null {
    return null;
  }

  translateRerankResponse(_body: Uint8Array, _model: string, _request: Json): Json | null {
    return null;
  }

  prepareModelCatalog(_provider: ProviderConfig): ProviderCatalogRequest {
    throw AdapterError.unsupportedProviderKind(this.kind());
  }

  parseModelCatalog(_body: Uint8Array): ProviderCatalogModel[] {
    throw AdapterError.unsupportedProviderKind(this.kind());
  }

  injectTools(body: Json, _tools: readonly ToolDef[]): Json {
    return body;
  }

  extractToolCalls(_body: Uint8Array): ToolCall[] {
    return [];
  }

  appendToolResults(body: Json, _results: readonly ToolResult[]): Json {
    return body;
  }

  isRetryableStatus(status: number): boolean {
    return status === 429 || (status >= 500 && status <= 599);
  }
}
