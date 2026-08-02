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
  /** Cloudflare AI Gateway routing (issue #406); absent means direct dispatch. */
  cloudflareAiGateway?: CloudflareAiGatewayRouting;
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
  | "Vertex";

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
  translateEmbeddingsResponse(body: Uint8Array, model: string): Json | null;
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

  translateEmbeddingsResponse(_body: Uint8Array, _model: string): Json | null {
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
