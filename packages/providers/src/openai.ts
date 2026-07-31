/**
 * OpenAI-compatible provider adapter — port of `openai.rs`.
 *
 * Backs the whole `openai-compatible` family (openai, deepseek, vllm, ollama, …)
 * plus the shared `chat/completions`, `responses`, `embeddings`,
 * `images/generations`, and `/models` request shaping. `requestOpenaiStreamUsage`
 * is re-used by the Azure adapter.
 */
import type { ToolCall, ToolDef, ToolResult } from "@ferrogate/core";

import {
  AdapterError,
  BaseProviderAdapter,
  SecretValue,
  isOpenAiCompatibleProviderKind,
} from "./types.js";
import type {
  ChatCompletionPlan,
  EmbeddingsPlan,
  ImagesPlan,
  ProviderCatalogModel,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";
import {
  asStr,
  asU64,
  getField,
  isObject,
  parseJson,
  parseJsonStringOrClone,
} from "./json.js";
import type { Json, JsonObject } from "./json.js";

export class OpenAiCompatibleAdapter extends BaseProviderAdapter {
  override kind(): string {
    return "openai-compatible";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureChatObjectBody(request.body);
    body["model"] = request.providerModel;
    body["stream"] = request.stream;
    if (request.stream) requestOpenaiStreamUsage(body);

    return {
      provider: provider.name,
      endpoint: chatCompletionsEndpoint(provider.baseUrl),
      body,
      stream: request.stream,
      headers: providerHeaders(provider.apiKey),
    };
  }

  override prepareResponses(
    provider: ProviderConfig,
    request: ResponsesPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureLabeledObjectBody(request.body, "responses request body");
    body["model"] = request.providerModel;
    body["stream"] = request.stream;

    return {
      provider: provider.name,
      endpoint: responsesEndpoint(provider.baseUrl),
      body,
      stream: request.stream,
      headers: providerHeaders(provider.apiKey),
    };
  }

  override prepareEmbeddings(
    provider: ProviderConfig,
    request: EmbeddingsPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureLabeledObjectBody(request.body, "embeddings request body");
    body["model"] = request.providerModel;

    return {
      provider: provider.name,
      endpoint: embeddingsEndpoint(provider.baseUrl),
      body,
      stream: false,
      headers: providerHeaders(provider.apiKey),
    };
  }

  override prepareImages(provider: ProviderConfig, request: ImagesPlan): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureLabeledObjectBody(request.body, "image generation request body");
    body["model"] = request.providerModel;

    return {
      provider: provider.name,
      endpoint: imagesGenerationsEndpoint(provider.baseUrl),
      body,
      stream: false,
      headers: providerHeaders(provider.apiKey),
    };
  }

  override prepareModelCatalog(provider: ProviderConfig): {
    provider: string;
    endpoint: string;
    headers: ProviderHeader[];
  } {
    validateKind(provider.kind);
    return {
      provider: provider.name,
      endpoint: modelsEndpoint(provider.baseUrl),
      headers: providerHeaders(provider.apiKey),
    };
  }

  override parseModelCatalog(body: Uint8Array): ProviderCatalogModel[] {
    return parseOpenAiModelCatalog(body);
  }

  override normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse {
    const parsed = parseJson(body);
    const providerError = getField(parsed, "error");
    const message =
      asStr(getField(providerError, "message")) ??
      fallbackErrorMessage(parsed, body) ??
      `provider returned HTTP ${status}`;
    const kind = asStr(getField(providerError, "type")) ?? "provider_error";
    const codeRaw = asStr(getField(providerError, "code"));
    const code = codeRaw !== undefined && codeRaw.trim().length > 0 ? codeRaw : "provider_error";

    return {
      status,
      body: {
        error: {
          message,
          type: "provider_error",
          provider_type: kind,
          code,
          provider_status: status,
          provider_content_type: contentType,
          request_id: requestId,
        },
      },
    };
  }

  override extractUsage(body: Uint8Array): ProviderUsage | undefined {
    const value = parseJson(body);
    if (value === undefined) return undefined;
    const usage = getField(value, "usage");
    if (usage === undefined) return undefined;
    const extracted: ProviderUsage = {
      promptTokens: asU64(getField(usage, "prompt_tokens")),
      completionTokens: asU64(getField(usage, "completion_tokens")),
      totalTokens: asU64(getField(usage, "total_tokens")),
    };
    return hasAnyUsage(extracted) ? extracted : undefined;
  }

  override injectTools(body: Json, tools: readonly ToolDef[]): Json {
    const object = ensureLabeledObjectBody(body, "tool-enabled request body");
    if (tools.length === 0) return object;
    object["tools"] = tools.map((tool) => {
      const fn: JsonObject = { name: tool.name, parameters: tool.input_schema as Json };
      if (tool.description !== undefined) fn["description"] = tool.description;
      return { type: "function", function: fn };
    });
    return object;
  }

  override extractToolCalls(body: Uint8Array): ToolCall[] {
    const value = parseJson(body);
    if (value === undefined) {
      throw AdapterError.invalidRequest("provider response body must be JSON");
    }
    const calls: ToolCall[] = [];
    for (const choice of asArrayOr(getField(value, "choices"))) {
      const message = getField(choice, "message");
      for (const toolCall of asArrayOr(getField(message, "tool_calls"))) {
        const canonical = openAiToolCallToCanonical(toolCall);
        if (canonical) calls.push(canonical);
      }
    }
    return calls;
  }

  override appendToolResults(body: Json, results: readonly ToolResult[]): Json {
    const object = ensureLabeledObjectBody(body, "tool-result request body");
    if (results.length === 0) return object;
    if (!Array.isArray(object["messages"])) object["messages"] = [];
    const messages = object["messages"] as Json[];
    for (const result of results) {
      messages.push({
        role: "tool",
        tool_call_id: result.tool_call_id,
        content: toolResultContentToString(result.content as Json),
      });
    }
    return object;
  }
}

/** Ensure `stream_options.include_usage = true` so streaming responses report usage. */
export function requestOpenaiStreamUsage(body: JsonObject): void {
  let streamOptions = body["stream_options"];
  if (!isObject(streamOptions)) {
    streamOptions = {};
    body["stream_options"] = streamOptions;
  }
  (streamOptions as JsonObject)["include_usage"] = true;
}

function validateKind(kind: string): void {
  if (!isOpenAiCompatibleProviderKind(kind)) {
    throw AdapterError.unsupportedProviderKind(kind.trim().toLowerCase());
  }
}

const ensureChatObjectBody = (body: Json): JsonObject =>
  ensureLabeledObjectBody(body, "chat completion request body");

export function ensureLabeledObjectBody(body: Json, label: string): JsonObject {
  if (isObject(body)) return body;
  throw AdapterError.invalidRequest(`${label} must be a JSON object`);
}

export function providerHeaders(apiKey: string | undefined): ProviderHeader[] {
  const headers: ProviderHeader[] = [
    { name: "content-type", value: new SecretValue("application/json") },
  ];
  if (apiKey !== undefined && apiKey.trim().length > 0) {
    headers.push({ name: "authorization", value: new SecretValue(`Bearer ${apiKey}`) });
  }
  return headers;
}

const trimEndSlashes = (value: string): string => value.replace(/\/+$/, "");
const chatCompletionsEndpoint = (baseUrl: string): string => `${trimEndSlashes(baseUrl)}/chat/completions`;
const responsesEndpoint = (baseUrl: string): string => `${trimEndSlashes(baseUrl)}/responses`;
const embeddingsEndpoint = (baseUrl: string): string => `${trimEndSlashes(baseUrl)}/embeddings`;
const imagesGenerationsEndpoint = (baseUrl: string): string => `${trimEndSlashes(baseUrl)}/images/generations`;
const modelsEndpoint = (baseUrl: string): string => `${trimEndSlashes(baseUrl)}/models`;

function parseOpenAiModelCatalog(body: Uint8Array): ProviderCatalogModel[] {
  const value = parseJson(body);
  if (value === undefined) {
    throw AdapterError.invalidRequest("provider model catalog must be JSON");
  }
  const data = getField(value, "data");
  if (!Array.isArray(data)) {
    throw AdapterError.invalidRequest("provider model catalog must include a data array");
  }
  return data.map((model) => {
    const idRaw = asStr(getField(model, "id"));
    const id = idRaw !== undefined && idRaw.trim().length > 0 ? idRaw : undefined;
    if (id === undefined) {
      throw AdapterError.invalidRequest("provider model catalog entry missing id");
    }
    return {
      id,
      ownedBy: asStr(getField(model, "owned_by")),
      created: asU64(getField(model, "created")),
      contextWindow: asU64(getField(model, "context_length") ?? getField(model, "context_window")),
      capabilities: catalogCapabilities(model),
    };
  });
}

function catalogCapabilities(model: Json): string[] {
  const capabilities: string[] = [];
  for (const key of [
    "capabilities",
    "supported_modalities",
    "input_modalities",
    "output_modalities",
  ]) {
    const values = getField(model, key);
    if (Array.isArray(values)) {
      for (const value of values) {
        if (typeof value === "string" && value.trim().length > 0) capabilities.push(value);
      }
    }
  }
  capabilities.sort();
  return dedupeSorted(capabilities);
}

const dedupeSorted = (values: string[]): string[] =>
  values.filter((value, index) => index === 0 || value !== values[index - 1]);

export function fallbackErrorMessage(parsed: Json | undefined, body: Uint8Array): string | undefined {
  if (typeof parsed === "string") return parsed;
  const text = new TextDecoder().decode(body).trim();
  if (text.length === 0) return undefined;
  return Array.from(text).slice(0, 512).join("");
}

function openAiToolCallToCanonical(value: Json): ToolCall | undefined {
  const fn = getField(value, "function");
  if (fn === undefined) return undefined;
  const id = asStr(getField(value, "id"));
  const name = asStr(getField(fn, "name"));
  const argsRaw = getField(fn, "arguments");
  if (id === undefined || name === undefined || argsRaw === undefined) return undefined;
  return { id, name, arguments: parseJsonStringOrClone(argsRaw) };
}

export const toolResultContentToString = (value: Json): string =>
  typeof value === "string" ? value : JSON.stringify(value);

const asArrayOr = (value: Json | undefined): Json[] => (Array.isArray(value) ? value : []);

export const hasAnyUsage = (usage: ProviderUsage): boolean =>
  usage.promptTokens !== undefined ||
  usage.completionTokens !== undefined ||
  usage.totalTokens !== undefined;
