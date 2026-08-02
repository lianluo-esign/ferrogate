/**
 * Google Gemini provider adapter — port of `gemini.rs`.
 *
 * Translates OpenAI-shaped chat/responses/embeddings requests into Gemini's
 * `generateContent`/`streamGenerateContent`/`batchEmbedContents` wire shapes and
 * normalizes the embedding response back to the OpenAI envelope. The exported
 * helpers (`openaiMessagesToGeminiContents`, `embeddingsTextInputs`,
 * `openaiEmbeddingsResponse`, …) are re-used by the Vertex and Bedrock adapters.
 */
import { AdapterError, BaseProviderAdapter, SecretValue } from "./types.js";
import type {
  ChatCompletionPlan,
  EmbeddingsPlan,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";
import { CanonicalAiRequest } from "./canonical.js";
import { applyStructuredOutputToGemini, structuredOutputFromChatBody } from "./structured.js";
import { assertPromptCacheForAutomaticFamily } from "./caching.js";
import { asI64, asStr, asU64, getField, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";
import { fallbackErrorMessage, hasAnyUsage } from "./openai.js";

export class GeminiAdapter extends BaseProviderAdapter {
  override kind(): string {
    return "gemini";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body);

    // Gemini caches implicitly and exposes no per-request breakpoint, so an
    // `auto` directive is already satisfied and anything stronger is refused
    // rather than served under Gemini's own rules (#690).
    assertPromptCacheForAutomaticFamily(body, provider.kind);

    const geminiBody: JsonObject = { contents: openaiMessagesToGeminiContents(body) };
    const instruction = systemInstruction(body);
    if (instruction !== undefined) geminiBody["systemInstruction"] = instruction;
    const config = structuredGenerationConfig(body, provider.kind);
    if (config !== undefined) geminiBody["generationConfig"] = config;

    return {
      provider: provider.name,
      endpoint: generateContentEndpoint(provider.baseUrl, request.providerModel, request.stream),
      body: geminiBody,
      stream: request.stream,
      headers: geminiHeaders(provider.apiKey),
    };
  }

  override prepareResponses(
    provider: ProviderConfig,
    request: ResponsesPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = CanonicalAiRequest.fromResponsesBody(request.body).intoGeminiBody();

    const geminiBody: JsonObject = { contents: getField(body, "contents") ?? [] };
    const instruction = getField(body, "systemInstruction");
    if (instruction !== undefined) geminiBody["systemInstruction"] = instruction;
    const config = getField(body, "generationConfig");
    if (config !== undefined) geminiBody["generationConfig"] = config;
    const tools = getField(body, "tools");
    if (tools !== undefined) geminiBody["tools"] = tools;
    const toolConfig = getField(body, "toolConfig");
    if (toolConfig !== undefined) geminiBody["toolConfig"] = toolConfig;

    return {
      provider: provider.name,
      endpoint: generateContentEndpoint(provider.baseUrl, request.providerModel, request.stream),
      body: geminiBody,
      stream: request.stream,
      headers: geminiHeaders(provider.apiKey),
    };
  }

  override prepareEmbeddings(
    provider: ProviderConfig,
    request: EmbeddingsPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body);
    const inputs = embeddingsTextInputs(body);
    const modelPath = `models/${trimStartMatches(request.providerModel, "models/")}`;
    const requests: Json[] = inputs.map((text) => ({
      model: modelPath,
      content: { parts: [{ text }] },
    }));

    return {
      provider: provider.name,
      endpoint: batchEmbedContentsEndpoint(provider.baseUrl, request.providerModel),
      body: { requests },
      stream: false,
      headers: geminiHeaders(provider.apiKey),
    };
  }

  override translateEmbeddingsResponse(body: Uint8Array, model: string): Json | null {
    const value = parseEmbeddingsResponseBody(body);
    const embeddings = getField(value, "embeddings");
    if (!Array.isArray(embeddings)) {
      throw AdapterError.invalidRequest("Gemini embeddings response is missing an embeddings array");
    }
    const vectors = embeddings.map((entry) => getField(entry, "values") ?? []);
    return openaiEmbeddingsResponse(vectors, model, undefined);
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
    const providerType =
      asStr(getField(providerError, "status")) ??
      (asI64(getField(providerError, "code")) !== undefined ? "google_rpc_error" : undefined) ??
      "provider_error";

    return {
      status,
      body: {
        error: {
          message,
          type: "provider_error",
          provider_type: providerType,
          code: providerType,
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
    const usage = getField(value, "usageMetadata");
    if (usage === undefined) return undefined;
    const extracted: ProviderUsage = {
      promptTokens: asU64(getField(usage, "promptTokenCount")),
      completionTokens: asU64(getField(usage, "candidatesTokenCount")),
      totalTokens: asU64(getField(usage, "totalTokenCount")),
    };
    return hasAnyUsage(extracted) ? extracted : undefined;
  }
}

function geminiHeaders(apiKey: string | undefined): ProviderHeader[] {
  const headers: ProviderHeader[] = [
    { name: "content-type", value: new SecretValue("application/json") },
  ];
  if (apiKey !== undefined && apiKey.trim().length > 0) {
    headers.push({ name: "x-goog-api-key", value: new SecretValue(apiKey) });
  }
  return headers;
}

function validateKind(kind: string): void {
  if (kind !== "gemini") throw AdapterError.unsupportedProviderKind(kind);
}

/** Shared with Vertex — `pub(crate)` in Rust. */
export function ensureObjectBody(body: Json): JsonObject {
  if (isObject(body)) return body;
  throw AdapterError.invalidRequest("chat completion request body must be a JSON object");
}

/** OpenAI-shaped `messages` → Gemini `contents` (shared with Vertex). */
export function openaiMessagesToGeminiContents(body: Json): Json {
  const messages = getField(body, "messages");
  if (!Array.isArray(messages)) return [];
  const contents: Json[] = [];
  for (const message of messages) {
    const roleRaw = asStr(getField(message, "role"));
    if (roleRaw === "system") continue;
    let role: string;
    switch (roleRaw) {
      case "assistant":
        role = "model";
        break;
      case "user":
      case undefined:
        role = "user";
        break;
      case "tool":
        role = "user";
        break;
      default:
        throw AdapterError.invalidRequest(`unsupported Gemini message role ${roleRaw}`);
    }
    contents.push({ role, parts: contentParts(getField(message, "content")) });
  }
  return contents;
}

/** Extract Gemini `systemInstruction` from OpenAI `system` messages (shared with Vertex). */
export function systemInstruction(body: Json): Json | undefined {
  const messages = getField(body, "messages");
  if (!Array.isArray(messages)) return undefined;
  const parts: Json[] = [];
  for (const message of messages) {
    if (asStr(getField(message, "role")) !== "system") continue;
    parts.push(...contentParts(getField(message, "content")));
  }
  if (parts.length === 0) return undefined;
  return { role: "system", parts };
}

function contentParts(content: Json | undefined): Json[] {
  if (typeof content === "string") return [{ text: content }];
  if (Array.isArray(content)) {
    return content.map((block) => {
      if (isObject(block) && asStr(block["type"]) === "text") {
        return { text: asStr(block["text"]) ?? "" };
      }
      if (typeof block === "string") return { text: block };
      throw AdapterError.invalidRequest("Gemini adapter supports text message content only");
    });
  }
  if (content === null || content === undefined) return [{ text: "" }];
  throw AdapterError.invalidRequest("Gemini adapter supports text message content only");
}

/** OpenAI sampling params → Gemini `generationConfig` (shared with Vertex). */
export function generationConfig(body: Json): Json | undefined {
  const config: JsonObject = {};
  copyConfig(body, config, "temperature", "temperature");
  copyConfig(body, config, "top_p", "topP");
  copyConfig(body, config, "top_k", "topK");
  copyConfig(body, config, "max_tokens", "maxOutputTokens");
  const stop = getField(body, "stop");
  if (typeof stop === "string") config["stopSequences"] = [stop];
  else if (Array.isArray(stop)) config["stopSequences"] = [...stop];
  return Object.keys(config).length > 0 ? config : undefined;
}

/**
 * `generationConfig` including the caller's structured-output requirement.
 *
 * Gemini expresses `response_format` as `responseMimeType` + `responseSchema`
 * INSIDE the generation config, so the sampling params and the output contract
 * share one object: building them separately is how the requirement got dropped
 * (issue #674). Shared with Vertex, which speaks the same body.
 */
export function structuredGenerationConfig(
  body: Json,
  providerKind: string,
): Json | undefined {
  const config = generationConfig(body);
  const structured = structuredOutputFromChatBody(body);
  if (structured === undefined) return config;
  const merged: JsonObject = isObject(config) ? { ...config } : {};
  applyStructuredOutputToGemini(merged, structured, providerKind);
  return merged;
}

function copyConfig(body: Json, config: JsonObject, source: string, target: string): void {
  const value = getField(body, source);
  if (value !== undefined) config[target] = value;
}

const trimStartMatches = (value: string, prefix: string): string =>
  value.startsWith(prefix) ? value.slice(prefix.length) : value;
const trimEndSlashes = (value: string): string => value.replace(/\/+$/, "");

function generateContentEndpoint(baseUrl: string, providerModel: string, stream: boolean): string {
  const action = stream ? "streamGenerateContent?alt=sse" : "generateContent";
  return `${trimEndSlashes(baseUrl)}/models/${trimStartMatches(providerModel, "models/")}:${action}`;
}

function batchEmbedContentsEndpoint(baseUrl: string, providerModel: string): string {
  return `${trimEndSlashes(baseUrl)}/models/${trimStartMatches(providerModel, "models/")}:batchEmbedContents`;
}

/** Extract text inputs from an OpenAI-shaped embeddings body (shared, issue #274). */
export function embeddingsTextInputs(body: Json): string[] {
  const input = getField(body, "input");
  if (typeof input === "string") return [input];
  if (Array.isArray(input)) {
    const inputs: string[] = [];
    for (const item of input) {
      if (typeof item === "string") inputs.push(item);
      else {
        throw AdapterError.invalidRequest(
          "embeddings adapter supports string or string-array input only",
        );
      }
    }
    return inputs;
  }
  throw AdapterError.invalidRequest(
    'embeddings request must include a string or string-array "input"',
  );
}

/** Build the canonical OpenAI-shaped embeddings response body (shared, issue #274). */
export function openaiEmbeddingsResponse(
  embeddings: Json[],
  model: string,
  promptTokens: number | undefined,
): Json {
  const data: Json[] = embeddings.map((embedding, index) => ({
    object: "embedding",
    index,
    embedding,
  }));
  const response: JsonObject = { object: "list", data, model };
  if (promptTokens !== undefined) {
    response["usage"] = { prompt_tokens: promptTokens, total_tokens: promptTokens };
  }
  return response;
}

/** Parse a provider embeddings response body as JSON (shared, issue #274). */
export function parseEmbeddingsResponseBody(body: Uint8Array): Json {
  const value = parseJson(body);
  if (value === undefined) {
    throw AdapterError.invalidRequest("provider embeddings response must be JSON");
  }
  return value;
}
