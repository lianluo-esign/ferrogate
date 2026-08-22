/**
 * Google Gemini provider adapter — port of `gemini.rs`.
 *
 * Translates OpenAI-shaped chat/responses/embeddings requests into Gemini's
 * `generateContent`/`streamGenerateContent`/`batchEmbedContents` wire shapes and
 * normalizes the embedding response back to the OpenAI envelope. The exported
 * helpers (`openaiMessagesToGeminiContents`, `embeddingsTextInputs`,
 * `openaiEmbeddingsResponse`, …) are re-used by the Vertex and Bedrock adapters.
 */

import { assertPromptCacheForAutomaticFamily } from "./caching.js";
import { CanonicalAiRequest } from "./canonical.js";
import { asI64, asStr, asU64, getField, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";
import { fallbackErrorMessage, hasAnyUsage } from "./openai.js";
import { applyStructuredOutputToGemini, structuredOutputFromChatBody } from "./structured.js";
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
    if (instruction !== undefined) geminiBody.systemInstruction = instruction;
    const config = structuredGenerationConfig(body, provider.kind);
    if (config !== undefined) geminiBody.generationConfig = config;
    const tools = openaiToolsToGemini(body);
    if (tools !== undefined) geminiBody.tools = tools;
    const toolConfig = openaiToolChoiceToGemini(body);
    if (toolConfig !== undefined) geminiBody.toolConfig = toolConfig;

    return {
      provider: provider.name,
      endpoint: generateContentEndpoint(provider.baseUrl, request.providerModel, request.stream),
      body: geminiBody,
      stream: request.stream,
      headers: geminiHeaders(provider.apiKey),
    };
  }

  override prepareResponses(provider: ProviderConfig, request: ResponsesPlan): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = CanonicalAiRequest.fromResponsesBody(request.body).intoGeminiBody();

    const geminiBody: JsonObject = { contents: getField(body, "contents") ?? [] };
    const instruction = getField(body, "systemInstruction");
    if (instruction !== undefined) geminiBody.systemInstruction = instruction;
    const config = getField(body, "generationConfig");
    if (config !== undefined) geminiBody.generationConfig = config;
    const tools = getField(body, "tools");
    if (tools !== undefined) geminiBody.tools = tools;
    const toolConfig = getField(body, "toolConfig");
    if (toolConfig !== undefined) geminiBody.toolConfig = toolConfig;

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
      throw AdapterError.invalidRequest(
        "Gemini embeddings response is missing an embeddings array",
      );
    }
    const vectors = embeddings.map((entry) => getField(entry, "values") ?? []);
    return openaiEmbeddingsResponse(vectors, model, undefined);
  }

  override translateChatCompletionResponse(body: Uint8Array, model: string): Json | null {
    const value = parseJson(body);
    if (!isObject(value)) return null;
    const candidates = getField(value, "candidates");
    if (!Array.isArray(candidates)) return null;

    const toolCallIds = new Set<string>();
    const choices: Json[] = candidates.map((candidate, candidateIndex) => {
      const content = getField(candidate, "content");
      const parts = getField(content, "parts");
      const text: string[] = [];
      const reasoning: string[] = [];
      const toolCalls: Json[] = [];
      let reasoningSignature: string | undefined;
      let textSignature: string | undefined;
      for (const [partIndex, part] of (Array.isArray(parts) ? parts : []).entries()) {
        const partText = asStr(getField(part, "text"));
        const thought = getField(part, "thought") === true;
        const partSignature = asStr(getField(part, "thoughtSignature"));
        if (partSignature !== undefined) {
          if (thought) reasoningSignature = partSignature;
          else if (partText !== undefined) textSignature = partSignature;
        }
        if (partText !== undefined) {
          if (thought) reasoning.push(partText);
          else text.push(partText);
        }
        const functionCall = getField(part, "functionCall");
        const name = asStr(getField(functionCall, "name"));
        if (name !== undefined) {
          const id = uniqueToolCallId(
            toolCallIds,
            asStr(getField(functionCall, "id")),
            `call_${candidateIndex}_${partIndex}`,
          );
          toolCalls.push({
            id,
            type: "function",
            function: {
              name,
              arguments: JSON.stringify(getField(functionCall, "args") ?? {}),
            },
            ...(partSignature === undefined ? {} : { thought_signature: partSignature }),
          });
        }
      }
      const message: JsonObject = {
        role: "assistant",
        content: text.length === 0 ? null : text.join(""),
      };
      if (reasoning.length > 0) message.reasoning_content = reasoning.join("");
      if (reasoningSignature !== undefined) message.reasoning_signature = reasoningSignature;
      if (textSignature !== undefined) message.text_signature = textSignature;
      if (toolCalls.length > 0) message.tool_calls = toolCalls;
      return {
        index: candidateIndex,
        message,
        finish_reason:
          toolCalls.length > 0
            ? "tool_calls"
            : geminiFinishReason(asStr(getField(candidate, "finishReason"))),
      };
    });

    const usageMetadata = getField(value, "usageMetadata");
    const usage = geminiChatUsage(usageMetadata);
    return {
      id: asStr(getField(value, "responseId")) ?? "chatcmpl_ferrogate",
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: asStr(getField(value, "modelVersion")) ?? model,
      choices,
      ...(usage === undefined ? {} : { usage }),
    };
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
    const visibleOutputTokens = asU64(getField(usage, "candidatesTokenCount"));
    const reasoningTokens = asU64(getField(usage, "thoughtsTokenCount"));
    const extracted: ProviderUsage = {
      promptTokens: asU64(getField(usage, "promptTokenCount")),
      completionTokens:
        visibleOutputTokens === undefined
          ? reasoningTokens
          : visibleOutputTokens + (reasoningTokens ?? 0),
      totalTokens: asU64(getField(usage, "totalTokenCount")),
    };
    return hasAnyUsage(extracted) ? extracted : undefined;
  }
}

function geminiFinishReason(reason: string | undefined): string {
  switch (reason) {
    case "MAX_TOKENS":
      return "length";
    case "SAFETY":
    case "RECITATION":
    case "PROHIBITED_CONTENT":
    case "BLOCKLIST":
    case "SPII":
    case "IMAGE_SAFETY":
      return "content_filter";
    default:
      return "stop";
  }
}

function geminiChatUsage(value: Json | undefined): JsonObject | undefined {
  if (!isObject(value)) return undefined;
  const promptTokens = asU64(getField(value, "promptTokenCount"));
  const visibleOutputTokens = asU64(getField(value, "candidatesTokenCount"));
  const reasoningTokens = asU64(getField(value, "thoughtsTokenCount"));
  const completionTokens =
    visibleOutputTokens === undefined
      ? reasoningTokens
      : visibleOutputTokens + (reasoningTokens ?? 0);
  const totalTokens =
    asU64(getField(value, "totalTokenCount")) ??
    (promptTokens !== undefined && completionTokens !== undefined
      ? promptTokens + completionTokens
      : undefined);
  const cachedTokens = asU64(getField(value, "cachedContentTokenCount"));
  const usage: JsonObject = {};
  if (promptTokens !== undefined) usage.prompt_tokens = promptTokens;
  if (completionTokens !== undefined) usage.completion_tokens = completionTokens;
  if (totalTokens !== undefined) usage.total_tokens = totalTokens;
  if (cachedTokens !== undefined) usage.prompt_tokens_details = { cached_tokens: cachedTokens };
  if (reasoningTokens !== undefined) {
    usage.completion_tokens_details = { reasoning_tokens: reasoningTokens };
  }
  return Object.keys(usage).length === 0 ? undefined : usage;
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
  const toolNames = new Map<string, string>();
  for (const message of messages) {
    const roleRaw = asStr(getField(message, "role"));
    if (roleRaw === "system") continue;

    if (roleRaw === "tool") {
      const id = asStr(getField(message, "tool_call_id")) ?? "";
      const name = toolNames.get(id) ?? asStr(getField(message, "name")) ?? id;
      const result = toolResultText(getField(message, "content"));
      const part: Json = {
        functionResponse: { name, response: { output: result }, ...(id === "" ? {} : { id }) },
      };
      const previous = contents[contents.length - 1];
      const previousParts = getField(previous, "parts");
      if (
        asStr(getField(previous, "role")) === "user" &&
        Array.isArray(previousParts) &&
        previousParts.some((entry) => getField(entry, "functionResponse") !== undefined)
      ) {
        previousParts.push(part);
      } else {
        contents.push({ role: "user", parts: [part] });
      }
      continue;
    }

    if (roleRaw !== "assistant" && roleRaw !== "user" && roleRaw !== undefined) {
      throw AdapterError.invalidRequest(`unsupported Gemini message role ${roleRaw}`);
    }
    const parts = contentParts(getField(message, "content"));
    if (roleRaw === "assistant") {
      const reasoning = asStr(getField(message, "reasoning_content"));
      const reasoningSignature = asStr(getField(message, "reasoning_signature"));
      const textSignature = asStr(getField(message, "text_signature"));
      if (textSignature !== undefined) {
        const textPart = [...parts].reverse().find((part) => getField(part, "text") !== undefined);
        if (isObject(textPart)) textPart.thoughtSignature = textSignature;
        else parts.push({ text: "", thoughtSignature: textSignature });
      }
      if ((reasoning !== undefined && reasoning.length > 0) || reasoningSignature !== undefined) {
        parts.push({
          thought: true,
          text: reasoning ?? "",
          ...(reasoningSignature === undefined ? {} : { thoughtSignature: reasoningSignature }),
        });
      }
      for (const toolCall of Array.isArray(getField(message, "tool_calls"))
        ? (getField(message, "tool_calls") as Json[])
        : []) {
        const fn = getField(toolCall, "function");
        const id = asStr(getField(toolCall, "id")) ?? "";
        const name = asStr(getField(fn, "name")) ?? "";
        if (id !== "") toolNames.set(id, name);
        const signature =
          asStr(getField(toolCall, "thought_signature")) ??
          asStr(getField(toolCall, "thoughtSignature"));
        parts.push({
          functionCall: {
            name,
            args: parseToolArguments(getField(fn, "arguments")),
            ...(id === "" ? {} : { id }),
          },
          ...(signature === undefined ? {} : { thoughtSignature: signature }),
        });
      }
    }
    if (parts.length > 0)
      contents.push({ role: roleRaw === "assistant" ? "model" : "user", parts });
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
      if (isObject(block) && (asStr(block.type) === "text" || asStr(block.type) === "input_text")) {
        return { text: asStr(block.text) ?? "" };
      }
      if (isObject(block) && (asStr(block.type) === "image_url" || asStr(block.type) === "image")) {
        const image = getField(block, "image_url") ?? getField(block, "url");
        const url = typeof image === "string" ? image : asStr(getField(image, "url"));
        if (url !== undefined) return geminiImagePart(url);
      }
      if (typeof block === "string") return { text: block };
      throw AdapterError.invalidRequest(
        "Gemini adapter supports text and image message content only",
      );
    });
  }
  if (content === null || content === undefined) return [];
  throw AdapterError.invalidRequest("Gemini adapter supports text and image message content only");
}

function geminiImagePart(url: string): Json {
  if (!url.startsWith("data:")) return { fileData: { fileUri: url } };
  const comma = url.indexOf(",");
  if (comma < 0) throw AdapterError.invalidRequest("Gemini image data URL is malformed");
  const meta = url.slice("data:".length, comma);
  return {
    inlineData: {
      mimeType: meta.split(";")[0] || "image/png",
      data: url.slice(comma + 1),
    },
  };
}

function parseToolArguments(value: Json | undefined): Json {
  if (typeof value !== "string") return value ?? {};
  return parseJson(new TextEncoder().encode(value)) ?? {};
}

function uniqueToolCallId(
  ids: Set<string>,
  provided: string | undefined,
  fallback: string,
): string {
  let candidate = provided ?? fallback;
  let suffix = 1;
  while (ids.has(candidate)) {
    candidate = `${fallback}_${suffix}`;
    suffix += 1;
  }
  ids.add(candidate);
  return candidate;
}

function toolResultText(value: Json | undefined): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map((entry) => asStr(getField(entry, "text")) ?? JSON.stringify(entry)).join("\n");
  }
  return value === undefined || value === null ? "" : JSON.stringify(value);
}

function openaiToolsToGemini(body: Json): Json | undefined {
  const tools = getField(body, "tools");
  if (!Array.isArray(tools) || tools.length === 0) return undefined;
  const declarations: Json[] = [];
  for (const tool of tools) {
    const fn = getField(tool, "function") ?? tool;
    const name = asStr(getField(fn, "name"));
    if (name === undefined || name.trim() === "") continue;
    const declaration: JsonObject = {
      name,
      parameters: getField(fn, "parameters") ?? getField(fn, "input_schema") ?? { type: "object" },
    };
    const description = asStr(getField(fn, "description"));
    if (description !== undefined) declaration.description = description;
    declarations.push(declaration);
  }
  return declarations.length === 0 ? undefined : [{ functionDeclarations: declarations }];
}

function openaiToolChoiceToGemini(body: Json): Json | undefined {
  const choice = getField(body, "tool_choice");
  if (choice === undefined) return undefined;
  if (choice === "auto") return { functionCallingConfig: { mode: "AUTO" } };
  if (choice === "none") return { functionCallingConfig: { mode: "NONE" } };
  if (choice === "required") return { functionCallingConfig: { mode: "ANY" } };
  const fn = getField(choice, "function");
  const name = asStr(getField(fn, "name") ?? getField(choice, "name"));
  return name === undefined
    ? undefined
    : { functionCallingConfig: { mode: "ANY", allowedFunctionNames: [name] } };
}

/** OpenAI sampling params → Gemini `generationConfig` (shared with Vertex). */
export function generationConfig(body: Json): Json | undefined {
  const config: JsonObject = {};
  copyConfig(body, config, "temperature", "temperature");
  copyConfig(body, config, "top_p", "topP");
  copyConfig(body, config, "top_k", "topK");
  copyConfig(body, config, "max_tokens", "maxOutputTokens");
  const stop = getField(body, "stop");
  if (typeof stop === "string") config.stopSequences = [stop];
  else if (Array.isArray(stop)) config.stopSequences = [...stop];
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
export function structuredGenerationConfig(body: Json, providerKind: string): Json | undefined {
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
    response.usage = { prompt_tokens: promptTokens, total_tokens: promptTokens };
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
