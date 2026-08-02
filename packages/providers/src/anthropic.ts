/**
 * Anthropic provider adapter — port of `anthropic.rs`.
 *
 * Dispatches chat completions and Responses plans as Anthropic `/v1/messages`
 * requests (the latter via {@link CanonicalAiRequest}), and normalizes
 * errors/usage/tool-calls back to the canonical gateway shape.
 */
import type { ToolCall, ToolDef, ToolResult } from "@ferrogate/core";

import { AdapterError, BaseProviderAdapter, SecretValue } from "./types.js";
import type {
  ChatCompletionPlan,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";
import { CanonicalAiRequest } from "./canonical.js";
import { applyPromptCacheToAnthropic, promptCacheFromBody } from "./caching.js";
import { applyStructuredOutputToAnthropic, structuredOutputFromChatBody } from "./structured.js";
import { asStr, asU64, getField, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";
import { fallbackErrorMessage, hasAnyUsage } from "./openai.js";

export class AnthropicAdapter extends BaseProviderAdapter {
  override kind(): string {
    return "anthropic";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body);
    const messages = getField(body, "messages") ?? [];
    const maxTokens = getField(body, "max_tokens") ?? 1024;

    const anthropicBody: JsonObject = {
      model: request.providerModel,
      messages,
      max_tokens: maxTokens,
      stream: request.stream,
    };
    const system = getField(body, "system");
    if (system !== undefined) anthropicBody["system"] = system;
    // `response_format` has no Anthropic equivalent, so it used to be dropped
    // here while surviving to an OpenAI upstream — the failover shape change of
    // issue #674. It is now coerced into a forced tool call, or refused.
    const structured = structuredOutputFromChatBody(body);
    if (structured !== undefined) {
      applyStructuredOutputToAnthropic(anthropicBody, structured, provider.kind);
    }
    // Prompt caching (issue #690). Applied AFTER the structured-output coercion
    // so a coercion tool is inside the cached prefix rather than appended after
    // the breakpoint, where it would invalidate the cache on every request.
    const promptCache = promptCacheFromBody(body);
    if (promptCache !== undefined) {
      applyPromptCacheToAnthropic(anthropicBody, promptCache, provider.kind);
    }

    return {
      provider: provider.name,
      endpoint: messagesEndpoint(provider.baseUrl),
      body: anthropicBody,
      stream: request.stream,
      headers: anthropicHeaders(provider.apiKey),
    };
  }

  override prepareResponses(
    provider: ProviderConfig,
    request: ResponsesPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = CanonicalAiRequest.fromResponsesBody(request.body).intoAnthropicBody();
    const messages = getField(body, "messages") ?? [];
    const maxTokens = getField(body, "max_tokens") ?? 1024;

    const anthropicBody: JsonObject = {
      model: request.providerModel,
      messages,
      max_tokens: maxTokens,
      stream: request.stream,
    };
    const system = getField(body, "system");
    if (system !== undefined) anthropicBody["system"] = system;
    const tools = getField(body, "tools");
    if (tools !== undefined) anthropicBody["tools"] = tools;
    const toolChoice = getField(body, "tool_choice");
    if (toolChoice !== undefined) anthropicBody["tool_choice"] = toolChoice;

    return {
      provider: provider.name,
      endpoint: messagesEndpoint(provider.baseUrl),
      body: anthropicBody,
      stream: request.stream,
      headers: anthropicHeaders(provider.apiKey),
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
    const providerType = asStr(getField(providerError, "type")) ?? "provider_error";

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
    const usage = getField(value, "usage") ?? getField(getField(value, "message"), "usage");
    if (usage === undefined) return undefined;
    const promptTokens = asU64(getField(usage, "input_tokens"));
    const completionTokens = asU64(getField(usage, "output_tokens"));
    const totalTokens =
      promptTokens !== undefined && completionTokens !== undefined
        ? promptTokens + completionTokens
        : undefined;
    const extracted: ProviderUsage = { promptTokens, completionTokens, totalTokens };
    return hasAnyUsage(extracted) ? extracted : undefined;
  }

  override injectTools(body: Json, tools: readonly ToolDef[]): Json {
    const object = ensureObjectBody(body);
    if (tools.length === 0) return object;
    object["tools"] = tools.map((tool) => {
      const value: JsonObject = { name: tool.name, input_schema: tool.input_schema as Json };
      if (tool.description !== undefined) value["description"] = tool.description;
      return value;
    });
    return object;
  }

  override extractToolCalls(body: Uint8Array): ToolCall[] {
    const value = parseJson(body);
    if (value === undefined) {
      throw AdapterError.invalidRequest("provider response body must be JSON");
    }
    const content = getField(value, "content");
    if (!Array.isArray(content)) return [];
    const calls: ToolCall[] = [];
    for (const block of content) {
      if (asStr(getField(block, "type")) === "tool_use") {
        const canonical = anthropicToolUseToCanonical(block);
        if (canonical) calls.push(canonical);
      }
    }
    return calls;
  }

  override appendToolResults(body: Json, results: readonly ToolResult[]): Json {
    const object = ensureObjectBody(body);
    if (results.length === 0) return object;
    if (!Array.isArray(object["messages"])) object["messages"] = [];
    const messages = object["messages"] as Json[];
    messages.push({
      role: "user",
      content: results.map((result) => ({
        type: "tool_result",
        tool_use_id: result.tool_call_id,
        content: toolResultContentToString(result.content as Json),
        is_error: result.is_error,
      })),
    });
    return object;
  }
}

function anthropicHeaders(apiKey: string | undefined): ProviderHeader[] {
  const headers: ProviderHeader[] = [
    { name: "content-type", value: new SecretValue("application/json") },
    { name: "anthropic-version", value: new SecretValue("2023-06-01") },
  ];
  if (apiKey !== undefined && apiKey.trim().length > 0) {
    headers.push({ name: "x-api-key", value: new SecretValue(apiKey) });
  }
  return headers;
}

function validateKind(kind: string): void {
  if (kind !== "anthropic") throw AdapterError.unsupportedProviderKind(kind);
}

function ensureObjectBody(body: Json): JsonObject {
  if (isObject(body)) return body;
  throw AdapterError.invalidRequest("chat completion request body must be a JSON object");
}

const trimEndSlashes = (value: string): string => value.replace(/\/+$/, "");
const messagesEndpoint = (baseUrl: string): string => `${trimEndSlashes(baseUrl)}/messages`;

function anthropicToolUseToCanonical(value: Json): ToolCall | undefined {
  const id = asStr(getField(value, "id"));
  const name = asStr(getField(value, "name"));
  if (id === undefined || name === undefined) return undefined;
  return { id, name, arguments: getField(value, "input") ?? null };
}

const toolResultContentToString = (value: Json): string =>
  typeof value === "string" ? value : JSON.stringify(value);
