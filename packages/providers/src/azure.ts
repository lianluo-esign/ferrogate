/**
 * Azure OpenAI provider adapter — port of `azure.rs`.
 *
 * Azure carries the deployment in the URL (not the body `model`) and
 * authenticates with an `api-key` header. The `api-version` is read from the
 * `base_url` query string, defaulting to {@link DEFAULT_API_VERSION}.
 */

import { asStr, asU64, getField, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";
import { fallbackErrorMessage, hasAnyUsage, requestOpenaiStreamUsage } from "./openai.js";
import { AdapterError, BaseProviderAdapter, SecretValue } from "./types.js";
import type {
  ChatCompletionPlan,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
} from "./types.js";

const DEFAULT_API_VERSION = "2024-10-21";

export class AzureOpenAiAdapter extends BaseProviderAdapter {
  override kind(): string {
    return "azure-openai";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body);
    // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
    delete body.model;
    body.stream = request.stream;
    if (request.stream) requestOpenaiStreamUsage(body);

    const headers: ProviderHeader[] = [
      { name: "content-type", value: new SecretValue("application/json") },
    ];
    if (provider.apiKey !== undefined && provider.apiKey.trim().length > 0) {
      headers.push({ name: "api-key", value: new SecretValue(provider.apiKey) });
    }

    return {
      provider: provider.name,
      endpoint: chatCompletionsEndpoint(provider.baseUrl, request.providerModel),
      body,
      stream: request.stream,
      headers,
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
    const codeRaw = asStr(getField(providerError, "code"));
    const code = codeRaw !== undefined && codeRaw.trim().length > 0 ? codeRaw : "provider_error";

    return {
      status,
      body: {
        error: {
          message,
          type: "provider_error",
          provider_type: code,
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
}

function validateKind(kind: string): void {
  if (kind !== "azure-openai" && kind !== "azure") throw AdapterError.unsupportedProviderKind(kind);
}

function ensureObjectBody(body: Json): JsonObject {
  if (isObject(body)) return body;
  throw AdapterError.invalidRequest("chat completion request body must be a JSON object");
}

function chatCompletionsEndpoint(baseUrl: string, deployment: string): string {
  const [endpoint, apiVersion] = splitBaseUrlApiVersion(baseUrl);
  return `${endpoint.replace(/\/+$/, "")}/openai/deployments/${encodePathSegment(deployment)}/chat/completions?api-version=${apiVersion}`;
}

function splitBaseUrlApiVersion(baseUrl: string): [string, string] {
  const queryIndex = baseUrl.indexOf("?");
  if (queryIndex < 0) return [baseUrl, DEFAULT_API_VERSION];
  const endpoint = baseUrl.slice(0, queryIndex);
  const query = baseUrl.slice(queryIndex + 1);
  let apiVersion: string | undefined;
  for (const pair of query.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    if (pair.slice(0, eq) === "api-version") {
      const value = pair.slice(eq + 1);
      if (value.trim().length > 0) {
        apiVersion = value;
        break;
      }
    }
  }
  return [endpoint, apiVersion ?? DEFAULT_API_VERSION];
}

function encodePathSegment(value: string): string {
  let encoded = "";
  for (const byte of new TextEncoder().encode(value)) {
    const keep =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x5f ||
      byte === 0x2e ||
      byte === 0x7e;
    encoded += keep
      ? String.fromCharCode(byte)
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}
