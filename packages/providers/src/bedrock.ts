/**
 * AWS Bedrock provider adapter — port of `bedrock.rs` (issue #172).
 *
 * Targets the Bedrock Runtime `Converse` (chat) and `InvokeModel` (Titan
 * embeddings) APIs, authenticating via SigV4 ({@link ./sigv4}). `extractHost`
 * is shared with the Vertex adapter.
 */
import { utf8 } from "./crypto.js";
import { AdapterError, BaseProviderAdapter, SecretValue } from "./types.js";
import type {
  AwsProviderCredentials,
  ChatCompletionPlan,
  EmbeddingsPlan,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
} from "./types.js";
import {
  embeddingsTextInputs,
  openaiEmbeddingsResponse,
  parseEmbeddingsResponseBody,
} from "./gemini.js";
import {
  applyStructuredOutputToBedrockConverse,
  structuredOutputFromChatBody,
} from "./structured.js";
import { applyPromptCacheToBedrockConverse, promptCacheFromBody } from "./caching.js";
import { sign } from "./sigv4.js";
import type { AwsCredentials, SigningRequest } from "./sigv4.js";
import { asStr, asU64, getField, isArray, isObject, ownBody, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";

export class BedrockAdapter extends BaseProviderAdapter {
  override kind(): string {
    return "bedrock";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const credentials = provider.awsCredentials;
    if (!credentials) {
      throw AdapterError.invalidRequest("bedrock provider is missing AWS credentials");
    }
    const body = ensureObjectBody(request.body);

    const draft: JsonObject = { messages: openaiMessagesToBedrockMessages(body) };
    const system = systemBlocks(body);
    if (system !== undefined) draft["system"] = system;
    const config = inferenceConfig(body);
    if (config !== undefined) draft["inferenceConfig"] = config;
    // Converse's shape is rebuilt block by block above, so nothing here aliases
    // the caller today — but the `apply*` helpers below take an owned body by
    // TYPE, and passing through the same boundary as every other family is what
    // keeps that true after the next field is added (issue #690).
    const bedrockBody = ownBody(draft);
    // Converse has no `response_format`; the schema becomes a forced `toolConfig`
    // tool, the Anthropic coercion in Converse's envelope (issue #674).
    const structured = structuredOutputFromChatBody(body);
    if (structured !== undefined) {
      applyStructuredOutputToBedrockConverse(bedrockBody, structured, provider.kind);
    }
    // Converse's own prefix-cache mechanism is a `cachePoint` block (#690);
    // applied after `toolConfig` exists so a tool prefix can carry it.
    const promptCache = promptCacheFromBody(body);
    if (promptCache !== undefined) {
      applyPromptCacheToBedrockConverse(bedrockBody, promptCache, provider.kind);
    }

    const path = `/model/${percentEncodePathSegment(request.providerModel)}/converse`;
    return signBedrockRequest(provider, credentials, path, bedrockBody, request.stream);
  }

  override prepareEmbeddings(
    provider: ProviderConfig,
    request: EmbeddingsPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const credentials = provider.awsCredentials;
    if (!credentials) {
      throw AdapterError.invalidRequest("bedrock provider is missing AWS credentials");
    }
    const body = ensureObjectBody(request.body);
    const inputs = embeddingsTextInputs(body);
    if (inputs.length !== 1) {
      throw AdapterError.invalidRequest("bedrock embeddings adapter supports a single string input");
    }

    const path = `/model/${percentEncodePathSegment(request.providerModel)}/invoke`;
    return signBedrockRequest(provider, credentials, path, { inputText: inputs[0]! }, false);
  }

  override translateEmbeddingsResponse(body: Uint8Array, model: string): Json | null {
    const value = parseEmbeddingsResponseBody(body);
    const embedding = getField(value, "embedding");
    const embeddings = getField(value, "embeddings");
    let vectors: Json[];
    if (isArray(embedding)) {
      vectors = [embedding];
    } else if (isArray(embeddings)) {
      vectors = embeddings;
    } else {
      throw AdapterError.invalidRequest("Bedrock embeddings response is missing an embedding vector");
    }
    const promptTokens = asU64(getField(value, "inputTextTokenCount"));
    return openaiEmbeddingsResponse(vectors, model, promptTokens);
  }

  override normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse {
    const parsed = parseJson(body);
    const message =
      asStr(getField(parsed, "message")) ??
      fallbackErrorMessage(body) ??
      `provider returned HTTP ${status}`;

    return {
      status,
      body: {
        error: {
          message,
          type: "provider_error",
          provider_type: "bedrock_error",
          code: "bedrock_error",
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
    if (usage === undefined) {
      const embeddingTokens = asU64(getField(value, "inputTextTokenCount"));
      if (embeddingTokens === undefined) return undefined;
      return {
        promptTokens: embeddingTokens,
        completionTokens: undefined,
        totalTokens: embeddingTokens,
      };
    }
    const promptTokens = asU64(getField(usage, "inputTokens"));
    const completionTokens = asU64(getField(usage, "outputTokens"));
    const totalTokens =
      asU64(getField(usage, "totalTokens")) ??
      (promptTokens !== undefined && completionTokens !== undefined
        ? promptTokens + completionTokens
        : undefined);
    const extracted: ProviderUsage = { promptTokens, completionTokens, totalTokens };
    if (
      extracted.promptTokens === undefined &&
      extracted.completionTokens === undefined &&
      extracted.totalTokens === undefined
    ) {
      return undefined;
    }
    return extracted;
  }
}

function signBedrockRequest(
  provider: ProviderConfig,
  credentials: AwsProviderCredentials,
  path: string,
  body: Json,
  stream: boolean,
): ProviderHttpRequest {
  const host = extractHost(provider.baseUrl);
  const scheme = provider.baseUrl.trimStart().startsWith("http://") ? "http" : "https";
  const endpoint = `${scheme}://${host}${path}`;
  const bodyBytes = utf8(JSON.stringify(body));

  const timestampUnix = Math.floor(Date.now() / 1000);
  const signingRequest: SigningRequest = {
    method: "POST",
    path,
    host,
    region: credentials.region,
    service: "bedrock",
    body: bodyBytes,
    timestampUnix,
  };
  const awsCredentials: AwsCredentials = {
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey.exposeSecret(),
    sessionToken: credentials.sessionToken?.exposeSecret(),
  };
  const signed = sign(signingRequest, awsCredentials);

  const headers: ProviderHeader[] = [
    { name: "content-type", value: new SecretValue("application/json") },
    { name: "host", value: new SecretValue(host) },
    { name: "x-amz-date", value: new SecretValue(signed.xAmzDate) },
    { name: "authorization", value: new SecretValue(signed.authorization) },
  ];
  if (signed.xAmzSecurityToken !== undefined) {
    headers.push({ name: "x-amz-security-token", value: new SecretValue(signed.xAmzSecurityToken) });
  }

  return { provider: provider.name, endpoint, body, stream, headers };
}

function validateKind(kind: string): void {
  if (kind !== "bedrock") throw AdapterError.unsupportedProviderKind(kind);
}

function ensureObjectBody(body: Json): JsonObject {
  if (isObject(body)) return body;
  throw AdapterError.invalidRequest("chat completion request body must be a JSON object");
}

function openaiMessagesToBedrockMessages(body: Json): Json {
  const messages = getField(body, "messages");
  if (!isArray(messages)) return [];
  const converted: Json[] = [];
  for (const message of messages) {
    const roleRaw = asStr(getField(message, "role"));
    let role: string;
    switch (roleRaw) {
      case "system":
        continue;
      case "assistant":
        role = "assistant";
        break;
      case "user":
      case undefined:
        role = "user";
        break;
      case "tool":
        role = "user";
        break;
      default:
        throw AdapterError.invalidRequest(`unsupported Bedrock message role ${roleRaw}`);
    }
    converted.push({ role, content: contentBlocks(getField(message, "content")) });
  }
  return converted;
}

function systemBlocks(body: Json): Json | undefined {
  const messages = getField(body, "messages");
  if (!isArray(messages)) return undefined;
  const blocks: Json[] = [];
  for (const message of messages) {
    if (asStr(getField(message, "role")) !== "system") continue;
    blocks.push(...contentBlocks(getField(message, "content")));
  }
  return blocks.length > 0 ? blocks : undefined;
}

function contentBlocks(content: Json | undefined): Json[] {
  if (typeof content === "string") return [{ text: content }];
  if (isArray(content)) {
    return content.map((block) => {
      if (isObject(block)) {
        if (asStr(block["type"]) === "text") return { text: asStr(block["text"]) ?? "" };
        throw AdapterError.invalidRequest(
          `unsupported Bedrock content block type ${JSON.stringify(block["type"] ?? null)}`,
        );
      }
      throw AdapterError.invalidRequest("Bedrock content blocks must be objects");
    });
  }
  if (content === null || content === undefined) return [{ text: "" }];
  throw AdapterError.invalidRequest("unsupported Bedrock message content shape");
}

function inferenceConfig(body: Json): Json | undefined {
  const config: JsonObject = {};
  copyConfig(body, config, "max_tokens", "maxTokens");
  copyConfig(body, config, "temperature", "temperature");
  copyConfig(body, config, "top_p", "topP");
  const stop = getField(body, "stop");
  if (typeof stop === "string") config["stopSequences"] = [stop];
  else if (isArray(stop)) config["stopSequences"] = [...stop];
  return Object.keys(config).length > 0 ? config : undefined;
}

function copyConfig(body: Json, config: JsonObject, source: string, target: string): void {
  const value = getField(body, source);
  if (value !== undefined) config[target] = value;
}

/** Extract `host[:port]` from a Bedrock/Vertex `base_url` (shared with Vertex). */
export function extractHost(baseUrl: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  const withoutScheme = trimmed.startsWith("https://")
    ? trimmed.slice("https://".length)
    : trimmed.startsWith("http://")
      ? trimmed.slice("http://".length)
      : trimmed;
  const host = withoutScheme.split("/")[0] ?? withoutScheme;
  if (host.length === 0) {
    throw AdapterError.invalidRequest(`bedrock provider base_url ${baseUrl} has no host`);
  }
  return host;
}

function percentEncodePathSegment(segment: string): string {
  let out = "";
  for (const byte of utf8(segment)) {
    const keep =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x5f ||
      byte === 0x2e ||
      byte === 0x7e;
    out += keep ? String.fromCharCode(byte) : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

function fallbackErrorMessage(body: Uint8Array): string | undefined {
  const text = new TextDecoder().decode(body).trim();
  if (text.length === 0) return undefined;
  return Array.from(text).slice(0, 512).join("");
}
