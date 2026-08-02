/**
 * Google Vertex AI provider adapter — port of `vertex.rs` (issue #172).
 *
 * Targets the Gemini-on-Vertex `generateContent`/`streamGenerateContent` and
 * `:predict` (embeddings) REST endpoints, authenticating with a pre-minted GCP
 * OAuth2 Bearer token. Reuses the Gemini request-shaping/normalization helpers.
 */
import { AdapterError, BaseProviderAdapter, SecretValue } from "./types.js";
import type {
  ChatCompletionPlan,
  EmbeddingsPlan,
  GcpProviderCredentials,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
} from "./types.js";
import { extractHost } from "./bedrock.js";
import {
  ensureObjectBody,
  embeddingsTextInputs,
  GeminiAdapter,
  openaiEmbeddingsResponse,
  openaiMessagesToGeminiContents,
  parseEmbeddingsResponseBody,
  structuredGenerationConfig,
  systemInstruction,
} from "./gemini.js";
import { asU64, getField, isArray, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";

const gemini = new GeminiAdapter();

export class VertexAiAdapter extends BaseProviderAdapter {
  override kind(): string {
    return "vertex";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const credentials = provider.gcpCredentials;
    if (!credentials) {
      throw AdapterError.invalidRequest("vertex provider is missing GCP credentials");
    }
    const body = ensureObjectBody(request.body);

    const vertexBody: JsonObject = { contents: openaiMessagesToGeminiContents(body) };
    const instruction = systemInstruction(body);
    if (instruction !== undefined) vertexBody["systemInstruction"] = instruction;
    // Gemini-on-Vertex speaks the same body, so it inherits the structured
    // output translation (`responseMimeType`/`responseSchema`) unchanged (#674).
    const config = structuredGenerationConfig(body, provider.kind);
    if (config !== undefined) vertexBody["generationConfig"] = config;

    const endpoint = generateContentEndpoint(
      provider.baseUrl,
      credentials,
      request.providerModel,
      request.stream,
    );

    return {
      provider: provider.name,
      endpoint,
      body: vertexBody,
      stream: request.stream,
      headers: vertexHeaders(credentials.accessToken),
    };
  }

  override prepareEmbeddings(
    provider: ProviderConfig,
    request: EmbeddingsPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const credentials = provider.gcpCredentials;
    if (!credentials) {
      throw AdapterError.invalidRequest("vertex provider is missing GCP credentials");
    }
    const body = ensureObjectBody(request.body);
    const inputs = embeddingsTextInputs(body);
    const instances: Json[] = inputs.map((text) => ({ content: text }));
    const endpoint = predictEndpoint(provider.baseUrl, credentials, request.providerModel);

    return {
      provider: provider.name,
      endpoint,
      body: { instances },
      stream: false,
      headers: vertexHeaders(credentials.accessToken),
    };
  }

  override translateEmbeddingsResponse(body: Uint8Array, model: string): Json | null {
    const value = parseEmbeddingsResponseBody(body);
    const predictions = getField(value, "predictions");
    if (!isArray(predictions)) {
      throw AdapterError.invalidRequest("Vertex embeddings response is missing a predictions array");
    }
    const vectors: Json[] = [];
    let tokenTotal = 0;
    let sawTokens = false;
    for (const prediction of predictions) {
      const embeddings = getField(prediction, "embeddings");
      vectors.push(getField(embeddings, "values") ?? []);
      const tokens = asU64(getField(getField(embeddings, "statistics"), "token_count"));
      if (tokens !== undefined) {
        tokenTotal += tokens;
        sawTokens = true;
      }
    }
    return openaiEmbeddingsResponse(vectors, model, sawTokens ? tokenTotal : undefined);
  }

  override normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse {
    // Vertex's Gemini-model error envelope matches the public Gemini API.
    return gemini.normalizeErrorResponse(status, contentType, body, requestId);
  }

  override extractUsage(body: Uint8Array): ProviderUsage | undefined {
    return gemini.extractUsage(body) ?? vertexEmbeddingsUsage(body);
  }
}

function vertexEmbeddingsUsage(body: Uint8Array): ProviderUsage | undefined {
  const value = parseJson(body);
  if (value === undefined) return undefined;
  const predictions = getField(value, "predictions");
  if (!isArray(predictions)) return undefined;
  let total = 0;
  let sawTokens = false;
  for (const prediction of predictions) {
    const tokens = asU64(
      getField(getField(getField(prediction, "embeddings"), "statistics"), "token_count"),
    );
    if (tokens !== undefined) {
      total += tokens;
      sawTokens = true;
    }
  }
  if (!sawTokens) return undefined;
  return { promptTokens: total, completionTokens: undefined, totalTokens: total };
}

function validateKind(kind: string): void {
  if (kind !== "vertex" && kind !== "vertex-ai") throw AdapterError.unsupportedProviderKind(kind);
}

function vertexHeaders(accessToken: SecretValue): ProviderHeader[] {
  return [
    { name: "content-type", value: new SecretValue("application/json") },
    { name: "authorization", value: new SecretValue(`Bearer ${accessToken.exposeSecret()}`) },
  ];
}

const trimStartMatches = (value: string, prefix: string): string =>
  value.startsWith(prefix) ? value.slice(prefix.length) : value;

const stripModelPrefixes = (providerModel: string): string =>
  trimStartMatches(
    trimStartMatches(providerModel, "publishers/google/models/"),
    "models/",
  );

function generateContentEndpoint(
  baseUrl: string,
  credentials: GcpProviderCredentials,
  providerModel: string,
  stream: boolean,
): string {
  const host = extractHost(baseUrl);
  const scheme = baseUrl.trimStart().startsWith("http://") ? "http" : "https";
  const action = stream ? "streamGenerateContent?alt=sse" : "generateContent";
  const model = stripModelPrefixes(providerModel);
  return `${scheme}://${host}/v1/projects/${credentials.projectId}/locations/${credentials.location}/publishers/google/models/${model}:${action}`;
}

function predictEndpoint(
  baseUrl: string,
  credentials: GcpProviderCredentials,
  providerModel: string,
): string {
  const host = extractHost(baseUrl);
  const scheme = baseUrl.trimStart().startsWith("http://") ? "http" : "https";
  const model = stripModelPrefixes(providerModel);
  return `${scheme}://${host}/v1/projects/${credentials.projectId}/locations/${credentials.location}/publishers/google/models/${model}:predict`;
}
