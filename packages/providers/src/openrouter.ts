/**
 * OpenRouter provider adapter — port of `openrouter.rs`.
 *
 * Delegates to {@link OpenAiCompatibleAdapter}, then injects OpenRouter's
 * `http-referer`/`x-title` attribution headers and strips the `stream_options`
 * opt-in (OpenRouter includes usage automatically and has deprecated it).
 */

import { isObject } from "./json.js";
import { OpenAiCompatibleAdapter } from "./openai.js";
import { AdapterError, BaseProviderAdapter, SecretValue } from "./types.js";
import type {
  ChatCompletionPlan,
  ProviderCatalogModel,
  ProviderCatalogRequest,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";

export class OpenRouterAdapter extends BaseProviderAdapter {
  readonly #openaiCompatible = new OpenAiCompatibleAdapter();

  override kind(): string {
    return "openrouter";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const headers = openrouterHeaders(provider);
    const stream = request.stream;
    const prepared = this.#openaiCompatible.prepareChatCompletions(
      { ...provider, kind: "openai-compatible" },
      request,
    );
    if (stream && isObject(prepared.body)) {
      // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
      delete prepared.body.stream_options;
    }
    prepared.headers.push(...headers);
    return prepared;
  }

  override prepareResponses(provider: ProviderConfig, request: ResponsesPlan): ProviderHttpRequest {
    validateKind(provider.kind);
    const headers = openrouterHeaders(provider);
    const prepared = this.#openaiCompatible.prepareResponses(
      { ...provider, kind: "openai-compatible" },
      request,
    );
    prepared.headers.push(...headers);
    return prepared;
  }

  override prepareModelCatalog(provider: ProviderConfig): ProviderCatalogRequest {
    validateKind(provider.kind);
    const headers = openrouterHeaders(provider);
    const prepared = this.#openaiCompatible.prepareModelCatalog({
      ...provider,
      kind: "openai-compatible",
    });
    prepared.headers.push(...headers);
    return prepared;
  }

  override parseModelCatalog(body: Uint8Array): ProviderCatalogModel[] {
    return this.#openaiCompatible.parseModelCatalog(body);
  }

  override normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse {
    return this.#openaiCompatible.normalizeErrorResponse(status, contentType, body, requestId);
  }

  override extractUsage(body: Uint8Array): ProviderUsage | undefined {
    return this.#openaiCompatible.extractUsage(body);
  }
}

function validateKind(kind: string): void {
  if (kind !== "openrouter") throw AdapterError.unsupportedProviderKind(kind);
}

function openrouterHeaders(provider: ProviderConfig): ProviderHeader[] {
  const headers: ProviderHeader[] = [];
  const referer = nonEmptyHeaderValue(provider.openrouterHttpReferer);
  if (referer !== undefined) {
    headers.push({ name: "http-referer", value: new SecretValue(referer) });
  }
  const title = nonEmptyHeaderValue(provider.openrouterXTitle);
  if (title !== undefined) {
    headers.push({ name: "x-title", value: new SecretValue(title) });
  }
  return headers;
}

function nonEmptyHeaderValue(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}
