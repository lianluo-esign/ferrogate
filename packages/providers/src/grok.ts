/**
 * xAI Grok provider adapter — port of `grok.rs`.
 *
 * Grok speaks the OpenAI wire protocol, so this delegates to
 * {@link OpenAiCompatibleAdapter} after re-labeling the provider kind, adding
 * only the `grok`/`xai` kind gate.
 */
import { AdapterError, BaseProviderAdapter } from "./types.js";
import type {
  ChatCompletionPlan,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";
import { OpenAiCompatibleAdapter } from "./openai.js";

export class GrokAdapter extends BaseProviderAdapter {
  readonly #openaiCompatible = new OpenAiCompatibleAdapter();

  override kind(): string {
    return "grok";
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    return this.#openaiCompatible.prepareChatCompletions(
      { ...provider, kind: "openai-compatible" },
      request,
    );
  }

  override prepareResponses(
    provider: ProviderConfig,
    request: ResponsesPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    return this.#openaiCompatible.prepareResponses(
      { ...provider, kind: "openai-compatible" },
      request,
    );
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
  if (kind !== "grok" && kind !== "xai") throw AdapterError.unsupportedProviderKind(kind);
}
