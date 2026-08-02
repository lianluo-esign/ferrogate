/**
 * Workers AI provider adapter — the NINTH family (issue #673).
 *
 * Unlike the other eight this one has no Rust ancestor: `ferrogate-providers`
 * never had a Workers AI family, because a Rust process has no `env.AI`. It is
 * written against the same `ProviderAdapter` trait all the same, so nothing
 * downstream special-cases it — `packageProviderAdapter()` wraps it exactly
 * like `GeminiAdapter`, and the handler, the failover ladder, the usage meter
 * and the response cache see a request shaped like everyone else's.
 *
 * ## The endpoint is a REAL URL, not a sentinel
 *
 * Every prepared request addresses Workers AI's REST run surface,
 * `POST {base_url}/run/{model}` where `base_url` is
 * `https://api.cloudflare.com/client/v4/accounts/<account_id>/ai` — the same
 * path `@ferrogate/guardrails`' `cloudflareRestWorkersAiClient` uses for
 * Llama Guard. Two things follow, and both are deliberate:
 *
 *  1. `dispatch.rs`'s `parse_provider_endpoint` guard (http/https only) passes
 *     on it, so the family needs no exemption from a gateway-policy check.
 *  2. The gateway's binding dispatcher recognises that path and serves it
 *     through `env.AI` instead, with no socket and no egress — but the request
 *     it short-circuits is a request that would have WORKED over the network,
 *     so the two legs cannot silently disagree about what was asked.
 *
 * ## Bodies are Workers AI NATIVE, and the responses are translated back
 *
 * Workers AI's run surface is task-shaped, not OpenAI-shaped: text generation
 * takes `{ messages }` and answers `{ response, usage }`; text embeddings take
 * `{ text }` and answer `{ shape, data }`. So this adapter emits the native
 * input, and the OpenAI-shaped answer the gateway contract owes the client is
 * rebuilt on the way out — {@link translateEmbeddingsResponse} here (the trait's
 * existing seam, the same one `gemini.rs` and `vertex.rs` use), and, for chat,
 * in the gateway's binding dispatcher, which is the only place that holds the
 * response at all.
 *
 * Choosing Workers AI's OpenAI-compatible REST surface (`/ai/v1/chat/
 * completions`) instead would have made the translation unnecessary — and would
 * also have made the binding unusable, because the binding exposes `run()`, not
 * that surface. The whole point of the issue is to stop paying egress, so the
 * native surface wins and the translation is the price.
 */
import type { ToolCall, ToolDef, ToolResult } from "@ferrogate/core";

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
import { asStr, asU64, getField, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";
import { embeddingsTextInputs, openaiEmbeddingsResponse } from "./gemini.js";
import { fallbackErrorMessage, hasAnyUsage } from "./openai.js";

/** The canonical `kind` string for this family. */
export const WORKERS_AI_KIND = "workers-ai";

/**
 * The path segment that marks a prepared request as a Workers AI run call.
 * Exported because the gateway's dispatcher matches on it — keeping the literal
 * in one place is what stops the adapter and the dispatcher drifting apart.
 */
export const WORKERS_AI_RUN_PATH_SEGMENT = "/ai/run/";

export class WorkersAiAdapter extends BaseProviderAdapter {
  override kind(): string {
    return WORKERS_AI_KIND;
  }

  override prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body, "chat completion request body");
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: textGenerationInput(body, request.stream),
      stream: request.stream,
      headers: workersAiHeaders(provider.apiKey),
    };
  }

  /**
   * `/v1/responses` reaches Workers AI through the SAME canonicalizer the
   * Anthropic adapter uses: `CanonicalAiRequest` folds the Responses grammar
   * (`input`, `instructions`, `tools`) down to a chat body, which is then shaped
   * exactly as {@link prepareChatCompletions} shapes one. Writing a second
   * Responses→native translation here would be the duplication the port rules
   * forbid, and it would drift.
   *
   * `intoChatBodyWithSystemMessage` — not the `system`-FIELD emitter — because
   * Workers AI has no top-level `system` key: `instructions` has to arrive as a
   * leading `role: "system"` message or it is silently dropped.
   */
  override prepareResponses(
    provider: ProviderConfig,
    request: ResponsesPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const canonical = CanonicalAiRequest.fromResponsesBody(
      request.body,
    ).intoChatBodyWithSystemMessage();
    const body = ensureObjectBody(canonical, "responses request body");
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: textGenerationInput(body, request.stream),
      stream: request.stream,
      headers: workersAiHeaders(provider.apiKey),
    };
  }

  /**
   * Workers AI text-embedding models take `{ text: [...] }`, not OpenAI's
   * `{ input }`. `embeddingsTextInputs` is the shared extractor the Gemini and
   * Vertex adapters already use, so the accepted client grammar (a string or a
   * string array, nothing else) is identical across all three.
   */
  override prepareEmbeddings(
    provider: ProviderConfig,
    request: EmbeddingsPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body, "embeddings request body");
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: { text: embeddingsTextInputs(body) },
      stream: false,
      headers: workersAiHeaders(provider.apiKey),
    };
  }

  /**
   * `{ shape, data: [[...]] }` → the OpenAI embeddings list.
   *
   * Both envelopes are accepted: the BINDING hands back the already-unwrapped
   * result, while the REST surface wraps it in Cloudflare's
   * `{ result, success, errors }`. Accepting either means the same adapter
   * serves a binding-backed and a token-backed deployment without a flag.
   *
   * Workers AI reports no token count for embeddings, so `promptTokens` is
   * `undefined` and the response carries no `usage` — the same thing
   * `gemini.rs` does for `batchEmbedContents`, and honest: a fabricated zero
   * would be metered as a real reading.
   */
  override translateEmbeddingsResponse(body: Uint8Array, model: string): Json | null {
    const parsed = parseJson(body);
    if (parsed === undefined) {
      throw AdapterError.invalidRequest("provider embeddings response must be JSON");
    }
    const result = unwrapCloudflareEnvelope(parsed);
    const data = getField(result, "data");
    if (!Array.isArray(data)) {
      throw AdapterError.invalidRequest(
        "workers ai embeddings response is missing a data array",
      );
    }
    return openaiEmbeddingsResponse(data as Json[], model, undefined);
  }

  /**
   * Cloudflare's API error envelope is `{ errors: [{ code, message }] }` —
   * neither OpenAI's `{ error: { message, type } }` nor Anthropic's. The
   * client-visible shape is still the gateway's canonical one; only the place
   * the message is read from differs.
   */
  override normalizeErrorResponse(
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse {
    const parsed = parseJson(body);
    const errors = getField(parsed, "errors");
    const first = Array.isArray(errors) ? errors[0] : undefined;
    const message =
      asStr(getField(first, "message")) ??
      asStr(getField(getField(parsed, "error"), "message")) ??
      fallbackErrorMessage(parsed, body) ??
      `provider returned HTTP ${status}`;
    // Cloudflare error codes are integers (e.g. 7003, 3036). They are rendered
    // as `cloudflare_<code>` so the client-visible `code` stays a string, which
    // is what every other family puts there.
    const code = asU64(getField(first, "code"));
    const providerType = code === undefined ? "provider_error" : `cloudflare_${code}`;

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

  /**
   * Workers AI reports OpenAI-NAMED counters (`prompt_tokens` /
   * `completion_tokens` / `total_tokens`), so the shape matches
   * `openai.rs::extract_usage` — but it may arrive at the top level (binding,
   * and the chat completion this family's dispatcher rebuilds) or nested under
   * the REST envelope's `result`. Both are read, because a family that scraped
   * nothing would be metered at the 512-token fallback estimate, which is the
   * token-budget bypass `inference/usage.ts` exists to prevent.
   */
  override extractUsage(body: Uint8Array): ProviderUsage | undefined {
    const value = parseJson(body);
    if (value === undefined) return undefined;
    const usage = getField(value, "usage") ?? getField(getField(value, "result"), "usage");
    if (usage === undefined) return undefined;
    const extracted: ProviderUsage = {
      promptTokens: asU64(getField(usage, "prompt_tokens")),
      completionTokens: asU64(getField(usage, "completion_tokens")),
      totalTokens: asU64(getField(usage, "total_tokens")),
    };
    return hasAnyUsage(extracted) ? extracted : undefined;
  }

  /**
   * Workers AI function calling takes OpenAI's `tools` array verbatim
   * (`{ type: "function", function: { name, description, parameters } }`), so
   * this is the OpenAI injection, not a second grammar.
   */
  override injectTools(body: Json, tools: readonly ToolDef[]): Json {
    const object = ensureObjectBody(body, "chat completion request body");
    if (tools.length === 0) return object;
    object["tools"] = tools.map((tool) => {
      const fn: JsonObject = { name: tool.name, parameters: tool.input_schema as Json };
      if (tool.description !== undefined) fn["description"] = tool.description;
      return { type: "function", function: fn };
    });
    return object;
  }

  /**
   * A Workers AI text-generation answer puts calls in a TOP-LEVEL `tool_calls`
   * array (`{ name, arguments }`) — not under `choices[].message`, and with no
   * per-call id, because the run surface has no notion of one. The canonical
   * `ToolCall.id` is synthesized positionally so `appendToolResults` can refer
   * back to it; an empty id would collide across calls in one turn.
   */
  override extractToolCalls(body: Uint8Array): ToolCall[] {
    const value = parseJson(body);
    if (value === undefined) {
      throw AdapterError.invalidRequest("provider response body must be JSON");
    }
    const result = unwrapCloudflareEnvelope(value);
    const calls = getField(result, "tool_calls");
    if (!Array.isArray(calls)) return [];
    const out: ToolCall[] = [];
    for (const [index, call] of calls.entries()) {
      const name = asStr(getField(call, "name"));
      if (name === undefined) continue;
      out.push({
        id: asStr(getField(call, "id")) ?? `workers_ai_tool_${index}`,
        name,
        arguments: getField(call, "arguments") ?? null,
      });
    }
    return out;
  }

  /** Tool results go back as OpenAI `role: "tool"` messages, which Workers AI accepts. */
  override appendToolResults(body: Json, results: readonly ToolResult[]): Json {
    const object = ensureObjectBody(body, "chat completion request body");
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The Workers AI text-generation input.
 *
 * `model` is NOT copied into the body: the run surface addresses the model in
 * the PATH, so a stray `model` key would be an unread field that an operator
 * reading a request log would reasonably mistake for the thing being invoked —
 * the same reason `azure.rs` deletes it.
 *
 * The generation knobs are forwarded only when the client set them, so Workers
 * AI's own per-model defaults apply otherwise rather than a default this
 * gateway invented.
 */
function textGenerationInput(body: JsonObject, stream: boolean): JsonObject {
  const messages = getField(body, "messages");
  if (!Array.isArray(messages)) {
    throw AdapterError.invalidRequest('chat completion request body must include "messages"');
  }
  const input: JsonObject = { messages, stream };
  for (const key of ["max_tokens", "temperature", "top_p", "top_k", "seed", "tools"]) {
    const value = getField(body, key);
    if (value !== undefined) input[key] = value;
  }
  return input;
}

/**
 * `{ result, success, errors }` → `result`, and anything else → itself.
 *
 * The REST surface wraps; the binding does not. Unwrapping only when the
 * envelope markers are actually present means a native body that happens to
 * carry a `result` key is left alone.
 */
function unwrapCloudflareEnvelope(value: Json): Json {
  if (isObject(value) && "result" in value && "success" in value) {
    return (value as JsonObject)["result"] ?? null;
  }
  return value;
}

/**
 * `Authorization: Bearer` when a token is configured, and NOTHING when it is
 * not — because the binding needs no credential at all. This is the same
 * "no key ⇒ no header" rule `openai.rs::provider_headers` follows, and here it
 * is load-bearing rather than a convenience: a binding-backed deployment has no
 * API token to configure, and demanding one would have made the family
 * unusable in exactly the deployment it exists for.
 */
function workersAiHeaders(apiKey: string | undefined): ProviderHeader[] {
  const headers: ProviderHeader[] = [
    { name: "content-type", value: new SecretValue("application/json") },
  ];
  if (apiKey !== undefined && apiKey.trim().length > 0) {
    headers.push({ name: "authorization", value: new SecretValue(`Bearer ${apiKey}`) });
  }
  return headers;
}

function validateKind(kind: string): void {
  if (kind !== WORKERS_AI_KIND) throw AdapterError.unsupportedProviderKind(kind);
}

function ensureObjectBody(body: Json, label: string): JsonObject {
  if (isObject(body)) return body;
  throw AdapterError.invalidRequest(`${label} must be a JSON object`);
}

const trimEndSlashes = (value: string): string => value.replace(/\/+$/, "");

/**
 * `{base}/run/{model}`.
 *
 * Workers AI model ids look like `@cf/meta/llama-3.1-8b-instruct` — they carry
 * slashes and an `@`, and Cloudflare's own URLs keep both UNESCAPED, so the id
 * is appended verbatim rather than percent-encoded. Encoding it would produce a
 * 404 against the real API. What is refused is a model id that could climb out
 * of the path (`..`) or inject a query/fragment, because `base_url` is operator
 * config and `provider_model` may come from a tenant-visible model row.
 */
function runEndpoint(baseUrl: string, providerModel: string): string {
  const model = providerModel.trim();
  if (model.length === 0) {
    throw AdapterError.invalidRequest("workers ai provider_model must not be empty");
  }
  if (model.includes("..") || model.includes("?") || model.includes("#") || /\s/.test(model)) {
    throw AdapterError.invalidRequest(
      `workers ai provider_model ${providerModel} contains characters that are not valid in a model id`,
    );
  }
  return `${trimEndSlashes(baseUrl)}/run/${model}`;
}

const toolResultContentToString = (value: Json): string =>
  typeof value === "string" ? value : JSON.stringify(value);
