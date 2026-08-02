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
  RerankPlan,
  ResponsesPlan,
  AudioBytes,
  SpeechPlan,
  TranscriptionPlan,
} from "./types.js";
import { CanonicalAiRequest } from "./canonical.js";
import { asStr, asU64, getField, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";
import { embeddingsTextInputs, openaiEmbeddingsResponse } from "./gemini.js";
import { fallbackErrorMessage, hasAnyUsage } from "./openai.js";
import { structuredOutputFromChatBody, structuredOutputFromResponsesBody } from "./structured.js";
import type { CanonicalStructuredOutput } from "./structured.js";

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
    const input = textGenerationInput(body, request.stream);
    applyStructuredOutput(input, structuredOutputFromChatBody(body), provider.kind);
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: input,
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
    const input = textGenerationInput(body, request.stream);
    // Read off the ORIGINAL Responses body: the requirement lives in
    // `text.format` there, and `intoChatBodyWithSystemMessage` does not move it.
    applyStructuredOutput(input, structuredOutputFromResponsesBody(request.body), provider.kind);
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: input,
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
   * Workers AI reranker models (`@cf/baai/bge-reranker-base`) take
   * `{ query, contexts: [{ text }], top_k }` — issue #676.
   *
   * The mapping is deliberate on all three fields:
   *
   *  - `contexts`, not `documents`: this is the native run-surface grammar, the
   *    same reason `prepareEmbeddings` emits `text` rather than `input`.
   *  - `top_k`, not the caller's `top_n`: Cohere's ingress spelling and
   *    Cloudflare's native spelling differ, and translating here is what keeps
   *    every other family's future rerank leg free to use its own.
   *  - the knob is forwarded ONLY when the caller set it. Defaulting `top_k` to
   *    the document count would look harmless and is not: Workers AI's own
   *    default is what an operator's model card documents, and inventing one
   *    here would silently change the answer for a caller who asked for nothing.
   */
  override prepareRerank(provider: ProviderConfig, request: RerankPlan): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body, "rerank request body");
    const query = asStr(getField(body, "query"));
    if (query === undefined || query.length === 0) {
      throw AdapterError.invalidRequest('rerank request body must include a "query" string');
    }
    const texts = rerankDocumentTexts(body);
    const input: JsonObject = { query, contexts: texts.map((text) => ({ text })) };
    const topN = asU64(getField(body, "top_n"));
    if (topN !== undefined) input["top_k"] = topN;
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: input,
      stream: false,
      headers: workersAiHeaders(provider.apiKey),
    };
  }

  /**
   * `{ response: [{ id, score }] }` → `{ object, model, results }`.
   *
   * `id` is the INDEX of the context in the request, which is why the caller's
   * body has to be in hand: `return_documents` is answered by joining those
   * indices back against the documents the caller sent, and no reranker echoes
   * them.
   *
   * The provider's ORDER is preserved rather than re-sorted by score. A
   * cross-encoder returns its ranking, and re-sorting here would silently
   * overwrite a provider's tie-breaking with this gateway's. `relevance_score`
   * is on every row, so a client that wants a different order has everything it
   * needs.
   *
   * An index the provider returns that is not in the caller's document list is
   * DROPPED rather than emitted with a missing document: it can only be a
   * provider bug or a truncated response, and passing it on would hand the
   * client a row whose `index` addresses nothing.
   */
  override translateRerankResponse(body: Uint8Array, model: string, request: Json): Json | null {
    const parsed = parseJson(body);
    if (parsed === undefined) {
      throw AdapterError.invalidRequest("provider rerank response must be JSON");
    }
    const result = unwrapCloudflareEnvelope(parsed);
    const rows = getField(result, "response");
    if (!Array.isArray(rows)) {
      throw AdapterError.invalidRequest("workers ai rerank response is missing a response array");
    }
    const documents = isObject(request) ? rerankDocumentTexts(request) : [];
    const returnDocuments = getField(request, "return_documents") === true;

    const results: Json[] = [];
    for (const row of rows) {
      const index = asU64(getField(row, "id"));
      const score = getField(row, "score");
      if (index === undefined || typeof score !== "number") continue;
      if (index >= documents.length) continue;
      const entry: JsonObject = { index, relevance_score: score };
      if (returnDocuments) entry["document"] = { text: documents[index] as string };
      results.push(entry);
    }
    return { object: "list", model, results };
  }

  // -------------------------------------------------------------------------
  // Audio (issue #703)
  // -------------------------------------------------------------------------

  /**
   * Workers AI Whisper (`@cf/openai/whisper-large-v3-turbo`) takes
   * `{ audio: "<base64>", task, language?, initial_prompt? }`.
   *
   * Three deliberate mappings:
   *
   *  - the audio is BASE64, not a byte array. Cloudflare's turbo model documents
   *    base64 and the older `@cf/openai/whisper` documents `number[]`; base64 is
   *    chosen because a 25 MiB clip as a JSON array of integers is roughly 100 MB
   *    of JSON text, which a Worker cannot serialize, while base64 is 1.33x. The
   *    older model is reachable by an operator who wants it and would need its
   *    own leg — stated rather than silently half-supported.
   *  - `task` carries the transcribe/translate distinction, which is the ONE
   *    difference between the two ingress operations.
   *  - `initial_prompt` is Whisper's spelling of OpenAI's `prompt` decoder hint.
   *    Translating the name here is what keeps the ingress OpenAI-compatible
   *    without leaking Cloudflare's vocabulary to the caller.
   *
   * `response_format` and `temperature` are deliberately NOT forwarded: the run
   * surface has no such knobs, and forwarding an unknown member to a task-typed
   * binding is how a 400 with no explanation happens. The caller's
   * `response_format` is honoured on the way OUT, by the gateway.
   */
  override prepareTranscription(
    provider: ProviderConfig,
    request: TranscriptionPlan,
  ): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body, "audio transcription request body");
    const bytes = audioUploadBytes(body);
    const input: JsonObject = {
      audio: base64Encode(bytes),
      task: request.translate ? "translate" : "transcribe",
    };
    const language = asStr(getField(body, "language"));
    if (language !== undefined && language.length > 0) input["language"] = language;
    const prompt = asStr(getField(body, "prompt"));
    if (prompt !== undefined && prompt.length > 0) input["initial_prompt"] = prompt;
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: input,
      stream: false,
      headers: workersAiHeaders(provider.apiKey),
    };
  }

  /**
   * Workers AI text-to-speech (`@cf/myshell-ai/melotts`) takes
   * `{ prompt, lang }` and answers `{ audio: "<base64 mp3>" }`.
   *
   * `prompt`, not `input`: the run surface's own spelling. `lang` takes the
   * caller's `language` and falls back to `voice` — a caller writing against
   * OpenAI sends `voice`, and MeloTTS's voice selection IS its language, so
   * mapping one onto the other is the closest honest reading of the request
   * rather than dropping it. Neither is invented when the caller sent neither:
   * MeloTTS's own default is what an operator's model card documents, and
   * defaulting to `en` here would silently change the answer for a caller who
   * asked for nothing.
   */
  override prepareSpeech(provider: ProviderConfig, request: SpeechPlan): ProviderHttpRequest {
    validateKind(provider.kind);
    const body = ensureObjectBody(request.body, "speech request body");
    const text = asStr(getField(body, "input"));
    if (text === undefined || text.length === 0) {
      throw AdapterError.invalidRequest('speech request body must include a non-empty "input"');
    }
    const input: JsonObject = { prompt: text };
    const lang = asStr(getField(body, "language")) ?? asStr(getField(body, "voice"));
    if (lang !== undefined && lang.length > 0) input["lang"] = lang;
    return {
      provider: provider.name,
      endpoint: runEndpoint(provider.baseUrl, request.providerModel),
      body: input,
      stream: false,
      headers: workersAiHeaders(provider.apiKey),
    };
  }

  /**
   * `{ text, word_count, segments }` → OpenAI's `{ text, duration, segments }`.
   *
   * `duration` is DERIVED — the largest segment `end` — because Whisper does not
   * report one and it is the quantity this operation is billed on. Taking the
   * maximum rather than the last element's `end` is deliberate: segment order is
   * the model's, not necessarily monotonic, and a duration read off a
   * mis-ordered last row would under-bill a long recording.
   *
   * When there are no segments at all the field is OMITTED rather than set to
   * zero. The gateway meters on exactly this value, and `0` would settle a real
   * call authoritatively at $0 where an absent field correctly falls through to
   * the rate card. That distinction is the whole reason `Usage.audioSeconds` is
   * optional.
   */
  override translateTranscriptionResponse(body: Uint8Array, _model: string): Json | null {
    const parsed = parseJson(body);
    if (parsed === undefined) {
      throw AdapterError.invalidRequest("provider transcription response must be JSON");
    }
    const result = unwrapCloudflareEnvelope(parsed);
    const text = asStr(getField(result, "text"));
    if (text === undefined) {
      throw AdapterError.invalidRequest("workers ai transcription response is missing text");
    }
    const out: JsonObject = { text };
    const segments = getField(result, "segments");
    if (Array.isArray(segments) && segments.length > 0) {
      let duration = 0;
      for (const segment of segments) {
        const end = getField(segment, "end");
        if (typeof end === "number" && Number.isFinite(end) && end > duration) duration = end;
      }
      if (duration > 0) out["duration"] = duration;
      out["segments"] = segments as Json;
    }
    const language = asStr(getField(result, "language"));
    if (language !== undefined) out["language"] = language;
    return out;
  }

  /**
   * `{ audio: "<base64>" }` → the decoded MP3.
   *
   * Without this leg the base64 STRING is what reaches the caller under an
   * `audio/*` content type — a 200 that every audio player rejects. That is the
   * silent, metered failure `runOnBinding`'s reranker arm exists to prevent one
   * surface over, and it is why this method returns bytes rather than `Json`.
   *
   * `audio/mpeg` is asserted rather than read off the upstream: the Cloudflare
   * run surface answers `application/json` (it IS JSON), so relaying its content
   * type would label an MP3 as JSON. MeloTTS emits MP3, which is also the OpenAI
   * default `response_format`, so the two dialects agree on the common case.
   */
  override translateSpeechResponse(body: Uint8Array, contentType: string): AudioBytes | null {
    // Not JSON at all ⇒ the upstream already answered with audio. Relay it.
    const parsed = parseJson(body);
    if (parsed === undefined || !isObject(parsed)) return null;
    const result = unwrapCloudflareEnvelope(parsed);
    const encoded = asStr(getField(result, "audio"));
    if (encoded === undefined) {
      throw AdapterError.invalidRequest("workers ai speech response is missing audio");
    }
    void contentType;
    return { bytes: base64Decode(encoded), contentType: "audio/mpeg" };
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
 * The caller's `documents` as plain text, in request order (issue #676).
 *
 * Both spellings the ingress schema admits are normalized here, ONCE, and this
 * is the only place that happens: `prepareRerank` needs the texts to build
 * `contexts`, and `translateRerankResponse` needs the same array — by the same
 * indices — to answer `return_documents`. Two extractors would be two chances
 * for those indices to disagree, which would attach the wrong document to a
 * score without any test failing on the shape.
 *
 * Exported because it is family-independent: it reads the gateway's ingress
 * grammar, not Cloudflare's, so the next family to grow a rerank leg reuses it
 * rather than writing a second reading of `documents`.
 */
export function rerankDocumentTexts(body: Json): string[] {
  const documents = getField(body, "documents");
  if (!Array.isArray(documents) || documents.length === 0) {
    throw AdapterError.invalidRequest(
      'rerank request must include a non-empty "documents" array',
    );
  }
  const texts: string[] = [];
  for (const document of documents) {
    if (typeof document === "string") {
      texts.push(document);
      continue;
    }
    const text = asStr(getField(document, "text"));
    if (text === undefined) {
      throw AdapterError.invalidRequest(
        'rerank documents must be strings or objects with a "text" string',
      );
    }
    texts.push(text);
  }
  return texts;
}

/**
 * The Workers AI dialect of the structured-output requirement — the ninth row
 * of the table in `./structured.ts` (issue #674).
 *
 * Workers AI has JSON Mode on its text-generation models and does take
 * `response_format` — but NOT OpenAI's spelling of it: the schema goes directly
 * under `json_schema`, where OpenAI nests `{ name, schema, strict }`. Copying
 * the caller's object through (which is what the OpenAI family does, and what
 * `textGenerationInput` would otherwise have to do) would hand Workers AI a
 * schema whose top level is `{name, schema, strict}` — a shape that constrains
 * nothing the caller asked for. So the canonical requirement is RE-EMITTED.
 *
 * `unmodeled` is REFUSED, not dropped. That is the rule `./structured.ts`
 * exists for: a request asking for a contract this family cannot express must
 * make the route unusable for THIS request, so the reliability ladder moves on,
 * rather than returning prose to a caller who asked for a schema.
 */
function applyStructuredOutput(
  input: JsonObject,
  structured: CanonicalStructuredOutput | undefined,
  providerKind: string,
): void {
  if (structured === undefined) return;
  if (structured.kind === "unmodeled") {
    throw AdapterError.unsupportedCapability(
      `structured output (response_format type ${structured.type})`,
      providerKind,
    );
  }
  if (structured.kind === "json_object") {
    input["response_format"] = { type: "json_object" };
    return;
  }
  input["response_format"] = { type: "json_schema", json_schema: structured.schema };
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

/**
 * The decoded upload bytes off the gateway's normalized `file` part (#703).
 *
 * Exported for the same reason `rerankDocumentTexts` is: it reads the GATEWAY's
 * ingress grammar, not Cloudflare's, so the next family to grow an audio leg
 * reuses it instead of writing a second reading of `file`. Two readings would be
 * two chances to disagree about which bytes were sent — and the byte count is
 * what the pre-dispatch reservation was computed from.
 */
export function audioUploadBytes(body: Json): Uint8Array {
  const file = getField(body, "file");
  const bytes = isObject(file) ? (file as { bytes?: unknown }).bytes : undefined;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
    throw AdapterError.invalidRequest('audio request must include a non-empty "file" part');
  }
  return bytes;
}

/**
 * Base64 in CHUNKS, which is not a micro-optimization.
 *
 * `String.fromCharCode(...bytes)` spreads every byte as a separate argument, and
 * a 25 MiB upload is 26 million arguments — past every engine's call-stack limit
 * — so the naive spelling does not merely run slowly, it THROWS on exactly the
 * large uploads this surface exists to accept. 8 KiB per call keeps the argument
 * count bounded while staying a handful of allocations.
 */
function base64Encode(bytes: Uint8Array): string {
  const CHUNK = 8192;
  let binary = "";
  for (let offset = 0; offset < bytes.byteLength; offset += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + CHUNK));
  }
  return btoa(binary);
}

/** The inverse. Throws `invalid_request` on a provider answer that is not base64. */
function base64Decode(encoded: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    throw AdapterError.invalidRequest("provider speech response is not valid base64 audio");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const toolResultContentToString = (value: Json): string =>
  typeof value === "string" ? value : JSON.stringify(value);
